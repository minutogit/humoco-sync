#![forbid(unsafe_code)]

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tracing::{error, info};

use humoco_sync_server::build_router;
use humoco_sync_server::config::Config;
use humoco_sync_server::crypto::{
    canonical_revocation_message, format_admin_put_members_message,
    format_admin_put_revoke_message, format_admin_status_message, format_delete_account_message,
    hash_admin_token, leading_zero_bits, parse_member_message, random_hex, sha256_hex, unix_now,
    RevocationNotice, RevocationReplacementTarget,
};
use humoco_sync_server::state::AppState;

#[derive(Parser)]
#[command(
    name = "humoco-sync-server",
    version,
    about = "High-performance Hybrid Rust Drop Server for HuMoCo"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the HTTP sync, public registration, and admin server
    Serve {
        /// Path to TOML configuration file (or set HUMOCO_SYNC_CONFIG)
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Optional bind address override (e.g. 0.0.0.0:8080)
        #[arg(short, long)]
        bind: Option<String>,
    },
    /// Generate an Argon2id or SHA-256 hash for security.admin_token_hash / api_bearer_token_hash
    HashToken {
        /// Plaintext token to hash (if omitted, generates a random 32-byte token)
        #[arg(long)]
        token: Option<String>,
        /// Output sha256:<hex> format instead of Argon2id (useful for high-rate webhook bearer tokens)
        #[arg(long)]
        sha256: bool,
    },
    /// Print a ready-to-edit config.toml template
    GenerateConfig {
        #[arg(long, value_enum, default_value_t = ConfigPreset::Hybrid)]
        mode: ConfigPreset,
        #[arg(long, default_value = "")]
        admin_pubkey: String,
        #[arg(long, default_value = "https://sync.example.org")]
        public_url: String,
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
    },
    /// Deterministic Ed25519 test vector helper for blackbox integration tests
    SignTest {
        #[command(subcommand)]
        action: SignTestCmd,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum ConfigPreset {
    Friends,
    Public,
    Hybrid,
}

#[derive(Subcommand)]
enum SignTestCmd {
    /// Generate a fresh Ed25519 keypair: prints "<priv_hex64> <pub_hex64>"
    Keygen,
    /// Sign a member/account request and print 128-hex signature
    SignMember {
        #[arg(long)]
        sk: String,
        #[arg(long)]
        method: String,
        #[arg(long, default_value = "")]
        channel: String,
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long, default_value = "")]
        media_id: String,
        #[arg(long)]
        ts: i64,
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        body_file: Option<PathBuf>,
    },
    /// Sign an admin request (PUT_MEMBERS, STATUS, PUT_REVOKE) and print 128-hex signature
    SignAdmin {
        #[arg(long)]
        sk: String,
        #[arg(long)]
        action: String,
        #[arg(long, default_value = "")]
        channel: String,
        #[arg(long)]
        ts: i64,
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        body_file: Option<PathBuf>,
    },
    /// Generate signed SyncRevocationNotice JSON
    SignRevokeNotice {
        #[arg(long)]
        sk: String,
        #[arg(long)]
        issued: u64,
        #[arg(long)]
        effective: u64,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        rep_write: Option<String>,
        #[arg(long)]
        rep_read: Option<String>,
        #[arg(long)]
        rep_pub: Option<String>,
    },
    /// Solve a PoW challenge and print the numeric nonce
    SolvePow {
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        bits: u8,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let exit_code = match cli.command {
        Commands::Serve { config, bind } => run_serve(config, bind).await,
        Commands::HashToken { token, sha256 } => run_hash_token(token, sha256),
        Commands::GenerateConfig {
            mode,
            admin_pubkey,
            public_url,
            bind,
        } => run_generate_config(mode, admin_pubkey, public_url, bind),
        Commands::SignTest { action } => run_sign_test(action),
    };

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

async fn run_serve(config_opt: Option<PathBuf>, bind_override: Option<String>) -> i32 {
    let config_path = config_opt
        .or_else(|| std::env::var_os("HUMOCO_SYNC_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    let mut cfg = match Config::load_from_path(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            return 1;
        }
    };
    if let Some(b) = bind_override {
        cfg.server.bind = b;
    }

    let bind_addr: SocketAddr = match cfg.server.bind.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Invalid bind address '{}': {}", cfg.server.bind, e);
            return 1;
        }
    };

    let state = match AppState::from_config(cfg.clone()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Database initialization error: {}", e);
            return 1;
        }
    };

    let maint_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(e) = maint_state.db.run_maintenance(&maint_state.config, unix_now()) {
                error!(error = %e, "Background maintenance pass failed");
            }
        }
    });

    let app = build_router(state);
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind {}: {}", bind_addr, e);
            return 1;
        }
    };

    info!(
        bind = %bind_addr,
        public_base_url = %cfg.server.public_base_url,
        enable_admin_app = cfg.mode.enable_admin_app,
        enable_public_registration = cfg.mode.enable_public_registration,
        "humoco-sync-server listening"
    );

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        error!(error = %e, "HTTP server terminated with error");
        return 1;
    }
    0
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("Shutdown signal received, draining server");
}

fn run_hash_token(token_opt: Option<String>, use_sha256: bool) -> i32 {
    let generated = token_opt.is_none();
    let raw = token_opt.unwrap_or_else(|| random_hex(32));
    if raw.trim().is_empty() {
        eprintln!("Token cannot be empty");
        return 1;
    }
    if generated {
        println!("GENERATED_RAW_TOKEN={}", raw);
    }
    if use_sha256 {
        println!("sha256:{}", sha256_hex(raw.as_bytes()));
        0
    } else {
        match hash_admin_token(&raw) {
            Ok(h) => {
                println!("{}", h);
                0
            }
            Err(e) => {
                eprintln!("{}", e);
                1
            }
        }
    }
}

fn run_generate_config(
    mode: ConfigPreset,
    admin_pubkey: String,
    public_url: String,
    bind: String,
) -> i32 {
    let mut cfg = Config::default();
    cfg.server.bind = bind;
    cfg.server.public_base_url = public_url.trim_end_matches('/').to_string();
    cfg.server.admin_pubkey = admin_pubkey.trim().to_ascii_lowercase();
    match mode {
        ConfigPreset::Friends => {
            cfg.mode.enable_admin_app = true;
            cfg.mode.enable_public_registration = false;
        }
        ConfigPreset::Public => {
            cfg.mode.enable_admin_app = false;
            cfg.mode.enable_public_registration = true;
        }
        ConfigPreset::Hybrid => {
            cfg.mode.enable_admin_app = true;
            cfg.mode.enable_public_registration = true;
        }
    }
    match toml::to_string_pretty(&cfg) {
        Ok(s) => {
            println!("{}", s);
            0
        }
        Err(e) => {
            eprintln!("Failed to serialize default config: {}", e);
            1
        }
    }
}

fn parse_sk(hex_sk: &str) -> Result<SigningKey, String> {
    let bytes = hex::decode(hex_sk.trim()).map_err(|_| "Invalid sk hex".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Secret key must be 32 bytes (64 hex chars)".to_string())?;
    Ok(SigningKey::from_bytes(&arr))
}

fn read_body_bytes(path_opt: Option<PathBuf>) -> Result<Vec<u8>, String> {
    match path_opt {
        Some(p) => fs::read(&p).map_err(|e| format!("Failed to read {}: {}", p.display(), e)),
        None => Ok(Vec::new()),
    }
}

fn run_sign_test(cmd: SignTestCmd) -> i32 {
    match cmd {
        SignTestCmd::Keygen => {
            let sk = SigningKey::generate(&mut OsRng);
            let vk = sk.verifying_key();
            println!(
                "{} {}",
                hex::encode(sk.to_bytes()),
                hex::encode(vk.as_bytes())
            );
            0
        }
        SignTestCmd::SignMember {
            sk,
            method,
            channel,
            prefix,
            media_id,
            ts,
            nonce,
            body_file,
        } => {
            let sk = match parse_sk(&sk) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("{}", e);
                    return 1;
                }
            };
            let msg = if method == "DELETE_ACCOUNT" {
                format_delete_account_message(ts, &nonce)
            } else {
                let body = match read_body_bytes(body_file) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("{}", e);
                        return 1;
                    }
                };
                let body_hash = sha256_hex(&body);
                let target = if channel == "media" {
                    if media_id.is_empty() {
                        "media".to_string()
                    } else {
                        format!("media:{}", media_id.to_ascii_lowercase())
                    }
                } else {
                    channel
                };
                parse_member_message(&method, &target, &prefix, ts, &nonce, &body_hash)
            };
            let sig = sk.sign(msg.as_bytes());
            println!("{}", hex::encode(sig.to_bytes()));
            0
        }
        SignTestCmd::SignAdmin {
            sk,
            action,
            channel,
            ts,
            nonce,
            body_file,
        } => {
            let sk = match parse_sk(&sk) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("{}", e);
                    return 1;
                }
            };
            let body = match read_body_bytes(body_file) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{}", e);
                    return 1;
                }
            };
            let body_hash = sha256_hex(&body);
            let msg = match action.as_str() {
                "PUT_MEMBERS" => format_admin_put_members_message(&channel, ts, &nonce, &body_hash),
                "STATUS" => format_admin_status_message(ts, &nonce),
                "PUT_REVOKE" => format_admin_put_revoke_message(ts, &nonce, &body_hash),
                other => {
                    eprintln!("Unsupported admin action '{}'", other);
                    return 1;
                }
            };
            let sig = sk.sign(msg.as_bytes());
            println!("{}", hex::encode(sig.to_bytes()));
            0
        }
        SignTestCmd::SignRevokeNotice {
            sk,
            issued,
            effective,
            reason,
            rep_write,
            rep_read,
            rep_pub,
        } => {
            let sk = match parse_sk(&sk) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("{}", e);
                    return 1;
                }
            };
            let drop_pub = hex::encode(sk.verifying_key().as_bytes());
            let replacement = match (rep_write, rep_read, rep_pub) {
                (Some(w), Some(r), Some(p)) => Some(RevocationReplacementTarget {
                    write_url: w,
                    read_url: r,
                    drop_pub: p.to_ascii_lowercase(),
                }),
                _ => None,
            };
            let mut notice = RevocationNotice {
                drop_pub,
                issued_at: issued,
                effective_at: effective,
                reason,
                replacement,
                signature: String::new(),
            };
            let msg = canonical_revocation_message(&notice);
            let sig = sk.sign(msg.as_bytes());
            notice.signature = hex::encode(sig.to_bytes());
            match serde_json::to_string(&notice) {
                Ok(s) => {
                    println!("{}", s);
                    0
                }
                Err(e) => {
                    eprintln!("{}", e);
                    1
                }
            }
        }
        SignTestCmd::SolvePow { challenge, bits } => {
            for n in 0u64.. {
                let mut h = Sha256::new();
                h.update(challenge.trim().as_bytes());
                h.update(b":");
                h.update(n.to_string().as_bytes());
                let digest = h.finalize();
                if leading_zero_bits(&digest) >= bits {
                    println!("{}", n);
                    return 0;
                }
            }
            1
        }
    }
}
