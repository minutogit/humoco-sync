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
    canonical_revocation_message, format_admin_post_lock_selftest_message,
    format_admin_put_config_message, format_admin_put_lock_delegate_message,
    format_admin_put_members_message, format_admin_put_revoke_message, format_admin_status_message,
    format_delete_account_message, format_lock_delegate_signature_message, hash_admin_token,
    leading_zero_bits, parse_member_message, random_hex, sha256_hex, unix_now, RevocationNotice,
    RevocationReplacementTarget,
};
use humoco_sync_server::locks::LockDelegation;
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
    /// Run lock quarterly retention garbage collection at a given Unix timestamp
    LockGc {
        /// Path to TOML configuration file (or set HUMOCO_SYNC_CONFIG)
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Simulated current Unix timestamp in seconds
        #[arg(long)]
        now_secs: u64,
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
    /// Derive 64-hex lowercase verifying pubkey from 64-hex signing key
    Pubkey {
        #[arg(long)]
        sk: String,
    },
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
    /// Sign an admin request (PUT_MEMBERS, STATUS, PUT_ADMIN_CONFIG, PUT_REVOKE) and print 128-hex signature
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
    /// Generate signed LockDelegation JSON payload for PUT ?lock_delegate
    SignLockDelegate {
        #[arg(long)]
        sk: String,
        #[arg(long)]
        lock_pub: String,
        #[arg(long)]
        write_url: String,
        #[arg(long)]
        read_url: String,
        #[arg(long)]
        issued: u64,
    },
    /// Generate complete valid AnchorManifest + 605B LockEntry batch JSON for blackbox HTTP tests
    MakeLockSample {
        #[arg(long)]
        lock_pub: String,
        #[arg(long)]
        admin_pub: String,
        #[arg(long)]
        quarter: u16,
        #[arg(long)]
        ticket_json: Option<PathBuf>,
        #[arg(long)]
        receipt_json: Option<PathBuf>,
        #[arg(long)]
        manifest_json: Option<PathBuf>,
        #[arg(long)]
        anchor_tag: Option<String>,
        #[arg(long, default_value_t = 8)]
        pow_bits: u32,
        #[arg(long)]
        variant: String,
    },
    /// Generate & cryptographically verify 3-phase rotation payloads against Rust/PHP HTTP APIs
    Rotation {
        #[command(subcommand)]
        sub: RotationTestCmd,
    },
}

#[derive(Subcommand)]
enum RotationTestCmd {
    MakeManifest {
        #[arg(long)]
        s1_lock_pub: String,
        #[arg(long)]
        s1_admin_pub: String,
        #[arg(long)]
        s1_url: String,
        #[arg(long)]
        s2_lock_pub: String,
        #[arg(long)]
        s2_admin_pub: String,
        #[arg(long)]
        s2_url: String,
        #[arg(long)]
        quarter: u16,
        #[arg(long)]
        anchor_tag: Option<String>,
    },
    MakePreFreeze {
        #[arg(long)]
        manifest_json: PathBuf,
    },
    MakePropose {
        #[arg(long)]
        manifest_json: PathBuf,
        #[arg(long)]
        ts: u64,
    },
    MakeVeto {
        #[arg(long)]
        manifest_json: PathBuf,
        #[arg(long)]
        propose_json: PathBuf,
        #[arg(long)]
        ts: u64,
    },
    VerifyFreeze {
        #[arg(long)]
        freeze_json: PathBuf,
        #[arg(long)]
        expected_lock_pub: String,
        #[arg(long, default_value_t = 0)]
        min_entries: usize,
    },
    MakeImport {
        #[arg(long)]
        manifest_json: PathBuf,
        #[arg(long)]
        propose_json: PathBuf,
        #[arg(long)]
        freeze_json: PathBuf,
    },
    VerifyImportAck {
        #[arg(long)]
        import_resp_json: PathBuf,
        #[arg(long)]
        expected_lock_pub: String,
    },
    MakeSignCommit {
        #[arg(long)]
        manifest_json: PathBuf,
        #[arg(long)]
        propose_json: PathBuf,
        #[arg(long)]
        import_resp_json: Option<PathBuf>,
    },
    MakeFinalize {
        #[arg(long)]
        manifest_json: PathBuf,
        #[arg(long)]
        propose_json: PathBuf,
        #[arg(long)]
        import_resp_json: PathBuf,
        #[arg(long)]
        sign_commit_resp_json: PathBuf,
    },
    VerifyManifest {
        #[arg(long)]
        manifest_json: PathBuf,
        #[arg(long)]
        expected_anchor_id: String,
        #[arg(long)]
        expected_rev: u64,
        #[arg(long)]
        wrapped_field: Option<String>,
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
        Commands::LockGc { config, now_secs } => run_lock_gc(config, now_secs),
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
            if let Err(e) = maint_state
                .db
                .run_maintenance(&maint_state.config, unix_now())
            {
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
        SignTestCmd::Pubkey { sk } => match parse_sk(&sk) {
            Ok(k) => {
                println!("{}", hex::encode(k.verifying_key().to_bytes()));
                0
            }
            Err(e) => {
                eprintln!("{}", e);
                1
            }
        },
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
                "PUT_ADMIN_CONFIG" => format_admin_put_config_message(ts, &nonce, &body_hash),
                "PUT_REVOKE" => format_admin_put_revoke_message(ts, &nonce, &body_hash),
                "PUT_LOCK_DELEGATE" => {
                    format_admin_put_lock_delegate_message(ts, &nonce, &body_hash)
                }
                "POST_LOCK_SELFTEST" => {
                    format_admin_post_lock_selftest_message(ts, &nonce, &body_hash)
                }
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
        SignTestCmd::SignLockDelegate {
            sk,
            lock_pub,
            write_url,
            read_url,
            issued,
        } => {
            let sk = match parse_sk(&sk) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("{}", e);
                    return 1;
                }
            };
            let Ok(lock_pub_bytes) = humoco_proto::decode_hex_fixed::<32>(lock_pub.trim()) else {
                eprintln!("Invalid lowercase 64-hex lock_pub");
                return 1;
            };
            let admin_pub_bytes = sk.verifying_key().to_bytes();
            let admin_pub_hex = hex::encode(admin_pub_bytes);
            let msg = format_lock_delegate_signature_message(
                &admin_pub_hex,
                lock_pub.trim(),
                write_url.trim(),
                read_url.trim(),
                issued,
            );
            let sig_bytes = sk.sign(msg.as_bytes()).to_bytes();
            let del = LockDelegation {
                admin_pub: admin_pub_bytes,
                lock_pub: lock_pub_bytes,
                write_url: write_url.trim().to_string(),
                read_url: read_url.trim().to_string(),
                issued_at: issued,
                sig: sig_bytes,
            };
            println!("{}", serde_json::to_string(&del).unwrap());
            0
        }
        SignTestCmd::MakeLockSample {
            lock_pub,
            admin_pub,
            quarter,
            ticket_json,
            receipt_json,
            manifest_json,
            anchor_tag,
            pow_bits,
            variant,
        } => run_make_lock_sample(MakeLockSampleArgs {
            lock_pub_hex: &lock_pub,
            admin_pub_hex: &admin_pub,
            quarter,
            ticket_json_path: ticket_json.as_ref(),
            receipt_json_path: receipt_json.as_ref(),
            manifest_json_path: manifest_json.as_ref(),
            anchor_tag: anchor_tag.as_deref(),
            pow_bits,
            variant: &variant,
        }),
        SignTestCmd::Rotation { sub } => run_rotation_test(sub),
    }
}

struct MakeLockSampleArgs<'a> {
    lock_pub_hex: &'a str,
    admin_pub_hex: &'a str,
    quarter: u16,
    ticket_json_path: Option<&'a PathBuf>,
    receipt_json_path: Option<&'a PathBuf>,
    manifest_json_path: Option<&'a PathBuf>,
    anchor_tag: Option<&'a str>,
    pow_bits: u32,
    variant: &'a str,
}

fn derive_sample_creator_sk(anchor_tag: Option<&str>) -> SigningKey {
    match anchor_tag {
        Some(tag) if !tag.is_empty() => {
            let dig: [u8; 32] = Sha256::digest(format!("HUMOCO_TEST_CREATOR_V1:{tag}")).into();
            SigningKey::from_bytes(&dig)
        }
        _ => SigningKey::from_bytes(&[91u8; 32]),
    }
}

fn derive_sample_guarantor_sk(anchor_tag: Option<&str>) -> SigningKey {
    match anchor_tag {
        Some(tag) if !tag.is_empty() => {
            let dig: [u8; 32] = Sha256::digest(format!("HUMOCO_TEST_GUARANTOR_V1:{tag}")).into();
            SigningKey::from_bytes(&dig)
        }
        _ => SigningKey::from_bytes(&[94u8; 32]),
    }
}

fn read_json_value(path: &PathBuf) -> Result<serde_json::Value, String> {
    let raw =
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("Failed to parse {}: {e}", path.display()))
}

fn run_make_lock_sample(args: MakeLockSampleArgs<'_>) -> i32 {
    use humoco_proto::{
        compute_root_mig_auth_digest, derive_bucket, derive_slot, derive_slot_file_id,
        hash_pubkey_sha3, solve_lock_pow, AnchorAuthority, AnchorManifest, CausalOutputProof,
        GenesisTicket, LockEntry, LockReceipt, NominatedBy, ServerEntry, HOP_ENCRYPTED_PAYLOAD_LEN,
    };

    let Ok(lock_pub) = humoco_proto::decode_hex_fixed::<32>(args.lock_pub_hex.trim()) else {
        eprintln!("Invalid lock_pub");
        return 1;
    };
    let Ok(admin_pub) = humoco_proto::decode_hex_fixed::<32>(args.admin_pub_hex.trim()) else {
        eprintln!("Invalid admin_pub");
        return 1;
    };
    let creator_mig_sk = derive_sample_creator_sk(args.anchor_tag);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();

    let manifest: AnchorManifest = if let Some(m_path) = args.manifest_json_path {
        match read_json_value(m_path).and_then(|v| {
            let inner = v.get("manifest").cloned().unwrap_or(v);
            serde_json::from_value(inner).map_err(|e| e.to_string())
        }) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("manifest error: {e}");
                return 1;
            }
        }
    } else {
        AnchorManifest {
            revision: 1,
            threshold: 1,
            servers: vec![ServerEntry {
                write_url: "https://sync1.example/sync.php".to_string(),
                read_url: "https://sync1.example/data".to_string(),
                admin_pub,
                lock_pub,
                nominated_by: NominatedBy::Creator,
            }],
            successors: Vec::new(),
            authority: AnchorAuthority {
                creator_mig_pub,
                guarantor_mig_pubs: Vec::new(),
            },
            migration_chain: Vec::new(),
            issued_at_ms: 1_794_916_800_000,
            retain_until_quarter: args.quarter,
        }
    };
    let anchor_id = match manifest.rev1_anchor_id() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("anchor_id error: {e}");
            return 1;
        }
    };

    let variant = args.variant;
    if variant == "anchor_id" {
        println!("{}", hex::encode(anchor_id));
        return 0;
    }

    let bucket = derive_bucket(&anchor_id, &lock_pub);
    if variant == "bucket_info" {
        println!("{} {}", hex::encode(anchor_id), hex::encode(bucket));
        return 0;
    }

    let seq_ds_tag =
        |idx: u32| -> [u8; 32] { Sha256::digest(format!("HUMOCO_SEQ_SLOT:{idx}")).into() };
    let slot0 = derive_slot(&anchor_id, &[0x11; 32]);
    let chosen_slot = if let Some(idx_s) = variant.strip_prefix("read_path_seq:") {
        let Ok(idx) = idx_s.parse::<u32>() else {
            eprintln!("Invalid read_path_seq index");
            return 1;
        };
        derive_slot(&anchor_id, &seq_ds_tag(idx))
    } else {
        slot0
    };
    if variant == "read_path" || variant.starts_with("read_path_seq:") {
        let q_str = humoco_proto::format_quarter(manifest.retain_until_quarter).unwrap();
        let file_s = derive_slot_file_id(&chosen_slot, &lock_pub);
        println!(
            "locks/{}/{}/{}.lock",
            q_str,
            hex::encode(bucket),
            hex::encode(file_s)
        );
        return 0;
    }

    let Some(ticket_path) = args.ticket_json_path else {
        eprintln!("--ticket-json is required for variant '{variant}'");
        return 1;
    };
    let ticket_val = match read_json_value(ticket_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let ticket_inner = ticket_val.get("ticket").unwrap_or(&ticket_val);
    let ticket: GenesisTicket = match serde_json::from_value(ticket_inner.clone()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ticket decode error: {e}");
            return 1;
        }
    };

    let known_head_receipt: Option<LockReceipt> = match args.receipt_json_path {
        Some(r_path) => match read_json_value(r_path).and_then(|v| {
            let inner = v
                .get("receipts")
                .and_then(|r| r.as_array())
                .and_then(|a| a.last())
                .cloned()
                .unwrap_or(v);
            serde_json::from_value(inner).map_err(|e| e.to_string())
        }) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("receipt decode error: {e}");
                return 1;
            }
        },
        None => None,
    };

    let genesis_sk = SigningKey::from_bytes(&[92u8; 32]);
    let genesis_pub = genesis_sk.verifying_key().to_bytes();
    let recv1_sk = SigningKey::from_bytes(&[93u8; 32]);
    let recv1_pub = recv1_sk.verifying_key().to_bytes();
    let recv1_hash = hash_pubkey_sha3(&recv1_pub);

    let (target_slot, child0, single_only) = if let Some(idx_s) = variant.strip_prefix("race:") {
        let Ok(idx) = idx_s.parse::<u32>() else {
            eprintln!("Invalid race index");
            return 1;
        };
        let mut c = [0xA0; 32];
        c[..4].copy_from_slice(&idx.to_le_bytes());
        (slot0, c, true)
    } else if let Some(idx_s) = variant.strip_prefix("seq:") {
        let Ok(idx) = idx_s.parse::<u32>() else {
            eprintln!("Invalid seq index");
            return 1;
        };
        let s = derive_slot(&anchor_id, &seq_ds_tag(idx));
        let mut c = [0xB0; 32];
        c[..4].copy_from_slice(&idx.to_le_bytes());
        (s, c, true)
    } else if variant == "conflict" {
        (slot0, [0x99; 32], true)
    } else {
        (slot0, [0x11; 32], false)
    };

    let mut causal0 = CausalOutputProof {
        anchor_id,
        slot: target_slot,
        parent_slot: [0u8; 32],
        output_branch: 0,
        depth: 0,
        child_lock: child0,
        sender_pubkey: genesis_pub,
        receiver_pubkey_hash: recv1_hash,
        change_pubkey_hash: None,
        causal_sig: [0u8; 64],
    };
    causal0.causal_sig = genesis_sk.sign(&causal0.digest().unwrap()).to_bytes();
    let root_mig_digest = compute_root_mig_auth_digest(&anchor_id, &target_slot, &genesis_pub);
    let root_mig_sig = creator_mig_sk.sign(&root_mig_digest).to_bytes();
    let pow0 = solve_lock_pow(&target_slot, &child0, 0, args.pow_bits, 0, 10_000_000).unwrap();
    let entry0 = LockEntry {
        slot: target_slot,
        parent_slot: [0u8; 32],
        output_branch: 0,
        depth: 0,
        child_lock: child0,
        sender_pubkey: genesis_pub,
        receiver_pubkey_hash: recv1_hash,
        change_pubkey_hash: None,
        causal_sig: causal0.causal_sig,
        root_mig_sig: Some(root_mig_sig),
        encrypted_payload: [0x55; HOP_ENCRYPTED_PAYLOAD_LEN],
        pow_nonce: pow0,
    };

    let entries = if single_only {
        vec![entry0.to_wire_hex().unwrap()]
    } else {
        let slot1 = derive_slot(&anchor_id, &[0x22; 32]);
        let child1 = [0x22; 32];
        let recv2_hash = [0x77; 32];
        let mut causal1 = CausalOutputProof {
            anchor_id,
            slot: slot1,
            parent_slot: target_slot,
            output_branch: 0,
            depth: 1,
            child_lock: child1,
            sender_pubkey: recv1_pub,
            receiver_pubkey_hash: recv2_hash,
            change_pubkey_hash: None,
            causal_sig: [0u8; 64],
        };
        causal1.causal_sig = recv1_sk.sign(&causal1.digest().unwrap()).to_bytes();
        let pow1 = solve_lock_pow(&slot1, &child1, 1, args.pow_bits, 0, 10_000_000).unwrap();
        let entry1 = LockEntry {
            slot: slot1,
            parent_slot: target_slot,
            output_branch: 0,
            depth: 1,
            child_lock: child1,
            sender_pubkey: recv1_pub,
            receiver_pubkey_hash: recv2_hash,
            change_pubkey_hash: None,
            causal_sig: causal1.causal_sig,
            root_mig_sig: None,
            encrypted_payload: [0x66; HOP_ENCRYPTED_PAYLOAD_LEN],
            pow_nonce: pow1,
        };
        vec![entry0.to_wire_hex().unwrap(), entry1.to_wire_hex().unwrap()]
    };

    let req = serde_json::json!({
        "anchor_id": hex::encode(anchor_id),
        "bucket": hex::encode(bucket),
        "recipient_nonce": hex::encode([0x44; 32]),
        "entries": entries,
        "manifest": manifest,
        "genesis_ticket": ticket,
        "known_head_receipt": known_head_receipt,
    });
    println!("{}", req);
    0
}

fn run_rotation_test(sub: RotationTestCmd) -> i32 {
    use humoco_proto::{
        verify_anchor_manifest_chain, AnchorAuthority, AnchorManifest, CommitteeSignature,
        ImportAck, LockEntry, MigrationCert, MigrationProposal, MigrationVeto, NominatedBy,
        ProposalInitiator, ServerEntry, SnapshotExport,
    };

    let res: Result<String, String> = (|| match sub {
        RotationTestCmd::MakeManifest {
            s1_lock_pub,
            s1_admin_pub,
            s1_url,
            s2_lock_pub,
            s2_admin_pub,
            s2_url,
            quarter,
            anchor_tag,
        } => {
            let s1_lp = humoco_proto::decode_hex_fixed::<32>(s1_lock_pub.trim())?;
            let s1_ap = humoco_proto::decode_hex_fixed::<32>(s1_admin_pub.trim())?;
            let s2_lp = humoco_proto::decode_hex_fixed::<32>(s2_lock_pub.trim())?;
            let s2_ap = humoco_proto::decode_hex_fixed::<32>(s2_admin_pub.trim())?;
            let tag = anchor_tag.as_deref();
            let c_sk = derive_sample_creator_sk(tag);
            let g_sk = derive_sample_guarantor_sk(tag);
            let manifest = AnchorManifest {
                revision: 1,
                threshold: 1,
                servers: vec![ServerEntry {
                    write_url: format!("{}/sync.php", s1_url.trim_end_matches('/')),
                    read_url: format!("{}/humoco_sync_data", s1_url.trim_end_matches('/')),
                    admin_pub: s1_ap,
                    lock_pub: s1_lp,
                    nominated_by: NominatedBy::Creator,
                }],
                successors: vec![ServerEntry {
                    write_url: format!("{}/sync.php", s2_url.trim_end_matches('/')),
                    read_url: format!("{}/humoco_sync_data", s2_url.trim_end_matches('/')),
                    admin_pub: s2_ap,
                    lock_pub: s2_lp,
                    nominated_by: NominatedBy::Creator,
                }],
                authority: AnchorAuthority {
                    creator_mig_pub: c_sk.verifying_key().to_bytes(),
                    guarantor_mig_pubs: vec![g_sk.verifying_key().to_bytes()],
                },
                migration_chain: Vec::new(),
                issued_at_ms: 1_794_916_800_000,
                retain_until_quarter: quarter,
            };
            let anchor_id = manifest.rev1_anchor_id()?;
            Ok(serde_json::json!({
                "anchor_id": hex::encode(anchor_id),
                "anchor_tag": tag.unwrap_or(""),
                "manifest": manifest,
            })
            .to_string())
        }
        RotationTestCmd::MakePreFreeze { manifest_json } => {
            let v = read_json_value(&manifest_json)?;
            let manifest: AnchorManifest =
                serde_json::from_value(v.get("manifest").cloned().unwrap_or(v))
                    .map_err(|e| e.to_string())?;
            let anchor_id = manifest.rev1_anchor_id()?;
            Ok(serde_json::json!({
                "action": "pre_freeze",
                "anchor_id": hex::encode(anchor_id),
                "current_manifest": manifest,
            })
            .to_string())
        }
        RotationTestCmd::MakePropose { manifest_json, ts } => {
            let v = read_json_value(&manifest_json)?;
            let tag = v
                .get("anchor_tag")
                .and_then(|t| t.as_str())
                .filter(|s| !s.is_empty());
            let c_sk = derive_sample_creator_sk(tag);
            let manifest: AnchorManifest =
                serde_json::from_value(v.get("manifest").cloned().unwrap_or_else(|| v.clone()))
                    .map_err(|e| e.to_string())?;
            let anchor_id = manifest.rev1_anchor_id()?;
            let mut prop = MigrationProposal {
                anchor_id,
                from_rev: manifest.revision,
                to_rev: manifest.revision + 1,
                new_threshold: 1,
                new_servers: vec![manifest
                    .successors
                    .first()
                    .ok_or("Missing successor s2")?
                    .clone()],
                new_successors: Vec::new(),
                retain_until_quarter: manifest.retain_until_quarter,
                proposed_at: ts,
                initiator: ProposalInitiator::Creator,
                proposer_sig: None,
                guarantor_cosigs: Vec::new(),
            };
            let dig = prop.core_digest().map_err(|e| e.to_string())?;
            prop.proposer_sig = Some(c_sk.sign(&dig).to_bytes());
            Ok(serde_json::json!({
                "action": "propose",
                "proposal": prop,
                "current_manifest": manifest,
            })
            .to_string())
        }
        RotationTestCmd::MakeVeto {
            manifest_json,
            propose_json,
            ts,
        } => {
            let mv = read_json_value(&manifest_json)?;
            let tag = mv
                .get("anchor_tag")
                .and_then(|t| t.as_str())
                .filter(|s| !s.is_empty());
            let g_sk = derive_sample_guarantor_sk(tag);
            let pv = read_json_value(&propose_json)?;
            let prop: MigrationProposal =
                serde_json::from_value(pv["proposal"].clone()).map_err(|e| e.to_string())?;
            let prop_hash = prop.core_digest().map_err(|e| e.to_string())?;
            let mut veto = MigrationVeto {
                anchor_id: prop.anchor_id,
                from_rev: prop.from_rev,
                proposal_hash: prop_hash,
                vetoer_pub: g_sk.verifying_key().to_bytes(),
                vetoed_at: ts,
                sig: [0u8; 64],
            };
            veto.sig = g_sk.sign(&veto.digest()).to_bytes();
            Ok(serde_json::json!({
                "action": "veto",
                "veto": veto,
            })
            .to_string())
        }
        RotationTestCmd::VerifyFreeze {
            freeze_json,
            expected_lock_pub,
            min_entries,
        } => {
            let fv = read_json_value(&freeze_json)?;
            let exp: SnapshotExport =
                serde_json::from_value(fv.get("snapshot_export").cloned().unwrap_or(fv))
                    .map_err(|e| e.to_string())?;
            let expected_lp = humoco_proto::decode_hex_fixed::<32>(expected_lock_pub.trim())?;
            if exp.snapshot.lock_pub != expected_lp {
                return Err("Snapshot lock_pub mismatch".to_string());
            }
            if exp.entries.len() < min_entries {
                return Err(format!(
                    "Expected at least {min_entries} entries, got {}",
                    exp.entries.len()
                ));
            }
            let entries: Vec<LockEntry> = exp
                .entries
                .iter()
                .map(|h| LockEntry::from_wire_hex(h))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            let conflicts: Vec<Vec<LockEntry>> = exp
                .conflicts
                .iter()
                .map(|g| {
                    g.iter()
                        .map(|h| LockEntry::from_wire_hex(h))
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            exp.snapshot
                .verify_with_entries(&entries, &conflicts)
                .map_err(|e| e.to_string())?;
            Ok("verified_snapshot".to_string())
        }
        RotationTestCmd::MakeImport {
            manifest_json,
            propose_json,
            freeze_json,
        } => {
            let mv = read_json_value(&manifest_json)?;
            let manifest: AnchorManifest =
                serde_json::from_value(mv.get("manifest").cloned().unwrap_or(mv))
                    .map_err(|e| e.to_string())?;
            let pv = read_json_value(&propose_json)?;
            let prop: MigrationProposal =
                serde_json::from_value(pv["proposal"].clone()).map_err(|e| e.to_string())?;
            let fv = read_json_value(&freeze_json)?;
            let exp: SnapshotExport =
                serde_json::from_value(fv.get("snapshot_export").cloned().unwrap_or(fv))
                    .map_err(|e| e.to_string())?;
            Ok(serde_json::json!({
                "anchor_id": hex::encode(prop.anchor_id),
                "active_manifest": manifest,
                "proposal": prop,
                "snapshots": [exp],
                "quorum_certificates": [],
            })
            .to_string())
        }
        RotationTestCmd::VerifyImportAck {
            import_resp_json,
            expected_lock_pub,
        } => {
            let iv = read_json_value(&import_resp_json)?;
            let ack: ImportAck =
                serde_json::from_value(iv["import_ack"].clone()).map_err(|e| e.to_string())?;
            let expected_lp = humoco_proto::decode_hex_fixed::<32>(expected_lock_pub.trim())?;
            if ack.lock_pub != expected_lp {
                return Err("ImportAck lock_pub mismatch".to_string());
            }
            if !ack.verify() {
                return Err("ImportAck signature verification failed".to_string());
            }
            Ok(hex::encode(ack.imported_state_hash))
        }
        RotationTestCmd::MakeSignCommit {
            manifest_json: _,
            propose_json,
            import_resp_json,
        } => {
            let pv = read_json_value(&propose_json)?;
            let prop: MigrationProposal =
                serde_json::from_value(pv["proposal"].clone()).map_err(|e| e.to_string())?;
            let (ish_hex, acks) = match import_resp_json {
                Some(path) => {
                    let iv = read_json_value(&path)?;
                    let ack: ImportAck = serde_json::from_value(iv["import_ack"].clone())
                        .map_err(|e| e.to_string())?;
                    (hex::encode(ack.imported_state_hash), vec![ack])
                }
                None => (hex::encode([0u8; 32]), Vec::new()),
            };
            Ok(serde_json::json!({
                "action": "sign_commit",
                "anchor_id": hex::encode(prop.anchor_id),
                "proposal": prop,
                "imported_state_hash": ish_hex,
                "import_acks": acks,
            })
            .to_string())
        }
        RotationTestCmd::MakeFinalize {
            manifest_json,
            propose_json,
            import_resp_json,
            sign_commit_resp_json,
        } => {
            let mv = read_json_value(&manifest_json)?;
            let prev: AnchorManifest =
                serde_json::from_value(mv.get("manifest").cloned().unwrap_or(mv))
                    .map_err(|e| e.to_string())?;
            let pv = read_json_value(&propose_json)?;
            let prop: MigrationProposal =
                serde_json::from_value(pv["proposal"].clone()).map_err(|e| e.to_string())?;
            let iv = read_json_value(&import_resp_json)?;
            let ack: ImportAck =
                serde_json::from_value(iv["import_ack"].clone()).map_err(|e| e.to_string())?;
            let cv = read_json_value(&sign_commit_resp_json)?;
            let cs: CommitteeSignature = serde_json::from_value(cv["committee_signature"].clone())
                .map_err(|e| e.to_string())?;
            let cert = MigrationCert {
                anchor_id: prop.anchor_id,
                genesis_manifest: Some(Box::new(prev.clone())),
                proposal: prop,
                imported_state_hash: ack.imported_state_hash,
                import_acks: vec![ack],
                commit_sigs: vec![cs],
            };
            let (new_manifest, _) = cert
                .verify_step(&cert.anchor_id, &prev)
                .map_err(|e| e.to_string())?;
            verify_anchor_manifest_chain(&new_manifest, &cert.anchor_id)
                .map_err(|e| e.to_string())?;
            Ok(serde_json::json!({
                "action": "finalize",
                "anchor_id": hex::encode(cert.anchor_id),
                "new_manifest": new_manifest,
            })
            .to_string())
        }
        RotationTestCmd::VerifyManifest {
            manifest_json,
            expected_anchor_id,
            expected_rev,
            wrapped_field,
        } => {
            let mv = read_json_value(&manifest_json)?;
            let val = if let Some(field) = wrapped_field {
                mv.get(&field)
                    .cloned()
                    .ok_or_else(|| format!("Missing field {field}"))?
            } else {
                mv
            };
            let manifest: AnchorManifest =
                serde_json::from_value(val).map_err(|e| e.to_string())?;
            let anchor_id = humoco_proto::decode_hex_fixed::<32>(expected_anchor_id.trim())?;
            verify_anchor_manifest_chain(&manifest, &anchor_id).map_err(|e| e.to_string())?;
            if manifest.revision != expected_rev {
                return Err(format!(
                    "Expected revision {expected_rev}, got {}",
                    manifest.revision
                ));
            }
            Ok(format!("verified_rev_{}", manifest.revision))
        }
    })();

    match res {
        Ok(out) => {
            println!("{out}");
            0
        }
        Err(e) => {
            eprintln!("Rotation helper error: {e}");
            1
        }
    }
}

fn run_lock_gc(config_opt: Option<PathBuf>, now_secs: u64) -> i32 {
    let config_path = config_opt
        .or_else(|| std::env::var_os("HUMOCO_SYNC_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    let cfg = match Config::load_from_path(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            return 1;
        }
    };
    let state = match AppState::from_config(cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Database initialization error: {}", e);
            return 1;
        }
    };
    match state.db.run_lock_gc(now_secs) {
        Ok((purged_buckets, purged_inodes)) => {
            println!(
                "purged_buckets={} purged_inodes={}",
                purged_buckets, purged_inodes
            );
            0
        }
        Err(e) => {
            eprintln!("Lock GC failed: {}", e);
            1
        }
    }
}
