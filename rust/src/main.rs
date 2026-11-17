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
    format_admin_put_lock_delegate_message, format_admin_put_members_message,
    format_admin_put_revoke_message, format_admin_status_message, format_delete_account_message,
    format_lock_delegate_signature_message, hash_admin_token, leading_zero_bits,
    parse_member_message, random_hex, sha256_hex, unix_now, RevocationNotice,
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
    /// Generate signed LockDelegation JSON payload for PUT ?lock_delegate
    SignLockDelegate {
        #[arg(long)]
        sk: String,
        #[arg(long)]
        lock_pub: String,
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
        variant: String,
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
            let msg =
                format_lock_delegate_signature_message(&admin_pub_hex, lock_pub.trim(), issued);
            let sig_bytes = sk.sign(msg.as_bytes()).to_bytes();
            let del = LockDelegation {
                admin_pub: admin_pub_bytes,
                lock_pub: lock_pub_bytes,
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
            variant,
        } => run_make_lock_sample(
            &lock_pub,
            &admin_pub,
            quarter,
            ticket_json.as_ref(),
            &variant,
        ),
    }
}

fn run_make_lock_sample(
    lock_pub_hex: &str,
    admin_pub_hex: &str,
    quarter: u16,
    ticket_json_path: Option<&PathBuf>,
    variant: &str,
) -> i32 {
    use humoco_proto::{
        compute_root_mig_auth_digest, derive_bucket, derive_slot, derive_slot_file_id,
        hash_pubkey_sha3, solve_lock_pow, AnchorAuthority, AnchorManifest, CausalOutputProof,
        GenesisTicket, LockEntry, NominatedBy, ServerEntry, HOP_ENCRYPTED_PAYLOAD_LEN,
    };

    let Ok(lock_pub) = humoco_proto::decode_hex_fixed::<32>(lock_pub_hex.trim()) else {
        eprintln!("Invalid lock_pub");
        return 1;
    };
    let Ok(admin_pub) = humoco_proto::decode_hex_fixed::<32>(admin_pub_hex.trim()) else {
        eprintln!("Invalid admin_pub");
        return 1;
    };
    let creator_mig_sk = SigningKey::from_bytes(&[91u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let manifest = AnchorManifest {
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
        retain_until_quarter: quarter,
    };
    let anchor_id = match manifest.rev1_anchor_id() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("anchor_id error: {}", e);
            return 1;
        }
    };

    if variant == "anchor_id" {
        println!("{}", hex::encode(anchor_id));
        return 0;
    }

    let bucket = derive_bucket(&anchor_id, &lock_pub);
    let slot0 = derive_slot(&anchor_id, &[0x11; 32]);
    if variant == "read_path" {
        let q_str = humoco_proto::format_quarter(quarter).unwrap();
        let file_s = derive_slot_file_id(&slot0, &lock_pub);
        println!(
            "locks/{}/{}/{}.lock",
            q_str,
            hex::encode(bucket),
            hex::encode(file_s)
        );
        return 0;
    }

    let ticket_path = match ticket_json_path {
        Some(p) => p,
        None => {
            eprintln!("--ticket-json is required for variant '{}'", variant);
            return 1;
        }
    };
    let ticket_raw = match fs::read_to_string(ticket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ticket read error: {}", e);
            return 1;
        }
    };
    let ticket_val: serde_json::Value = match serde_json::from_str(&ticket_raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ticket parse error: {}", e);
            return 1;
        }
    };
    let ticket_inner = ticket_val.get("ticket").unwrap_or(&ticket_val);
    let ticket: GenesisTicket = match serde_json::from_value(ticket_inner.clone()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ticket decode error: {}", e);
            return 1;
        }
    };

    let genesis_sk = SigningKey::from_bytes(&[92u8; 32]);
    let genesis_pub = genesis_sk.verifying_key().to_bytes();
    let recv1_sk = SigningKey::from_bytes(&[93u8; 32]);
    let recv1_pub = recv1_sk.verifying_key().to_bytes();
    let recv1_hash = hash_pubkey_sha3(&recv1_pub);
    let child0 = if variant == "conflict" {
        [0x99; 32]
    } else {
        [0x11; 32]
    };
    let mut causal0 = CausalOutputProof {
        anchor_id,
        slot: slot0,
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
    let root_mig_digest = compute_root_mig_auth_digest(&anchor_id, &slot0, &genesis_pub);
    let root_mig_sig = creator_mig_sk.sign(&root_mig_digest).to_bytes();
    let pow0 = solve_lock_pow(&slot0, &child0, 0, 8, 0, 100_000).unwrap();
    let entry0 = LockEntry {
        slot: slot0,
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

    let entries = if variant == "conflict" {
        vec![entry0.to_wire_hex().unwrap()]
    } else {
        let slot1 = derive_slot(&anchor_id, &[0x22; 32]);
        let child1 = [0x22; 32];
        let recv2_hash = [0x77; 32];
        let mut causal1 = CausalOutputProof {
            anchor_id,
            slot: slot1,
            parent_slot: slot0,
            output_branch: 0,
            depth: 1,
            child_lock: child1,
            sender_pubkey: recv1_pub,
            receiver_pubkey_hash: recv2_hash,
            change_pubkey_hash: None,
            causal_sig: [0u8; 64],
        };
        causal1.causal_sig = recv1_sk.sign(&causal1.digest().unwrap()).to_bytes();
        let pow1 = solve_lock_pow(&slot1, &child1, 1, 8, 0, 100_000).unwrap();
        let entry1 = LockEntry {
            slot: slot1,
            parent_slot: slot0,
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
        "known_head_receipt": serde_json::Value::Null,
    });
    println!("{}", req);
    0
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
