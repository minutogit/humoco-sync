#![allow(dead_code)]

use std::net::SocketAddr;

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use tempfile::TempDir;

use humoco_sync_server::build_router;
use humoco_sync_server::config::Config;
use humoco_sync_server::crypto::{parse_member_message, random_hex, sha256_hex, unix_now};
use humoco_sync_server::state::AppState;

pub struct TestServer {
    pub base_url: String,
    pub state: AppState,
    pub client: reqwest::Client,
    _dir: TempDir,
}

impl TestServer {
    pub async fn start(mut cfg: Config) -> Self {
        let dir = TempDir::new().expect("create temp dir");
        cfg.server.db_path = dir.path().join("test.redb");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        cfg.server.bind = addr.to_string();
        cfg.server.public_base_url = format!("http://{}", addr);
        cfg.normalize();
        cfg.validate().expect("valid test config");

        let state = AppState::from_config(cfg).expect("init app state");
        let app = build_router(state.clone());
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client");

        Self {
            base_url: state.config.server.public_base_url.clone(),
            state,
            client,
            _dir: dir,
        }
    }
}

pub fn gen_keypair() -> (SigningKey, String) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_hex = hex::encode(sk.verifying_key().as_bytes());
    (sk, pk_hex)
}

pub fn base_hybrid_config(admin_pk: &str) -> Config {
    let mut cfg = Config::default();
    cfg.server.admin_pubkey = admin_pk.to_string();
    cfg.mode.enable_admin_app = true;
    cfg.mode.enable_public_registration = true;
    cfg.mode.registration_gates = vec!["open".to_string(), "code".to_string()];
    cfg.security.ip_requests_per_minute = 5000;
    cfg.security.pubkey_requests_per_minute = 5000;
    cfg.security.max_registrations_per_ipv4_24_per_day = 100;
    cfg.security.max_registrations_per_ipv6_48_per_day = 100;
    cfg
}

pub fn sign_member_headers(
    sk: &SigningKey,
    method: &str,
    channel: &str,
    prefix: &str,
    media_id: &str,
    ts: i64,
    body: &[u8],
) -> Vec<(&'static str, String)> {
    let pk = hex::encode(sk.verifying_key().as_bytes());
    let nonce = random_hex(16);
    let body_hash = sha256_hex(body);
    let target = if channel == "media" && !media_id.is_empty() {
        format!("media:{}", media_id)
    } else {
        channel.to_string()
    };
    let msg = parse_member_message(method, &target, prefix, ts, &nonce, &body_hash);
    let sig = hex::encode(sk.sign(msg.as_bytes()).to_bytes());
    let mut headers = vec![
        ("X-Drop-Pubkey", pk),
        ("X-Channel", channel.to_string()),
        ("X-Drop-Timestamp", ts.to_string()),
        ("X-Drop-Nonce", nonce),
        ("X-Drop-Signature", sig),
    ];
    if !prefix.is_empty() {
        headers.push(("X-Drop-Prefix", prefix.to_string()));
    }
    if !media_id.is_empty() {
        headers.push(("X-Media-Id", media_id.to_string()));
    }
    headers
}

#[allow(clippy::too_many_arguments)]
pub fn sign_lock_entry_helper(
    anchor_id: [u8; 32],
    ds_tag: [u8; 32],
    parent_slot: [u8; 32],
    output_branch: u8,
    depth: u32,
    child_lock: [u8; 32],
    sender_sk: &SigningKey,
    receiver_pubkey_hash: [u8; 32],
    change_pubkey_hash: Option<[u8; 32]>,
    creator_mig_sk: Option<&SigningKey>,
    pow_base_bits: u32,
) -> humoco_proto::LockEntry {
    let slot = humoco_proto::derive_slot(&anchor_id, &ds_tag);
    let sender_pub = sender_sk.verifying_key().to_bytes();
    let mut causal = humoco_proto::CausalOutputProof {
        anchor_id,
        slot,
        parent_slot,
        output_branch,
        depth,
        child_lock,
        sender_pubkey: sender_pub,
        receiver_pubkey_hash,
        change_pubkey_hash,
        causal_sig: [0u8; 64],
    };
    causal.causal_sig = sender_sk.sign(&causal.digest().unwrap()).to_bytes();
    let root_mig_sig = if depth == 0 {
        let mig_sk = creator_mig_sk.expect("creator_mig_sk required at depth 0");
        let d = humoco_proto::compute_root_mig_auth_digest(&anchor_id, &slot, &sender_pub);
        Some(mig_sk.sign(&d).to_bytes())
    } else {
        None
    };
    let req_bits = humoco_proto::required_lock_pow_bits(pow_base_bits, depth);
    let pow_nonce =
        humoco_proto::solve_lock_pow(&slot, &child_lock, depth, req_bits, 0, 500_000).unwrap();
    humoco_proto::LockEntry {
        slot,
        parent_slot,
        output_branch,
        depth,
        child_lock,
        sender_pubkey: sender_pub,
        receiver_pubkey_hash,
        change_pubkey_hash,
        causal_sig: causal.causal_sig,
        root_mig_sig,
        encrypted_payload: [0x5A; humoco_proto::HOP_ENCRYPTED_PAYLOAD_LEN],
        pow_nonce,
    }
}

pub fn build_single_server_manifest(
    admin_pub: [u8; 32],
    lock_pub: [u8; 32],
    creator_mig_pub: [u8; 32],
    retain_until_quarter: u16,
) -> humoco_proto::AnchorManifest {
    humoco_proto::AnchorManifest {
        revision: 1,
        threshold: 1,
        servers: vec![humoco_proto::ServerEntry {
            write_url: "https://sync1.example/sync.php".to_string(),
            read_url: "https://sync1.example/humoco_sync_data".to_string(),
            admin_pub,
            lock_pub,
            nominated_by: humoco_proto::NominatedBy::Creator,
        }],
        successors: Vec::new(),
        authority: humoco_proto::AnchorAuthority {
            creator_mig_pub,
            guarantor_mig_pubs: Vec::new(),
        },
        migration_chain: Vec::new(),
        issued_at_ms: 1_794_916_800_000,
        retain_until_quarter,
    }
}

pub async fn fetch_ticket_signed(
    srv: &TestServer,
    caller_sk: &SigningKey,
    anchor_id: [u8; 32],
    retain_until_quarter: u16,
) -> (u16, serde_json::Value) {
    let body = serde_json::to_vec(&serde_json::json!({
        "anchor_id": hex::encode(anchor_id),
        "retain_until_quarter": retain_until_quarter,
        "pow_timestamp": serde_json::Value::Null,
        "pow_nonce": serde_json::Value::Null,
    }))
    .unwrap();
    let ts = unix_now() as i64;
    let nonce = random_hex(16);
    let pk_hex = hex::encode(caller_sk.verifying_key().as_bytes());
    let msg = parse_member_message("POST", "lock_ticket", "", ts, &nonce, &sha256_hex(&body));
    let sig = hex::encode(caller_sk.sign(msg.as_bytes()).to_bytes());
    let resp = srv
        .client
        .post(format!("{}/sync.php?lock_ticket", srv.base_url))
        .header("X-Drop-Pubkey", pk_hex)
        .header("X-Drop-Timestamp", ts.to_string())
        .header("X-Drop-Nonce", nonce)
        .header("X-Drop-Signature", sig)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let code = resp.status().as_u16();
    let val: serde_json::Value = resp.json().await.unwrap();
    (code, val)
}

pub fn server_entry_for_test(
    srv: &TestServer,
    admin_sk: &SigningKey,
    nominated_by: humoco_proto::NominatedBy,
) -> humoco_proto::ServerEntry {
    humoco_proto::ServerEntry {
        write_url: format!("{}/sync.php", srv.base_url),
        read_url: format!("{}/humoco_sync_data", srv.base_url),
        admin_pub: admin_sk.verifying_key().to_bytes(),
        lock_pub: srv.state.db.lock_pubkey_bytes().unwrap(),
        nominated_by,
    }
}

pub fn build_multi_server_manifest(
    servers: Vec<humoco_proto::ServerEntry>,
    successors: Vec<humoco_proto::ServerEntry>,
    threshold: u8,
    creator_mig_pub: [u8; 32],
    guarantor_mig_pubs: Vec<[u8; 32]>,
    issued_at_ms: u64,
    retain_until_quarter: u16,
) -> humoco_proto::AnchorManifest {
    humoco_proto::AnchorManifest {
        revision: 1,
        threshold,
        servers,
        successors,
        authority: humoco_proto::AnchorAuthority {
            creator_mig_pub,
            guarantor_mig_pubs,
        },
        migration_chain: Vec::new(),
        issued_at_ms,
        retain_until_quarter,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_signed_proposal(
    anchor_id: [u8; 32],
    from_rev: u64,
    new_threshold: u8,
    new_servers: Vec<humoco_proto::ServerEntry>,
    new_successors: Vec<humoco_proto::ServerEntry>,
    retain_until_quarter: u16,
    proposed_at: u64,
    initiator: humoco_proto::ProposalInitiator,
    signer_sk: Option<&SigningKey>,
    cosigs: Vec<(&SigningKey, u8)>,
) -> humoco_proto::MigrationProposal {
    let mut prop = humoco_proto::MigrationProposal {
        anchor_id,
        from_rev,
        to_rev: from_rev + 1,
        new_threshold,
        new_servers,
        new_successors,
        retain_until_quarter,
        proposed_at,
        initiator,
        proposer_sig: None,
        guarantor_cosigs: Vec::new(),
    };
    let digest = prop.core_digest().unwrap();
    if let Some(sk) = signer_sk {
        prop.proposer_sig = Some(sk.sign(&digest).to_bytes());
    }
    for (g_sk, g_idx) in cosigs {
        prop.guarantor_cosigs.push(humoco_proto::GuarantorCosig {
            guarantor_index: g_idx,
            sig: g_sk.sign(&digest).to_bytes(),
        });
    }
    prop
}

pub async fn start_lock_test_server(
    allow_pow_tickets: bool,
    timelock_secs: Option<u64>,
) -> (SigningKey, String, TestServer) {
    let (admin_sk, admin_pk) = gen_keypair();
    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.allow_pow_tickets = allow_pow_tickets;
    cfg.lock.ticket_pow_bits = 8;
    if let Some(tl) = timelock_secs {
        cfg.lock.proposal_timelock_secs = tl;
    }
    let srv = TestServer::start(cfg).await;
    (admin_sk, admin_pk, srv)
}

pub async fn issue_pow_ticket_http(
    srv: &TestServer,
    anchor_id: [u8; 32],
    quarter: u16,
) -> humoco_proto::GenesisTicket {
    let now = unix_now();
    let nonce = humoco_proto::solve_ticket_pow(&anchor_id, quarter, now, 8, 0, 200_000).unwrap();
    let resp = srv
        .client
        .post(format!("{}/sync.php?lock_ticket", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "retain_until_quarter": quarter,
            "pow_timestamp": now,
            "pow_nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let val: serde_json::Value = resp.json().await.unwrap();
    serde_json::from_value(val["ticket"].clone()).unwrap()
}

pub fn issue_pow_ticket_db(
    srv: &TestServer,
    anchor_id: [u8; 32],
    quarter: u16,
    now: u64,
) -> humoco_proto::GenesisTicket {
    let nonce = humoco_proto::solve_ticket_pow(&anchor_id, quarter, now, 8, 0, 200_000).unwrap();
    srv.state
        .db
        .issue_genesis_ticket(
            &srv.state.config,
            humoco_sync_server::locks::TicketCallerAuth::UnauthenticatedPow,
            humoco_sync_server::locks::LockTicketRequest {
                anchor_id,
                retain_until_quarter: quarter,
                pow_timestamp: Some(now),
                pow_nonce: Some(nonce),
            },
            now,
        )
        .unwrap()
}

pub fn verify_selftest_report_sig(report: &serde_json::Value) {
    let runtime = report["runtime"].as_str().unwrap();
    let checked_at = report["checked_at"].as_u64().unwrap();
    let lock_pub = report["lock_pub"].as_str().unwrap();
    let all_passed = report["all_passed"].as_bool().unwrap();
    let free_inodes = report["free_inodes"].as_u64().unwrap();
    let c = &report["checks"];
    let checks_line = format!(
        "{},{},{},{},{},{},{},{},{}",
        c["ext_sodium"].as_str().unwrap(),
        c["sha3_256"].as_str().unwrap(),
        c["atomic_link_eexist"].as_str().unwrap(),
        c["fsync"].as_str().unwrap(),
        c["ignore_user_abort"].as_str().unwrap(),
        c["storage_writable"].as_str().unwrap(),
        c["inode_budget"].as_str().unwrap(),
        c["fastcgi_finish_request"].as_str().unwrap(),
        free_inodes
    );
    let checks_digest_hex = sha256_hex(checks_line.as_bytes());
    let msg = humoco_sync_server::crypto::format_lock_selftest_signature_message(
        runtime,
        checked_at,
        lock_pub,
        all_passed,
        &checks_digest_hex,
    );
    assert!(
        humoco_sync_server::crypto::verify_ed25519_hex(
            lock_pub,
            report["sig"].as_str().unwrap(),
            msg.as_bytes(),
        ),
        "SelftestReport Ed25519 signature must verify cleanly"
    );
}
