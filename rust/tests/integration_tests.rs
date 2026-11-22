use std::collections::BTreeMap;
use std::net::SocketAddr;

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use tempfile::TempDir;

use humoco_sync_server::build_router;
use humoco_sync_server::config::{ChannelQuotaConfig, Config, ProfileConfig};
use humoco_sync_server::crypto::{
    canonical_revocation_message, format_admin_put_config_message,
    format_admin_put_members_message, format_admin_put_revoke_message, format_admin_status_message,
    format_delete_account_message, parse_member_message, random_hex, sha256_hex, unix_now,
    RevocationNotice, RevocationReplacementTarget,
};
use humoco_sync_server::db::ConditionalPrecondition;
use humoco_sync_server::state::AppState;

struct TestServer {
    base_url: String,
    state: AppState,
    client: reqwest::Client,
    _dir: TempDir,
}

impl TestServer {
    async fn start(mut cfg: Config) -> Self {
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

fn gen_keypair() -> (SigningKey, String) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_hex = hex::encode(sk.verifying_key().as_bytes());
    (sk, pk_hex)
}

fn base_hybrid_config(admin_pk: &str) -> Config {
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

fn sign_member_headers(
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

#[tokio::test]
async fn test_1_wire_parity_and_delete_account() {
    let (admin_sk, admin_pk) = gen_keypair();
    let (friend_sk, friend_pk) = gen_keypair();
    let (other_sk, _other_pk) = gen_keypair();

    let srv = TestServer::start(base_hybrid_config(&admin_pk)).await;
    let now = unix_now() as i64;

    // 1. /sync.php?info and /sync?info parity
    let info_php: serde_json::Value = srv
        .client
        .get(format!("{}/sync.php?info", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let info_clean: serde_json::Value = srv
        .client
        .get(format!("{}/sync?info", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info_php, info_clean);
    assert_eq!(info_php["drop_pub"], admin_pk);
    assert_eq!(
        info_php["register_url"],
        format!("{}/register", srv.base_url)
    );

    // 2. Unauthorized HEAD
    let head_unauth = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &friend_pk)
        .header("X-Channel", "card")
        .send()
        .await
        .unwrap();
    assert_eq!(head_unauth.status().as_u16(), 200);
    assert_eq!(
        head_unauth
            .headers()
            .get("X-Drop-Authorized")
            .unwrap()
            .to_str()
            .unwrap(),
        "false"
    );

    // 3. Admin PUT ?members on /sync.php -> authorizes friend_pk
    let members_body = serde_json::to_vec(&serde_json::json!({ "pubkeys": [friend_pk] })).unwrap();
    let nonce = random_hex(16);
    let sig = hex::encode(
        admin_sk
            .sign(
                format_admin_put_members_message("card", now, &nonce, &sha256_hex(&members_body))
                    .as_bytes(),
            )
            .to_bytes(),
    );
    let pm_resp = srv
        .client
        .put(format!("{}/sync.php?members&channel=card", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &nonce)
        .header("X-Drop-Signature", &sig)
        .body(members_body)
        .send()
        .await
        .unwrap();
    assert_eq!(pm_resp.status().as_u16(), 200);

    let head_auth = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &friend_pk)
        .header("X-Channel", "card")
        .send()
        .await
        .unwrap();
    assert_eq!(head_auth.status().as_u16(), 200);
    assert_eq!(
        head_auth
            .headers()
            .get("X-Drop-Authorized")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );
    assert_eq!(
        head_auth
            .headers()
            .get("X-Channel-Max-Bytes")
            .unwrap()
            .to_str()
            .unwrap(),
        "1048576"
    );
    assert_eq!(
        head_auth
            .headers()
            .get("X-Slot-Occupied")
            .unwrap()
            .to_str()
            .unwrap(),
        "false"
    );

    // Replay same nonce -> 409 Conflict
    let nonce_replay_body =
        serde_json::to_vec(&serde_json::json!({ "pubkeys": [friend_pk] })).unwrap();
    let replay_resp = srv
        .client
        .put(format!("{}/sync.php?members&channel=card", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &nonce)
        .header("X-Drop-Signature", &sig)
        .body(nonce_replay_body)
        .send()
        .await
        .unwrap();
    assert_eq!(replay_resp.status().as_u16(), 409);

    // 4. Friend PUT /sync with X-Drop-Prefix + If-None-Match: * + ETag + 304 + 412
    let payload_v1 = b"encrypted-card-v1".to_vec();
    let mut req = srv
        .client
        .put(format!("{}/sync", srv.base_url))
        .header("If-None-Match", "*");
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "home", "", now, &payload_v1) {
        req = req.header(k, v);
    }
    let put_v1 = req.body(payload_v1.clone()).send().await.unwrap();
    assert_eq!(put_v1.status().as_u16(), 200);
    let put_v1_json: serde_json::Value = put_v1.json().await.unwrap();
    let etag1 = put_v1_json["etag"].as_str().unwrap().to_string();

    // If-None-Match: * fails with 412 when already exists
    let mut req_inm = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .header("If-None-Match", "*");
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "home", "", now, &payload_v1) {
        req_inm = req_inm.header(k, v);
    }
    assert_eq!(
        req_inm
            .body(payload_v1.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        412
    );

    // Wrong If-Match -> 412
    let payload_v2 = b"encrypted-card-v2".to_vec();
    let mut req_bad_im = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .header("If-Match", "\"deadbeef\"");
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "home", "", now, &payload_v2) {
        req_bad_im = req_bad_im.header(k, v);
    }
    assert_eq!(
        req_bad_im
            .body(payload_v2.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        412
    );

    // Valid If-Match -> 200
    let mut req_good_im = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .header("If-Match", format!("\"{}\"", etag1));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "home", "", now, &payload_v2) {
        req_good_im = req_good_im.header(k, v);
    }
    let put_v2 = req_good_im.body(payload_v2.clone()).send().await.unwrap();
    assert_eq!(put_v2.status().as_u16(), 200);
    let etag2 = put_v2.json::<serde_json::Value>().await.unwrap()["etag"]
        .as_str()
        .unwrap()
        .to_string();

    // Static GET + If-None-Match -> 304
    let slot_url = format!(
        "{}/humoco_sync_data/{}_home.card.bin",
        srv.base_url, friend_pk
    );
    let get_blob = srv.client.get(&slot_url).send().await.unwrap();
    assert_eq!(get_blob.status().as_u16(), 200);
    assert_eq!(
        get_blob.bytes().await.unwrap().as_ref(),
        payload_v2.as_slice()
    );

    let get_304 = srv
        .client
        .get(&slot_url)
        .header("If-None-Match", format!("\"{}\"", etag2))
        .send()
        .await
        .unwrap();
    assert_eq!(get_304.status().as_u16(), 304);

    // 5. Timestamp drift -> 401
    let mut req_old = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "", "", now - 300, &payload_v1) {
        req_old = req_old.header(k, v);
    }
    assert_eq!(
        req_old
            .body(payload_v1.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );

    // 6. Media channel upload, ownership enforcement, fetch, and delete
    let media_id = sha256_hex(b"blob-1");
    let media_bytes = b"encrypted-webp-payload".to_vec();
    let mut req_m = srv.client.put(format!("{}/sync", srv.base_url));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "media", "", &media_id, now, &media_bytes)
    {
        req_m = req_m.header(k, v);
    }
    assert_eq!(
        req_m
            .body(media_bytes.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // Authorize other user via open gate and verify they CANNOT overwrite friend's media_id (403)
    srv.client
        .post(format!("{}/register/open", srv.base_url))
        .form(&[("pubkey", hex::encode(other_sk.verifying_key().as_bytes()))])
        .send()
        .await
        .unwrap();
    let mut req_hijack = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&other_sk, "PUT", "media", "", &media_id, now, b"hijack") {
        req_hijack = req_hijack.header(k, v);
    }
    assert_eq!(
        req_hijack
            .body(b"hijack".to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );

    // 7. Revocation lifecycle (set -> 410 Gone -> revocation.json -> clear with effective_at: null)
    let mut notice = RevocationNotice {
        drop_pub: admin_pk.clone(),
        issued_at: now as u64,
        effective_at: (now + 60) as u64,
        reason: Some("Migrating server".to_string()),
        replacement: None,
        signature: String::new(),
    };
    notice.signature = hex::encode(
        admin_sk
            .sign(canonical_revocation_message(&notice).as_bytes())
            .to_bytes(),
    );
    let rev_body = serde_json::to_vec(&notice).unwrap();
    let rev_nonce = random_hex(16);
    let rev_sig = hex::encode(
        admin_sk
            .sign(
                format_admin_put_revoke_message(now, &rev_nonce, &sha256_hex(&rev_body)).as_bytes(),
            )
            .to_bytes(),
    );
    let rev_resp = srv
        .client
        .put(format!("{}/sync.php?revoke", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &rev_nonce)
        .header("X-Drop-Signature", &rev_sig)
        .body(rev_body)
        .send()
        .await
        .unwrap();
    assert_eq!(rev_resp.status().as_u16(), 200);

    let gone_head = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &friend_pk)
        .send()
        .await
        .unwrap();
    assert_eq!(gone_head.status().as_u16(), 410);

    let rev_json_resp = srv
        .client
        .get(format!("{}/humoco_sync_data/revocation.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(rev_json_resp.status().as_u16(), 200);

    // Clear revocation using human-money-app payload shape
    let clear_body = serde_json::to_vec(&serde_json::json!({
        "issued_at": now,
        "effective_at": null
    }))
    .unwrap();
    let clr_nonce = random_hex(16);
    let clr_sig = hex::encode(
        admin_sk
            .sign(
                format_admin_put_revoke_message(now, &clr_nonce, &sha256_hex(&clear_body))
                    .as_bytes(),
            )
            .to_bytes(),
    );
    let clr_resp = srv
        .client
        .put(format!("{}/sync.php?revoke", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &clr_nonce)
        .header("X-Drop-Signature", &clr_sig)
        .body(clear_body)
        .send()
        .await
        .unwrap();
    assert_eq!(clr_resp.status().as_u16(), 200);

    // 8. Admin GET ?status
    let st_nonce = random_hex(16);
    let st_sig = hex::encode(
        admin_sk
            .sign(format_admin_status_message(now, &st_nonce).as_bytes())
            .to_bytes(),
    );
    let st_resp = srv
        .client
        .get(format!("{}/sync.php?status", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &st_nonce)
        .header("X-Drop-Signature", &st_sig)
        .send()
        .await
        .unwrap();
    assert_eq!(st_resp.status().as_u16(), 200);

    // 9. Cryptographic DELETE /sync.php?account wipes friend's slots & media
    let del_nonce = random_hex(16);
    let del_sig = hex::encode(
        friend_sk
            .sign(format_delete_account_message(now, &del_nonce).as_bytes())
            .to_bytes(),
    );
    let del_resp = srv
        .client
        .delete(format!("{}/sync.php?account", srv.base_url))
        .header("X-Drop-Pubkey", &friend_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &del_nonce)
        .header("X-Drop-Signature", &del_sig)
        .send()
        .await
        .unwrap();
    assert_eq!(del_resp.status().as_u16(), 200);
    let del_json: serde_json::Value = del_resp.json().await.unwrap();
    assert_eq!(del_json["deleted_slots"], 1);
    assert_eq!(del_json["deleted_media"], 1);
    assert_eq!(
        srv.client
            .get(&slot_url)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );

    // 10. Pure-public server (enable_admin_app = false, admin_pubkey = "") still emits valid 64-hex drop_pub
    let mut pub_cfg = Config::default();
    pub_cfg.mode.enable_admin_app = false;
    pub_cfg.mode.enable_public_registration = true;
    pub_cfg.mode.registration_gates = vec!["open".to_string()];
    let pub_srv = TestServer::start(pub_cfg).await;
    let pub_info: serde_json::Value = pub_srv
        .client
        .get(format!("{}/sync.php?info", pub_srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let dp = pub_info["drop_pub"].as_str().unwrap();
    assert_eq!(dp.len(), 64);
    let dp_bytes: [u8; 32] = hex::decode(dp).unwrap().try_into().unwrap();
    assert!(ed25519_dalek::VerifyingKey::from_bytes(&dp_bytes).is_ok());
}

#[tokio::test]
async fn test_2_hybrid_isolation_and_index_json_privacy() {
    let (admin_sk, admin_pk) = gen_keypair();
    let (friend_sk, friend_pk) = gen_keypair();
    let (public_sk, public_pk) = gen_keypair();

    let srv = TestServer::start(base_hybrid_config(&admin_pk)).await;
    let now = unix_now() as i64;

    // Friend A authorized via admin PUT ?members
    let members_body = serde_json::to_vec(&serde_json::json!({ "pubkeys": [friend_pk] })).unwrap();
    let nonce = random_hex(16);
    let sig = hex::encode(
        admin_sk
            .sign(
                format_admin_put_members_message("card", now, &nonce, &sha256_hex(&members_body))
                    .as_bytes(),
            )
            .to_bytes(),
    );
    srv.client
        .put(format!("{}/sync.php?members&channel=card", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &nonce)
        .header("X-Drop-Signature", &sig)
        .body(members_body)
        .send()
        .await
        .unwrap();

    // User B registered via /register/open
    let reg_resp = srv
        .client
        .post(format!("{}/register/open", srv.base_url))
        .form(&[("pubkey", public_pk.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(reg_resp.status().as_u16(), 303);

    // Both upload card and media
    for (sk, tag) in [
        (&friend_sk, b"friend-card".as_slice()),
        (&public_sk, b"public-card".as_slice()),
    ] {
        let mut req = srv.client.put(format!("{}/sync.php", srv.base_url));
        for (k, v) in sign_member_headers(sk, "PUT", "card", "", "", now, tag) {
            req = req.header(k, v);
        }
        assert_eq!(
            req.body(tag.to_vec())
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            200
        );

        let mid = sha256_hex(tag);
        let mut req_m = srv.client.put(format!("{}/sync.php", srv.base_url));
        for (k, v) in sign_member_headers(sk, "PUT", "media", "", &mid, now, tag) {
            req_m = req_m.header(k, v);
        }
        assert_eq!(
            req_m
                .body(tag.to_vec())
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            200
        );
    }

    // index.json must contain ONLY Friend A's card, never User B, never media
    let idx: Vec<serde_json::Value> = srv
        .client
        .get(format!("{}/humoco_sync_data/index.json", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(idx.len(), 1);
    assert_eq!(idx[0]["id"], friend_pk);
    assert_eq!(idx[0]["channel"], "card");

    // Public User B's direct O(1) fetch succeeds
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.card.bin",
                srv.base_url, public_pk
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // Remove ALL admin_app friends via PUT ?members {"pubkeys":[]}
    let empty_body = serde_json::to_vec(&serde_json::json!({ "pubkeys": [] })).unwrap();
    let n2 = random_hex(16);
    let s2 = hex::encode(
        admin_sk
            .sign(
                format_admin_put_members_message("card", now, &n2, &sha256_hex(&empty_body))
                    .as_bytes(),
            )
            .to_bytes(),
    );
    srv.client
        .put(format!("{}/sync.php?members&channel=card", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &n2)
        .header("X-Drop-Signature", &s2)
        .body(empty_body)
        .send()
        .await
        .unwrap();

    // Friend A's slot is pruned & index.json is empty
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.card.bin",
                srv.base_url, friend_pk
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    let idx_after: Vec<serde_json::Value> = srv
        .client
        .get(format!("{}/humoco_sync_data/index.json", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(idx_after.is_empty());

    // Public User B remains authorized & intact!
    let head_b = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &public_pk)
        .send()
        .await
        .unwrap();
    assert_eq!(
        head_b
            .headers()
            .get("X-Drop-Authorized")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.card.bin",
                srv.base_url, public_pk
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    let mid_b = sha256_hex(b"public-card");
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv.base_url, mid_b
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
}

#[tokio::test]
async fn test_3_pool_isolation_and_prio3_media_eviction() {
    let (_, admin_pk) = gen_keypair();
    let (_, free1) = gen_keypair();
    let (_, free2) = gen_keypair();
    let (_, free3) = gen_keypair();
    let (_, friend_pk) = gen_keypair();
    let (_, pro_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.storage.max_total_storage_mb = 2; // 2 MiB total server storage
    cfg.storage.max_free_pool_mb = 1; // 1 MiB isolated free pool
    cfg.profiles.insert(
        "tight_pro".to_string(),
        ProfileConfig {
            display_name: "Tight Pro".to_string(),
            max_total_bytes: 200_000,
            is_free_pool: false,
            store_contact_email: false,
            channels: BTreeMap::from([
                (
                    "backup".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 150_000,
                        ttl_days: 0,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "card".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 150_000,
                        ttl_days: 0,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "media".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 120_000,
                        ttl_days: 0,
                        max_user_count: Some(4),
                        max_user_bytes: Some(200_000),
                    },
                ),
            ]),
        },
    );

    let srv = TestServer::start(cfg.clone()).await;
    let db = &srv.state.db;
    let now = unix_now();

    db.put_admin_members(
        &srv.state.config,
        "card",
        std::slice::from_ref(&friend_pk),
        now,
    )
    .unwrap();
    db.register_or_upgrade_user(&srv.state.config, &free1, "free", None, None, "open", now)
        .unwrap();
    db.register_or_upgrade_user(&srv.state.config, &free2, "free", None, None, "open", now)
        .unwrap();
    db.register_or_upgrade_user(&srv.state.config, &free3, "free", None, None, "open", now)
        .unwrap();
    db.register_or_upgrade_user(
        &srv.state.config,
        &pro_pk,
        "tight_pro",
        None,
        None,
        "admin",
        now,
    )
    .unwrap();

    // Pro uploads media before free pool fills -> Free users must NEVER evict Pro media
    let pro_m_id = sha256_hex(b"pro-media");
    db.put_media(
        &srv.state.config,
        &pro_pk,
        &pro_m_id,
        &vec![1u8; 80_000],
        &ConditionalPrecondition::None,
        now,
    )
    .unwrap();

    // Free1 + Free2 fill 1 MiB free pool (500 KB + 500 KB = 1,000,000 bytes)
    db.put_slot(
        &srv.state.config,
        &free1,
        "card",
        None,
        &vec![2u8; 500_000],
        &ConditionalPrecondition::None,
        now,
    )
    .unwrap();
    db.put_slot(
        &srv.state.config,
        &free2,
        "card",
        None,
        &vec![3u8; 500_000],
        &ConditionalPrecondition::None,
        now,
    )
    .unwrap();

    // Free3 tries 100 KB -> exceeds 1 MiB free pool -> must return 507
    let err = db
        .put_slot(
            &srv.state.config,
            &free3,
            "card",
            None,
            &vec![4u8; 100_000],
            &ConditionalPrecondition::None,
            now,
        )
        .unwrap_err();
    assert!(err.to_string().contains("507"));

    // Friend A (non-free) STILL succeeds -> zero starvation!
    db.put_slot(
        &srv.state.config,
        &friend_pk,
        "card",
        None,
        &vec![5u8; 200_000],
        &ConditionalPrecondition::None,
        now,
    )
    .unwrap();
    // Pro media is untouched
    assert!(db
        .get_media_blob(&srv.state.config, &pro_m_id, now)
        .unwrap()
        .is_some());

    // Pro uploads second 90 KB media (80+90=170 KB <= 200 KB acct cap)
    let pro_m2_id = sha256_hex(b"pro-media-2");
    db.put_media(
        &srv.state.config,
        &pro_pk,
        &pro_m2_id,
        &vec![6u8; 90_000],
        &ConditionalPrecondition::None,
        now + 10,
    )
    .unwrap();

    // Pro uploads Prio-1 backup of 100 KB (170+100=270 KB > 200 KB) -> automatically evicts oldest Prio-3 media (pro_m_id)!
    let backup_out = db
        .put_slot(
            &srv.state.config,
            &pro_pk,
            "backup",
            None,
            &vec![7u8; 100_000],
            &ConditionalPrecondition::None,
            now + 20,
        )
        .unwrap();
    assert!(backup_out.evicted_media >= 1);
    assert!(db
        .get_media_blob(&srv.state.config, &pro_m_id, now + 20)
        .unwrap()
        .is_none());
    assert!(db
        .get_media_blob(&srv.state.config, &pro_m2_id, now + 20)
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn test_4_zero_pii_email_codes_downgrade_and_safe_deletion() {
    let (_, admin_pk) = gen_keypair();
    let (_, k1_pk) = gen_keypair();
    let (_, k2_pk) = gen_keypair();

    let bearer_secret = "super-secret-webhook-token";
    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.mode.registration_gates = vec!["email".to_string(), "code".to_string()];
    cfg.email.enabled = true;
    cfg.email.transport = "log".to_string();
    cfg.storage.downgrade_grace_days = 7;
    cfg.security.api_bearer_token_hash = format!("sha256:{}", sha256_hex(bearer_secret.as_bytes()));

    let srv = TestServer::start(cfg).await;

    // 1. Register via Zero-PII Email Double-Opt-In
    let email_resp = srv
        .client
        .post(format!("{}/register/email", srv.base_url))
        .form(&[
            ("pubkey", k1_pk.as_str()),
            ("email", "Alice.User@googlemail.com"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(email_resp.status().as_u16(), 303);

    // Confirm not active before clicking link
    let pre_head = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &k1_pk)
        .send()
        .await
        .unwrap();
    assert_eq!(
        pre_head
            .headers()
            .get("X-Drop-Authorized")
            .unwrap()
            .to_str()
            .unwrap(),
        "false"
    );

    let mails = srv.state.mailer.take_recorded();
    assert_eq!(mails.len(), 1);
    let confirm_url = mails[0]
        .body
        .lines()
        .find(|l| l.starts_with("http://"))
        .unwrap()
        .trim()
        .to_string();

    let conf_resp = srv.client.get(&confirm_url).send().await.unwrap();
    assert_eq!(conf_resp.status().as_u16(), 303);

    let post_head = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &k1_pk)
        .send()
        .await
        .unwrap();
    assert_eq!(
        post_head
            .headers()
            .get("X-Drop-Authorized")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );

    // Zero-PII GDPR verification: email_hmac set, plaintext/encrypted email absent!
    let rec = srv.state.db.get_registered_user(&k1_pk).unwrap().unwrap();
    assert!(rec.email_hmac.is_some());
    assert!(rec.encrypted_contact_email.is_none());

    // Gmail dot/plus canonical duplicate blocked
    let dup_resp = srv
        .client
        .post(format!("{}/register/email", srv.base_url))
        .form(&[
            ("pubkey", k2_pk.as_str()),
            ("email", "aliceuser+test@gmail.com"),
        ])
        .send()
        .await
        .unwrap();
    let dup_loc = dup_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(dup_loc.contains("already+linked") || dup_loc.contains("err="));
    assert!(srv.state.mailer.take_recorded().is_empty());

    // 2. Bearer Admin API creates PRO code -> User redeems via /register/redeem
    let code_resp = srv
        .client
        .post(format!("{}/api/v1/admin/codes", srv.base_url))
        .header("Authorization", format!("Bearer {}", bearer_secret))
        .json(&serde_json::json!({
            "count": 1,
            "profile": "pro",
            "duration_days": 30,
            "note": "order-42"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(code_resp.status().as_u16(), 201);
    let code_json: serde_json::Value = code_resp.json().await.unwrap();
    let code = code_json["codes"][0]["code"].as_str().unwrap().to_string();

    let redeem_resp = srv
        .client
        .post(format!("{}/register/redeem", srv.base_url))
        .form(&[("pubkey", k1_pk.as_str()), ("code", code.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(redeem_resp.status().as_u16(), 303);

    let user_summary: serde_json::Value = srv
        .client
        .get(format!("{}/api/v1/admin/users/{}", srv.base_url, k1_pk))
        .header("Authorization", format!("Bearer {}", bearer_secret))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(user_summary["profile"], "pro");
    let valid_until = user_summary["valid_until"].as_u64().unwrap();

    // 3. Graceful Downgrade check: 2 days past valid_until -> still pro (in_grace_period = true)
    let in_grace = srv
        .state
        .db
        .resolve_member_access(&srv.state.config, &k1_pk, valid_until + 2 * 86_400)
        .unwrap()
        .unwrap();
    assert_eq!(in_grace.profile_name, "pro");
    assert!(in_grace.in_grace_period);

    // 8 days past valid_until (> 7d grace) + maintenance -> downgraded cleanly to free
    let after_grace_now = valid_until + 8 * 86_400;
    srv.state
        .db
        .run_maintenance(&srv.state.config, after_grace_now)
        .unwrap();
    let downgraded = srv.state.db.get_registered_user(&k1_pk).unwrap().unwrap();
    assert_eq!(downgraded.profile, "free");
    assert!(downgraded.encrypted_contact_email.is_none());

    // 4. Verified web self-deletion: wrong email NEVER deletes; matching email confirmation deletes!
    srv.client
        .post(format!("{}/register/delete-request", srv.base_url))
        .form(&[
            ("pubkey", k1_pk.as_str()),
            ("email", "attacker@example.org"),
        ])
        .send()
        .await
        .unwrap();
    assert!(srv.state.mailer.take_recorded().is_empty());
    assert!(srv.state.db.get_registered_user(&k1_pk).unwrap().is_some());

    srv.client
        .post(format!("{}/register/delete-request", srv.base_url))
        .form(&[("pubkey", k1_pk.as_str()), ("email", "aliceuser@gmail.com")])
        .send()
        .await
        .unwrap();
    let del_mails = srv.state.mailer.take_recorded();
    assert_eq!(del_mails.len(), 1);
    let del_url = del_mails[0]
        .body
        .lines()
        .find(|l| l.starts_with("http://"))
        .unwrap()
        .trim()
        .to_string();

    let del_conf = srv.client.get(&del_url).send().await.unwrap();
    assert_eq!(del_conf.status().as_u16(), 303);
    assert!(srv.state.db.get_registered_user(&k1_pk).unwrap().is_none());

    // Email can now be reused after deletion
    let re_reg = srv
        .client
        .post(format!("{}/register/email", srv.base_url))
        .form(&[("pubkey", k2_pk.as_str()), ("email", "aliceuser@gmail.com")])
        .send()
        .await
        .unwrap();
    assert_eq!(re_reg.status().as_u16(), 303);
    assert_eq!(srv.state.mailer.take_recorded().len(), 1);
}

#[allow(clippy::too_many_arguments)]
fn sign_lock_entry_helper(
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

fn build_single_server_manifest(
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

async fn fetch_ticket_signed(
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

#[tokio::test]
async fn test_lock_delegation_selftest_probe_and_ticket_auth() {
    let (admin_sk, admin_pk) = gen_keypair();
    let (member_sk, member_pk) = gen_keypair();
    let (outsider_sk, _outsider_pk) = gen_keypair();
    let (reg_sk, reg_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.max_retention_quarter = humoco_proto::encode_quarter(2032, 4).unwrap();
    cfg.lock.allow_pow_tickets = true;
    cfg.lock.ticket_pow_bits = 8;
    let srv = TestServer::start(cfg).await;

    // 1. GET ?info contains lock block & cached selftest
    let info: serde_json::Value = srv
        .client
        .get(format!("{}/sync.php?info", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(info["channels"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "lock"));
    let lock_pub_hex = info["lock"]["lock_pub"].as_str().unwrap().to_string();
    assert_eq!(info["lock"]["selftest"]["all_passed"], true);
    assert_eq!(info["lock"]["selftest"]["runtime"], "rust");
    assert_eq!(
        info["lock"]["selftest"]["checks"]["ext_sodium"],
        "not_applicable"
    );
    assert_eq!(info["lock"]["selftest"]["checks"]["sha3_256"], "pass");
    assert_eq!(info["lock"]["ticket_pow_bits"], 8);
    let mut bad_cfg = base_hybrid_config(&admin_pk);
    bad_cfg.lock.ticket_pow_bits = 25;
    assert!(bad_cfg.validate().is_err());
    assert!(info["lock"]["delegation"].is_null());

    // 2. PUT ?lock_delegate + POST ?lock_selftest
    let issued_at = unix_now();
    let del_write_url = format!("{}/sync.php", srv.base_url);
    let del_read_url = format!("{}/humoco_sync_data", srv.base_url);
    let del_msg = humoco_sync_server::crypto::format_lock_delegate_signature_message(
        &admin_pk,
        &lock_pub_hex,
        &del_write_url,
        &del_read_url,
        issued_at,
    );
    let del_body = serde_json::to_vec(&serde_json::json!({
        "admin_pub": admin_pk,
        "lock_pub": lock_pub_hex,
        "write_url": del_write_url,
        "read_url": del_read_url,
        "issued_at": issued_at,
        "sig": hex::encode(admin_sk.sign(del_msg.as_bytes()).to_bytes()),
    }))
    .unwrap();
    let ts = unix_now() as i64;
    let nonce = random_hex(16);
    let admin_msg = humoco_sync_server::crypto::format_admin_put_lock_delegate_message(
        ts,
        &nonce,
        &sha256_hex(&del_body),
    );
    let del_resp = srv
        .client
        .put(format!("{}/sync.php?lock_delegate", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", ts.to_string())
        .header("X-Drop-Nonce", &nonce)
        .header(
            "X-Drop-Signature",
            hex::encode(admin_sk.sign(admin_msg.as_bytes()).to_bytes()),
        )
        .body(del_body)
        .send()
        .await
        .unwrap();
    assert_eq!(del_resp.status().as_u16(), 200);

    let ts_st = unix_now() as i64;
    let nonce_st = random_hex(16);
    let st_msg = humoco_sync_server::crypto::format_admin_post_lock_selftest_message(
        ts_st,
        &nonce_st,
        humoco_sync_server::crypto::EMPTY_SHA256_HEX,
    );
    let st_resp = srv
        .client
        .post(format!("{}/sync.php?lock_selftest", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", ts_st.to_string())
        .header("X-Drop-Nonce", &nonce_st)
        .header(
            "X-Drop-Signature",
            hex::encode(admin_sk.sign(st_msg.as_bytes()).to_bytes()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(st_resp.status().as_u16(), 200);

    // 3. Zero-write WAF probe (must verify signed response and leave buckets=0, inodes=0)
    let client_nonce = random_hex(32);
    let probe_resp: serde_json::Value = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({ "probe": true, "client_nonce": client_nonce }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(probe_resp["probe_ok"], true);
    let probe_sig_msg = humoco_sync_server::crypto::format_lock_probe_signature_message(
        &lock_pub_hex,
        probe_resp["client_nonce"].as_str().unwrap(),
        probe_resp["server_time"].as_u64().unwrap(),
    );
    assert!(humoco_sync_server::crypto::verify_ed25519_hex(
        &lock_pub_hex,
        probe_resp["sig"].as_str().unwrap(),
        probe_sig_msg.as_bytes()
    ));
    assert_eq!(srv.state.db.lock_bucket_count_and_inodes().unwrap(), (0, 0));

    // 4. Ticket authorization: add admin member on channel "lock" + register public user
    let m_body = serde_json::to_vec(&serde_json::json!({ "pubkeys": [member_pk] })).unwrap();
    let ts_m = unix_now() as i64;
    let nonce_m = random_hex(16);
    let m_msg = format_admin_put_members_message("lock", ts_m, &nonce_m, &sha256_hex(&m_body));
    assert_eq!(
        srv.client
            .put(format!("{}/sync.php?members&channel=lock", srv.base_url))
            .header("X-Drop-Pubkey", &admin_pk)
            .header("X-Drop-Timestamp", ts_m.to_string())
            .header("X-Drop-Nonce", &nonce_m)
            .header(
                "X-Drop-Signature",
                hex::encode(admin_sk.sign(m_msg.as_bytes()).to_bytes())
            )
            .body(m_body)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    assert_eq!(
        srv.client
            .post(format!("{}/register/open", srv.base_url))
            .form(&[("pubkey", reg_pk.as_str())])
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        303
    );

    let anchor_id = [0x11; 32];
    let q_ok = humoco_proto::encode_quarter(2031, 2).unwrap();
    let q_too_far = humoco_proto::encode_quarter(2035, 1).unwrap();

    // Member, registered user, and admin succeed; outsider rejected (403); excess retention rejected (422)
    assert_eq!(
        fetch_ticket_signed(&srv, &member_sk, anchor_id, q_ok)
            .await
            .0,
        200
    );
    assert_eq!(
        fetch_ticket_signed(&srv, &reg_sk, anchor_id, q_ok).await.0,
        200
    );
    assert_eq!(
        fetch_ticket_signed(&srv, &admin_sk, anchor_id, q_ok)
            .await
            .0,
        200
    );
    assert_eq!(
        fetch_ticket_signed(&srv, &outsider_sk, anchor_id, q_ok)
            .await
            .0,
        403
    );
    assert_eq!(
        fetch_ticket_signed(&srv, &member_sk, anchor_id, q_too_far)
            .await
            .0,
        422
    );

    // Unauthenticated PoW ticket succeeds once, replay rejected (409)
    let pow_ts = unix_now();
    let pow_nonce =
        humoco_proto::solve_ticket_pow(&anchor_id, q_ok, pow_ts, 8, 0, 100_000).unwrap();
    let pow_body = serde_json::json!({
        "anchor_id": hex::encode(anchor_id),
        "retain_until_quarter": q_ok,
        "pow_timestamp": pow_ts,
        "pow_nonce": pow_nonce,
    });
    assert_eq!(
        srv.client
            .post(format!("{}/sync.php?lock_ticket", srv.base_url))
            .json(&pow_body)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        srv.client
            .post(format!("{}/sync.php?lock_ticket", srv.base_url))
            .json(&pow_body)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        409
    );
}

#[tokio::test]
async fn test_lock_batch_idempotency_conflict_partial_batch_rollback_and_gc_immunity() {
    let (admin_sk, admin_pk) = gen_keypair();
    let (user_sk, user_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.max_inodes = 4;
    let srv = TestServer::start(cfg).await;

    // Register public user so user_pk can fetch ticket AND call DELETE ?account later
    srv.client
        .post(format!("{}/register/open", srv.base_url))
        .form(&[("pubkey", user_pk.as_str())])
        .send()
        .await
        .unwrap();

    let lock_pub = srv.state.db.lock_pubkey_bytes().unwrap();
    let admin_pub_bytes = admin_sk.verifying_key().to_bytes();
    let creator_mig_sk = SigningKey::from_bytes(&[40u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 2).unwrap();
    let manifest =
        build_single_server_manifest(admin_pub_bytes, lock_pub, creator_mig_pub, quarter);
    let anchor_id = manifest.rev1_anchor_id().unwrap();
    let bucket = humoco_proto::derive_bucket(&anchor_id, &lock_pub);

    let (t_code, t_json) = fetch_ticket_signed(&srv, &user_sk, anchor_id, quarter).await;
    assert_eq!(t_code, 200);
    let ticket: humoco_proto::GenesisTicket =
        serde_json::from_value(t_json["ticket"].clone()).unwrap();

    // Build two distinct depth=0 vouchers in same anchor bucket + one depth=1 spend from voucher 1
    let g1_sk = SigningKey::from_bytes(&[41u8; 32]);
    let r1_sk = SigningKey::from_bytes(&[42u8; 32]);
    let r1_hash = humoco_proto::hash_pubkey_sha3(&r1_sk.verifying_key().to_bytes());
    let e0_v1 = sign_lock_entry_helper(
        anchor_id,
        [0x01; 32],
        [0u8; 32],
        0,
        0,
        [0x10; 32],
        &g1_sk,
        r1_hash,
        None,
        Some(&creator_mig_sk),
        8,
    );

    let g2_sk = SigningKey::from_bytes(&[43u8; 32]);
    let r2_sk = SigningKey::from_bytes(&[44u8; 32]);
    let r2_hash = humoco_proto::hash_pubkey_sha3(&r2_sk.verifying_key().to_bytes());
    let e0_v2 = sign_lock_entry_helper(
        anchor_id,
        [0x02; 32],
        [0u8; 32],
        0,
        0,
        [0x20; 32],
        &g2_sk,
        r2_hash,
        None,
        Some(&creator_mig_sk),
        8,
    );

    let r3_hash = [0x77; 32];
    let e1_v1 = sign_lock_entry_helper(
        anchor_id, [0x03; 32], e0_v1.slot, 0, 1, [0x30; 32], &r1_sk, r3_hash, None, None, 8,
    );

    let req1 = serde_json::json!({
        "anchor_id": hex::encode(anchor_id),
        "bucket": hex::encode(bucket),
        "recipient_nonce": hex::encode([0xAA; 32]),
        "entries": [e0_v1.to_wire_hex().unwrap(), e0_v2.to_wire_hex().unwrap(), e1_v1.to_wire_hex().unwrap()],
        "manifest": manifest,
        "genesis_ticket": ticket,
        "known_head_receipt": serde_json::Value::Null,
    });
    let resp1: humoco_sync_server::locks::LockBatchResponse = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&req1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp1.status, "ok");
    assert!(resp1.conflict.is_none());
    assert_eq!(resp1.receipts.len(), 3);
    assert_eq!(resp1.receipts[2].write_seq, 3);
    assert!(resp1.receipts.iter().all(|r| r.verify_signature()));

    // Static read fetches exact 605 bytes for e0_v1
    let q_str = humoco_proto::format_quarter(quarter).unwrap();
    let file_s = hex::encode(humoco_proto::derive_slot_file_id(&e0_v1.slot, &lock_pub));
    let read_url = format!(
        "{}/humoco_sync_data/locks/{}/{}/{}.lock",
        srv.base_url,
        q_str,
        hex::encode(bucket),
        file_s
    );
    let static_bytes = srv
        .client
        .get(&read_url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(static_bytes.as_ref(), &e0_v1.to_wire_bytes().unwrap());

    // Idempotent retry does not advance write_seq
    let retry_resp: humoco_sync_server::locks::LockBatchResponse = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "bucket": hex::encode(bucket),
            "recipient_nonce": hex::encode([0xAB; 32]),
            "entries": [e1_v1.to_wire_hex().unwrap()],
            "manifest": serde_json::Value::Null,
            "genesis_ticket": serde_json::Value::Null,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        retry_resp.receipts[0].kind,
        humoco_proto::LockReceiptKind::FirstWrite
    );
    assert_eq!(retry_resp.receipts[0].write_seq, 3);

    // Partial-batch conflict: [valid e1_v2 on v2, conflicting e1_v1_alt on e0_v1's child slot, skipped e2]
    // First test 1-child-slot-per-output rule with a DIFFERENT ds_tag on e0_v1 branch 0 -> 409 output_branch_already_claimed
    let illegal_branch_reuse = sign_lock_entry_helper(
        anchor_id, [0x99; 32], e0_v1.slot, 0, 1, [0x99; 32], &r1_sk, [0x88; 32], None, None, 8,
    );
    let reuse_resp = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "bucket": hex::encode(bucket),
            "recipient_nonce": hex::encode([0xAC; 32]),
            "entries": [illegal_branch_reuse.to_wire_hex().unwrap()],
            "manifest": serde_json::Value::Null,
            "genesis_ticket": serde_json::Value::Null,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reuse_resp.status().as_u16(), 409);

    // Now test same ds_tag [0x03; 32] (same slot = e1_v1.slot) with DIFFERENT child_lock [0x31; 32],
    // preceded by valid new entry e1_v2 (4th inode: hits max_inodes=4 inside already active bucket!)
    let e1_v2 = sign_lock_entry_helper(
        anchor_id, [0x04; 32], e0_v2.slot, 0, 1, [0x40; 32], &r2_sk, [0x78; 32], None, None, 8,
    );
    let e1_v1_conflict = sign_lock_entry_helper(
        anchor_id, [0x03; 32], e0_v1.slot, 0, 1, [0x31; 32], &r1_sk, [0x79; 32], None, None, 8,
    );
    let conflict_resp: humoco_sync_server::locks::LockBatchResponse = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "bucket": hex::encode(bucket),
            "recipient_nonce": hex::encode([0xAD; 32]),
            "entries": [e1_v2.to_wire_hex().unwrap(), e1_v1_conflict.to_wire_hex().unwrap()],
            "manifest": serde_json::Value::Null,
            "genesis_ticket": serde_json::Value::Null,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(conflict_resp.status, "conflict");
    assert_eq!(conflict_resp.receipts.len(), 1); // prefix e1_v2 committed!
    assert_eq!(conflict_resp.receipts[0].write_seq, 4);
    let c = conflict_resp.conflict.unwrap();
    assert_eq!(c.entry_index, 1);
    assert_eq!(c.receipt.kind, humoco_proto::LockReceiptKind::ConflictSeen);
    assert_eq!(c.receipt.child_lock, [0x30; 32]); // stored original winner!
    assert_eq!(c.competing_entry, e1_v1.to_wire_hex().unwrap());
    assert!(c.receipt.verify_signature());

    // Now used_inodes == 4 == max_inodes: new anchor genesis_ticket returns 507!
    assert_eq!(
        fetch_ticket_signed(&srv, &user_sk, [0xEE; 32], quarter)
            .await
            .0,
        507
    );

    // DELETE ?account on user_pk MUST leave all active locks untouched!
    let ts_del = unix_now() as i64;
    let nonce_del = random_hex(16);
    let msg_del = format_delete_account_message(ts_del, &nonce_del);
    assert_eq!(
        srv.client
            .delete(format!("{}/sync.php?account", srv.base_url))
            .header("X-Drop-Pubkey", &user_pk)
            .header("X-Drop-Timestamp", ts_del.to_string())
            .header("X-Drop-Nonce", &nonce_del)
            .header(
                "X-Drop-Signature",
                hex::encode(user_sk.sign(msg_del.as_bytes()).to_bytes())
            )
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    assert_eq!(srv.state.db.lock_bucket_count_and_inodes().unwrap(), (1, 4));
    assert_eq!(
        srv.client
            .get(&read_url)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // Forged known_head_receipt MUST reject (401) and NEVER freeze the bucket!
    let mut forged_head = conflict_resp.receipts[0].clone();
    forged_head.write_seq = 999;
    let forged_resp = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "bucket": hex::encode(bucket),
            "recipient_nonce": hex::encode([0xAE; 32]),
            "entries": [e1_v1.to_wire_hex().unwrap()],
            "manifest": serde_json::Value::Null,
            "genesis_ticket": serde_json::Value::Null,
            "known_head_receipt": forged_head,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(forged_resp.status().as_u16(), 401);

    // Quarterly GC immunity: 1 second before quarter_end + 30d removes 0 buckets; at threshold purges whole bucket!
    let purge_at = humoco_proto::bucket_purge_after_secs(quarter).unwrap();
    assert_eq!(srv.state.db.run_lock_gc(purge_at - 1).unwrap(), (0, 0));
    assert_eq!(srv.state.db.lock_bucket_count_and_inodes().unwrap(), (1, 4));

    // Purge bucket via simulated clock and verify missing-bucket rollback detection
    assert_eq!(srv.state.db.run_lock_gc(purge_at).unwrap(), (1, 4));
    assert_eq!(srv.state.db.lock_bucket_count_and_inodes().unwrap(), (0, 0));
    assert_eq!(
        srv.client
            .get(&read_url)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );

    let rollback_resp = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "bucket": hex::encode(bucket),
            "recipient_nonce": hex::encode([0xAF; 32]),
            "entries": [e0_v1.to_wire_hex().unwrap()],
            "manifest": serde_json::Value::Null,
            "genesis_ticket": serde_json::Value::Null,
            "known_head_receipt": conflict_resp.receipts[0],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rollback_resp.status().as_u16(), 409);
    let rollback_json: serde_json::Value = rollback_resp.json().await.unwrap();
    assert_eq!(rollback_json["error"], "bucket_self_frozen");
}

#[tokio::test]
async fn test_lock_key_persists_across_restarts_and_snapshot_rollback_self_freezes() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.allow_pow_tickets = true;
    cfg.lock.ticket_pow_bits = 8;

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("srv.redb");
    let snap_path = dir.path().join("srv_seq1.redb.snap");

    let creator_mig_sk = SigningKey::from_bytes(&[50u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 2).unwrap();

    // 1. Open server DB, commit write_seq = 1, close cleanly and take DB snapshot
    let (anchor_id, bucket, lock_pub, manifest, ticket, e0_v1, e1_v1) = {
        let db = humoco_sync_server::db::SyncDb::open(&db_path, "").unwrap();
        let lp = db.lock_pubkey_bytes().unwrap();
        let man = build_single_server_manifest([9u8; 32], lp, creator_mig_pub, quarter);
        let aid = man.rev1_anchor_id().unwrap();
        let bkt = humoco_proto::derive_bucket(&aid, &lp);

        let now = unix_now();
        let pn = humoco_proto::solve_ticket_pow(&aid, quarter, now, 8, 0, 100_000).unwrap();
        let tkt = db
            .issue_genesis_ticket(
                &cfg,
                humoco_sync_server::locks::TicketCallerAuth::UnauthenticatedPow,
                humoco_sync_server::locks::LockTicketRequest {
                    anchor_id: aid,
                    retain_until_quarter: quarter,
                    pow_timestamp: Some(now),
                    pow_nonce: Some(pn),
                },
                now,
            )
            .unwrap();

        let g_sk = SigningKey::from_bytes(&[51u8; 32]);
        let r_sk = SigningKey::from_bytes(&[52u8; 32]);
        let r_hash = humoco_proto::hash_pubkey_sha3(&r_sk.verifying_key().to_bytes());
        let e0 = sign_lock_entry_helper(
            aid,
            [0x11; 32],
            [0u8; 32],
            0,
            0,
            [0x21; 32],
            &g_sk,
            r_hash,
            None,
            Some(&creator_mig_sk),
            8,
        );
        let e1 = sign_lock_entry_helper(
            aid, [0x12; 32], e0.slot, 0, 1, [0x22; 32], &r_sk, [0x77; 32], None, None, 8,
        );

        let req = humoco_sync_server::locks::LockBatchRequest {
            anchor_id: aid,
            bucket: bkt,
            recipient_nonce: [0xC1; 32],
            entries: vec![e0.to_wire_hex().unwrap()],
            manifest: Some(man.clone()),
            genesis_ticket: Some(tkt.clone()),
            known_head_receipt: None,
        };
        let (code, _) = db.process_lock_batch(&cfg, req, now).unwrap();
        assert_eq!(code, 200);
        (aid, bkt, lp, man, tkt, e0, e1)
    };
    std::fs::copy(&db_path, &snap_path).unwrap();

    // 2. Reopen server DB: same lock_pub survives restart; advance to write_seq = 2 and grab receipt
    let receipt_seq2: humoco_proto::LockReceipt = {
        let db = humoco_sync_server::db::SyncDb::open(&db_path, "").unwrap();
        assert_eq!(db.lock_pubkey_bytes().unwrap(), lock_pub);
        let (code, resp_val) = db
            .process_lock_batch(
                &cfg,
                humoco_sync_server::locks::LockBatchRequest {
                    anchor_id,
                    bucket,
                    recipient_nonce: [0xC2; 32],
                    entries: vec![e1_v1.to_wire_hex().unwrap()],
                    manifest: Some(manifest.clone()),
                    genesis_ticket: Some(ticket.clone()),
                    known_head_receipt: None,
                },
                unix_now(),
            )
            .unwrap();
        assert_eq!(code, 200);
        let parsed: humoco_sync_server::locks::LockBatchResponse =
            serde_json::from_value(resp_val).unwrap();
        assert_eq!(parsed.receipts[0].write_seq, 2);
        parsed.receipts.into_iter().next().unwrap()
    };

    // 3. Simulate hoster DB snapshot rollback back to write_seq = 1
    std::fs::copy(&snap_path, &db_path).unwrap();
    let rolled_back_db = humoco_sync_server::db::SyncDb::open(&db_path, "").unwrap();
    assert_eq!(rolled_back_db.lock_pubkey_bytes().unwrap(), lock_pub);

    // Client retries with its higher known_head_receipt (write_seq = 2 > local write_seq = 1) -> Self-Freeze!
    let (rb_code, rb_val) = rolled_back_db
        .process_lock_batch(
            &cfg,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id,
                bucket,
                recipient_nonce: [0xC3; 32],
                entries: vec![e0_v1.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: Some(receipt_seq2),
            },
            unix_now(),
        )
        .unwrap();
    assert_eq!(rb_code, 409);
    assert_eq!(rb_val["error"], "bucket_self_frozen");

    // Subsequent writes to that self-frozen bucket stay blocked (409 bucket_self_frozen)
    let (sub_code, sub_val) = rolled_back_db
        .process_lock_batch(
            &cfg,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id,
                bucket,
                recipient_nonce: [0xC4; 32],
                entries: vec![e1_v1.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: None,
            },
            unix_now(),
        )
        .unwrap();
    assert_eq!(sub_code, 409);
    assert_eq!(sub_val["error"], "bucket_self_frozen");
}

fn server_entry_for_test(
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

fn build_multi_server_manifest(
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
fn build_signed_proposal(
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

async fn start_lock_test_server(
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

async fn issue_pow_ticket_http(
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

fn issue_pow_ticket_db(
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

#[tokio::test]
async fn test_sync007_full_http_three_phase_rotation_overlap_and_discovery() {
    let (a1_sk, _, s1) = start_lock_test_server(true, Some(0)).await;
    let (a2_sk, _, s2) = start_lock_test_server(true, Some(0)).await;
    let (a3_sk, _, s3) = start_lock_test_server(true, Some(0)).await;
    let (a5_sk, _, s5) = start_lock_test_server(true, Some(0)).await;

    let creator_mig_sk = SigningKey::from_bytes(&[71u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let now = unix_now();

    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
    let e_s2 = server_entry_for_test(&s2, &a2_sk, humoco_proto::NominatedBy::Creator);
    let e_s3 = server_entry_for_test(&s3, &a3_sk, humoco_proto::NominatedBy::Creator);
    let e_s5 = server_entry_for_test(&s5, &a5_sk, humoco_proto::NominatedBy::Creator);

    let manifest_rev1 = build_multi_server_manifest(
        vec![e_s1.clone(), e_s2.clone(), e_s3.clone()],
        vec![e_s5.clone()],
        2,
        creator_mig_pub,
        Vec::new(),
        now.saturating_mul(1_000),
        quarter,
    );
    let anchor_id = manifest_rev1.rev1_anchor_id().unwrap();
    let anchor_hex = hex::encode(anchor_id);

    let tkt1 = issue_pow_ticket_http(&s1, anchor_id, quarter).await;
    let tkt2 = issue_pow_ticket_http(&s2, anchor_id, quarter).await;
    let tkt3 = issue_pow_ticket_http(&s3, anchor_id, quarter).await;

    let g_sk = SigningKey::from_bytes(&[72u8; 32]);
    let r1_sk = SigningKey::from_bytes(&[73u8; 32]);
    let r2_sk = SigningKey::from_bytes(&[74u8; 32]);
    let r3_hash = humoco_proto::hash_pubkey_sha3(&[88u8; 32]);
    let r1_hash = humoco_proto::hash_pubkey_sha3(&r1_sk.verifying_key().to_bytes());
    let r2_hash = humoco_proto::hash_pubkey_sha3(&r2_sk.verifying_key().to_bytes());

    let e0 = sign_lock_entry_helper(
        anchor_id,
        [0x10; 32],
        [0u8; 32],
        0,
        0,
        [0x20; 32],
        &g_sk,
        r1_hash,
        None,
        Some(&creator_mig_sk),
        8,
    );
    let e1 = sign_lock_entry_helper(
        anchor_id, [0x11; 32], e0.slot, 0, 1, [0x21; 32], &r1_sk, r2_hash, None, None, 8,
    );
    let e2 = sign_lock_entry_helper(
        anchor_id, [0x12; 32], e1.slot, 0, 2, [0x22; 32], &r2_sk, r3_hash, None, None, 8,
    );

    // S1 & S2 receive [e0, e1]; S3 only receives [e0] (lacks e1 before freeze)
    for (srv, tkt, entries) in [
        (
            &s1,
            &tkt1,
            vec![e0.to_wire_hex().unwrap(), e1.to_wire_hex().unwrap()],
        ),
        (
            &s2,
            &tkt2,
            vec![e0.to_wire_hex().unwrap(), e1.to_wire_hex().unwrap()],
        ),
        (&s3, &tkt3, vec![e0.to_wire_hex().unwrap()]),
    ] {
        let bkt =
            humoco_proto::derive_bucket(&anchor_id, &srv.state.db.lock_pubkey_bytes().unwrap());
        let resp = srv
            .client
            .post(format!("{}/sync.php?lock", srv.base_url))
            .json(&serde_json::json!({
                "anchor_id": anchor_hex,
                "bucket": hex::encode(bkt),
                "recipient_nonce": hex::encode([0xA1; 32]),
                "entries": entries,
                "manifest": manifest_rev1,
                "genesis_ticket": tkt,
                "known_head_receipt": serde_json::Value::Null,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    // Phase 1: Propose rotation [S1, S2, S3] -> [S1, S2, S5] via HTTP ?lock_freeze
    let prop_at = unix_now();
    let proposal = build_signed_proposal(
        anchor_id,
        1,
        2,
        vec![e_s1.clone(), e_s2.clone(), e_s5.clone()],
        Vec::new(),
        quarter,
        prop_at,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        Vec::new(),
    );
    let prop_body = serde_json::json!({
        "action": "propose",
        "proposal": proposal,
        "current_manifest": serde_json::Value::Null,
    });

    let mut exports = Vec::new();
    for srv in [&s1, &s2, &s3] {
        let resp = srv
            .client
            .post(format!("{}/sync.php?lock_freeze", srv.base_url))
            .json(&prop_body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let j: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(j["status"], "proposed");
        let exp: humoco_proto::SnapshotExport =
            serde_json::from_value(j["snapshot_export"].clone()).unwrap();
        exports.push(exp);
    }

    // GET ?lock_freeze&anchor_id=<hex> inspects permanent_proposal + voted_proposal + snapshot
    let inspect_resp = s1
        .client
        .get(format!(
            "{}/sync.php?lock_freeze&anchor_id={}",
            s1.base_url, anchor_hex
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(inspect_resp.status().as_u16(), 200);
    let inspect_json: serde_json::Value = inspect_resp.json().await.unwrap();
    assert!(inspect_json["bucket_freeze_state"]["permanent_proposal"].is_object());
    assert!(inspect_json["voted_proposal"].is_object());
    assert!(inspect_json["snapshot_export"].is_object());

    // Phase 2: Import Q_old=[S1, S3] snapshots onto [S1, S2, S5]; note S3 missed e1, S1 has [e0, e1]
    let q_old_snaps = vec![exports[0].clone(), exports[2].clone()];
    let mut acks = Vec::new();
    let mut imported_state_hash = [0u8; 32];
    for srv in [&s1, &s2, &s5] {
        let resp = srv
            .client
            .post(format!("{}/sync.php?lock_import", srv.base_url))
            .json(&serde_json::json!({
                "anchor_id": anchor_hex,
                "active_manifest": manifest_rev1,
                "proposal": proposal,
                "snapshots": q_old_snaps,
                "quorum_certificates": [],
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let j: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(j["status"], "imported");
        assert_eq!(j["imported_slots"], 2);
        let ack: humoco_proto::ImportAck = serde_json::from_value(j["import_ack"].clone()).unwrap();
        imported_state_hash = ack.imported_state_hash;
        acks.push(ack);
    }

    // Overlap servers S1/S2 must remain frozen (409 proposal_frozen) between Phase 2 Import and Phase 3 Finalize!
    let bkt_s1 = humoco_proto::derive_bucket(&anchor_id, &s1.state.db.lock_pubkey_bytes().unwrap());
    let mid_lock = s1
        .client
        .post(format!("{}/sync.php?lock", s1.base_url))
        .json(&serde_json::json!({
            "anchor_id": anchor_hex,
            "bucket": hex::encode(bkt_s1),
            "recipient_nonce": hex::encode([0xA2; 32]),
            "entries": [e2.to_wire_hex().unwrap()],
            "manifest": serde_json::Value::Null,
            "genesis_ticket": serde_json::Value::Null,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(mid_lock.status().as_u16(), 409);

    // Phase 3: SignCommit on Q_old=[S1, S3] and Finalize across [S1, S2, S3, S5]
    let mut commit_sigs = Vec::new();
    for srv in [&s1, &s3] {
        let resp = srv
            .client
            .post(format!("{}/sync.php?lock_commit", srv.base_url))
            .json(&serde_json::json!({
                "action": "sign_commit",
                "anchor_id": anchor_hex,
                "proposal": proposal,
                "imported_state_hash": hex::encode(imported_state_hash),
                "import_acks": acks,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let j: serde_json::Value = resp.json().await.unwrap();
        let cs: humoco_proto::CommitteeSignature =
            serde_json::from_value(j["committee_signature"].clone()).unwrap();
        commit_sigs.push(cs);
    }

    let cert = humoco_proto::MigrationCert {
        anchor_id,
        genesis_manifest: Some(Box::new(manifest_rev1.clone())),
        proposal: proposal.clone(),
        imported_state_hash,
        import_acks: acks,
        commit_sigs,
    };
    let (manifest_rev2, reduced) = cert.verify_step(&anchor_id, &manifest_rev1).unwrap();
    assert!(!reduced);
    manifest_rev2.verify_anchor_id(&anchor_id).unwrap();

    for (srv, expected_frozen) in [(&s1, false), (&s2, false), (&s5, false), (&s3, true)] {
        let resp = srv
            .client
            .post(format!("{}/sync.php?lock_commit", srv.base_url))
            .json(&serde_json::json!({
                "action": "finalize",
                "anchor_id": anchor_hex,
                "new_manifest": manifest_rev2,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let j: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(j["revision"], 2);
        if expected_frozen {
            assert!(j["bucket_freeze_state"]["epoch_frozen"].is_object());
        } else {
            assert_eq!(j["bucket_freeze_state"], "active");
        }
    }

    // Retired S3 returns 409 epoch_frozen with latest_manifest Rev 2 on POST ?lock
    let bkt_s3 = humoco_proto::derive_bucket(&anchor_id, &s3.state.db.lock_pubkey_bytes().unwrap());
    let s3_locked = s3
        .client
        .post(format!("{}/sync.php?lock", s3.base_url))
        .json(&serde_json::json!({
            "anchor_id": anchor_hex,
            "bucket": hex::encode(bkt_s3),
            "recipient_nonce": hex::encode([0xA3; 32]),
            "entries": [e2.to_wire_hex().unwrap()],
            "manifest": serde_json::Value::Null,
            "genesis_ticket": serde_json::Value::Null,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(s3_locked.status().as_u16(), 409);
    let s3_err: serde_json::Value = s3_locked.json().await.unwrap();
    assert_eq!(s3_err["error"], "epoch_frozen");
    assert_eq!(s3_err["current_revision"], 2);
    let recovered_manifest: humoco_proto::AnchorManifest =
        serde_json::from_value(s3_err["latest_manifest"].clone()).unwrap();
    recovered_manifest.verify_anchor_id(&anchor_id).unwrap();

    // Active Rev-2 servers [S1, S2, S5] accept child spend e2 (including brand-new S5 validating causal parent e1!)
    for srv in [&s1, &s2, &s5] {
        let bkt =
            humoco_proto::derive_bucket(&anchor_id, &srv.state.db.lock_pubkey_bytes().unwrap());
        let resp = srv
            .client
            .post(format!("{}/sync.php?lock", srv.base_url))
            .json(&serde_json::json!({
                "anchor_id": anchor_hex,
                "bucket": hex::encode(bkt),
                "recipient_nonce": hex::encode([0xA4; 32]),
                "entries": [e2.to_wire_hex().unwrap()],
                "manifest": serde_json::Value::Null,
                "genesis_ticket": serde_json::Value::Null,
                "known_head_receipt": serde_json::Value::Null,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let lr: humoco_sync_server::locks::LockBatchResponse = resp.json().await.unwrap();
        assert_eq!(lr.status, "ok");
        assert!(lr.receipts[0].verify_signature());
    }

    // Static anchor discovery endpoint GET / HEAD + ETag 304 on S5 and S3
    let anchor_get = s5
        .client
        .get(format!("{}/anchors/{}.bin", s5.base_url, anchor_hex))
        .send()
        .await
        .unwrap();
    assert_eq!(anchor_get.status().as_u16(), 200);
    let etag = anchor_get
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let fetched_man: humoco_proto::AnchorManifest = anchor_get.json().await.unwrap();
    assert_eq!(fetched_man, manifest_rev2);

    let not_mod = s5
        .client
        .get(format!(
            "{}/humoco_sync_data/anchors/{}.bin",
            s5.base_url, anchor_hex
        ))
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(not_mod.status().as_u16(), 304);

    let head_resp = s3
        .client
        .head(format!("{}/anchors/{}.bin", s3.base_url, anchor_hex))
        .send()
        .await
        .unwrap();
    assert_eq!(head_resp.status().as_u16(), 200);
    assert!(head_resp.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_sync007_pre_freeze_ttl_1800_and_voted_proposal_uniqueness() {
    let (a1_sk, _, s1) = start_lock_test_server(true, None).await;
    let (a5_sk, _, s5) = start_lock_test_server(true, None).await;
    assert_eq!(s1.state.config.lock.pre_freeze_ttl_secs, 1800);
    assert_eq!(s1.state.config.lock.proposal_timelock_secs, 259_200);

    let creator_mig_sk = SigningKey::from_bytes(&[81u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let g_mig_pub = SigningKey::from_bytes(&[84u8; 32])
        .verifying_key()
        .to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;

    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
    let e_s5 = server_entry_for_test(&s5, &a5_sk, humoco_proto::NominatedBy::Creator);
    let man = build_multi_server_manifest(
        vec![e_s1.clone()],
        vec![e_s5.clone()],
        1,
        creator_mig_pub,
        vec![g_mig_pub],
        t0 * 1_000,
        quarter,
    );
    let aid = man.rev1_anchor_id().unwrap();
    let bkt = humoco_proto::derive_bucket(&aid, &s1.state.db.lock_pubkey_bytes().unwrap());
    let tkt = issue_pow_ticket_db(&s1, aid, quarter, t0);

    let g_sk = SigningKey::from_bytes(&[82u8; 32]);
    let r1_sk = SigningKey::from_bytes(&[83u8; 32]);
    let e0 = sign_lock_entry_helper(
        aid,
        [0x21; 32],
        [0u8; 32],
        0,
        0,
        [0x31; 32],
        &g_sk,
        humoco_proto::hash_pubkey_sha3(&r1_sk.verifying_key().to_bytes()),
        None,
        Some(&creator_mig_sk),
        8,
    );
    let e1 = sign_lock_entry_helper(
        aid, [0x22; 32], e0.slot, 0, 1, [0x32; 32], &r1_sk, [0x99; 32], None, None, 8,
    );

    let (c0, _) = s1
        .state
        .db
        .process_lock_batch(
            &s1.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt,
                recipient_nonce: [0x10; 32],
                entries: vec![e0.to_wire_hex().unwrap()],
                manifest: Some(man.clone()),
                genesis_ticket: Some(tkt),
                known_head_receipt: None,
            },
            t0,
        )
        .unwrap();
    assert_eq!(c0, 200);

    let (pf_code, pf_val) = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::PreFreeze {
                anchor_id: aid,
                current_manifest: None,
            },
            t0 + 10,
        )
        .unwrap();
    assert_eq!(pf_code, 200);
    assert_eq!(pf_val["expires_at"], t0 + 1810);

    // 1 second before PreFreeze expiration -> 409 pre_proposal_frozen
    let (blocked_code, blocked_val) = s1
        .state
        .db
        .process_lock_batch(
            &s1.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt,
                recipient_nonce: [0x11; 32],
                entries: vec![e1.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: None,
            },
            t0 + 1809,
        )
        .unwrap();
    assert_eq!(blocked_code, 409);
    assert_eq!(blocked_val["error"], "pre_proposal_frozen");

    // At expires_at -> PreFreeze automatically reverts to Active and write succeeds
    let (unblocked_code, _) = s1
        .state
        .db
        .process_lock_batch(
            &s1.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt,
                recipient_nonce: [0x12; 32],
                entries: vec![e1.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: None,
            },
            t0 + 1810,
        )
        .unwrap();
    assert_eq!(unblocked_code, 200);

    // Submit Proposal P1 at t1 = t0 + 2000; test idempotency vs competing P2 + timelock 409
    let t1 = t0 + 2000;
    let p1 = build_signed_proposal(
        aid,
        1,
        1,
        vec![e_s5],
        Vec::new(),
        quarter,
        t1,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        Vec::new(),
    );
    let (p1_code, p1_val) = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: p1.clone(),
                current_manifest: None,
            },
            t1,
        )
        .unwrap();
    assert_eq!(p1_code, 200);
    assert_eq!(p1_val["effective_at"], t1 + 259_200);
    let snap1: humoco_proto::SnapshotExport =
        serde_json::from_value(p1_val["snapshot_export"].clone()).unwrap();
    assert_eq!(snap1.snapshot.frozen_at, t1);

    // Idempotent resend preserves frozen_at & proposal_hash
    let (idem_code, idem_val) = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: p1.clone(),
                current_manifest: None,
            },
            t1 + 300,
        )
        .unwrap();
    assert_eq!(idem_code, 200);
    assert_eq!(idem_val["proposal_hash"], p1_val["proposal_hash"]);

    // Competing proposal P2 in same revision -> 409 Conflict
    let (a6_sk, _, s6) = start_lock_test_server(true, None).await;
    let e_s6 = server_entry_for_test(&s6, &a6_sk, humoco_proto::NominatedBy::Creator);
    let p2 = build_signed_proposal(
        aid,
        1,
        1,
        vec![e_s6],
        Vec::new(),
        quarter,
        t1 + 50,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        Vec::new(),
    );
    let p2_err = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: p2,
                current_manifest: None,
            },
            t1 + 300,
        )
        .unwrap_err();
    assert!(matches!(
        p2_err,
        humoco_sync_server::db::DbError::Http { status: 409, .. }
    ));

    // Import 1s before 72h timelock expiry -> 409 Conflict
    let early_imp = s5
        .state
        .db
        .process_lock_import(
            &s5.state.config,
            humoco_sync_server::lock_rotation::LockImportRequest {
                anchor_id: aid,
                active_manifest: man,
                proposal: p1,
                snapshots: vec![snap1],
                quorum_certificates: Vec::new(),
            },
            t1 + 259_199,
        )
        .unwrap_err();
    assert!(matches!(
        early_imp,
        humoco_sync_server::db::DbError::Http { status: 409, .. }
    ));
}

#[tokio::test]
async fn test_sync007_authority_veto_during_timelock_and_blacklisting() {
    let (a1_sk, _, s1) = start_lock_test_server(true, None).await;
    let (a2_sk, _, s2) = start_lock_test_server(true, None).await;
    let (a3_sk, _, s3) = start_lock_test_server(true, None).await;
    let (a5_sk, _, s5) = start_lock_test_server(true, None).await;

    let creator_mig_sk = SigningKey::from_bytes(&[91u8; 32]);
    let g_mig_sk = SigningKey::from_bytes(&[92u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let g_mig_pub = g_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;

    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
    let e_s2 = server_entry_for_test(&s2, &a2_sk, humoco_proto::NominatedBy::Creator);
    let e_s3 = server_entry_for_test(&s3, &a3_sk, humoco_proto::NominatedBy::Guarantor(0));
    let e_s5 = server_entry_for_test(&s5, &a5_sk, humoco_proto::NominatedBy::Guarantor(0));

    let man = build_multi_server_manifest(
        vec![e_s1.clone(), e_s2.clone(), e_s3.clone()],
        vec![e_s5.clone()],
        2,
        creator_mig_pub,
        vec![g_mig_pub],
        t0 * 1_000,
        quarter,
    );
    let aid = man.rev1_anchor_id().unwrap();
    let bkt1 = humoco_proto::derive_bucket(&aid, &s1.state.db.lock_pubkey_bytes().unwrap());
    let tkt1 = issue_pow_ticket_db(&s1, aid, quarter, t0);

    let g_sk = SigningKey::from_bytes(&[93u8; 32]);
    let r_sk = SigningKey::from_bytes(&[94u8; 32]);
    let e0 = sign_lock_entry_helper(
        aid,
        [0x31; 32],
        [0u8; 32],
        0,
        0,
        [0x41; 32],
        &g_sk,
        humoco_proto::hash_pubkey_sha3(&r_sk.verifying_key().to_bytes()),
        None,
        Some(&creator_mig_sk),
        8,
    );
    let e1 = sign_lock_entry_helper(
        aid, [0x32; 32], e0.slot, 0, 1, [0x42; 32], &r_sk, [0xAA; 32], None, None, 8,
    );

    s1.state
        .db
        .process_lock_batch(
            &s1.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt1,
                recipient_nonce: [0x20; 32],
                entries: vec![e0.to_wire_hex().unwrap()],
                manifest: Some(man.clone()),
                genesis_ticket: Some(tkt1),
                known_head_receipt: None,
            },
            t0,
        )
        .unwrap();

    let p1 = build_signed_proposal(
        aid,
        1,
        2,
        vec![e_s1, e_s2, e_s5],
        Vec::new(),
        quarter,
        t0 + 10,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        vec![(&g_mig_sk, 0)],
    );
    let prop_hash = p1.core_digest().unwrap();
    let (pc, pv) = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: p1.clone(),
                current_manifest: None,
            },
            t0 + 10,
        )
        .unwrap();
    assert_eq!(pc, 200);
    let snap: humoco_proto::SnapshotExport =
        serde_json::from_value(pv["snapshot_export"].clone()).unwrap();

    // Creator cannot self-veto -> 401
    let mut bad_veto = humoco_proto::MigrationVeto {
        anchor_id: aid,
        from_rev: 1,
        proposal_hash: prop_hash,
        vetoer_pub: creator_mig_pub,
        vetoed_at: t0 + 100,
        sig: [0; 64],
    };
    bad_veto.sig = creator_mig_sk.sign(&bad_veto.digest()).to_bytes();
    let bad_err = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Veto { veto: bad_veto },
            t0 + 100,
        )
        .unwrap_err();
    assert!(matches!(
        bad_err,
        humoco_sync_server::db::DbError::Http { status: 401, .. }
    ));

    // Guarantor vetoes Creator's proposal before timelock expires -> unfreezes bucket to Active
    let mut good_veto = humoco_proto::MigrationVeto {
        anchor_id: aid,
        from_rev: 1,
        proposal_hash: prop_hash,
        vetoer_pub: g_mig_pub,
        vetoed_at: t0 + 200,
        sig: [0; 64],
    };
    good_veto.sig = g_mig_sk.sign(&good_veto.digest()).to_bytes();
    let (vc, vv) = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Veto { veto: good_veto },
            t0 + 200,
        )
        .unwrap();
    assert_eq!(vc, 200);
    assert_eq!(vv["status"], "vetoed");

    // Bucket is Active again -> e1 commits!
    let (c1, _) = s1
        .state
        .db
        .process_lock_batch(
            &s1.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt1,
                recipient_nonce: [0x21; 32],
                entries: vec![e1.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: None,
            },
            t0 + 210,
        )
        .unwrap();
    assert_eq!(c1, 200);

    // Replaying vetoed proposal P1 is rejected with 409
    let replay_err = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: p1.clone(),
                current_manifest: None,
            },
            t0 + 220,
        )
        .unwrap_err();
    assert!(matches!(
        replay_err,
        humoco_sync_server::db::DbError::Http { status: 409, .. }
    ));

    // Also once timelock expires, importing the vetoed proposal against a record tracking veto fails (or after veto propagated)
    let _ = (man, snap);
}

#[tokio::test]
async fn test_sync007_nomination_binding_rejects_malicious_guarantor_replacement() {
    let (a1_sk, _, s1) = start_lock_test_server(true, Some(0)).await;
    let (a2_sk, _, s2) = start_lock_test_server(true, Some(0)).await;
    let (a3_sk, _, s3) = start_lock_test_server(true, Some(0)).await;
    let (a5_sk, _, s5) = start_lock_test_server(true, Some(0)).await;

    let creator_mig_sk = SigningKey::from_bytes(&[101u8; 32]);
    let g_mig_sk = SigningKey::from_bytes(&[102u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let g_mig_pub = g_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = unix_now();

    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
    let e_s2 = server_entry_for_test(&s2, &a2_sk, humoco_proto::NominatedBy::Creator);
    let e_s3 = server_entry_for_test(&s3, &a3_sk, humoco_proto::NominatedBy::Guarantor(0));
    let mut e_s5_hijack = server_entry_for_test(&s5, &a5_sk, humoco_proto::NominatedBy::Creator);

    let man = build_multi_server_manifest(
        vec![e_s1.clone(), e_s2.clone(), e_s3.clone()],
        Vec::new(),
        2,
        creator_mig_pub,
        vec![g_mig_pub],
        t0 * 1_000,
        quarter,
    );
    let aid = man.rev1_anchor_id().unwrap();

    // Malicious Creator replaces Guarantor(0) slot S3 with Creator server S5 without guarantor cosig!
    let bad_prop = build_signed_proposal(
        aid,
        1,
        2,
        vec![e_s1.clone(), e_s2.clone(), e_s5_hijack.clone()],
        Vec::new(),
        quarter,
        t0,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        Vec::new(),
    );

    let err_freeze = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: bad_prop.clone(),
                current_manifest: Some(man.clone()),
            },
            t0,
        )
        .unwrap_err();
    assert!(matches!(
        err_freeze,
        humoco_sync_server::db::DbError::Http { status: 400, .. }
    ));

    // Even direct ?lock_import on target S5 rejects the un-cosigned replacement (400)
    let err_import = s5
        .state
        .db
        .process_lock_import(
            &s5.state.config,
            humoco_sync_server::lock_rotation::LockImportRequest {
                anchor_id: aid,
                active_manifest: man.clone(),
                proposal: bad_prop,
                snapshots: Vec::new(),
                quorum_certificates: Vec::new(),
            },
            t0 + 1,
        )
        .unwrap_err();
    assert!(matches!(
        err_import,
        humoco_sync_server::db::DbError::Http { status: 400, .. }
    ));

    // When Guarantor(0) co-signs OR S5 is designated Guarantor(0) WITH guarantor cosig, Propose succeeds!
    e_s5_hijack.nominated_by = humoco_proto::NominatedBy::Guarantor(0);
    let ok_prop = build_signed_proposal(
        aid,
        1,
        2,
        vec![e_s1, e_s2, e_s5_hijack],
        Vec::new(),
        quarter,
        t0,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        vec![(&g_mig_sk, 0)],
    );
    let (ok_code, _) = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: ok_prop,
                current_manifest: Some(man),
            },
            t0,
        )
        .unwrap();
    assert_eq!(ok_code, 200);
}

#[tokio::test]
async fn test_sync007_creator_30d_inactivity_takeover_and_heartbeat() {
    let (a1_sk, _, s1) = start_lock_test_server(true, None).await;
    let (a5_sk, _, s5) = start_lock_test_server(true, None).await;
    assert_eq!(s1.state.config.lock.creator_inactivity_secs, 2_592_000);

    let creator_mig_sk = SigningKey::from_bytes(&[111u8; 32]);
    let g_mig_sk = SigningKey::from_bytes(&[112u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let g_mig_pub = g_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;

    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
    let e_s5 = server_entry_for_test(&s5, &a5_sk, humoco_proto::NominatedBy::Guarantor(0));
    let man = build_multi_server_manifest(
        vec![e_s1.clone()],
        Vec::new(),
        1,
        creator_mig_pub,
        vec![g_mig_pub],
        t0 * 1_000,
        quarter,
    );
    let aid = man.rev1_anchor_id().unwrap();
    let bkt1 = humoco_proto::derive_bucket(&aid, &s1.state.db.lock_pubkey_bytes().unwrap());
    let tkt1 = issue_pow_ticket_db(&s1, aid, quarter, t0);

    // Offline depth=0 spend at t0 + 1_000_000 MUST NOT bump last_creator_activity_secs!
    let g_sk = SigningKey::from_bytes(&[113u8; 32]);
    let e0 = sign_lock_entry_helper(
        aid,
        [0x41; 32],
        [0u8; 32],
        0,
        0,
        [0x51; 32],
        &g_sk,
        [0x77; 32],
        None,
        Some(&creator_mig_sk),
        8,
    );
    s1.state
        .db
        .process_lock_batch(
            &s1.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt1,
                recipient_nonce: [0x30; 32],
                entries: vec![e0.to_wire_hex().unwrap()],
                manifest: Some(man),
                genesis_ticket: Some(tkt1),
                known_head_receipt: None,
            },
            t0 + 1_000_000,
        )
        .unwrap();

    let status0 = s1
        .state
        .db
        .get_lock_freeze_status(&s1.state.config, aid, t0 + 1_000_000)
        .unwrap();
    assert_eq!(status0["last_creator_activity_secs"], t0);

    // 1 second before 30d window expires -> Guarantor takeover rejected with 403
    let g_prop_early = build_signed_proposal(
        aid,
        1,
        1,
        vec![e_s5.clone()],
        Vec::new(),
        quarter,
        t0 + 2_591_999,
        humoco_proto::ProposalInitiator::Guarantor { guarantor_index: 0 },
        Some(&g_mig_sk),
        Vec::new(),
    );
    let early_err = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: g_prop_early,
                current_manifest: None,
            },
            t0 + 2_591_999,
        )
        .unwrap_err();
    assert!(matches!(
        early_err,
        humoco_sync_server::db::DbError::Http { status: 403, .. }
    ));

    // Creator submits live CreatorHeartbeat at t_hb = t0 + 2_000_000
    let t_hb = t0 + 2_000_000;
    let mut hb = humoco_proto::CreatorHeartbeat {
        anchor_id: aid,
        timestamp_secs: t_hb,
        sig: [0; 64],
    };
    hb.sig = creator_mig_sk.sign(&hb.digest()).to_bytes();
    let (hb_code, hb_val) = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Heartbeat {
                heartbeat: hb,
                current_manifest: None,
            },
            t_hb,
        )
        .unwrap();
    assert_eq!(hb_code, 200);
    assert_eq!(hb_val["last_creator_activity_secs"], t_hb);

    // At t0 + 2_592_000 (< t_hb + 30d), Guarantor takeover MUST STILL be rejected (403)!
    let g_prop_mid = build_signed_proposal(
        aid,
        1,
        1,
        vec![e_s5.clone()],
        Vec::new(),
        quarter,
        t0 + 2_592_000,
        humoco_proto::ProposalInitiator::Guarantor { guarantor_index: 0 },
        Some(&g_mig_sk),
        Vec::new(),
    );
    let mid_err = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: g_prop_mid,
                current_manifest: None,
            },
            t0 + 2_592_000,
        )
        .unwrap_err();
    assert!(matches!(
        mid_err,
        humoco_sync_server::db::DbError::Http { status: 403, .. }
    ));

    // At t_hb + 2_592_000 (>= 30d since last live creator activity) -> Guarantor takeover succeeds!
    let t_ok = t_hb + 2_592_000;
    let g_prop_ok = build_signed_proposal(
        aid,
        1,
        1,
        vec![e_s5],
        Vec::new(),
        quarter,
        t_ok,
        humoco_proto::ProposalInitiator::Guarantor { guarantor_index: 0 },
        Some(&g_mig_sk),
        Vec::new(),
    );
    let (ok_code, _) = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: g_prop_ok,
                current_manifest: None,
            },
            t_ok,
        )
        .unwrap();
    assert_eq!(ok_code, 200);
}

#[tokio::test]
async fn test_sync007_holder_standby_successor_rotation_without_authority_sig() {
    let (a1_sk, _, s1) = start_lock_test_server(true, None).await;
    let (a2_sk, _, s2) = start_lock_test_server(true, None).await;
    let (a3_sk, _, s3) = start_lock_test_server(true, None).await;
    let (a5_sk, _, s5) = start_lock_test_server(true, None).await;
    let (a6_sk, _, s6) = start_lock_test_server(true, None).await;

    let creator_mig_sk = SigningKey::from_bytes(&[121u8; 32]);
    let g_mig_sk = SigningKey::from_bytes(&[122u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let g_mig_pub = g_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;

    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
    let e_s2 = server_entry_for_test(&s2, &a2_sk, humoco_proto::NominatedBy::Creator);
    let e_s3 = server_entry_for_test(&s3, &a3_sk, humoco_proto::NominatedBy::Guarantor(0));
    let e_s5_g_succ = server_entry_for_test(&s5, &a5_sk, humoco_proto::NominatedBy::Guarantor(0));
    let e_s6_c_succ = server_entry_for_test(&s6, &a6_sk, humoco_proto::NominatedBy::Creator);

    let man = build_multi_server_manifest(
        vec![e_s1.clone(), e_s2.clone(), e_s3.clone()],
        vec![e_s5_g_succ.clone(), e_s6_c_succ.clone()],
        2,
        creator_mig_pub,
        vec![g_mig_pub],
        t0 * 1_000,
        quarter,
    );
    let aid = man.rev1_anchor_id().unwrap();

    // Negative: HolderStandby trying to promote Creator successor into Guarantor(0) slot MUST fail (400)
    let bad_standby = build_signed_proposal(
        aid,
        1,
        2,
        vec![e_s1.clone(), e_s2.clone(), e_s6_c_succ.clone()],
        vec![e_s5_g_succ.clone()],
        quarter,
        t0,
        humoco_proto::ProposalInitiator::HolderStandby,
        None,
        Vec::new(),
    );
    assert!(matches!(
        s1.state.db.process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: bad_standby,
                current_manifest: Some(man.clone()),
            },
            t0,
        ),
        Err(humoco_sync_server::db::DbError::Http { status: 400, .. })
    ));

    // Positive: Unsigned HolderStandby promotes S5 (Guarantor(0) successor) into S3's slot, leaving [S6]
    let standby_prop = build_signed_proposal(
        aid,
        1,
        2,
        vec![e_s1.clone(), e_s2.clone(), e_s5_g_succ],
        vec![e_s6_c_succ],
        quarter,
        t0,
        humoco_proto::ProposalInitiator::HolderStandby,
        None,
        Vec::new(),
    );

    let mut snaps = Vec::new();
    for srv in [&s1, &s2] {
        let (code, val) = srv
            .state
            .db
            .process_lock_freeze(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                    proposal: standby_prop.clone(),
                    current_manifest: Some(man.clone()),
                },
                t0,
            )
            .unwrap();
        assert_eq!(code, 200);
        snaps.push(
            serde_json::from_value::<humoco_proto::SnapshotExport>(val["snapshot_export"].clone())
                .unwrap(),
        );
    }

    let t_mature = t0 + 259_200;
    let mut acks = Vec::new();
    let mut imported_state_hash = [0u8; 32];
    for srv in [&s1, &s2, &s5] {
        let (code, val) = srv
            .state
            .db
            .process_lock_import(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockImportRequest {
                    anchor_id: aid,
                    active_manifest: man.clone(),
                    proposal: standby_prop.clone(),
                    snapshots: snaps.clone(),
                    quorum_certificates: Vec::new(),
                },
                t_mature,
            )
            .unwrap();
        assert_eq!(code, 200);
        let ack: humoco_proto::ImportAck =
            serde_json::from_value(val["import_ack"].clone()).unwrap();
        imported_state_hash = ack.imported_state_hash;
        acks.push(ack);
    }

    let mut commit_sigs = Vec::new();
    for srv in [&s1, &s2] {
        let (code, val) = srv
            .state
            .db
            .process_lock_commit(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                    anchor_id: aid,
                    proposal: standby_prop.clone(),
                    imported_state_hash,
                    import_acks: acks.clone(),
                },
                t_mature,
            )
            .unwrap();
        assert_eq!(code, 200);
        commit_sigs.push(
            serde_json::from_value::<humoco_proto::CommitteeSignature>(
                val["committee_signature"].clone(),
            )
            .unwrap(),
        );
    }

    let cert = humoco_proto::MigrationCert {
        anchor_id: aid,
        genesis_manifest: Some(Box::new(man.clone())),
        proposal: standby_prop,
        imported_state_hash,
        import_acks: acks,
        commit_sigs,
    };
    let (new_manifest, reduced) = cert.verify_step(&aid, &man).unwrap();
    assert!(!reduced);
    new_manifest.verify_anchor_id(&aid).unwrap();
    assert_eq!(new_manifest.successors.len(), 1);
}

#[tokio::test]
async fn test_sync007_phase2_union_qc_resolution_unresolved_conflict_and_gc() {
    let creator_mig_sk = SigningKey::from_bytes(&[131u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;

    // Part A: 2:1 split resolved cleanly by QuorumCertificate on target import
    {
        let (a1_sk, _, s1) = start_lock_test_server(true, None).await;
        let (a2_sk, _, s2) = start_lock_test_server(true, None).await;
        let (a3_sk, _, s3) = start_lock_test_server(true, None).await;
        let (a5_sk, _, s5) = start_lock_test_server(true, None).await;

        let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
        let e_s2 = server_entry_for_test(&s2, &a2_sk, humoco_proto::NominatedBy::Creator);
        let e_s3 = server_entry_for_test(&s3, &a3_sk, humoco_proto::NominatedBy::Creator);
        let e_s5 = server_entry_for_test(&s5, &a5_sk, humoco_proto::NominatedBy::Creator);

        let man = build_multi_server_manifest(
            vec![e_s1.clone(), e_s2.clone(), e_s3],
            vec![e_s5.clone()],
            2,
            creator_mig_pub,
            Vec::new(),
            t0 * 1_000,
            quarter,
        );
        let aid = man.rev1_anchor_id().unwrap();

        let g_sk = SigningKey::from_bytes(&[132u8; 32]);
        let r1_sk = SigningKey::from_bytes(&[133u8; 32]);
        let r_win_sk = SigningKey::from_bytes(&[134u8; 32]);
        let r_alt_sk = SigningKey::from_bytes(&[135u8; 32]);

        let e0 = sign_lock_entry_helper(
            aid,
            [0x50; 32],
            [0u8; 32],
            0,
            0,
            [0x60; 32],
            &g_sk,
            humoco_proto::hash_pubkey_sha3(&r1_sk.verifying_key().to_bytes()),
            None,
            Some(&creator_mig_sk),
            8,
        );
        let e1_win = sign_lock_entry_helper(
            aid,
            [0x51; 32],
            e0.slot,
            0,
            1,
            [0x61; 32],
            &r1_sk,
            humoco_proto::hash_pubkey_sha3(&r_win_sk.verifying_key().to_bytes()),
            None,
            None,
            8,
        );
        let e1_alt = sign_lock_entry_helper(
            aid,
            [0x51; 32],
            e0.slot,
            0,
            1,
            [0x62; 32],
            &r1_sk,
            humoco_proto::hash_pubkey_sha3(&r_alt_sk.verifying_key().to_bytes()),
            None,
            None,
            8,
        );

        let mut qc_receipts = Vec::new();
        for srv in [&s1, &s2] {
            let bkt = humoco_proto::derive_bucket(&aid, &srv.state.db.lock_pubkey_bytes().unwrap());
            let tkt = issue_pow_ticket_db(srv, aid, quarter, t0);
            let (_, val) = srv
                .state
                .db
                .process_lock_batch(
                    &srv.state.config,
                    humoco_sync_server::locks::LockBatchRequest {
                        anchor_id: aid,
                        bucket: bkt,
                        recipient_nonce: [0x41; 32],
                        entries: vec![e0.to_wire_hex().unwrap(), e1_win.to_wire_hex().unwrap()],
                        manifest: Some(man.clone()),
                        genesis_ticket: Some(tkt),
                        known_head_receipt: None,
                    },
                    t0,
                )
                .unwrap();
            let resp: humoco_sync_server::locks::LockBatchResponse =
                serde_json::from_value(val).unwrap();
            qc_receipts.push(resp.receipts[1].clone());
        }

        // S3 stores conflicting e1_alt
        let bkt3 = humoco_proto::derive_bucket(&aid, &s3.state.db.lock_pubkey_bytes().unwrap());
        let tkt3 = issue_pow_ticket_db(&s3, aid, quarter, t0);
        s3.state
            .db
            .process_lock_batch(
                &s3.state.config,
                humoco_sync_server::locks::LockBatchRequest {
                    anchor_id: aid,
                    bucket: bkt3,
                    recipient_nonce: [0x42; 32],
                    entries: vec![e0.to_wire_hex().unwrap(), e1_alt.to_wire_hex().unwrap()],
                    manifest: Some(man.clone()),
                    genesis_ticket: Some(tkt3),
                    known_head_receipt: None,
                },
                t0,
            )
            .unwrap();

        let prop = build_signed_proposal(
            aid,
            1,
            2,
            vec![e_s1, e_s2, e_s5],
            Vec::new(),
            quarter,
            t0 + 10,
            humoco_proto::ProposalInitiator::Creator,
            Some(&creator_mig_sk),
            Vec::new(),
        );
        // Freeze S1 (holds e1_win) and S3 (holds e1_alt) so Q_old=2 snapshots have 1:1 conflict without S2,
        // resolved deterministically via the 2-of-3 QuorumCertificate!
        let mut snaps = Vec::new();
        for srv in [&s1, &s3] {
            let (_, val) = srv
                .state
                .db
                .process_lock_freeze(
                    &srv.state.config,
                    humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                        proposal: prop.clone(),
                        current_manifest: None,
                    },
                    t0 + 10,
                )
                .unwrap();
            snaps.push(
                serde_json::from_value::<humoco_proto::SnapshotExport>(
                    val["snapshot_export"].clone(),
                )
                .unwrap(),
            );
        }

        let qc = humoco_proto::QuorumCertificate {
            slot: e1_win.slot,
            child_lock: e1_win.child_lock,
            receipts: qc_receipts,
        };
        let (imp_code, imp_val) = s5
            .state
            .db
            .process_lock_import(
                &s5.state.config,
                humoco_sync_server::lock_rotation::LockImportRequest {
                    anchor_id: aid,
                    active_manifest: man,
                    proposal: prop,
                    snapshots: snaps,
                    quorum_certificates: vec![qc],
                },
                t0 + 10 + 259_200,
            )
            .unwrap();
        assert_eq!(imp_code, 200);
        assert_eq!(imp_val["imported_slots"], 2);
        let bkt5_hex = hex::encode(humoco_proto::derive_bucket(
            &aid,
            &s5.state.db.lock_pubkey_bytes().unwrap(),
        ));
        assert!(s5
            .state
            .db
            .lock_conflict_entries_in_bucket(&bkt5_hex)
            .unwrap()
            .is_empty());
        let stored_s5 = s5.state.db.lock_entries_in_bucket(&bkt5_hex).unwrap();
        assert_eq!(
            stored_s5.get(&hex::encode(e1_win.slot)).unwrap(),
            &e1_win.to_wire_bytes().unwrap()
        );
    }

    // Part B: 1:1 split without QC stores CONFLICT([A, B]), preserves child spend, triggers ConflictSeen & cleans up in GC
    let (a1_sk, _, s1) = start_lock_test_server(true, None).await;
    let (a2_sk, _, s2) = start_lock_test_server(true, None).await;
    let (a3_sk, _, s3) = start_lock_test_server(true, None).await;
    let (a5_sk, _, s5) = start_lock_test_server(true, None).await;

    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
    let e_s2 = server_entry_for_test(&s2, &a2_sk, humoco_proto::NominatedBy::Creator);
    let e_s3 = server_entry_for_test(&s3, &a3_sk, humoco_proto::NominatedBy::Creator);
    let e_s5 = server_entry_for_test(&s5, &a5_sk, humoco_proto::NominatedBy::Creator);

    let man = build_multi_server_manifest(
        vec![e_s1.clone(), e_s2.clone(), e_s3],
        vec![e_s5.clone()],
        2,
        creator_mig_pub,
        Vec::new(),
        t0 * 1_000,
        quarter,
    );
    let aid = man.rev1_anchor_id().unwrap();

    let g_sk = SigningKey::from_bytes(&[141u8; 32]);
    let r1_sk = SigningKey::from_bytes(&[142u8; 32]);
    let r_a_sk = SigningKey::from_bytes(&[143u8; 32]);
    let r_b_sk = SigningKey::from_bytes(&[144u8; 32]);
    let r_next_sk = SigningKey::from_bytes(&[145u8; 32]);

    let e0 = sign_lock_entry_helper(
        aid,
        [0x70; 32],
        [0u8; 32],
        0,
        0,
        [0x80; 32],
        &g_sk,
        humoco_proto::hash_pubkey_sha3(&r1_sk.verifying_key().to_bytes()),
        None,
        Some(&creator_mig_sk),
        8,
    );
    let e1_a = sign_lock_entry_helper(
        aid,
        [0x71; 32],
        e0.slot,
        0,
        1,
        [0x81; 32],
        &r1_sk,
        humoco_proto::hash_pubkey_sha3(&r_a_sk.verifying_key().to_bytes()),
        None,
        None,
        8,
    );
    let e1_b = sign_lock_entry_helper(
        aid,
        [0x71; 32],
        e0.slot,
        0,
        1,
        [0x82; 32],
        &r1_sk,
        humoco_proto::hash_pubkey_sha3(&r_b_sk.verifying_key().to_bytes()),
        None,
        None,
        8,
    );
    let e1_c = sign_lock_entry_helper(
        aid, [0x71; 32], e0.slot, 0, 1, [0x83; 32], &r1_sk, [0xCC; 32], None, None, 8,
    );
    let e2_child_of_a = sign_lock_entry_helper(
        aid,
        [0x72; 32],
        e1_a.slot,
        0,
        2,
        [0x84; 32],
        &r_a_sk,
        humoco_proto::hash_pubkey_sha3(&r_next_sk.verifying_key().to_bytes()),
        None,
        None,
        8,
    );

    let bkt1 = humoco_proto::derive_bucket(&aid, &s1.state.db.lock_pubkey_bytes().unwrap());
    let tkt1 = issue_pow_ticket_db(&s1, aid, quarter, t0);
    s1.state
        .db
        .process_lock_batch(
            &s1.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt1,
                recipient_nonce: [0x51; 32],
                entries: vec![e0.to_wire_hex().unwrap(), e1_a.to_wire_hex().unwrap()],
                manifest: Some(man.clone()),
                genesis_ticket: Some(tkt1),
                known_head_receipt: None,
            },
            t0,
        )
        .unwrap();

    let bkt3 = humoco_proto::derive_bucket(&aid, &s3.state.db.lock_pubkey_bytes().unwrap());
    let tkt3 = issue_pow_ticket_db(&s3, aid, quarter, t0);
    s3.state
        .db
        .process_lock_batch(
            &s3.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt3,
                recipient_nonce: [0x52; 32],
                entries: vec![e0.to_wire_hex().unwrap(), e1_b.to_wire_hex().unwrap()],
                manifest: Some(man.clone()),
                genesis_ticket: Some(tkt3),
                known_head_receipt: None,
            },
            t0,
        )
        .unwrap();

    let prop = build_signed_proposal(
        aid,
        1,
        2,
        vec![e_s1, e_s2, e_s5],
        Vec::new(),
        quarter,
        t0 + 10,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        Vec::new(),
    );
    let mut snaps = Vec::new();
    for srv in [&s1, &s3] {
        let (_, val) = srv
            .state
            .db
            .process_lock_freeze(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                    proposal: prop.clone(),
                    current_manifest: None,
                },
                t0 + 10,
            )
            .unwrap();
        snaps.push(
            serde_json::from_value::<humoco_proto::SnapshotExport>(val["snapshot_export"].clone())
                .unwrap(),
        );
    }

    let t_mature = t0 + 10 + 259_200;
    let mut acks = Vec::new();
    let mut imported_state_hash = [0u8; 32];
    for srv in [&s1, &s2, &s5] {
        let (code, val) = srv
            .state
            .db
            .process_lock_import(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockImportRequest {
                    anchor_id: aid,
                    active_manifest: man.clone(),
                    proposal: prop.clone(),
                    snapshots: snaps.clone(),
                    quorum_certificates: Vec::new(),
                },
                t_mature,
            )
            .unwrap();
        assert_eq!(code, 200);
        let ack: humoco_proto::ImportAck =
            serde_json::from_value(val["import_ack"].clone()).unwrap();
        imported_state_hash = ack.imported_state_hash;
        acks.push(ack);
    }

    // Complete Finalize on S5 so S5 is Active in Rev 2
    let mut commit_sigs = Vec::new();
    for srv in [&s1, &s3] {
        let (_, val) = srv
            .state
            .db
            .process_lock_commit(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                    anchor_id: aid,
                    proposal: prop.clone(),
                    imported_state_hash,
                    import_acks: acks.clone(),
                },
                t_mature,
            )
            .unwrap();
        commit_sigs.push(
            serde_json::from_value::<humoco_proto::CommitteeSignature>(
                val["committee_signature"].clone(),
            )
            .unwrap(),
        );
    }
    let cert = humoco_proto::MigrationCert {
        anchor_id: aid,
        genesis_manifest: Some(Box::new(man.clone())),
        proposal: prop,
        imported_state_hash,
        import_acks: acks,
        commit_sigs,
    };
    let (rev2_man, _) = cert.verify_step(&aid, &man).unwrap();
    s5.state
        .db
        .process_lock_commit(
            &s5.state.config,
            humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                anchor_id: aid,
                new_manifest: rev2_man,
            },
            t_mature,
        )
        .unwrap();

    // S5 holds 2 inodes: e0 in LOCK_ENTRIES and [e1_a, e1_b] in LOCK_CONFLICTS
    let bkt5 = humoco_proto::derive_bucket(&aid, &s5.state.db.lock_pubkey_bytes().unwrap());
    let bkt5_hex = hex::encode(bkt5);
    assert_eq!(s5.state.db.lock_bucket_count_and_inodes().unwrap(), (1, 2));
    let conflicts = s5
        .state
        .db
        .lock_conflict_entries_in_bucket(&bkt5_hex)
        .unwrap();
    assert_eq!(conflicts.get(&hex::encode(e1_a.slot)).unwrap().len(), 2);

    // Partial-batch POST ?lock: [e2_child_of_a (causal parent is in LOCK_CONFLICTS!), e1_c (hits LOCK_CONFLICTS)]
    // -> e2_child_of_a commits (inode 3) while e1_c triggers ConflictSeen!
    let (batch_code, batch_val) = s5
        .state
        .db
        .process_lock_batch(
            &s5.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt5,
                recipient_nonce: [0x55; 32],
                entries: vec![
                    e2_child_of_a.to_wire_hex().unwrap(),
                    e1_c.to_wire_hex().unwrap(),
                ],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: None,
            },
            t_mature + 10,
        )
        .unwrap();
    assert_eq!(batch_code, 200);
    let parsed: humoco_sync_server::locks::LockBatchResponse =
        serde_json::from_value(batch_val).unwrap();
    assert_eq!(parsed.status, "conflict");
    assert_eq!(parsed.receipts.len(), 1);
    assert_eq!(parsed.receipts[0].slot, e2_child_of_a.slot);
    let conf = parsed.conflict.unwrap();
    assert_eq!(conf.entry_index, 1);
    assert_eq!(
        conf.receipt.kind,
        humoco_proto::LockReceiptKind::ConflictSeen
    );
    assert!(conf.receipt.verify_signature());

    assert_eq!(s5.state.db.lock_bucket_count_and_inodes().unwrap(), (1, 3));

    // GC at retention expiry purges LOCK_ENTRIES, LOCK_CONFLICTS, LOCK_ROTATIONS & LOCK_ANCHORS cleanly
    let purge_at = humoco_proto::bucket_purge_after_secs(quarter).unwrap();
    let (purged_b, purged_i) = s5.state.db.run_lock_gc(purge_at).unwrap();
    assert_eq!((purged_b, purged_i), (1, 3));
    assert_eq!(s5.state.db.lock_bucket_count_and_inodes().unwrap(), (0, 0));
    assert!(s5
        .state
        .db
        .get_static_anchor_manifest(&hex::encode(aid))
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_sync007_sync_revocation_returns_410_gone_across_lock_endpoints() {
    let (admin_sk, admin_pk, s1) = start_lock_test_server(true, Some(0)).await;
    let (_rep_sk, rep_pk, s_rep) = start_lock_test_server(true, Some(0)).await;

    let now = unix_now();
    let mut notice = RevocationNotice {
        drop_pub: admin_pk.clone(),
        issued_at: now,
        effective_at: now,
        reason: Some("Server decommissioned".to_string()),
        replacement: Some(humoco_sync_server::crypto::RevocationReplacementTarget {
            write_url: format!("{}/sync.php", s_rep.base_url),
            read_url: format!("{}/humoco_sync_data", s_rep.base_url),
            drop_pub: rep_pk,
        }),
        signature: String::new(),
    };
    notice.signature = hex::encode(
        admin_sk
            .sign(canonical_revocation_message(&notice).as_bytes())
            .to_bytes(),
    );
    let rev_body = serde_json::to_vec(&notice).unwrap();
    let rev_nonce = random_hex(16);
    let rev_sig = hex::encode(
        admin_sk
            .sign(
                format_admin_put_revoke_message(now as i64, &rev_nonce, &sha256_hex(&rev_body))
                    .as_bytes(),
            )
            .to_bytes(),
    );
    let put_rev = s1
        .client
        .put(format!("{}/sync.php?revoke", s1.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &rev_nonce)
        .header("X-Drop-Signature", &rev_sig)
        .body(rev_body)
        .send()
        .await
        .unwrap();
    assert_eq!(put_rev.status().as_u16(), 200);

    let aid_hex = hex::encode([0xAA; 32]);
    let dummy_body = serde_json::json!({"anchor_id": aid_hex});

    for (resp_fut, label) in [
        (
            s1.client
                .post(format!("{}/sync.php?lock", s1.base_url))
                .json(&dummy_body)
                .send(),
            "POST ?lock",
        ),
        (
            s1.client
                .post(format!("{}/sync.php?lock_ticket", s1.base_url))
                .json(&dummy_body)
                .send(),
            "POST ?lock_ticket",
        ),
        (
            s1.client
                .get(format!(
                    "{}/sync.php?lock_freeze&anchor_id={}",
                    s1.base_url, aid_hex
                ))
                .send(),
            "GET ?lock_freeze",
        ),
        (
            s1.client
                .post(format!("{}/sync.php?lock_freeze", s1.base_url))
                .json(&dummy_body)
                .send(),
            "POST ?lock_freeze",
        ),
        (
            s1.client
                .post(format!("{}/sync.php?lock_import", s1.base_url))
                .json(&dummy_body)
                .send(),
            "POST ?lock_import",
        ),
        (
            s1.client
                .post(format!("{}/sync.php?lock_commit", s1.base_url))
                .json(&dummy_body)
                .send(),
            "POST ?lock_commit",
        ),
    ] {
        let resp = resp_fut.await.unwrap();
        assert_eq!(
            resp.status().as_u16(),
            410,
            "{label} should return 410 Gone"
        );
        let j: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(j["revocation"]["drop_pub"], admin_pk);
        assert_eq!(
            j["revocation"]["replacement"]["write_url"],
            format!("{}/sync.php", s_rep.base_url)
        );
    }

    // Replacement server continues issuing tickets cleanly
    let q = humoco_proto::encode_quarter(2031, 4).unwrap();
    let _rep_tkt = issue_pow_ticket_http(&s_rep, [0xAA; 32], q).await;
}

#[tokio::test]
async fn test_put_admin_config_validation_live_enforcement_and_persistence() {
    let (admin_sk, admin_pk) = gen_keypair();
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("admin_cfg.redb");

    let sign_put_cfg = |body: &str| {
        let now = unix_now() as i64;
        let nonce = random_hex(16);
        let msg = format_admin_put_config_message(now, &nonce, &sha256_hex(body.as_bytes()));
        let sig = hex::encode(admin_sk.sign(msg.as_bytes()).to_bytes());
        (now, nonce, sig)
    };

    // Start first server instance with shutdown handle
    let (tx_shutdown, rx_shutdown) = tokio::sync::oneshot::channel::<()>();
    let (addr_str, base_cfg, srv_handle) = {
        let mut cfg = base_hybrid_config(&admin_pk);
        cfg.server.db_path = db_path.clone();
        cfg.mode.max_admin_members = 2;
        cfg.storage.max_total_storage_mb = 4096;
        cfg.storage.max_free_pool_mb = 1024;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        cfg.server.bind = addr.to_string();
        cfg.server.public_base_url = format!("http://{}", addr);
        cfg.normalize();
        cfg.validate().unwrap();
        let state = AppState::from_config(cfg.clone()).unwrap();
        let app = build_router(state);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = rx_shutdown.await;
            })
            .await;
        });
        (format!("http://{}", addr), cfg, handle)
    };

    let client = reqwest::Client::new();

    // 1. Validation: max_user_storage_mb < 10 -> 400
    let bad_user_body = r#"{"max_total_storage_mb":512,"max_members":10,"max_user_storage_mb":5}"#;
    let (ts, nonce, sig) = sign_put_cfg(bad_user_body);
    let r_bad1 = client
        .put(format!("{}/sync.php?admin_config", addr_str))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", ts.to_string())
        .header("X-Drop-Nonce", &nonce)
        .header("X-Drop-Signature", &sig)
        .body(bad_user_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r_bad1.status().as_u16(), 400);

    // 2. Validation: max_total_storage_mb < max_user_storage_mb -> 400
    let bad_total_body = r#"{"max_total_storage_mb":20,"max_members":10,"max_user_storage_mb":30}"#;
    let (ts, nonce, sig) = sign_put_cfg(bad_total_body);
    let r_bad2 = client
        .put(format!("{}/sync.php?admin_config", addr_str))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", ts.to_string())
        .header("X-Drop-Nonce", &nonce)
        .header("X-Drop-Signature", &sig)
        .body(bad_total_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r_bad2.status().as_u16(), 400);

    // 3. Valid update: lower total to 500 MB (clamps free_pool 1024 -> 500), raise max_members 2 -> 3, user quota 15 MB
    let ok_body = r#"{"max_total_storage_mb":500,"max_members":3,"max_user_storage_mb":15}"#;
    let (ts, nonce, sig) = sign_put_cfg(ok_body);
    let r_ok = client
        .put(format!("{}/sync.php?admin_config", addr_str))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", ts.to_string())
        .header("X-Drop-Nonce", &nonce)
        .header("X-Drop-Signature", &sig)
        .body(ok_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r_ok.status().as_u16(), 200);
    let st_json: serde_json::Value = r_ok.json().await.unwrap();
    assert_eq!(st_json["max_bytes"], 500 * 1024 * 1024);
    assert_eq!(st_json["max_members"], 3);
    assert_eq!(st_json["max_user_bytes"], 15 * 1024 * 1024);
    assert_eq!(st_json["free_pool_max_bytes"], 500 * 1024 * 1024);

    // 4. Live enforcement: PUT ?members with 3 pubkeys succeeds (was capped at 2), 4 pubkeys fails (507)
    let (_, pk1) = gen_keypair();
    let (_, pk2) = gen_keypair();
    let (_, pk3) = gen_keypair();
    let (_, pk4) = gen_keypair();
    let m3_body = serde_json::json!({ "pubkeys": [&pk1, &pk2, &pk3] }).to_string();
    let now = unix_now() as i64;
    let m_nonce = random_hex(16);
    let m_msg =
        format_admin_put_members_message("card", now, &m_nonce, &sha256_hex(m3_body.as_bytes()));
    let m_sig = hex::encode(admin_sk.sign(m_msg.as_bytes()).to_bytes());
    let r_m3 = client
        .put(format!("{}/sync.php?members&channel=card", addr_str))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &m_nonce)
        .header("X-Drop-Signature", &m_sig)
        .body(m3_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r_m3.status().as_u16(), 200);

    let m4_body = serde_json::json!({ "pubkeys": [&pk1, &pk2, &pk3, &pk4] }).to_string();
    let m4_nonce = random_hex(16);
    let m4_msg =
        format_admin_put_members_message("card", now, &m4_nonce, &sha256_hex(m4_body.as_bytes()));
    let m4_sig = hex::encode(admin_sk.sign(m4_msg.as_bytes()).to_bytes());
    let r_m4 = client
        .put(format!("{}/sync.php?members&channel=card", addr_str))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &m4_nonce)
        .header("X-Drop-Signature", &m4_sig)
        .body(m4_body)
        .send()
        .await
        .unwrap();
    assert_eq!(r_m4.status().as_u16(), 507);

    // 5. Persistence across server restart (shutdown first server, reopen DB with original base_cfg)
    drop(client);
    let _ = tx_shutdown.send(());
    let _ = srv_handle.await;

    let restarted_state = AppState::from_config(base_cfg).unwrap();
    let restarted_st = restarted_state
        .db
        .admin_status(&restarted_state.config, unix_now())
        .unwrap();
    assert_eq!(restarted_st.max_bytes, 500 * 1024 * 1024);
    assert_eq!(restarted_st.max_members, 3);
    assert_eq!(restarted_st.max_user_bytes, 15 * 1024 * 1024);
    assert_eq!(restarted_st.free_pool_max_bytes, 500 * 1024 * 1024);
}

#[tokio::test]
async fn test_slot_put_returns_verified_slot_ack_receipt() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let (admin_sk, admin_pk) = gen_keypair();
    let (member_sk, member_pk) = gen_keypair();
    let cfg = base_hybrid_config(&admin_pk);
    let srv = TestServer::start(cfg).await;

    let members_body = serde_json::json!({ "pubkeys": [&member_pk] }).to_string();
    let ts = unix_now() as i64;
    let m_nonce = random_hex(16);
    let m_msg = format_admin_put_members_message(
        "backup",
        ts,
        &m_nonce,
        &sha256_hex(members_body.as_bytes()),
    );
    let m_sig = hex::encode(admin_sk.sign(m_msg.as_bytes()).to_bytes());
    let mem_resp = srv
        .client
        .put(format!("{}/sync.php?members&channel=backup", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", ts.to_string())
        .header("X-Drop-Nonce", &m_nonce)
        .header("X-Drop-Signature", &m_sig)
        .body(members_body)
        .send()
        .await
        .unwrap();
    assert_eq!(mem_resp.status().as_u16(), 200);

    let info_json: serde_json::Value = srv
        .client
        .get(format!("{}/sync.php?info", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let expected_lock_pub = info_json["lock"]["lock_pub"]
        .as_str()
        .expect("GET ?info exposes lock.lock_pub")
        .to_string();

    for prefix in [None, Some("pc")] {
        let payload = if prefix.is_some() {
            b"prefixed-backup-blob".to_vec()
        } else {
            b"unprefixed-backup-blob".to_vec()
        };
        let put_ts = unix_now() as i64;
        let put_nonce = random_hex(16);
        let pfx_str = prefix.unwrap_or("");
        let req_msg = format!(
            "HUMOCO-DROP-REQ-V1\nPUT\nbackup\n{}\n{}\n{}\n{}",
            pfx_str,
            put_ts,
            put_nonce,
            sha256_hex(&payload)
        );
        let req_sig = hex::encode(member_sk.sign(req_msg.as_bytes()).to_bytes());
        let mut req = srv
            .client
            .put(format!("{}/sync.php", srv.base_url))
            .header("X-Drop-Pubkey", &member_pk)
            .header("X-Channel", "backup")
            .header("X-Drop-Timestamp", put_ts.to_string())
            .header("X-Drop-Nonce", &put_nonce)
            .header("X-Drop-Signature", &req_sig);
        if let Some(p) = prefix {
            req = req.header("X-Drop-Prefix", p);
        }
        let resp = req.body(payload.clone()).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let ack = body["slot_ack"].as_object().expect("slot_ack present");
        let ack_lock_pub = ack["lock_pub"].as_str().unwrap();
        assert_eq!(ack_lock_pub, expected_lock_pub);
        assert_eq!(ack["pubkey"].as_str().unwrap(), member_pk);
        assert_eq!(ack["prefix"].as_str(), prefix);
        assert_eq!(ack["channel"].as_str().unwrap(), "backup");
        let expected_etag = sha256_hex(&payload);
        assert_eq!(ack["etag"].as_str().unwrap(), expected_etag);
        let ack_ts = ack["timestamp"].as_u64().unwrap();
        let ack_sig_bytes: [u8; 64] = hex::decode(ack["sig"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let vk_bytes: [u8; 32] = hex::decode(ack_lock_pub).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();
        let ack_msg = format!(
            "HUMOCO-SLOT-ACK-V1\n{}\n{}\n{}\nbackup\n{}\n{}",
            ack_lock_pub, member_pk, pfx_str, expected_etag, ack_ts
        );
        vk.verify(ack_msg.as_bytes(), &Signature::from_bytes(&ack_sig_bytes))
            .expect("slot_ack Ed25519 signature must verify");
    }
}

#[tokio::test]
async fn test_sync007_creator_zero_timelock_when_no_guarantors() {
    let (a1_sk, _, s1) = start_lock_test_server(true, None).await;
    let (a2_sk, _, s2) = start_lock_test_server(true, None).await;
    assert_eq!(s1.state.config.lock.proposal_timelock_secs, 259_200);

    let creator_mig_sk = SigningKey::from_bytes(&[97u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;

    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
    let e_s2 = server_entry_for_test(&s2, &a2_sk, humoco_proto::NominatedBy::Creator);
    let man = build_multi_server_manifest(
        vec![e_s1.clone()],
        Vec::new(),
        1,
        creator_mig_pub,
        Vec::new(),
        t0 * 1_000,
        quarter,
    );
    let aid = man.rev1_anchor_id().unwrap();

    let tkt = issue_pow_ticket_db(&s1, aid, quarter, t0);
    let bkt = humoco_proto::derive_bucket(&aid, &s1.state.db.lock_pubkey_bytes().unwrap());
    let g_sk = SigningKey::from_bytes(&[98u8; 32]);
    let r1_sk = SigningKey::from_bytes(&[99u8; 32]);
    let e0 = sign_lock_entry_helper(
        aid,
        [0x51; 32],
        [0u8; 32],
        0,
        0,
        [0x61; 32],
        &g_sk,
        humoco_proto::hash_pubkey_sha3(&r1_sk.verifying_key().to_bytes()),
        None,
        Some(&creator_mig_sk),
        8,
    );
    let (c0, _) = s1
        .state
        .db
        .process_lock_batch(
            &s1.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt,
                recipient_nonce: [0x11; 32],
                entries: vec![e0.to_wire_hex().unwrap()],
                manifest: Some(man.clone()),
                genesis_ticket: Some(tkt),
                known_head_receipt: None,
            },
            t0,
        )
        .unwrap();
    assert_eq!(c0, 200);

    let t1 = t0 + 100;
    let prop = build_signed_proposal(
        aid,
        1,
        2,
        vec![e_s1.clone(), e_s2.clone()],
        Vec::new(),
        quarter,
        t1,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        Vec::new(),
    );
    let (p_code, p_val) = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: prop.clone(),
                current_manifest: None,
            },
            t1,
        )
        .unwrap();
    assert_eq!(p_code, 200);
    assert_eq!(p_val["effective_at"], t1);
    let snap: humoco_proto::SnapshotExport =
        serde_json::from_value(p_val["snapshot_export"].clone()).unwrap();

    // Immediate import & sign_commit at t1 succeed without 72h freeze!
    let mut acks = Vec::new();
    let mut imported_state_hash = [0u8; 32];
    for srv in [&s1, &s2] {
        let (imp_code, imp_val) = srv
            .state
            .db
            .process_lock_import(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockImportRequest {
                    anchor_id: aid,
                    active_manifest: man.clone(),
                    proposal: prop.clone(),
                    snapshots: vec![snap.clone()],
                    quorum_certificates: Vec::new(),
                },
                t1,
            )
            .unwrap();
        assert_eq!(imp_code, 200);
        let ack: humoco_proto::ImportAck =
            serde_json::from_value(imp_val["import_ack"].clone()).unwrap();
        imported_state_hash = ack.imported_state_hash;
        acks.push(ack);
    }

    let (sc_code, _) = s1
        .state
        .db
        .process_lock_commit(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                anchor_id: aid,
                proposal: prop,
                imported_state_hash,
                import_acks: acks,
            },
            t1,
        )
        .unwrap();
    assert_eq!(sc_code, 200);
}

#[tokio::test]
async fn test_k4_creator_non_growth_keeps_timelock_and_rejects_collapse_to_single_server() {
    let (a1_sk, _, s1) = start_lock_test_server(true, None).await;
    let (a2_sk, _, s2) = start_lock_test_server(true, None).await;
    let (a3_sk, _, s3) = start_lock_test_server(true, None).await;

    let creator_mig_sk = SigningKey::from_bytes(&[107u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;

    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
    let e_s2 = server_entry_for_test(&s2, &a2_sk, humoco_proto::NominatedBy::Creator);
    let e_s3 = server_entry_for_test(&s3, &a3_sk, humoco_proto::NominatedBy::Creator);
    let man = build_multi_server_manifest(
        vec![e_s1.clone(), e_s2.clone()],
        Vec::new(),
        2,
        creator_mig_pub,
        Vec::new(),
        t0 * 1_000,
        quarter,
    );
    let aid = man.rev1_anchor_id().unwrap();

    for srv in [&s1, &s2] {
        let tkt = issue_pow_ticket_db(srv, aid, quarter, t0);
        let bkt = humoco_proto::derive_bucket(&aid, &srv.state.db.lock_pubkey_bytes().unwrap());
        let g_sk = SigningKey::from_bytes(&[108u8; 32]);
        let r1_sk = SigningKey::from_bytes(&[109u8; 32]);
        let e0 = sign_lock_entry_helper(
            aid,
            [0x52; 32],
            [0u8; 32],
            0,
            0,
            [0x62; 32],
            &g_sk,
            humoco_proto::hash_pubkey_sha3(&r1_sk.verifying_key().to_bytes()),
            None,
            Some(&creator_mig_sk),
            8,
        );
        let (code, _) = srv
            .state
            .db
            .process_lock_batch(
                &srv.state.config,
                humoco_sync_server::locks::LockBatchRequest {
                    anchor_id: aid,
                    bucket: bkt,
                    recipient_nonce: [0x12; 32],
                    entries: vec![e0.to_wire_hex().unwrap()],
                    manifest: Some(man.clone()),
                    genesis_ticket: Some(tkt),
                    known_head_receipt: None,
                },
                t0,
            )
            .unwrap();
        assert_eq!(code, 200);
    }

    let t1 = t0 + 100;
    // Collapse from N=2(Q=2) -> N=1(Q=1) is rejected outright by verify_nomination_binding
    let collapse_prop = build_signed_proposal(
        aid,
        1,
        1,
        vec![e_s1.clone()],
        Vec::new(),
        quarter,
        t1,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        Vec::new(),
    );
    let err = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: collapse_prop,
                current_manifest: None,
            },
            t1,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        humoco_sync_server::db::DbError::Http { status: 400, .. }
    ));

    // Server replacement 2 -> 2 (not pure growth) MUST still enforce full 72h timelock
    let replace_prop = build_signed_proposal(
        aid,
        1,
        2,
        vec![e_s1, e_s3],
        Vec::new(),
        quarter,
        t1,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        Vec::new(),
    );
    let (p_code, p_val) = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: replace_prop,
                current_manifest: None,
            },
            t1,
        )
        .unwrap();
    assert_eq!(p_code, 200);
    assert_eq!(
        p_val["effective_at"].as_u64().unwrap(),
        t1 + s1.state.config.lock.proposal_timelock_secs
    );
}

#[tokio::test]
async fn test_s01_output_branch_claimed_aborts_partial_batch_atomically() {
    let (admin_sk, _, srv) = start_lock_test_server(true, None).await;
    let lock_pub = srv.state.db.lock_pubkey_bytes().unwrap();
    let admin_pub = admin_sk.verifying_key().to_bytes();
    let creator_mig_sk = SigningKey::from_bytes(&[121u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 3).unwrap();
    let manifest = build_single_server_manifest(admin_pub, lock_pub, creator_mig_pub, quarter);
    let anchor_id = manifest.rev1_anchor_id().unwrap();
    let bucket = humoco_proto::derive_bucket(&anchor_id, &lock_pub);
    let bucket_hex = hex::encode(bucket);
    let ticket = issue_pow_ticket_http(&srv, anchor_id, quarter).await;

    let g_sk = SigningKey::from_bytes(&[122u8; 32]);
    let r1_sk = SigningKey::from_bytes(&[123u8; 32]);
    let r1_hash = humoco_proto::hash_pubkey_sha3(&r1_sk.verifying_key().to_bytes());
    let e0 = sign_lock_entry_helper(
        anchor_id,
        [0x01; 32],
        [0u8; 32],
        0,
        0,
        [0x10; 32],
        &g_sk,
        r1_hash,
        None,
        Some(&creator_mig_sk),
        8,
    );
    let e1_a = sign_lock_entry_helper(
        anchor_id, [0x11; 32], e0.slot, 0, 1, [0x21; 32], &r1_sk, [0x71; 32], None, None, 8,
    );
    let e1_b = sign_lock_entry_helper(
        anchor_id, [0x22; 32], e0.slot, 0, 1, [0x22; 32], &r1_sk, [0x72; 32], None, None, 8,
    );

    // 1. Brand-new bucket batch [e0, e1_a, e1_b] hits output_branch_already_claimed on e1_b ->
    //    must abort atomically without creating bucket or orphan entries.
    let resp = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "bucket": bucket_hex,
            "recipient_nonce": hex::encode([0xD1; 32]),
            "entries": [
                e0.to_wire_hex().unwrap(),
                e1_a.to_wire_hex().unwrap(),
                e1_b.to_wire_hex().unwrap(),
            ],
            "manifest": manifest,
            "genesis_ticket": ticket,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409);
    let err_json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(err_json["error"], "output_branch_already_claimed");
    assert_eq!(srv.state.db.lock_bucket_count_and_inodes().unwrap(), (0, 0));
    assert!(srv
        .state
        .db
        .lock_entries_in_bucket(&bucket_hex)
        .unwrap()
        .is_empty());

    // 2. Commit [e0] first, then submit [e1_a, e1_b] -> must abort cleanly leaving ONLY e0.
    let ok_resp = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "bucket": bucket_hex,
            "recipient_nonce": hex::encode([0xD2; 32]),
            "entries": [e0.to_wire_hex().unwrap()],
            "manifest": manifest,
            "genesis_ticket": ticket,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok_resp.status().as_u16(), 200);
    assert_eq!(srv.state.db.lock_bucket_count_and_inodes().unwrap(), (1, 1));

    let resp2 = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "bucket": bucket_hex,
            "recipient_nonce": hex::encode([0xD3; 32]),
            "entries": [e1_a.to_wire_hex().unwrap(), e1_b.to_wire_hex().unwrap()],
            "manifest": serde_json::Value::Null,
            "genesis_ticket": serde_json::Value::Null,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status().as_u16(), 409);
    let err_json2: serde_json::Value = resp2.json().await.unwrap();
    assert_eq!(err_json2["error"], "output_branch_already_claimed");
    assert_eq!(srv.state.db.lock_bucket_count_and_inodes().unwrap(), (1, 1));
    let entries_after = srv.state.db.lock_entries_in_bucket(&bucket_hex).unwrap();
    assert_eq!(entries_after.len(), 1);
    assert!(entries_after.contains_key(&hex::encode(e0.slot)));
}

#[test]
fn test_s01_ticket_replay_rejected_at_exact_expiry_boundary() {
    let (admin_sk, admin_pk) = gen_keypair();
    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.allow_pow_tickets = true;
    cfg.lock.ticket_pow_bits = 8;

    let dir = TempDir::new().unwrap();
    let db = humoco_sync_server::db::SyncDb::open(&dir.path().join("sync.redb"), "").unwrap();

    let anchor_id = [0x61; 32];
    let quarter = humoco_proto::encode_quarter(2031, 3).unwrap();
    let t0 = 1_795_000_000u64;

    // 1. SignedMember exact-boundary replay: ts = t0 + 60, first call at t0 -> exp = t0 + 120.
    //    Replaying at now_secs = t0 + 120 keeps |now - ts| == 60 <= 60 while now_secs == exp.
    let raw_body = serde_json::to_vec(&serde_json::json!({
        "anchor_id": hex::encode(anchor_id),
        "retain_until_quarter": quarter,
    }))
    .unwrap();
    let ts_signed = (t0 + 60) as i64;
    let nonce = random_hex(16);
    let msg = parse_member_message(
        "POST",
        "lock_ticket",
        "",
        ts_signed,
        &nonce,
        &sha256_hex(&raw_body),
    );
    let sig = hex::encode(admin_sk.sign(msg.as_bytes()).to_bytes());
    let req = humoco_sync_server::locks::LockTicketRequest {
        anchor_id,
        retain_until_quarter: quarter,
        pow_timestamp: None,
        pow_nonce: None,
    };

    assert!(db
        .issue_genesis_ticket(
            &cfg,
            humoco_sync_server::locks::TicketCallerAuth::SignedMember {
                pubkey_hex: &admin_pk,
                timestamp: ts_signed,
                nonce: &nonce,
                sig: &sig,
                raw_body: &raw_body,
            },
            req.clone(),
            t0,
        )
        .is_ok());

    let err_member = db
        .issue_genesis_ticket(
            &cfg,
            humoco_sync_server::locks::TicketCallerAuth::SignedMember {
                pubkey_hex: &admin_pk,
                timestamp: ts_signed,
                nonce: &nonce,
                sig: &sig,
                raw_body: &raw_body,
            },
            req,
            t0 + 120,
        )
        .unwrap_err();
    assert!(matches!(
        err_member,
        humoco_sync_server::db::DbError::Http { status: 409, .. }
    ));

    // 2. UnauthenticatedPow exact-boundary replay: pow_ts = t0 + 300, first call at t0 -> exp = t0 + 600.
    //    Replaying at now_secs = t0 + 600 keeps |now - pow_ts| == 300 <= 300 while now_secs == exp.
    let pow_ts = t0 + 300;
    let pow_nonce =
        humoco_proto::solve_ticket_pow(&anchor_id, quarter, pow_ts, 8, 0, 200_000).unwrap();
    let pow_req = humoco_sync_server::locks::LockTicketRequest {
        anchor_id,
        retain_until_quarter: quarter,
        pow_timestamp: Some(pow_ts),
        pow_nonce: Some(pow_nonce),
    };

    assert!(db
        .issue_genesis_ticket(
            &cfg,
            humoco_sync_server::locks::TicketCallerAuth::UnauthenticatedPow,
            pow_req.clone(),
            t0,
        )
        .is_ok());

    let err_pow = db
        .issue_genesis_ticket(
            &cfg,
            humoco_sync_server::locks::TicketCallerAuth::UnauthenticatedPow,
            pow_req,
            t0 + 600,
        )
        .unwrap_err();
    assert!(matches!(
        err_pow,
        humoco_sync_server::db::DbError::Http { status: 409, .. }
    ));
}

#[tokio::test]
async fn test_s02_self_frozen_persists_across_propose_veto_and_finalize() {
    let dir = TempDir::new().unwrap();
    let db1_path = dir.path().join("s1.redb");
    let db1_snap_path = dir.path().join("s1.snap.redb");

    let (a1_sk, a1_pk) = gen_keypair();
    let (a2_sk, _, s2) = start_lock_test_server(true, None).await;
    let (a3_sk, _, s3) = start_lock_test_server(true, None).await;
    let (a4_sk, _, s4) = start_lock_test_server(true, None).await;

    let mut cfg1 = base_hybrid_config(&a1_pk);
    cfg1.lock.allow_pow_tickets = true;
    cfg1.lock.ticket_pow_bits = 8;

    let creator_mig_sk = SigningKey::from_bytes(&[151u8; 32]);
    let g_mig_sk = SigningKey::from_bytes(&[152u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let g_mig_pub = g_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;

    let (lp1, manifest, anchor_id, bucket1, ticket1, e0, e1, e2, receipt_seq2) = {
        let db1 = humoco_sync_server::db::SyncDb::open(&db1_path, "").unwrap();
        let lp1 = db1.lock_pubkey_bytes().unwrap();
        let e_s1 = humoco_proto::ServerEntry {
            write_url: "https://s1.example/sync.php".to_string(),
            read_url: "https://s1.example/humoco_sync_data".to_string(),
            admin_pub: a1_sk.verifying_key().to_bytes(),
            lock_pub: lp1,
            nominated_by: humoco_proto::NominatedBy::Creator,
        };
        let e_s2 = server_entry_for_test(&s2, &a2_sk, humoco_proto::NominatedBy::Creator);
        let e_s3 = server_entry_for_test(&s3, &a3_sk, humoco_proto::NominatedBy::Guarantor(0));
        let e_s4 = server_entry_for_test(&s4, &a4_sk, humoco_proto::NominatedBy::Guarantor(0));
        let manifest = build_multi_server_manifest(
            vec![e_s1, e_s2, e_s3],
            vec![e_s4],
            2,
            creator_mig_pub,
            vec![g_mig_pub],
            t0 * 1_000,
            quarter,
        );
        let anchor_id = manifest.rev1_anchor_id().unwrap();
        let bucket1 = humoco_proto::derive_bucket(&anchor_id, &lp1);
        let pow_nonce =
            humoco_proto::solve_ticket_pow(&anchor_id, quarter, t0, 8, 0, 200_000).unwrap();
        let ticket1 = db1
            .issue_genesis_ticket(
                &cfg1,
                humoco_sync_server::locks::TicketCallerAuth::UnauthenticatedPow,
                humoco_sync_server::locks::LockTicketRequest {
                    anchor_id,
                    retain_until_quarter: quarter,
                    pow_timestamp: Some(t0),
                    pow_nonce: Some(pow_nonce),
                },
                t0,
            )
            .unwrap();

        let g_sk = SigningKey::from_bytes(&[153u8; 32]);
        let r1_sk = SigningKey::from_bytes(&[154u8; 32]);
        let r2_sk = SigningKey::from_bytes(&[155u8; 32]);
        let e0 = sign_lock_entry_helper(
            anchor_id,
            [0x61; 32],
            [0u8; 32],
            0,
            0,
            [0x71; 32],
            &g_sk,
            humoco_proto::hash_pubkey_sha3(&r1_sk.verifying_key().to_bytes()),
            None,
            Some(&creator_mig_sk),
            8,
        );
        let e1 = sign_lock_entry_helper(
            anchor_id,
            [0x62; 32],
            e0.slot,
            0,
            1,
            [0x72; 32],
            &r1_sk,
            humoco_proto::hash_pubkey_sha3(&r2_sk.verifying_key().to_bytes()),
            None,
            None,
            8,
        );
        let e2 = sign_lock_entry_helper(
            anchor_id, [0x63; 32], e1.slot, 0, 2, [0x73; 32], &r2_sk, [0xAA; 32], None, None, 8,
        );

        let (c0, _) = db1
            .process_lock_batch(
                &cfg1,
                humoco_sync_server::locks::LockBatchRequest {
                    anchor_id,
                    bucket: bucket1,
                    recipient_nonce: [0x11; 32],
                    entries: vec![e0.to_wire_hex().unwrap()],
                    manifest: Some(manifest.clone()),
                    genesis_ticket: Some(ticket1.clone()),
                    known_head_receipt: None,
                },
                t0,
            )
            .unwrap();
        assert_eq!(c0, 200);
        drop(db1);
        std::fs::copy(&db1_path, &db1_snap_path).unwrap();

        let db1 = humoco_sync_server::db::SyncDb::open(&db1_path, "").unwrap();
        let (c1, v1) = db1
            .process_lock_batch(
                &cfg1,
                humoco_sync_server::locks::LockBatchRequest {
                    anchor_id,
                    bucket: bucket1,
                    recipient_nonce: [0x12; 32],
                    entries: vec![e1.to_wire_hex().unwrap()],
                    manifest: None,
                    genesis_ticket: None,
                    known_head_receipt: None,
                },
                t0 + 5,
            )
            .unwrap();
        assert_eq!(c1, 200);
        let resp1: humoco_sync_server::locks::LockBatchResponse =
            serde_json::from_value(v1).unwrap();
        let receipt_seq2 = resp1.receipts.into_iter().next().unwrap();
        assert_eq!(receipt_seq2.write_seq, 2);
        (
            lp1,
            manifest,
            anchor_id,
            bucket1,
            ticket1,
            e0,
            e1,
            e2,
            receipt_seq2,
        )
    };

    // Roll back S1 to write_seq=1 and trigger SelfFrozen via known_head_receipt
    std::fs::copy(&db1_snap_path, &db1_path).unwrap();
    let db1 = humoco_sync_server::db::SyncDb::open(&db1_path, "").unwrap();
    assert_eq!(db1.lock_pubkey_bytes().unwrap(), lp1);

    let (rb_code, rb_val) = db1
        .process_lock_batch(
            &cfg1,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id,
                bucket: bucket1,
                recipient_nonce: [0x13; 32],
                entries: vec![e0.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: Some(receipt_seq2),
            },
            t0 + 10,
        )
        .unwrap();
    assert_eq!(rb_code, 409);
    assert_eq!(rb_val["error"], "bucket_self_frozen");

    // 1. Propose + Veto on SelfFrozen bucket MUST NOT escape back to Active!
    let p_veto = build_signed_proposal(
        anchor_id,
        1,
        2,
        vec![
            manifest.servers[0].clone(),
            manifest.servers[1].clone(),
            manifest.successors[0].clone(),
        ],
        Vec::new(),
        quarter,
        t0 + 20,
        humoco_proto::ProposalInitiator::HolderStandby,
        None,
        Vec::new(),
    );
    let p_veto_hash = p_veto.core_digest().unwrap();
    let (pv_code, _) = db1
        .process_lock_freeze(
            &cfg1,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: p_veto,
                current_manifest: None,
            },
            t0 + 20,
        )
        .unwrap();
    assert_eq!(pv_code, 200);

    let mut veto = humoco_proto::MigrationVeto {
        anchor_id,
        from_rev: 1,
        proposal_hash: p_veto_hash,
        vetoer_pub: g_mig_pub,
        vetoed_at: t0 + 30,
        sig: [0; 64],
    };
    veto.sig = g_mig_sk.sign(&veto.digest()).to_bytes();
    let (vc, _) = db1
        .process_lock_freeze(
            &cfg1,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Veto { veto },
            t0 + 30,
        )
        .unwrap();
    assert_eq!(vc, 200);

    let status_after_veto = db1
        .get_lock_freeze_status(&cfg1, anchor_id, t0 + 35)
        .unwrap();
    assert!(
        status_after_veto["bucket_freeze_state"]["self_frozen"].is_object(),
        "SelfFrozen must survive Propose + Veto, got: {status_after_veto}"
    );
    let (write_code, write_val) = db1
        .process_lock_batch(
            &cfg1,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id,
                bucket: bucket1,
                recipient_nonce: [0x14; 32],
                entries: vec![e1.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: None,
            },
            t0 + 35,
        )
        .unwrap();
    assert_eq!(write_code, 409);
    assert_eq!(write_val["error"], "bucket_self_frozen");

    // 2. Propose + Import + SignCommit + Finalize keeping S1 in new_committee MUST keep S1 SelfFrozen!
    let tkt2 = issue_pow_ticket_db(&s2, anchor_id, quarter, t0);
    let bkt2 = humoco_proto::derive_bucket(&anchor_id, &s2.state.db.lock_pubkey_bytes().unwrap());
    s2.state
        .db
        .process_lock_batch(
            &s2.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id,
                bucket: bkt2,
                recipient_nonce: [0x15; 32],
                entries: vec![e0.to_wire_hex().unwrap(), e1.to_wire_hex().unwrap()],
                manifest: Some(manifest.clone()),
                genesis_ticket: Some(tkt2),
                known_head_receipt: None,
            },
            t0 + 10,
        )
        .unwrap();

    let t_prop2 = t0 + 40;
    let p_rot = build_signed_proposal(
        anchor_id,
        1,
        2,
        vec![
            manifest.servers[0].clone(),
            manifest.servers[1].clone(),
            manifest.successors[0].clone(),
        ],
        Vec::new(),
        quarter,
        t_prop2,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        vec![(&g_mig_sk, 0)],
    );

    let (_, f1_val) = db1
        .process_lock_freeze(
            &cfg1,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: p_rot.clone(),
                current_manifest: None,
            },
            t_prop2,
        )
        .unwrap();
    let (_, f2_val) = s2
        .state
        .db
        .process_lock_freeze(
            &s2.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: p_rot.clone(),
                current_manifest: None,
            },
            t_prop2,
        )
        .unwrap();
    let snaps = vec![
        serde_json::from_value::<humoco_proto::SnapshotExport>(f1_val["snapshot_export"].clone())
            .unwrap(),
        serde_json::from_value::<humoco_proto::SnapshotExport>(f2_val["snapshot_export"].clone())
            .unwrap(),
    ];

    let t_mature = t_prop2 + cfg1.lock.proposal_timelock_secs;
    let mut acks = Vec::new();
    let mut imp_hash = [0u8; 32];
    for (is_s1, srv_opt) in [(true, None), (false, Some(&s2)), (false, Some(&s4))] {
        let (code, val) = if is_s1 {
            db1.process_lock_import(
                &cfg1,
                humoco_sync_server::lock_rotation::LockImportRequest {
                    anchor_id,
                    active_manifest: manifest.clone(),
                    proposal: p_rot.clone(),
                    snapshots: snaps.clone(),
                    quorum_certificates: Vec::new(),
                },
                t_mature,
            )
            .unwrap()
        } else {
            let srv = srv_opt.unwrap();
            srv.state
                .db
                .process_lock_import(
                    &srv.state.config,
                    humoco_sync_server::lock_rotation::LockImportRequest {
                        anchor_id,
                        active_manifest: manifest.clone(),
                        proposal: p_rot.clone(),
                        snapshots: snaps.clone(),
                        quorum_certificates: Vec::new(),
                    },
                    t_mature,
                )
                .unwrap()
        };
        assert_eq!(code, 200);
        let ack: humoco_proto::ImportAck =
            serde_json::from_value(val["import_ack"].clone()).unwrap();
        imp_hash = ack.imported_state_hash;
        acks.push(ack);
    }

    let (_, sc1) = db1
        .process_lock_commit(
            &cfg1,
            humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                anchor_id,
                proposal: p_rot.clone(),
                imported_state_hash: imp_hash,
                import_acks: acks.clone(),
            },
            t_mature,
        )
        .unwrap();
    let (_, sc2) = s2
        .state
        .db
        .process_lock_commit(
            &s2.state.config,
            humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                anchor_id,
                proposal: p_rot.clone(),
                imported_state_hash: imp_hash,
                import_acks: acks.clone(),
            },
            t_mature,
        )
        .unwrap();
    let commit_sigs = vec![
        serde_json::from_value::<humoco_proto::CommitteeSignature>(
            sc1["committee_signature"].clone(),
        )
        .unwrap(),
        serde_json::from_value::<humoco_proto::CommitteeSignature>(
            sc2["committee_signature"].clone(),
        )
        .unwrap(),
    ];
    let cert = humoco_proto::MigrationCert {
        anchor_id,
        genesis_manifest: Some(Box::new(manifest.clone())),
        proposal: p_rot,
        imported_state_hash: imp_hash,
        import_acks: acks,
        commit_sigs,
    };
    let (rev2_manifest, _) = cert.verify_step(&anchor_id, &manifest).unwrap();

    let (fin_code, fin_val) = db1
        .process_lock_commit(
            &cfg1,
            humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                anchor_id,
                new_manifest: rev2_manifest,
            },
            t_mature,
        )
        .unwrap();
    assert_eq!(fin_code, 200);
    assert!(
        fin_val["bucket_freeze_state"]["self_frozen"].is_object(),
        "Finalize keeping SelfFrozen server in committee must preserve SelfFrozen, got: {fin_val}"
    );
    let (post_fin_code, post_fin_val) = db1
        .process_lock_batch(
            &cfg1,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id,
                bucket: bucket1,
                recipient_nonce: [0x16; 32],
                entries: vec![e2.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: None,
            },
            t_mature + 5,
        )
        .unwrap();
    assert_eq!(post_fin_code, 409);
    assert_eq!(post_fin_val["error"], "bucket_self_frozen");
    let _ = ticket1;
}

#[tokio::test]
async fn test_s02_rotation_guards_block_stale_replay_downgrade_and_unrelated_finalize() {
    let (a1_sk, _, s1) = start_lock_test_server(true, None).await;
    let (a2_sk, _, s2) = start_lock_test_server(true, None).await;
    let (a3_sk, _, s3) = start_lock_test_server(true, None).await;
    let (a5_sk, _, s5) = start_lock_test_server(true, None).await;

    let creator_mig_sk = SigningKey::from_bytes(&[161u8; 32]);
    let g_mig_sk = SigningKey::from_bytes(&[162u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let g_mig_pub = g_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;

    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
    let e_s2 = server_entry_for_test(&s2, &a2_sk, humoco_proto::NominatedBy::Creator);
    let e_s3 = server_entry_for_test(&s3, &a3_sk, humoco_proto::NominatedBy::Creator);
    let e_s5 = server_entry_for_test(&s5, &a5_sk, humoco_proto::NominatedBy::Creator);

    let man_rev1 = build_multi_server_manifest(
        vec![e_s1.clone(), e_s2.clone(), e_s3.clone()],
        Vec::new(),
        2,
        creator_mig_pub,
        vec![g_mig_pub],
        t0 * 1_000,
        quarter,
    );
    let aid = man_rev1.rev1_anchor_id().unwrap();
    let aid_hex = hex::encode(aid);

    let g_sk = SigningKey::from_bytes(&[163u8; 32]);
    let r1_sk = SigningKey::from_bytes(&[164u8; 32]);
    let r2_sk = SigningKey::from_bytes(&[165u8; 32]);
    let e0 = sign_lock_entry_helper(
        aid,
        [0x81; 32],
        [0u8; 32],
        0,
        0,
        [0x91; 32],
        &g_sk,
        humoco_proto::hash_pubkey_sha3(&r1_sk.verifying_key().to_bytes()),
        None,
        Some(&creator_mig_sk),
        8,
    );
    let e1 = sign_lock_entry_helper(
        aid,
        [0x82; 32],
        e0.slot,
        0,
        1,
        [0x92; 32],
        &r1_sk,
        humoco_proto::hash_pubkey_sha3(&r2_sk.verifying_key().to_bytes()),
        None,
        None,
        8,
    );
    let e2 = sign_lock_entry_helper(
        aid, [0x83; 32], e1.slot, 0, 2, [0x93; 32], &r2_sk, [0xDD; 32], None, None, 8,
    );

    for srv in [&s1, &s2, &s3] {
        let tkt = issue_pow_ticket_db(srv, aid, quarter, t0);
        let bkt = humoco_proto::derive_bucket(&aid, &srv.state.db.lock_pubkey_bytes().unwrap());
        srv.state
            .db
            .process_lock_batch(
                &srv.state.config,
                humoco_sync_server::locks::LockBatchRequest {
                    anchor_id: aid,
                    bucket: bkt,
                    recipient_nonce: [0x21; 32],
                    entries: vec![e0.to_wire_hex().unwrap()],
                    manifest: Some(man_rev1.clone()),
                    genesis_ticket: Some(tkt),
                    known_head_receipt: None,
                },
                t0,
            )
            .unwrap();
    }

    // Rotate Rev 1 -> Rev 2: [S1, S2, S3] -> [S1, S2, S5]
    let t_prop12 = t0 + 10;
    let prop12 = build_signed_proposal(
        aid,
        1,
        2,
        vec![e_s1.clone(), e_s2.clone(), e_s5.clone()],
        Vec::new(),
        quarter,
        t_prop12,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        Vec::new(),
    );
    let prop12_hash = prop12.core_digest().unwrap();

    let mut snaps12 = Vec::new();
    for srv in [&s1, &s2, &s3] {
        let (_, v) = srv
            .state
            .db
            .process_lock_freeze(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                    proposal: prop12.clone(),
                    current_manifest: None,
                },
                t_prop12,
            )
            .unwrap();
        snaps12.push(
            serde_json::from_value::<humoco_proto::SnapshotExport>(v["snapshot_export"].clone())
                .unwrap(),
        );
    }

    let t_fin12 = t_prop12 + s1.state.config.lock.proposal_timelock_secs;
    let mut acks12 = Vec::new();
    let mut imp_hash12 = [0u8; 32];
    for srv in [&s1, &s2, &s5] {
        let (_, v) = srv
            .state
            .db
            .process_lock_import(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockImportRequest {
                    anchor_id: aid,
                    active_manifest: man_rev1.clone(),
                    proposal: prop12.clone(),
                    snapshots: snaps12.clone(),
                    quorum_certificates: Vec::new(),
                },
                t_fin12,
            )
            .unwrap();
        let ack: humoco_proto::ImportAck = serde_json::from_value(v["import_ack"].clone()).unwrap();
        imp_hash12 = ack.imported_state_hash;
        acks12.push(ack);
    }

    let mut cs12 = Vec::new();
    for srv in [&s1, &s2] {
        let (_, v) = srv
            .state
            .db
            .process_lock_commit(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                    anchor_id: aid,
                    proposal: prop12.clone(),
                    imported_state_hash: imp_hash12,
                    import_acks: acks12.clone(),
                },
                t_fin12,
            )
            .unwrap();
        cs12.push(
            serde_json::from_value::<humoco_proto::CommitteeSignature>(
                v["committee_signature"].clone(),
            )
            .unwrap(),
        );
    }
    let cert12 = humoco_proto::MigrationCert {
        anchor_id: aid,
        genesis_manifest: Some(Box::new(man_rev1.clone())),
        proposal: prop12.clone(),
        imported_state_hash: imp_hash12,
        import_acks: acks12,
        commit_sigs: cs12,
    };
    let (man_rev2, _) = cert12.verify_step(&aid, &man_rev1).unwrap();

    for srv in [&s1, &s2, &s3, &s5] {
        let (code, _) = srv
            .state
            .db
            .process_lock_commit(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                    anchor_id: aid,
                    new_manifest: man_rev2.clone(),
                },
                t_fin12,
            )
            .unwrap();
        assert_eq!(code, 200);
    }

    // Commit new Rev-2 entry e1 onto S1, S2, S5
    for srv in [&s1, &s2, &s5] {
        let bkt = humoco_proto::derive_bucket(&aid, &srv.state.db.lock_pubkey_bytes().unwrap());
        let (code, _) = srv
            .state
            .db
            .process_lock_batch(
                &srv.state.config,
                humoco_sync_server::locks::LockBatchRequest {
                    anchor_id: aid,
                    bucket: bkt,
                    recipient_nonce: [0x22; 32],
                    entries: vec![e1.to_wire_hex().unwrap()],
                    manifest: None,
                    genesis_ticket: None,
                    known_head_receipt: None,
                },
                t_fin12 + 5,
            )
            .unwrap();
        assert_eq!(code, 200);
    }

    // SYNC-S02-03a: Replaying Rev 1->2 Propose on active Rev-2 overlap server S1 must return 409
    let stale_prop_err = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: prop12.clone(),
                current_manifest: None,
            },
            t_fin12 + 10,
        )
        .unwrap_err();
    assert!(
        matches!(
            stale_prop_err,
            humoco_sync_server::db::DbError::Http { status: 409, .. }
        ),
        "Stale Rev-1 Propose replay must reject with 409, got {stale_prop_err:?}"
    );

    // SYNC-S02-03b: Veto(from_rev=1) after Rev 2 Finalize must reject with 409 (even with clock skew)
    let mut stale_veto = humoco_proto::MigrationVeto {
        anchor_id: aid,
        from_rev: 1,
        proposal_hash: prop12_hash,
        vetoer_pub: g_mig_pub,
        vetoed_at: t_prop12 + 100,
        sig: [0; 64],
    };
    stale_veto.sig = g_mig_sk.sign(&stale_veto.digest()).to_bytes();
    let stale_veto_err = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Veto { veto: stale_veto },
            t_prop12 + 100,
        )
        .unwrap_err();
    assert!(
        matches!(
            stale_veto_err,
            humoco_sync_server::db::DbError::Http { status: 409, .. }
        ),
        "Veto on already-finalized revision must reject with 409, got {stale_veto_err:?}"
    );

    // SYNC-S02-02a: Replaying Rev 1->2 ?lock_import on S1/S5 must reject 409 and preserve Rev-2 entry e1!
    for srv in [&s1, &s5] {
        let replay_imp_err = srv
            .state
            .db
            .process_lock_import(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockImportRequest {
                    anchor_id: aid,
                    active_manifest: man_rev1.clone(),
                    proposal: prop12.clone(),
                    snapshots: snaps12.clone(),
                    quorum_certificates: Vec::new(),
                },
                t_fin12 + 20,
            )
            .unwrap_err();
        assert!(
            matches!(
                replay_imp_err,
                humoco_sync_server::db::DbError::Http { status: 409, .. }
            ),
            "Replayed Rev 1->2 lock_import must fail with 409, got {replay_imp_err:?}"
        );
        let bkt_hex = hex::encode(humoco_proto::derive_bucket(
            &aid,
            &srv.state.db.lock_pubkey_bytes().unwrap(),
        ));
        let entries = srv.state.db.lock_entries_in_bucket(&bkt_hex).unwrap();
        assert!(
            entries.contains_key(&hex::encode(e1.slot)),
            "Rev-2 entry e1 must remain intact after rejected replay"
        );
    }

    // Rotate Rev 2 -> Rev 3: [S1, S2, S5] -> [S1, S3, S5] (bringing retired S3 back!)
    let t_prop23 = t_fin12 + 30;
    let prop23 = build_signed_proposal(
        aid,
        2,
        2,
        vec![e_s1.clone(), e_s3.clone(), e_s5.clone()],
        Vec::new(),
        quarter,
        t_prop23,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        Vec::new(),
    );
    let mut snaps23 = Vec::new();
    for srv in [&s1, &s2, &s5] {
        let (_, v) = srv
            .state
            .db
            .process_lock_freeze(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                    proposal: prop23.clone(),
                    current_manifest: None,
                },
                t_prop23,
            )
            .unwrap();
        snaps23.push(
            serde_json::from_value::<humoco_proto::SnapshotExport>(v["snapshot_export"].clone())
                .unwrap(),
        );
    }
    let t_fin23 = t_prop23 + s1.state.config.lock.proposal_timelock_secs;
    let mut acks23 = Vec::new();
    let mut imp_hash23 = [0u8; 32];
    for srv in [&s1, &s3, &s5] {
        let (_, v) = srv
            .state
            .db
            .process_lock_import(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockImportRequest {
                    anchor_id: aid,
                    active_manifest: man_rev2.clone(),
                    proposal: prop23.clone(),
                    snapshots: snaps23.clone(),
                    quorum_certificates: Vec::new(),
                },
                t_fin23,
            )
            .unwrap();
        let ack: humoco_proto::ImportAck = serde_json::from_value(v["import_ack"].clone()).unwrap();
        imp_hash23 = ack.imported_state_hash;
        acks23.push(ack);
    }

    // SYNC-S02-02b: Before Finalize(Rev 3), S3 MUST remain EpochFrozen on POST ?lock!
    let bkt3 = humoco_proto::derive_bucket(&aid, &s3.state.db.lock_pubkey_bytes().unwrap());
    let (pre_fin_s3_code, pre_fin_s3_val) = s3
        .state
        .db
        .process_lock_batch(
            &s3.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt3,
                recipient_nonce: [0x23; 32],
                entries: vec![e2.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: None,
            },
            t_fin23 + 1,
        )
        .unwrap();
    assert_eq!(
        pre_fin_s3_code, 409,
        "EpochFrozen S3 must not unlock to Active during ?lock_import before Finalize"
    );
    assert_eq!(pre_fin_s3_val["error"], "epoch_frozen");

    let mut cs23 = Vec::new();
    for srv in [&s1, &s2] {
        let (_, v) = srv
            .state
            .db
            .process_lock_commit(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                    anchor_id: aid,
                    proposal: prop23.clone(),
                    imported_state_hash: imp_hash23,
                    import_acks: acks23.clone(),
                },
                t_fin23,
            )
            .unwrap();
        cs23.push(
            serde_json::from_value::<humoco_proto::CommitteeSignature>(
                v["committee_signature"].clone(),
            )
            .unwrap(),
        );
    }
    let cert23 = humoco_proto::MigrationCert {
        anchor_id: aid,
        genesis_manifest: None,
        proposal: prop23,
        imported_state_hash: imp_hash23,
        import_acks: acks23,
        commit_sigs: cs23,
    };
    let (man_rev3, _) = cert23.verify_step(&aid, &man_rev2).unwrap();

    for srv in [&s1, &s2, &s3, &s5] {
        let (code, _) = srv
            .state
            .db
            .process_lock_commit(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                    anchor_id: aid,
                    new_manifest: man_rev3.clone(),
                },
                t_fin23,
            )
            .unwrap();
        assert_eq!(code, 200);
    }

    // SYNC-S02-04c: Idempotent Finalize(man_rev3) retry succeeds (200) on active S3
    let (idem_fin_code, _) = s3
        .state
        .db
        .process_lock_commit(
            &s3.state.config,
            humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                anchor_id: aid,
                new_manifest: man_rev3.clone(),
            },
            t_fin23 + 2,
        )
        .unwrap();
    assert_eq!(idem_fin_code, 200);

    // SYNC-S02-04b: Replaying old Finalize(man_rev2) onto active Rev-3 S3 MUST fail 409 (no downgrade/freeze!)
    let downgrade_err = s3
        .state
        .db
        .process_lock_commit(
            &s3.state.config,
            humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                anchor_id: aid,
                new_manifest: man_rev2,
            },
            t_fin23 + 5,
        )
        .unwrap_err();
    assert!(
        matches!(
            downgrade_err,
            humoco_sync_server::db::DbError::Http { status: 409, .. }
        ),
        "Finalize downgrade from Rev 3 to Rev 2 must fail with 409, got {downgrade_err:?}"
    );
    let stored_man: humoco_proto::AnchorManifest = serde_json::from_slice(
        &s3.state
            .db
            .get_static_anchor_manifest(&aid_hex)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(stored_man.revision, 3);
    let (s3_ok_code, _) = s3
        .state
        .db
        .process_lock_batch(
            &s3.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt3,
                recipient_nonce: [0x24; 32],
                entries: vec![e2.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: None,
            },
            t_fin23 + 6,
        )
        .unwrap();
    assert_eq!(s3_ok_code, 200);

    // SYNC-S02-04a: Unrelated manifest chain not containing S1 anywhere must be rejected (400)
    let (_, _, s_unrel1) = start_lock_test_server(true, Some(0)).await;
    let (_, _, s_unrel2) = start_lock_test_server(true, Some(0)).await;
    let (ua1_sk, _) = gen_keypair();
    let (ua2_sk, _) = gen_keypair();
    let u_mig_sk = SigningKey::from_bytes(&[177u8; 32]);
    let u_e1 = server_entry_for_test(&s_unrel1, &ua1_sk, humoco_proto::NominatedBy::Creator);
    let u_e2 = server_entry_for_test(&s_unrel2, &ua2_sk, humoco_proto::NominatedBy::Creator);
    let u_rev1 = build_multi_server_manifest(
        vec![u_e1],
        vec![u_e2.clone()],
        1,
        u_mig_sk.verifying_key().to_bytes(),
        Vec::new(),
        t0 * 1_000,
        quarter,
    );
    let u_aid = u_rev1.rev1_anchor_id().unwrap();
    let u_prop = build_signed_proposal(
        u_aid,
        1,
        1,
        vec![u_e2],
        Vec::new(),
        quarter,
        t0 + 10,
        humoco_proto::ProposalInitiator::Creator,
        Some(&u_mig_sk),
        Vec::new(),
    );
    let (_, uf1) = s_unrel1
        .state
        .db
        .process_lock_freeze(
            &s_unrel1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: u_prop.clone(),
                current_manifest: Some(u_rev1.clone()),
            },
            t0 + 10,
        )
        .unwrap();
    let u_snap: humoco_proto::SnapshotExport =
        serde_json::from_value(uf1["snapshot_export"].clone()).unwrap();
    let (_, u_imp) = s_unrel2
        .state
        .db
        .process_lock_import(
            &s_unrel2.state.config,
            humoco_sync_server::lock_rotation::LockImportRequest {
                anchor_id: u_aid,
                active_manifest: u_rev1.clone(),
                proposal: u_prop.clone(),
                snapshots: vec![u_snap],
                quorum_certificates: Vec::new(),
            },
            t0 + 10,
        )
        .unwrap();
    let u_ack: humoco_proto::ImportAck =
        serde_json::from_value(u_imp["import_ack"].clone()).unwrap();
    let u_ish = u_ack.imported_state_hash;
    let (_, u_sc) = s_unrel1
        .state
        .db
        .process_lock_commit(
            &s_unrel1.state.config,
            humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                anchor_id: u_aid,
                proposal: u_prop.clone(),
                imported_state_hash: u_ish,
                import_acks: vec![u_ack.clone()],
            },
            t0 + 10,
        )
        .unwrap();
    let u_cs: humoco_proto::CommitteeSignature =
        serde_json::from_value(u_sc["committee_signature"].clone()).unwrap();
    let u_cert = humoco_proto::MigrationCert {
        anchor_id: u_aid,
        genesis_manifest: Some(Box::new(u_rev1.clone())),
        proposal: u_prop,
        imported_state_hash: u_ish,
        import_acks: vec![u_ack],
        commit_sigs: vec![u_cs],
    };
    let (u_rev2, _) = u_cert.verify_step(&u_aid, &u_rev1).unwrap();

    let unrel_err = s1
        .state
        .db
        .process_lock_commit(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                anchor_id: u_aid,
                new_manifest: u_rev2,
            },
            t0 + 20,
        )
        .unwrap_err();
    assert!(
        matches!(
            unrel_err,
            humoco_sync_server::db::DbError::Http { status: 400, .. }
        ),
        "Finalize for unrelated anchor must reject with 400, got {unrel_err:?}"
    );
    assert!(s1
        .state
        .db
        .get_static_anchor_manifest(&hex::encode(u_aid))
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_s03_nonce_boundary_and_public_account_integrity() {
    let (_, admin_pk) = gen_keypair();
    let (victim_sk, victim_pk) = gen_keypair();
    let (_, suspended_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.mode.registration_gates = vec!["email".to_string(), "code".to_string(), "open".to_string()];
    cfg.email.enabled = true;
    cfg.email.transport = "log".to_string();

    let srv = TestServer::start(cfg).await;
    let db = &srv.state.db;
    let now = unix_now();

    // 1. SYNC-S03-01: Nonce replay MUST fail at exact expiry boundary (exp == now_secs)
    let nonce = random_hex(16);
    assert!(db.check_and_consume_nonce(&nonce, now).unwrap());
    let exp = now + humoco_sync_server::crypto::NONCE_TTL_SECS;
    db.run_maintenance(&srv.state.config, exp).unwrap();
    assert!(
        !db.check_and_consume_nonce(&nonce, exp).unwrap(),
        "Nonce replay MUST be rejected at exact expiry boundary exp == now_secs"
    );

    // 2. SYNC-S03-02: Victim registers via email & upgrades to pro; attacker cannot hijack email,
    // downgrade via /register/open or pow, or delete victim's account.
    db.register_or_upgrade_user(
        &srv.state.config,
        &victim_pk,
        "pro",
        Some("victim@example.org"),
        Some(30),
        "admin",
        now,
    )
    .unwrap();
    let mut victim_slot = sign_member_headers(
        &victim_sk,
        "PUT",
        "card",
        "",
        "",
        now as i64,
        b"secret-card",
    );
    let mut put_req = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in victim_slot.drain(..) {
        put_req = put_req.header(k, v);
    }
    assert_eq!(
        put_req
            .body(b"secret-card".to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // Attacker tries /register/open against victim's public key
    let open_hijack = srv
        .client
        .post(format!("{}/register/open", srv.base_url))
        .form(&[("pubkey", victim_pk.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(open_hijack.status().as_u16(), 303);
    let after_open = db.get_registered_user(&victim_pk).unwrap().unwrap();
    assert_eq!(
        after_open.profile, "pro",
        "Public /register/open must NOT downgrade existing pro account"
    );
    assert!(after_open.valid_until.is_some());

    // Direct pow gate against existing key must also fail with 409
    let pow_err = db
        .register_or_upgrade_user(
            &srv.state.config,
            &victim_pk,
            "free",
            None,
            None,
            "pow",
            now + 1,
        )
        .unwrap_err();
    assert!(
        matches!(
            pow_err,
            humoco_sync_server::db::DbError::Http { status: 409, .. }
        ),
        "Expected 409 for duplicate public registration, got {pow_err:?}"
    );

    // Attacker tries /register/email + /register/confirm with attacker@evil.com to hijack deletion
    let _ = srv.state.mailer.take_recorded();
    let email_resp = srv
        .client
        .post(format!("{}/register/email", srv.base_url))
        .form(&[
            ("pubkey", victim_pk.as_str()),
            ("email", "attacker@evil.example"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(email_resp.status().as_u16(), 303);
    if let Some(mail) = srv.state.mailer.take_recorded().into_iter().next() {
        let confirm_url = mail
            .body
            .lines()
            .find(|l| l.starts_with("http://"))
            .unwrap()
            .trim()
            .to_string();
        let _ = srv.client.get(&confirm_url).send().await.unwrap();
    }
    let after_email = db.get_registered_user(&victim_pk).unwrap().unwrap();
    assert_eq!(
        after_email.profile, "pro",
        "Email gate must NOT overwrite existing pro profile or email_hmac"
    );
    assert!(after_email.encrypted_contact_email.is_some());

    // Attacker tries /register/delete-request with attacker@evil.example -> must NOT send link or delete victim
    let _ = srv.state.mailer.take_recorded();
    let _ = srv
        .client
        .post(format!("{}/register/delete-request", srv.base_url))
        .form(&[
            ("pubkey", victim_pk.as_str()),
            ("email", "attacker@evil.example"),
        ])
        .send()
        .await
        .unwrap();
    assert!(
        srv.state.mailer.take_recorded().is_empty(),
        "Attacker email must NOT bind to victim pubkey for deletion"
    );
    assert!(db.get_registered_user(&victim_pk).unwrap().is_some());

    // 3. Suspended account cannot reactivate via public gates or redeem codes
    db.register_or_upgrade_user(
        &srv.state.config,
        &suspended_pk,
        "free",
        None,
        None,
        "open",
        now,
    )
    .unwrap();
    db.set_user_status(
        &suspended_pk,
        humoco_sync_server::db::AccountStatus::Suspended,
        now,
    )
    .unwrap();

    let susp_open_err = db
        .register_or_upgrade_user(
            &srv.state.config,
            &suspended_pk,
            "free",
            None,
            None,
            "open",
            now + 1,
        )
        .unwrap_err();
    assert!(
        matches!(
            susp_open_err,
            humoco_sync_server::db::DbError::Http { status: 403, .. }
        ),
        "Suspended account must NOT reactivate via open gate, got {susp_open_err:?}"
    );
    assert_eq!(
        db.get_registered_user(&suspended_pk)
            .unwrap()
            .unwrap()
            .status,
        humoco_sync_server::db::AccountStatus::Suspended
    );

    // 4. SYNC-S03-03: Redeem code protections (suspended blocked, downgrade blocked, timed->unlimited protected)
    let invite_codes = db
        .create_redeem_codes(&srv.state.config, 1, "free", None, 1, None, None, None, now)
        .unwrap();
    let invite_code = &invite_codes[0].code;

    let susp_code_err = db
        .redeem_code_for_pubkey(&srv.state.config, &suspended_pk, invite_code, now + 1)
        .unwrap_err();
    assert!(
        matches!(
            susp_code_err,
            humoco_sync_server::db::DbError::Http { status: 403, .. }
        ),
        "Suspended account must NOT redeem code, got {susp_code_err:?}"
    );

    let downgrade_code_err = db
        .redeem_code_for_pubkey(&srv.state.config, &victim_pk, invite_code, now + 1)
        .unwrap_err();
    assert!(
        matches!(
            downgrade_code_err,
            humoco_sync_server::db::DbError::Http { status: 409, .. }
        ),
        "Invite code must NOT downgrade active pro user, got {downgrade_code_err:?}"
    );
    assert_eq!(db.list_redeem_codes().unwrap()[0].used_count, 0);

    // Permanent pro account (valid_until = None) cannot be overwritten with a timed pro code
    let (_, perm_pro_pk) = gen_keypair();
    db.register_or_upgrade_user(
        &srv.state.config,
        &perm_pro_pk,
        "pro",
        None,
        None,
        "admin",
        now,
    )
    .unwrap();
    let pro_codes = db
        .create_redeem_codes(
            &srv.state.config,
            1,
            "pro",
            Some(30),
            2,
            None,
            None,
            None,
            now,
        )
        .unwrap();
    let pro_code = &pro_codes[0].code;
    let perm_err = db
        .redeem_code_for_pubkey(&srv.state.config, &perm_pro_pk, pro_code, now + 1)
        .unwrap_err();
    assert!(
        matches!(
            perm_err,
            humoco_sync_server::db::DbError::Http { status: 409, .. }
        ),
        "Timed pro code must NOT overwrite permanent pro valid_until=None, got {perm_err:?}"
    );

    // Legitimate renewal of timed pro account MUST still extend valid_until
    let prev_exp = db
        .get_registered_user(&victim_pk)
        .unwrap()
        .unwrap()
        .valid_until
        .unwrap();
    let renewed = db
        .redeem_code_for_pubkey(&srv.state.config, &victim_pk, pro_code, now + 1)
        .unwrap();
    assert_eq!(renewed.valid_until.unwrap(), prev_exp + 30 * 86_400);
}

#[tokio::test]
async fn test_s03_suspended_pool_isolation_empty_put_and_hybrid_prune() {
    let (_, admin_pk) = gen_keypair();
    let (_, pro_pk) = gen_keypair();
    let (_, free_pk) = gen_keypair();
    let (hybrid_sk, hybrid_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.storage.max_total_storage_mb = 4; // 4 MiB global
    cfg.storage.max_free_pool_mb = 1; // 1 MiB isolated free pool
    cfg.media.max_channel_mb = 1; // 1 MiB global media channel

    let srv = TestServer::start(cfg).await;
    let db = &srv.state.db;
    let now = unix_now();

    db.register_or_upgrade_user(
        &srv.state.config,
        &pro_pk,
        "pro",
        None,
        Some(30),
        "admin",
        now,
    )
    .unwrap();
    db.register_or_upgrade_user(&srv.state.config, &free_pk, "free", None, None, "open", now)
        .unwrap();
    db.register_or_upgrade_user(
        &srv.state.config,
        &hybrid_pk,
        "pro",
        None,
        Some(30),
        "admin",
        now,
    )
    .unwrap();
    db.put_admin_members(
        &srv.state.config,
        "card",
        std::slice::from_ref(&hybrid_pk),
        now,
    )
    .unwrap();

    // Pro uploads 800 KB backup + 900 KB media (> 1 MiB free pool)
    db.put_slot(
        &srv.state.config,
        &pro_pk,
        "backup",
        None,
        &vec![1u8; 800_000],
        &ConditionalPrecondition::None,
        now,
    )
    .unwrap();
    let pro_media_id = sha256_hex(b"suspended-pro-media");
    db.put_media(
        &srv.state.config,
        &pro_pk,
        &pro_media_id,
        &vec![2u8; 900_000],
        &ConditionalPrecondition::None,
        now,
    )
    .unwrap();

    // Hybrid user uploads card + media before suspension
    db.put_slot(
        &srv.state.config,
        &hybrid_pk,
        "card",
        None,
        &vec![3u8; 40_000],
        &ConditionalPrecondition::None,
        now,
    )
    .unwrap();
    let hybrid_media_id = sha256_hex(b"hybrid-media");
    db.put_media(
        &srv.state.config,
        &hybrid_pk,
        &hybrid_media_id,
        &vec![4u8; 40_000],
        &ConditionalPrecondition::None,
        now,
    )
    .unwrap();

    // Suspend pro_pk & hybrid_pk
    db.set_user_status(
        &pro_pk,
        humoco_sync_server::db::AccountStatus::Suspended,
        now + 1,
    )
    .unwrap();
    db.set_user_status(
        &hybrid_pk,
        humoco_sync_server::db::AccountStatus::Suspended,
        now + 1,
    )
    .unwrap();

    // 1. SYNC-S03-04: Suspended pro accounts must NOT pollute free_pool_used_bytes or starve free users
    let status = db.admin_status(&srv.state.config, now + 2).unwrap();
    assert_eq!(
        status.free_pool_used_bytes, 0,
        "Suspended pro storage must NOT count toward free_pool_used_bytes"
    );

    db.put_slot(
        &srv.state.config,
        &free_pk,
        "card",
        None,
        &vec![5u8; 400_000],
        &ConditionalPrecondition::None,
        now + 2,
    )
    .expect("Free user must NOT be starved by suspended pro user's storage");

    // Free user media upload exceeding max_channel_mb (1 MiB) must NOT evict suspended pro media!
    let free_media_id = sha256_hex(b"free-media-overflow");
    let evict_err = db
        .put_media(
            &srv.state.config,
            &free_pk,
            &free_media_id,
            &vec![6u8; 200_000],
            &ConditionalPrecondition::None,
            now + 2,
        )
        .unwrap_err();
    assert!(
        matches!(
            evict_err,
            humoco_sync_server::db::DbError::Http { status: 507, .. }
        ),
        "Free user must receive 507 instead of evicting suspended pro media, got {evict_err:?}"
    );
    assert!(
        db.get_media_blob(&srv.state.config, &pro_media_id, now + 2)
            .unwrap()
            .is_some(),
        "Suspended pro media must remain intact"
    );

    // 2. SYNC-S03-05: Empty (0-byte) PUT payloads must be rejected with 400 (parity with PHP)
    let empty_slot_err = db
        .put_slot(
            &srv.state.config,
            &free_pk,
            "card",
            Some("empty"),
            b"",
            &ConditionalPrecondition::None,
            now + 3,
        )
        .unwrap_err();
    assert!(
        matches!(
            empty_slot_err,
            humoco_sync_server::db::DbError::Http { status: 400, .. }
        ),
        "Empty put_slot must return 400, got {empty_slot_err:?}"
    );
    let empty_media_err = db
        .put_media(
            &srv.state.config,
            &free_pk,
            &sha256_hex(b""),
            b"",
            &ConditionalPrecondition::None,
            now + 3,
        )
        .unwrap_err();
    assert!(
        matches!(
            empty_media_err,
            humoco_sync_server::db::DbError::Http { status: 400, .. }
        ),
        "Empty put_media must return 400, got {empty_media_err:?}"
    );

    // 3. SYNC-S03-06: PUT ?members removing hybrid_pk must NOT prune suspended registered user's slots/media
    db.put_admin_members(&srv.state.config, "card", &[], now + 4)
        .unwrap();
    assert!(
        db.get_slot_blob(&srv.state.config, "card", &hybrid_pk, now + 4)
            .unwrap()
            .is_some(),
        "Suspended registered user's card slot must survive admin PUT ?members removal"
    );
    assert!(
        db.get_media_blob(&srv.state.config, &hybrid_media_id, now + 4)
            .unwrap()
            .is_some(),
        "Suspended registered user's media must survive admin PUT ?members removal"
    );
    let _ = hybrid_sk;
}

#[tokio::test]
async fn test_s03_lock_disabled_capability_ttl_expiry_and_profile_safety() {
    let (_, admin_pk) = gen_keypair();
    let (_, lock_only_pk) = gen_keypair();
    let (_, card_and_lock_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.enabled = true;

    let srv = TestServer::start(cfg.clone()).await;
    let db = &srv.state.db;
    let now = unix_now();

    db.put_admin_members(
        &srv.state.config,
        "lock",
        &[lock_only_pk.clone(), card_and_lock_pk.clone()],
        now,
    )
    .unwrap();
    db.put_admin_members(
        &srv.state.config,
        "card",
        std::slice::from_ref(&card_and_lock_pk),
        now,
    )
    .unwrap();
    db.put_admin_members(
        &srv.state.config,
        "post",
        std::slice::from_ref(&card_and_lock_pk),
        now,
    )
    .unwrap();

    // 1. When lock.enabled = false, lock membership must NOT grant HEAD authorization or appear in allowed_channels
    let mut no_lock_cfg = (*srv.state.config).clone();
    no_lock_cfg.lock.enabled = false;
    assert!(
        db.resolve_member_access(&no_lock_cfg, &lock_only_pk, now)
            .unwrap()
            .is_none(),
        "Lock-only admin member must NOT appear authorized when lock.enabled = false"
    );
    let cap_card_lock = db
        .head_capability(&no_lock_cfg, &card_and_lock_pk, None, None, None, now)
        .unwrap();
    assert!(cap_card_lock.authorized);
    assert!(
        !cap_card_lock.allowed_channels.iter().any(|ch| ch == "lock"),
        "allowed_channels must omit 'lock' when lock.enabled = false"
    );

    // 2. TTL-expired slot/media parity between GET, HEAD, and PUT If-None-Match: * before maintenance sweeps
    let put_post = db
        .put_slot(
            &srv.state.config,
            &card_and_lock_pk,
            "post",
            None,
            b"ephemeral-post-v1",
            &ConditionalPrecondition::None,
            now,
        )
        .unwrap();
    let mid = sha256_hex(b"ephemeral-media-v1");
    db.put_media(
        &srv.state.config,
        &card_and_lock_pk,
        &mid,
        b"ephemeral-media-v1",
        &ConditionalPrecondition::None,
        now,
    )
    .unwrap();

    let expired_now = now + 91 * 86_400; // friends.post & friends.media ttl_days = 90
    assert!(db
        .get_slot_blob(&srv.state.config, "post", &card_and_lock_pk, expired_now)
        .unwrap()
        .is_none());
    let head_post_exp = db
        .head_capability(
            &srv.state.config,
            &card_and_lock_pk,
            Some("post"),
            None,
            None,
            expired_now,
        )
        .unwrap();
    assert_eq!(
        head_post_exp.slot_occupied,
        Some(false),
        "HEAD must report X-Slot-Occupied: false once TTL expires"
    );
    assert!(
        head_post_exp.slot_etag.is_none(),
        "HEAD must omit ETag once TTL expires"
    );

    let head_media_exp = db
        .head_capability(
            &srv.state.config,
            &card_and_lock_pk,
            Some("media"),
            None,
            Some(&mid),
            expired_now,
        )
        .unwrap();
    assert_eq!(head_media_exp.slot_occupied, Some(false));
    assert!(head_media_exp.slot_etag.is_none());

    // Old ETag If-Match must reject 412 when expired; If-None-Match: * must succeed
    let stale_im_err = db
        .put_slot(
            &srv.state.config,
            &card_and_lock_pk,
            "post",
            None,
            b"ephemeral-post-v2",
            &ConditionalPrecondition::IfMatch(put_post.etag),
            expired_now,
        )
        .unwrap_err();
    assert!(matches!(
        stale_im_err,
        humoco_sync_server::db::DbError::Http { status: 412, .. }
    ));

    db.put_slot(
        &srv.state.config,
        &card_and_lock_pk,
        "post",
        None,
        b"ephemeral-post-v2",
        &ConditionalPrecondition::IfNoneMatchStar,
        expired_now,
    )
    .expect("If-None-Match: * must succeed once prior slot TTL has expired");

    // 3. Unvalidated Config missing profiles must return Err rather than panicking
    let mut broken_cfg = (*srv.state.config).clone();
    broken_cfg.profiles.clear();
    let missing_prof_err = db
        .resolve_member_access(&broken_cfg, &card_and_lock_pk, now)
        .unwrap_err();
    assert!(matches!(
        missing_prof_err,
        humoco_sync_server::db::DbError::Http { status: 500, .. }
    ));
}

#[tokio::test]
async fn test_s04_auth_rate_limit_ordering_and_put_streaming_validation() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let (friend_sk, friend_pk) = gen_keypair();
    let (outsider_sk, _outsider_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.security.ip_requests_per_minute = 5000;
    cfg.security.pubkey_requests_per_minute = 3;
    let srv = TestServer::start(cfg).await;
    let now_u = unix_now();
    let now = now_u as i64;

    srv.state
        .db
        .put_admin_members(
            &srv.state.config,
            "card",
            std::slice::from_ref(&friend_pk),
            now_u,
        )
        .unwrap();
    srv.state
        .db
        .put_admin_members(
            &srv.state.config,
            "wot",
            std::slice::from_ref(&friend_pk),
            now_u,
        )
        .unwrap();
    srv.state
        .db
        .put_admin_members(
            &srv.state.config,
            "lock",
            std::slice::from_ref(&friend_pk),
            now_u,
        )
        .unwrap();

    // 1. Unauthenticated HEAD and forged PUT/DELETE/DELETE?account/POST?lock_ticket
    // must NEVER drain friend_pk's authenticated pubkey rate-limit bucket.
    let bad_sig = "00".repeat(64);
    let ticket_body = serde_json::to_vec(&serde_json::json!({
        "anchor_id": "11".repeat(32),
        "retain_until_quarter": humoco_proto::encode_quarter(2031, 2).unwrap(),
        "pow_timestamp": serde_json::Value::Null,
        "pow_nonce": serde_json::Value::Null,
    }))
    .unwrap();
    for _ in 0..5 {
        assert_eq!(
            srv.client
                .head(format!("{}/sync.php", srv.base_url))
                .header("X-Drop-Pubkey", &friend_pk)
                .header("X-Channel", "card")
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            200
        );
        assert_eq!(
            srv.client
                .put(format!("{}/sync", srv.base_url))
                .header("X-Drop-Pubkey", &friend_pk)
                .header("X-Channel", "card")
                .header("X-Drop-Timestamp", now.to_string())
                .header("X-Drop-Nonce", random_hex(16))
                .header("X-Drop-Signature", &bad_sig)
                .body(b"forged-put".to_vec())
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            401
        );
        assert_eq!(
            srv.client
                .delete(format!("{}/sync", srv.base_url))
                .header("X-Drop-Pubkey", &friend_pk)
                .header("X-Channel", "card")
                .header("X-Drop-Timestamp", now.to_string())
                .header("X-Drop-Nonce", random_hex(16))
                .header("X-Drop-Signature", &bad_sig)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            401
        );
        assert_eq!(
            srv.client
                .delete(format!("{}/sync?account", srv.base_url))
                .header("X-Drop-Pubkey", &friend_pk)
                .header("X-Drop-Timestamp", now.to_string())
                .header("X-Drop-Nonce", random_hex(16))
                .header("X-Drop-Signature", &bad_sig)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            401
        );
        assert_eq!(
            srv.client
                .post(format!("{}/sync?lock_ticket", srv.base_url))
                .header("X-Drop-Pubkey", &friend_pk)
                .header("X-Drop-Timestamp", now.to_string())
                .header("X-Drop-Nonce", random_hex(16))
                .header("X-Drop-Signature", &bad_sig)
                .header("Content-Type", "application/json")
                .body(ticket_body.clone())
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            401
        );
    }

    // 2. Empty PUT must return 400 BEFORE consuming the nonce, so reusing that nonce
    // for a valid non-empty PUT succeeds (also proving bucket wasn't drained!).
    let reused_nonce_empty = random_hex(16);
    let empty_sig = hex::encode(
        friend_sk
            .sign(
                parse_member_message(
                    "PUT",
                    "card",
                    "",
                    now,
                    &reused_nonce_empty,
                    &sha256_hex(b""),
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    let empty_resp = srv
        .client
        .put(format!("{}/sync", srv.base_url))
        .header("X-Drop-Pubkey", &friend_pk)
        .header("X-Channel", "card")
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &reused_nonce_empty)
        .header("X-Drop-Signature", &empty_sig)
        .body(Vec::<u8>::new())
        .send()
        .await
        .unwrap();
    assert_eq!(
        empty_resp.status().as_u16(),
        400,
        "Empty PUT payload must be rejected with 400"
    );

    let ok_payload = b"valid-after-forged-flood-and-empty".to_vec();
    let ok_sig = hex::encode(
        friend_sk
            .sign(
                parse_member_message(
                    "PUT",
                    "card",
                    "",
                    now,
                    &reused_nonce_empty,
                    &sha256_hex(&ok_payload),
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    let ok_resp = srv
        .client
        .put(format!("{}/sync", srv.base_url))
        .header("X-Drop-Pubkey", &friend_pk)
        .header("X-Channel", "card")
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &reused_nonce_empty)
        .header("X-Drop-Signature", &ok_sig)
        .body(ok_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(
        ok_resp.status().as_u16(),
        200,
        "Legitimate signed PUT must succeed after forged flood & empty PUT (no bucket drain or nonce burn)"
    );

    // 3. Oversized wot PUT (friends.wot.max_bytes = 262_144 < pro.backup 16 MiB) must fail 413
    // BEFORE signature verification / nonce burn / pubkey bucket consumption.
    let too_big_wot = vec![0xAAu8; 262_145];
    let reused_nonce_big = random_hex(16);
    let big_sig = hex::encode(
        friend_sk
            .sign(
                parse_member_message(
                    "PUT",
                    "wot",
                    "",
                    now,
                    &reused_nonce_big,
                    &sha256_hex(&too_big_wot),
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    let big_resp = srv
        .client
        .put(format!("{}/sync", srv.base_url))
        .header("X-Drop-Pubkey", &friend_pk)
        .header("X-Channel", "wot")
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &reused_nonce_big)
        .header("X-Drop-Signature", &big_sig)
        .body(too_big_wot)
        .send()
        .await
        .unwrap();
    assert_eq!(
        big_resp.status().as_u16(),
        413,
        "Exceeding channel max_bytes must return 413 before consuming nonce"
    );

    let small_wot = b"small-wot-payload".to_vec();
    let small_sig = hex::encode(
        friend_sk
            .sign(
                parse_member_message(
                    "PUT",
                    "wot",
                    "",
                    now,
                    &reused_nonce_big,
                    &sha256_hex(&small_wot),
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    assert_eq!(
        srv.client
            .put(format!("{}/sync", srv.base_url))
            .header("X-Drop-Pubkey", &friend_pk)
            .header("X-Channel", "wot")
            .header("X-Drop-Timestamp", now.to_string())
            .header("X-Drop-Nonce", &reused_nonce_big)
            .header("X-Drop-Signature", &small_sig)
            .body(small_wot)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // 4. Unauthorized caller sending oversized payload gets 403 before buffering body
    let outsider_payload = vec![0xBBu8; 300_000];
    let mut outsider_req = srv.client.put(format!("{}/sync", srv.base_url));
    for (k, v) in sign_member_headers(&outsider_sk, "PUT", "card", "", "", now, &outsider_payload) {
        outsider_req = outsider_req.header(k, v);
    }
    assert_eq!(
        outsider_req
            .body(outsider_payload)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );

    // 5. Non-UTF-8 X-Drop-Prefix must return 400 rather than silently being ignored
    let bad_hdr_resp = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &friend_pk)
        .header("X-Channel", "card")
        .header(
            "X-Drop-Prefix",
            reqwest::header::HeaderValue::from_bytes(b"\xff\xfe").unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(bad_hdr_resp.status().as_u16(), 400);

    // 6. Real pubkey rate limit still enforces after 3 legitimate signed requests (used 2 above)
    let mut req3 = srv.client.put(format!("{}/sync", srv.base_url));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "", "", now, b"third") {
        req3 = req3.header(k, v);
    }
    assert_eq!(
        req3.body(b"third".to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    let mut req4 = srv.client.put(format!("{}/sync", srv.base_url));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "", "", now, b"fourth") {
        req4 = req4.header(k, v);
    }
    assert_eq!(
        req4.body(b"fourth".to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        429
    );
}

#[tokio::test]
async fn test_s04_static_lock_304_etag_members_capacity_and_fast_fail() {
    let (admin_sk, admin_pk) = gen_keypair();
    let (user_sk, user_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.mode.max_admin_members = 10_000;
    let srv = TestServer::start(cfg).await;
    let now = unix_now() as i64;

    // 1. Commit a lock entry and verify GET/HEAD static .lock conditional 304 Not Modified
    srv.client
        .post(format!("{}/register/open", srv.base_url))
        .form(&[("pubkey", user_pk.as_str())])
        .send()
        .await
        .unwrap();

    let lock_pub = srv.state.db.lock_pubkey_bytes().unwrap();
    let admin_pub_bytes = admin_sk.verifying_key().to_bytes();
    let creator_mig_sk = SigningKey::from_bytes(&[55u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 2).unwrap();
    let manifest =
        build_single_server_manifest(admin_pub_bytes, lock_pub, creator_mig_pub, quarter);
    let anchor_id = manifest.rev1_anchor_id().unwrap();
    let bucket = humoco_proto::derive_bucket(&anchor_id, &lock_pub);

    let (t_code, t_json) = fetch_ticket_signed(&srv, &user_sk, anchor_id, quarter).await;
    assert_eq!(t_code, 200);
    let ticket: humoco_proto::GenesisTicket =
        serde_json::from_value(t_json["ticket"].clone()).unwrap();

    let g_sk = SigningKey::from_bytes(&[56u8; 32]);
    let r_hash = [0x66; 32];
    let e0 = sign_lock_entry_helper(
        anchor_id,
        [0x21; 32],
        [0u8; 32],
        0,
        0,
        [0x31; 32],
        &g_sk,
        r_hash,
        None,
        Some(&creator_mig_sk),
        8,
    );
    let batch_req = serde_json::json!({
        "anchor_id": hex::encode(anchor_id),
        "bucket": hex::encode(bucket),
        "recipient_nonce": hex::encode([0xBB; 32]),
        "entries": [e0.to_wire_hex().unwrap()],
        "manifest": manifest,
        "genesis_ticket": ticket,
        "known_head_receipt": serde_json::Value::Null,
    });
    assert_eq!(
        srv.client
            .post(format!("{}/sync.php?lock", srv.base_url))
            .json(&batch_req)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    let q_str = humoco_proto::format_quarter(quarter).unwrap();
    let file_s = hex::encode(humoco_proto::derive_slot_file_id(&e0.slot, &lock_pub));
    let lock_url = format!(
        "{}/humoco_sync_data/locks/{}/{}/{}.lock",
        srv.base_url,
        q_str,
        hex::encode(bucket),
        file_s
    );
    let lock_get = srv.client.get(&lock_url).send().await.unwrap();
    assert_eq!(lock_get.status().as_u16(), 200);
    let lock_etag = lock_get
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let lock_bytes = lock_get.bytes().await.unwrap();
    assert_eq!(lock_bytes.len(), 605);
    assert_eq!(lock_etag, format!("\"{}\"", sha256_hex(&lock_bytes)));

    let lock_304 = srv
        .client
        .get(&lock_url)
        .header("If-None-Match", &lock_etag)
        .send()
        .await
        .unwrap();
    assert_eq!(
        lock_304.status().as_u16(),
        304,
        "Static .lock read MUST return 304 Not Modified on matching If-None-Match"
    );

    let lock_304_multi = srv
        .client
        .head(&lock_url)
        .header("If-None-Match", format!("\"deadbeef\", W/{}", lock_etag))
        .send()
        .await
        .unwrap();
    assert_eq!(lock_304_multi.status().as_u16(), 304);

    let static_post = srv.client.post(&lock_url).send().await.unwrap();
    assert_eq!(static_post.status().as_u16(), 405);
    assert_eq!(
        static_post
            .headers()
            .get("allow")
            .unwrap()
            .to_str()
            .unwrap(),
        "GET, HEAD"
    );

    // 2. PUT ?members must accept payloads > 512 KiB (e.g., 8,500 members ~570 KiB)
    let big_members: Vec<String> = (0..8_500u32).map(|i| format!("{:064x}", i + 1)).collect();
    let big_members_body =
        serde_json::to_vec(&serde_json::json!({ "pubkeys": big_members })).unwrap();
    assert!(big_members_body.len() > 512 * 1024);
    let m_nonce = random_hex(16);
    let m_sig = hex::encode(
        admin_sk
            .sign(
                format_admin_put_members_message(
                    "card",
                    now,
                    &m_nonce,
                    &sha256_hex(&big_members_body),
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    let pm_big = srv
        .client
        .put(format!("{}/sync.php?members&channel=card", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &m_nonce)
        .header("X-Drop-Signature", &m_sig)
        .body(big_members_body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        pm_big.status().as_u16(),
        200,
        "PUT ?members must support large admin member lists (> 512 KiB up to 100k members)"
    );

    // 3. Disabled admin_app / disabled lock fast-fail before consuming nonce or buffering body
    let mut off_cfg = Config::default();
    off_cfg.server.admin_pubkey = admin_pk.clone();
    off_cfg.mode.enable_admin_app = false;
    off_cfg.lock.enabled = false;
    off_cfg.security.ip_requests_per_minute = 5000;
    let off_srv = TestServer::start(off_cfg).await;

    let reused_admin_nonce = random_hex(16);
    let pm_off_body = serde_json::to_vec(&serde_json::json!({ "pubkeys": [] })).unwrap();
    let pm_off_sig = hex::encode(
        admin_sk
            .sign(
                format_admin_put_members_message(
                    "card",
                    now,
                    &reused_admin_nonce,
                    &sha256_hex(&pm_off_body),
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    let pm_off_resp = off_srv
        .client
        .put(format!(
            "{}/sync.php?members&channel=card",
            off_srv.base_url
        ))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &reused_admin_nonce)
        .header("X-Drop-Signature", &pm_off_sig)
        .body(pm_off_body)
        .send()
        .await
        .unwrap();
    assert_eq!(pm_off_resp.status().as_u16(), 403);
    // Nonce must NOT have been consumed when enable_admin_app = false
    assert!(off_srv
        .state
        .db
        .check_and_consume_nonce(&reused_admin_nonce, now as u64)
        .unwrap());

    assert_eq!(
        off_srv
            .client
            .post(format!("{}/sync.php?lock_import", off_srv.base_url))
            .body(b"{\"invalid\":true}".to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
}

#[tokio::test]
async fn test_s05_registration_prechecks_pow_replay_and_delete_binding() {
    use humoco_sync_server::crypto::{
        create_pow_challenge, hmac_email, leading_zero_bits, sign_stateless_token,
        SignedActionToken,
    };
    use humoco_sync_server::db::AccountStatus;
    use sha2::{Digest, Sha256};

    let (_, admin_pk) = gen_keypair();
    let (_, active_pk) = gen_keypair();
    let (_, suspended_pk) = gen_keypair();
    let (_, fresh_pk) = gen_keypair();
    let (_, pow_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.mode.registration_gates = vec!["email".to_string(), "pow".to_string(), "open".to_string()];
    cfg.email.enabled = true;
    cfg.email.transport = "log".to_string();
    cfg.security.pow_difficulty_bits = 4;
    cfg.security.max_registrations_per_ipv4_24_per_day = 1;
    let srv = TestServer::start(cfg).await;
    let now = unix_now();

    srv.state
        .db
        .register_or_upgrade_user(
            &srv.state.config,
            &active_pk,
            "free",
            None,
            None,
            "open",
            now,
        )
        .unwrap();
    srv.state
        .db
        .register_or_upgrade_user(
            &srv.state.config,
            &suspended_pk,
            "free",
            None,
            None,
            "open",
            now,
        )
        .unwrap();
    srv.state
        .db
        .set_user_status(&suspended_pk, AccountStatus::Suspended, now)
        .unwrap();

    // 1. Pre-check in /register/email: must NOT dispatch emails or burn the 1/day subnet slot
    for (pk, mail) in [
        (&active_pk, "victim1@example.org"),
        (&suspended_pk, "victim2@example.org"),
    ] {
        let resp = srv
            .client
            .post(format!("{}/register/email", srv.base_url))
            .form(&[("pubkey", pk.as_str()), ("email", mail)])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 303);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            loc.contains("err="),
            "Expected immediate rejection for existing key, got location: {loc}"
        );
    }
    assert!(
        srv.state.mailer.take_recorded().is_empty(),
        "Existing/suspended pubkeys must NEVER trigger confirmation emails"
    );

    // 2. Pre-check in /register/open and /register/pow: must NOT burn the 1/day subnet slot
    let open_dup = srv
        .client
        .post(format!("{}/register/open", srv.base_url))
        .form(&[("pubkey", active_pk.as_str())])
        .send()
        .await
        .unwrap();
    assert!(open_dup
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("err="));

    let solve_pow = |pk: &str| -> (String, String) {
        let chal = create_pow_challenge(srv.state.db.pepper(), pk, 4, unix_now());
        for n in 0u64..100_000 {
            let mut h = Sha256::new();
            h.update(chal.as_bytes());
            h.update(b":");
            h.update(n.to_string().as_bytes());
            if leading_zero_bits(&h.finalize()) >= 4 {
                return (chal, n.to_string());
            }
        }
        panic!("failed to solve 4-bit PoW");
    };

    let (act_chal, act_nonce) = solve_pow(&active_pk);
    let pow_dup = srv
        .client
        .post(format!("{}/register/pow", srv.base_url))
        .form(&[
            ("pubkey", active_pk.as_str()),
            ("challenge", act_chal.as_str()),
            ("nonce", act_nonce.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert!(pow_dup
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("err="));

    // Fresh user MUST still succeed using the untouched 1/day subnet slot
    let fresh_resp = srv
        .client
        .post(format!("{}/register/open", srv.base_url))
        .form(&[("pubkey", fresh_pk.as_str())])
        .send()
        .await
        .unwrap();
    assert!(
        fresh_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("msg="),
        "Subnet quota must NOT have been burned by already-registered keys"
    );

    // 3. PoW challenge must be strictly single-use across DELETE ?account + re-register
    let mut cfg_pow = base_hybrid_config(&admin_pk);
    cfg_pow.mode.registration_gates = vec!["pow".to_string()];
    cfg_pow.security.pow_difficulty_bits = 4;
    let srv_pow = TestServer::start(cfg_pow).await;

    let chal = create_pow_challenge(srv_pow.state.db.pepper(), &pow_pk, 4, unix_now());
    let mut pow_nonce = String::new();
    for n in 0u64..100_000 {
        let mut h = Sha256::new();
        h.update(chal.as_bytes());
        h.update(b":");
        h.update(n.to_string().as_bytes());
        if leading_zero_bits(&h.finalize()) >= 4 {
            pow_nonce = n.to_string();
            break;
        }
    }
    let p1 = srv_pow
        .client
        .post(format!("{}/register/pow", srv_pow.base_url))
        .form(&[
            ("pubkey", pow_pk.as_str()),
            ("challenge", chal.as_str()),
            ("nonce", pow_nonce.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert!(p1
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("msg="));

    srv_pow.state.db.delete_account_and_data(&pow_pk).unwrap();
    let p_replay = srv_pow
        .client
        .post(format!("{}/register/pow", srv_pow.base_url))
        .form(&[
            ("pubkey", pow_pk.as_str()),
            ("challenge", chal.as_str()),
            ("nonce", pow_nonce.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert!(
        p_replay
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("err="),
        "Replayed PoW challenge must be rejected after account deletion"
    );

    // 4. /register/confirm must reject tokens when 'email' gate is disabled
    let mut cfg_no_email = base_hybrid_config(&admin_pk);
    cfg_no_email.mode.registration_gates = vec!["code".to_string()];
    let srv_no_email = TestServer::start(cfg_no_email).await;
    let (_, gate_pk) = gen_keypair();
    let tok = sign_stateless_token(
        srv_no_email.state.db.pepper(),
        &SignedActionToken {
            action: "confirm_register".to_string(),
            pubkey: gate_pk.clone(),
            email_hmac: hmac_email(srv_no_email.state.db.pepper(), "a@example.org"),
            contact_email: None,
            profile: "free".to_string(),
            exp: unix_now() + 600,
            jti: random_hex(16),
        },
    );
    let gate_res = srv_no_email
        .client
        .get(format!(
            "{}/register/confirm?token={}",
            srv_no_email.base_url, tok
        ))
        .send()
        .await
        .unwrap();
    assert!(gate_res.status().is_redirection() || gate_res.status().as_u16() == 403);
    assert!(
        srv_no_email
            .state
            .db
            .get_registered_user(&gate_pk)
            .unwrap()
            .is_none(),
        "/register/confirm must NOT activate users when email gate is disabled"
    );

    // 5. /register/delete-confirm must bind to current account email_hmac (block stale token after email update)
    let (_, del_pk) = gen_keypair();
    srv.state
        .db
        .register_or_upgrade_user(
            &srv.state.config,
            &del_pk,
            "free",
            Some("alice@example.org"),
            None,
            "email",
            unix_now(),
        )
        .unwrap();
    srv.client
        .post(format!("{}/register/delete-request", srv.base_url))
        .form(&[("pubkey", del_pk.as_str()), ("email", "alice@example.org")])
        .send()
        .await
        .unwrap();
    let del_mails = srv.state.mailer.take_recorded();
    assert_eq!(del_mails.len(), 1);
    let del_url = del_mails[0]
        .body
        .lines()
        .find(|l| l.starts_with("http://"))
        .unwrap()
        .trim()
        .to_string();

    // Admin updates contact email to bob@example.org -> old deletion token must NOT delete!
    srv.state
        .db
        .register_or_upgrade_user(
            &srv.state.config,
            &del_pk,
            "pro",
            Some("bob@example.org"),
            Some(30),
            "admin",
            unix_now(),
        )
        .unwrap();
    let stale_del = srv.client.get(&del_url).send().await.unwrap();
    assert!(stale_del
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("err="));
    assert!(
        srv.state.db.get_registered_user(&del_pk).unwrap().is_some(),
        "Stale deletion token for old email must NOT delete account bound to new email"
    );

    // 6. Confirmation endpoints must enforce IP rate limiting
    let mut rl_cfg = base_hybrid_config(&admin_pk);
    rl_cfg.mode.registration_gates = vec!["email".to_string()];
    rl_cfg.email.enabled = true;
    rl_cfg.security.ip_requests_per_minute = 2;
    let rl_srv = TestServer::start(rl_cfg).await;
    for _ in 0..2 {
        let _ = rl_srv
            .client
            .get(format!(
                "{}/register/confirm?token=invalid",
                rl_srv.base_url
            ))
            .send()
            .await
            .unwrap();
    }
    let rl_hit = rl_srv
        .client
        .get(format!(
            "{}/register/delete-confirm?token=invalid",
            rl_srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(rl_hit.status().as_u16(), 429);
}

#[tokio::test]
async fn test_s05_admin_ui_duration_validation_cookie_and_panic_safety() {
    use humoco_sync_server::crypto::hash_admin_token;

    let (_, admin_pk) = gen_keypair();
    let (_, target_pk) = gen_keypair();
    let raw_token = "super-admin-ui-secret-token";

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.security.admin_token_hash = hash_admin_token(raw_token).unwrap();
    let srv = TestServer::start(cfg).await;

    // 1. Login to /admin
    let login_resp = srv
        .client
        .post(format!("{}/admin/login", srv.base_url))
        .form(&[("token", raw_token)])
        .send()
        .await
        .unwrap();
    assert_eq!(login_resp.status().as_u16(), 303);
    let set_cookie = login_resp
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    let sess_cookie = set_cookie.split(';').next().unwrap().to_string();

    // 2. Multiple Cookie headers (HTTP/2 style) must authenticate GET /admin
    let dash = srv
        .client
        .get(format!("{}/admin", srv.base_url))
        .header(reqwest::header::COOKIE, "other_cookie=ignored")
        .header(reqwest::header::COOKIE, &sess_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(dash.status().as_u16(), 200);
    let html = dash.text().await.unwrap();
    let csrf_marker = "name=\"csrf\" value=\"";
    let csrf = html
        .split(csrf_marker)
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("Authenticated /admin must render CSRF token")
        .to_string();

    // 3. Invalid non-empty duration_days must FAIL and NEVER grant permanent profile/code
    for bad_dur in ["0", "-5", "30d", "999999999999"] {
        let prof_resp = srv
            .client
            .post(format!("{}/admin/users/profile", srv.base_url))
            .header(reqwest::header::COOKIE, &sess_cookie)
            .form(&[
                ("csrf", csrf.as_str()),
                ("pubkey", target_pk.as_str()),
                ("profile", "pro"),
                ("duration_days", bad_dur),
            ])
            .send()
            .await
            .unwrap();
        let loc = prof_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            loc.contains("err="),
            "Invalid duration_days '{bad_dur}' must be rejected, got {loc}"
        );
        assert!(
            srv.state
                .db
                .get_registered_user(&target_pk)
                .unwrap()
                .is_none(),
            "Invalid duration_days '{bad_dur}' must NOT register a permanent user"
        );

        let code_resp = srv
            .client
            .post(format!("{}/admin/codes", srv.base_url))
            .header(reqwest::header::COOKIE, &sess_cookie)
            .form(&[
                ("csrf", csrf.as_str()),
                ("profile", "pro"),
                ("count", "1"),
                ("duration_days", bad_dur),
                ("note", "bad"),
            ])
            .send()
            .await
            .unwrap();
        let code_loc = code_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            code_loc.contains("err="),
            "Invalid code duration_days '{bad_dur}' must be rejected, got {code_loc}"
        );
        assert!(srv.state.db.list_redeem_codes().unwrap().is_empty());
    }

    // 4. Empty duration_days explicitly means permanent, positive integer means timed
    let ok_perm = srv
        .client
        .post(format!("{}/admin/users/profile", srv.base_url))
        .header(reqwest::header::COOKIE, &sess_cookie)
        .form(&[
            ("csrf", csrf.as_str()),
            ("pubkey", target_pk.as_str()),
            ("profile", "pro"),
            ("duration_days", ""),
        ])
        .send()
        .await
        .unwrap();
    assert!(ok_perm
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("msg="));
    assert!(srv
        .state
        .db
        .get_registered_user(&target_pk)
        .unwrap()
        .unwrap()
        .valid_until
        .is_none());
}

#[tokio::test]
async fn test_s05_admin_api_rate_limit_preauth_and_cache_control() {
    use humoco_sync_server::crypto::hash_admin_token;

    let (_, admin_pk) = gen_keypair();
    let (_, target_pk) = gen_keypair();
    let bearer_secret = "argon2-admin-api-secret";

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.security.api_bearer_token_hash = hash_admin_token(bearer_secret).unwrap();
    cfg.security.ip_requests_per_minute = 4;
    let srv = TestServer::start(cfg).await;

    // 1. Unauthenticated POST with invalid JSON / missing fields must return 401 BEFORE JSON parsing (never 400/422 schema leak)
    let no_auth_bad_json = srv
        .client
        .post(format!("{}/api/v1/admin/codes", srv.base_url))
        .header("Content-Type", "application/json")
        .body("{\"not_valid_schema\": true}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        no_auth_bad_json.status().as_u16(),
        401,
        "Missing Authorization must fail 401 before JSON deserialization"
    );

    // 2. Wrong Bearer token with malformed JSON must return 403 BEFORE JSON parsing
    let bad_auth_bad_json = srv
        .client
        .post(format!(
            "{}/api/v1/admin/users/{}/profile",
            srv.base_url, target_pk
        ))
        .header("Authorization", "Bearer wrong-token")
        .header("Content-Type", "application/json")
        .body("{not-json")
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad_auth_bad_json.status().as_u16(),
        403,
        "Invalid Bearer token must fail 403 before JSON deserialization"
    );

    // 3. Valid Bearer request succeeds and emits Cache-Control: no-store
    let ok_stats = srv
        .client
        .get(format!("{}/api/v1/admin/stats", srv.base_url))
        .header("Authorization", format!("Bearer {}", bearer_secret))
        .send()
        .await
        .unwrap();
    assert_eq!(ok_stats.status().as_u16(), 200);
    assert_eq!(
        ok_stats
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );

    // 4. Oversized authenticated admin JSON payload (> 64 KiB) rejected cleanly with 413
    let huge_note = "A".repeat(80_000);
    let huge_resp = srv
        .client
        .post(format!("{}/api/v1/admin/codes", srv.base_url))
        .header("Authorization", format!("Bearer {}", bearer_secret))
        .json(&serde_json::json!({
            "profile": "pro",
            "note": huge_note
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(huge_resp.status().as_u16(), 413);

    // 5. Next request hits IP rate limit (4/min) -> 429 Too Many Requests (protects Argon2id from CPU DoS)
    let throttled = srv
        .client
        .get(format!("{}/api/v1/admin/stats", srv.base_url))
        .header("Authorization", "Bearer invalid-flood")
        .send()
        .await
        .unwrap();
    assert_eq!(
        throttled.status().as_u16(),
        429,
        "Admin API must enforce IP rate limiting before Argon2id verification"
    );
}

#[tokio::test]
async fn test_s05_recheck_admin_api_bounds_and_ui_session_hardening() {
    use humoco_sync_server::crypto::hash_admin_token;

    let (_, admin_pk) = gen_keypair();
    let (_, target_pk) = gen_keypair();
    let api_secret = "recheck-admin-api-secret";
    let ui_secret = "recheck-admin-ui-secret";

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.security.admin_token_hash = hash_admin_token(ui_secret).unwrap();
    cfg.security.api_bearer_token_hash = hash_admin_token(api_secret).unwrap();
    cfg.security.ip_requests_per_minute = 120;
    let srv = TestServer::start(cfg).await;

    // 1. POST /api/v1/admin/codes must reject count=0, count=501, duration_days=0, expires_in_days=0 with 400
    for bad_codes_payload in [
        serde_json::json!({ "profile": "pro", "count": 0 }),
        serde_json::json!({ "profile": "pro", "count": 501 }),
        serde_json::json!({ "profile": "pro", "count": 1, "duration_days": 0 }),
        serde_json::json!({ "profile": "pro", "count": 1, "expires_in_days": 0 }),
    ] {
        let resp = srv
            .client
            .post(format!("{}/api/v1/admin/codes", srv.base_url))
            .header("Authorization", format!("Bearer {}", api_secret))
            .json(&bad_codes_payload)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "POST /api/v1/admin/codes must reject {bad_codes_payload} with 400"
        );
    }
    assert!(
        srv.state.db.list_redeem_codes().unwrap().is_empty(),
        "Rejected /api/v1/admin/codes calls must NOT create any redeem codes"
    );

    // 2. POST /api/v1/admin/users/:pk/profile must reject duration_days=0 with 400
    let zero_dur_prof = srv
        .client
        .post(format!(
            "{}/api/v1/admin/users/{}/profile",
            srv.base_url, target_pk
        ))
        .header("Authorization", format!("Bearer {}", api_secret))
        .json(&serde_json::json!({ "profile": "pro", "duration_days": 0 }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        zero_dur_prof.status().as_u16(),
        400,
        "POST /api/v1/admin/users/:pk/profile must reject duration_days=0 with 400"
    );
    assert!(srv
        .state
        .db
        .get_registered_user(&target_pk)
        .unwrap()
        .is_none());

    // 3. /admin/login must emit Cache-Control: no-store on redirect carrying Set-Cookie
    let login_resp = srv
        .client
        .post(format!("{}/admin/login", srv.base_url))
        .form(&[("token", ui_secret)])
        .send()
        .await
        .unwrap();
    assert_eq!(login_resp.status().as_u16(), 303);
    assert_eq!(
        login_resp
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "/admin/login redirect with Set-Cookie must emit Cache-Control: no-store"
    );
    let sess_cookie = login_resp
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let dash = srv
        .client
        .get(format!("{}/admin", srv.base_url))
        .header(reqwest::header::COOKIE, &sess_cookie)
        .send()
        .await
        .unwrap();
    let html = dash.text().await.unwrap();
    let csrf = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_string();

    // 4. POST /admin/codes with count=101 must fail with err= instead of silently clamping to 100
    let over_count = srv
        .client
        .post(format!("{}/admin/codes", srv.base_url))
        .header(reqwest::header::COOKIE, &sess_cookie)
        .form(&[
            ("csrf", csrf.as_str()),
            ("profile", "pro"),
            ("count", "101"),
            ("duration_days", "30"),
            ("note", "over-limit"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(over_count.status().as_u16(), 303);
    assert_eq!(
        over_count
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let over_loc = over_count
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        over_loc.contains("err="),
        "POST /admin/codes count=101 must return err=, got {over_loc}"
    );
    assert!(srv.state.db.list_redeem_codes().unwrap().is_empty());

    // 5. POST /admin/logout with wrong CSRF must NOT emit Set-Cookie clearing the admin session
    let bad_logout = srv
        .client
        .post(format!("{}/admin/logout", srv.base_url))
        .header(reqwest::header::COOKIE, &sess_cookie)
        .form(&[("csrf", "forged-csrf-token")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad_logout.status().as_u16(), 303);
    assert!(
        bad_logout
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .is_none(),
        "Failed-CSRF /admin/logout must NOT emit Set-Cookie to clear session"
    );
    let dash_still_valid = srv
        .client
        .get(format!("{}/admin", srv.base_url))
        .header(reqwest::header::COOKIE, &sess_cookie)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(dash_still_valid.contains("Authenticated Operator"));
}

#[tokio::test]
async fn test_s09_f1_conditional_preconditions_parity() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let (friend_sk, friend_pk) = gen_keypair();

    let srv = TestServer::start(base_hybrid_config(&admin_pk)).await;
    let now_u = unix_now();
    let now = now_u as i64;
    srv.state
        .db
        .put_admin_members(
            &srv.state.config,
            "card",
            std::slice::from_ref(&friend_pk),
            now_u,
        )
        .unwrap();

    // 1. Standard slot: If-Match: "none" and If-Match: "" MUST succeed (200) on absent slots
    let v1 = b"slot-cond-v1".to_vec();
    let v1_etag = sha256_hex(&v1);
    let mut r_none_create = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .header("If-Match", "\"none\"");
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "", "", now, &v1) {
        r_none_create = r_none_create.header(k, v);
    }
    assert_eq!(
        r_none_create
            .body(v1.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200,
        "If-Match: \"none\" must succeed when slot is absent"
    );

    let mut r_empty_create = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .header("If-Match", "\"\"");
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "alt", "", now, &v1) {
        r_empty_create = r_empty_create.header(k, v);
    }
    assert_eq!(
        r_empty_create
            .body(v1.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200,
        "If-Match: \"\" must succeed when prefixed slot is absent"
    );

    // 2. If-Match: "none" and "" MUST fail (412) when slot is occupied
    let v2 = b"slot-cond-v2".to_vec();
    let v2_etag = sha256_hex(&v2);
    for hdr_val in ["\"none\"", "none", "\"\"", ""] {
        let mut r_occ = srv
            .client
            .put(format!("{}/sync.php", srv.base_url))
            .header("If-Match", hdr_val);
        for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "", "", now, &v2) {
            r_occ = r_occ.header(k, v);
        }
        let resp = r_occ.body(v2.clone()).send().await.unwrap();
        assert_eq!(
            resp.status().as_u16(),
            412,
            "If-Match: {hdr_val} must reject occupied slot with 412"
        );
        assert_eq!(
            resp.headers().get("etag").and_then(|v| v.to_str().ok()),
            Some(format!("\"{v1_etag}\"").as_str())
        );
    }

    // 3. If-None-Match: "<current_etag>", weak list, and multiple headers MUST fail (412)
    for inm in [
        format!("\"{v1_etag}\""),
        format!("\"deadbeef\", W/\"{v1_etag}\""),
        "\"deadbeef\", *".to_string(),
    ] {
        let mut r_inm = srv
            .client
            .put(format!("{}/sync.php", srv.base_url))
            .header("If-None-Match", &inm);
        for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "", "", now, &v2) {
            r_inm = r_inm.header(k, v);
        }
        let resp = r_inm.body(v2.clone()).send().await.unwrap();
        assert_eq!(
            resp.status().as_u16(),
            412,
            "If-None-Match: {inm} must reject matching occupied slot with 412"
        );
    }

    let mut r_multi_inm = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .header("If-None-Match", "\"deadbeef\"")
        .header("If-None-Match", format!("\"{v1_etag}\""));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "", "", now, &v2) {
        r_multi_inm = r_multi_inm.header(k, v);
    }
    assert_eq!(
        r_multi_inm
            .body(v2.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        412,
        "Multiple If-None-Match headers matching current ETag must return 412"
    );

    // 4. Non-matching If-None-Match allows update to v2
    let mut r_inm_miss = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .header("If-None-Match", "\"deadbeef\"");
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "", "", now, &v2) {
        r_inm_miss = r_inm_miss.header(k, v);
    }
    assert_eq!(
        r_inm_miss
            .body(v2.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // 5. Combined If-None-Match + If-Match evaluates BOTH (If-None-Match match -> 412)
    let v3 = b"slot-cond-v3".to_vec();
    let mut r_both = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .header("If-None-Match", format!("\"{v2_etag}\""))
        .header("If-Match", format!("\"{v2_etag}\""));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "", "", now, &v3) {
        r_both = r_both.header(k, v);
    }
    assert_eq!(
        r_both
            .body(v3.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        412,
        "Matching If-None-Match must fail 412 even when If-Match also matches"
    );

    // 6. Quoted ETag with inner whitespace normalizes identically to PHP
    let mut r_ws_im = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .header("If-Match", format!("W/\"  {v2_etag}  \""));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "", "", now, &v3) {
        r_ws_im = r_ws_im.header(k, v);
    }
    assert_eq!(
        r_ws_im.body(v3).send().await.unwrap().status().as_u16(),
        200
    );

    // 7. Media channel precondition parity (If-Match: "none" & If-None-Match: "<etag>")
    let m1 = b"media-cond-v1".to_vec();
    let m1_id = sha256_hex(&m1);
    let m1_etag = sha256_hex(&m1);
    let mut r_m_create = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .header("If-Match", "none");
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "media", "", &m1_id, now, &m1) {
        r_m_create = r_m_create.header(k, v);
    }
    assert_eq!(
        r_m_create.body(m1).send().await.unwrap().status().as_u16(),
        200,
        "PUT media with If-Match: none must succeed on absent media"
    );

    let m2 = b"media-cond-v2".to_vec();
    let mut r_m_inm = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .header("If-None-Match", format!("\"{m1_etag}\""));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "media", "", &m1_id, now, &m2) {
        r_m_inm = r_m_inm.header(k, v);
    }
    assert_eq!(
        r_m_inm
            .body(m2.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        412,
        "PUT media with matching If-None-Match ETag must return 412"
    );

    let mut r_m_both_ok = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .header("If-None-Match", "\"deadbeef\"")
        .header("If-Match", format!("\"{m1_etag}\""));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "media", "", &m1_id, now, &m2) {
        r_m_both_ok = r_m_both_ok.header(k, v);
    }
    assert_eq!(
        r_m_both_ok.body(m2).send().await.unwrap().status().as_u16(),
        200
    );
}

#[tokio::test]
async fn test_s09_f1_head_index_members_and_delete_parity() {
    let (admin_sk, admin_pk) = gen_keypair();
    let (friend_sk, friend_pk) = gen_keypair();
    let (friend2_sk, friend2_pk) = gen_keypair();
    let (_, extra_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.mode.max_admin_members = 2;
    cfg.profiles.insert(
        "friends_tight".to_string(),
        ProfileConfig {
            display_name: "Friends Tight".to_string(),
            max_total_bytes: 200_000,
            is_free_pool: false,
            store_contact_email: false,
            channels: BTreeMap::from([
                (
                    "card".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 100_000,
                        ttl_days: 0,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "backup".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 150_000,
                        ttl_days: 0,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "post".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 50_000,
                        ttl_days: 30,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "media".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 100_000,
                        ttl_days: 30,
                        max_user_count: Some(4),
                        max_user_bytes: Some(200_000),
                    },
                ),
            ]),
        },
    );
    cfg.mode.admin_app_profile = "friends_tight".to_string();
    let srv = TestServer::start(cfg).await;
    let now_u = unix_now();
    let now = now_u as i64;

    // 1. PUT ?members with extra query parameter MUST return 405 Method Not Allowed
    let dup_members_body = serde_json::to_vec(
        &serde_json::json!({ "pubkeys": [&friend_pk, &friend_pk, &friend2_pk] }),
    )
    .unwrap();
    let extra_nonce = random_hex(16);
    let extra_sig = hex::encode(
        admin_sk
            .sign(
                format_admin_put_members_message(
                    "card",
                    now,
                    &extra_nonce,
                    &sha256_hex(&dup_members_body),
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    let extra_resp = srv
        .client
        .put(format!(
            "{}/sync.php?members&channel=card&extra=1",
            srv.base_url
        ))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &extra_nonce)
        .header("X-Drop-Signature", &extra_sig)
        .body(dup_members_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        extra_resp.status().as_u16(),
        405,
        "PUT ?members with extra query param must return 405"
    );

    // 2. PUT ?members deduplicates before checking max_admin_members=2
    let m_nonce = random_hex(16);
    let m_sig = hex::encode(
        admin_sk
            .sign(
                format_admin_put_members_message(
                    "card",
                    now,
                    &m_nonce,
                    &sha256_hex(&dup_members_body),
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    let dedup_ok = srv
        .client
        .put(format!("{}/sync.php?members&channel=card", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", &m_nonce)
        .header("X-Drop-Signature", &m_sig)
        .body(dup_members_body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        dedup_ok.status().as_u16(),
        200,
        "PUT ?members must deduplicate pubkeys before checking max_admin_members"
    );

    let too_many_body =
        serde_json::to_vec(&serde_json::json!({ "pubkeys": [&friend_pk, &friend2_pk, &extra_pk] }))
            .unwrap();
    let m2_nonce = random_hex(16);
    let m2_sig = hex::encode(
        admin_sk
            .sign(
                format_admin_put_members_message(
                    "card",
                    now,
                    &m2_nonce,
                    &sha256_hex(&too_many_body),
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    assert_eq!(
        srv.client
            .put(format!("{}/sync.php?members&channel=card", srv.base_url))
            .header("X-Drop-Pubkey", &admin_pk)
            .header("X-Drop-Timestamp", now.to_string())
            .header("X-Drop-Nonce", &m2_nonce)
            .header("X-Drop-Signature", &m2_sig)
            .body(too_many_body)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        507
    );

    for ch in ["backup", "post", "lock"] {
        srv.state
            .db
            .put_admin_members(
                &srv.state.config,
                ch,
                &[friend_pk.clone(), friend2_pk.clone()],
                now_u,
            )
            .unwrap();
    }

    // 3. HEAD with X-Channel: lock must omit X-Slot-Occupied (matching PHP & SPEC.md §2)
    let lock_head = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &friend_pk)
        .header("X-Channel", "lock")
        .send()
        .await
        .unwrap();
    assert_eq!(lock_head.status().as_u16(), 200);
    assert_eq!(
        lock_head
            .headers()
            .get("x-drop-authorized")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );
    assert!(
        !lock_head.headers().contains_key("x-slot-occupied"),
        "HEAD with X-Channel: lock must NOT emit X-Slot-Occupied"
    );

    // 4. Upload card, expired post (ttl=30d), and expired media (ttl=30d); check TTL expiry in HEAD & HTTP index.json
    let expired_upload_ts = now_u.saturating_sub(31 * 86_400);
    srv.state
        .db
        .put_slot(
            &srv.state.config,
            &friend_pk,
            "card",
            None,
            b"card-keep",
            &ConditionalPrecondition::None,
            now_u,
        )
        .unwrap();
    srv.state
        .db
        .put_slot(
            &srv.state.config,
            &friend_pk,
            "post",
            None,
            b"post-expiring",
            &ConditionalPrecondition::None,
            expired_upload_ts,
        )
        .unwrap();
    let exp_mid = sha256_hex(b"exp-media");
    srv.state
        .db
        .put_media(
            &srv.state.config,
            &friend_pk,
            &exp_mid,
            b"exp-media-bytes",
            &ConditionalPrecondition::None,
            expired_upload_ts,
        )
        .unwrap();

    let head_exp = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &friend_pk)
        .header("X-Channel", "media")
        .header("X-Media-Id", &exp_mid)
        .send()
        .await
        .unwrap();
    assert_eq!(head_exp.status().as_u16(), 200);
    assert_eq!(
        head_exp
            .headers()
            .get("x-media-count")
            .and_then(|v| v.to_str().ok()),
        Some("0"),
        "HEAD must exclude TTL-expired media from X-Media-Count"
    );
    assert_eq!(
        head_exp
            .headers()
            .get("x-media-bytes")
            .and_then(|v| v.to_str().ok()),
        Some("0"),
        "HEAD must exclude TTL-expired media from X-Media-Bytes"
    );

    let idx_exp: Vec<serde_json::Value> = srv
        .client
        .get(format!("{}/humoco_sync_data/index.json", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        idx_exp.len(),
        1,
        "index.json must omit TTL-expired post slot and retain non-expiring card"
    );
    assert_eq!(idx_exp[0]["channel"], "card");

    // 5. Authorized DELETE standard slot (prefixed) + single & bulk DELETE media + cross-user 403
    let mut r_put_pfx = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "dev1", "", now, b"pfx-card") {
        r_put_pfx = r_put_pfx.header(k, v);
    }
    assert_eq!(
        r_put_pfx
            .body(b"pfx-card".to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    let mut r_del_pfx = srv.client.delete(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&friend_sk, "DELETE", "card", "dev1", "", now, b"") {
        r_del_pfx = r_del_pfx.header(k, v);
    }
    assert_eq!(r_del_pfx.send().await.unwrap().status().as_u16(), 200);
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}_dev1.card.bin",
                srv.base_url, friend_pk
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );

    // Media blobs for friend & friend2
    let f2_blob = b"friend2-media".to_vec();
    let f2_mid = sha256_hex(&f2_blob);
    let mut r_f2m = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&friend2_sk, "PUT", "media", "", &f2_mid, now, &f2_blob) {
        r_f2m = r_f2m.header(k, v);
    }
    assert_eq!(
        r_f2m.body(f2_blob).send().await.unwrap().status().as_u16(),
        200
    );

    // Cross-user DELETE media -> 403
    let mut r_cross_del = srv.client.delete(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&friend_sk, "DELETE", "media", "", &f2_mid, now, b"") {
        r_cross_del = r_cross_del.header(k, v);
    }
    assert_eq!(r_cross_del.send().await.unwrap().status().as_u16(), 403);

    // Friend uploads two more media blobs, deletes one by id, then deletes remaining via bulk DELETE (no X-Media-Id)
    let fm_a = b"friend-media-a".to_vec();
    let fm_a_id = sha256_hex(&fm_a);
    let fm_b = b"friend-media-b".to_vec();
    let fm_b_id = sha256_hex(&fm_b);
    for (mid, body) in [(&fm_a_id, &fm_a), (&fm_b_id, &fm_b)] {
        let mut r = srv.client.put(format!("{}/sync.php", srv.base_url));
        for (k, v) in sign_member_headers(&friend_sk, "PUT", "media", "", mid, now, body) {
            r = r.header(k, v);
        }
        assert_eq!(
            r.body(body.clone()).send().await.unwrap().status().as_u16(),
            200
        );
    }

    let mut r_del_single = srv.client.delete(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&friend_sk, "DELETE", "media", "", &fm_a_id, now, b"") {
        r_del_single = r_del_single.header(k, v);
    }
    assert_eq!(r_del_single.send().await.unwrap().status().as_u16(), 200);
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv.base_url, fm_a_id
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );

    // Bulk DELETE media (X-Media-Id omitted) removes exp_mid + fm_b_id, preserves friend2's f2_mid
    let mut r_del_all = srv.client.delete(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&friend_sk, "DELETE", "media", "", "", now, b"") {
        r_del_all = r_del_all.header(k, v);
    }
    let del_all_resp = r_del_all.send().await.unwrap();
    assert_eq!(del_all_resp.status().as_u16(), 200);
    let del_all_json: serde_json::Value = del_all_resp.json().await.unwrap();
    assert_eq!(del_all_json["deleted"], 2);
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv.base_url, fm_b_id
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv.base_url, f2_mid
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // 6. HTTP Prio-3 media LRU eviction triggered by Prio-1 backup upload
    let m_old = vec![0x11u8; 70_000];
    let m_old_id = sha256_hex(&m_old);
    let m_new = vec![0x22u8; 70_000];
    let m_new_id = sha256_hex(&m_new);
    let mut r_mo = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "media", "", &m_old_id, now, &m_old) {
        r_mo = r_mo.header(k, v);
    }
    assert_eq!(
        r_mo.body(m_old).send().await.unwrap().status().as_u16(),
        200
    );

    let mut r_mn = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "media", "", &m_new_id, now, &m_new) {
        r_mn = r_mn.header(k, v);
    }
    assert_eq!(
        r_mn.body(m_new).send().await.unwrap().status().as_u16(),
        200
    );

    // Touch m_old at now+120? No, deterministic creation/last_access_at via media_id tiebreak or sequential:
    // Actually m_old and m_new have same `now` (unless >=1s passed), so tiebreak would be media_id!
    // Let's upload backup 100KB (total 140KB media + 100KB backup > 200KB max_total_bytes -> evicts 1 media blob).
    let bkp = vec![0x33u8; 100_000];
    let mut r_bkp = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "backup", "", "", now, &bkp) {
        r_bkp = r_bkp.header(k, v);
    }
    let bkp_resp = r_bkp.body(bkp).send().await.unwrap();
    assert_eq!(bkp_resp.status().as_u16(), 200);
    let bkp_json: serde_json::Value = bkp_resp.json().await.unwrap();
    assert!(bkp_json["evicted_media"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn test_s08_router_caps_form_body_and_preserves_large_slot_uploads() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let (friend_sk, friend_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.mode.register_path = "/join".to_string();
    let srv = TestServer::start(cfg).await;
    let now_u = unix_now();
    let now = now_u as i64;
    srv.state
        .db
        .put_admin_members(
            &srv.state.config,
            "backup",
            std::slice::from_ref(&friend_pk),
            now_u,
        )
        .unwrap();

    // 1. Oversized form POST (> 64 KiB) to public web form must reject with 413 Payload Too Large
    let big_form = format!("pubkey={}", "a".repeat(256 * 1024));
    let form_resp = srv
        .client
        .post(format!("{}/join/open", srv.base_url))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(big_form)
        .send()
        .await
        .unwrap();
    assert_eq!(
        form_resp.status().as_u16(),
        413,
        "Oversized web form POST must be rejected at 64 KiB DefaultBodyLimit"
    );

    // 2. Large binary PUT /sync.php (> 64 KiB) still works up to channel quota
    let big_backup = vec![0x5Au8; 200_000];
    let mut put_req = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "backup", "", "", now, &big_backup) {
        put_req = put_req.header(k, v);
    }
    let put_resp = put_req.body(big_backup).send().await.unwrap();
    assert_eq!(
        put_resp.status().as_u16(),
        200,
        "PUT /sync.php slot > 64 KiB must still succeed via streaming Body limit"
    );
}

#[test]
fn test_s08_deployment_hardening_invariants() {
    let dockerfile = include_str!("../../Dockerfile");
    assert!(dockerfile.contains("USER humoco"));
    assert!(
        dockerfile.contains("/var/lib/humoco-sync/data"),
        "Dockerfile must pre-create /var/lib/humoco-sync/data for non-root Docker volume ownership"
    );
    assert!(
        dockerfile.contains("chmod 0700 /var/lib/humoco-sync/data"),
        "Dockerfile must restrict /var/lib/humoco-sync/data permissions to 0700"
    );
    assert!(
        !dockerfile.contains("chown -R humoco:humoco /var/lib/humoco-sync /etc/humoco-sync"),
        "Dockerfile must not grant humoco user write ownership over /etc/humoco-sync"
    );
    assert!(
        dockerfile.contains("humoco-proto"),
        "Dockerfile must copy humoco-proto via named BuildKit context"
    );
    assert!(
        dockerfile.contains("RUN cargo build --release --locked"),
        "Dockerfile must enforce cargo build --release --locked"
    );
    assert!(
        !dockerfile.contains("2>/dev/null || cargo build --release"),
        "Dockerfile must not fall back past --locked build failures"
    );
    let builder_rust_ver = dockerfile
        .lines()
        .find_map(|line| line.trim().strip_prefix("FROM rust:"))
        .and_then(|rest| rest.split(['-', ' ']).next())
        .and_then(|ver| {
            let mut parts = ver.split('.');
            let major: u32 = parts.next()?.parse().ok()?;
            let minor: u32 = parts.next()?.parse().ok()?;
            Some((major, minor))
        })
        .expect("Dockerfile must specify a FROM rust:<major>.<minor> builder tag");
    assert!(
        builder_rust_ver >= (1, 88),
        "Dockerfile builder Rust toolchain {:?} is older than required MSRV (1, 88) for Cargo.lock (icu_* 2.4.0) and usize::is_multiple_of",
        builder_rust_ver
    );

    let compose = include_str!("../../docker/docker-compose.yml");
    assert!(compose.contains("additional_contexts:"));
    assert!(compose.contains("humoco-proto: ../../humoco-proto"));
    assert!(compose.contains("127.0.0.1:8080:8080"));
    assert!(compose.contains(":ro"));
    assert!(compose.contains("cap_drop:"));
    assert!(compose.contains("ALL"));
    assert!(compose.contains("no-new-privileges:true"));

    let systemd = include_str!("../../docker/humoco-sync.service");
    for required in [
        "User=humoco-sync",
        "Group=humoco-sync",
        "UMask=0077",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "PrivateDevices=true",
        "ProtectKernelLogs=true",
        "ProtectClock=true",
        "ProtectHostname=true",
        "RestrictNamespaces=true",
        "RestrictRealtime=true",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "SystemCallArchitectures=native",
        "MemoryDenyWriteExecute=true",
    ] {
        assert!(
            systemd.contains(required),
            "systemd unit missing hardening directive: {required}"
        );
    }
}

#[tokio::test]
async fn test_s02_cold_pre_freeze_rejected_and_max_buckets_enforced() {
    let (a1_sk, a1_pk) = gen_keypair();
    let mut cfg = base_hybrid_config(&a1_pk);
    cfg.lock.max_buckets = 1;
    let s1 = TestServer::start(cfg).await;

    let creator_mig_sk = SigningKey::from_bytes(&[141u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;
    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);

    let man1 = build_multi_server_manifest(
        vec![e_s1.clone()],
        Vec::new(),
        1,
        creator_mig_pub,
        Vec::new(),
        t0 * 1_000,
        quarter,
    );
    let aid1 = man1.rev1_anchor_id().unwrap();

    // Cold PreFreeze MUST be rejected with 404 even when current_manifest is supplied
    let cold_pf = s1
        .client
        .post(format!("{}/sync.php?lock_freeze", s1.base_url))
        .json(&serde_json::json!({
            "action": "pre_freeze",
            "anchor_id": hex::encode(aid1),
            "current_manifest": man1,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        cold_pf.status().as_u16(),
        404,
        "Unauthenticated cold PreFreeze must return 404 and not allocate bucket state"
    );

    // Ensure 0 entries in LOCK_BUCKETS / LOCK_ROTATIONS / LOCK_ANCHORS after rejected cold PreFreeze
    let status_after_pf = s1
        .state
        .db
        .get_lock_freeze_status(&s1.state.config, aid1, t0);
    assert!(matches!(
        status_after_pf,
        Err(humoco_sync_server::db::DbError::Http { status: 404, .. })
    ));

    // Signed cold CreatorHeartbeat succeeds once (consuming max_buckets = 1)
    let mut hb1 = humoco_proto::CreatorHeartbeat {
        anchor_id: aid1,
        timestamp_secs: t0,
        sig: [0u8; 64],
    };
    hb1.sig = creator_mig_sk.sign(&hb1.digest()).to_bytes();
    let (hb1_code, _) = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Heartbeat {
                heartbeat: hb1,
                current_manifest: Some(man1),
            },
            t0,
        )
        .unwrap();
    assert_eq!(hb1_code, 200);

    // Second distinct anchor cold bootstrap hits max_buckets = 1 -> 507
    let man2 = build_multi_server_manifest(
        vec![e_s1],
        Vec::new(),
        1,
        creator_mig_pub,
        Vec::new(),
        (t0 + 10) * 1_000,
        quarter,
    );
    let aid2 = man2.rev1_anchor_id().unwrap();
    let mut hb2 = humoco_proto::CreatorHeartbeat {
        anchor_id: aid2,
        timestamp_secs: t0 + 10,
        sig: [0u8; 64],
    };
    hb2.sig = creator_mig_sk.sign(&hb2.digest()).to_bytes();
    let cap_err = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Heartbeat {
                heartbeat: hb2,
                current_manifest: Some(man2),
            },
            t0 + 10,
        )
        .unwrap_err();
    assert!(
        matches!(
            cap_err,
            humoco_sync_server::db::DbError::Http { status: 507, .. }
        ),
        "Second cold bucket beyond max_buckets=1 must fail with 507, got: {cap_err:?}"
    );
}

#[tokio::test]
async fn test_audit_decisions_cluster2_auth_permissions_and_ttl() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let (backup_sk, backup_pk) = gen_keypair();
    let (card_sk, card_pk) = gen_keypair();
    let (media_sk, media_pk) = gen_keypair();
    let (stranger_sk, stranger_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.mode.enable_public_registration = true;
    cfg.mode.registration_gates = vec!["email".to_string(), "code".to_string()];
    cfg.email.enabled = false;
    let srv = TestServer::start(cfg).await;
    let db = &srv.state.db;
    let now_u = unix_now();
    let now = now_u as i64;

    // 1. Unix DB file & newly-created parent permissions (0600 / 0700)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let db_mode = std::fs::metadata(&srv.state.config.server.db_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(db_mode, 0o600, "DB file must have 0600 permissions");

        let sub_dir = srv
            .state
            .config
            .server
            .db_path
            .parent()
            .unwrap()
            .join("sub");
        let sub_db = sub_dir.join("perm_check.redb");
        let _ = humoco_sync_server::db::SyncDb::open(&sub_db, "").unwrap();
        let dir_mode = std::fs::metadata(&sub_dir).unwrap().permissions().mode() & 0o777;
        let sub_db_mode = std::fs::metadata(&sub_db).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "Newly created DB parent dir must have 0700"
        );
        assert_eq!(sub_db_mode, 0o600, "Nested DB file must have 0600");
    }

    // 2. SYNC-S05-06: email.enabled = false disables /register/email even if "email" is in registration_gates
    let mail_off_resp = srv
        .client
        .post(format!("{}/register/email", srv.base_url))
        .form(&[("pubkey", stranger_pk.as_str()), ("email", "a@example.org")])
        .send()
        .await
        .unwrap();
    let mail_off_loc = mail_off_resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        mail_off_loc.contains("disabled") || mail_off_loc.contains("err="),
        "POST /register/email must reject when email.enabled=false, got {mail_off_loc:?}"
    );

    // 3. SYNC-S03-08: Unauthorized DELETE media (single & bulk) returns 403
    let del_media_id = sha256_hex(b"missing-blob");
    let mut r_del_unauth_single = srv.client.delete(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&stranger_sk, "DELETE", "media", "", &del_media_id, now, b"")
    {
        r_del_unauth_single = r_del_unauth_single.header(k, v);
    }
    assert_eq!(
        r_del_unauth_single.send().await.unwrap().status().as_u16(),
        403,
        "Unauthorized single DELETE media must return 403"
    );
    let mut r_del_unauth_bulk = srv.client.delete(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&stranger_sk, "DELETE", "media", "", "", now, b"") {
        r_del_unauth_bulk = r_del_unauth_bulk.header(k, v);
    }
    assert_eq!(
        r_del_unauth_bulk.send().await.unwrap().status().as_u16(),
        403,
        "Unauthorized bulk DELETE media must return 403"
    );

    // 4. SYNC-S09-04: backup-only friend denied media (403); card fallback works when media unconfigured; explicit media isolates & prunes
    db.put_admin_members(
        &srv.state.config,
        "backup",
        std::slice::from_ref(&backup_pk),
        now_u,
    )
    .unwrap();
    db.put_admin_members(
        &srv.state.config,
        "card",
        std::slice::from_ref(&card_pk),
        now_u,
    )
    .unwrap();

    let b_mid = sha256_hex(b"backup-only-media");
    let mut r_backup_media = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&backup_sk, "PUT", "media", "", &b_mid, now, b"backup-media")
    {
        r_backup_media = r_backup_media.header(k, v);
    }
    assert_eq!(
        r_backup_media
            .body(b"backup-media".to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403,
        "backup-only admin friend must NOT inherit media access"
    );

    let c_mid = sha256_hex(b"card-fallback-media");
    let mut r_card_media = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&card_sk, "PUT", "media", "", &c_mid, now, b"card-media") {
        r_card_media = r_card_media.header(k, v);
    }
    assert_eq!(
        r_card_media
            .body(b"card-media".to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200,
        "card member inherits media while media list has not been explicitly configured"
    );

    // Explicit PUT ?members&channel=media([media_pk]) isolates media from card and prunes card_pk's fallback media
    db.put_admin_members(
        &srv.state.config,
        "media",
        std::slice::from_ref(&media_pk),
        now_u + 1,
    )
    .unwrap();
    let status_after_media = db.admin_status(&srv.state.config, now_u + 1).unwrap();
    assert_eq!(
        status_after_media.admin_members_count, 3,
        "ADMIN_MEDIA_CONFIGURED_KEY sentinel must never inflate admin_members_count"
    );
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv.base_url, c_mid
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404,
        "Setting explicit media list must prune orphaned media of card-only member"
    );

    let m_mid = sha256_hex(b"explicit-media-blob");
    let mut r_exp_media = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(
        &media_sk,
        "PUT",
        "media",
        "",
        &m_mid,
        now,
        b"explicit-media",
    ) {
        r_exp_media = r_exp_media.header(k, v);
    }
    assert_eq!(
        r_exp_media
            .body(b"explicit-media".to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    // Clearing card list leaves explicit media member untouched
    db.put_admin_members(&srv.state.config, "card", &[], now_u + 2)
        .unwrap();
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv.base_url, m_mid
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    // Removing from media prunes their media
    db.put_admin_members(&srv.state.config, "media", &[], now_u + 3)
        .unwrap();
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv.base_url, m_mid
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );

    // 5. Suspended account slots must still expire by TTL in get_slot_blob and run_maintenance
    let (_, susp_pk) = gen_keypair();
    db.register_or_upgrade_user(
        &srv.state.config,
        &susp_pk,
        "free",
        None,
        None,
        "open",
        now_u,
    )
    .unwrap();
    let old_ts = now_u.saturating_sub(100 * 86_400); // free card ttl = 90d
    db.put_slot(
        &srv.state.config,
        &susp_pk,
        "card",
        None,
        b"susp-expiring-card",
        &ConditionalPrecondition::None,
        old_ts,
    )
    .unwrap();
    db.set_user_status(
        &susp_pk,
        humoco_sync_server::db::AccountStatus::Suspended,
        now_u,
    )
    .unwrap();
    assert!(
        db.get_slot_blob(&srv.state.config, "card", &susp_pk, now_u)
            .unwrap()
            .is_none(),
        "get_slot_blob must enforce TTL expiry even when owner is Suspended"
    );
    db.run_maintenance(&srv.state.config, now_u).unwrap();
    assert_eq!(
        db.admin_status(&srv.state.config, now_u)
            .unwrap()
            .slot_count,
        0,
        "run_maintenance must prune TTL-expired slots owned by Suspended users"
    );

    // 6. create_redeem_codes strict validation
    assert!(db
        .create_redeem_codes(
            &srv.state.config,
            0,
            "free",
            None,
            1,
            None,
            None,
            None,
            now_u
        )
        .is_err());
    assert!(db
        .create_redeem_codes(
            &srv.state.config,
            501,
            "free",
            None,
            1,
            None,
            None,
            None,
            now_u
        )
        .is_err());
    assert!(db
        .create_redeem_codes(
            &srv.state.config,
            1,
            "free",
            None,
            0,
            None,
            None,
            None,
            now_u
        )
        .is_err());
    assert!(db
        .create_redeem_codes(
            &srv.state.config,
            1,
            "free",
            None,
            1,
            None,
            None,
            Some("BAD\nPREFIX"),
            now_u
        )
        .is_err());
    assert!(db
        .create_redeem_codes(
            &srv.state.config,
            1,
            "free",
            None,
            1,
            None,
            None,
            Some(&"A".repeat(25)),
            now_u
        )
        .is_err());
    assert!(db
        .create_redeem_codes(
            &srv.state.config,
            1,
            "free",
            None,
            1,
            None,
            None,
            Some("PROMO_2026-Q4"),
            now_u
        )
        .is_ok());
}

#[tokio::test]
async fn test_audit_decisions_cluster4_revoke_and_delete_account_parity() {
    let (admin_sk, admin_pk) = gen_keypair();
    let (user_sk, user_pk) = gen_keypair();
    let (_rep_sk, rep_pk) = gen_keypair();
    let srv = TestServer::start(base_hybrid_config(&admin_pk)).await;
    let now = unix_now() as i64;

    let send_revoke = |body_val: serde_json::Value| {
        let srv = &srv;
        let admin_sk = &admin_sk;
        let admin_pk = &admin_pk;
        async move {
            let body = serde_json::to_vec(&body_val).unwrap();
            let nonce = random_hex(16);
            let msg = format_admin_put_revoke_message(now, &nonce, &sha256_hex(&body));
            let sig = hex::encode(admin_sk.sign(msg.as_bytes()).to_bytes());
            srv.client
                .put(format!("{}/sync.php?revoke", srv.base_url))
                .header("X-Drop-Pubkey", admin_pk)
                .header("X-Drop-Timestamp", now.to_string())
                .header("X-Drop-Nonce", nonce)
                .header("X-Drop-Signature", sig)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
                .unwrap()
        }
    };

    let build_signed_notice = |issued_at: u64,
                               effective_at: u64,
                               write_url: &str,
                               read_url: &str,
                               reason: Option<&str>| {
        let mut n = RevocationNotice {
            drop_pub: admin_pk.clone(),
            issued_at,
            effective_at,
            reason: reason.map(|s| s.to_string()),
            replacement: Some(RevocationReplacementTarget {
                write_url: write_url.to_string(),
                read_url: read_url.to_string(),
                drop_pub: rep_pk.clone(),
            }),
            signature: String::new(),
        };
        let msg = canonical_revocation_message(&n);
        n.signature = hex::encode(admin_sk.sign(msg.as_bytes()).to_bytes());
        n
    };

    // 1. Non-loopback http:// replacement URL rejected with 400
    let bad_http = build_signed_notice(
        100,
        200,
        "http://evil.example/sync.php",
        "https://new.example/data",
        Some("migrate"),
    );
    assert_eq!(
        send_revoke(serde_json::to_value(&bad_http).unwrap())
            .await
            .status()
            .as_u16(),
        400
    );

    // 2. Self-redirect write_url (/sync.php, /sync/) and read_url rejected with 400
    let self_write_php = build_signed_notice(
        100,
        200,
        &format!("{}/sync.php", srv.base_url),
        "https://new.example/data",
        None,
    );
    assert_eq!(
        send_revoke(serde_json::to_value(&self_write_php).unwrap())
            .await
            .status()
            .as_u16(),
        400
    );

    let self_write_clean = build_signed_notice(
        100,
        200,
        &format!("{}/sync/", srv.base_url),
        "https://new.example/data",
        None,
    );
    assert_eq!(
        send_revoke(serde_json::to_value(&self_write_clean).unwrap())
            .await
            .status()
            .as_u16(),
        400
    );

    let self_read = build_signed_notice(
        100,
        200,
        "https://new.example/sync.php",
        &format!("{}/", srv.state.config.read_url()),
        None,
    );
    assert_eq!(
        send_revoke(serde_json::to_value(&self_read).unwrap())
            .await
            .status()
            .as_u16(),
        400
    );

    // 3. Whitespace/newline in revocation signature must be rejected (400) before persistence;
    //    valid HTTPS replacement with uppercase hex + empty reason "" normalizes to lowercase / null.
    let canonical_valid = build_signed_notice(
        100,
        200,
        "https://new.example/sync.php",
        "https://new.example/data",
        None,
    );
    let expected_sig = canonical_valid.signature.clone();
    let mut dirty_sig = canonical_valid.clone();
    dirty_sig.signature = format!("{}\n", expected_sig);
    assert_eq!(
        send_revoke(serde_json::to_value(&dirty_sig).unwrap())
            .await
            .status()
            .as_u16(),
        400
    );
    let upper_payload = serde_json::json!({
        "drop_pub": admin_pk.to_ascii_uppercase(),
        "issued_at": 100u64,
        "effective_at": 200u64,
        "reason": "",
        "replacement": {
            "write_url": "https://new.example/sync.php",
            "read_url": "https://new.example/data",
            "drop_pub": rep_pk.to_ascii_uppercase(),
        },
        "signature": expected_sig.to_ascii_uppercase(),
    });
    let pub_resp = send_revoke(upper_payload).await;
    assert_eq!(pub_resp.status().as_u16(), 200);
    let pub_json: serde_json::Value = pub_resp.json().await.unwrap();
    assert_eq!(pub_json["revoked"], true);
    assert_eq!(pub_json["revocation"]["drop_pub"], admin_pk);
    assert_eq!(pub_json["revocation"]["signature"], expected_sig);
    assert_eq!(pub_json["revocation"]["replacement"]["drop_pub"], rep_pk);
    assert!(pub_json["revocation"]["reason"].is_null());

    // 4. Stale / non-increasing issued_at rejected with 409 Conflict
    let equal_ts = build_signed_notice(
        100,
        210,
        "https://new.example/sync.php",
        "https://new.example/data",
        None,
    );
    assert_eq!(
        send_revoke(serde_json::to_value(&equal_ts).unwrap())
            .await
            .status()
            .as_u16(),
        409
    );
    let older_ts = build_signed_notice(
        99,
        210,
        "https://new.example/sync.php",
        "https://new.example/data",
        None,
    );
    assert_eq!(
        send_revoke(serde_json::to_value(&older_ts).unwrap())
            .await
            .status()
            .as_u16(),
        409
    );

    // 5. Strictly greater issued_at succeeds
    let newer_ts = build_signed_notice(
        101,
        220,
        "https://new.example/sync.php",
        "https://new.example/data",
        Some("rotated"),
    );
    assert_eq!(
        send_revoke(serde_json::to_value(&newer_ts).unwrap())
            .await
            .status()
            .as_u16(),
        200
    );

    // 6a. effective_at: 0 clears revocation
    let clear_zero = send_revoke(serde_json::json!({
        "notice": {
            "drop_pub": admin_pk,
            "issued_at": 102,
            "effective_at": 0
        }
    }))
    .await;
    assert_eq!(clear_zero.status().as_u16(), 200);
    assert_eq!(
        clear_zero.json::<serde_json::Value>().await.unwrap()["revoked"],
        false
    );
    assert!(srv.state.db.get_revocation().unwrap().is_none());

    // 6b. Re-publish then clear with object missing effective_at
    let repub = build_signed_notice(
        103,
        250,
        "https://new.example/sync.php",
        "https://new.example/data",
        None,
    );
    assert_eq!(
        send_revoke(serde_json::to_value(&repub).unwrap())
            .await
            .status()
            .as_u16(),
        200
    );
    let clear_missing = send_revoke(serde_json::json!({
        "drop_pub": admin_pk,
        "issued_at": 104
    }))
    .await;
    assert_eq!(clear_missing.status().as_u16(), 200);
    assert_eq!(
        clear_missing.json::<serde_json::Value>().await.unwrap()["revoked"],
        false
    );
    assert!(srv.state.db.get_revocation().unwrap().is_none());

    // 7. DELETE ?account returns pubkey string and slot/media counts
    let members_body = serde_json::to_vec(&serde_json::json!({ "pubkeys": [user_pk] })).unwrap();
    let m_nonce = random_hex(16);
    let m_msg = format_admin_put_members_message("card", now, &m_nonce, &sha256_hex(&members_body));
    let m_sig = hex::encode(admin_sk.sign(m_msg.as_bytes()).to_bytes());
    let m_resp = srv
        .client
        .put(format!("{}/sync.php?members&channel=card", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", m_nonce)
        .header("X-Drop-Signature", m_sig)
        .header("Content-Type", "application/json")
        .body(members_body)
        .send()
        .await
        .unwrap();
    assert_eq!(m_resp.status().as_u16(), 200);

    let mut req_card = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&user_sk, "PUT", "card", "home", "", now, b"card-blob") {
        req_card = req_card.header(k, v);
    }
    assert_eq!(
        req_card
            .body(b"card-blob".to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    let parity_media_id = sha256_hex(b"parity-media-01");
    let mut req_media = srv.client.put(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(
        &user_sk,
        "PUT",
        "media",
        "",
        &parity_media_id,
        now,
        b"media-blob",
    ) {
        req_media = req_media.header(k, v);
    }
    assert_eq!(
        req_media
            .body(b"media-blob".to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    let del_nonce = random_hex(16);
    let del_msg = format_delete_account_message(now, &del_nonce);
    let del_sig = hex::encode(user_sk.sign(del_msg.as_bytes()).to_bytes());
    let del_resp = srv
        .client
        .delete(format!("{}/sync.php?account", srv.base_url))
        .header("X-Drop-Pubkey", &user_pk)
        .header("X-Drop-Timestamp", now.to_string())
        .header("X-Drop-Nonce", del_nonce)
        .header("X-Drop-Signature", del_sig)
        .send()
        .await
        .unwrap();
    assert_eq!(del_resp.status().as_u16(), 200);
    let del_json: serde_json::Value = del_resp.json().await.unwrap();
    assert_eq!(del_json["deleted_account"], user_pk);
    assert_eq!(del_json["deleted_slots"], 1);
    assert_eq!(del_json["deleted_media"], 1);
}

#[tokio::test]
async fn test_s01_max_buckets_enforced_on_ticket_and_batch_creation() {
    let (admin_sk, admin_pk) = gen_keypair();
    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.allow_pow_tickets = true;
    cfg.lock.ticket_pow_bits = 8;
    cfg.lock.max_buckets = 1;
    cfg.lock.max_inodes = 50;
    let srv = TestServer::start(cfg).await;

    let lock_pub = srv.state.db.lock_pubkey_bytes().unwrap();
    let admin_pub = admin_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 3).unwrap();

    let cmig1_sk = SigningKey::from_bytes(&[161u8; 32]);
    let cmig1_pub = cmig1_sk.verifying_key().to_bytes();
    let m1 = build_single_server_manifest(admin_pub, lock_pub, cmig1_pub, quarter);
    let aid1 = m1.rev1_anchor_id().unwrap();
    let b1 = humoco_proto::derive_bucket(&aid1, &lock_pub);

    let cmig2_sk = SigningKey::from_bytes(&[162u8; 32]);
    let cmig2_pub = cmig2_sk.verifying_key().to_bytes();
    let m2 = build_single_server_manifest(admin_pub, lock_pub, cmig2_pub, quarter);
    let aid2 = m2.rev1_anchor_id().unwrap();
    let b2 = humoco_proto::derive_bucket(&aid2, &lock_pub);

    // Pre-fetch ticket2 BEFORE Bucket 1 exists (simulates pre-issued GenesisTicket race).
    let ticket1 = issue_pow_ticket_http(&srv, aid1, quarter).await;
    let ticket2_prefetched = issue_pow_ticket_http(&srv, aid2, quarter).await;

    let g1_sk = SigningKey::from_bytes(&[163u8; 32]);
    let r1_sk = SigningKey::from_bytes(&[164u8; 32]);
    let r1_hash = humoco_proto::hash_pubkey_sha3(&r1_sk.verifying_key().to_bytes());
    let e1_0 = sign_lock_entry_helper(
        aid1,
        [0x01; 32],
        [0u8; 32],
        0,
        0,
        [0x11; 32],
        &g1_sk,
        r1_hash,
        None,
        Some(&cmig1_sk),
        8,
    );

    // 1. Creating Bucket 1 succeeds (1/1 bucket budget used)
    let resp1 = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(aid1),
            "bucket": hex::encode(b1),
            "recipient_nonce": hex::encode([0xA1; 32]),
            "entries": [e1_0.to_wire_hex().unwrap()],
            "manifest": m1,
            "genesis_ticket": ticket1,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status().as_u16(), 200);
    assert_eq!(srv.state.db.lock_bucket_count_and_inodes().unwrap(), (1, 1));

    // 2. Existing Bucket 1 continues to accept new entries and tickets when max_buckets is full
    let e1_1 = sign_lock_entry_helper(
        aid1, [0x02; 32], e1_0.slot, 0, 1, [0x12; 32], &r1_sk, [0x77; 32], None, None, 8,
    );
    let resp1_next = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(aid1),
            "bucket": hex::encode(b1),
            "recipient_nonce": hex::encode([0xA2; 32]),
            "entries": [e1_1.to_wire_hex().unwrap()],
            "manifest": serde_json::Value::Null,
            "genesis_ticket": serde_json::Value::Null,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp1_next.status().as_u16(), 200);
    assert_eq!(srv.state.db.lock_bucket_count_and_inodes().unwrap(), (1, 2));

    let now = unix_now();
    let pow1_existing = humoco_proto::solve_ticket_pow(
        &aid1,
        quarter,
        now,
        8,
        ticket1.issued_at + 100_000,
        200_000,
    )
    .unwrap();
    let existing_ticket_resp = srv
        .client
        .post(format!("{}/sync.php?lock_ticket", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(aid1),
            "retain_until_quarter": quarter,
            "pow_timestamp": now,
            "pow_nonce": pow1_existing,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        existing_ticket_resp.status().as_u16(),
        200,
        "POST ?lock_ticket for already-existing Bucket 1 must still succeed at max_buckets=1"
    );

    // 3. New bucket ticket request beyond max_buckets=1 must fail with 507
    let pow2 = humoco_proto::solve_ticket_pow(&aid2, quarter, now, 8, 100_000, 200_000).unwrap();
    let t2_resp = srv
        .client
        .post(format!("{}/sync.php?lock_ticket", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(aid2),
            "retain_until_quarter": quarter,
            "pow_timestamp": now,
            "pow_nonce": pow2,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        t2_resp.status().as_u16(),
        507,
        "POST ?lock_ticket for unseen bucket beyond max_buckets=1 must return 507"
    );

    // 4. Pre-fetched GenesisTicket for Bucket 2 must ALSO fail with 507 on POST ?lock
    let g2_sk = SigningKey::from_bytes(&[165u8; 32]);
    let e2_0 = sign_lock_entry_helper(
        aid2,
        [0x03; 32],
        [0u8; 32],
        0,
        0,
        [0x13; 32],
        &g2_sk,
        [0x88; 32],
        None,
        Some(&cmig2_sk),
        8,
    );
    let resp2 = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(aid2),
            "bucket": hex::encode(b2),
            "recipient_nonce": hex::encode([0xA3; 32]),
            "entries": [e2_0.to_wire_hex().unwrap()],
            "manifest": m2,
            "genesis_ticket": ticket2_prefetched,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp2.status().as_u16(),
        507,
        "POST ?lock creating unseen bucket beyond max_buckets=1 must return 507"
    );
    assert_eq!(srv.state.db.lock_bucket_count_and_inodes().unwrap(), (1, 2));
}

#[tokio::test]
async fn test_s02_import_and_finalize_enforce_max_buckets() {
    let (av_sk, av_pk) = gen_keypair();
    let mut cfg_v = base_hybrid_config(&av_pk);
    cfg_v.lock.allow_pow_tickets = true;
    cfg_v.lock.ticket_pow_bits = 8;
    cfg_v.lock.max_buckets = 1;
    cfg_v.lock.max_inodes = 50;
    let s_victim = TestServer::start(cfg_v).await;

    let (aa1_sk, _, s_att1) = start_lock_test_server(true, Some(0)).await;
    let (aa2_sk, _, s_att2) = start_lock_test_server(true, Some(0)).await;
    let (an_sk, _, s_new) = start_lock_test_server(true, Some(0)).await;

    let ev = server_entry_for_test(&s_victim, &av_sk, humoco_proto::NominatedBy::Creator);
    let ea1 = server_entry_for_test(&s_att1, &aa1_sk, humoco_proto::NominatedBy::Creator);
    let ea2 = server_entry_for_test(&s_att2, &aa2_sk, humoco_proto::NominatedBy::Creator);
    let en = server_entry_for_test(&s_new, &an_sk, humoco_proto::NominatedBy::Creator);

    let cmig_sk = SigningKey::from_bytes(&[171u8; 32]);
    let cmig_pub = cmig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;

    // 1. Fill max_buckets = 1 on s_victim with Bucket 1 (aid1)
    let man1 = build_multi_server_manifest(
        vec![ev.clone(), ea1.clone(), ea2.clone()],
        Vec::new(),
        2,
        cmig_pub,
        Vec::new(),
        t0 * 1_000,
        quarter,
    );
    let aid1 = man1.rev1_anchor_id().unwrap();
    let g_sk = SigningKey::from_bytes(&[172u8; 32]);
    let e1_0 = sign_lock_entry_helper(
        aid1,
        [0x11; 32],
        [0u8; 32],
        0,
        0,
        [0x21; 32],
        &g_sk,
        [0x31; 32],
        None,
        Some(&cmig_sk),
        8,
    );
    for srv in [&s_victim, &s_att1, &s_att2] {
        let tkt = issue_pow_ticket_db(srv, aid1, quarter, t0);
        let bkt = humoco_proto::derive_bucket(&aid1, &srv.state.db.lock_pubkey_bytes().unwrap());
        let (code, _) = srv
            .state
            .db
            .process_lock_batch(
                &srv.state.config,
                humoco_sync_server::locks::LockBatchRequest {
                    anchor_id: aid1,
                    bucket: bkt,
                    recipient_nonce: [0x41; 32],
                    entries: vec![e1_0.to_wire_hex().unwrap()],
                    manifest: Some(man1.clone()),
                    genesis_ticket: Some(tkt),
                    known_head_receipt: None,
                },
                t0,
            )
            .unwrap();
        assert_eq!(code, 200);
    }
    assert_eq!(
        s_victim.state.db.lock_bucket_count_and_inodes().unwrap(),
        (1, 1)
    );

    // 2. Unseen anchor aid2 via POST ?lock_import (0s pure growth [s_att1] -> [s_att1, s_victim])
    //    even with 0 entries MUST fail 507 when max_buckets=1 is already reached!
    let man2 = build_multi_server_manifest(
        vec![ea1.clone()],
        Vec::new(),
        1,
        cmig_pub,
        Vec::new(),
        t0 * 1_000,
        quarter,
    );
    let aid2 = man2.rev1_anchor_id().unwrap();
    let prop2 = build_signed_proposal(
        aid2,
        1,
        2,
        vec![ea1.clone(), ev.clone()],
        Vec::new(),
        quarter,
        t0 + 10,
        humoco_proto::ProposalInitiator::Creator,
        Some(&cmig_sk),
        Vec::new(),
    );
    let (_, pf2) = s_att1
        .state
        .db
        .process_lock_freeze(
            &s_att1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: prop2.clone(),
                current_manifest: Some(man2.clone()),
            },
            t0 + 10,
        )
        .unwrap();
    let snap2: humoco_proto::SnapshotExport =
        serde_json::from_value(pf2["snapshot_export"].clone()).unwrap();
    let imp_err = s_victim
        .state
        .db
        .process_lock_import(
            &s_victim.state.config,
            humoco_sync_server::lock_rotation::LockImportRequest {
                anchor_id: aid2,
                active_manifest: man2,
                proposal: prop2,
                snapshots: vec![snap2],
                quorum_certificates: Vec::new(),
            },
            t0 + 10,
        )
        .unwrap_err();
    assert!(
        matches!(
            imp_err,
            humoco_sync_server::db::DbError::Http { status: 507, .. }
        ),
        "Unseen bucket via ?lock_import beyond max_buckets=1 must fail with 507, got {imp_err:?}"
    );
    assert_eq!(
        s_victim.state.db.lock_bucket_count_and_inodes().unwrap(),
        (1, 1)
    );

    // 3. Unseen anchor aid3 via ?lock_commit Finalize ([s_victim, s_att1, s_att2] -> [s_att1, s_att2])
    //    signed solely by s_att1 & s_att2 MUST also fail 507 on s_victim!
    let man3_rev1 = build_multi_server_manifest(
        vec![ev.clone(), ea1.clone(), ea2.clone()],
        Vec::new(),
        2,
        cmig_pub,
        Vec::new(),
        (t0 + 20) * 1_000,
        quarter,
    );
    let aid3 = man3_rev1.rev1_anchor_id().unwrap();
    let prop3 = build_signed_proposal(
        aid3,
        1,
        2,
        vec![ea1.clone(), ea2.clone()],
        Vec::new(),
        quarter,
        t0 + 25,
        humoco_proto::ProposalInitiator::Creator,
        Some(&cmig_sk),
        Vec::new(),
    );
    let mut snaps3 = Vec::new();
    for srv in [&s_att1, &s_att2] {
        let (_, v) = srv
            .state
            .db
            .process_lock_freeze(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                    proposal: prop3.clone(),
                    current_manifest: Some(man3_rev1.clone()),
                },
                t0 + 25,
            )
            .unwrap();
        snaps3.push(
            serde_json::from_value::<humoco_proto::SnapshotExport>(v["snapshot_export"].clone())
                .unwrap(),
        );
    }
    let mut acks3 = Vec::new();
    let mut ish3 = [0u8; 32];
    for srv in [&s_att1, &s_att2] {
        let (_, v) = srv
            .state
            .db
            .process_lock_import(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockImportRequest {
                    anchor_id: aid3,
                    active_manifest: man3_rev1.clone(),
                    proposal: prop3.clone(),
                    snapshots: snaps3.clone(),
                    quorum_certificates: Vec::new(),
                },
                t0 + 25,
            )
            .unwrap();
        let ack: humoco_proto::ImportAck = serde_json::from_value(v["import_ack"].clone()).unwrap();
        ish3 = ack.imported_state_hash;
        acks3.push(ack);
    }
    let mut cs3 = Vec::new();
    for srv in [&s_att1, &s_att2] {
        let (_, v) = srv
            .state
            .db
            .process_lock_commit(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                    anchor_id: aid3,
                    proposal: prop3.clone(),
                    imported_state_hash: ish3,
                    import_acks: acks3.clone(),
                },
                t0 + 25,
            )
            .unwrap();
        cs3.push(
            serde_json::from_value::<humoco_proto::CommitteeSignature>(
                v["committee_signature"].clone(),
            )
            .unwrap(),
        );
    }
    let cert3 = humoco_proto::MigrationCert {
        anchor_id: aid3,
        genesis_manifest: Some(Box::new(man3_rev1.clone())),
        proposal: prop3,
        imported_state_hash: ish3,
        import_acks: acks3,
        commit_sigs: cs3,
    };
    let (man3_rev2, _) = cert3.verify_step(&aid3, &man3_rev1).unwrap();
    let fin3_err = s_victim
        .state
        .db
        .process_lock_commit(
            &s_victim.state.config,
            humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                anchor_id: aid3,
                new_manifest: man3_rev2,
            },
            t0 + 30,
        )
        .unwrap_err();
    assert!(
        matches!(
            fin3_err,
            humoco_sync_server::db::DbError::Http { status: 507, .. }
        ),
        "Unseen bucket via ?lock_commit Finalize beyond max_buckets=1 must fail with 507, got {fin3_err:?}"
    );
    assert_eq!(
        s_victim.state.db.lock_bucket_count_and_inodes().unwrap(),
        (1, 1)
    );
    assert!(s_victim
        .state
        .db
        .get_static_anchor_manifest(&hex::encode(aid3))
        .unwrap()
        .is_none());

    // 4. Existing Bucket 1 (aid1) rotation still succeeds at max_buckets = 1!
    let t_prop1 = t0 + 40;
    let prop1 = build_signed_proposal(
        aid1,
        1,
        2,
        vec![ev, ea1, en],
        Vec::new(),
        quarter,
        t_prop1,
        humoco_proto::ProposalInitiator::Creator,
        Some(&cmig_sk),
        Vec::new(),
    );
    let mut snaps1 = Vec::new();
    for srv in [&s_victim, &s_att1] {
        let (_, v) = srv
            .state
            .db
            .process_lock_freeze(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                    proposal: prop1.clone(),
                    current_manifest: None,
                },
                t_prop1,
            )
            .unwrap();
        snaps1.push(
            serde_json::from_value::<humoco_proto::SnapshotExport>(v["snapshot_export"].clone())
                .unwrap(),
        );
    }
    let t_mat1 = t_prop1 + s_victim.state.config.lock.proposal_timelock_secs;
    let mut acks1 = Vec::new();
    let mut ish1 = [0u8; 32];
    for srv in [&s_victim, &s_att1, &s_new] {
        let (code, v) = srv
            .state
            .db
            .process_lock_import(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockImportRequest {
                    anchor_id: aid1,
                    active_manifest: man1.clone(),
                    proposal: prop1.clone(),
                    snapshots: snaps1.clone(),
                    quorum_certificates: Vec::new(),
                },
                t_mat1,
            )
            .unwrap();
        assert_eq!(code, 200);
        let ack: humoco_proto::ImportAck = serde_json::from_value(v["import_ack"].clone()).unwrap();
        ish1 = ack.imported_state_hash;
        acks1.push(ack);
    }
    let mut cs1 = Vec::new();
    for srv in [&s_victim, &s_att1] {
        let (_, v) = srv
            .state
            .db
            .process_lock_commit(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                    anchor_id: aid1,
                    proposal: prop1.clone(),
                    imported_state_hash: ish1,
                    import_acks: acks1.clone(),
                },
                t_mat1,
            )
            .unwrap();
        cs1.push(
            serde_json::from_value::<humoco_proto::CommitteeSignature>(
                v["committee_signature"].clone(),
            )
            .unwrap(),
        );
    }
    let cert1 = humoco_proto::MigrationCert {
        anchor_id: aid1,
        genesis_manifest: Some(Box::new(man1.clone())),
        proposal: prop1,
        imported_state_hash: ish1,
        import_acks: acks1,
        commit_sigs: cs1,
    };
    let (man1_rev2, _) = cert1.verify_step(&aid1, &man1).unwrap();
    let (fin1_code, _) = s_victim
        .state
        .db
        .process_lock_commit(
            &s_victim.state.config,
            humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                anchor_id: aid1,
                new_manifest: man1_rev2,
            },
            t_mat1,
        )
        .unwrap();
    assert_eq!(fin1_code, 200);
    assert_eq!(
        s_victim.state.db.lock_bucket_count_and_inodes().unwrap(),
        (1, 1)
    );
}

#[tokio::test]
async fn test_s02_import_preserves_monotonic_head_against_prerotation_receipt() {
    let (a1_sk, _, s1) = start_lock_test_server(true, None).await;
    let (a2_sk, _, s2) = start_lock_test_server(true, None).await;
    let (a3_sk, _, s3) = start_lock_test_server(true, None).await;
    let (a5_sk, _, s5) = start_lock_test_server(true, None).await;

    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
    let e_s2 = server_entry_for_test(&s2, &a2_sk, humoco_proto::NominatedBy::Creator);
    let e_s3 = server_entry_for_test(&s3, &a3_sk, humoco_proto::NominatedBy::Creator);
    let e_s5 = server_entry_for_test(&s5, &a5_sk, humoco_proto::NominatedBy::Creator);

    let cmig_sk = SigningKey::from_bytes(&[181u8; 32]);
    let cmig_pub = cmig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;

    let man_rev1 = build_multi_server_manifest(
        vec![e_s1.clone(), e_s2.clone(), e_s3],
        Vec::new(),
        2,
        cmig_pub,
        Vec::new(),
        t0 * 1_000,
        quarter,
    );
    let aid = man_rev1.rev1_anchor_id().unwrap();

    // Order two root slots deterministically so slot_hi > slot_lo lexicographically
    let g_sk = SigningKey::from_bytes(&[182u8; 32]);
    let r_lo_sk = SigningKey::from_bytes(&[183u8; 32]);
    let r_hi_sk = SigningKey::from_bytes(&[184u8; 32]);
    let (ds_lo, ds_hi) = if humoco_proto::derive_slot(&aid, &[0x11; 32])
        < humoco_proto::derive_slot(&aid, &[0x22; 32])
    {
        ([0x11; 32], [0x22; 32])
    } else {
        ([0x22; 32], [0x11; 32])
    };
    let root_hi = sign_lock_entry_helper(
        aid,
        ds_hi,
        [0u8; 32],
        0,
        0,
        [0x51; 32],
        &g_sk,
        humoco_proto::hash_pubkey_sha3(&r_hi_sk.verifying_key().to_bytes()),
        None,
        Some(&cmig_sk),
        8,
    );
    let root_lo = sign_lock_entry_helper(
        aid,
        ds_lo,
        [0u8; 32],
        0,
        0,
        [0x52; 32],
        &g_sk,
        humoco_proto::hash_pubkey_sha3(&r_lo_sk.verifying_key().to_bytes()),
        None,
        Some(&cmig_sk),
        8,
    );
    assert!(root_hi.slot > root_lo.slot);

    // Insert root_hi FIRST (write_seq=1) and root_lo SECOND (write_seq=2) on S1
    let tkt1 = issue_pow_ticket_db(&s1, aid, quarter, t0);
    let bkt1 = humoco_proto::derive_bucket(&aid, &s1.state.db.lock_pubkey_bytes().unwrap());
    let (c1, _) = s1
        .state
        .db
        .process_lock_batch(
            &s1.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt1,
                recipient_nonce: [0x61; 32],
                entries: vec![root_hi.to_wire_hex().unwrap()],
                manifest: Some(man_rev1.clone()),
                genesis_ticket: Some(tkt1),
                known_head_receipt: None,
            },
            t0,
        )
        .unwrap();
    assert_eq!(c1, 200);
    let (c2, v2) = s1
        .state
        .db
        .process_lock_batch(
            &s1.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt1,
                recipient_nonce: [0x62; 32],
                entries: vec![root_lo.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: None,
            },
            t0 + 1,
        )
        .unwrap();
    assert_eq!(c2, 200);
    let resp2: humoco_sync_server::locks::LockBatchResponse = serde_json::from_value(v2).unwrap();
    let rev1_head_receipt = resp2.receipts.into_iter().next().unwrap();
    assert_eq!(rev1_head_receipt.write_seq, 2);

    // Commit both entries to S2 as well (no extra entries, so union has exact same 2 entries)
    let tkt2 = issue_pow_ticket_db(&s2, aid, quarter, t0);
    let bkt2 = humoco_proto::derive_bucket(&aid, &s2.state.db.lock_pubkey_bytes().unwrap());
    s2.state
        .db
        .process_lock_batch(
            &s2.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt2,
                recipient_nonce: [0x63; 32],
                entries: vec![
                    root_lo.to_wire_hex().unwrap(),
                    root_hi.to_wire_hex().unwrap(),
                ],
                manifest: Some(man_rev1.clone()),
                genesis_ticket: Some(tkt2),
                known_head_receipt: None,
            },
            t0 + 1,
        )
        .unwrap();

    // Rotate Rev 1 -> Rev 2 keeping S1 in committee: [S1, S2, S3] -> [S1, S2, S5]
    let t_prop = t0 + 10;
    let prop12 = build_signed_proposal(
        aid,
        1,
        2,
        vec![e_s1.clone(), e_s2.clone(), e_s5.clone()],
        Vec::new(),
        quarter,
        t_prop,
        humoco_proto::ProposalInitiator::Creator,
        Some(&cmig_sk),
        Vec::new(),
    );
    let mut snaps = Vec::new();
    for srv in [&s1, &s2] {
        let (_, v) = srv
            .state
            .db
            .process_lock_freeze(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                    proposal: prop12.clone(),
                    current_manifest: None,
                },
                t_prop,
            )
            .unwrap();
        snaps.push(
            serde_json::from_value::<humoco_proto::SnapshotExport>(v["snapshot_export"].clone())
                .unwrap(),
        );
    }
    let t_mat = t_prop + s1.state.config.lock.proposal_timelock_secs;
    let mut acks = Vec::new();
    let mut ish = [0u8; 32];
    for srv in [&s1, &s2, &s5] {
        let (_, v) = srv
            .state
            .db
            .process_lock_import(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockImportRequest {
                    anchor_id: aid,
                    active_manifest: man_rev1.clone(),
                    proposal: prop12.clone(),
                    snapshots: snaps.clone(),
                    quorum_certificates: Vec::new(),
                },
                t_mat,
            )
            .unwrap();
        let ack: humoco_proto::ImportAck = serde_json::from_value(v["import_ack"].clone()).unwrap();
        ish = ack.imported_state_hash;
        acks.push(ack);
    }
    let mut cs = Vec::new();
    for srv in [&s1, &s2] {
        let (_, v) = srv
            .state
            .db
            .process_lock_commit(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                    anchor_id: aid,
                    proposal: prop12.clone(),
                    imported_state_hash: ish,
                    import_acks: acks.clone(),
                },
                t_mat,
            )
            .unwrap();
        cs.push(
            serde_json::from_value::<humoco_proto::CommitteeSignature>(
                v["committee_signature"].clone(),
            )
            .unwrap(),
        );
    }
    let cert12 = humoco_proto::MigrationCert {
        anchor_id: aid,
        genesis_manifest: Some(Box::new(man_rev1.clone())),
        proposal: prop12,
        imported_state_hash: ish,
        import_acks: acks,
        commit_sigs: cs,
    };
    let (man_rev2, _) = cert12.verify_step(&aid, &man_rev1).unwrap();
    for srv in [&s1, &s2, &s5] {
        srv.state
            .db
            .process_lock_commit(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                    anchor_id: aid,
                    new_manifest: man_rev2.clone(),
                },
                t_mat,
            )
            .unwrap();
    }

    // In Rev 2, an honest client presents pre-rotation receipt (write_seq=2) on S1:
    // MUST NOT falsely SelfFreeze S1!
    let child_entry = sign_lock_entry_helper(
        aid,
        [0x33; 32],
        root_lo.slot,
        0,
        1,
        [0x53; 32],
        &r_lo_sk,
        [0xAA; 32],
        None,
        None,
        8,
    );
    let (post_rot_code, post_rot_val) = s1
        .state
        .db
        .process_lock_batch(
            &s1.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt1,
                recipient_nonce: [0x64; 32],
                entries: vec![child_entry.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: Some(rev1_head_receipt),
            },
            t_mat + 5,
        )
        .unwrap();
    assert_eq!(
        post_rot_code, 200,
        "Retained server S1 must not falsely SelfFreeze on valid Rev-1 receipt after rotation, got: {post_rot_val}"
    );
    let rev2_resp: humoco_sync_server::locks::LockBatchResponse =
        serde_json::from_value(post_rot_val).unwrap();
    let rev2_head_receipt = rev2_resp.receipts.into_iter().next().unwrap();
    assert_eq!(rev2_head_receipt.write_seq, 3);

    // Also test Rev 2 -> Rev 3 when S1's Single slot (child_entry) turns into an unresolved
    // Conflict on S5: Single count drops 3 -> 2, yet S1's write_seq MUST NOT drop below 3!
    let bkt5 = humoco_proto::derive_bucket(&aid, &s5.state.db.lock_pubkey_bytes().unwrap());
    let child_conflict = sign_lock_entry_helper(
        aid,
        [0x33; 32],
        root_lo.slot,
        0,
        1,
        [0x54; 32],
        &r_lo_sk,
        [0xBB; 32],
        None,
        None,
        8,
    );
    s5.state
        .db
        .process_lock_batch(
            &s5.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt5,
                recipient_nonce: [0x65; 32],
                entries: vec![child_conflict.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: None,
            },
            t_mat + 6,
        )
        .unwrap();

    let t_prop23 = t_mat + 10;
    let prop23 = build_signed_proposal(
        aid,
        2,
        2,
        vec![e_s1, e_s2, e_s5],
        Vec::new(),
        quarter,
        t_prop23,
        humoco_proto::ProposalInitiator::Creator,
        Some(&cmig_sk),
        Vec::new(),
    );
    let mut snaps23 = Vec::new();
    for srv in [&s1, &s5] {
        let (_, v) = srv
            .state
            .db
            .process_lock_freeze(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                    proposal: prop23.clone(),
                    current_manifest: None,
                },
                t_prop23,
            )
            .unwrap();
        snaps23.push(
            serde_json::from_value::<humoco_proto::SnapshotExport>(v["snapshot_export"].clone())
                .unwrap(),
        );
    }
    let t_mat23 = t_prop23 + s1.state.config.lock.proposal_timelock_secs;
    let mut acks23 = Vec::new();
    let mut ish23 = [0u8; 32];
    for srv in [&s1, &s2, &s5] {
        let (_, v) = srv
            .state
            .db
            .process_lock_import(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockImportRequest {
                    anchor_id: aid,
                    active_manifest: man_rev2.clone(),
                    proposal: prop23.clone(),
                    snapshots: snaps23.clone(),
                    quorum_certificates: Vec::new(),
                },
                t_mat23,
            )
            .unwrap();
        let ack: humoco_proto::ImportAck = serde_json::from_value(v["import_ack"].clone()).unwrap();
        ish23 = ack.imported_state_hash;
        acks23.push(ack);
    }
    let mut cs23 = Vec::new();
    for srv in [&s1, &s5] {
        let (_, v) = srv
            .state
            .db
            .process_lock_commit(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                    anchor_id: aid,
                    proposal: prop23.clone(),
                    imported_state_hash: ish23,
                    import_acks: acks23.clone(),
                },
                t_mat23,
            )
            .unwrap();
        cs23.push(
            serde_json::from_value::<humoco_proto::CommitteeSignature>(
                v["committee_signature"].clone(),
            )
            .unwrap(),
        );
    }
    let cert23 = humoco_proto::MigrationCert {
        anchor_id: aid,
        genesis_manifest: None,
        proposal: prop23,
        imported_state_hash: ish23,
        import_acks: acks23,
        commit_sigs: cs23,
    };
    let (man_rev3, _) = cert23.verify_step(&aid, &man_rev2).unwrap();
    for srv in [&s1, &s2, &s5] {
        srv.state
            .db
            .process_lock_commit(
                &srv.state.config,
                humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                    anchor_id: aid,
                    new_manifest: man_rev3.clone(),
                },
                t_mat23,
            )
            .unwrap();
    }

    // Presenting rev2_head_receipt (write_seq=3) on S1 in Rev 3 must return 200 ConflictSeen,
    // NOT falsely SelfFreeze!
    let (rev3_code, rev3_val) = s1
        .state
        .db
        .process_lock_batch(
            &s1.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: aid,
                bucket: bkt1,
                recipient_nonce: [0x66; 32],
                entries: vec![child_entry.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: Some(rev2_head_receipt),
            },
            t_mat23 + 5,
        )
        .unwrap();
    assert_eq!(
        rev3_code, 200,
        "S1 must not falsely SelfFreeze when Single slot turned into Conflict across rotation, got: {rev3_val}"
    );
    assert_eq!(rev3_val["status"], "conflict");
}

#[tokio::test]
async fn test_s02_import_and_finalize_reject_forked_history_chain() {
    let dir = TempDir::new().unwrap();
    let db2_path = dir.path().join("s2.redb");
    let db2_fork_path = dir.path().join("s2_fork.redb");
    let db5b_path = dir.path().join("s5b.redb");

    let (a1_sk, _, s1) = start_lock_test_server(true, Some(0)).await;
    let (a2_sk, a2_pk) = gen_keypair();
    let (a3_sk, _, s3) = start_lock_test_server(true, Some(0)).await;
    let (a5a_sk, _, s5a) = start_lock_test_server(true, Some(0)).await;
    let (a5b_sk, a5b_pk) = gen_keypair();

    let mut cfg2 = base_hybrid_config(&a2_pk);
    cfg2.lock.proposal_timelock_secs = 0;
    let mut cfg5b = base_hybrid_config(&a5b_pk);
    cfg5b.lock.proposal_timelock_secs = 0;

    let lp2 = {
        let db2 = humoco_sync_server::db::SyncDb::open(&db2_path, "").unwrap();
        db2.lock_pubkey_bytes().unwrap()
    };
    std::fs::copy(&db2_path, &db2_fork_path).unwrap();
    let lp5b = {
        let db5b = humoco_sync_server::db::SyncDb::open(&db5b_path, "").unwrap();
        db5b.lock_pubkey_bytes().unwrap()
    };

    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
    let e_s2 = humoco_proto::ServerEntry {
        write_url: "https://s2.example/sync.php".to_string(),
        read_url: "https://s2.example/humoco_sync_data".to_string(),
        admin_pub: a2_sk.verifying_key().to_bytes(),
        lock_pub: lp2,
        nominated_by: humoco_proto::NominatedBy::Creator,
    };
    let e_s3 = server_entry_for_test(&s3, &a3_sk, humoco_proto::NominatedBy::Creator);
    let e_s5a = server_entry_for_test(&s5a, &a5a_sk, humoco_proto::NominatedBy::Creator);
    let e_s5b = humoco_proto::ServerEntry {
        write_url: "https://s5b.example/sync.php".to_string(),
        read_url: "https://s5b.example/humoco_sync_data".to_string(),
        admin_pub: a5b_sk.verifying_key().to_bytes(),
        lock_pub: lp5b,
        nominated_by: humoco_proto::NominatedBy::Creator,
    };

    let cmig_sk = SigningKey::from_bytes(&[191u8; 32]);
    let cmig_pub = cmig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;

    let man_rev1 = build_multi_server_manifest(
        vec![e_s1.clone(), e_s2.clone(), e_s3.clone()],
        Vec::new(),
        2,
        cmig_pub,
        Vec::new(),
        t0 * 1_000,
        quarter,
    );
    let aid = man_rev1.rev1_anchor_id().unwrap();

    // Branch A: Finalize Rev 1 -> Rev 2A ([S1, S2, S5a]) on S1
    let prop_2a = build_signed_proposal(
        aid,
        1,
        2,
        vec![e_s1.clone(), e_s2.clone(), e_s5a.clone()],
        Vec::new(),
        quarter,
        t0 + 10,
        humoco_proto::ProposalInitiator::Creator,
        Some(&cmig_sk),
        Vec::new(),
    );
    let db2_a = humoco_sync_server::db::SyncDb::open(&db2_path, "").unwrap();
    let (_, pf1_a) = s1
        .state
        .db
        .process_lock_freeze(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: prop_2a.clone(),
                current_manifest: Some(man_rev1.clone()),
            },
            t0 + 10,
        )
        .unwrap();
    let (_, pf2_a) = db2_a
        .process_lock_freeze(
            &cfg2,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: prop_2a.clone(),
                current_manifest: Some(man_rev1.clone()),
            },
            t0 + 10,
        )
        .unwrap();
    let snaps_2a = vec![
        serde_json::from_value::<humoco_proto::SnapshotExport>(pf1_a["snapshot_export"].clone())
            .unwrap(),
        serde_json::from_value::<humoco_proto::SnapshotExport>(pf2_a["snapshot_export"].clone())
            .unwrap(),
    ];
    let t_2a = t0 + 10 + s1.state.config.lock.proposal_timelock_secs;
    let (_, i1_a) = s1
        .state
        .db
        .process_lock_import(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockImportRequest {
                anchor_id: aid,
                active_manifest: man_rev1.clone(),
                proposal: prop_2a.clone(),
                snapshots: snaps_2a.clone(),
                quorum_certificates: Vec::new(),
            },
            t_2a,
        )
        .unwrap();
    let (_, i2_a) = db2_a
        .process_lock_import(
            &cfg2,
            humoco_sync_server::lock_rotation::LockImportRequest {
                anchor_id: aid,
                active_manifest: man_rev1.clone(),
                proposal: prop_2a.clone(),
                snapshots: snaps_2a.clone(),
                quorum_certificates: Vec::new(),
            },
            t_2a,
        )
        .unwrap();
    let (_, i5_a) = s5a
        .state
        .db
        .process_lock_import(
            &s5a.state.config,
            humoco_sync_server::lock_rotation::LockImportRequest {
                anchor_id: aid,
                active_manifest: man_rev1.clone(),
                proposal: prop_2a.clone(),
                snapshots: snaps_2a,
                quorum_certificates: Vec::new(),
            },
            t_2a,
        )
        .unwrap();
    let acks_2a: Vec<humoco_proto::ImportAck> = [i1_a, i2_a, i5_a]
        .into_iter()
        .map(|v| serde_json::from_value(v["import_ack"].clone()).unwrap())
        .collect();
    let ish_2a = acks_2a[0].imported_state_hash;
    let (_, sc1_a) = s1
        .state
        .db
        .process_lock_commit(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                anchor_id: aid,
                proposal: prop_2a.clone(),
                imported_state_hash: ish_2a,
                import_acks: acks_2a.clone(),
            },
            t_2a,
        )
        .unwrap();
    let (_, sc2_a) = db2_a
        .process_lock_commit(
            &cfg2,
            humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                anchor_id: aid,
                proposal: prop_2a.clone(),
                imported_state_hash: ish_2a,
                import_acks: acks_2a.clone(),
            },
            t_2a,
        )
        .unwrap();
    let cert_2a = humoco_proto::MigrationCert {
        anchor_id: aid,
        genesis_manifest: Some(Box::new(man_rev1.clone())),
        proposal: prop_2a,
        imported_state_hash: ish_2a,
        import_acks: acks_2a,
        commit_sigs: vec![
            serde_json::from_value(sc1_a["committee_signature"].clone()).unwrap(),
            serde_json::from_value(sc2_a["committee_signature"].clone()).unwrap(),
        ],
    };
    let (man_rev2_a, _) = cert_2a.verify_step(&aid, &man_rev1).unwrap();
    s1.state
        .db
        .process_lock_commit(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                anchor_id: aid,
                new_manifest: man_rev2_a.clone(),
            },
            t_2a,
        )
        .unwrap();

    // Branch B (equivocating fork using cloned db2_fork + s3): Rev 1 -> Rev 2B ([S2, S5b], Q=2)
    let db2_b = humoco_sync_server::db::SyncDb::open(&db2_fork_path, "").unwrap();
    let prop_2b = build_signed_proposal(
        aid,
        1,
        2,
        vec![e_s2.clone(), e_s5b.clone()],
        Vec::new(),
        quarter,
        t0 + 20,
        humoco_proto::ProposalInitiator::Creator,
        Some(&cmig_sk),
        Vec::new(),
    );
    let (_, pf2_b) = db2_b
        .process_lock_freeze(
            &cfg2,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: prop_2b.clone(),
                current_manifest: Some(man_rev1.clone()),
            },
            t0 + 20,
        )
        .unwrap();
    let (_, pf3_b) = s3
        .state
        .db
        .process_lock_freeze(
            &s3.state.config,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: prop_2b.clone(),
                current_manifest: Some(man_rev1.clone()),
            },
            t0 + 20,
        )
        .unwrap();
    let snaps_2b = vec![
        serde_json::from_value::<humoco_proto::SnapshotExport>(pf2_b["snapshot_export"].clone())
            .unwrap(),
        serde_json::from_value::<humoco_proto::SnapshotExport>(pf3_b["snapshot_export"].clone())
            .unwrap(),
    ];
    let t_2b = t0 + 20 + s3.state.config.lock.proposal_timelock_secs;
    let (_, i2_b) = db2_b
        .process_lock_import(
            &cfg2,
            humoco_sync_server::lock_rotation::LockImportRequest {
                anchor_id: aid,
                active_manifest: man_rev1.clone(),
                proposal: prop_2b.clone(),
                snapshots: snaps_2b.clone(),
                quorum_certificates: Vec::new(),
            },
            t_2b,
        )
        .unwrap();
    let db5b = humoco_sync_server::db::SyncDb::open(&db5b_path, "").unwrap();
    let (_, i5_b) = db5b
        .process_lock_import(
            &cfg5b,
            humoco_sync_server::lock_rotation::LockImportRequest {
                anchor_id: aid,
                active_manifest: man_rev1.clone(),
                proposal: prop_2b.clone(),
                snapshots: snaps_2b,
                quorum_certificates: Vec::new(),
            },
            t_2b,
        )
        .unwrap();
    let acks_2b: Vec<humoco_proto::ImportAck> = [i2_b, i5_b]
        .into_iter()
        .map(|v| serde_json::from_value(v["import_ack"].clone()).unwrap())
        .collect();
    let ish_2b = acks_2b[0].imported_state_hash;
    let (_, sc2_b) = db2_b
        .process_lock_commit(
            &cfg2,
            humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                anchor_id: aid,
                proposal: prop_2b.clone(),
                imported_state_hash: ish_2b,
                import_acks: acks_2b.clone(),
            },
            t_2b,
        )
        .unwrap();
    let (_, sc3_b) = s3
        .state
        .db
        .process_lock_commit(
            &s3.state.config,
            humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                anchor_id: aid,
                proposal: prop_2b.clone(),
                imported_state_hash: ish_2b,
                import_acks: acks_2b.clone(),
            },
            t_2b,
        )
        .unwrap();
    let cert_2b = humoco_proto::MigrationCert {
        anchor_id: aid,
        genesis_manifest: Some(Box::new(man_rev1.clone())),
        proposal: prop_2b,
        imported_state_hash: ish_2b,
        import_acks: acks_2b,
        commit_sigs: vec![
            serde_json::from_value(sc2_b["committee_signature"].clone()).unwrap(),
            serde_json::from_value(sc3_b["committee_signature"].clone()).unwrap(),
        ],
    };
    let (man_rev2_b, _) = cert_2b.verify_step(&aid, &man_rev1).unwrap();
    db2_b
        .process_lock_commit(
            &cfg2,
            humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                anchor_id: aid,
                new_manifest: man_rev2_b.clone(),
            },
            t_2b,
        )
        .unwrap();
    db5b.process_lock_commit(
        &cfg5b,
        humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
            anchor_id: aid,
            new_manifest: man_rev2_b.clone(),
        },
        t_2b,
    )
    .unwrap();

    // Snapshot db2_b and db5b at Rev 2B before advancing to Rev 3B so we can generate valid
    // snapshots for both prop_3b_to_s1 (?lock_import test) and prop_3b_fin (Finalize test)
    let db2_rev2b_copy = dir.path().join("s2_rev2b_copy.redb");
    let db5b_rev2b_copy = dir.path().join("s5b_rev2b_copy.redb");
    drop(db2_b);
    drop(db5b);
    std::fs::copy(&db2_fork_path, &db2_rev2b_copy).unwrap();
    std::fs::copy(&db5b_path, &db5b_rev2b_copy).unwrap();

    // 1. Test ?lock_import on S1 (at Rev 2A) with forked active_manifest = man_rev2_b -> must reject 409!
    let prop_3b_to_s1 = build_signed_proposal(
        aid,
        2,
        2,
        vec![e_s1, e_s2.clone(), e_s5b.clone()],
        Vec::new(),
        quarter,
        t_2b + 10,
        humoco_proto::ProposalInitiator::Creator,
        Some(&cmig_sk),
        Vec::new(),
    );
    let db2_b_imp = humoco_sync_server::db::SyncDb::open(&db2_rev2b_copy, "").unwrap();
    let db5b_imp = humoco_sync_server::db::SyncDb::open(&db5b_rev2b_copy, "").unwrap();
    let (_, pf2_imp) = db2_b_imp
        .process_lock_freeze(
            &cfg2,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: prop_3b_to_s1.clone(),
                current_manifest: None,
            },
            t_2b + 10,
        )
        .unwrap();
    let (_, pf5_imp) = db5b_imp
        .process_lock_freeze(
            &cfg5b,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: prop_3b_to_s1.clone(),
                current_manifest: None,
            },
            t_2b + 10,
        )
        .unwrap();
    let snaps_3b_imp = vec![
        serde_json::from_value::<humoco_proto::SnapshotExport>(pf2_imp["snapshot_export"].clone())
            .unwrap(),
        serde_json::from_value::<humoco_proto::SnapshotExport>(pf5_imp["snapshot_export"].clone())
            .unwrap(),
    ];
    let imp_fork_err = s1
        .state
        .db
        .process_lock_import(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockImportRequest {
                anchor_id: aid,
                active_manifest: man_rev2_b.clone(),
                proposal: prop_3b_to_s1,
                snapshots: snaps_3b_imp,
                quorum_certificates: Vec::new(),
            },
            t_2b + 10,
        )
        .unwrap_err();
    assert!(
        matches!(
            imp_fork_err,
            humoco_sync_server::db::DbError::Http { status: 409, .. }
        ),
        "?lock_import with forked active_manifest (Rev 2B != Rev 2A) must fail with 409, got {imp_fork_err:?}"
    );

    // 2. Test Finalize on S1 (at Rev 2A) with forked Rev 3B -> must reject 409!
    let db2_b = humoco_sync_server::db::SyncDb::open(&db2_fork_path, "").unwrap();
    let db5b = humoco_sync_server::db::SyncDb::open(&db5b_path, "").unwrap();
    let prop_3b_fin = build_signed_proposal(
        aid,
        2,
        2,
        vec![e_s2, e_s3, e_s5b],
        Vec::new(),
        quarter,
        t_2b + 20,
        humoco_proto::ProposalInitiator::Creator,
        Some(&cmig_sk),
        Vec::new(),
    );
    let (_, pf2_3b) = db2_b
        .process_lock_freeze(
            &cfg2,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: prop_3b_fin.clone(),
                current_manifest: None,
            },
            t_2b + 20,
        )
        .unwrap();
    let (_, pf5_3b) = db5b
        .process_lock_freeze(
            &cfg5b,
            humoco_sync_server::lock_rotation::LockFreezeRequest::Propose {
                proposal: prop_3b_fin.clone(),
                current_manifest: None,
            },
            t_2b + 20,
        )
        .unwrap();
    let snaps_3b = vec![
        serde_json::from_value::<humoco_proto::SnapshotExport>(pf2_3b["snapshot_export"].clone())
            .unwrap(),
        serde_json::from_value::<humoco_proto::SnapshotExport>(pf5_3b["snapshot_export"].clone())
            .unwrap(),
    ];
    let t_3b = t_2b + 20 + cfg5b.lock.proposal_timelock_secs;
    let (_, i2_3b) = db2_b
        .process_lock_import(
            &cfg2,
            humoco_sync_server::lock_rotation::LockImportRequest {
                anchor_id: aid,
                active_manifest: man_rev2_b.clone(),
                proposal: prop_3b_fin.clone(),
                snapshots: snaps_3b.clone(),
                quorum_certificates: Vec::new(),
            },
            t_3b,
        )
        .unwrap();
    let (_, i3_3b) = s3
        .state
        .db
        .process_lock_import(
            &s3.state.config,
            humoco_sync_server::lock_rotation::LockImportRequest {
                anchor_id: aid,
                active_manifest: man_rev2_b.clone(),
                proposal: prop_3b_fin.clone(),
                snapshots: snaps_3b.clone(),
                quorum_certificates: Vec::new(),
            },
            t_3b,
        )
        .unwrap();
    let (_, i5_3b) = db5b
        .process_lock_import(
            &cfg5b,
            humoco_sync_server::lock_rotation::LockImportRequest {
                anchor_id: aid,
                active_manifest: man_rev2_b.clone(),
                proposal: prop_3b_fin.clone(),
                snapshots: snaps_3b,
                quorum_certificates: Vec::new(),
            },
            t_3b,
        )
        .unwrap();
    let acks_3b: Vec<humoco_proto::ImportAck> = [i2_3b, i3_3b, i5_3b]
        .into_iter()
        .map(|v| serde_json::from_value(v["import_ack"].clone()).unwrap())
        .collect();
    let ish_3b = acks_3b[0].imported_state_hash;
    let (_, sc2_3b) = db2_b
        .process_lock_commit(
            &cfg2,
            humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                anchor_id: aid,
                proposal: prop_3b_fin.clone(),
                imported_state_hash: ish_3b,
                import_acks: acks_3b.clone(),
            },
            t_3b,
        )
        .unwrap();
    let (_, sc5_3b) = db5b
        .process_lock_commit(
            &cfg5b,
            humoco_sync_server::lock_rotation::LockCommitRequest::SignCommit {
                anchor_id: aid,
                proposal: prop_3b_fin.clone(),
                imported_state_hash: ish_3b,
                import_acks: acks_3b.clone(),
            },
            t_3b,
        )
        .unwrap();
    let cert_3b = humoco_proto::MigrationCert {
        anchor_id: aid,
        genesis_manifest: None,
        proposal: prop_3b_fin,
        imported_state_hash: ish_3b,
        import_acks: acks_3b,
        commit_sigs: vec![
            serde_json::from_value(sc2_3b["committee_signature"].clone()).unwrap(),
            serde_json::from_value(sc5_3b["committee_signature"].clone()).unwrap(),
        ],
    };
    let (man_rev3_b, _) = cert_3b.verify_step(&aid, &man_rev2_b).unwrap();

    let fin_fork_err = s1
        .state
        .db
        .process_lock_commit(
            &s1.state.config,
            humoco_sync_server::lock_rotation::LockCommitRequest::Finalize {
                anchor_id: aid,
                new_manifest: man_rev3_b,
            },
            t_3b,
        )
        .unwrap_err();
    assert!(
        matches!(
            fin_fork_err,
            humoco_sync_server::db::DbError::Http { status: 409, .. }
        ),
        "Finalize with forked history chain (Rev 3B != Rev 2A prefix) must fail with 409, got {fin_fork_err:?}"
    );
    let stored_man: humoco_proto::AnchorManifest = serde_json::from_slice(
        &s1.state
            .db
            .get_static_anchor_manifest(&hex::encode(aid))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(stored_man, man_rev2_a);
}

#[tokio::test]
async fn test_s03_suspended_media_ttl_enforcement() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let (_free_sk, free_pk) = gen_keypair();
    let (_pro_sk, pro_pk) = gen_keypair();
    let (_observer_sk, observer_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.mode.enable_public_registration = true;
    cfg.mode.registration_gates = vec!["open".to_string(), "code".to_string()];
    cfg.media.ttl_days = 90; // global fallback differs from free (60d) and pro (365d)
    let srv = TestServer::start(cfg).await;
    let db = &srv.state.db;
    let base_cfg = &srv.state.config;
    let now = unix_now();

    db.put_admin_members(base_cfg, "card", std::slice::from_ref(&observer_pk), now)
        .unwrap();
    db.register_or_upgrade_user(base_cfg, &free_pk, "free", None, None, "open", now)
        .unwrap();
    db.register_or_upgrade_user(base_cfg, &pro_pk, "pro", None, Some(400), "code", now)
        .unwrap();

    // Free media uploaded 65 days ago (> 60d free TTL, < 90d global fallback TTL)
    let m_free = sha256_hex(b"suspended-free-media-65d");
    let free_ts = now.saturating_sub(65 * 86_400);
    db.put_media(
        base_cfg,
        &free_pk,
        &m_free,
        b"free-expired-payload",
        &ConditionalPrecondition::None,
        free_ts,
    )
    .unwrap();

    // Pro media uploaded 100 days ago (> 90d global fallback TTL, < 365d pro TTL)
    let m_pro = sha256_hex(b"suspended-pro-media-100d");
    let pro_ts = now.saturating_sub(100 * 86_400);
    db.put_media(
        base_cfg,
        &pro_pk,
        &m_pro,
        b"pro-active-payload",
        &ConditionalPrecondition::None,
        pro_ts,
    )
    .unwrap();

    // Suspend both users
    db.set_user_status(
        &free_pk,
        humoco_sync_server::db::AccountStatus::Suspended,
        now,
    )
    .unwrap();
    db.set_user_status(
        &pro_pk,
        humoco_sync_server::db::AccountStatus::Suspended,
        now,
    )
    .unwrap();

    // 1. Suspended free user's 65d-old media (> 60d free TTL) must remain expired (None), NOT resurrected by 90d global TTL
    assert!(
        db.get_media_blob(base_cfg, &m_free, now).unwrap().is_none(),
        "get_media_blob must enforce free media TTL (60d) on Suspended accounts instead of 90d global fallback"
    );

    // 2. Suspended pro user's 100d-old media (< 365d pro TTL) must remain intact (Some), NOT prematurely treated as expired by 90d global TTL
    assert!(
        db.get_media_blob(base_cfg, &m_pro, now).unwrap().is_some(),
        "get_media_blob must preserve pro media TTL (365d) when owner is Suspended"
    );

    // 3. head_capability must apply resolved profile media TTL for Suspended accounts (both owner stats and X-Media-Id lookup)
    let cap_free = db
        .head_capability(base_cfg, &free_pk, Some("media"), None, None, now)
        .unwrap();
    assert_eq!(
        cap_free.media_used_count, 0,
        "head_capability must exclude TTL-expired media for Suspended free user"
    );
    assert_eq!(cap_free.media_used_bytes, 0);

    let cap_obs_free = db
        .head_capability(
            base_cfg,
            &observer_pk,
            Some("media"),
            None,
            Some(&m_free),
            now,
        )
        .unwrap();
    assert_eq!(
        cap_obs_free.slot_occupied,
        Some(false),
        "head_capability X-Media-Id must report expired Suspended free media as unoccupied"
    );

    let cap_obs_pro = db
        .head_capability(
            base_cfg,
            &observer_pk,
            Some("media"),
            None,
            Some(&m_pro),
            now,
        )
        .unwrap();
    assert_eq!(
        cap_obs_pro.slot_occupied,
        Some(true),
        "head_capability X-Media-Id must report live Suspended pro media as occupied"
    );

    // 4. run_maintenance must prune Suspended free expired media (65d > 60d) while retaining Suspended pro live media (100d < 365d)
    db.run_maintenance(base_cfg, now).unwrap();
    assert_eq!(
        db.admin_status(base_cfg, now).unwrap().slot_count,
        1,
        "run_maintenance must prune Suspended free expired media and keep Suspended pro media"
    );
    assert!(db.get_media_blob(base_cfg, &m_pro, now).unwrap().is_some());
}

#[tokio::test]
async fn test_s03_admin_config_overrides_applied_across_all_db_paths() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let (_dual_sk, dual_pk) = gen_keypair();
    let (_reg_friends_sk, reg_friends_pk) = gen_keypair();
    let (_dual2_sk, dual2_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.mode.enable_public_registration = true;
    cfg.mode.registration_gates = vec!["open".to_string(), "code".to_string()];
    cfg.profiles.insert(
        "starter_backup".to_string(),
        humoco_sync_server::config::ProfileConfig {
            display_name: "Starter Backup".to_string(),
            max_total_bytes: 15 * 1024 * 1024, // 15 MiB (< default 25 MiB friends, > 10 MiB overridden friends)
            is_free_pool: false,
            store_contact_email: false,
            channels: std::collections::BTreeMap::from([
                (
                    "card".to_string(),
                    humoco_sync_server::config::ChannelQuotaConfig {
                        max_bytes: 524_288,
                        ttl_days: 90,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "backup".to_string(),
                    humoco_sync_server::config::ChannelQuotaConfig {
                        max_bytes: 524_288,
                        ttl_days: 90,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
            ]),
        },
    );

    let srv = TestServer::start(cfg).await;
    let db = &srv.state.db;
    let base_cfg = &srv.state.config;
    let now = unix_now();

    // Dual member: admin_app("card") + registered("pro" 100 MiB, card TTL 365d, media TTL 365d)
    db.put_admin_members(base_cfg, "card", std::slice::from_ref(&dual_pk), now)
        .unwrap();
    db.register_or_upgrade_user(base_cfg, &dual_pk, "pro", None, Some(500), "code", now)
        .unwrap();

    // Override admin_app_profile ("friends") to 200 MiB (> pro's 100 MiB).
    // Now effective chosen_prof for dual_pk is "friends" (card TTL 0 = infinite, media TTL 90d).
    db.set_admin_config_overrides(&humoco_sync_server::db::AdminConfigOverrides {
        max_total_storage_mb: 2048,
        max_members: 300,
        max_user_storage_mb: 200,
    })
    .unwrap();

    let card_old_ts = now.saturating_sub(400 * 86_400); // > 365d pro TTL, valid under friends TTL 0
    db.put_slot(
        base_cfg,
        &dual_pk,
        "card",
        None,
        b"dual-infinite-friends-card",
        &ConditionalPrecondition::None,
        card_old_ts,
    )
    .unwrap();

    let m_dual = sha256_hex(b"dual-friends-media-120d");
    let media_old_ts = now.saturating_sub(120 * 86_400); // > 90d friends TTL, < 365d pro TTL
    db.put_media(
        base_cfg,
        &dual_pk,
        &m_dual,
        b"dual-expired-friends-media",
        &ConditionalPrecondition::None,
        media_old_ts,
    )
    .unwrap();

    // 1. head_capability, get_slot_blob, build_admin_index, get_media_blob must all agree on "friends"
    let cap = db
        .head_capability(base_cfg, &dual_pk, Some("card"), None, None, now)
        .unwrap();
    assert_eq!(cap.slot_occupied, Some(true));
    assert!(
        db.get_slot_blob(base_cfg, "card", &dual_pk, now)
            .unwrap()
            .is_some(),
        "get_slot_blob must apply admin_config overrides so friends (TTL 0) beats pro (365d)"
    );
    let (idx_entries, _) = db.build_admin_index(base_cfg).unwrap();
    assert_eq!(
        idx_entries.len(),
        1,
        "build_admin_index must apply admin_config overrides so friends (TTL 0) stays in index.json"
    );
    assert!(
        db.get_media_blob(base_cfg, &m_dual, now).unwrap().is_none(),
        "get_media_blob must apply admin_config overrides so friends media TTL (90d) expires 120d blob"
    );

    // 2. run_maintenance must prune the 120d media (> 90d friends TTL) while preserving the 400d card slot (friends TTL 0)
    db.run_maintenance(base_cfg, now).unwrap();
    assert!(
        db.get_slot_blob(base_cfg, "card", &dual_pk, now)
            .unwrap()
            .is_some(),
        "run_maintenance must preserve friends infinite-TTL card slot under admin_config override"
    );
    assert_eq!(
        db.admin_status(base_cfg, now).unwrap().slot_count,
        1,
        "run_maintenance must prune expired friends media while keeping friends card slot"
    );

    // 3. redeem_code_for_pubkey must compare against effective_config (200 MiB friends > 100 MiB pro => 409)
    db.register_or_upgrade_user(
        base_cfg,
        &reg_friends_pk,
        "friends",
        None,
        Some(30),
        "admin",
        now,
    )
    .unwrap();
    let pro_codes = db
        .create_redeem_codes(base_cfg, 1, "pro", Some(30), 1, None, None, None, now)
        .unwrap();
    let err = db
        .redeem_code_for_pubkey(base_cfg, &reg_friends_pk, &pro_codes[0].code, now)
        .unwrap_err();
    assert!(
        matches!(err, humoco_sync_server::db::DbError::Http { status: 409, .. }),
        "redeem_code_for_pubkey must block downgrade from 200 MiB effective friends to 100 MiB pro, got {err:?}"
    );

    // 4. delete_slot must reflect effective_config when admin_config lowers friends below starter_backup (15 MiB)
    let mut cfg2 = (**base_cfg).clone();
    if let Some(fp) = cfg2.profiles.get_mut("friends") {
        fp.channels.remove("backup");
    }
    db.put_admin_members(&cfg2, "card", std::slice::from_ref(&dual2_pk), now)
        .unwrap();
    db.register_or_upgrade_user(
        &cfg2,
        &dual2_pk,
        "starter_backup",
        None,
        Some(60),
        "code",
        now,
    )
    .unwrap();
    db.set_admin_config_overrides(&humoco_sync_server::db::AdminConfigOverrides {
        max_total_storage_mb: 2048,
        max_members: 300,
        max_user_storage_mb: 10, // lowers friends to 10 MiB < starter_backup 15 MiB
    })
    .unwrap();
    assert!(
        db.delete_slot(&cfg2, &dual2_pk, "backup", None, now).is_ok(),
        "delete_slot must honor admin_config overrides where starter_backup (15 MiB > 10 MiB friends) grants backup channel"
    );
}

#[tokio::test]
async fn test_s04_static_lock_non_ascii_quarter_no_panic() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let cfg = base_hybrid_config(&admin_pk);
    let srv = TestServer::start(cfg).await;

    let dummy_hex = "00".repeat(32);
    // "aäää" has byte length 7 (1 + 2 + 2 + 2), placing byte offsets 4 and 6 inside multi-byte UTF-8 chars.
    let get_res = srv
        .client
        .get(format!(
            "{}/humoco_sync_data/locks/a%C3%A4%C3%A4%C3%A4/{}/{}.lock",
            srv.base_url, dummy_hex, dummy_hex
        ))
        .send()
        .await
        .expect("GET with non-ASCII 7-byte quarter must return HTTP 404 without panicking");
    assert_eq!(get_res.status().as_u16(), 404);

    let head_res = srv
        .client
        .head(format!(
            "{}/humoco_sync_data/locks/%C3%A4%C3%A4%C3%A4a/{}/1.lock",
            srv.base_url, dummy_hex
        ))
        .send()
        .await
        .expect("HEAD with non-ASCII 7-byte quarter must return HTTP 404 without panicking");
    assert_eq!(head_res.status().as_u16(), 404);
}

fn verify_selftest_report_sig(report: &serde_json::Value) {
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

#[tokio::test]
async fn test_s09_f2_lock_channel_cryptographic_and_adversarial_parity() {
    let (admin_sk, admin_pk) = gen_keypair();
    let (outsider_sk, outsider_pk) = gen_keypair();
    let (other_sk, other_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.max_inodes = 5;
    cfg.lock.allow_pow_tickets = false;
    cfg.lock.pow_base_bits = 8;
    let srv = TestServer::start(cfg).await;

    // 1. SelftestReport signature parity (GET + admin POST + non-admin 403 + wrong method 405)
    let st_get: serde_json::Value = srv
        .client
        .get(format!("{}/sync.php?lock_selftest", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(st_get["all_passed"], true);
    verify_selftest_report_sig(&st_get);
    let lock_pub_hex = st_get["lock_pub"].as_str().unwrap().to_string();
    let lock_pub_bytes: [u8; 32] = hex::decode(&lock_pub_hex).unwrap().try_into().unwrap();

    let ts_st = unix_now() as i64;
    let nonce_st = random_hex(16);
    let st_msg = humoco_sync_server::crypto::format_admin_post_lock_selftest_message(
        ts_st,
        &nonce_st,
        humoco_sync_server::crypto::EMPTY_SHA256_HEX,
    );
    let st_nonadmin = srv
        .client
        .post(format!("{}/sync.php?lock_selftest", srv.base_url))
        .header("X-Drop-Pubkey", &outsider_pk)
        .header("X-Drop-Timestamp", ts_st.to_string())
        .header("X-Drop-Nonce", &nonce_st)
        .header(
            "X-Drop-Signature",
            hex::encode(outsider_sk.sign(st_msg.as_bytes()).to_bytes()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(st_nonadmin.status().as_u16(), 403);

    let st_del = srv
        .client
        .delete(format!("{}/sync.php?lock_selftest", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(st_del.status().as_u16(), 405);

    let nonce_st2 = random_hex(16);
    let st_msg2 = humoco_sync_server::crypto::format_admin_post_lock_selftest_message(
        ts_st,
        &nonce_st2,
        humoco_sync_server::crypto::EMPTY_SHA256_HEX,
    );
    let st_post_resp = srv
        .client
        .post(format!("{}/sync.php?lock_selftest", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Drop-Timestamp", ts_st.to_string())
        .header("X-Drop-Nonce", &nonce_st2)
        .header(
            "X-Drop-Signature",
            hex::encode(admin_sk.sign(st_msg2.as_bytes()).to_bytes()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(st_post_resp.status().as_u16(), 200);
    let st_post: serde_json::Value = st_post_resp.json().await.unwrap();
    verify_selftest_report_sig(&st_post);

    // 2. PUT ?lock_delegate error codes (403 mismatched admin_pub, 400 bad url/uppercase sig, 401 wrong sig) & GET ?info persistence
    let issued_at = unix_now();
    let del_write = format!("{}/sync.php", srv.base_url);
    let del_read = format!("{}/humoco_sync_data", srv.base_url);
    let send_delegate = |body_bytes: Vec<u8>| {
        let srv = &srv;
        let admin_sk = &admin_sk;
        let admin_pk = &admin_pk;
        async move {
            let ts = unix_now() as i64;
            let nonce = random_hex(16);
            let msg = humoco_sync_server::crypto::format_admin_put_lock_delegate_message(
                ts,
                &nonce,
                &sha256_hex(&body_bytes),
            );
            srv.client
                .put(format!("{}/sync.php?lock_delegate", srv.base_url))
                .header("X-Drop-Pubkey", admin_pk)
                .header("X-Drop-Timestamp", ts.to_string())
                .header("X-Drop-Nonce", &nonce)
                .header(
                    "X-Drop-Signature",
                    hex::encode(admin_sk.sign(msg.as_bytes()).to_bytes()),
                )
                .body(body_bytes)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    let bad_admin_msg = humoco_sync_server::crypto::format_lock_delegate_signature_message(
        &other_pk,
        &lock_pub_hex,
        &del_write,
        &del_read,
        issued_at,
    );
    assert_eq!(
        send_delegate(
            serde_json::to_vec(&serde_json::json!({
                "admin_pub": other_pk,
                "lock_pub": lock_pub_hex,
                "write_url": del_write,
                "read_url": del_read,
                "issued_at": issued_at,
                "sig": hex::encode(other_sk.sign(bad_admin_msg.as_bytes()).to_bytes()),
            }))
            .unwrap()
        )
        .await,
        403
    );

    let ok_del_msg = humoco_sync_server::crypto::format_lock_delegate_signature_message(
        &admin_pk,
        &lock_pub_hex,
        &del_write,
        &del_read,
        issued_at,
    );
    let valid_del_sig = hex::encode(admin_sk.sign(ok_del_msg.as_bytes()).to_bytes());
    assert_eq!(
        send_delegate(
            serde_json::to_vec(&serde_json::json!({
                "admin_pub": admin_pk,
                "lock_pub": lock_pub_hex,
                "write_url": del_write,
                "read_url": del_read,
                "issued_at": issued_at,
                "sig": valid_del_sig.to_ascii_uppercase(),
            }))
            .unwrap()
        )
        .await,
        400
    );
    assert_eq!(
        send_delegate(
            serde_json::to_vec(&serde_json::json!({
                "admin_pub": admin_pk,
                "lock_pub": lock_pub_hex,
                "write_url": del_write,
                "read_url": "ftp://invalid.example/data",
                "issued_at": issued_at,
                "sig": valid_del_sig,
            }))
            .unwrap()
        )
        .await,
        400
    );
    assert_eq!(
        send_delegate(
            serde_json::to_vec(&serde_json::json!({
                "admin_pub": admin_pk,
                "lock_pub": lock_pub_hex,
                "write_url": del_write,
                "read_url": del_read,
                "issued_at": issued_at,
                "sig": "ab".repeat(64),
            }))
            .unwrap()
        )
        .await,
        401
    );
    assert_eq!(
        send_delegate(
            serde_json::to_vec(&serde_json::json!({
                "admin_pub": admin_pk,
                "lock_pub": lock_pub_hex,
                "write_url": del_write,
                "read_url": del_read,
                "issued_at": issued_at,
                "sig": valid_del_sig,
            }))
            .unwrap()
        )
        .await,
        200
    );

    let info_del: serde_json::Value = srv
        .client
        .get(format!("{}/sync.php?info", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info_del["lock"]["delegation"]["write_url"], del_write);
    assert_eq!(info_del["lock"]["delegation"]["read_url"], del_read);
    assert_eq!(info_del["lock"]["delegation"]["sig"], valid_del_sig);
    assert_eq!(info_del["lock"]["inode_warning"], false);

    // 3. Probe malformed nonce (400), GET ?lock (405), GET ?lock_ticket (405), outsider non-PoW ?lock_ticket (403)
    assert_eq!(
        srv.client
            .post(format!("{}/sync.php?lock", srv.base_url))
            .json(&serde_json::json!({ "probe": true, "client_nonce": "00".repeat(32) }))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        400
    );
    assert_eq!(
        srv.client
            .get(format!("{}/sync.php?lock", srv.base_url))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        405
    );
    assert_eq!(
        srv.client
            .get(format!("{}/sync.php?lock_ticket", srv.base_url))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        405
    );

    let quarter = humoco_proto::encode_quarter(2031, 2).unwrap();
    let (creator_mig_sk, _creator_mig_pk_hex) = gen_keypair();
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let manifest = build_single_server_manifest(
        hex::decode(&admin_pk).unwrap().try_into().unwrap(),
        lock_pub_bytes,
        creator_mig_pub,
        quarter,
    );
    let anchor_id = manifest.rev1_anchor_id().unwrap();
    let bucket = humoco_proto::derive_bucket(&anchor_id, &lock_pub_bytes);

    let (outsider_code, _) = fetch_ticket_signed(&srv, &outsider_sk, anchor_id, quarter).await;
    assert_eq!(outsider_code, 403);

    // 4. Valid GenesisTicket + verify GenesisTicket::verify()
    let (tkt_code, tkt_val) = fetch_ticket_signed(&srv, &admin_sk, anchor_id, quarter).await;
    assert_eq!(tkt_code, 200);
    let ticket: humoco_proto::GenesisTicket =
        serde_json::from_value(tkt_val["ticket"].clone()).unwrap();
    assert!(
        ticket.verify(),
        "GenesisTicket returned over HTTP must pass Ed25519 + retention verification"
    );
    assert_eq!(ticket.lock_pub, lock_pub_bytes);

    // 5. Prepare keys for root (depth=0) -> split outputs (branch=0 receiver, branch=1 change) & 422 adversarial checks
    let (s0_sk, _) = gen_keypair();
    let (recv1_sk, _) = gen_keypair();
    let (chg1_sk, _) = gen_keypair();
    let (wrong_mig_sk, _) = gen_keypair();

    let recv1_hash = humoco_proto::hash_pubkey_sha3(recv1_sk.verifying_key().as_bytes());
    let chg1_hash = humoco_proto::hash_pubkey_sha3(chg1_sk.verifying_key().as_bytes());
    let sink_hash = [0x99u8; 32];

    let root_entry = sign_lock_entry_helper(
        anchor_id,
        [0x10; 32],
        [0u8; 32],
        0,
        0,
        [0xA0; 32],
        &s0_sk,
        recv1_hash,
        Some(chg1_hash),
        Some(&creator_mig_sk),
        8,
    );

    // 5a. Non-list entries JSON object -> 400
    let assoc_resp = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "bucket": hex::encode(bucket),
            "recipient_nonce": "11".repeat(32),
            "entries": { "a": root_entry.to_wire_hex().unwrap() },
            "manifest": manifest,
            "genesis_ticket": ticket,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(assoc_resp.status().as_u16(), 400);

    // 5b. 422 PoW fail, 422 causal_sig fail, 422 root_mig_sig fail, 422 missing parent at depth=1
    let mut bad_pow = root_entry.clone();
    for candidate in 0u64..10_000 {
        let h =
            humoco_proto::compute_lock_pow_hash(&bad_pow.slot, &bad_pow.child_lock, 0, candidate);
        if !humoco_proto::check_pow_difficulty(&h, 8) {
            bad_pow.pow_nonce = candidate;
            break;
        }
    }
    let mut bad_causal = root_entry.clone();
    bad_causal.causal_sig[0] ^= 0xff;
    let bad_root_sig = sign_lock_entry_helper(
        anchor_id,
        [0x11; 32],
        [0u8; 32],
        0,
        0,
        [0xA1; 32],
        &s0_sk,
        recv1_hash,
        None,
        Some(&wrong_mig_sk),
        8,
    );
    let missing_parent = sign_lock_entry_helper(
        anchor_id, [0x12; 32], [0x77; 32], 0, 1, [0xA2; 32], &recv1_sk, sink_hash, None, None, 8,
    );

    for bad_e in [&bad_pow, &bad_causal, &bad_root_sig, &missing_parent] {
        let r = srv
            .client
            .post(format!("{}/sync.php?lock", srv.base_url))
            .json(&serde_json::json!({
                "anchor_id": hex::encode(anchor_id),
                "bucket": hex::encode(bucket),
                "recipient_nonce": "12".repeat(32),
                "entries": [bad_e.to_wire_hex().unwrap()],
                "manifest": manifest,
                "genesis_ticket": ticket,
                "known_head_receipt": serde_json::Value::Null,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 422);
    }

    // 6. Commit root (write_seq=1) + child on output_branch=0 (write_seq=2) + child on output_branch=1 (write_seq=3)
    // First batch: root + branch0 (2 inodes = 40%)
    let child_b0 = sign_lock_entry_helper(
        anchor_id,
        [0x20; 32],
        root_entry.slot,
        0,
        1,
        [0xB0; 32],
        &recv1_sk,
        sink_hash,
        None, // No change output!
        None,
        8,
    );
    let batch1_resp = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "bucket": hex::encode(bucket),
            "recipient_nonce": "21".repeat(32),
            "entries": [root_entry.to_wire_hex().unwrap(), child_b0.to_wire_hex().unwrap()],
            "manifest": manifest,
            "genesis_ticket": ticket,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(batch1_resp.status().as_u16(), 200);
    let b1_json: serde_json::Value = batch1_resp.json().await.unwrap();
    let r1: Vec<humoco_proto::LockReceipt> =
        serde_json::from_value(b1_json["receipts"].clone()).unwrap();
    assert_eq!(r1.len(), 2);
    assert!(r1[0].verify_signature() && r1[1].verify_signature());
    let head0 = humoco_proto::compute_bucket_init_head(&bucket, quarter);
    let head1 = humoco_proto::compute_bucket_step_head(
        &head0,
        1,
        &root_entry.slot,
        &root_entry.entry_hash().unwrap(),
    );
    let head2 = humoco_proto::compute_bucket_step_head(
        &head1,
        2,
        &child_b0.slot,
        &child_b0.entry_hash().unwrap(),
    );
    assert_eq!(r1[0].write_seq, 1);
    assert_eq!(r1[0].bucket_head, head1);
    assert_eq!(r1[1].write_seq, 2);
    assert_eq!(r1[1].bucket_head, head2);

    // Attempt output_branch=1 on child_b0 which has change_pubkey_hash=None -> 422
    let illegal_change_child = sign_lock_entry_helper(
        anchor_id,
        [0x21; 32],
        child_b0.slot,
        1,
        2,
        [0xB1; 32],
        &chg1_sk,
        sink_hash,
        None,
        None,
        8,
    );
    assert_eq!(
        srv.client
            .post(format!("{}/sync.php?lock", srv.base_url))
            .json(&serde_json::json!({
                "anchor_id": hex::encode(anchor_id),
                "bucket": hex::encode(bucket),
                "recipient_nonce": "22".repeat(32),
                "entries": [illegal_change_child.to_wire_hex().unwrap()],
                "manifest": serde_json::Value::Null,
                "genesis_ticket": serde_json::Value::Null,
                "known_head_receipt": r1[1],
            }))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        422
    );

    // Spend valid output_branch=1 (change output) of root_entry -> 3/5 inodes = 60% -> inode_warning still false
    let child_b1 = sign_lock_entry_helper(
        anchor_id,
        [0x30; 32],
        root_entry.slot,
        1,
        1,
        [0xC0; 32],
        &chg1_sk,
        recv1_hash,
        None,
        None,
        8,
    );
    let b2_resp = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "bucket": hex::encode(bucket),
            "recipient_nonce": "23".repeat(32),
            "entries": [child_b1.to_wire_hex().unwrap()],
            "manifest": serde_json::Value::Null,
            "genesis_ticket": serde_json::Value::Null,
            "known_head_receipt": r1[1],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(b2_resp.status().as_u16(), 200);
    let b2_json: serde_json::Value = b2_resp.json().await.unwrap();
    let r2: Vec<humoco_proto::LockReceipt> =
        serde_json::from_value(b2_json["receipts"].clone()).unwrap();
    assert_eq!(r2.len(), 1);
    assert!(r2[0].verify_signature());
    let head3 = humoco_proto::compute_bucket_step_head(
        &head2,
        3,
        &child_b1.slot,
        &child_b1.entry_hash().unwrap(),
    );
    assert_eq!(r2[0].write_seq, 3);
    assert_eq!(r2[0].bucket_head, head3);

    let info_60: serde_json::Value = srv
        .client
        .get(format!("{}/sync.php?info", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info_60["lock"]["used_inodes"], 3);
    assert_eq!(info_60["lock"]["inode_warning"], false);

    // 7. 4th slot reaches 4/5 = 80% -> inode_warning becomes true! Also verify static .lock 605B + ETag + 304 + 405
    let grand_child = sign_lock_entry_helper(
        anchor_id,
        [0x40; 32],
        child_b1.slot,
        0,
        2,
        [0xD0; 32],
        &recv1_sk,
        sink_hash,
        None,
        None,
        8,
    );
    let b3_resp = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "bucket": hex::encode(bucket),
            "recipient_nonce": "24".repeat(32),
            "entries": [grand_child.to_wire_hex().unwrap()],
            "manifest": serde_json::Value::Null,
            "genesis_ticket": serde_json::Value::Null,
            "known_head_receipt": r2[0],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(b3_resp.status().as_u16(), 200);

    let info_80: serde_json::Value = srv
        .client
        .get(format!("{}/sync.php?info", srv.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info_80["lock"]["used_inodes"], 4);
    assert_eq!(info_80["lock"]["inode_warning"], true);

    let q_str = humoco_proto::format_quarter(quarter).unwrap();
    let file_id = humoco_proto::derive_slot_file_id(&child_b1.slot, &lock_pub_bytes);
    let lock_url = format!(
        "{}/humoco_sync_data/locks/{}/{}/{}.lock",
        srv.base_url,
        q_str,
        hex::encode(bucket),
        hex::encode(file_id)
    );
    let get_static = srv.client.get(&lock_url).send().await.unwrap();
    assert_eq!(get_static.status().as_u16(), 200);
    let etag = get_static
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let cc = get_static
        .headers()
        .get("cache-control")
        .unwrap()
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    assert!(cc.contains("immutable"), "static .lock Cache-Control: {cc}");
    let wire_bytes = get_static.bytes().await.unwrap();
    let expected_wire = hex::decode(child_b1.to_wire_hex().unwrap()).unwrap();
    assert_eq!(wire_bytes.as_ref(), expected_wire.as_slice());

    let static_304 = srv
        .client
        .get(&lock_url)
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(static_304.status().as_u16(), 304);

    let static_405 = srv.client.post(&lock_url).send().await.unwrap();
    assert_eq!(static_405.status().as_u16(), 405);
}

#[tokio::test]
async fn test_s09_f3_cold_self_frozen_pre_freeze_no_leak_and_schema_400_parity() {
    let (admin_sk, _admin_pk, cold2) = start_lock_test_server(true, None).await;
    let admin_pub = admin_sk.verifying_key().to_bytes();
    let creator_mig_sk = SigningKey::from_bytes(&[171u8; 32]);
    let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let now = unix_now();
    let g_sk = SigningKey::from_bytes(&[172u8; 32]);
    let cold2_pub = cold2.state.db.lock_pubkey_bytes().unwrap();
    let cold2_man = build_single_server_manifest(admin_pub, cold2_pub, creator_mig_pub, quarter);
    let cold2_aid = cold2_man.rev1_anchor_id().unwrap();
    let cold2_ahex = hex::encode(cold2_aid);
    let cold2_bkt = humoco_proto::derive_bucket(&cold2_aid, &cold2_pub);
    let cold2_tkt = issue_pow_ticket_db(&cold2, cold2_aid, quarter, now);
    let cold2_e0 = sign_lock_entry_helper(
        cold2_aid,
        [0xF1; 32],
        [0u8; 32],
        0,
        0,
        [0xF2; 32],
        &g_sk,
        [0xF3; 32],
        None,
        Some(&creator_mig_sk),
        8,
    );
    let (_, cold2_ok) = cold2
        .state
        .db
        .process_lock_batch(
            &cold2.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: cold2_aid,
                bucket: cold2_bkt,
                recipient_nonce: [0xF4; 32],
                entries: vec![cold2_e0.to_wire_hex().unwrap()],
                manifest: Some(cold2_man.clone()),
                genesis_ticket: Some(cold2_tkt),
                known_head_receipt: None,
            },
            now,
        )
        .unwrap();
    let _cold2_rcpt: humoco_proto::LockReceipt =
        serde_json::from_value(cold2_ok["receipts"][0].clone()).unwrap();
    let past_q = humoco_proto::encode_quarter(2025, 1).unwrap();
    let past_man = build_single_server_manifest(admin_pub, cold2_pub, creator_mig_pub, past_q);
    let past_aid = past_man.rev1_anchor_id().unwrap();
    let past_ahex = hex::encode(past_aid);
    let past_bkt = humoco_proto::derive_bucket(&past_aid, &cold2_pub);
    let past_tkt = issue_pow_ticket_db(&cold2, past_aid, past_q, now);
    let past_e0 = sign_lock_entry_helper(
        past_aid,
        [0xA1; 32],
        [0u8; 32],
        0,
        0,
        [0xA2; 32],
        &g_sk,
        [0xA3; 32],
        None,
        Some(&creator_mig_sk),
        8,
    );
    let (_, past_ok) = cold2
        .state
        .db
        .process_lock_batch(
            &cold2.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: past_aid,
                bucket: past_bkt,
                recipient_nonce: [0xA4; 32],
                entries: vec![past_e0.to_wire_hex().unwrap()],
                manifest: Some(past_man.clone()),
                genesis_ticket: Some(past_tkt),
                known_head_receipt: None,
            },
            now,
        )
        .unwrap();
    let past_rcpt: humoco_proto::LockReceipt =
        serde_json::from_value(past_ok["receipts"][0].clone()).unwrap();
    // GC removes past_aid (2025-Q1 purged at `now`), wiping bucket + rotation + anchor!
    let (purged_b, _) = cold2.state.db.run_lock_gc(now).unwrap();
    assert_eq!(purged_b, 1);
    assert!(cold2
        .state
        .db
        .get_static_anchor_manifest(&past_ahex)
        .unwrap()
        .is_none());

    // Replay past_rcpt -> creates SelfFrozen tombstone without rotation/anchor metadata
    let (rb_code, rb_val) = cold2
        .state
        .db
        .process_lock_batch(
            &cold2.state.config,
            humoco_sync_server::locks::LockBatchRequest {
                anchor_id: past_aid,
                bucket: past_bkt,
                recipient_nonce: [0xA5; 32],
                entries: vec![past_e0.to_wire_hex().unwrap()],
                manifest: None,
                genesis_ticket: None,
                known_head_receipt: Some(past_rcpt),
            },
            now,
        )
        .unwrap();
    assert_eq!(rb_code, 409);
    assert_eq!(rb_val["error"], "bucket_self_frozen");

    // PreFreeze with `current_manifest` MUST reject 409 AND leave 0 anchor/rotation records!
    let pf_resp = cold2
        .client
        .post(format!("{}/sync.php?lock_freeze", cold2.base_url))
        .json(&serde_json::json!({
            "action": "pre_freeze",
            "anchor_id": past_ahex,
            "current_manifest": past_man,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(pf_resp.status().as_u16(), 409);
    assert!(cold2
        .state
        .db
        .get_static_anchor_manifest(&past_ahex)
        .unwrap()
        .is_none());
    let static_404 = cold2
        .client
        .get(format!("{}/anchors/{}.bin", cold2.base_url, past_ahex))
        .send()
        .await
        .unwrap();
    assert_eq!(static_404.status().as_u16(), 404);

    // SYNC-S09-11 JSON schema strictness parity via HTTP (all MUST reject 400):
    // 1) negative veto.from_rev -> 400
    let r_vneg = cold2
        .client
        .post(format!("{}/sync.php?lock_freeze", cold2.base_url))
        .json(&serde_json::json!({
            "action": "veto",
            "veto": {
                "anchor_id": cold2_ahex,
                "from_rev": -1,
                "proposal_hash": "11".repeat(32),
                "vetoer_pub": hex::encode(creator_mig_pub),
                "vetoed_at": now,
                "sig": "22".repeat(64),
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r_vneg.status().as_u16(), 400);

    // 2) propose & sign_commit missing guarantor_cosigs -> 400
    let p_missing_cosigs = serde_json::json!({
        "anchor_id": cold2_ahex,
        "from_rev": 1,
        "to_rev": 2,
        "new_threshold": 2,
        "new_servers": [cold2_man.servers[0]],
        "new_successors": [],
        "retain_until_quarter": quarter,
        "proposed_at": now,
        "initiator": {"kind": "creator"},
        "proposer_sig": "00".repeat(64),
    });
    let r_pmiss = cold2
        .client
        .post(format!("{}/sync.php?lock_freeze", cold2.base_url))
        .json(&serde_json::json!({"action": "propose", "proposal": p_missing_cosigs}))
        .send()
        .await
        .unwrap();
    assert_eq!(r_pmiss.status().as_u16(), 400);

    let r_scmiss = cold2
        .client
        .post(format!("{}/sync.php?lock_commit", cold2.base_url))
        .json(&serde_json::json!({
            "action": "sign_commit",
            "anchor_id": cold2_ahex,
            "proposal": p_missing_cosigs,
            "imported_state_hash": "11".repeat(32),
            "import_acks": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r_scmiss.status().as_u16(), 400);

    // 3) lock_import non-list SnapshotExport.entries, missing conflicts, malformed QuorumCertificate -> 400
    let valid_prop = build_signed_proposal(
        cold2_aid,
        1,
        2,
        vec![cold2_man.servers[0].clone()],
        Vec::new(),
        quarter,
        now,
        humoco_proto::ProposalInitiator::Creator,
        Some(&creator_mig_sk),
        Vec::new(),
    );
    let r_imp_obj = cold2
        .client
        .post(format!("{}/sync.php?lock_import", cold2.base_url))
        .json(&serde_json::json!({
            "anchor_id": cold2_ahex,
            "active_manifest": cold2_man,
            "proposal": valid_prop,
            "snapshots": [{"snapshot": {"anchor_id": cold2_ahex}, "entries": {"k0": "00"}, "conflicts": []}],
            "quorum_certificates": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r_imp_obj.status().as_u16(), 400);

    let r_imp_miss = cold2
        .client
        .post(format!("{}/sync.php?lock_import", cold2.base_url))
        .json(&serde_json::json!({
            "anchor_id": cold2_ahex,
            "active_manifest": cold2_man,
            "proposal": valid_prop,
            "snapshots": [{"snapshot": {"anchor_id": cold2_ahex}, "entries": []}],
            "quorum_certificates": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r_imp_miss.status().as_u16(), 400);

    let r_imp_qc = cold2
        .client
        .post(format!("{}/sync.php?lock_import", cold2.base_url))
        .json(&serde_json::json!({
            "anchor_id": cold2_ahex,
            "active_manifest": cold2_man,
            "proposal": valid_prop,
            "snapshots": [],
            "quorum_certificates": [{"slot": "bad"}],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r_imp_qc.status().as_u16(), 400);

    // 4) finalize associative commit_sigs map -> 400
    let r_fin_map = cold2
        .client
        .post(format!("{}/sync.php?lock_commit", cold2.base_url))
        .json(&serde_json::json!({
            "action": "finalize",
            "anchor_id": cold2_ahex,
            "new_manifest": {
                "revision": 2,
                "threshold": 1,
                "servers": cold2_man.servers,
                "successors": [],
                "authority": cold2_man.authority,
                "migration_chain": [{
                    "anchor_id": cold2_ahex,
                    "genesis_manifest": cold2_man,
                    "proposal": valid_prop,
                    "imported_state_hash": "11".repeat(32),
                    "import_acks": [],
                    "commit_sigs": {"a": {"lock_pub": hex::encode(cold2_pub), "committed_at": now, "sig": "00".repeat(64)}},
                }],
                "issued_at_ms": now * 1000,
                "retain_until_quarter": quarter,
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r_fin_map.status().as_u16(), 400);
}

#[tokio::test]
async fn test_s09_f4_hybrid_head_pool_grace_suspended_and_codes_parity() {
    use humoco_sync_server::db::AccountStatus;

    let (admin_sk, admin_pk) = gen_keypair();
    let (friend_sk, friend_pk) = gen_keypair();
    let (free_sk, free_pk) = gen_keypair();
    let (_pro_sk, pro_pk) = gen_keypair();
    let (grace_sk, grace_pk) = gen_keypair();
    let (post_grace_sk, post_grace_pk) = gen_keypair();
    let (susp_sk, susp_pk) = gen_keypair();
    let (_outsider_sk, outsider_pk) = gen_keypair();

    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.enabled = true;
    cfg.storage.downgrade_grace_days = 7;
    cfg.storage.max_total_storage_mb = 32;
    cfg.storage.max_free_pool_mb = 16;
    let srv = TestServer::start(cfg).await;
    let now = unix_now();
    let ts = now as i64;

    // 1. SYNC-S09-13: configured server admin_pubkey (not in ADMIN_MEMBERS) MUST receive
    //    X-Drop-Authorized: true and X-Drop-Channels: lock on HEAD with X-Channel: lock or omitted X-Channel.
    let head_admin_lock = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Channel", "lock")
        .send()
        .await
        .unwrap();
    assert_eq!(head_admin_lock.status().as_u16(), 200);
    assert_eq!(
        head_admin_lock
            .headers()
            .get("x-drop-authorized")
            .and_then(|v| v.to_str().ok()),
        Some("true"),
        "admin_pubkey must be authorized for lock channel on HEAD"
    );
    assert_eq!(
        head_admin_lock
            .headers()
            .get("x-drop-channels")
            .and_then(|v| v.to_str().ok()),
        Some("lock")
    );
    assert!(head_admin_lock.headers().get("x-slot-occupied").is_none());
    assert!(head_admin_lock
        .headers()
        .get("x-channel-max-bytes")
        .is_none());

    let head_admin_any = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .send()
        .await
        .unwrap();
    assert_eq!(head_admin_any.status().as_u16(), 200);
    assert_eq!(
        head_admin_any
            .headers()
            .get("x-drop-authorized")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );
    assert_eq!(
        head_admin_any
            .headers()
            .get("x-drop-channels")
            .and_then(|v| v.to_str().ok()),
        Some("lock")
    );

    let head_admin_card = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &admin_pk)
        .header("X-Channel", "card")
        .send()
        .await
        .unwrap();
    assert_eq!(head_admin_card.status().as_u16(), 200);
    assert_eq!(
        head_admin_card
            .headers()
            .get("x-drop-authorized")
            .and_then(|v| v.to_str().ok()),
        Some("false")
    );
    assert_eq!(
        head_admin_card
            .headers()
            .get("x-drop-channels")
            .and_then(|v| v.to_str().ok()),
        Some("lock")
    );

    // 2. Hybrid admin_app vs registered isolation + PUT ?members&channel=media + index.json exclusion
    let members_card = serde_json::to_vec(&serde_json::json!({ "pubkeys": [friend_pk] })).unwrap();
    let nonce_m1 = random_hex(16);
    let sig_m1 = hex::encode(
        admin_sk
            .sign(
                format_admin_put_members_message("card", ts, &nonce_m1, &sha256_hex(&members_card))
                    .as_bytes(),
            )
            .to_bytes(),
    );
    assert_eq!(
        srv.client
            .put(format!("{}/sync.php?members&channel=card", srv.base_url))
            .header("X-Drop-Pubkey", &admin_pk)
            .header("X-Drop-Timestamp", ts.to_string())
            .header("X-Drop-Nonce", nonce_m1)
            .header("X-Drop-Signature", sig_m1)
            .body(members_card)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // Friend uploads card slot + media (before explicit media list -> inherits card fallback)
    let card_blob = b"friend-hybrid-card-blob".to_vec();
    let mut req = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .body(card_blob.clone());
    for (k, v) in sign_member_headers(&friend_sk, "PUT", "card", "", "", ts, &card_blob) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 200);

    // Unauthorized outsider HEAD must return 200 X-Drop-Authorized: false without oracle leaks
    let head_unauth = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &outsider_pk)
        .header("X-Channel", "card")
        .send()
        .await
        .unwrap();
    assert_eq!(head_unauth.status().as_u16(), 200);
    assert_eq!(
        head_unauth
            .headers()
            .get("x-drop-authorized")
            .and_then(|v| v.to_str().ok()),
        Some("false")
    );
    assert!(head_unauth.headers().get("x-drop-channels").is_none());
    assert!(head_unauth.headers().get("x-slot-occupied").is_none());
    assert!(head_unauth.headers().get("etag").is_none());
    assert!(head_unauth.headers().get("x-channel-max-bytes").is_none());

    let friend_media_id = sha256_hex(b"friend-media-item");
    let friend_media_blob = b"friend-media-payload".to_vec();
    let mut req = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .body(friend_media_blob.clone());
    for (k, v) in sign_member_headers(
        &friend_sk,
        "PUT",
        "media",
        "",
        &friend_media_id,
        ts,
        &friend_media_blob,
    ) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 200);

    // Public registered free user uploads wot slot + media blob
    srv.state
        .db
        .register_or_upgrade_user(&srv.state.config, &free_pk, "free", None, None, "open", now)
        .unwrap();
    let free_wot_blob = b"registered-free-wot".to_vec();
    let mut req = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .body(free_wot_blob.clone());
    for (k, v) in sign_member_headers(&free_sk, "PUT", "wot", "", "", ts, &free_wot_blob) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 200);

    let free_media_id = sha256_hex(b"free-media-item");
    let free_media_blob = b"free-media-payload".to_vec();
    let mut req = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .body(free_media_blob.clone());
    for (k, v) in sign_member_headers(
        &free_sk,
        "PUT",
        "media",
        "",
        &free_media_id,
        ts,
        &free_media_blob,
    ) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 200);

    // PUT ?members&channel=media with [] revokes admin_app media access & prunes friend media,
    // while keeping friend card slot AND registered free user's media untouched.
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv.base_url, friend_media_id
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200,
        "friend media must be downloadable before pruning"
    );
    let empty_media = br#"{"pubkeys":[]}"#.to_vec();
    let nonce_m2 = random_hex(16);
    let sig_m2 = hex::encode(
        admin_sk
            .sign(
                format_admin_put_members_message("media", ts, &nonce_m2, &sha256_hex(&empty_media))
                    .as_bytes(),
            )
            .to_bytes(),
    );
    assert_eq!(
        srv.client
            .put(format!("{}/sync.php?members&channel=media", srv.base_url))
            .header("X-Drop-Pubkey", &admin_pk)
            .header("X-Drop-Timestamp", ts.to_string())
            .header("X-Drop-Nonce", nonce_m2)
            .header("X-Drop-Signature", sig_m2)
            .body(empty_media)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv.base_url, friend_media_id
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404,
        "friend media must be pruned when explicit media admin list removes them"
    );
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.card.bin",
                srv.base_url, friend_pk
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200,
        "friend card slot must survive media list pruning"
    );
    let mut req = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .body(friend_media_blob.clone());
    for (k, v) in sign_member_headers(
        &friend_sk,
        "PUT",
        "media",
        "",
        &friend_media_id,
        ts,
        &friend_media_blob,
    ) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 403);

    // Registered public user keeps media access and existing blob
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv.base_url, free_media_id
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // index.json must include friend's card slot and exclude registered wot slot & all media blobs
    let idx_resp = srv
        .client
        .get(format!("{}/humoco_sync_data/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(idx_resp.status().as_u16(), 200);
    let idx_json: serde_json::Value = idx_resp.json().await.unwrap();
    let entries = idx_json.as_array().unwrap();
    assert!(entries
        .iter()
        .any(|e| e["id"].as_str() == Some(friend_pk.as_str()) && e["channel"] == "card"));
    assert!(
        !entries
            .iter()
            .any(|e| e["id"].as_str() == Some(free_pk.as_str()) || e["channel"] == "media"),
        "index.json must exclude registered users and media blobs: {idx_json}"
    );

    // 3. Grace period (valid_until + downgrade_grace_days) and post-grace downgrade
    // grace_sk registered as pro 2 days ago for 1 day -> valid_until = now - 1d (inside 7d grace)
    srv.state
        .db
        .register_or_upgrade_user(
            &srv.state.config,
            &grace_pk,
            "pro",
            Some("grace@example.org"),
            Some(1),
            "admin",
            now.saturating_sub(2 * 86_400),
        )
        .unwrap();
    let head_grace = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &grace_pk)
        .header("X-Channel", "card")
        .send()
        .await
        .unwrap();
    assert_eq!(
        head_grace
            .headers()
            .get("x-channel-max-bytes")
            .and_then(|v| v.to_str().ok()),
        Some("2097152"),
        "User inside grace period keeps pro quota on HEAD"
    );
    let big_card = vec![0x5Au8; 600 * 1024]; // > free 512 KiB, <= pro 2 MiB
    let mut req = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .body(big_card.clone());
    for (k, v) in sign_member_headers(&grace_sk, "PUT", "card", "", "", ts, &big_card) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 200);
    let q_ok = humoco_proto::encode_quarter(2030, 4).unwrap();
    let (grace_tkt_code, _) = fetch_ticket_signed(&srv, &grace_sk, [0x42; 32], q_ok).await;
    assert_eq!(
        grace_tkt_code, 403,
        "Expired user inside grace period must NOT receive new lock tickets"
    );

    // post_grace_sk registered as pro 9 days ago for 1 day -> valid_until = now - 8d (> 7d grace)
    srv.state
        .db
        .register_or_upgrade_user(
            &srv.state.config,
            &post_grace_pk,
            "pro",
            Some("Post.Grace+Tag@example.org"),
            Some(1),
            "admin",
            now.saturating_sub(9 * 86_400),
        )
        .unwrap();
    let head_post_grace = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &post_grace_pk)
        .header("X-Channel", "card")
        .send()
        .await
        .unwrap();
    assert_eq!(
        head_post_grace
            .headers()
            .get("x-channel-max-bytes")
            .and_then(|v| v.to_str().ok()),
        Some("524288"),
        "User past grace period drops immediately to free quota on HEAD"
    );
    let mut req = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .body(big_card.clone());
    for (k, v) in sign_member_headers(&post_grace_sk, "PUT", "card", "", "", ts, &big_card) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 413);
    assert_eq!(
        fetch_ticket_signed(&srv, &post_grace_sk, [0x43; 32], q_ok)
            .await
            .0,
        403
    );

    // Maintenance finalizes downgrade to free, wipes encrypted_contact_email, preserves email_hmac
    srv.state
        .db
        .run_maintenance(&srv.state.config, now)
        .unwrap();
    let post_rec = srv
        .state
        .db
        .get_registered_user(&post_grace_pk)
        .unwrap()
        .unwrap();
    assert_eq!(post_rec.profile, "free");
    assert!(post_rec.valid_until.is_none());
    assert!(post_rec.encrypted_contact_email.is_none());
    assert!(post_rec.email_hmac.is_some());

    // 4. Suspended HTTP matrix (PUT/DELETE/lock_ticket -> 403, HEAD -> authorized=false, DELETE ?account -> 200)
    srv.state
        .db
        .register_or_upgrade_user(&srv.state.config, &susp_pk, "pro", None, None, "admin", now)
        .unwrap();
    let susp_slot = b"susp-slot-before-suspend".to_vec();
    let mut req = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .body(susp_slot.clone());
    for (k, v) in sign_member_headers(&susp_sk, "PUT", "card", "", "", ts, &susp_slot) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 200);
    let susp_media_id = sha256_hex(b"susp-media-before-suspend");
    let susp_media_blob = b"susp-media-payload".to_vec();
    let mut req = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .body(susp_media_blob.clone());
    for (k, v) in sign_member_headers(
        &susp_sk,
        "PUT",
        "media",
        "",
        &susp_media_id,
        ts,
        &susp_media_blob,
    ) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 200);

    srv.state
        .db
        .set_user_status(&susp_pk, AccountStatus::Suspended, now)
        .unwrap();

    let head_susp = srv
        .client
        .head(format!("{}/sync.php", srv.base_url))
        .header("X-Drop-Pubkey", &susp_pk)
        .header("X-Channel", "card")
        .send()
        .await
        .unwrap();
    assert_eq!(head_susp.status().as_u16(), 200);
    assert_eq!(
        head_susp
            .headers()
            .get("x-drop-authorized")
            .and_then(|v| v.to_str().ok()),
        Some("false")
    );
    assert!(head_susp.headers().get("x-drop-channels").is_none());
    assert!(head_susp.headers().get("x-slot-occupied").is_none());

    let mut req = srv
        .client
        .put(format!("{}/sync.php", srv.base_url))
        .body(susp_slot.clone());
    for (k, v) in sign_member_headers(&susp_sk, "PUT", "card", "", "", ts, &susp_slot) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 403);

    // Suspended user cannot delete absent/unowned slot (403), CAN delete own leftover slot (200),
    // and then second DELETE returns 403.
    let mut req = srv.client.delete(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&susp_sk, "DELETE", "wot", "", "", ts, b"") {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 403);

    let mut req = srv.client.delete(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&susp_sk, "DELETE", "card", "", "", ts, b"") {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 200);

    let mut req = srv.client.delete(format!("{}/sync.php", srv.base_url));
    for (k, v) in sign_member_headers(&susp_sk, "DELETE", "card", "", "", ts, b"") {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 403);
    assert_eq!(
        fetch_ticket_signed(&srv, &susp_sk, [0x44; 32], q_ok)
            .await
            .0,
        403
    );

    // Suspended user may still self-delete account via DELETE ?account (wiping remaining media too)
    let del_nonce = random_hex(16);
    let del_sig = hex::encode(
        susp_sk
            .sign(format_delete_account_message(ts, &del_nonce).as_bytes())
            .to_bytes(),
    );
    let del_resp = srv
        .client
        .delete(format!("{}/sync.php?account", srv.base_url))
        .header("X-Drop-Pubkey", &susp_pk)
        .header("X-Drop-Timestamp", ts.to_string())
        .header("X-Drop-Nonce", del_nonce)
        .header("X-Drop-Signature", del_sig)
        .send()
        .await
        .unwrap();
    assert_eq!(del_resp.status().as_u16(), 200);
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.card.bin",
                srv.base_url, susp_pk
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    assert_eq!(
        srv.client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv.base_url, susp_media_id
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );

    // 5. Redeem code expiry (410), max_uses exhaustion (409), 404, 400, and HTTP error handling
    let past_codes = srv
        .state
        .db
        .create_redeem_codes(
            &srv.state.config,
            1,
            "pro",
            Some(30),
            1,
            Some(1),
            None,
            Some("EXP"),
            now.saturating_sub(2 * 86_400),
        )
        .unwrap();
    let exp_err = srv
        .state
        .db
        .redeem_code_for_pubkey(&srv.state.config, &free_pk, &past_codes[0].code, now)
        .unwrap_err();
    assert!(matches!(
        exp_err,
        humoco_sync_server::db::DbError::Http { status: 410, .. }
    ));

    let one_use = srv
        .state
        .db
        .create_redeem_codes(
            &srv.state.config,
            1,
            "pro",
            Some(30),
            1,
            Some(5),
            None,
            Some("ONCE"),
            now,
        )
        .unwrap();
    assert!(srv
        .state
        .db
        .redeem_code_for_pubkey(&srv.state.config, &free_pk, &one_use[0].code, now)
        .is_ok());
    let conflict_err = srv
        .state
        .db
        .redeem_code_for_pubkey(&srv.state.config, &pro_pk, &one_use[0].code, now)
        .unwrap_err();
    assert!(matches!(
        conflict_err,
        humoco_sync_server::db::DbError::Http { status: 409, .. }
    ));
    assert!(matches!(
        srv.state
            .db
            .redeem_code_for_pubkey(&srv.state.config, &pro_pk, "NO-SUCH-CODE", now)
            .unwrap_err(),
        humoco_sync_server::db::DbError::Http { status: 404, .. }
    ));
    assert!(matches!(
        srv.state
            .db
            .redeem_code_for_pubkey(&srv.state.config, &pro_pk, "   ", now)
            .unwrap_err(),
        humoco_sync_server::db::DbError::Http { status: 400, .. }
    ));

    let bad_redeem_http = srv
        .client
        .post(format!("{}/register/redeem", srv.base_url))
        .form(&[
            ("pubkey", pro_pk.as_str()),
            ("code", one_use[0].code.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(bad_redeem_http.status().as_u16(), 303);
    assert!(bad_redeem_http
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("err="));
    assert!(srv.state.db.get_registered_user(&pro_pk).unwrap().is_none());

    // 6. Tight Global Storage + Free-Pool Prio-3 eviction matrix
    let mut cfg_pool = base_hybrid_config(&admin_pk);
    cfg_pool.storage.max_total_storage_mb = 1; // 1 MiB
    cfg_pool.storage.max_free_pool_mb = 1; // 1 MiB
    let srv_pool = TestServer::start(cfg_pool).await;
    let (pool_free_sk, pool_free_pk) = gen_keypair();
    let (pool_pro_sk, pool_pro_pk) = gen_keypair();
    srv_pool
        .state
        .db
        .register_or_upgrade_user(
            &srv_pool.state.config,
            &pool_free_pk,
            "free",
            None,
            None,
            "open",
            now,
        )
        .unwrap();
    srv_pool
        .state
        .db
        .register_or_upgrade_user(
            &srv_pool.state.config,
            &pool_pro_pk,
            "pro",
            None,
            None,
            "admin",
            now,
        )
        .unwrap();

    let pro_blob1 = vec![0x11u8; 450 * 1024];
    let pro_id1 = sha256_hex(&pro_blob1);
    let mut req = srv_pool
        .client
        .put(format!("{}/sync.php", srv_pool.base_url))
        .body(pro_blob1.clone());
    for (k, v) in sign_member_headers(&pool_pro_sk, "PUT", "media", "", &pro_id1, ts, &pro_blob1) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 200);

    let free_blob1 = vec![0x22u8; 400 * 1024];
    let free_id1 = sha256_hex(&free_blob1);
    let mut req = srv_pool
        .client
        .put(format!("{}/sync.php", srv_pool.base_url))
        .body(free_blob1.clone());
    for (k, v) in sign_member_headers(
        &pool_free_sk,
        "PUT",
        "media",
        "",
        &free_id1,
        ts,
        &free_blob1,
    ) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 200);

    assert_eq!(
        srv_pool
            .client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv_pool.base_url, free_id1
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // Pro upload pushes total (450 + 400 + 300 = 1150 KiB) > 1024 KiB -> MUST evict free_blob1 first!
    let pro_blob2 = vec![0x33u8; 300 * 1024];
    let pro_id2 = sha256_hex(&pro_blob2);
    let mut req = srv_pool
        .client
        .put(format!("{}/sync.php", srv_pool.base_url))
        .body(pro_blob2.clone());
    for (k, v) in sign_member_headers(&pool_pro_sk, "PUT", "media", "", &pro_id2, ts, &pro_blob2) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 200);
    assert_eq!(
        srv_pool
            .client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv_pool.base_url, free_id1
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404,
        "Global Prio-3 eviction must evict free-pool media before paid pro media"
    );
    assert_eq!(
        srv_pool
            .client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv_pool.base_url, pro_id1
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // Free user trying to exceed remaining global space (750 + 350 > 1024 KiB) MUST fail 507
    // and NEVER evict pro media!
    let free_blob2 = vec![0x44u8; 350 * 1024];
    let free_id2 = sha256_hex(&free_blob2);
    let mut req = srv_pool
        .client
        .put(format!("{}/sync.php", srv_pool.base_url))
        .body(free_blob2.clone());
    for (k, v) in sign_member_headers(
        &pool_free_sk,
        "PUT",
        "media",
        "",
        &free_id2,
        ts,
        &free_blob2,
    ) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 507);
    assert_eq!(
        srv_pool
            .client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv_pool.base_url, pro_id1
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        srv_pool
            .client
            .get(format!(
                "{}/humoco_sync_data/{}.media.bin",
                srv_pool.base_url, pro_id2
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
}

#[tokio::test]
async fn test_s09_f4_web_register_admin_ui_and_admin_api_hardening() {
    use humoco_sync_server::crypto::{
        create_pow_challenge, hash_admin_token, hmac_email, leading_zero_bits,
        sign_stateless_token, SignedActionToken,
    };
    use humoco_sync_server::db::{AccountStatus, AdminUserSummary};

    let (admin_sk, admin_pk) = gen_keypair();
    let admin_secret = "f4-admin-ui-secret";
    let bearer_secret = "f4-api-bearer-secret";

    // 1. Disabled public registration & unconfigured admin tokens -> fail closed (403 / 503)
    let mut cfg_closed = base_hybrid_config(&admin_pk);
    cfg_closed.mode.enable_public_registration = false;
    let srv_closed = TestServer::start(cfg_closed).await;
    assert_eq!(
        srv_closed
            .client
            .get(format!("{}/register", srv_closed.base_url))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    let r_confirm_closed = srv_closed
        .client
        .get(format!(
            "{}/register/confirm?token=abc",
            srv_closed.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r_confirm_closed.status().as_u16(), 303);
    assert_eq!(
        r_confirm_closed
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some("/")
    );
    assert_eq!(
        srv_closed
            .client
            .get(format!("{}/admin", srv_closed.base_url))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        503
    );
    assert_eq!(
        srv_closed
            .client
            .get(format!("{}/api/v1/admin/stats", srv_closed.base_url))
            .header("Authorization", "Bearer anything")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        503
    );

    // 2. Active server with separate admin UI + API bearer tokens, PoW, email log transport, trusted proxy
    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.mode.registration_gates = vec![
        "email".to_string(),
        "code".to_string(),
        "pow".to_string(),
        "open".to_string(),
    ];
    cfg.security.pow_difficulty_bits = 8;
    cfg.security.max_registrations_per_ipv6_48_per_day = 1;
    cfg.security.max_registrations_per_ipv4_24_per_day = 2;
    cfg.security.admin_token_hash = hash_admin_token(admin_secret).unwrap();
    cfg.security.api_bearer_token_hash = hash_admin_token(bearer_secret).unwrap();
    cfg.server.trusted_proxy_hops = 1;
    cfg.email.enabled = true;
    cfg.email.transport = "log".to_string();
    let srv = TestServer::start(cfg).await;
    let now = unix_now();

    // 2a. Zero-PII confirm_register ignores embedded contact_email on store_contact_email=false,
    //     rejects delete_account token on /register/confirm and confirm_register on /register/delete-confirm.
    let (_e_sk, e_pk) = gen_keypair();
    let e_hmac = hmac_email(srv.state.db.pepper(), "zero.pii@example.org");
    let del_tok = sign_stateless_token(
        srv.state.db.pepper(),
        &SignedActionToken {
            action: "delete_account".to_string(),
            pubkey: e_pk.clone(),
            email_hmac: e_hmac.clone(),
            contact_email: None,
            profile: "free".to_string(),
            exp: now + 600,
            jti: random_hex(16),
        },
    );
    let wrong_confirm = srv
        .client
        .get(format!(
            "{}/register/confirm?token={}",
            srv.base_url, del_tok
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_confirm.status().as_u16(), 303);
    assert!(srv.state.db.get_registered_user(&e_pk).unwrap().is_none());

    let reg_tok = sign_stateless_token(
        srv.state.db.pepper(),
        &SignedActionToken {
            action: "confirm_register".to_string(),
            pubkey: e_pk.clone(),
            email_hmac: e_hmac.clone(),
            contact_email: None,
            profile: "free".to_string(),
            exp: now + 600,
            jti: random_hex(16),
        },
    );
    let wrong_del = srv
        .client
        .get(format!(
            "{}/register/delete-confirm?token={}",
            srv.base_url, reg_tok
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_del.status().as_u16(), 303);

    let ok_confirm = srv
        .client
        .get(format!(
            "{}/register/confirm?token={}",
            srv.base_url, reg_tok
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(ok_confirm.status().as_u16(), 303);
    assert!(ok_confirm
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("msg="));
    let e_rec = srv.state.db.get_registered_user(&e_pk).unwrap().unwrap();
    assert_eq!(e_rec.email_hmac.as_deref(), Some(e_hmac.as_str()));
    assert!(e_rec.encrypted_contact_email.is_none());

    // Valid delete-confirm permanently removes account via verified token
    let ok_del = srv
        .client
        .get(format!(
            "{}/register/delete-confirm?token={}",
            srv.base_url, del_tok
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(ok_del.status().as_u16(), 303);
    assert!(srv.state.db.get_registered_user(&e_pk).unwrap().is_none());

    // 2b. store_contact_email=true profile ("pro") persists encrypted email visible only in admin summary
    let (_pro_mail_sk, pro_mail_pk) = gen_keypair();
    let pro_hmac = hmac_email(srv.state.db.pepper(), "supporter@example.org");
    let pro_tok = sign_stateless_token(
        srv.state.db.pepper(),
        &SignedActionToken {
            action: "confirm_register".to_string(),
            pubkey: pro_mail_pk.clone(),
            email_hmac: pro_hmac,
            contact_email: Some("supporter@example.org".to_string()),
            profile: "pro".to_string(),
            exp: now + 600,
            jti: random_hex(16),
        },
    );
    assert_eq!(
        srv.client
            .get(format!(
                "{}/register/confirm?token={}",
                srv.base_url, pro_tok
            ))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        303
    );
    let pro_rec = srv
        .state
        .db
        .get_registered_user(&pro_mail_pk)
        .unwrap()
        .unwrap();
    assert!(pro_rec.encrypted_contact_email.is_some());

    // 2c. PoW registration (/register/pow): bad nonce rejected, wrong pubkey rejected, valid solved nonce accepted
    let (_pow_sk, pow_pk) = gen_keypair();
    let (_other_pow_sk, other_pow_pk) = gen_keypair();
    let chal = create_pow_challenge(srv.state.db.pepper(), &pow_pk, 8, now);
    let mut solved_nonce = 0u64;
    loop {
        let digest =
            hex::decode(sha256_hex(format!("{}:{}", chal, solved_nonce).as_bytes())).unwrap();
        if leading_zero_bits(&digest) >= 8 {
            break;
        }
        solved_nonce += 1;
    }
    let _ = srv
        .client
        .post(format!("{}/register/pow", srv.base_url))
        .form(&[
            ("pubkey", pow_pk.as_str()),
            ("challenge", chal.as_str()),
            ("nonce", "999999999"),
        ])
        .send()
        .await
        .unwrap();
    let _ = srv
        .client
        .post(format!("{}/register/pow", srv.base_url))
        .form(&[
            ("pubkey", other_pow_pk.as_str()),
            ("challenge", chal.as_str()),
            ("nonce", &solved_nonce.to_string()),
        ])
        .send()
        .await
        .unwrap();
    assert!(srv.state.db.get_registered_user(&pow_pk).unwrap().is_none());
    assert!(srv
        .state
        .db
        .get_registered_user(&other_pow_pk)
        .unwrap()
        .is_none());

    let ok_pow = srv
        .client
        .post(format!("{}/register/pow", srv.base_url))
        .form(&[
            ("pubkey", pow_pk.as_str()),
            ("challenge", chal.as_str()),
            ("nonce", &solved_nonce.to_string()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(ok_pow.status().as_u16(), 303);
    assert!(srv.state.db.get_registered_user(&pow_pk).unwrap().is_some());

    // 2d. IPv6 /48 & IPv4-mapped /24 open registration caps via X-Forwarded-For
    let (_v6_a_sk, v6_a_pk) = gen_keypair();
    let (_v6_b_sk, v6_b_pk) = gen_keypair();
    let (_v6_c_sk, v6_c_pk) = gen_keypair();
    srv.client
        .post(format!("{}/register/open", srv.base_url))
        .header("X-Forwarded-For", "2001:db8:1234:1::10")
        .form(&[("pubkey", v6_a_pk.as_str())])
        .send()
        .await
        .unwrap();
    srv.client
        .post(format!("{}/register/open", srv.base_url))
        .header("X-Forwarded-For", "2001:db8:1234:ffff::99")
        .form(&[("pubkey", v6_b_pk.as_str())])
        .send()
        .await
        .unwrap();
    srv.client
        .post(format!("{}/register/open", srv.base_url))
        .header("X-Forwarded-For", "2001:db8:5678:1::1")
        .form(&[("pubkey", v6_c_pk.as_str())])
        .send()
        .await
        .unwrap();
    assert!(srv
        .state
        .db
        .get_registered_user(&v6_a_pk)
        .unwrap()
        .is_some());
    assert!(
        srv.state
            .db
            .get_registered_user(&v6_b_pk)
            .unwrap()
            .is_none(),
        "Second IPv6 registration inside same /48 must be blocked"
    );
    assert!(srv
        .state
        .db
        .get_registered_user(&v6_c_pk)
        .unwrap()
        .is_some());

    let (_v4m_1_sk, v4m_1_pk) = gen_keypair();
    let (_v4m_2_sk, v4m_2_pk) = gen_keypair();
    let (_v4m_3_sk, v4m_3_pk) = gen_keypair();
    for (pk, xff) in [
        (&v4m_1_pk, "::ffff:198.51.100.10"),
        (&v4m_2_pk, "::ffff:198.51.100.20"),
        (&v4m_3_pk, "198.51.100.30"),
    ] {
        srv.client
            .post(format!("{}/register/open", srv.base_url))
            .header("X-Forwarded-For", xff)
            .form(&[("pubkey", pk.as_str())])
            .send()
            .await
            .unwrap();
    }
    assert!(srv
        .state
        .db
        .get_registered_user(&v4m_1_pk)
        .unwrap()
        .is_some());
    assert!(srv
        .state
        .db
        .get_registered_user(&v4m_2_pk)
        .unwrap()
        .is_some());
    assert!(
        srv.state
            .db
            .get_registered_user(&v4m_3_pk)
            .unwrap()
            .is_none(),
        "IPv4-mapped ::ffff: and raw IPv4 must share /24 daily cap"
    );

    // 3. /admin UI headers, XSS escaping, CSRF enforcement on all 4 POST forms, logout, rate limit
    let unauth_admin = srv
        .client
        .get(format!(
            "{}/admin?err=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth_admin.status().as_u16(), 200);
    assert_eq!(
        unauth_admin
            .headers()
            .get("x-frame-options")
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        unauth_admin
            .headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        unauth_admin
            .headers()
            .get("referrer-policy")
            .and_then(|v| v.to_str().ok()),
        Some("no-referrer")
    );
    assert_eq!(
        unauth_admin
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert!(unauth_admin
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("form-action 'self'")));
    let unauth_html = unauth_admin.text().await.unwrap();
    assert!(unauth_html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!unauth_html.contains("<script>alert(1)</script>"));

    // Wrong admin token must NOT set cookie
    let bad_login = srv
        .client
        .post(format!("{}/admin/login", srv.base_url))
        .form(&[("token", "wrong-secret")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad_login.status().as_u16(), 303);
    assert!(bad_login
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .is_none());

    // Valid login sets HttpOnly; SameSite=Strict cookie (and omits Secure over http://)
    let ok_login = srv
        .client
        .post(format!("{}/admin/login", srv.base_url))
        .form(&[("token", admin_secret)])
        .send()
        .await
        .unwrap();
    assert_eq!(ok_login.status().as_u16(), 303);
    let set_cookie = ok_login
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(!set_cookie.contains("; Secure"));
    let sess_cookie = set_cookie.split(';').next().unwrap().to_string();

    // Seed XSS-payload code note via API and confirm escaped in /admin HTML
    let xss_code_resp = srv
        .client
        .post(format!("{}/api/v1/admin/codes", srv.base_url))
        .header("Authorization", format!("Bearer {}", bearer_secret))
        .json(&serde_json::json!({
            "count": 1,
            "profile": "pro",
            "duration_days": 30,
            "note": "<img src=x onerror=alert(2)>"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(xss_code_resp.status().as_u16(), 201);

    let dash_html = srv
        .client
        .get(format!("{}/admin", srv.base_url))
        .header(reqwest::header::COOKIE, &sess_cookie)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(dash_html.contains("&lt;img src=x onerror=alert(2)&gt;"));
    assert!(!dash_html.contains("<img src=x onerror=alert(2)>"));
    let csrf = dash_html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_string();

    // Forged CSRF across ALL 4 mutating /admin routes MUST fail without altering state
    for (path, body_vec) in [
        (
            "/admin/users/profile",
            vec![
                ("csrf", "forged-csrf"),
                ("pubkey", v6_a_pk.as_str()),
                ("profile", "pro"),
                ("duration_days", "30"),
            ],
        ),
        (
            "/admin/users/status",
            vec![
                ("csrf", "forged-csrf"),
                ("pubkey", v6_a_pk.as_str()),
                ("status", "suspended"),
            ],
        ),
        (
            "/admin/users/delete",
            vec![("csrf", "forged-csrf"), ("pubkey", v6_a_pk.as_str())],
        ),
        (
            "/admin/codes",
            vec![("csrf", "forged-csrf"), ("profile", "pro"), ("count", "1")],
        ),
    ] {
        let r = srv
            .client
            .post(format!("{}{}", srv.base_url, path))
            .header(reqwest::header::COOKIE, &sess_cookie)
            .form(&body_vec)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 303);
        assert!(r
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("err=Session+expired"));
    }
    assert_eq!(
        srv.state
            .db
            .get_registered_user(&v6_a_pk)
            .unwrap()
            .unwrap()
            .status,
        AccountStatus::Active
    );

    // Valid CSRF mutations on status & delete & create codes
    let r_stat = srv
        .client
        .post(format!("{}/admin/users/status", srv.base_url))
        .header(reqwest::header::COOKIE, &sess_cookie)
        .form(&[
            ("csrf", csrf.as_str()),
            ("pubkey", v6_a_pk.as_str()),
            ("status", "suspended"),
        ])
        .send()
        .await
        .unwrap();
    assert!(r_stat
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("msg="));
    assert_eq!(
        srv.state
            .db
            .get_registered_user(&v6_a_pk)
            .unwrap()
            .unwrap()
            .status,
        AccountStatus::Suspended
    );

    let r_code = srv
        .client
        .post(format!("{}/admin/codes", srv.base_url))
        .header(reqwest::header::COOKIE, &sess_cookie)
        .form(&[
            ("csrf", csrf.as_str()),
            ("profile", "pro"),
            ("count", "1"),
            ("duration_days", "30"),
        ])
        .send()
        .await
        .unwrap();
    assert!(r_code
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("msg="));

    let r_del = srv
        .client
        .post(format!("{}/admin/users/delete", srv.base_url))
        .header(reqwest::header::COOKIE, &sess_cookie)
        .form(&[("csrf", csrf.as_str()), ("pubkey", pow_pk.as_str())])
        .send()
        .await
        .unwrap();
    assert!(r_del
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("msg="));
    assert!(srv.state.db.get_registered_user(&pow_pk).unwrap().is_none());

    // Logout revokes session so reusing cookie falls back to login page
    let r_logout = srv
        .client
        .post(format!("{}/admin/logout", srv.base_url))
        .header(reqwest::header::COOKIE, &sess_cookie)
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r_logout.status().as_u16(), 303);
    let reused_dash = srv
        .client
        .get(format!("{}/admin", srv.base_url))
        .header(reqwest::header::COOKIE, &sess_cookie)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(reused_dash.contains("Operator Admin Token"));
    assert!(!reused_dash.contains("name=\"csrf\""));

    // 4. /api/v1/admin/* token isolation, user management, pro->free email wipe, lock immunity, codes
    // Distinct api_bearer_token_hash must REJECT admin_secret as Bearer token
    let reject_admin_tok = srv
        .client
        .get(format!("{}/api/v1/admin/stats", srv.base_url))
        .header("Authorization", format!("Bearer {}", admin_secret))
        .send()
        .await
        .unwrap();
    assert_eq!(reject_admin_tok.status().as_u16(), 403);

    let ok_stats = srv
        .client
        .get(format!("{}/api/v1/admin/stats", srv.base_url))
        .header("Authorization", format!("Bearer {}", bearer_secret))
        .send()
        .await
        .unwrap();
    assert_eq!(ok_stats.status().as_u16(), 200);
    assert_eq!(
        ok_stats
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );

    assert_eq!(
        srv.client
            .get(format!("{}/api/v1/admin/users/bad-hex", srv.base_url))
            .header("Authorization", format!("Bearer {}", bearer_secret))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        400
    );
    let (_unknown_sk, unknown_pk) = gen_keypair();
    assert_eq!(
        srv.client
            .get(format!(
                "{}/api/v1/admin/users/{}",
                srv.base_url, unknown_pk
            ))
            .header("Authorization", format!("Bearer {}", bearer_secret))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );

    let users_list: serde_json::Value = srv
        .client
        .get(format!("{}/api/v1/admin/users", srv.base_url))
        .header("Authorization", format!("Bearer {}", bearer_secret))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(users_list["users"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["pubkey"].as_str() == Some(pro_mail_pk.as_str())));

    let pro_detail: AdminUserSummary = srv
        .client
        .get(format!(
            "{}/api/v1/admin/users/{}",
            srv.base_url, pro_mail_pk
        ))
        .header("Authorization", format!("Bearer {}", bearer_secret))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        pro_detail.contact_email.as_deref(),
        Some("supporter@example.org")
    );

    // Downgrading pro -> free (store_contact_email=false) via API must wipe encrypted_contact_email
    let downgrade_resp: AdminUserSummary = srv
        .client
        .post(format!(
            "{}/api/v1/admin/users/{}/profile",
            srv.base_url, pro_mail_pk
        ))
        .header("Authorization", format!("Bearer {}", bearer_secret))
        .json(&serde_json::json!({ "profile": "free" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(downgrade_resp.profile, "free");
    assert!(downgrade_resp.contact_email.is_none());
    assert!(srv
        .state
        .db
        .get_registered_user(&pro_mail_pk)
        .unwrap()
        .unwrap()
        .encrypted_contact_email
        .is_none());

    let api_status_resp: AdminUserSummary = srv
        .client
        .post(format!(
            "{}/api/v1/admin/users/{}/status",
            srv.base_url, v6_c_pk
        ))
        .header("Authorization", format!("Bearer {}", bearer_secret))
        .json(&serde_json::json!({ "status": "suspended" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(api_status_resp.status, AccountStatus::Suspended);

    let codes_json: serde_json::Value = srv
        .client
        .get(format!("{}/api/v1/admin/codes", srv.base_url))
        .header("Authorization", format!("Bearer {}", bearer_secret))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(codes_json["codes"].as_array().unwrap().len() >= 2);

    // Admin DELETE /api/v1/admin/users/:pk wipes user + blobs while preserving existing lock buckets
    let (lock_owner_sk, lock_owner_pk) = gen_keypair();
    srv.state
        .db
        .register_or_upgrade_user(
            &srv.state.config,
            &lock_owner_pk,
            "free",
            None,
            None,
            "open",
            now,
        )
        .unwrap();
    let lock_pub = srv.state.db.lock_pubkey_bytes().unwrap();
    let admin_pub_bytes = admin_sk.verifying_key().to_bytes();
    let mig_sk = SigningKey::from_bytes(&[77u8; 32]);
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let manifest = build_single_server_manifest(
        admin_pub_bytes,
        lock_pub,
        mig_sk.verifying_key().to_bytes(),
        quarter,
    );
    let anchor_id = manifest.rev1_anchor_id().unwrap();
    let bucket = humoco_proto::derive_bucket(&anchor_id, &lock_pub);
    let (t_code, t_json) = fetch_ticket_signed(&srv, &lock_owner_sk, anchor_id, quarter).await;
    assert_eq!(t_code, 200);
    let ticket: humoco_proto::GenesisTicket =
        serde_json::from_value(t_json["ticket"].clone()).unwrap();
    let g_sk = SigningKey::from_bytes(&[78u8; 32]);
    let entry0 = sign_lock_entry_helper(
        anchor_id,
        [0x09; 32],
        [0u8; 32],
        0,
        0,
        [0x19; 32],
        &g_sk,
        [0x29; 32],
        None,
        Some(&mig_sk),
        8,
    );
    let lock_resp = srv
        .client
        .post(format!("{}/sync.php?lock", srv.base_url))
        .json(&serde_json::json!({
            "anchor_id": hex::encode(anchor_id),
            "bucket": hex::encode(bucket),
            "recipient_nonce": hex::encode([0xBBu8; 32]),
            "entries": [entry0.to_wire_hex().unwrap()],
            "manifest": manifest,
            "genesis_ticket": ticket,
            "known_head_receipt": serde_json::Value::Null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(lock_resp.status().as_u16(), 200);
    assert_eq!(srv.state.db.lock_bucket_count_and_inodes().unwrap(), (1, 1));

    let del_user_resp: serde_json::Value = srv
        .client
        .delete(format!(
            "{}/api/v1/admin/users/{}",
            srv.base_url, lock_owner_pk
        ))
        .header("Authorization", format!("Bearer {}", bearer_secret))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(del_user_resp["deleted_account"], true);
    assert!(srv
        .state
        .db
        .get_registered_user(&lock_owner_pk)
        .unwrap()
        .is_none());
    assert_eq!(
        srv.state.db.lock_bucket_count_and_inodes().unwrap(),
        (1, 1),
        "Admin user deletion MUST NOT delete lock buckets/inodes"
    );

    // 5. Tight-rate-limit server for /admin/login rate-limiting + admin_token_hash Bearer fallback
    let mut cfg_rl = base_hybrid_config(&admin_pk);
    cfg_rl.security.ip_requests_per_minute = 2;
    cfg_rl.security.admin_token_hash = hash_admin_token(admin_secret).unwrap();
    let srv_rl = TestServer::start(cfg_rl).await;
    assert_eq!(
        srv_rl
            .client
            .get(format!("{}/api/v1/admin/stats", srv_rl.base_url))
            .header("Authorization", format!("Bearer {}", admin_secret))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200,
        "When api_bearer_token_hash is unset, API falls back to admin_token_hash"
    );
    let _ = srv_rl
        .client
        .post(format!("{}/admin/login", srv_rl.base_url))
        .form(&[("token", admin_secret)])
        .send()
        .await
        .unwrap();
    let rl_login = srv_rl
        .client
        .post(format!("{}/admin/login", srv_rl.base_url))
        .form(&[("token", admin_secret)])
        .send()
        .await
        .unwrap();
    assert_eq!(rl_login.status().as_u16(), 303);
    assert!(rl_login
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Rate+limit+exceeded"));
}
