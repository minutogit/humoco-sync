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
    RevocationNotice,
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

    srv_pow
        .state
        .db
        .delete_account_and_data(&pow_pk, false)
        .unwrap();
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
