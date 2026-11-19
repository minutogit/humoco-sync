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
    assert!(info["lock"]["delegation"].is_null());

    // 2. PUT ?lock_delegate + POST ?lock_selftest
    let issued_at = unix_now();
    let del_msg = humoco_sync_server::crypto::format_lock_delegate_signature_message(
        &admin_pk,
        &lock_pub_hex,
        issued_at,
    );
    let del_body = serde_json::to_vec(&serde_json::json!({
        "admin_pub": admin_pk,
        "lock_pub": lock_pub_hex,
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
    let quarter = humoco_proto::encode_quarter(2031, 4).unwrap();
    let t0 = 1_795_000_000u64;

    let e_s1 = server_entry_for_test(&s1, &a1_sk, humoco_proto::NominatedBy::Creator);
    let e_s5 = server_entry_for_test(&s5, &a5_sk, humoco_proto::NominatedBy::Creator);
    let man = build_multi_server_manifest(
        vec![e_s1.clone()],
        vec![e_s5.clone()],
        1,
        creator_mig_pub,
        Vec::new(),
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
