use std::collections::BTreeMap;
use std::net::SocketAddr;

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use tempfile::TempDir;

use humoco_sync_server::build_router;
use humoco_sync_server::config::{ChannelQuotaConfig, Config, ProfileConfig};
use humoco_sync_server::crypto::{
    canonical_revocation_message, format_admin_put_members_message,
    format_admin_put_revoke_message, format_admin_status_message, format_delete_account_message,
    parse_member_message, random_hex, sha256_hex, unix_now, RevocationNotice,
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
