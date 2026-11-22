mod common;
use common::*;

use std::collections::BTreeMap;
use std::net::SocketAddr;

use ed25519_dalek::{Signer, SigningKey};
use humoco_sync_server::build_router;
use humoco_sync_server::config::{ChannelQuotaConfig, Config, ProfileConfig};
use humoco_sync_server::crypto::{
    canonical_revocation_message, format_admin_put_config_message,
    format_admin_put_members_message, format_admin_put_revoke_message, format_admin_status_message,
    format_delete_account_message, parse_member_message, random_hex, sha256_hex, unix_now,
    RevocationNotice, RevocationReplacementTarget,
};
use humoco_sync_server::db::{ConditionalPrecondition, DbError};
use humoco_sync_server::state::AppState;
use tempfile::TempDir;

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

#[tokio::test]
async fn test_parity_zero_media_caps_and_zero_rotation_timestamps() {
    let (admin_sk, admin_pk) = gen_keypair();
    let (user_sk, user_pk) = gen_keypair();
    let now = unix_now() as i64;

    // 1. Seed a live media blob under normal limits, then confirm max_user_count=0 -> 507
    //    without evicting existing media (matching PHP's $maxUserCount < 1 check).
    let mut cfg_seed = base_hybrid_config(&admin_pk);
    cfg_seed.lock.enabled = true;
    let srv_seed = TestServer::start(cfg_seed.clone()).await;
    srv_seed
        .state
        .db
        .put_admin_members(
            &srv_seed.state.config,
            "card",
            std::slice::from_ref(&user_pk),
            now as u64,
        )
        .unwrap();
    let existing_media_id = sha256_hex(b"existing-media-blob");
    let existing_bytes = vec![0xABu8; 64];
    let put_existing_hdrs = sign_member_headers(
        &user_sk,
        "PUT",
        "media",
        "",
        &existing_media_id,
        now,
        &existing_bytes,
    );
    let mut req_seed = srv_seed
        .client
        .put(format!("{}/sync.php", srv_seed.base_url))
        .body(existing_bytes);
    for (k, v) in put_existing_hdrs {
        req_seed = req_seed.header(k, v);
    }
    assert_eq!(req_seed.send().await.unwrap().status().as_u16(), 200);

    let mut cfg_zero_count = (*srv_seed.state.config).clone();
    if let Some(prof) = cfg_zero_count.profiles.get_mut("friends") {
        if let Some(mq) = prof.channels.get_mut("media") {
            mq.max_user_count = Some(0);
        }
    }
    let blocked_media_id = sha256_hex(b"blocked-zero-count");
    let put_zero_count = srv_seed.state.db.put_media(
        &cfg_zero_count,
        &user_pk,
        &blocked_media_id,
        b"small-media",
        &ConditionalPrecondition::None,
        now as u64,
    );
    match put_zero_count {
        Err(DbError::Http { status, .. }) => assert_eq!(
            status, 507,
            "max_user_count=0 must reject PUT media with 507 Insufficient Storage (PHP parity)"
        ),
        other => panic!("Expected 507 DbError::Http for max_user_count=0, got {other:?}"),
    }
    assert!(
        srv_seed
            .state
            .db
            .get_media_blob(&cfg_zero_count, &existing_media_id, now as u64)
            .unwrap()
            .is_some(),
        "max_user_count=0 rejection must NOT evict existing user media"
    );

    // 2. media.max_channel_mb = 0 -> 507 without evicting existing user media
    let mut cfg_zero_chan = (*srv_seed.state.config).clone();
    cfg_zero_chan.media.max_channel_mb = 0;
    let put_zero_chan = srv_seed.state.db.put_media(
        &cfg_zero_chan,
        &user_pk,
        &blocked_media_id,
        b"small-media",
        &ConditionalPrecondition::None,
        now as u64,
    );
    match put_zero_chan {
        Err(DbError::Http { status, .. }) => assert_eq!(
            status, 507,
            "media.max_channel_mb=0 must reject PUT media with 507 Insufficient Storage (PHP parity)"
        ),
        other => panic!("Expected 507 DbError::Http for max_channel_mb=0, got {other:?}"),
    }
    assert!(
        srv_seed
            .state
            .db
            .get_media_blob(&cfg_zero_chan, &existing_media_id, now as u64)
            .unwrap()
            .is_some(),
        "max_channel_mb=0 rejection must NOT evict existing media"
    );

    // 3. Explicit zero timestamps on ?lock_freeze heartbeat/veto -> 400 Bad Request (PHP parity)
    let _ = admin_sk;
    let anchor_hex = "aa".repeat(32);
    let zero_hb = srv_seed
        .client
        .post(format!("{}/sync.php?lock_freeze", srv_seed.base_url))
        .json(&serde_json::json!({
            "action": "heartbeat",
            "heartbeat": {
                "anchor_id": anchor_hex,
                "timestamp_secs": 0,
                "sig": "11".repeat(64),
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        zero_hb.status().as_u16(),
        400,
        "heartbeat.timestamp_secs=0 must reject with 400 Bad Request (PHP parity)"
    );

    let zero_veto = srv_seed
        .client
        .post(format!("{}/sync.php?lock_freeze", srv_seed.base_url))
        .json(&serde_json::json!({
            "action": "veto",
            "veto": {
                "anchor_id": anchor_hex,
                "from_rev": 1,
                "proposal_hash": "22".repeat(32),
                "vetoer_pub": "33".repeat(32),
                "vetoed_at": 0,
                "sig": "44".repeat(64),
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        zero_veto.status().as_u16(),
        400,
        "veto.vetoed_at=0 must reject with 400 Bad Request (PHP parity)"
    );
}
