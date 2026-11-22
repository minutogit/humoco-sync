mod common;
use common::*;

use std::collections::BTreeMap;

use ed25519_dalek::Signer;
use humoco_sync_server::config::{ChannelQuotaConfig, ProfileConfig};
use humoco_sync_server::crypto::{
    format_admin_put_members_message, format_delete_account_message, random_hex, sha256_hex,
    unix_now,
};
use humoco_sync_server::db::{AccountStatus, ConditionalPrecondition};

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
async fn test_s09_f4_head_admin_pubkey_lock_authorization() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.enabled = true;
    let srv = TestServer::start(cfg).await;

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
}

#[tokio::test]
async fn test_s09_f4_hybrid_admin_vs_registered_media_and_index_json() {
    let (admin_sk, admin_pk) = gen_keypair();
    let (friend_sk, friend_pk) = gen_keypair();
    let (free_sk, free_pk) = gen_keypair();
    let (_outsider_sk, outsider_pk) = gen_keypair();
    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.enabled = true;
    let srv = TestServer::start(cfg).await;
    let now = unix_now();
    let ts = now as i64;

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
}

#[tokio::test]
async fn test_s09_f4_grace_period_and_post_grace_downgrade() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let (grace_sk, grace_pk) = gen_keypair();
    let (post_grace_sk, post_grace_pk) = gen_keypair();
    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.enabled = true;
    cfg.storage.downgrade_grace_days = 7;
    let srv = TestServer::start(cfg).await;
    let now = unix_now();
    let ts = now as i64;

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
}

#[tokio::test]
async fn test_s09_f4_suspended_http_matrix_and_self_delete() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let (susp_sk, susp_pk) = gen_keypair();
    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.enabled = true;
    let srv = TestServer::start(cfg).await;
    let now = unix_now();
    let ts = now as i64;
    let q_ok = humoco_proto::encode_quarter(2030, 4).unwrap();

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
}

#[tokio::test]
async fn test_s09_f4_redeem_codes_expiry_exhaustion_and_http_errors() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let (_free_sk, free_pk) = gen_keypair();
    let (_pro_sk, pro_pk) = gen_keypair();
    let cfg = base_hybrid_config(&admin_pk);
    let srv = TestServer::start(cfg).await;
    let now = unix_now();
    srv.state
        .db
        .register_or_upgrade_user(&srv.state.config, &free_pk, "free", None, None, "open", now)
        .unwrap();

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
}

#[tokio::test]
async fn test_s09_f4_tight_global_storage_and_free_pool_eviction() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let now = unix_now();
    let ts = now as i64;

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
