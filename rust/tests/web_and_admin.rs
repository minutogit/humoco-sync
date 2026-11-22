mod common;
use common::*;

use ed25519_dalek::SigningKey;
use humoco_sync_server::crypto::{
    create_pow_challenge, hash_admin_token, hmac_email, leading_zero_bits, random_hex, sha256_hex,
    sign_stateless_token, unix_now, SignedActionToken,
};
use humoco_sync_server::db::{AccountStatus, AdminUserSummary};

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
async fn test_s09_f4_disabled_registration_and_unconfigured_admin_fail_closed() {
    let (_admin_sk, admin_pk) = gen_keypair();

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
}

#[tokio::test]
async fn test_s09_f4_web_registration_email_pow_and_ip_caps() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let admin_secret = "f4-admin-ui-secret";
    let bearer_secret = "f4-api-bearer-secret";

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
}

#[tokio::test]
async fn test_s09_f4_admin_ui_xss_csrf_and_logout_hardening() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let admin_secret = "f4-admin-ui-secret";
    let bearer_secret = "f4-api-bearer-secret";
    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.security.admin_token_hash = hash_admin_token(admin_secret).unwrap();
    cfg.security.api_bearer_token_hash = hash_admin_token(bearer_secret).unwrap();
    let srv = TestServer::start(cfg).await;
    let now = unix_now();
    let (_v6_a_sk, v6_a_pk) = gen_keypair();
    let (_pow_sk, pow_pk) = gen_keypair();
    srv.state
        .db
        .register_or_upgrade_user(&srv.state.config, &v6_a_pk, "free", None, None, "open", now)
        .unwrap();
    srv.state
        .db
        .register_or_upgrade_user(&srv.state.config, &pow_pk, "free", None, None, "pow", now)
        .unwrap();

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
}

#[tokio::test]
async fn test_s09_f4_admin_api_bearer_isolation_downgrade_and_lock_immunity() {
    let (admin_sk, admin_pk) = gen_keypair();
    let admin_secret = "f4-admin-ui-secret";
    let bearer_secret = "f4-api-bearer-secret";
    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.security.admin_token_hash = hash_admin_token(admin_secret).unwrap();
    cfg.security.api_bearer_token_hash = hash_admin_token(bearer_secret).unwrap();
    let srv = TestServer::start(cfg).await;
    let now = unix_now();
    let (_pro_mail_sk, pro_mail_pk) = gen_keypair();
    let (_v6_c_sk, v6_c_pk) = gen_keypair();
    srv.state
        .db
        .register_or_upgrade_user(
            &srv.state.config,
            &pro_mail_pk,
            "pro",
            Some("supporter@example.org"),
            Some(30),
            "email",
            now,
        )
        .unwrap();
    srv.state
        .db
        .register_or_upgrade_user(&srv.state.config, &v6_c_pk, "free", None, None, "open", now)
        .unwrap();
    srv.state
        .db
        .create_redeem_codes(
            &srv.state.config,
            2,
            "pro",
            Some(30),
            1,
            None,
            None,
            None,
            now,
        )
        .unwrap();

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
}

#[tokio::test]
async fn test_s09_f4_admin_login_rate_limit_and_bearer_fallback() {
    let (_admin_sk, admin_pk) = gen_keypair();
    let admin_secret = "f4-admin-ui-secret";

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
