mod common;
use common::*;

use ed25519_dalek::{Signer, SigningKey};
use humoco_sync_server::crypto::{
    format_admin_put_members_message, format_delete_account_message, parse_member_message,
    random_hex, sha256_hex, unix_now,
};
use tempfile::TempDir;

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
async fn test_s09_f2_lock_selftest_delegate_and_probe_parity() {
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
    let _bucket = humoco_proto::derive_bucket(&anchor_id, &lock_pub_bytes);

    let (outsider_code, _) = fetch_ticket_signed(&srv, &outsider_sk, anchor_id, quarter).await;
    assert_eq!(outsider_code, 403);
}

#[tokio::test]
async fn test_s09_f2_lock_ticket_batch_split_branches_and_inode_warning() {
    let (admin_sk, admin_pk) = gen_keypair();
    let mut cfg = base_hybrid_config(&admin_pk);
    cfg.lock.max_inodes = 5;
    cfg.lock.allow_pow_tickets = false;
    cfg.lock.pow_base_bits = 8;
    let srv = TestServer::start(cfg).await;
    let lock_pub_bytes = srv.state.db.lock_pubkey_bytes().unwrap();
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
