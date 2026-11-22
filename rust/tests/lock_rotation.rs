mod common;
use common::*;

use ed25519_dalek::{Signer, SigningKey};
use humoco_sync_server::crypto::{
    canonical_revocation_message, format_admin_put_revoke_message, random_hex, sha256_hex,
    unix_now, RevocationNotice,
};
use tempfile::TempDir;

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
