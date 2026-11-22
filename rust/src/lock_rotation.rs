use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::{Signer, SigningKey};
use humoco_proto::{
    compute_bucket_init_head, compute_bucket_step_head, compute_freeze_state_hash,
    decode_hex_fixed, derive_bucket, derive_slot_file_id, format_quarter, resolve_import_union,
    AnchorManifest, CommitteeSignature, CreatorHeartbeat, FreezeSnapshot, ImportAck, LockEntry,
    LockPubKey, MigrationCert, MigrationProposal, MigrationVeto, ProposalInitiator,
    QuorumCertificate, ResolvedSlot, SnapshotExport, LOCK_ENTRY_WIRE_LEN,
};
use redb::{ReadableTable, ReadableTableMetadata, WriteTransaction};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::db::{
    DbError, SyncDb, LOCK_ANCHORS, LOCK_BUCKETS, LOCK_CONFLICTS, LOCK_ENTRIES, LOCK_FILE_INDEX,
    LOCK_OUTPUT_CLAIMS, LOCK_QUARTER_INDEX, LOCK_ROTATIONS, SERVER_META,
};
use crate::locks::{
    bucket_entry_prefix, bucket_slot_key, file_index_key, load_lock_signing_key_read,
    output_claim_key, quarter_index_key, read_used_inodes, remove_keys_with_prefix,
    BucketFreezeState, LockBucketRecord, LOCK_USED_INODES_META,
};

pub(crate) fn effective_proposal_timelock_secs(
    cfg: &Config,
    active_manifest: &AnchorManifest,
    proposal: &MigrationProposal,
) -> u64 {
    if matches!(proposal.initiator, ProposalInitiator::Creator)
        && active_manifest.authority.guarantor_mig_pubs.is_empty()
        && humoco_proto::is_pure_committee_growth(active_manifest, proposal)
    {
        0
    } else {
        cfg.lock.proposal_timelock_secs
    }
}

pub(crate) struct LockEntryStorageExt;

impl LockEntryStorageExt {
    pub(crate) fn decode_conflict_group(raw: &[u8]) -> Result<Vec<LockEntry>, DbError> {
        let hex_entries: Vec<String> = serde_json::from_slice(raw)?;
        let mut out = Vec::with_capacity(hex_entries.len());
        for hex_s in hex_entries {
            let e = LockEntry::from_wire_hex(&hex_s).map_err(|err| {
                DbError::Backend(format!("Corrupted LOCK_CONFLICTS entry: {err}"))
            })?;
            out.push(e);
        }
        Ok(out)
    }

    pub(crate) fn encode_conflict_group(entries: &[LockEntry]) -> Result<Vec<u8>, DbError> {
        let mut hexes = Vec::with_capacity(entries.len());
        for entry in entries {
            hexes.push(
                entry
                    .to_wire_hex()
                    .map_err(|err| DbError::Backend(format!("Encode LockEntry failed: {err}")))?,
            );
        }
        Ok(serde_json::to_vec(&hexes)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotedProposalRecord {
    pub proposal: MigrationProposal,
    #[serde(with = "humoco_proto::types::serde_hex_32")]
    pub proposal_hash: [u8; 32],
    pub accepted_at: u64,
    pub effective_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedProposalRecord {
    #[serde(with = "humoco_proto::types::serde_hex_32")]
    pub proposal_hash: [u8; 32],
    pub to_rev: u64,
    #[serde(with = "humoco_proto::types::serde_hex_32")]
    pub imported_state_hash: [u8; 32],
    pub acked_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfFrozenOrigin {
    pub frozen_at: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorRotationRecord {
    pub active_manifest: AnchorManifest,
    pub last_creator_activity_secs: u64,
    pub voted_proposals_by_rev: BTreeMap<u64, VotedProposalRecord>,
    pub vetoed_proposal_hashes: Vec<[u8; 32]>,
    pub imported_proposal: Option<ImportedProposalRecord>,
    #[serde(default)]
    pub self_frozen_origin: Option<SelfFrozenOrigin>,
}

impl AnchorRotationRecord {
    pub fn new(active_manifest: AnchorManifest, now_secs: u64) -> Self {
        Self {
            active_manifest,
            last_creator_activity_secs: now_secs,
            voted_proposals_by_rev: BTreeMap::new(),
            vetoed_proposal_hashes: Vec::new(),
            imported_proposal: None,
            self_frozen_origin: None,
        }
    }
}

fn restore_non_proposal_freeze_state(rot: &AnchorRotationRecord) -> BucketFreezeState {
    match &rot.self_frozen_origin {
        Some(sf) => BucketFreezeState::SelfFrozen {
            frozen_at: sf.frozen_at,
            reason: sf.reason.clone(),
        },
        None => BucketFreezeState::Active,
    }
}

fn manifests_share_chain_prefix(existing: &AnchorManifest, incoming: &AnchorManifest) -> bool {
    if incoming.revision < existing.revision {
        return false;
    }
    existing
        .migration_chain
        .iter()
        .zip(&incoming.migration_chain)
        .all(|(e_cert, i_cert)| {
            matches!(
                (e_cert.proposal.core_digest(), i_cert.proposal.core_digest()),
                (Ok(a), Ok(b)) if a == b
            ) && e_cert.imported_state_hash == i_cert.imported_state_hash
        })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum LockFreezeRequest {
    PreFreeze {
        #[serde(with = "humoco_proto::types::serde_hex_32")]
        anchor_id: [u8; 32],
        current_manifest: Option<AnchorManifest>,
    },
    Propose {
        proposal: MigrationProposal,
        current_manifest: Option<AnchorManifest>,
    },
    Veto {
        veto: MigrationVeto,
    },
    Heartbeat {
        heartbeat: CreatorHeartbeat,
        current_manifest: Option<AnchorManifest>,
    },
    FetchSnapshot {
        #[serde(with = "humoco_proto::types::serde_hex_32")]
        anchor_id: [u8; 32],
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct LockImportRequest {
    #[serde(with = "humoco_proto::types::serde_hex_32")]
    pub anchor_id: [u8; 32],
    pub active_manifest: AnchorManifest,
    pub proposal: MigrationProposal,
    pub snapshots: Vec<SnapshotExport>,
    pub quorum_certificates: Vec<QuorumCertificate>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum LockCommitRequest {
    SignCommit {
        #[serde(with = "humoco_proto::types::serde_hex_32")]
        anchor_id: [u8; 32],
        proposal: MigrationProposal,
        #[serde(with = "humoco_proto::types::serde_hex_32")]
        imported_state_hash: [u8; 32],
        import_acks: Vec<ImportAck>,
    },
    Finalize {
        #[serde(with = "humoco_proto::types::serde_hex_32")]
        anchor_id: [u8; 32],
        new_manifest: AnchorManifest,
    },
}

fn export_bucket_entries(
    entries_tbl: &impl ReadableTable<&'static str, &'static [u8]>,
    conflicts_tbl: &impl ReadableTable<&'static str, &'static [u8]>,
    bucket_hex: &str,
) -> Result<(Vec<LockEntry>, Vec<Vec<LockEntry>>), DbError> {
    let prefix = bucket_entry_prefix(bucket_hex);
    let mut entries = Vec::new();
    for item in entries_tbl.iter()? {
        let (k, v) = item?;
        if k.value().starts_with(&prefix) {
            if v.value().len() != LOCK_ENTRY_WIRE_LEN {
                return Err(DbError::Backend(
                    "Corrupted stored LockEntry length during export".to_string(),
                ));
            }
            entries.push(
                LockEntry::from_wire_bytes(v.value())
                    .map_err(|e| DbError::Backend(format!("Corrupted LockEntry: {e}")))?,
            );
        }
    }

    let mut conflicts = Vec::new();
    for item in conflicts_tbl.iter()? {
        let (k, v) = item?;
        if k.value().starts_with(&prefix) {
            conflicts.push(LockEntryStorageExt::decode_conflict_group(v.value())?);
        }
    }

    Ok((entries, conflicts))
}

struct SnapshotFreezeParams {
    from_rev: u64,
    permanent: bool,
    proposal_hash: Option<[u8; 32]>,
    frozen_at: u64,
    expires_at: Option<u64>,
}

fn build_signed_snapshot_export(
    lock_sk: &SigningKey,
    bucket: &LockBucketRecord,
    bucket_hex: &str,
    params: SnapshotFreezeParams,
    entries_tbl: &impl ReadableTable<&'static str, &'static [u8]>,
    conflicts_tbl: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<SnapshotExport, DbError> {
    let lock_pub = lock_sk.verifying_key().to_bytes();
    let expected_bucket = derive_bucket(&bucket.anchor_id, &lock_pub);
    let (entries, conflicts) = export_bucket_entries(entries_tbl, conflicts_tbl, bucket_hex)?;
    let state_hash =
        compute_freeze_state_hash(&bucket.anchor_id, params.from_rev, &entries, &conflicts)
            .map_err(|e| DbError::Backend(format!("compute_freeze_state_hash failed: {e}")))?;

    let mut snap = FreezeSnapshot {
        anchor_id: bucket.anchor_id,
        bucket: expected_bucket,
        from_rev: params.from_rev,
        retain_until_quarter: bucket.retain_until_quarter,
        write_seq: bucket.write_seq,
        bucket_head: bucket.bucket_head,
        state_hash,
        permanent: params.permanent,
        proposal_hash: params.proposal_hash,
        frozen_at: params.frozen_at,
        expires_at: params.expires_at,
        lock_pub,
        sig: [0; 64],
    };
    snap.sig = lock_sk.sign(&snap.digest()).to_bytes();

    let mut hex_entries = Vec::with_capacity(entries.len());
    for e in entries {
        hex_entries.push(
            e.to_wire_hex()
                .map_err(|err| DbError::Backend(err.to_string()))?,
        );
    }
    let mut hex_conflicts = Vec::with_capacity(conflicts.len());
    for group in conflicts {
        let mut g_hex = Vec::with_capacity(group.len());
        for e in group {
            g_hex.push(
                e.to_wire_hex()
                    .map_err(|err| DbError::Backend(err.to_string()))?,
            );
        }
        hex_conflicts.push(g_hex);
    }

    Ok(SnapshotExport {
        snapshot: snap,
        entries: hex_entries,
        conflicts: hex_conflicts,
    })
}

fn bootstrap_bucket_and_rotation_if_supplied(
    cfg: &Config,
    write_txn: &WriteTransaction,
    anchor_id: [u8; 32],
    lock_pub: LockPubKey,
    supplied_manifest: Option<&AnchorManifest>,
    now_secs: u64,
    allow_cold_bootstrap: bool,
) -> Result<(LockBucketRecord, AnchorRotationRecord), DbError> {
    let anchor_hex = hex::encode(anchor_id);
    let bucket = derive_bucket(&anchor_id, &lock_pub);
    let bucket_hex = hex::encode(bucket);

    let mut buckets = write_txn.open_table(LOCK_BUCKETS)?;
    let mut quarter_idx = write_txn.open_table(LOCK_QUARTER_INDEX)?;
    let mut rotations_tbl = write_txn.open_table(LOCK_ROTATIONS)?;
    let mut anchors_tbl = write_txn.open_table(LOCK_ANCHORS)?;
    let meta = write_txn.open_table(SERVER_META)?;

    let existing_rot: Option<AnchorRotationRecord> = match rotations_tbl.get(anchor_hex.as_str())? {
        Some(g) => Some(serde_json::from_slice(g.value())?),
        None => None,
    };
    let existing_bucket: Option<LockBucketRecord> = match buckets.get(bucket_hex.as_str())? {
        Some(g) => Some(serde_json::from_slice(g.value())?),
        None => None,
    };

    if let (Some(mut b), Some(rot)) = (existing_bucket.clone(), existing_rot) {
        if let BucketFreezeState::PreProposal { expires_at, .. } = b.freeze_state {
            if now_secs >= expires_at {
                b.freeze_state = BucketFreezeState::Active;
                let bytes = serde_json::to_vec(&b)?;
                buckets.insert(bucket_hex.as_str(), bytes.as_slice())?;
            }
        }
        return Ok((b, rot));
    }

    if existing_bucket.is_none() && !allow_cold_bootstrap {
        return Err(DbError::http(
            404,
            "Anchor bucket not initialized on this server",
        ));
    }

    let manifest = supplied_manifest
        .ok_or_else(|| DbError::http(404, "Anchor bucket not initialized on this server"))?;
    manifest
        .verify_anchor_id(&anchor_id)
        .map_err(|e| DbError::http(400, format!("Invalid current_manifest: {e}")))?;
    let committee = manifest.committee().map_err(|e| DbError::http(400, e))?;
    if !committee.contains(&lock_pub) {
        return Err(DbError::http(
            400,
            "Server lock_pub is not a member of active manifest",
        ));
    }
    if manifest.retain_until_quarter > cfg.lock.max_retention_quarter {
        return Err(DbError::http(
            422,
            "Manifest retain_until_quarter exceeds server limit",
        ));
    }

    let b = match existing_bucket {
        Some(b) => b,
        None => {
            if buckets.len()? >= cfg.lock.max_buckets {
                return Err(DbError::http(507, "Lock bucket budget exhausted"));
            }
            let used_inodes = read_used_inodes(&meta)?;
            if used_inodes >= cfg.lock.max_inodes {
                return Err(DbError::http(507, "Lock inode budget exhausted"));
            }
            let nb = LockBucketRecord {
                anchor_id,
                retain_until_quarter: manifest.retain_until_quarter,
                creator_mig_pub: manifest.authority.creator_mig_pub,
                write_seq: 0,
                bucket_head: compute_bucket_init_head(&bucket, manifest.retain_until_quarter),
                freeze_state: BucketFreezeState::Active,
            };
            let b_bytes = serde_json::to_vec(&nb)?;
            buckets.insert(bucket_hex.as_str(), b_bytes.as_slice())?;
            quarter_idx.insert(
                quarter_index_key(nb.retain_until_quarter, &bucket_hex).as_str(),
                &[] as &[u8],
            )?;
            nb
        }
    };

    let rot_raw = rotations_tbl
        .get(anchor_hex.as_str())?
        .map(|g| g.value().to_vec());
    let rot = match rot_raw {
        Some(bytes) => serde_json::from_slice::<AnchorRotationRecord>(&bytes)?,
        None => {
            let init_activity = (manifest.issued_at_ms / 1_000).min(now_secs);
            let nr = AnchorRotationRecord::new(manifest.clone(), init_activity);
            let nr_bytes = serde_json::to_vec(&nr)?;
            rotations_tbl.insert(anchor_hex.as_str(), nr_bytes.as_slice())?;
            let m_bytes = serde_json::to_vec(manifest)?;
            anchors_tbl.insert(anchor_hex.as_str(), m_bytes.as_slice())?;
            nr
        }
    };

    Ok((b, rot))
}

impl SyncDb {
    pub fn get_lock_freeze_status(
        &self,
        cfg: &Config,
        anchor_id: [u8; 32],
        now_secs: u64,
    ) -> Result<serde_json::Value, DbError> {
        if !cfg.lock.enabled {
            return Err(DbError::http(404, "Lock channel is disabled"));
        }
        let read_txn = self.raw_db().begin_read()?;
        let meta = read_txn.open_table(SERVER_META)?;
        let lock_sk = load_lock_signing_key_read(&meta)?;
        let lock_pub = lock_sk.verifying_key().to_bytes();
        let bucket = derive_bucket(&anchor_id, &lock_pub);
        let bucket_hex = hex::encode(bucket);
        let anchor_hex = hex::encode(anchor_id);

        let buckets = read_txn.open_table(LOCK_BUCKETS)?;
        let entries_tbl = read_txn.open_table(LOCK_ENTRIES)?;
        let conflicts_tbl = read_txn.open_table(LOCK_CONFLICTS)?;
        let rotations_tbl = read_txn.open_table(LOCK_ROTATIONS)?;

        let rot_opt: Option<AnchorRotationRecord> = match rotations_tbl.get(anchor_hex.as_str())? {
            Some(g) => Some(serde_json::from_slice(g.value())?),
            None => None,
        };
        let bucket_opt: Option<LockBucketRecord> = match buckets.get(bucket_hex.as_str())? {
            Some(g) => {
                let mut b: LockBucketRecord = serde_json::from_slice(g.value())?;
                if let BucketFreezeState::PreProposal { expires_at, .. } = b.freeze_state {
                    if now_secs >= expires_at {
                        b.freeze_state = BucketFreezeState::Active;
                    }
                }
                Some(b)
            }
            None => None,
        };

        let Some(ref b) = bucket_opt else {
            return Err(DbError::http(404, "Lock bucket not found on this server"));
        };
        let rev = rot_opt
            .as_ref()
            .map(|r| r.active_manifest.revision)
            .unwrap_or(1);
        let voted = rot_opt
            .as_ref()
            .and_then(|r| r.voted_proposals_by_rev.get(&rev))
            .map(|vp| vp.proposal.clone());

        let snapshot_export = match &b.freeze_state {
            BucketFreezeState::PreProposal {
                frozen_at,
                expires_at,
            } if now_secs < *expires_at => Some(build_signed_snapshot_export(
                &lock_sk,
                b,
                &bucket_hex,
                SnapshotFreezeParams {
                    from_rev: rev,
                    permanent: false,
                    proposal_hash: None,
                    frozen_at: *frozen_at,
                    expires_at: Some(*expires_at),
                },
                &entries_tbl,
                &conflicts_tbl,
            )?),
            BucketFreezeState::PermanentProposal {
                from_rev,
                proposal_hash,
                frozen_at,
                ..
            } => Some(build_signed_snapshot_export(
                &lock_sk,
                b,
                &bucket_hex,
                SnapshotFreezeParams {
                    from_rev: *from_rev,
                    permanent: true,
                    proposal_hash: Some(*proposal_hash),
                    frozen_at: *frozen_at,
                    expires_at: None,
                },
                &entries_tbl,
                &conflicts_tbl,
            )?),
            _ => None,
        };

        Ok(serde_json::json!({
            "anchor_id": anchor_hex,
            "bucket": bucket_hex,
            "active_manifest": rot_opt.as_ref().map(|r| &r.active_manifest),
            "last_creator_activity_secs": rot_opt.as_ref().map(|r| r.last_creator_activity_secs),
            "bucket_freeze_state": b.freeze_state,
            "voted_proposal": voted,
            "snapshot_export": snapshot_export,
        }))
    }

    pub fn process_lock_freeze(
        &self,
        cfg: &Config,
        req: LockFreezeRequest,
        now_secs: u64,
    ) -> Result<(u16, serde_json::Value), DbError> {
        if !cfg.lock.enabled {
            return Err(DbError::http(404, "Lock channel is disabled"));
        }
        let lock_sk = {
            let rt = self.raw_db().begin_read()?;
            let meta = rt.open_table(SERVER_META)?;
            load_lock_signing_key_read(&meta)?
        };
        let lock_pub = lock_sk.verifying_key().to_bytes();

        match req {
            LockFreezeRequest::FetchSnapshot { anchor_id } => {
                let status = self.get_lock_freeze_status(cfg, anchor_id, now_secs)?;
                Ok((200, status))
            }
            LockFreezeRequest::PreFreeze {
                anchor_id,
                current_manifest,
            } => {
                let bucket_hex = hex::encode(derive_bucket(&anchor_id, &lock_pub));
                let write_txn = self.raw_db().begin_write()?;
                let (mut bucket, rot) = bootstrap_bucket_and_rotation_if_supplied(
                    cfg,
                    &write_txn,
                    anchor_id,
                    lock_pub,
                    current_manifest.as_ref(),
                    now_secs,
                    false,
                )?;
                {
                    let mut buckets = write_txn.open_table(LOCK_BUCKETS)?;
                    let entries_tbl = write_txn.open_table(LOCK_ENTRIES)?;
                    let conflicts_tbl = write_txn.open_table(LOCK_CONFLICTS)?;

                    match &bucket.freeze_state {
                        BucketFreezeState::EpochFrozen { .. } => {
                            return Err(DbError::http(409, "epoch_frozen"));
                        }
                        BucketFreezeState::PermanentProposal { .. } => {
                            return Err(DbError::http(409, "proposal_frozen"));
                        }
                        BucketFreezeState::PreProposal {
                            frozen_at,
                            expires_at,
                        } if now_secs < *expires_at => {
                            let export = build_signed_snapshot_export(
                                &lock_sk,
                                &bucket,
                                &bucket_hex,
                                SnapshotFreezeParams {
                                    from_rev: rot.active_manifest.revision,
                                    permanent: false,
                                    proposal_hash: None,
                                    frozen_at: *frozen_at,
                                    expires_at: Some(*expires_at),
                                },
                                &entries_tbl,
                                &conflicts_tbl,
                            )?;
                            return Ok((
                                200,
                                serde_json::json!({
                                    "status": "pre_frozen",
                                    "expires_at": *expires_at,
                                    "snapshot_export": export,
                                }),
                            ));
                        }
                        BucketFreezeState::SelfFrozen { .. } => {
                            return Err(DbError::http(
                                409,
                                "Bucket is self_frozen; submit a signed Propose directly to rotate",
                            ));
                        }
                        BucketFreezeState::Active | BucketFreezeState::PreProposal { .. } => {}
                    }

                    let expires_at = now_secs.saturating_add(cfg.lock.pre_freeze_ttl_secs);
                    bucket.freeze_state = BucketFreezeState::PreProposal {
                        frozen_at: now_secs,
                        expires_at,
                    };
                    let b_bytes = serde_json::to_vec(&bucket)?;
                    buckets.insert(bucket_hex.as_str(), b_bytes.as_slice())?;

                    let export = build_signed_snapshot_export(
                        &lock_sk,
                        &bucket,
                        &bucket_hex,
                        SnapshotFreezeParams {
                            from_rev: rot.active_manifest.revision,
                            permanent: false,
                            proposal_hash: None,
                            frozen_at: now_secs,
                            expires_at: Some(expires_at),
                        },
                        &entries_tbl,
                        &conflicts_tbl,
                    )?;
                    drop((buckets, entries_tbl, conflicts_tbl));
                    write_txn.commit()?;
                    Ok((
                        200,
                        serde_json::json!({
                            "status": "pre_frozen",
                            "expires_at": expires_at,
                            "snapshot_export": export,
                        }),
                    ))
                }
            }
            LockFreezeRequest::Heartbeat {
                heartbeat,
                current_manifest,
            } => {
                if heartbeat.timestamp_secs > now_secs.saturating_add(60) {
                    return Err(DbError::http(400, "Heartbeat timestamp is in the future"));
                }
                let anchor_hex = hex::encode(heartbeat.anchor_id);
                let write_txn = self.raw_db().begin_write()?;
                let (_b, mut rot) = bootstrap_bucket_and_rotation_if_supplied(
                    cfg,
                    &write_txn,
                    heartbeat.anchor_id,
                    lock_pub,
                    current_manifest.as_ref(),
                    now_secs,
                    true,
                )?;
                if !heartbeat.verify(&rot.active_manifest.authority.creator_mig_pub) {
                    return Err(DbError::http(401, "Invalid CreatorHeartbeat signature"));
                }
                rot.last_creator_activity_secs =
                    rot.last_creator_activity_secs.max(heartbeat.timestamp_secs);
                {
                    let mut rotations_tbl = write_txn.open_table(LOCK_ROTATIONS)?;
                    let r_bytes = serde_json::to_vec(&rot)?;
                    rotations_tbl.insert(anchor_hex.as_str(), r_bytes.as_slice())?;
                }
                write_txn.commit()?;
                Ok((
                    200,
                    serde_json::json!({
                        "status": "heartbeat_recorded",
                        "last_creator_activity_secs": rot.last_creator_activity_secs,
                    }),
                ))
            }
            LockFreezeRequest::Propose {
                proposal,
                current_manifest,
            } => {
                let anchor_id = proposal.anchor_id;
                let anchor_hex = hex::encode(anchor_id);
                let bucket_hex = hex::encode(derive_bucket(&anchor_id, &lock_pub));
                let prop_hash = proposal.core_digest().map_err(|e| DbError::http(400, e))?;

                let write_txn = self.raw_db().begin_write()?;
                let (mut bucket, mut rot) = bootstrap_bucket_and_rotation_if_supplied(
                    cfg,
                    &write_txn,
                    anchor_id,
                    lock_pub,
                    current_manifest.as_ref(),
                    now_secs,
                    true,
                )?;

                if matches!(bucket.freeze_state, BucketFreezeState::EpochFrozen { .. }) {
                    return Err(DbError::http(409, "epoch_frozen"));
                }
                if rot.vetoed_proposal_hashes.contains(&prop_hash) {
                    return Err(DbError::http(409, "Proposal was previously vetoed"));
                }
                if proposal.from_rev != rot.active_manifest.revision {
                    return Err(DbError::http(409, "Manifest revision mismatch"));
                }

                // Single-proposal lock (`voted_proposal[rev]`)
                if let Some(existing_vp) = rot.voted_proposals_by_rev.get(&proposal.from_rev) {
                    if existing_vp.proposal_hash == prop_hash {
                        let frozen_at = match bucket.freeze_state {
                            BucketFreezeState::PermanentProposal { frozen_at, .. } => frozen_at,
                            _ => existing_vp.accepted_at,
                        };
                        let entries_tbl = write_txn.open_table(LOCK_ENTRIES)?;
                        let conflicts_tbl = write_txn.open_table(LOCK_CONFLICTS)?;
                        let export = build_signed_snapshot_export(
                            &lock_sk,
                            &bucket,
                            &bucket_hex,
                            SnapshotFreezeParams {
                                from_rev: proposal.from_rev,
                                permanent: true,
                                proposal_hash: Some(prop_hash),
                                frozen_at,
                                expires_at: None,
                            },
                            &entries_tbl,
                            &conflicts_tbl,
                        )?;
                        return Ok((
                            200,
                            serde_json::json!({
                                "status": "proposed",
                                "proposal_hash": hex::encode(prop_hash),
                                "effective_at": existing_vp.effective_at,
                                "snapshot_export": export,
                            }),
                        ));
                    } else {
                        return Err(DbError::http(
                            409,
                            "A conflicting proposal is already locked in voted_proposal[rev]",
                        ));
                    }
                }

                if proposal.proposed_at > now_secs.saturating_add(60)
                    || now_secs.saturating_sub(proposal.proposed_at) > 3600
                {
                    return Err(DbError::http(
                        400,
                        "Proposal proposed_at outside fresh 3600s submission window",
                    ));
                }

                proposal
                    .verify_against_manifest(&anchor_id, &rot.active_manifest)
                    .map_err(|e| DbError::http(400, format!("Proposal validation failed: {e}")))?;

                if let ProposalInitiator::Guarantor { .. } = proposal.initiator {
                    let threshold = rot
                        .last_creator_activity_secs
                        .saturating_add(cfg.lock.creator_inactivity_secs);
                    if now_secs < threshold {
                        return Err(DbError::http(
                            403,
                            "Creator 30-day inactivity window has not elapsed yet",
                        ));
                    }
                } else if matches!(proposal.initiator, ProposalInitiator::Creator) {
                    rot.last_creator_activity_secs = rot.last_creator_activity_secs.max(now_secs);
                }

                let timelock_secs =
                    effective_proposal_timelock_secs(cfg, &rot.active_manifest, &proposal);
                let effective_at = now_secs.saturating_add(timelock_secs);
                rot.voted_proposals_by_rev.insert(
                    proposal.from_rev,
                    VotedProposalRecord {
                        proposal: proposal.clone(),
                        proposal_hash: prop_hash,
                        accepted_at: now_secs,
                        effective_at,
                    },
                );
                if let BucketFreezeState::SelfFrozen {
                    frozen_at,
                    ref reason,
                } = bucket.freeze_state
                {
                    rot.self_frozen_origin = Some(SelfFrozenOrigin {
                        frozen_at,
                        reason: reason.clone(),
                    });
                }
                bucket.freeze_state = BucketFreezeState::PermanentProposal {
                    from_rev: proposal.from_rev,
                    proposal_hash: prop_hash,
                    frozen_at: now_secs,
                    effective_at,
                };

                let export = {
                    let mut buckets = write_txn.open_table(LOCK_BUCKETS)?;
                    let mut rotations_tbl = write_txn.open_table(LOCK_ROTATIONS)?;
                    let entries_tbl = write_txn.open_table(LOCK_ENTRIES)?;
                    let conflicts_tbl = write_txn.open_table(LOCK_CONFLICTS)?;

                    buckets.insert(bucket_hex.as_str(), serde_json::to_vec(&bucket)?.as_slice())?;
                    rotations_tbl
                        .insert(anchor_hex.as_str(), serde_json::to_vec(&rot)?.as_slice())?;

                    build_signed_snapshot_export(
                        &lock_sk,
                        &bucket,
                        &bucket_hex,
                        SnapshotFreezeParams {
                            from_rev: proposal.from_rev,
                            permanent: true,
                            proposal_hash: Some(prop_hash),
                            frozen_at: now_secs,
                            expires_at: None,
                        },
                        &entries_tbl,
                        &conflicts_tbl,
                    )?
                };
                write_txn.commit()?;

                Ok((
                    200,
                    serde_json::json!({
                        "status": "proposed",
                        "proposal_hash": hex::encode(prop_hash),
                        "effective_at": effective_at,
                        "snapshot_export": export,
                    }),
                ))
            }
            LockFreezeRequest::Veto { veto } => {
                if veto.vetoed_at > now_secs.saturating_add(60) {
                    return Err(DbError::http(400, "Veto timestamp is in the future"));
                }
                let anchor_hex = hex::encode(veto.anchor_id);
                let bucket_hex = hex::encode(derive_bucket(&veto.anchor_id, &lock_pub));
                let write_txn = self.raw_db().begin_write()?;
                {
                    let mut buckets = write_txn.open_table(LOCK_BUCKETS)?;
                    let mut rotations_tbl = write_txn.open_table(LOCK_ROTATIONS)?;

                    let mut rot: AnchorRotationRecord = match rotations_tbl
                        .get(anchor_hex.as_str())?
                    {
                        Some(g) => serde_json::from_slice(g.value())?,
                        None => return Err(DbError::http(404, "Anchor rotation record not found")),
                    };
                    let mut bucket: LockBucketRecord = match buckets.get(bucket_hex.as_str())? {
                        Some(g) => serde_json::from_slice(g.value())?,
                        None => return Err(DbError::http(404, "Lock bucket not found")),
                    };

                    if matches!(bucket.freeze_state, BucketFreezeState::EpochFrozen { .. }) {
                        return Err(DbError::http(409, "epoch_frozen"));
                    }
                    if veto.from_rev != rot.active_manifest.revision {
                        return Err(DbError::http(409, "Manifest revision mismatch"));
                    }

                    let Some(vp) = rot.voted_proposals_by_rev.get(&veto.from_rev).cloned() else {
                        return Err(DbError::http(404, "No pending proposal in this revision"));
                    };
                    if vp.proposal_hash != veto.proposal_hash {
                        return Err(DbError::http(409, "Veto proposal_hash mismatch"));
                    }
                    if now_secs >= vp.effective_at {
                        return Err(DbError::http(
                            409,
                            "Proposal 72h timelock already expired; veto window closed",
                        ));
                    }

                    veto.verify(&rot.active_manifest.authority, &vp.proposal.initiator)
                        .map_err(|e| {
                            DbError::http(401, format!("Veto verification failed: {e}"))
                        })?;

                    if veto.vetoer_pub == rot.active_manifest.authority.creator_mig_pub {
                        rot.last_creator_activity_secs =
                            rot.last_creator_activity_secs.max(now_secs);
                    }
                    rot.voted_proposals_by_rev.remove(&veto.from_rev);
                    if !rot.vetoed_proposal_hashes.contains(&veto.proposal_hash) {
                        rot.vetoed_proposal_hashes.push(veto.proposal_hash);
                    }
                    if matches!(
                        bucket.freeze_state,
                        BucketFreezeState::PermanentProposal { .. }
                    ) {
                        bucket.freeze_state = restore_non_proposal_freeze_state(&rot);
                    }

                    buckets.insert(bucket_hex.as_str(), serde_json::to_vec(&bucket)?.as_slice())?;
                    rotations_tbl
                        .insert(anchor_hex.as_str(), serde_json::to_vec(&rot)?.as_slice())?;
                }
                write_txn.commit()?;

                Ok((
                    200,
                    serde_json::json!({
                        "status": "vetoed",
                        "proposal_hash": hex::encode(veto.proposal_hash),
                    }),
                ))
            }
        }
    }

    pub fn process_lock_import(
        &self,
        cfg: &Config,
        req: LockImportRequest,
        now_secs: u64,
    ) -> Result<(u16, serde_json::Value), DbError> {
        if !cfg.lock.enabled {
            return Err(DbError::http(404, "Lock channel is disabled"));
        }
        let lock_sk = {
            let rt = self.raw_db().begin_read()?;
            let meta = rt.open_table(SERVER_META)?;
            load_lock_signing_key_read(&meta)?
        };
        let lock_pub = lock_sk.verifying_key().to_bytes();

        req.active_manifest
            .verify_anchor_id(&req.anchor_id)
            .map_err(|e| DbError::http(400, format!("Invalid active_manifest chain: {e}")))?;
        let new_committee = req
            .proposal
            .new_committee()
            .map_err(|e| DbError::http(400, e))?;
        if !new_committee.contains(&lock_pub) {
            return Err(DbError::http(
                400,
                "Target server lock_pub is not in proposal.new_servers",
            ));
        }
        if req.proposal.retain_until_quarter > cfg.lock.max_retention_quarter {
            return Err(DbError::http(
                422,
                "Proposal retain_until_quarter exceeds server max_retention_quarter",
            ));
        }
        let timelock_secs =
            effective_proposal_timelock_secs(cfg, &req.active_manifest, &req.proposal);
        if now_secs < req.proposal.proposed_at.saturating_add(timelock_secs) {
            return Err(DbError::http(
                409,
                "Proposal 72h timelock has not elapsed yet",
            ));
        }

        let prop_hash = req
            .proposal
            .core_digest()
            .map_err(|e| DbError::http(400, e))?;
        let union = resolve_import_union(
            &req.anchor_id,
            &req.active_manifest,
            &req.proposal,
            &req.snapshots,
            &req.quorum_certificates,
            cfg.lock.pow_base_bits,
        )
        .map_err(|e| DbError::http(400, format!("Import union validation failed: {e}")))?;

        let matured_snaps = req
            .snapshots
            .iter()
            .filter(|e| now_secs >= e.snapshot.frozen_at.saturating_add(timelock_secs))
            .count();
        if matured_snaps < usize::from(req.active_manifest.threshold) {
            return Err(DbError::http(
                409,
                "Proposal 72h timelock has not elapsed across Q_old freeze snapshots",
            ));
        }

        let bucket = derive_bucket(&req.anchor_id, &lock_pub);
        let bucket_hex = hex::encode(bucket);
        let anchor_hex = hex::encode(req.anchor_id);
        let quarter_str = format_quarter(req.proposal.retain_until_quarter)
            .map_err(|e| DbError::Backend(e.to_string()))?;

        let write_txn = self.raw_db().begin_write()?;
        let ack = {
            let mut meta = write_txn.open_table(SERVER_META)?;
            let mut buckets = write_txn.open_table(LOCK_BUCKETS)?;
            let mut entries_tbl = write_txn.open_table(LOCK_ENTRIES)?;
            let mut conflicts_tbl = write_txn.open_table(LOCK_CONFLICTS)?;
            let mut claims_tbl = write_txn.open_table(LOCK_OUTPUT_CLAIMS)?;
            let mut file_idx = write_txn.open_table(LOCK_FILE_INDEX)?;
            let mut quarter_idx = write_txn.open_table(LOCK_QUARTER_INDEX)?;
            let mut rotations_tbl = write_txn.open_table(LOCK_ROTATIONS)?;
            let mut anchors_tbl = write_txn.open_table(LOCK_ANCHORS)?;

            let mut rot: AnchorRotationRecord = match rotations_tbl.get(anchor_hex.as_str())? {
                Some(g) => {
                    let existing: AnchorRotationRecord = serde_json::from_slice(g.value())?;
                    if req.proposal.to_rev <= existing.active_manifest.revision {
                        return Err(DbError::http(
                            409,
                            "Target revision has already been finalized",
                        ));
                    }
                    if !manifests_share_chain_prefix(
                        &existing.active_manifest,
                        &req.active_manifest,
                    ) {
                        return Err(DbError::http(
                            409,
                            "Active manifest conflicts with finalized history on this server",
                        ));
                    }
                    existing
                }
                None => AnchorRotationRecord::new(
                    req.active_manifest.clone(),
                    (req.active_manifest.issued_at_ms / 1_000).min(now_secs),
                ),
            };

            if rot.vetoed_proposal_hashes.contains(&prop_hash) {
                return Err(DbError::http(409, "Proposal was vetoed on this server"));
            }

            if let Some(ref existing_imp) = rot.imported_proposal {
                if existing_imp.proposal_hash == prop_hash
                    && existing_imp.to_rev == req.proposal.to_rev
                    && existing_imp.imported_state_hash == union.imported_state_hash
                {
                    let mut ack = ImportAck {
                        anchor_id: req.anchor_id,
                        proposal_hash: prop_hash,
                        to_rev: req.proposal.to_rev,
                        imported_state_hash: union.imported_state_hash,
                        retain_until_quarter: req.proposal.retain_until_quarter,
                        lock_pub,
                        acked_at: existing_imp.acked_at,
                        sig: [0; 64],
                    };
                    ack.sig = lock_sk.sign(&ack.digest()).to_bytes();
                    return Ok((
                        200,
                        serde_json::json!({
                            "status": "imported",
                            "import_ack": ack,
                            "imported_slots": union.slots.len(),
                        }),
                    ));
                }
            }

            let prev_bucket: Option<LockBucketRecord> = match buckets.get(bucket_hex.as_str())? {
                Some(g) => Some(serde_json::from_slice(g.value())?),
                None => None,
            };
            if prev_bucket.is_none() && buckets.len()? >= cfg.lock.max_buckets {
                return Err(DbError::http(507, "Lock bucket budget exhausted"));
            }

            let mut used_inodes = read_used_inodes(&meta)?;
            let prefix = bucket_entry_prefix(&bucket_hex);
            let removed_single = remove_keys_with_prefix(&mut entries_tbl, &prefix)?;
            let removed_conf = remove_keys_with_prefix(&mut conflicts_tbl, &prefix)?;
            let _ = remove_keys_with_prefix(&mut claims_tbl, &prefix)?;
            let f_prefix = format!("{}/{}/", quarter_str, bucket_hex);
            let _ = remove_keys_with_prefix(&mut file_idx, &f_prefix)?;

            let old_inodes = (removed_single.len() + removed_conf.len()) as u64;
            let new_inodes = union.slots.len() as u64;
            used_inodes = used_inodes.saturating_sub(old_inodes);
            if new_inodes > 0
                && used_inodes.saturating_add(new_inodes) > cfg.lock.max_inodes
                && prev_bucket.is_none()
                && used_inodes >= cfg.lock.max_inodes
            {
                return Err(DbError::http(507, "Lock inode budget exhausted"));
            }

            // Preserve monotonic (write_seq, bucket_head) across rotation on existing buckets so
            // pre-rotation signed LockReceipts cannot falsely trigger 409 bucket_self_frozen.
            let mut prev_single_hashes: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
            if prev_bucket.is_some() {
                for (_, wire) in &removed_single {
                    if let Ok(entry) = LockEntry::from_wire_bytes(wire) {
                        if let Ok(eh) = entry.entry_hash() {
                            prev_single_hashes.insert(entry.slot, eh);
                        }
                    }
                }
            }

            let (mut write_seq, mut bucket_head) = match prev_bucket.as_ref() {
                Some(prev_b) => (prev_b.write_seq, prev_b.bucket_head),
                None => (
                    0u64,
                    compute_bucket_init_head(&bucket, req.proposal.retain_until_quarter),
                ),
            };

            for (slot, resolved) in &union.slots {
                let slot_hex = hex::encode(slot);
                let e_key = bucket_slot_key(&bucket_hex, &slot_hex);
                match resolved {
                    ResolvedSlot::Single(entry) => {
                        let wire = entry
                            .to_wire_bytes()
                            .map_err(|e| DbError::Backend(e.to_string()))?;
                        let eh = entry
                            .entry_hash()
                            .map_err(|e| DbError::Backend(e.to_string()))?;
                        entries_tbl.insert(e_key.as_str(), wire.as_slice())?;
                        let file_hex = hex::encode(derive_slot_file_id(slot, &lock_pub));
                        let f_key = file_index_key(&quarter_str, &bucket_hex, &file_hex);
                        file_idx.insert(f_key.as_str(), e_key.as_bytes())?;
                        let unchanged_slot = prev_single_hashes
                            .get(slot)
                            .is_some_and(|prev_eh| *prev_eh == eh);
                        if !unchanged_slot {
                            write_seq = write_seq.saturating_add(1);
                            bucket_head =
                                compute_bucket_step_head(&bucket_head, write_seq, slot, &eh);
                        }
                    }
                    ResolvedSlot::Conflict(group) => {
                        let encoded = LockEntryStorageExt::encode_conflict_group(group)?;
                        conflicts_tbl.insert(e_key.as_str(), encoded.as_slice())?;
                    }
                }
            }

            for ((parent_slot, branch), child_slot) in &union.output_claims {
                let claim_k = output_claim_key(&bucket_hex, &hex::encode(parent_slot), *branch);
                claims_tbl.insert(claim_k.as_str(), child_slot.as_slice())?;
            }

            used_inodes = used_inodes.saturating_add(new_inodes);

            // Preserve PermanentProposal/SelfFrozen freeze state if this server is ALSO in OldCommittee
            // until Phase 3 (?lock_commit Finalize) switches epoch; pure new target starts Active.
            let freeze_state = match prev_bucket {
                Some(prev_b) => match prev_b.freeze_state {
                    BucketFreezeState::SelfFrozen { .. }
                    | BucketFreezeState::PermanentProposal { .. }
                    | BucketFreezeState::EpochFrozen { .. } => prev_b.freeze_state,
                    BucketFreezeState::PreProposal { expires_at, .. } if now_secs < expires_at => {
                        prev_b.freeze_state
                    }
                    BucketFreezeState::Active | BucketFreezeState::PreProposal { .. } => {
                        BucketFreezeState::Active
                    }
                },
                None => BucketFreezeState::Active,
            };

            let updated_bucket = LockBucketRecord {
                anchor_id: req.anchor_id,
                retain_until_quarter: req.proposal.retain_until_quarter,
                creator_mig_pub: req.active_manifest.authority.creator_mig_pub,
                write_seq,
                bucket_head,
                freeze_state,
            };
            buckets.insert(
                bucket_hex.as_str(),
                serde_json::to_vec(&updated_bucket)?.as_slice(),
            )?;
            quarter_idx.insert(
                quarter_index_key(updated_bucket.retain_until_quarter, &bucket_hex).as_str(),
                &[] as &[u8],
            )?;
            meta.insert(LOCK_USED_INODES_META, used_inodes.to_le_bytes().as_slice())?;

            rot.imported_proposal = Some(ImportedProposalRecord {
                proposal_hash: prop_hash,
                to_rev: req.proposal.to_rev,
                imported_state_hash: union.imported_state_hash,
                acked_at: now_secs,
            });
            rotations_tbl.insert(anchor_hex.as_str(), serde_json::to_vec(&rot)?.as_slice())?;
            if anchors_tbl.get(anchor_hex.as_str())?.is_none() {
                anchors_tbl.insert(
                    anchor_hex.as_str(),
                    serde_json::to_vec(&req.active_manifest)?.as_slice(),
                )?;
            }

            let mut ack = ImportAck {
                anchor_id: req.anchor_id,
                proposal_hash: prop_hash,
                to_rev: req.proposal.to_rev,
                imported_state_hash: union.imported_state_hash,
                retain_until_quarter: req.proposal.retain_until_quarter,
                lock_pub,
                acked_at: now_secs,
                sig: [0; 64],
            };
            ack.sig = lock_sk.sign(&ack.digest()).to_bytes();
            ack
        };
        write_txn.commit()?;

        Ok((
            200,
            serde_json::json!({
                "status": "imported",
                "import_ack": ack,
                "imported_slots": union.slots.len(),
            }),
        ))
    }

    pub fn process_lock_commit(
        &self,
        cfg: &Config,
        req: LockCommitRequest,
        now_secs: u64,
    ) -> Result<(u16, serde_json::Value), DbError> {
        if !cfg.lock.enabled {
            return Err(DbError::http(404, "Lock channel is disabled"));
        }
        let lock_sk = {
            let rt = self.raw_db().begin_read()?;
            let meta = rt.open_table(SERVER_META)?;
            load_lock_signing_key_read(&meta)?
        };
        let lock_pub = lock_sk.verifying_key().to_bytes();

        match req {
            LockCommitRequest::SignCommit {
                anchor_id,
                proposal,
                imported_state_hash,
                import_acks,
            } => {
                if proposal.anchor_id != anchor_id {
                    return Err(DbError::http(400, "proposal.anchor_id mismatch"));
                }
                let anchor_hex = hex::encode(anchor_id);
                let prop_hash = proposal.core_digest().map_err(|e| DbError::http(400, e))?;

                let read_txn = self.raw_db().begin_read()?;
                let rotations_tbl = read_txn.open_table(LOCK_ROTATIONS)?;
                let Some(g) = rotations_tbl.get(anchor_hex.as_str())? else {
                    return Err(DbError::http(404, "Anchor rotation record not found"));
                };
                let rot: AnchorRotationRecord = serde_json::from_slice(g.value())?;
                if rot.active_manifest.revision != proposal.from_rev {
                    return Err(DbError::http(409, "Manifest revision mismatch"));
                }
                let prev_committee = rot
                    .active_manifest
                    .committee()
                    .map_err(|e| DbError::Backend(e.to_string()))?;
                if !prev_committee.contains(&lock_pub) {
                    return Err(DbError::http(
                        400,
                        "This server is not a member of previous committee",
                    ));
                }
                let Some(vp) = rot.voted_proposals_by_rev.get(&proposal.from_rev) else {
                    return Err(DbError::http(
                        409,
                        "Proposal was not locked in voted_proposal[rev]",
                    ));
                };
                if vp.proposal_hash != prop_hash {
                    return Err(DbError::http(
                        409,
                        "Proposal does not match voted_proposal[rev]",
                    ));
                }
                let timelock_secs =
                    effective_proposal_timelock_secs(cfg, &rot.active_manifest, &proposal);
                if timelock_secs > 0 && now_secs < vp.effective_at {
                    return Err(DbError::http(
                        409,
                        "Proposal 72h timelock has not elapsed yet",
                    ));
                }

                let new_committee = proposal
                    .new_committee()
                    .map_err(|e| DbError::http(400, e))?;
                if import_acks.len() != new_committee.members.len() {
                    return Err(DbError::http(
                        400,
                        "import_acks must cover every target server in new_servers",
                    ));
                }
                let mut seen_targets = std::collections::HashSet::new();
                for ack in &import_acks {
                    if ack.anchor_id != anchor_id
                        || ack.proposal_hash != prop_hash
                        || ack.to_rev != proposal.to_rev
                        || ack.imported_state_hash != imported_state_hash
                        || ack.retain_until_quarter != proposal.retain_until_quarter
                        || !new_committee.contains(&ack.lock_pub)
                        || !ack.verify()
                        || !seen_targets.insert(ack.lock_pub)
                    {
                        return Err(DbError::http(401, "Invalid or incomplete ImportAck"));
                    }
                }

                let commit_digest = MigrationCert::commit_digest(
                    &anchor_id,
                    &prop_hash,
                    proposal.to_rev,
                    &imported_state_hash,
                );
                let sig = lock_sk.sign(&commit_digest).to_bytes();
                let cs = CommitteeSignature {
                    lock_pub,
                    committed_at: now_secs,
                    sig,
                };
                Ok((
                    200,
                    serde_json::json!({
                        "status": "commit_signed",
                        "committee_signature": cs,
                    }),
                ))
            }
            LockCommitRequest::Finalize {
                anchor_id,
                new_manifest,
            } => {
                let chain_report = new_manifest
                    .verify_anchor_id(&anchor_id)
                    .map_err(|e| DbError::http(400, format!("Invalid new_manifest chain: {e}")))?;
                if !chain_report
                    .historical_committees
                    .iter()
                    .any(|c| c.contains(&lock_pub))
                {
                    return Err(DbError::http(
                        400,
                        "Server lock_pub is not a member of manifest chain",
                    ));
                }
                if new_manifest.revision <= 1 {
                    return Err(DbError::http(
                        400,
                        "Finalize requires migrated manifest revision >= 2",
                    ));
                }
                if new_manifest.retain_until_quarter > cfg.lock.max_retention_quarter {
                    return Err(DbError::http(
                        422,
                        "Manifest retain_until_quarter exceeds server limit",
                    ));
                }

                let new_committee = new_manifest
                    .committee()
                    .map_err(|e| DbError::http(400, e))?;
                let latest_cert = new_manifest
                    .migration_chain
                    .last()
                    .ok_or_else(|| DbError::http(400, "Missing latest MigrationCert"))?;
                let latest_prop_hash = latest_cert
                    .proposal
                    .core_digest()
                    .map_err(|e| DbError::http(400, e))?;

                let anchor_hex = hex::encode(anchor_id);
                let bucket = derive_bucket(&anchor_id, &lock_pub);
                let bucket_hex = hex::encode(bucket);

                let write_txn = self.raw_db().begin_write()?;
                let new_state = {
                    let mut buckets = write_txn.open_table(LOCK_BUCKETS)?;
                    let mut quarter_idx = write_txn.open_table(LOCK_QUARTER_INDEX)?;
                    let mut rotations_tbl = write_txn.open_table(LOCK_ROTATIONS)?;
                    let mut anchors_tbl = write_txn.open_table(LOCK_ANCHORS)?;

                    let mut rot: AnchorRotationRecord = match rotations_tbl
                        .get(anchor_hex.as_str())?
                    {
                        Some(g) => {
                            let existing: AnchorRotationRecord = serde_json::from_slice(g.value())?;
                            if new_manifest.revision < existing.active_manifest.revision {
                                return Err(DbError::http(
                                    409,
                                    "Cannot downgrade active manifest revision",
                                ));
                            }
                            if !manifests_share_chain_prefix(
                                &existing.active_manifest,
                                &new_manifest,
                            ) {
                                return Err(DbError::http(
                                    409,
                                    "Manifest migration_chain conflicts with finalized history on this server",
                                ));
                            }
                            if new_manifest.revision == existing.active_manifest.revision {
                                if let Some(bg) = buckets.get(bucket_hex.as_str())? {
                                    let b: LockBucketRecord = serde_json::from_slice(bg.value())?;
                                    return Ok((
                                        200,
                                        serde_json::json!({
                                            "status": "finalized",
                                            "revision": new_manifest.revision,
                                            "bucket_freeze_state": b.freeze_state,
                                        }),
                                    ));
                                }
                            }
                            existing
                        }
                        None => AnchorRotationRecord::new(
                            new_manifest.clone(),
                            (new_manifest.issued_at_ms / 1_000).min(now_secs),
                        ),
                    };

                    let in_new_committee = new_committee.contains(&lock_pub);
                    if in_new_committee {
                        let imported_ok = rot.imported_proposal.as_ref().is_some_and(|imp| {
                            imp.proposal_hash == latest_prop_hash
                                && imp.to_rev == new_manifest.revision
                                && imp.imported_state_hash == latest_cert.imported_state_hash
                        });
                        if !imported_ok {
                            return Err(DbError::http(
                                409,
                                "Target server must complete ?lock_import for this revision before Finalize",
                            ));
                        }
                    }

                    let existing_bucket: Option<LockBucketRecord> =
                        match buckets.get(bucket_hex.as_str())? {
                            Some(g) => Some(serde_json::from_slice(g.value())?),
                            None => None,
                        };
                    if existing_bucket.is_none() && buckets.len()? >= cfg.lock.max_buckets {
                        return Err(DbError::http(507, "Lock bucket budget exhausted"));
                    }

                    rot.active_manifest = new_manifest.clone();
                    rot.imported_proposal = None;
                    rotations_tbl
                        .insert(anchor_hex.as_str(), serde_json::to_vec(&rot)?.as_slice())?;
                    anchors_tbl.insert(
                        anchor_hex.as_str(),
                        serde_json::to_vec(&new_manifest)?.as_slice(),
                    )?;

                    let updated_bucket = match existing_bucket {
                        Some(mut b) => {
                            b.freeze_state = if in_new_committee {
                                match b.freeze_state {
                                    BucketFreezeState::SelfFrozen { .. } => b.freeze_state,
                                    _ => restore_non_proposal_freeze_state(&rot),
                                }
                            } else {
                                BucketFreezeState::EpochFrozen {
                                    committed_rev: new_manifest.revision,
                                    frozen_at: now_secs,
                                }
                            };
                            b
                        }
                        None => LockBucketRecord {
                            anchor_id,
                            retain_until_quarter: new_manifest.retain_until_quarter,
                            creator_mig_pub: new_manifest.authority.creator_mig_pub,
                            write_seq: 0,
                            bucket_head: compute_bucket_init_head(
                                &bucket,
                                new_manifest.retain_until_quarter,
                            ),
                            freeze_state: if in_new_committee {
                                BucketFreezeState::Active
                            } else {
                                BucketFreezeState::EpochFrozen {
                                    committed_rev: new_manifest.revision,
                                    frozen_at: now_secs,
                                }
                            },
                        },
                    };
                    let state_copy = updated_bucket.freeze_state.clone();
                    buckets.insert(
                        bucket_hex.as_str(),
                        serde_json::to_vec(&updated_bucket)?.as_slice(),
                    )?;
                    quarter_idx.insert(
                        quarter_index_key(new_manifest.retain_until_quarter, &bucket_hex).as_str(),
                        &[] as &[u8],
                    )?;
                    state_copy
                };
                write_txn.commit()?;

                Ok((
                    200,
                    serde_json::json!({
                        "status": "finalized",
                        "revision": new_manifest.revision,
                        "bucket_freeze_state": new_state,
                    }),
                ))
            }
        }
    }

    pub fn get_static_anchor_manifest(&self, anchor_hex: &str) -> Result<Option<Vec<u8>>, DbError> {
        if decode_hex_fixed::<32>(anchor_hex).is_err() {
            return Ok(None);
        }
        let read_txn = self.raw_db().begin_read()?;
        let anchors_tbl = read_txn.open_table(LOCK_ANCHORS)?;
        match anchors_tbl.get(anchor_hex)? {
            Some(g) => Ok(Some(g.value().to_vec())),
            None => Ok(None),
        }
    }

    /// Reads conflicting entries for diagnostics/tests on a slot without a QC.
    pub fn lock_conflict_entries_in_bucket(
        &self,
        bucket_hex: &str,
    ) -> Result<HashMap<String, Vec<LockEntry>>, DbError> {
        let read_txn = self.raw_db().begin_read()?;
        let conflicts_tbl = read_txn.open_table(LOCK_CONFLICTS)?;
        let prefix = bucket_entry_prefix(bucket_hex);
        let mut out = HashMap::new();
        for item in conflicts_tbl.iter()? {
            let (k, v) = item?;
            if let Some(slot_hex) = k.value().strip_prefix(&prefix) {
                out.insert(
                    slot_hex.to_string(),
                    LockEntryStorageExt::decode_conflict_group(v.value())?,
                );
            }
        }
        Ok(out)
    }
}
