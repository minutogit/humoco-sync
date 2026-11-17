use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::{Signer, SigningKey};
use humoco_proto::{
    bucket_purge_after_secs, compute_bucket_init_head, compute_bucket_step_head, decode_hex_fixed,
    decode_quarter, derive_bucket, derive_slot_file_id, format_quarter, parse_quarter,
    required_lock_pow_bits, AnchorManifest, GenesisTicket, LockEntry, LockPubKey, LockReceipt,
    LockReceiptKind, LOCK_ENTRY_IDENTITY_LEN, LOCK_ENTRY_WIRE_LEN,
};
use redb::{ReadableTable, WriteTransaction};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Sha3_256};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::crypto::{
    format_lock_delegate_signature_message, format_lock_probe_signature_message,
    format_lock_selftest_signature_message, sha256_hex, verify_ed25519_hex,
};
use crate::db::{
    AccountStatus, DbError, RegisteredUserRecord, SyncDb, ADMIN_MEMBERS, LOCK_BUCKETS,
    LOCK_ENTRIES, LOCK_FILE_INDEX, LOCK_OUTPUT_CLAIMS, LOCK_QUARTER_INDEX, NONCES,
    REGISTERED_USERS, SERVER_META,
};

const LOCK_KEY_META: &str = "lock_key";
const LOCK_DELEGATION_META: &str = "lock_delegation";
const LOCK_SELFTEST_META: &str = "lock_selftest";
const LOCK_USED_INODES_META: &str = "lock_used_inodes";
const LOCK_SELFTEST_PROBE_META: &str = "lock_selftest_probe";
const TICKET_POW_WINDOW_SECS: i64 = 300;
const TICKET_POW_REPLAY_TTL_SECS: u64 = 600;
const MAX_LOCK_BATCH_ENTRIES: usize = 64;

/// FIPS 202 `SHA3-256(b"abc")` KAT digest used by `?lock_selftest`.
const SHA3_256_ABC_KAT_HEX: &str =
    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockDelegation {
    #[serde(with = "humoco_proto::types::serde_hex_32")]
    pub admin_pub: [u8; 32],
    #[serde(with = "humoco_proto::types::serde_hex_32")]
    pub lock_pub: LockPubKey,
    pub issued_at: u64,
    #[serde(with = "humoco_proto::types::serde_hex_64")]
    pub sig: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelftestChecks {
    pub ext_sodium: String,
    pub sha3_256: String,
    pub atomic_link_eexist: String,
    pub fsync: String,
    pub ignore_user_abort: String,
    pub storage_writable: String,
    pub inode_budget: String,
    pub fastcgi_finish_request: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelftestReport {
    pub runtime: String,
    pub checked_at: u64,
    #[serde(with = "humoco_proto::types::serde_hex_32")]
    pub lock_pub: LockPubKey,
    pub php_version: Option<String>,
    pub checks: SelftestChecks,
    pub free_inodes: u64,
    pub all_passed: bool,
    #[serde(with = "humoco_proto::types::serde_hex_64")]
    pub sig: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockTicketRequest {
    #[serde(with = "humoco_proto::types::serde_hex_32")]
    pub anchor_id: [u8; 32],
    pub retain_until_quarter: u16,
    pub pow_timestamp: Option<u64>,
    pub pow_nonce: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockBatchRequest {
    #[serde(with = "humoco_proto::types::serde_hex_32")]
    pub anchor_id: [u8; 32],
    #[serde(with = "humoco_proto::types::serde_hex_32")]
    pub bucket: [u8; 32],
    #[serde(with = "humoco_proto::types::serde_hex_32")]
    pub recipient_nonce: [u8; 32],
    pub entries: Vec<String>,
    pub manifest: Option<AnchorManifest>,
    pub genesis_ticket: Option<GenesisTicket>,
    pub known_head_receipt: Option<LockReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockBatchConflict {
    pub entry_index: usize,
    pub slot: String,
    pub receipt: LockReceipt,
    pub competing_entry: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockBatchResponse {
    pub status: String,
    pub bucket: String,
    pub retain_until_quarter: u16,
    pub receipts: Vec<LockReceipt>,
    pub conflict: Option<LockBatchConflict>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BucketFreezeState {
    Active,
    SelfFrozen { frozen_at: u64, reason: String },
    EpochFrozen { frozen_at: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockBucketRecord {
    pub anchor_id: [u8; 32],
    pub retain_until_quarter: u16,
    pub creator_mig_pub: [u8; 32],
    pub write_seq: u64,
    pub bucket_head: [u8; 32],
    pub freeze_state: BucketFreezeState,
}

pub enum TicketCallerAuth<'a> {
    SignedMember {
        pubkey_hex: &'a str,
        timestamp: i64,
        nonce: &'a str,
        sig: &'a str,
        raw_body: &'a [u8],
    },
    UnauthenticatedPow,
}

struct PendingReceipt {
    kind: LockReceiptKind,
    slot: [u8; 32],
    child_lock: [u8; 32],
    entry_hash: [u8; 32],
    write_seq: u64,
    bucket_head: [u8; 32],
}

enum LockBatchTxOutcome {
    Frozen {
        error: &'static str,
        bucket_hex: String,
    },
    OutputBranchClaimed {
        parent_slot: String,
        output_branch: u8,
    },
    Committed {
        retain_until_quarter: u16,
        pending_receipts: Vec<PendingReceipt>,
        conflict: Option<(usize, [u8; 32], PendingReceipt, String)>,
    },
}

fn load_lock_signing_key_read(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<SigningKey, DbError> {
    let raw = meta
        .get(LOCK_KEY_META)?
        .ok_or_else(|| DbError::Backend("Missing SERVER_META['lock_key']".to_string()))?;
    let bytes = raw.value();
    if bytes.len() != 32 {
        return Err(DbError::Backend("Corrupted lock_key length".to_string()));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(bytes);
    Ok(SigningKey::from_bytes(&seed))
}

fn read_used_inodes(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<u64, DbError> {
    match meta.get(LOCK_USED_INODES_META)? {
        Some(g) if g.value().len() == 8 => {
            let arr: [u8; 8] = g
                .value()
                .try_into()
                .map_err(|_| DbError::Backend("invalid used_inodes".to_string()))?;
            Ok(u64::from_le_bytes(arr))
        }
        Some(_) => Err(DbError::Backend("corrupted lock_used_inodes".to_string())),
        None => Ok(0),
    }
}

fn sign_lock_receipt(
    lock_sk: &SigningKey,
    bucket: [u8; 32],
    retain_until_quarter: u16,
    recipient_nonce: [u8; 32],
    pending: PendingReceipt,
) -> LockReceipt {
    let mut r = LockReceipt {
        kind: pending.kind,
        lock_pub: lock_sk.verifying_key().to_bytes(),
        bucket,
        slot: pending.slot,
        child_lock: pending.child_lock,
        entry_hash: pending.entry_hash,
        retain_until_quarter,
        write_seq: pending.write_seq,
        bucket_head: pending.bucket_head,
        recipient_nonce,
        sig: [0u8; 64],
    };
    r.sig = lock_sk.sign(&r.digest()).to_bytes();
    r
}

fn bucket_entry_prefix(bucket_hex: &str) -> String {
    format!("{}:", bucket_hex)
}

fn bucket_slot_key(bucket_hex: &str, slot_hex: &str) -> String {
    format!("{}:{}", bucket_hex, slot_hex)
}

fn output_claim_key(bucket_hex: &str, parent_slot_hex: &str, output_branch: u8) -> String {
    format!("{}:{}:{}", bucket_hex, parent_slot_hex, output_branch)
}

fn quarter_index_key(quarter: u16, bucket_hex: &str) -> String {
    format!("{:05}:{}", quarter, bucket_hex)
}

fn file_index_key(quarter_str: &str, bucket_hex: &str, file_hex: &str) -> String {
    format!("{}/{}/{}", quarter_str, bucket_hex, file_hex)
}

fn remove_keys_with_prefix(
    table: &mut redb::Table<'_, &str, &[u8]>,
    prefix: &str,
) -> Result<Vec<(String, Vec<u8>)>, DbError> {
    let mut matched = Vec::new();
    for entry in table.iter()? {
        let (k, v) = entry?;
        if k.value().starts_with(prefix) {
            matched.push((k.value().to_string(), v.value().to_vec()));
        }
    }
    for (k, _) in &matched {
        let _ = table.remove(k.as_str())?;
    }
    Ok(matched)
}

impl SyncDb {
    pub fn lock_pubkey_bytes(&self) -> Result<[u8; 32], DbError> {
        let read_txn = self.raw_db().begin_read()?;
        let meta = read_txn.open_table(SERVER_META)?;
        Ok(load_lock_signing_key_read(&meta)?
            .verifying_key()
            .to_bytes())
    }

    pub fn lock_pubkey_hex(&self) -> Result<String, DbError> {
        Ok(hex::encode(self.lock_pubkey_bytes()?))
    }

    pub fn get_lock_delegation(&self) -> Result<Option<LockDelegation>, DbError> {
        let read_txn = self.raw_db().begin_read()?;
        let meta = read_txn.open_table(SERVER_META)?;
        match meta.get(LOCK_DELEGATION_META)? {
            Some(g) => Ok(Some(serde_json::from_slice(g.value())?)),
            None => Ok(None),
        }
    }

    pub fn set_lock_delegation(
        &self,
        cfg: &Config,
        del: LockDelegation,
    ) -> Result<LockDelegation, DbError> {
        if !cfg.lock.enabled {
            return Err(DbError::http(404, "Lock channel is disabled"));
        }
        if cfg.server.admin_pubkey.is_empty() {
            return Err(DbError::http(
                403,
                "server.admin_pubkey must be configured to delegate lock key",
            ));
        }
        let admin_pub_hex = hex::encode(del.admin_pub);
        if admin_pub_hex != cfg.server.admin_pubkey {
            return Err(DbError::http(
                403,
                "Delegation admin_pub does not match configured admin_pubkey",
            ));
        }
        let lock_pub = self.lock_pubkey_bytes()?;
        if del.lock_pub != lock_pub {
            return Err(DbError::http(
                400,
                "Delegation lock_pub does not match this server's lock_pub",
            ));
        }
        if del.issued_at == 0 {
            return Err(DbError::http(400, "Delegation issued_at must be positive"));
        }

        let lock_pub_hex = hex::encode(del.lock_pub);
        let msg =
            format_lock_delegate_signature_message(&admin_pub_hex, &lock_pub_hex, del.issued_at);
        let sig_hex = hex::encode(del.sig);
        if !verify_ed25519_hex(&admin_pub_hex, &sig_hex, msg.as_bytes()) {
            return Err(DbError::http(401, "Invalid lock delegation signature"));
        }

        let write_txn = self.raw_db().begin_write()?;
        {
            let mut meta = write_txn.open_table(SERVER_META)?;
            let encoded = serde_json::to_vec(&del)?;
            meta.insert(LOCK_DELEGATION_META, encoded.as_slice())?;
        }
        write_txn.commit()?;
        Ok(del)
    }

    pub fn get_or_run_lock_selftest(
        &self,
        cfg: &Config,
        now_secs: u64,
    ) -> Result<SelftestReport, DbError> {
        if !cfg.lock.enabled {
            return Err(DbError::http(404, "Lock channel is disabled"));
        }
        {
            let read_txn = self.raw_db().begin_read()?;
            let meta = read_txn.open_table(SERVER_META)?;
            if let Some(g) = meta.get(LOCK_SELFTEST_META)? {
                let report: SelftestReport = serde_json::from_slice(g.value())?;
                return Ok(report);
            }
        }
        self.run_lock_selftest(cfg, now_secs)
    }

    pub fn run_lock_selftest(
        &self,
        cfg: &Config,
        now_secs: u64,
    ) -> Result<SelftestReport, DbError> {
        if !cfg.lock.enabled {
            return Err(DbError::http(404, "Lock channel is disabled"));
        }

        let sha3_ok = hex::encode(Sha3_256::digest(b"abc")) == SHA3_256_ABC_KAT_HEX;
        let write_txn = self.raw_db().begin_write()?;
        let (lock_sk, used_inodes, storage_writable) = {
            let mut meta = write_txn.open_table(SERVER_META)?;
            let sk = load_lock_signing_key_read(&meta)?;
            let used = read_used_inodes(&meta)?;
            let probe_bytes = now_secs.to_le_bytes();
            let writable = meta
                .insert(LOCK_SELFTEST_PROBE_META, probe_bytes.as_slice())
                .is_ok();
            (sk, used, writable)
        };
        write_txn.commit()?;

        let free_inodes = cfg.lock.max_inodes.saturating_sub(used_inodes);
        let inode_ok = free_inodes > 0;
        let all_passed = sha3_ok && storage_writable && inode_ok;

        let checks = SelftestChecks {
            ext_sodium: "not_applicable".to_string(),
            sha3_256: if sha3_ok { "pass" } else { "fail" }.to_string(),
            atomic_link_eexist: "not_applicable".to_string(),
            fsync: if storage_writable { "pass" } else { "fail" }.to_string(),
            ignore_user_abort: "not_applicable".to_string(),
            storage_writable: if storage_writable { "pass" } else { "fail" }.to_string(),
            inode_budget: if inode_ok { "pass" } else { "fail" }.to_string(),
            fastcgi_finish_request: "not_applicable".to_string(),
        };

        let lock_pub = lock_sk.verifying_key().to_bytes();
        let lock_pub_hex = hex::encode(lock_pub);
        let canonical_checks_line = format!(
            "{},{},{},{},{},{},{},{},{}",
            checks.ext_sodium,
            checks.sha3_256,
            checks.atomic_link_eexist,
            checks.fsync,
            checks.ignore_user_abort,
            checks.storage_writable,
            checks.inode_budget,
            checks.fastcgi_finish_request,
            free_inodes
        );
        let checks_digest_hex = sha256_hex(canonical_checks_line.as_bytes());
        let msg = format_lock_selftest_signature_message(
            "rust",
            now_secs,
            &lock_pub_hex,
            all_passed,
            &checks_digest_hex,
        );
        let sig = lock_sk.sign(msg.as_bytes()).to_bytes();

        let report = SelftestReport {
            runtime: "rust".to_string(),
            checked_at: now_secs,
            lock_pub,
            php_version: None,
            checks,
            free_inodes,
            all_passed,
            sig,
        };

        let save_txn = self.raw_db().begin_write()?;
        {
            let mut meta = save_txn.open_table(SERVER_META)?;
            let encoded = serde_json::to_vec(&report)?;
            meta.insert(LOCK_SELFTEST_META, encoded.as_slice())?;
        }
        save_txn.commit()?;
        Ok(report)
    }

    pub fn sign_lock_probe(
        &self,
        cfg: &Config,
        client_nonce: &str,
        now_secs: u64,
    ) -> Result<serde_json::Value, DbError> {
        if !cfg.lock.enabled {
            return Err(DbError::http(404, "Lock channel is disabled"));
        }
        let clean_nonce = client_nonce.trim();
        let nonce_bytes = decode_hex_fixed::<32>(clean_nonce).map_err(|_| {
            DbError::http(
                400,
                "Invalid probe client_nonce (expected 64 lowercase hex)",
            )
        })?;
        if nonce_bytes == [0u8; 32] {
            return Err(DbError::http(400, "Probe client_nonce must be non-zero"));
        }

        let read_txn = self.raw_db().begin_read()?;
        let meta = read_txn.open_table(SERVER_META)?;
        let lock_sk = load_lock_signing_key_read(&meta)?;
        let lock_pub_hex = hex::encode(lock_sk.verifying_key().to_bytes());
        let msg = format_lock_probe_signature_message(&lock_pub_hex, clean_nonce, now_secs);
        let sig_hex = hex::encode(lock_sk.sign(msg.as_bytes()).to_bytes());

        Ok(serde_json::json!({
            "probe_ok": true,
            "lock_pub": lock_pub_hex,
            "client_nonce": clean_nonce,
            "server_time": now_secs,
            "sig": sig_hex,
        }))
    }

    pub fn get_lock_info_json(
        &self,
        cfg: &Config,
        now_secs: u64,
    ) -> Result<serde_json::Value, DbError> {
        if !cfg.lock.enabled {
            return Ok(serde_json::Value::Null);
        }
        let selftest = self.get_or_run_lock_selftest(cfg, now_secs)?;
        let read_txn = self.raw_db().begin_read()?;
        let meta = read_txn.open_table(SERVER_META)?;
        let lock_pub_hex = hex::encode(
            load_lock_signing_key_read(&meta)?
                .verifying_key()
                .as_bytes(),
        );
        let delegation = match meta.get(LOCK_DELEGATION_META)? {
            Some(g) => Some(serde_json::from_slice::<LockDelegation>(g.value())?),
            None => None,
        };
        let used_inodes = read_used_inodes(&meta)?;
        let inode_warning =
            used_inodes.saturating_mul(100) >= cfg.lock.max_inodes.saturating_mul(80);

        Ok(serde_json::json!({
            "lock_pub": lock_pub_hex,
            "delegation": delegation,
            "max_retention_quarter": cfg.lock.max_retention_quarter,
            "max_inodes": cfg.lock.max_inodes,
            "used_inodes": used_inodes,
            "inode_warning": inode_warning,
            "pow_base_bits": cfg.lock.pow_base_bits,
            "allow_pow_tickets": cfg.lock.allow_pow_tickets,
            "selftest": selftest,
        }))
    }

    pub fn issue_genesis_ticket(
        &self,
        cfg: &Config,
        caller: TicketCallerAuth<'_>,
        req: LockTicketRequest,
        now_secs: u64,
    ) -> Result<GenesisTicket, DbError> {
        if !cfg.lock.enabled {
            return Err(DbError::http(404, "Lock channel is disabled"));
        }
        if decode_quarter(req.retain_until_quarter).is_err() {
            return Err(DbError::http(400, "Invalid retain_until_quarter"));
        }
        if req.retain_until_quarter > cfg.lock.max_retention_quarter {
            return Err(DbError::http(
                422,
                "Requested retain_until_quarter exceeds server lock.max_retention_quarter",
            ));
        }

        let write_txn = self.raw_db().begin_write()?;
        let ticket = {
            let meta = write_txn.open_table(SERVER_META)?;
            let mut nonces = write_txn.open_table(NONCES)?;
            let admin_table = write_txn.open_table(ADMIN_MEMBERS)?;
            let reg_table = write_txn.open_table(REGISTERED_USERS)?;
            let buckets = write_txn.open_table(LOCK_BUCKETS)?;

            // Authorize caller + replay protection
            match caller {
                TicketCallerAuth::SignedMember {
                    pubkey_hex,
                    timestamp,
                    nonce,
                    sig,
                    raw_body,
                } => {
                    if !crate::crypto::check_timestamp_window(timestamp, now_secs) {
                        return Err(DbError::http(401, "Timestamp outside allowed window"));
                    }
                    let body_hash = sha256_hex(raw_body);
                    let msg = crate::crypto::parse_member_message(
                        "POST",
                        "lock_ticket",
                        "",
                        timestamp,
                        nonce,
                        &body_hash,
                    );
                    if !verify_ed25519_hex(pubkey_hex, sig, msg.as_bytes()) {
                        return Err(DbError::http(401, "Invalid request signature"));
                    }

                    // Consume request nonce
                    if let Some(exp) = nonces.get(nonce)?.map(|g| g.value()) {
                        if exp > now_secs {
                            return Err(DbError::http(409, "Nonce already used"));
                        }
                    }
                    nonces.insert(nonce, now_secs + crate::crypto::NONCE_TTL_SECS)?;

                    let is_server_admin = !cfg.server.admin_pubkey.is_empty()
                        && pubkey_hex == cfg.server.admin_pubkey;
                    let is_lock_admin_member = cfg.mode.enable_admin_app
                        && admin_table
                            .get(format!("lock:{}", pubkey_hex).as_str())?
                            .is_some();
                    let is_active_unrestricted_registered = if cfg.mode.enable_public_registration {
                        match reg_table.get(pubkey_hex)? {
                            Some(g) => {
                                let rec: RegisteredUserRecord = serde_json::from_slice(g.value())?;
                                rec.status == AccountStatus::Active
                                    && rec.valid_until.is_none_or(|v| now_secs <= v)
                            }
                            None => false,
                        }
                    } else {
                        false
                    };

                    if !is_server_admin
                        && !is_lock_admin_member
                        && !is_active_unrestricted_registered
                    {
                        return Err(DbError::http(
                            403,
                            "Account is not authorized for lock tickets",
                        ));
                    }
                }
                TicketCallerAuth::UnauthenticatedPow => {
                    if !cfg.lock.allow_pow_tickets {
                        return Err(DbError::http(
                            401,
                            "Authentication required for lock_ticket",
                        ));
                    }
                    let pow_ts = req
                        .pow_timestamp
                        .ok_or_else(|| DbError::http(400, "Missing pow_timestamp"))?;
                    let pow_nonce = req
                        .pow_nonce
                        .ok_or_else(|| DbError::http(400, "Missing pow_nonce"))?;
                    let drift = (now_secs as i64 - pow_ts as i64).abs();
                    if drift > TICKET_POW_WINDOW_SECS {
                        return Err(DbError::http(
                            401,
                            "Ticket PoW timestamp outside allowed 300s window",
                        ));
                    }
                    if !humoco_proto::verify_ticket_pow(
                        &req.anchor_id,
                        req.retain_until_quarter,
                        pow_ts,
                        pow_nonce,
                        cfg.lock.ticket_pow_bits,
                    ) {
                        return Err(DbError::http(422, "Insufficient lock_ticket proof-of-work"));
                    }
                    let tuple_key = format!(
                        "ticket_pow:{}:{}:{}:{}",
                        hex::encode(req.anchor_id),
                        req.retain_until_quarter,
                        pow_ts,
                        pow_nonce
                    );
                    if let Some(exp) = nonces.get(tuple_key.as_str())?.map(|g| g.value()) {
                        if exp > now_secs {
                            return Err(DbError::http(409, "Ticket PoW replay rejected"));
                        }
                    }
                    nonces.insert(tuple_key.as_str(), now_secs + TICKET_POW_REPLAY_TTL_SECS)?;
                }
            }

            let lock_sk = load_lock_signing_key_read(&meta)?;
            let lock_pub = lock_sk.verifying_key().to_bytes();

            let bucket = derive_bucket(&req.anchor_id, &lock_pub);
            let bucket_hex = hex::encode(bucket);
            if let Some(g) = buckets.get(bucket_hex.as_str())? {
                let b: LockBucketRecord = serde_json::from_slice(g.value())?;
                match b.freeze_state {
                    BucketFreezeState::SelfFrozen { .. } => {
                        return Err(DbError::http(409, "bucket_self_frozen"));
                    }
                    BucketFreezeState::EpochFrozen { .. } => {
                        return Err(DbError::http(409, "epoch_frozen"));
                    }
                    BucketFreezeState::Active => {}
                }
            }

            let used_inodes = read_used_inodes(&meta)?;
            if used_inodes >= cfg.lock.max_inodes {
                return Err(DbError::http(507, "Lock inode budget exhausted"));
            }

            let mut ticket = GenesisTicket {
                anchor_id: req.anchor_id,
                retain_until_quarter: req.retain_until_quarter,
                issued_at: now_secs,
                lock_pub,
                sig: [0u8; 64],
            };
            ticket.sig = lock_sk.sign(&ticket.digest()).to_bytes();
            ticket
        };
        write_txn.commit()?;
        Ok(ticket)
    }

    pub fn process_lock_batch(
        &self,
        cfg: &Config,
        req: LockBatchRequest,
        now_secs: u64,
    ) -> Result<(u16, serde_json::Value), DbError> {
        if !cfg.lock.enabled {
            return Err(DbError::http(404, "Lock channel is disabled"));
        }
        if req.entries.is_empty() || req.entries.len() > MAX_LOCK_BATCH_ENTRIES {
            return Err(DbError::http(400, "Lock batch must contain 1..=64 entries"));
        }
        if req.recipient_nonce == [0u8; 32] {
            return Err(DbError::http(400, "recipient_nonce must be non-zero"));
        }

        let lock_pub = self.lock_pubkey_bytes()?;
        let expected_bucket = derive_bucket(&req.anchor_id, &lock_pub);
        if req.bucket != expected_bucket {
            return Err(DbError::http(
                400,
                "bucket does not match derive_bucket(anchor_id, lock_pub)",
            ));
        }

        let mut parsed_entries = Vec::with_capacity(req.entries.len());
        for raw_hex in &req.entries {
            if raw_hex.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(DbError::http(400, "Entry hex must be lowercase"));
            }
            let entry = LockEntry::from_wire_hex(raw_hex)
                .map_err(|e| DbError::http(400, format!("Invalid LockEntry wire bytes: {}", e)))?;
            parsed_entries.push(entry);
        }

        // Verify known_head_receipt BEFORE touching bucket freeze state (SPEC §6.6.4 step 1).
        if let Some(ref kr) = req.known_head_receipt {
            if kr.lock_pub != lock_pub || kr.bucket != req.bucket {
                return Err(DbError::http(
                    400,
                    "known_head_receipt lock_pub or bucket mismatch",
                ));
            }
            if decode_quarter(kr.retain_until_quarter).is_err() || !kr.verify_signature() {
                return Err(DbError::http(
                    401,
                    "Invalid signature on known_head_receipt",
                ));
            }
        }

        let bucket_hex = hex::encode(req.bucket);
        let write_txn = self.raw_db().begin_write()?;
        let outcome = Self::execute_lock_batch_in_txn(
            &write_txn,
            cfg,
            &req,
            &parsed_entries,
            lock_pub,
            &bucket_hex,
            now_secs,
        )?;
        write_txn.commit()?;

        match outcome {
            LockBatchTxOutcome::Frozen { error, bucket_hex } => Ok((
                409,
                serde_json::json!({
                    "error": error,
                    "bucket": bucket_hex,
                }),
            )),
            LockBatchTxOutcome::OutputBranchClaimed {
                parent_slot,
                output_branch,
            } => Ok((
                409,
                serde_json::json!({
                    "error": "output_branch_already_claimed",
                    "parent_slot": parent_slot,
                    "output_branch": output_branch,
                }),
            )),
            LockBatchTxOutcome::Committed {
                retain_until_quarter,
                pending_receipts,
                conflict,
            } => {
                // Sign receipts ONLY AFTER write_txn.commit() succeeded!
                let read_txn = self.raw_db().begin_read()?;
                let meta = read_txn.open_table(SERVER_META)?;
                let lock_sk = load_lock_signing_key_read(&meta)?;

                let signed_receipts: Vec<LockReceipt> = pending_receipts
                    .into_iter()
                    .map(|p| {
                        sign_lock_receipt(
                            &lock_sk,
                            req.bucket,
                            retain_until_quarter,
                            req.recipient_nonce,
                            p,
                        )
                    })
                    .collect();

                let (status, conflict_dto) =
                    if let Some((idx, slot, c_pending, wire_hex)) = conflict {
                        let c_receipt = sign_lock_receipt(
                            &lock_sk,
                            req.bucket,
                            retain_until_quarter,
                            req.recipient_nonce,
                            c_pending,
                        );
                        (
                            "conflict".to_string(),
                            Some(LockBatchConflict {
                                entry_index: idx,
                                slot: hex::encode(slot),
                                receipt: c_receipt,
                                competing_entry: wire_hex,
                            }),
                        )
                    } else {
                        ("ok".to_string(), None)
                    };

                let resp = LockBatchResponse {
                    status,
                    bucket: bucket_hex,
                    retain_until_quarter,
                    receipts: signed_receipts,
                    conflict: conflict_dto,
                };
                Ok((200, serde_json::to_value(resp)?))
            }
        }
    }

    fn execute_lock_batch_in_txn(
        write_txn: &WriteTransaction,
        cfg: &Config,
        req: &LockBatchRequest,
        parsed_entries: &[LockEntry],
        lock_pub: LockPubKey,
        bucket_hex: &str,
        now_secs: u64,
    ) -> Result<LockBatchTxOutcome, DbError> {
        let mut meta = write_txn.open_table(SERVER_META)?;
        let mut buckets = write_txn.open_table(LOCK_BUCKETS)?;
        let mut entries_tbl = write_txn.open_table(LOCK_ENTRIES)?;
        let mut claims_tbl = write_txn.open_table(LOCK_OUTPUT_CLAIMS)?;
        let mut file_idx = write_txn.open_table(LOCK_FILE_INDEX)?;
        let mut quarter_idx = write_txn.open_table(LOCK_QUARTER_INDEX)?;

        let mut existing_bucket: Option<LockBucketRecord> = match buckets.get(bucket_hex)? {
            Some(g) => Some(serde_json::from_slice(g.value())?),
            None => None,
        };

        // Step 1: Rollback Self-Freeze Check (SPEC §6.6.4 step 1)
        if let Some(ref kr) = req.known_head_receipt {
            match existing_bucket {
                None => {
                    let tomb = LockBucketRecord {
                        anchor_id: req.anchor_id,
                        retain_until_quarter: kr.retain_until_quarter,
                        creator_mig_pub: [0u8; 32],
                        write_seq: kr.write_seq,
                        bucket_head: kr.bucket_head,
                        freeze_state: BucketFreezeState::SelfFrozen {
                            frozen_at: now_secs,
                            reason: "Rollback detected: client presented valid signed receipt for missing bucket".to_string(),
                        },
                    };
                    let bytes = serde_json::to_vec(&tomb)?;
                    buckets.insert(bucket_hex, bytes.as_slice())?;
                    quarter_idx.insert(
                        quarter_index_key(kr.retain_until_quarter, bucket_hex).as_str(),
                        &[] as &[u8],
                    )?;
                    return Ok(LockBatchTxOutcome::Frozen {
                        error: "bucket_self_frozen",
                        bucket_hex: bucket_hex.to_string(),
                    });
                }
                Some(ref mut b) => {
                    if kr.write_seq > b.write_seq
                        || (kr.write_seq == b.write_seq && kr.bucket_head != b.bucket_head)
                    {
                        b.freeze_state = BucketFreezeState::SelfFrozen {
                            frozen_at: now_secs,
                            reason: "Rollback detected: client head exceeds local bucket state"
                                .to_string(),
                        };
                        let bytes = serde_json::to_vec(&b)?;
                        buckets.insert(bucket_hex, bytes.as_slice())?;
                        return Ok(LockBatchTxOutcome::Frozen {
                            error: "bucket_self_frozen",
                            bucket_hex: bucket_hex.to_string(),
                        });
                    }
                }
            }
        }

        // Step 2: Frozen check
        let mut bucket = match existing_bucket {
            Some(b) => match &b.freeze_state {
                BucketFreezeState::SelfFrozen { .. } => {
                    return Ok(LockBatchTxOutcome::Frozen {
                        error: "bucket_self_frozen",
                        bucket_hex: bucket_hex.to_string(),
                    });
                }
                BucketFreezeState::EpochFrozen { .. } => {
                    return Ok(LockBatchTxOutcome::Frozen {
                        error: "epoch_frozen",
                        bucket_hex: bucket_hex.to_string(),
                    });
                }
                BucketFreezeState::Active => {
                    if let Some(ref m) = req.manifest {
                        let aid = m.rev1_anchor_id().map_err(|e| DbError::http(400, e))?;
                        if aid != b.anchor_id {
                            return Err(DbError::http(400, "Manifest anchor_id mismatch"));
                        }
                    }
                    b
                }
            },
            None => {
                // Step 3: Bucket Creation
                let manifest = req.manifest.as_ref().ok_or_else(|| {
                    DbError::http(400, "Missing AnchorManifest for initial bucket creation")
                })?;
                let ticket = req.genesis_ticket.as_ref().ok_or_else(|| {
                    DbError::http(400, "Missing GenesisTicket for initial bucket creation")
                })?;

                if manifest.revision != 1 {
                    return Err(DbError::http(
                        400,
                        "Initial bucket creation requires revision 1",
                    ));
                }
                let aid = manifest
                    .rev1_anchor_id()
                    .map_err(|e| DbError::http(400, e))?;
                if aid != req.anchor_id {
                    return Err(DbError::http(400, "Manifest rev1_anchor_id mismatch"));
                }
                let committee = manifest.committee().map_err(|e| DbError::http(400, e))?;
                if !committee.contains(&lock_pub) {
                    return Err(DbError::http(
                        400,
                        "This server's lock_pub is not a member of manifest committee",
                    ));
                }
                if ticket.anchor_id != req.anchor_id
                    || ticket.lock_pub != lock_pub
                    || ticket.retain_until_quarter != manifest.retain_until_quarter
                    || !ticket.verify()
                {
                    return Err(DbError::http(401, "Invalid or mismatched GenesisTicket"));
                }
                if manifest.retain_until_quarter > cfg.lock.max_retention_quarter {
                    return Err(DbError::http(
                        422,
                        "Manifest retain_until_quarter exceeds server limit",
                    ));
                }

                let used_inodes = read_used_inodes(&meta)?;
                if used_inodes >= cfg.lock.max_inodes {
                    return Err(DbError::http(507, "Lock inode budget exhausted"));
                }

                let b = LockBucketRecord {
                    anchor_id: req.anchor_id,
                    retain_until_quarter: manifest.retain_until_quarter,
                    creator_mig_pub: manifest.authority.creator_mig_pub,
                    write_seq: 0,
                    bucket_head: compute_bucket_init_head(
                        &req.bucket,
                        manifest.retain_until_quarter,
                    ),
                    freeze_state: BucketFreezeState::Active,
                };
                let b_bytes = serde_json::to_vec(&b)?;
                buckets.insert(bucket_hex, b_bytes.as_slice())?;
                quarter_idx.insert(
                    quarter_index_key(b.retain_until_quarter, bucket_hex).as_str(),
                    &[] as &[u8],
                )?;
                b
            }
        };

        let quarter_str = format_quarter(bucket.retain_until_quarter)
            .map_err(|e| DbError::Backend(e.to_string()))?;
        let mut used_inodes = read_used_inodes(&meta)?;
        let mut batch_accepted: HashMap<[u8; 32], LockEntry> =
            HashMap::with_capacity(parsed_entries.len());
        let mut batch_claims: HashMap<([u8; 32], u8), [u8; 32]> =
            HashMap::with_capacity(parsed_entries.len());
        let mut pending_receipts = Vec::with_capacity(parsed_entries.len());
        let mut conflict = None;

        // Step 4: Sequential Entry Processing
        for (idx, entry) in parsed_entries.iter().enumerate() {
            let slot_hex = hex::encode(entry.slot);

            // Check PoW against configured baseline + entry depth
            let req_bits = required_lock_pow_bits(cfg.lock.pow_base_bits, entry.depth);
            if !humoco_proto::verify_lock_pow(
                &entry.slot,
                &entry.child_lock,
                entry.depth,
                entry.pow_nonce,
                req_bits,
            ) {
                return Err(DbError::http(422, "Insufficient lock entry proof-of-work"));
            }

            // Load parent if depth >= 1 (either committed earlier in batch OR already in DB)
            let parent_opt: Option<LockEntry> = if entry.depth == 0 {
                None
            } else if let Some(p) = batch_accepted.get(&entry.parent_slot) {
                Some(p.clone())
            } else {
                let p_key = bucket_slot_key(bucket_hex, &hex::encode(entry.parent_slot));
                match entries_tbl.get(p_key.as_str())? {
                    Some(g) => Some(LockEntry::from_wire_bytes(g.value()).map_err(|e| {
                        DbError::Backend(format!("Corrupted stored parent lock entry: {}", e))
                    })?),
                    None => {
                        return Err(DbError::http(
                            422,
                            "Missing causal parent lock entry for spend depth >= 1",
                        ));
                    }
                }
            };

            entry
                .verify_entry(
                    &bucket.anchor_id,
                    &bucket.creator_mig_pub,
                    cfg.lock.pow_base_bits,
                    parent_opt.as_ref(),
                )
                .map_err(|e| DbError::http(422, format!("Causal validation failed: {}", e)))?;

            // Check max-1-child-slot per (parent_slot, output_branch) for depth >= 1
            let parent_slot_hex = hex::encode(entry.parent_slot);
            if entry.depth >= 1 {
                if let Some(existing_slot) =
                    batch_claims.get(&(entry.parent_slot, entry.output_branch))
                {
                    if *existing_slot != entry.slot {
                        return Ok(LockBatchTxOutcome::OutputBranchClaimed {
                            parent_slot: parent_slot_hex,
                            output_branch: entry.output_branch,
                        });
                    }
                } else {
                    let claim_k =
                        output_claim_key(bucket_hex, &parent_slot_hex, entry.output_branch);
                    if let Some(g) = claims_tbl.get(claim_k.as_str())? {
                        if g.value().len() != 32 {
                            return Err(DbError::Backend(
                                "Corrupted output claim length".to_string(),
                            ));
                        }
                        if g.value() != entry.slot {
                            return Ok(LockBatchTxOutcome::OutputBranchClaimed {
                                parent_slot: parent_slot_hex,
                                output_branch: entry.output_branch,
                            });
                        }
                    }
                }
            }

            // Write-Once check on entry.slot
            let e_key = bucket_slot_key(bucket_hex, &slot_hex);
            let incoming_wire = entry.to_wire_bytes().map_err(|e| DbError::http(400, e))?;
            let incoming_entry_hash = entry.entry_hash().map_err(|e| DbError::http(400, e))?;

            let existing_raw = entries_tbl.get(e_key.as_str())?.map(|g| g.value().to_vec());
            match existing_raw {
                None => {
                    entries_tbl.insert(e_key.as_str(), incoming_wire.as_slice())?;
                    if entry.depth >= 1 {
                        let claim_k =
                            output_claim_key(bucket_hex, &parent_slot_hex, entry.output_branch);
                        claims_tbl.insert(claim_k.as_str(), entry.slot.as_slice())?;
                    }
                    let file_hex = hex::encode(derive_slot_file_id(&entry.slot, &lock_pub));
                    let f_key = file_index_key(&quarter_str, bucket_hex, &file_hex);
                    file_idx.insert(f_key.as_str(), e_key.as_bytes())?;

                    used_inodes = used_inodes.saturating_add(1);
                    bucket.write_seq = bucket.write_seq.saturating_add(1);
                    bucket.bucket_head = compute_bucket_step_head(
                        &bucket.bucket_head,
                        bucket.write_seq,
                        &entry.slot,
                        &incoming_entry_hash,
                    );

                    pending_receipts.push(PendingReceipt {
                        kind: LockReceiptKind::FirstWrite,
                        slot: entry.slot,
                        child_lock: entry.child_lock,
                        entry_hash: incoming_entry_hash,
                        write_seq: bucket.write_seq,
                        bucket_head: bucket.bucket_head,
                    });
                    if entry.depth >= 1 {
                        batch_claims.insert((entry.parent_slot, entry.output_branch), entry.slot);
                    }
                    batch_accepted.insert(entry.slot, entry.clone());
                }
                Some(stored_bytes) => {
                    if stored_bytes.len() != LOCK_ENTRY_WIRE_LEN {
                        return Err(DbError::Backend(
                            "Corrupted stored LockEntry length".to_string(),
                        ));
                    }
                    if stored_bytes[..LOCK_ENTRY_IDENTITY_LEN]
                        == incoming_wire[..LOCK_ENTRY_IDENTITY_LEN]
                    {
                        // Idempotent retry: preserve state, sign FirstWrite with current head
                        let stored_entry = LockEntry::from_wire_bytes(&stored_bytes)
                            .map_err(|e| DbError::Backend(e.to_string()))?;
                        pending_receipts.push(PendingReceipt {
                            kind: LockReceiptKind::FirstWrite,
                            slot: stored_entry.slot,
                            child_lock: stored_entry.child_lock,
                            entry_hash: incoming_entry_hash,
                            write_seq: bucket.write_seq,
                            bucket_head: bucket.bucket_head,
                        });
                        if stored_entry.depth >= 1 {
                            batch_claims.insert(
                                (stored_entry.parent_slot, stored_entry.output_branch),
                                stored_entry.slot,
                            );
                        }
                        batch_accepted.insert(stored_entry.slot, stored_entry);
                    } else {
                        // ConflictSeen! Keep prefix 0..idx, do NOT write idx or > idx.
                        let stored_entry = LockEntry::from_wire_bytes(&stored_bytes)
                            .map_err(|e| DbError::Backend(e.to_string()))?;
                        let stored_hash = stored_entry
                            .entry_hash()
                            .map_err(|e| DbError::Backend(e.to_string()))?;
                        let stored_hex = hex::encode(&stored_bytes);
                        let c_pending = PendingReceipt {
                            kind: LockReceiptKind::ConflictSeen,
                            slot: stored_entry.slot,
                            child_lock: stored_entry.child_lock,
                            entry_hash: stored_hash,
                            write_seq: bucket.write_seq,
                            bucket_head: bucket.bucket_head,
                        };
                        conflict = Some((idx, entry.slot, c_pending, stored_hex));
                        break;
                    }
                }
            }
        }

        // Persist updated bucket & inode counter
        let b_bytes = serde_json::to_vec(&bucket)?;
        buckets.insert(bucket_hex, b_bytes.as_slice())?;
        meta.insert(LOCK_USED_INODES_META, used_inodes.to_le_bytes().as_slice())?;

        Ok(LockBatchTxOutcome::Committed {
            retain_until_quarter: bucket.retain_until_quarter,
            pending_receipts,
            conflict,
        })
    }

    pub fn get_static_lock_entry(
        &self,
        quarter_str: &str,
        bucket_hex: &str,
        file_hex: &str,
    ) -> Result<Option<Vec<u8>>, DbError> {
        if parse_quarter(quarter_str).is_err() {
            return Ok(None);
        }
        if decode_hex_fixed::<32>(bucket_hex).is_err() || decode_hex_fixed::<32>(file_hex).is_err()
        {
            return Ok(None);
        }

        let read_txn = self.raw_db().begin_read()?;
        let file_idx = read_txn.open_table(LOCK_FILE_INDEX)?;
        let entries_tbl = read_txn.open_table(LOCK_ENTRIES)?;

        let f_key = file_index_key(quarter_str, bucket_hex, file_hex);
        let Some(slot_key_guard) = file_idx.get(f_key.as_str())? else {
            return Ok(None);
        };
        let slot_key = std::str::from_utf8(slot_key_guard.value())
            .map_err(|_| DbError::Backend("Corrupted LOCK_FILE_INDEX UTF-8".to_string()))?;
        match entries_tbl.get(slot_key)? {
            Some(g) => Ok(Some(g.value().to_vec())),
            None => Ok(None),
        }
    }

    /// Purges ONLY entire lock buckets whose immutable retention window + 30-day grace
    /// has strictly elapsed (`now_secs >= bucket_purge_after_secs(retain_until_quarter)`).
    pub fn run_lock_gc(&self, now_secs: u64) -> Result<(usize, u64), DbError> {
        let write_txn = self.raw_db().begin_write()?;
        let (purged_buckets, purged_entries) = {
            let mut meta = write_txn.open_table(SERVER_META)?;
            let mut buckets = write_txn.open_table(LOCK_BUCKETS)?;
            let mut entries_tbl = write_txn.open_table(LOCK_ENTRIES)?;
            let mut claims_tbl = write_txn.open_table(LOCK_OUTPUT_CLAIMS)?;
            let mut file_idx = write_txn.open_table(LOCK_FILE_INDEX)?;
            let mut quarter_idx = write_txn.open_table(LOCK_QUARTER_INDEX)?;

            let mut expired: Vec<(String, u16, String)> = Vec::new();
            for entry in quarter_idx.iter()? {
                let (k, _) = entry?;
                let ks = k.value();
                if let Some((q_str, bucket_hex)) = ks.split_once(':') {
                    if let Ok(q) = q_str.parse::<u16>() {
                        if let Ok(threshold) = bucket_purge_after_secs(q) {
                            if now_secs >= threshold {
                                expired.push((ks.to_string(), q, bucket_hex.to_string()));
                            }
                        }
                    }
                }
            }

            let mut removed_buckets = 0usize;
            let mut removed_entries = 0u64;
            let mut used_inodes = read_used_inodes(&meta)?;

            for (q_key, quarter, bucket_hex) in expired {
                let prefix = bucket_entry_prefix(&bucket_hex);
                let deleted_slots = remove_keys_with_prefix(&mut entries_tbl, &prefix)?;
                removed_entries = removed_entries.saturating_add(deleted_slots.len() as u64);
                let _ = remove_keys_with_prefix(&mut claims_tbl, &prefix)?;

                if let Ok(quarter_label) = format_quarter(quarter) {
                    let f_prefix = format!("{}/{}/", quarter_label, bucket_hex);
                    let _ = remove_keys_with_prefix(&mut file_idx, &f_prefix)?;
                }

                let _ = buckets.remove(bucket_hex.as_str())?;
                let _ = quarter_idx.remove(q_key.as_str())?;
                used_inodes = used_inodes.saturating_sub(deleted_slots.len() as u64);
                removed_buckets += 1;
            }

            meta.insert(LOCK_USED_INODES_META, used_inodes.to_le_bytes().as_slice())?;
            (removed_buckets, removed_entries)
        };
        write_txn.commit()?;
        Ok((purged_buckets, purged_entries))
    }

    pub fn lock_bucket_count_and_inodes(&self) -> Result<(usize, u64), DbError> {
        let read_txn = self.raw_db().begin_read()?;
        let buckets = read_txn.open_table(LOCK_BUCKETS)?;
        let meta = read_txn.open_table(SERVER_META)?;
        let mut count = 0usize;
        for _ in buckets.iter()? {
            count += 1;
        }
        Ok((count, read_used_inodes(&meta)?))
    }

    /// Lists active slot wire hexes for diagnostics/testing without exposing private storage internals.
    pub fn lock_entries_in_bucket(
        &self,
        bucket_hex: &str,
    ) -> Result<BTreeMap<String, Vec<u8>>, DbError> {
        let read_txn = self.raw_db().begin_read()?;
        let entries_tbl = read_txn.open_table(LOCK_ENTRIES)?;
        let prefix = bucket_entry_prefix(bucket_hex);
        let mut out = BTreeMap::new();
        for entry in entries_tbl.iter()? {
            let (k, v) = entry?;
            if let Some(slot_hex) = k.value().strip_prefix(&prefix) {
                out.insert(slot_hex.to_string(), v.value().to_vec());
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_anti_amnesia_fails_when_lock_key_deleted_with_active_buckets() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("sync.redb");
        {
            let db = SyncDb::open(&db_path, "").unwrap();
            let write_txn = db.raw_db().begin_write().unwrap();
            {
                let mut buckets = write_txn.open_table(LOCK_BUCKETS).unwrap();
                buckets
                    .insert("aa".repeat(32).as_str(), b"dummy".as_slice())
                    .unwrap();
                let mut meta = write_txn.open_table(SERVER_META).unwrap();
                meta.remove(LOCK_KEY_META).unwrap();
            }
            write_txn.commit().unwrap();
        }
        let err = match SyncDb::open(&db_path, "") {
            Ok(_) => panic!("expected anti-amnesia open failure"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("Anti-amnesia halt"));
    }
}
