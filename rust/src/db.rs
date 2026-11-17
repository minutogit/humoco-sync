use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use rand::rngs::OsRng;
use rand::RngCore;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{Config, ProfileConfig, ADMIN_MEMBER_CHANNELS};
use crate::crypto::{
    canonicalize_email, decrypt_contact_email, encrypt_contact_email, hmac_email, random_hex,
    sha256_hex, RevocationNotice, NONCE_TTL_SECS,
};

pub(crate) const SERVER_META: TableDefinition<&str, &[u8]> = TableDefinition::new("server_meta");
pub(crate) const NONCES: TableDefinition<&str, u64> = TableDefinition::new("nonces");
pub(crate) const ADMIN_MEMBERS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("admin_members");
pub(crate) const REGISTERED_USERS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("registered_users");
const EMAIL_INDEX: TableDefinition<&str, &str> = TableDefinition::new("email_index");
const SLOT_META: TableDefinition<&str, &[u8]> = TableDefinition::new("slot_meta");
const SLOT_DATA: TableDefinition<&str, &[u8]> = TableDefinition::new("slot_data");
const MEDIA_META: TableDefinition<&str, &[u8]> = TableDefinition::new("media_meta");
const MEDIA_DATA: TableDefinition<&str, &[u8]> = TableDefinition::new("media_data");
const REDEEM_CODES: TableDefinition<&str, &[u8]> = TableDefinition::new("redeem_codes");
const USED_ACTION_JTIS: TableDefinition<&str, u64> = TableDefinition::new("used_action_jtis");

pub(crate) const LOCK_BUCKETS: TableDefinition<&str, &[u8]> = TableDefinition::new("lock_buckets");
pub(crate) const LOCK_ENTRIES: TableDefinition<&str, &[u8]> = TableDefinition::new("lock_entries");
pub(crate) const LOCK_CONFLICTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("lock_conflicts");
pub(crate) const LOCK_OUTPUT_CLAIMS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("lock_output_claims");
pub(crate) const LOCK_FILE_INDEX: TableDefinition<&str, &[u8]> =
    TableDefinition::new("lock_file_index");
pub(crate) const LOCK_QUARTER_INDEX: TableDefinition<&str, &[u8]> =
    TableDefinition::new("lock_quarter_index");
pub(crate) const LOCK_ROTATIONS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("lock_rotations");
pub(crate) const LOCK_ANCHORS: TableDefinition<&str, &[u8]> = TableDefinition::new("lock_anchors");

#[derive(Debug, Error)]
pub enum DbError {
    #[error("storage I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database backend error: {0}")]
    Backend(String),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{status}: {message}")]
    Http { status: u16, message: String },
}

impl From<redb::Error> for DbError {
    fn from(e: redb::Error) -> Self {
        Self::Backend(e.to_string())
    }
}
impl From<redb::DatabaseError> for DbError {
    fn from(e: redb::DatabaseError) -> Self {
        Self::Backend(e.to_string())
    }
}
impl From<redb::TransactionError> for DbError {
    fn from(e: redb::TransactionError) -> Self {
        Self::Backend(e.to_string())
    }
}
impl From<redb::TableError> for DbError {
    fn from(e: redb::TableError) -> Self {
        Self::Backend(e.to_string())
    }
}
impl From<redb::StorageError> for DbError {
    fn from(e: redb::StorageError) -> Self {
        Self::Backend(e.to_string())
    }
}
impl From<redb::CommitError> for DbError {
    fn from(e: redb::CommitError) -> Self {
        Self::Backend(e.to_string())
    }
}

impl DbError {
    pub fn http(status: u16, message: impl Into<String>) -> Self {
        Self::Http {
            status,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminMemberRecord {
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Active,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredUserRecord {
    pub pubkey: String,
    pub profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_hmac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_contact_email: Option<Vec<u8>>,
    pub status: AccountStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
    pub registration_gate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotMetaRecord {
    pub owner_pubkey: String,
    pub channel: String,
    pub slot_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    pub size: usize,
    pub etag: String,
    pub mtime: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaMetaRecord {
    pub owner_pubkey: String,
    pub media_id: String,
    pub size: usize,
    pub etag: String,
    pub created_at: u64,
    pub last_access_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemCodeRecord {
    pub code: String,
    pub profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_days: Option<u32>,
    pub max_uses: u32,
    pub used_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EffectiveAccess {
    pub profile_name: String,
    pub profile: ProfileConfig,
    pub allowed_channels: BTreeSet<String>,
    pub is_admin_member: bool,
    pub is_registered: bool,
    pub in_grace_period: bool,
    pub grace_until: Option<u64>,
    pub valid_until: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct HeadCapability {
    pub authorized: bool,
    pub allowed_channels: Vec<String>,
    pub channel_max_bytes: Option<usize>,
    pub channel_ttl_days: Option<u32>,
    pub slot_etag: Option<String>,
    pub slot_occupied: Option<bool>,
    pub media_max_count: Option<usize>,
    pub media_max_user_bytes: Option<u64>,
    pub media_used_count: usize,
    pub media_used_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncIndexEntry {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    pub channel: String,
    pub mtime: u64,
    pub size: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminStatusResponse {
    pub used_bytes: u64,
    pub max_bytes: u64,
    pub soft_limit_bytes: u64,
    pub soft_warning: bool,
    pub slot_count: usize,
    pub channel_counts: BTreeMap<String, usize>,
    pub admin_pubkey: String,
    pub admin_members_count: usize,
    pub registered_users_count: usize,
    pub free_pool_used_bytes: u64,
    pub free_pool_max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUserSummary {
    pub pubkey: String,
    pub profile: String,
    pub effective_profile: String,
    pub status: AccountStatus,
    pub valid_until: Option<u64>,
    pub in_grace_period: bool,
    pub grace_until: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
    pub registration_gate: String,
    pub has_email_hmac: bool,
    pub contact_email: Option<String>,
    pub is_admin_member: bool,
    pub used_bytes: u64,
    pub slot_count: usize,
    pub media_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutOutcome {
    pub channel: String,
    pub bytes: usize,
    pub etag: String,
    pub evicted_media: usize,
}

#[derive(Debug, Clone)]
pub enum ConditionalPrecondition {
    None,
    IfMatch(String),
    IfNoneMatchStar,
}

impl ConditionalPrecondition {
    pub fn from_headers(if_match: Option<&str>, if_none_match: Option<&str>) -> Self {
        if let Some(m) = if_match {
            let clean = normalize_etag(m);
            return Self::IfMatch(clean);
        }
        if let Some(nm) = if_none_match {
            if nm.trim() == "*" {
                return Self::IfNoneMatchStar;
            }
        }
        Self::None
    }
}

pub fn normalize_etag(raw: &str) -> String {
    let trimmed = raw.trim();
    let no_weak = trimmed.strip_prefix("W/").unwrap_or(trimmed);
    no_weak.trim_matches('"').to_string()
}

pub struct SyncDb {
    db: Database,
    pepper: [u8; 32],
    fallback_drop_pub: String,
}

impl SyncDb {
    pub fn open(db_path: &Path, config_pepper_hex: &str) -> Result<Self, DbError> {
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let db = Database::create(db_path)?;

        let write_txn = db.begin_write()?;
        let mut pepper = [0u8; 32];
        {
            let mut server_meta = write_txn.open_table(SERVER_META)?;
            let _ = write_txn.open_table(NONCES)?;
            let _ = write_txn.open_table(ADMIN_MEMBERS)?;
            let _ = write_txn.open_table(REGISTERED_USERS)?;
            let _ = write_txn.open_table(EMAIL_INDEX)?;
            let _ = write_txn.open_table(SLOT_META)?;
            let _ = write_txn.open_table(SLOT_DATA)?;
            let _ = write_txn.open_table(MEDIA_META)?;
            let _ = write_txn.open_table(MEDIA_DATA)?;
            let _ = write_txn.open_table(REDEEM_CODES)?;
            let _ = write_txn.open_table(USED_ACTION_JTIS)?;
            let lock_buckets = write_txn.open_table(LOCK_BUCKETS)?;
            let _ = write_txn.open_table(LOCK_ENTRIES)?;
            let _ = write_txn.open_table(LOCK_CONFLICTS)?;
            let _ = write_txn.open_table(LOCK_OUTPUT_CLAIMS)?;
            let _ = write_txn.open_table(LOCK_FILE_INDEX)?;
            let _ = write_txn.open_table(LOCK_QUARTER_INDEX)?;
            let _ = write_txn.open_table(LOCK_ROTATIONS)?;
            let _ = write_txn.open_table(LOCK_ANCHORS)?;

            // Anti-Amnesia guard (SPEC Section 6.1): if lock buckets exist, the persistent
            // lock signing keypair MUST already exist inside redb.
            let lock_key_existing = server_meta.get("lock_key")?.map(|g| g.value().to_vec());
            match lock_key_existing {
                Some(raw) => {
                    if raw.len() != 32 {
                        return Err(DbError::Backend(
                            "Corrupted SERVER_META['lock_key'] length".to_string(),
                        ));
                    }
                }
                None => {
                    if !lock_buckets.is_empty()? {
                        return Err(DbError::Backend(
                            "Anti-amnesia halt: lock buckets exist in DB but lock_key is missing"
                                .to_string(),
                        ));
                    }
                    let mut sk_bytes = [0u8; 32];
                    OsRng.fill_bytes(&mut sk_bytes);
                    server_meta.insert("lock_key", sk_bytes.as_slice())?;
                }
            }

            if !config_pepper_hex.is_empty() {
                let bytes = hex::decode(config_pepper_hex)
                    .map_err(|_| DbError::http(500, "Invalid configured server_pepper_hex"))?;
                let hash = blake3::hash(&bytes);
                pepper.copy_from_slice(hash.as_bytes());
            } else {
                let existing = server_meta.get("pepper")?.map(|g| g.value().to_vec());
                if let Some(raw) = existing {
                    if raw.len() == 32 {
                        pepper.copy_from_slice(&raw);
                    } else {
                        let hash = blake3::hash(&raw);
                        pepper.copy_from_slice(hash.as_bytes());
                    }
                } else {
                    OsRng.fill_bytes(&mut pepper);
                    server_meta.insert("pepper", pepper.as_slice())?;
                }
            }
        }
        write_txn.commit()?;

        let derived_sk_bytes = blake3::derive_key("humoco-sync server-drop-pub v1", &pepper);
        let derived_vk = ed25519_dalek::SigningKey::from_bytes(&derived_sk_bytes).verifying_key();
        let fallback_drop_pub = hex::encode(derived_vk.as_bytes());

        Ok(Self {
            db,
            pepper,
            fallback_drop_pub,
        })
    }

    pub fn pepper(&self) -> &[u8; 32] {
        &self.pepper
    }

    pub(crate) fn raw_db(&self) -> &Database {
        &self.db
    }

    pub fn effective_drop_pub(&self, cfg: &Config) -> String {
        if !cfg.server.admin_pubkey.is_empty() {
            cfg.server.admin_pubkey.clone()
        } else {
            self.fallback_drop_pub.clone()
        }
    }

    pub fn check_and_consume_nonce(&self, nonce_hex: &str, now_secs: u64) -> Result<bool, DbError> {
        let write_txn = self.db.begin_write()?;
        let inserted = {
            let mut table = write_txn.open_table(NONCES)?;
            let existing = table.get(nonce_hex)?.map(|g| g.value());
            if let Some(exp) = existing {
                if exp > now_secs {
                    false
                } else {
                    table.insert(nonce_hex, now_secs + NONCE_TTL_SECS)?;
                    true
                }
            } else {
                table.insert(nonce_hex, now_secs + NONCE_TTL_SECS)?;
                true
            }
        };
        write_txn.commit()?;
        Ok(inserted)
    }

    pub fn consume_action_jti(&self, jti: &str, exp: u64, now_secs: u64) -> Result<bool, DbError> {
        let write_txn = self.db.begin_write()?;
        let fresh = {
            let mut table = write_txn.open_table(USED_ACTION_JTIS)?;
            let prev_opt = table.get(jti)?.map(|g| g.value());
            if let Some(prev_exp) = prev_opt {
                if prev_exp >= now_secs {
                    false
                } else {
                    table.insert(jti, exp)?;
                    true
                }
            } else {
                table.insert(jti, exp)?;
                true
            }
        };
        write_txn.commit()?;
        Ok(fresh)
    }

    pub fn get_revocation(&self) -> Result<Option<RevocationNotice>, DbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SERVER_META)?;
        if let Some(guard) = table.get("revocation")? {
            let notice: RevocationNotice = serde_json::from_slice(guard.value())?;
            Ok(Some(notice))
        } else {
            Ok(None)
        }
    }

    pub fn set_revocation(&self, notice: Option<&RevocationNotice>) -> Result<(), DbError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SERVER_META)?;
            match notice {
                Some(n) => {
                    let json = serde_json::to_vec(n)?;
                    table.insert("revocation", json.as_slice())?;
                }
                None => {
                    let _ = table.remove("revocation")?;
                }
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    fn admin_channels_for_pubkey_read<R: ReadableTable<&'static str, &'static [u8]>>(
        admin_table: &R,
        cfg: &Config,
        pubkey: &str,
    ) -> Result<BTreeSet<String>, DbError> {
        let mut out = BTreeSet::new();
        if !cfg.mode.enable_admin_app {
            return Ok(out);
        }
        for ch in ADMIN_MEMBER_CHANNELS {
            let key = admin_member_key(ch, pubkey);
            if admin_table.get(key.as_str())?.is_some() {
                out.insert(ch.to_string());
            }
        }
        Ok(out)
    }

    fn resolve_registered_profile<'a>(
        rec: &'a RegisteredUserRecord,
        cfg: &'a Config,
        now_secs: u64,
    ) -> (&'a str, &'a ProfileConfig, bool, Option<u64>) {
        let default_name = cfg.mode.default_public_profile.as_str();
        let requested_name = if cfg.profiles.contains_key(&rec.profile) {
            rec.profile.as_str()
        } else {
            default_name
        };

        if let Some(valid_until) = rec.valid_until {
            if now_secs > valid_until && requested_name != default_name {
                let grace_secs = (cfg.storage.downgrade_grace_days as u64).saturating_mul(86_400);
                let grace_until = valid_until.saturating_add(grace_secs);
                if now_secs <= grace_until {
                    let prof = &cfg.profiles[requested_name];
                    return (requested_name, prof, true, Some(grace_until));
                } else {
                    let prof = &cfg.profiles[default_name];
                    return (default_name, prof, false, None);
                }
            }
        }
        (requested_name, &cfg.profiles[requested_name], false, None)
    }

    fn resolve_member_access_in_txn<
        R1: ReadableTable<&'static str, &'static [u8]>,
        R2: ReadableTable<&'static str, &'static [u8]>,
    >(
        admin_table: &R1,
        reg_table: &R2,
        cfg: &Config,
        pubkey: &str,
        now_secs: u64,
    ) -> Result<Option<EffectiveAccess>, DbError> {
        let admin_channels = Self::admin_channels_for_pubkey_read(admin_table, cfg, pubkey)?;
        let reg_rec: Option<RegisteredUserRecord> = match reg_table.get(pubkey)? {
            Some(g) => Some(serde_json::from_slice(g.value())?),
            None => None,
        };

        let is_admin_member = !admin_channels.is_empty();
        let active_reg = reg_rec
            .as_ref()
            .filter(|r| cfg.mode.enable_public_registration && r.status == AccountStatus::Active);

        if reg_rec
            .as_ref()
            .is_some_and(|r| r.status == AccountStatus::Suspended)
            && !is_admin_member
        {
            return Ok(None);
        }

        match (is_admin_member, active_reg) {
            (false, None) => Ok(None),
            (true, None) => {
                let prof_name = cfg.mode.admin_app_profile.clone();
                let prof = cfg.profiles[&prof_name].clone();
                let mut allowed = admin_channels;
                // Admin friend members authorized on any standard blob channel also get media if profile enables it
                let has_blob_channel = allowed.iter().any(|c| c != "lock");
                if prof.channels.contains_key("media") && has_blob_channel {
                    allowed.insert("media".to_string());
                }
                Ok(Some(EffectiveAccess {
                    profile_name: prof_name,
                    profile: prof,
                    allowed_channels: allowed,
                    is_admin_member: true,
                    is_registered: false,
                    in_grace_period: false,
                    grace_until: None,
                    valid_until: None,
                }))
            }
            (false, Some(rec)) => {
                let (eff_name, eff_prof, in_grace, grace_until) =
                    Self::resolve_registered_profile(rec, cfg, now_secs);
                let allowed: BTreeSet<String> = eff_prof.channels.keys().cloned().collect();
                Ok(Some(EffectiveAccess {
                    profile_name: eff_name.to_string(),
                    profile: eff_prof.clone(),
                    allowed_channels: allowed,
                    is_admin_member: false,
                    is_registered: true,
                    in_grace_period: in_grace,
                    grace_until,
                    valid_until: rec.valid_until,
                }))
            }
            (true, Some(rec)) => {
                let (reg_name, reg_prof, in_grace, grace_until) =
                    Self::resolve_registered_profile(rec, cfg, now_secs);
                let admin_prof_name = cfg.mode.admin_app_profile.as_str();
                let admin_prof = &cfg.profiles[admin_prof_name];
                let (chosen_name, chosen_prof) =
                    if reg_prof.max_total_bytes >= admin_prof.max_total_bytes {
                        (reg_name.to_string(), reg_prof.clone())
                    } else {
                        (admin_prof_name.to_string(), admin_prof.clone())
                    };
                let mut allowed: BTreeSet<String> = admin_channels;
                for ch in chosen_prof.channels.keys() {
                    allowed.insert(ch.clone());
                }
                Ok(Some(EffectiveAccess {
                    profile_name: chosen_name,
                    profile: chosen_prof,
                    allowed_channels: allowed,
                    is_admin_member: true,
                    is_registered: true,
                    in_grace_period: in_grace,
                    grace_until,
                    valid_until: rec.valid_until,
                }))
            }
        }
    }

    pub fn resolve_member_access(
        &self,
        cfg: &Config,
        pubkey: &str,
        now_secs: u64,
    ) -> Result<Option<EffectiveAccess>, DbError> {
        let read_txn = self.db.begin_read()?;
        let admin_table = read_txn.open_table(ADMIN_MEMBERS)?;
        let reg_table = read_txn.open_table(REGISTERED_USERS)?;
        Self::resolve_member_access_in_txn(&admin_table, &reg_table, cfg, pubkey, now_secs)
    }

    pub fn get_registered_user(
        &self,
        pubkey: &str,
    ) -> Result<Option<RegisteredUserRecord>, DbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(REGISTERED_USERS)?;
        match table.get(pubkey)? {
            Some(g) => Ok(Some(serde_json::from_slice(g.value())?)),
            None => Ok(None),
        }
    }

    pub fn head_capability(
        &self,
        cfg: &Config,
        pubkey: &str,
        channel: Option<&str>,
        prefix: Option<&str>,
        media_id: Option<&str>,
        now_secs: u64,
    ) -> Result<HeadCapability, DbError> {
        let read_txn = self.db.begin_read()?;
        let admin_table = read_txn.open_table(ADMIN_MEMBERS)?;
        let reg_table = read_txn.open_table(REGISTERED_USERS)?;
        let slot_meta = read_txn.open_table(SLOT_META)?;
        let media_meta = read_txn.open_table(MEDIA_META)?;

        let access =
            Self::resolve_member_access_in_txn(&admin_table, &reg_table, cfg, pubkey, now_secs)?;

        let mut media_used_count = 0usize;
        let mut media_used_bytes = 0u64;
        for entry in media_meta.iter()? {
            let (_, val) = entry?;
            let meta: MediaMetaRecord = serde_json::from_slice(val.value())?;
            if meta.owner_pubkey == pubkey {
                media_used_count += 1;
                media_used_bytes += meta.size as u64;
            }
        }

        let Some(access) = access else {
            return Ok(HeadCapability {
                authorized: false,
                allowed_channels: Vec::new(),
                channel_max_bytes: None,
                channel_ttl_days: None,
                slot_etag: None,
                slot_occupied: None,
                media_max_count: None,
                media_max_user_bytes: None,
                media_used_count,
                media_used_bytes,
            });
        };

        let allowed_channels: Vec<String> = ADMIN_MEMBER_CHANNELS
            .iter()
            .filter(|ch| access.allowed_channels.contains(**ch))
            .map(|s| s.to_string())
            .collect();

        let requested_authorized = match channel {
            Some(ch) => access.allowed_channels.contains(ch),
            None => !allowed_channels.is_empty(),
        };

        let (ch_max_bytes, ch_ttl_days) = if let Some(ch) = channel {
            if let Some(q) = access.profile.channels.get(ch) {
                (
                    Some(q.max_bytes),
                    if q.ttl_days > 0 {
                        Some(q.ttl_days)
                    } else {
                        None
                    },
                )
            } else if ch == "media" {
                (
                    Some(cfg.media.max_bytes),
                    if cfg.media.ttl_days > 0 {
                        Some(cfg.media.ttl_days)
                    } else {
                        None
                    },
                )
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let (media_max_count, media_max_user_bytes) =
            if let Some(mq) = access.profile.channels.get("media") {
                (
                    Some(mq.max_user_count.unwrap_or(cfg.media.max_user_count)),
                    Some(mq.max_user_bytes.unwrap_or(cfg.media.max_user_bytes)),
                )
            } else {
                (
                    Some(cfg.media.max_user_count),
                    Some(cfg.media.max_user_bytes),
                )
            };

        let (slot_occupied, slot_etag) = match channel {
            Some("media") => {
                if let Some(mid) = media_id {
                    if let Some(g) = media_meta.get(mid)? {
                        let meta: MediaMetaRecord = serde_json::from_slice(g.value())?;
                        if meta.owner_pubkey == pubkey {
                            (Some(true), Some(meta.etag))
                        } else {
                            (Some(true), None)
                        }
                    } else {
                        (Some(false), None)
                    }
                } else {
                    (None, None)
                }
            }
            Some(ch) => {
                let slot_id = crate::crypto::format_slot_id(pubkey, prefix);
                let skey = slot_key(ch, &slot_id);
                if let Some(g) = slot_meta.get(skey.as_str())? {
                    let meta: SlotMetaRecord = serde_json::from_slice(g.value())?;
                    (Some(true), Some(meta.etag))
                } else {
                    (Some(false), None)
                }
            }
            None => (None, None),
        };

        Ok(HeadCapability {
            authorized: requested_authorized,
            allowed_channels,
            channel_max_bytes: ch_max_bytes,
            channel_ttl_days: ch_ttl_days,
            slot_etag,
            slot_occupied,
            media_max_count,
            media_max_user_bytes,
            media_used_count,
            media_used_bytes,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn put_slot(
        &self,
        cfg: &Config,
        pubkey: &str,
        channel: &str,
        prefix: Option<&str>,
        data: &[u8],
        precondition: &ConditionalPrecondition,
        now_secs: u64,
    ) -> Result<PutOutcome, DbError> {
        if channel == "media" {
            return Err(DbError::http(
                400,
                "Use media endpoint headers for media uploads",
            ));
        }
        let slot_id = crate::crypto::format_slot_id(pubkey, prefix);
        let skey = slot_key(channel, &slot_id);

        let write_txn = self.db.begin_write()?;
        let outcome = {
            let admin_table = write_txn.open_table(ADMIN_MEMBERS)?;
            let reg_table = write_txn.open_table(REGISTERED_USERS)?;
            let mut slot_meta = write_txn.open_table(SLOT_META)?;
            let mut slot_data = write_txn.open_table(SLOT_DATA)?;
            let mut media_meta = write_txn.open_table(MEDIA_META)?;
            let mut media_data = write_txn.open_table(MEDIA_DATA)?;

            let access = Self::resolve_member_access_in_txn(
                &admin_table,
                &reg_table,
                cfg,
                pubkey,
                now_secs,
            )?
            .filter(|a| a.allowed_channels.contains(channel))
            .ok_or_else(|| DbError::http(403, "Pubkey not authorized for channel"))?;

            let max_ch_bytes = access
                .profile
                .channels
                .get(channel)
                .map(|c| c.max_bytes)
                .ok_or_else(|| DbError::http(403, "Channel disabled in profile"))?;

            if data.len() > max_ch_bytes {
                return Err(DbError::http(413, "Payload exceeds channel limit"));
            }

            let existing_meta: Option<SlotMetaRecord> = match slot_meta.get(skey.as_str())? {
                Some(g) => Some(serde_json::from_slice(g.value())?),
                None => None,
            };

            if let Some(ref em) = existing_meta {
                if em.owner_pubkey != pubkey {
                    return Err(DbError::http(403, "Slot owned by different pubkey"));
                }
            }

            match precondition {
                ConditionalPrecondition::None => {}
                ConditionalPrecondition::IfMatch(expected) => match &existing_meta {
                    Some(em) if &em.etag == expected => {}
                    Some(em) => {
                        return Err(DbError::http(412, format!("ETAG_MISMATCH:{}", em.etag)));
                    }
                    None => return Err(DbError::http(412, "ETAG_MISMATCH:")),
                },
                ConditionalPrecondition::IfNoneMatchStar => {
                    if let Some(em) = &existing_meta {
                        return Err(DbError::http(412, format!("ETAG_MISMATCH:{}", em.etag)));
                    }
                }
            }

            let old_size = existing_meta.as_ref().map(|m| m.size).unwrap_or(0) as i64;
            let delta = data.len() as i64 - old_size;
            let mut evicted_media = 0usize;

            if delta > 0 {
                let delta_u = delta as u64;
                evicted_media = ensure_quota_with_media_eviction(
                    cfg,
                    &admin_table,
                    &reg_table,
                    &slot_meta,
                    &mut media_meta,
                    &mut media_data,
                    pubkey,
                    &access,
                    delta_u,
                    None,
                    now_secs,
                )?;
            }

            let etag = sha256_hex(data);
            let new_meta = SlotMetaRecord {
                owner_pubkey: pubkey.to_string(),
                channel: channel.to_string(),
                slot_id: slot_id.clone(),
                prefix: prefix.map(|s| s.to_string()),
                size: data.len(),
                etag: etag.clone(),
                mtime: now_secs,
            };
            slot_meta.insert(skey.as_str(), serde_json::to_vec(&new_meta)?.as_slice())?;
            slot_data.insert(skey.as_str(), data)?;

            PutOutcome {
                channel: channel.to_string(),
                bytes: data.len(),
                etag,
                evicted_media,
            }
        };
        write_txn.commit()?;
        Ok(outcome)
    }

    pub fn put_media(
        &self,
        cfg: &Config,
        pubkey: &str,
        media_id: &str,
        data: &[u8],
        precondition: &ConditionalPrecondition,
        now_secs: u64,
    ) -> Result<PutOutcome, DbError> {
        let write_txn = self.db.begin_write()?;
        let outcome = {
            let admin_table = write_txn.open_table(ADMIN_MEMBERS)?;
            let reg_table = write_txn.open_table(REGISTERED_USERS)?;
            let slot_meta = write_txn.open_table(SLOT_META)?;
            let mut media_meta = write_txn.open_table(MEDIA_META)?;
            let mut media_data = write_txn.open_table(MEDIA_DATA)?;

            let access = Self::resolve_member_access_in_txn(
                &admin_table,
                &reg_table,
                cfg,
                pubkey,
                now_secs,
            )?
            .filter(|a| a.allowed_channels.contains("media"))
            .ok_or_else(|| DbError::http(403, "Pubkey not authorized for media channel"))?;

            let media_q = access.profile.channels.get("media");
            let max_blob_bytes = media_q.map(|q| q.max_bytes).unwrap_or(cfg.media.max_bytes);
            let max_user_count = media_q
                .and_then(|q| q.max_user_count)
                .unwrap_or(cfg.media.max_user_count);
            let max_user_bytes = media_q
                .and_then(|q| q.max_user_bytes)
                .unwrap_or(cfg.media.max_user_bytes);

            if data.len() > max_blob_bytes || (data.len() as u64) > max_user_bytes {
                return Err(DbError::http(
                    413,
                    "Media blob exceeds per-blob or user limit",
                ));
            }

            let existing: Option<MediaMetaRecord> = match media_meta.get(media_id)? {
                Some(g) => Some(serde_json::from_slice(g.value())?),
                None => None,
            };
            if let Some(ref em) = existing {
                if em.owner_pubkey != pubkey {
                    return Err(DbError::http(403, "Media blob owned by another pubkey"));
                }
            }

            match precondition {
                ConditionalPrecondition::None => {}
                ConditionalPrecondition::IfMatch(expected) => match &existing {
                    Some(em) if &em.etag == expected => {}
                    Some(em) => {
                        return Err(DbError::http(412, format!("ETAG_MISMATCH:{}", em.etag)));
                    }
                    None => return Err(DbError::http(412, "ETAG_MISMATCH:")),
                },
                ConditionalPrecondition::IfNoneMatchStar => {
                    if let Some(em) = &existing {
                        return Err(DbError::http(412, format!("ETAG_MISMATCH:{}", em.etag)));
                    }
                }
            }

            let mut evicted = 0usize;
            // Evict user's own oldest media if per-user count or bytes exceeded
            loop {
                let mut user_media: Vec<MediaMetaRecord> = Vec::new();
                let mut user_bytes = 0u64;
                for entry in media_meta.iter()? {
                    let (_, val) = entry?;
                    let m: MediaMetaRecord = serde_json::from_slice(val.value())?;
                    if m.owner_pubkey == pubkey && m.media_id != media_id {
                        user_bytes += m.size as u64;
                        user_media.push(m);
                    }
                }
                let need_count = max_user_count > 0 && user_media.len() >= max_user_count;
                let need_bytes = user_bytes + data.len() as u64 > max_user_bytes;
                if !need_count && !need_bytes {
                    break;
                }
                user_media.sort_by_key(|m| (m.last_access_at, m.created_at, m.media_id.clone()));
                if let Some(victim) = user_media.first() {
                    media_meta.remove(victim.media_id.as_str())?;
                    media_data.remove(victim.media_id.as_str())?;
                    evicted += 1;
                } else {
                    return Err(DbError::http(507, "Media user quota exceeded"));
                }
            }

            // Enforce media channel global cap
            let max_channel_bytes = cfg.media_channel_max_bytes();
            if max_channel_bytes > 0 {
                if (data.len() as u64) > max_channel_bytes {
                    return Err(DbError::http(
                        507,
                        "Media exceeds total media channel capacity",
                    ));
                }
                loop {
                    let mut all_media: Vec<(MediaMetaRecord, bool)> = Vec::new();
                    let mut total_media_bytes = 0u64;
                    for entry in media_meta.iter()? {
                        let (_, val) = entry?;
                        let m: MediaMetaRecord = serde_json::from_slice(val.value())?;
                        if m.media_id != media_id {
                            total_media_bytes += m.size as u64;
                            let is_free = Self::resolve_member_access_in_txn(
                                &admin_table,
                                &reg_table,
                                cfg,
                                &m.owner_pubkey,
                                now_secs,
                            )?
                            .map(|a| a.profile.is_free_pool)
                            .unwrap_or(true);
                            all_media.push((m, is_free));
                        }
                    }
                    if total_media_bytes + data.len() as u64 <= max_channel_bytes {
                        break;
                    }
                    all_media.sort_by_key(|(m, is_free)| {
                        (
                            !*is_free,
                            m.last_access_at,
                            m.created_at,
                            m.media_id.clone(),
                        )
                    });
                    if let Some((victim, victim_free)) = all_media.first() {
                        if access.profile.is_free_pool && !*victim_free {
                            return Err(DbError::http(507, "Free media pool exhausted"));
                        }
                        media_meta.remove(victim.media_id.as_str())?;
                        media_data.remove(victim.media_id.as_str())?;
                        evicted += 1;
                    } else {
                        return Err(DbError::http(507, "Media channel quota exceeded"));
                    }
                }
            }

            let old_size = existing.as_ref().map(|m| m.size).unwrap_or(0) as i64;
            let delta = data.len() as i64 - old_size;
            if delta > 0 {
                evicted += ensure_quota_with_media_eviction(
                    cfg,
                    &admin_table,
                    &reg_table,
                    &slot_meta,
                    &mut media_meta,
                    &mut media_data,
                    pubkey,
                    &access,
                    delta as u64,
                    Some(media_id),
                    now_secs,
                )?;
            }

            let etag = sha256_hex(data);
            let meta = MediaMetaRecord {
                owner_pubkey: pubkey.to_string(),
                media_id: media_id.to_string(),
                size: data.len(),
                etag: etag.clone(),
                created_at: existing.as_ref().map(|m| m.created_at).unwrap_or(now_secs),
                last_access_at: now_secs,
            };
            media_meta.insert(media_id, serde_json::to_vec(&meta)?.as_slice())?;
            media_data.insert(media_id, data)?;

            PutOutcome {
                channel: "media".to_string(),
                bytes: data.len(),
                etag,
                evicted_media: evicted,
            }
        };
        write_txn.commit()?;
        Ok(outcome)
    }

    pub fn delete_slot(
        &self,
        cfg: &Config,
        pubkey: &str,
        channel: &str,
        prefix: Option<&str>,
        now_secs: u64,
    ) -> Result<(), DbError> {
        let slot_id = crate::crypto::format_slot_id(pubkey, prefix);
        let skey = slot_key(channel, &slot_id);
        let write_txn = self.db.begin_write()?;
        {
            let admin_table = write_txn.open_table(ADMIN_MEMBERS)?;
            let reg_table = write_txn.open_table(REGISTERED_USERS)?;
            let mut slot_meta = write_txn.open_table(SLOT_META)?;
            let mut slot_data = write_txn.open_table(SLOT_DATA)?;

            let access = Self::resolve_member_access_in_txn(
                &admin_table,
                &reg_table,
                cfg,
                pubkey,
                now_secs,
            )?;
            if access
                .as_ref()
                .is_some_and(|a| a.allowed_channels.contains(channel))
            {
                // authorized
            } else {
                // Still allow owner to delete their own leftover slot if they own it
                match slot_meta.get(skey.as_str())? {
                    Some(g) => {
                        let m: SlotMetaRecord = serde_json::from_slice(g.value())?;
                        if m.owner_pubkey != pubkey {
                            return Err(DbError::http(403, "Not authorized"));
                        }
                    }
                    None => return Err(DbError::http(403, "Not authorized")),
                }
            }

            if let Some(g) = slot_meta.get(skey.as_str())? {
                let m: SlotMetaRecord = serde_json::from_slice(g.value())?;
                if m.owner_pubkey != pubkey {
                    return Err(DbError::http(403, "Slot owned by different pubkey"));
                }
            }
            slot_meta.remove(skey.as_str())?;
            slot_data.remove(skey.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn delete_media(
        &self,
        cfg: &Config,
        pubkey: &str,
        media_id: Option<&str>,
        now_secs: u64,
    ) -> Result<usize, DbError> {
        let write_txn = self.db.begin_write()?;
        let deleted_count = {
            let admin_table = write_txn.open_table(ADMIN_MEMBERS)?;
            let reg_table = write_txn.open_table(REGISTERED_USERS)?;
            let mut media_meta = write_txn.open_table(MEDIA_META)?;
            let mut media_data = write_txn.open_table(MEDIA_DATA)?;

            let _ = Self::resolve_member_access_in_txn(
                &admin_table,
                &reg_table,
                cfg,
                pubkey,
                now_secs,
            )?;

            if let Some(mid) = media_id {
                let existing: Option<MediaMetaRecord> = match media_meta.get(mid)? {
                    Some(g) => Some(serde_json::from_slice(g.value())?),
                    None => None,
                };
                if let Some(meta) = existing {
                    if meta.owner_pubkey != pubkey {
                        return Err(DbError::http(403, "Media blob owned by another pubkey"));
                    }
                    media_meta.remove(mid)?;
                    media_data.remove(mid)?;
                    1
                } else {
                    0
                }
            } else {
                let mut to_remove = Vec::new();
                for entry in media_meta.iter()? {
                    let (k, v) = entry?;
                    let meta: MediaMetaRecord = serde_json::from_slice(v.value())?;
                    if meta.owner_pubkey == pubkey {
                        to_remove.push(k.value().to_string());
                    }
                }
                let n = to_remove.len();
                for mid in to_remove {
                    media_meta.remove(mid.as_str())?;
                    media_data.remove(mid.as_str())?;
                }
                n
            }
        };
        write_txn.commit()?;
        Ok(deleted_count)
    }

    /// Deletes a registered account (and removes all slots + media blobs owned by pubkey).
    /// Also removes from ADMIN_MEMBERS if `also_remove_admin_membership` is true.
    pub fn delete_account_and_data(
        &self,
        pubkey: &str,
        also_remove_admin_membership: bool,
    ) -> Result<(usize, usize, bool), DbError> {
        let write_txn = self.db.begin_write()?;
        let (deleted_slots, deleted_media, deleted_account) = {
            let mut admin_table = write_txn.open_table(ADMIN_MEMBERS)?;
            let mut reg_table = write_txn.open_table(REGISTERED_USERS)?;
            let mut email_idx = write_txn.open_table(EMAIL_INDEX)?;
            let mut slot_meta = write_txn.open_table(SLOT_META)?;
            let mut slot_data = write_txn.open_table(SLOT_DATA)?;
            let mut media_meta = write_txn.open_table(MEDIA_META)?;
            let mut media_data = write_txn.open_table(MEDIA_DATA)?;

            let reg_rec: Option<RegisteredUserRecord> = match reg_table.get(pubkey)? {
                Some(g) => Some(serde_json::from_slice(g.value())?),
                None => None,
            };
            let deleted_account = reg_rec.is_some();
            if let Some(rec) = reg_rec {
                if let Some(ref hmac) = rec.email_hmac {
                    let _ = email_idx.remove(hmac.as_str())?;
                }
                reg_table.remove(pubkey)?;
            }

            if also_remove_admin_membership {
                for ch in ADMIN_MEMBER_CHANNELS {
                    let key = admin_member_key(ch, pubkey);
                    let _ = admin_table.remove(key.as_str())?;
                }
            }

            let mut slot_keys = Vec::new();
            for entry in slot_meta.iter()? {
                let (k, v) = entry?;
                let meta: SlotMetaRecord = serde_json::from_slice(v.value())?;
                if meta.owner_pubkey == pubkey {
                    slot_keys.push(k.value().to_string());
                }
            }
            let ds = slot_keys.len();
            for k in slot_keys {
                slot_meta.remove(k.as_str())?;
                slot_data.remove(k.as_str())?;
            }

            let mut media_ids = Vec::new();
            for entry in media_meta.iter()? {
                let (k, v) = entry?;
                let meta: MediaMetaRecord = serde_json::from_slice(v.value())?;
                if meta.owner_pubkey == pubkey {
                    media_ids.push(k.value().to_string());
                }
            }
            let dm = media_ids.len();
            for mid in media_ids {
                media_meta.remove(mid.as_str())?;
                media_data.remove(mid.as_str())?;
            }

            (ds, dm, deleted_account)
        };
        write_txn.commit()?;
        Ok((deleted_slots, deleted_media, deleted_account))
    }

    /// Replaces `ADMIN_MEMBERS` for `channel` ONLY.
    /// Hybrid Invariant: Never modifies or deletes `REGISTERED_USERS` or slots owned by registered users!
    pub fn put_admin_members(
        &self,
        cfg: &Config,
        channel: &str,
        pubkeys: &[String],
        now_secs: u64,
    ) -> Result<usize, DbError> {
        if !cfg.mode.enable_admin_app {
            return Err(DbError::http(403, "Admin app member management disabled"));
        }
        if pubkeys.len() > cfg.mode.max_admin_members {
            return Err(DbError::http(413, "Too many members for channel"));
        }
        let target_set: BTreeSet<String> = pubkeys.iter().cloned().collect();

        let write_txn = self.db.begin_write()?;
        {
            let mut admin_table = write_txn.open_table(ADMIN_MEMBERS)?;
            let reg_table = write_txn.open_table(REGISTERED_USERS)?;
            let mut slot_meta = write_txn.open_table(SLOT_META)?;
            let mut slot_data = write_txn.open_table(SLOT_DATA)?;
            let mut media_meta = write_txn.open_table(MEDIA_META)?;
            let mut media_data = write_txn.open_table(MEDIA_DATA)?;

            let prefix = format!("{}:", channel);
            let mut old_pubkeys = Vec::new();
            for entry in admin_table.iter()? {
                let (k, _) = entry?;
                let ks = k.value();
                if let Some(pk) = ks.strip_prefix(&prefix) {
                    old_pubkeys.push(pk.to_string());
                }
            }

            let mut removed_pubkeys = Vec::new();
            for old_pk in old_pubkeys {
                if !target_set.contains(&old_pk) {
                    admin_table.remove(admin_member_key(channel, &old_pk).as_str())?;
                    removed_pubkeys.push(old_pk);
                }
            }

            let record_bytes = serde_json::to_vec(&AdminMemberRecord {
                created_at: now_secs,
            })?;
            for pk in &target_set {
                let key = admin_member_key(channel, pk);
                if admin_table.get(key.as_str())?.is_none() {
                    admin_table.insert(key.as_str(), record_bytes.as_slice())?;
                }
            }

            // Prune orphaned slots in `channel` ONLY for removed pubkeys NOT authorized via REGISTERED_USERS
            let removed_set: BTreeSet<String> = removed_pubkeys.into_iter().collect();
            if !removed_set.is_empty() {
                let mut slots_to_delete = Vec::new();
                for entry in slot_meta.iter()? {
                    let (k, v) = entry?;
                    let meta: SlotMetaRecord = serde_json::from_slice(v.value())?;
                    if meta.channel == channel && removed_set.contains(&meta.owner_pubkey) {
                        let still_authorized = Self::resolve_member_access_in_txn(
                            &admin_table,
                            &reg_table,
                            cfg,
                            &meta.owner_pubkey,
                            now_secs,
                        )?
                        .is_some_and(|a| a.allowed_channels.contains(channel));
                        if !still_authorized {
                            slots_to_delete.push(k.value().to_string());
                        }
                    }
                }
                for sk in slots_to_delete {
                    slot_meta.remove(sk.as_str())?;
                    slot_data.remove(sk.as_str())?;
                }

                // Prune orphaned media if removed user no longer has ANY authorization on the server
                let mut still_unauthorized = BTreeSet::new();
                for pk in &removed_set {
                    if Self::resolve_member_access_in_txn(
                        &admin_table,
                        &reg_table,
                        cfg,
                        pk,
                        now_secs,
                    )?
                    .is_none()
                    {
                        still_unauthorized.insert(pk.clone());
                    }
                }
                if !still_unauthorized.is_empty() {
                    let mut media_to_del = Vec::new();
                    for entry in media_meta.iter()? {
                        let (k, v) = entry?;
                        let m: MediaMetaRecord = serde_json::from_slice(v.value())?;
                        if still_unauthorized.contains(&m.owner_pubkey) {
                            media_to_del.push(k.value().to_string());
                        }
                    }
                    for mid in media_to_del {
                        media_meta.remove(mid.as_str())?;
                        media_data.remove(mid.as_str())?;
                    }
                }
            }
        }
        write_txn.commit()?;
        Ok(target_set.len())
    }

    pub fn build_admin_index(
        &self,
        cfg: &Config,
    ) -> Result<(Vec<SyncIndexEntry>, String), DbError> {
        let read_txn = self.db.begin_read()?;
        let admin_table = read_txn.open_table(ADMIN_MEMBERS)?;
        let slot_meta = read_txn.open_table(SLOT_META)?;

        let mut entries = Vec::new();
        if cfg.mode.enable_admin_app {
            for entry in slot_meta.iter()? {
                let (_, v) = entry?;
                let meta: SlotMetaRecord = serde_json::from_slice(v.value())?;
                if meta.channel == "media" {
                    continue;
                }
                // Hybrid invariant: ONLY admin_app member slots appear in index.json!
                let key = admin_member_key(&meta.channel, &meta.owner_pubkey);
                if admin_table.get(key.as_str())?.is_some() {
                    entries.push(SyncIndexEntry {
                        id: meta.owner_pubkey,
                        prefix: meta.prefix,
                        channel: meta.channel,
                        mtime: meta.mtime,
                        size: meta.size,
                        etag: Some(meta.etag),
                    });
                }
            }
        }
        entries.sort_by(|a, b| {
            a.id.cmp(&b.id)
                .then(a.channel.cmp(&b.channel))
                .then(a.prefix.cmp(&b.prefix))
        });
        let json_bytes = serde_json::to_vec(&entries)?;
        let etag = sha256_hex(&json_bytes);
        Ok((entries, etag))
    }

    pub fn get_slot_blob(
        &self,
        cfg: &Config,
        channel: &str,
        slot_id: &str,
        now_secs: u64,
    ) -> Result<Option<(SlotMetaRecord, Vec<u8>)>, DbError> {
        let skey = slot_key(channel, slot_id);
        let read_txn = self.db.begin_read()?;
        let admin_table = read_txn.open_table(ADMIN_MEMBERS)?;
        let reg_table = read_txn.open_table(REGISTERED_USERS)?;
        let slot_meta = read_txn.open_table(SLOT_META)?;
        let slot_data = read_txn.open_table(SLOT_DATA)?;

        let Some(meta_guard) = slot_meta.get(skey.as_str())? else {
            return Ok(None);
        };
        let meta: SlotMetaRecord = serde_json::from_slice(meta_guard.value())?;

        // Respect TTL expiration
        if let Some(access) = Self::resolve_member_access_in_txn(
            &admin_table,
            &reg_table,
            cfg,
            &meta.owner_pubkey,
            now_secs,
        )? {
            if let Some(q) = access.profile.channels.get(channel) {
                if q.ttl_days > 0 {
                    let ttl_secs = (q.ttl_days as u64).saturating_mul(86_400);
                    if meta.mtime.saturating_add(ttl_secs) < now_secs {
                        return Ok(None);
                    }
                }
            }
        }

        let Some(data_guard) = slot_data.get(skey.as_str())? else {
            return Ok(None);
        };
        Ok(Some((meta, data_guard.value().to_vec())))
    }

    pub fn get_media_blob(
        &self,
        cfg: &Config,
        media_id: &str,
        now_secs: u64,
    ) -> Result<Option<(MediaMetaRecord, Vec<u8>)>, DbError> {
        let read_txn = self.db.begin_read()?;
        let admin_table = read_txn.open_table(ADMIN_MEMBERS)?;
        let reg_table = read_txn.open_table(REGISTERED_USERS)?;
        let media_meta = read_txn.open_table(MEDIA_META)?;
        let media_data = read_txn.open_table(MEDIA_DATA)?;

        let Some(meta_guard) = media_meta.get(media_id)? else {
            return Ok(None);
        };
        let meta: MediaMetaRecord = serde_json::from_slice(meta_guard.value())?;

        let ttl_days = Self::resolve_member_access_in_txn(
            &admin_table,
            &reg_table,
            cfg,
            &meta.owner_pubkey,
            now_secs,
        )?
        .and_then(|a| a.profile.channels.get("media").map(|q| q.ttl_days))
        .unwrap_or(cfg.media.ttl_days);
        if ttl_days > 0 {
            let ttl_secs = (ttl_days as u64).saturating_mul(86_400);
            if meta.created_at.saturating_add(ttl_secs) < now_secs {
                return Ok(None);
            }
        }

        let Some(data_guard) = media_data.get(media_id)? else {
            return Ok(None);
        };
        Ok(Some((meta, data_guard.value().to_vec())))
    }

    pub fn touch_media_access(&self, media_id: &str, now_secs: u64) -> Result<(), DbError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut media_meta = write_txn.open_table(MEDIA_META)?;
            let updated = if let Some(g) = media_meta.get(media_id)? {
                let mut m: MediaMetaRecord = serde_json::from_slice(g.value())?;
                if now_secs.saturating_sub(m.last_access_at) >= 60 {
                    m.last_access_at = now_secs;
                    Some(serde_json::to_vec(&m)?)
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(bytes) = updated {
                media_meta.insert(media_id, bytes.as_slice())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn admin_status(
        &self,
        cfg: &Config,
        now_secs: u64,
    ) -> Result<AdminStatusResponse, DbError> {
        let read_txn = self.db.begin_read()?;
        let admin_table = read_txn.open_table(ADMIN_MEMBERS)?;
        let reg_table = read_txn.open_table(REGISTERED_USERS)?;
        let slot_meta = read_txn.open_table(SLOT_META)?;
        let media_meta = read_txn.open_table(MEDIA_META)?;

        let mut admin_unique_pks = BTreeSet::new();
        for entry in admin_table.iter()? {
            let (k, _) = entry?;
            if let Some((_, pk)) = k.value().split_once(':') {
                admin_unique_pks.insert(pk.to_string());
            }
        }
        let registered_users_count = reg_table.len()? as usize;

        let mut used_bytes = 0u64;
        let mut free_pool_used_bytes = 0u64;
        let mut slot_count = 0usize;
        let mut channel_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut owner_free_cache: BTreeMap<String, bool> = BTreeMap::new();

        for entry in slot_meta.iter()? {
            let (_, v) = entry?;
            let meta: SlotMetaRecord = serde_json::from_slice(v.value())?;
            slot_count += 1;
            used_bytes += meta.size as u64;
            *channel_counts.entry(meta.channel.clone()).or_insert(0) += 1;
            let is_free = if let Some(&cached) = owner_free_cache.get(&meta.owner_pubkey) {
                cached
            } else {
                let f = Self::resolve_member_access_in_txn(
                    &admin_table,
                    &reg_table,
                    cfg,
                    &meta.owner_pubkey,
                    now_secs,
                )?
                .map(|a| a.profile.is_free_pool)
                .unwrap_or(true);
                owner_free_cache.insert(meta.owner_pubkey.clone(), f);
                f
            };
            if is_free {
                free_pool_used_bytes += meta.size as u64;
            }
        }

        for entry in media_meta.iter()? {
            let (_, v) = entry?;
            let m: MediaMetaRecord = serde_json::from_slice(v.value())?;
            slot_count += 1;
            used_bytes += m.size as u64;
            *channel_counts.entry("media".to_string()).or_insert(0) += 1;
            let is_free = if let Some(&cached) = owner_free_cache.get(&m.owner_pubkey) {
                cached
            } else {
                let f = Self::resolve_member_access_in_txn(
                    &admin_table,
                    &reg_table,
                    cfg,
                    &m.owner_pubkey,
                    now_secs,
                )?
                .map(|a| a.profile.is_free_pool)
                .unwrap_or(true);
                owner_free_cache.insert(m.owner_pubkey.clone(), f);
                f
            };
            if is_free {
                free_pool_used_bytes += m.size as u64;
            }
        }

        let max_bytes = cfg.max_total_bytes();
        let soft_limit_bytes = cfg.soft_limit_bytes();

        Ok(AdminStatusResponse {
            used_bytes,
            max_bytes,
            soft_limit_bytes,
            soft_warning: used_bytes >= soft_limit_bytes,
            slot_count,
            channel_counts,
            admin_pubkey: cfg.server.admin_pubkey.clone(),
            admin_members_count: admin_unique_pks.len(),
            registered_users_count,
            free_pool_used_bytes,
            free_pool_max_bytes: cfg.max_free_pool_bytes(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_or_upgrade_user(
        &self,
        cfg: &Config,
        pubkey: &str,
        profile_name: &str,
        raw_email: Option<&str>,
        duration_days: Option<u32>,
        gate: &str,
        now_secs: u64,
    ) -> Result<RegisteredUserRecord, DbError> {
        let email_info = match raw_email {
            Some(e) => {
                let canon = canonicalize_email(e)
                    .ok_or_else(|| DbError::http(400, "Invalid email address"))?;
                let hmac = hmac_email(&self.pepper, &canon);
                Some((canon, hmac))
            }
            None => None,
        };
        let (contact_email, hmac_ref) = match &email_info {
            Some((canon, hmac)) => (Some(canon.as_str()), Some(hmac.as_str())),
            None => (None, None),
        };
        self.register_or_upgrade_user_by_hmac(
            cfg,
            pubkey,
            profile_name,
            hmac_ref,
            contact_email,
            duration_days,
            gate,
            now_secs,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_or_upgrade_user_by_hmac(
        &self,
        cfg: &Config,
        pubkey: &str,
        profile_name: &str,
        email_hmac_opt: Option<&str>,
        contact_email_opt: Option<&str>,
        duration_days: Option<u32>,
        gate: &str,
        now_secs: u64,
    ) -> Result<RegisteredUserRecord, DbError> {
        let Some(profile_cfg) = cfg.profiles.get(profile_name) else {
            return Err(DbError::http(
                400,
                format!("Unknown profile '{}'", profile_name),
            ));
        };

        let write_txn = self.db.begin_write()?;
        let rec = {
            let mut reg_table = write_txn.open_table(REGISTERED_USERS)?;
            let mut email_idx = write_txn.open_table(EMAIL_INDEX)?;

            let existing: Option<RegisteredUserRecord> = match reg_table.get(pubkey)? {
                Some(g) => Some(serde_json::from_slice(g.value())?),
                None => None,
            };

            let mut final_email_hmac = existing.as_ref().and_then(|r| r.email_hmac.clone());
            let mut final_enc_email = existing
                .as_ref()
                .and_then(|r| r.encrypted_contact_email.clone());

            if let Some(hmac) = email_hmac_opt {
                if let Some(bound_pk_guard) = email_idx.get(hmac)? {
                    let bound_pk = bound_pk_guard.value().to_string();
                    if bound_pk != pubkey && reg_table.get(bound_pk.as_str())?.is_some() {
                        return Err(DbError::http(
                            409,
                            "This email address is already bound to another registered key",
                        ));
                    }
                }
                if let Some(ref prev_hmac) = final_email_hmac {
                    if prev_hmac != hmac {
                        let _ = email_idx.remove(prev_hmac.as_str())?;
                    }
                }
                email_idx.insert(hmac, pubkey)?;
                final_email_hmac = Some(hmac.to_string());
            }

            if profile_cfg.store_contact_email {
                if let Some(email_plain) = contact_email_opt {
                    final_enc_email = Some(
                        encrypt_contact_email(&self.pepper, email_plain)
                            .map_err(|e| DbError::http(500, e))?,
                    );
                }
            } else {
                final_enc_email = None;
            }

            let valid_until = duration_days.map(|days| {
                let add_secs = (days as u64).saturating_mul(86_400);
                let base = existing
                    .as_ref()
                    .and_then(|e| e.valid_until)
                    .filter(|&v| v > now_secs)
                    .unwrap_or(now_secs);
                base.saturating_add(add_secs)
            });

            let rec = RegisteredUserRecord {
                pubkey: pubkey.to_string(),
                profile: profile_name.to_string(),
                email_hmac: final_email_hmac,
                encrypted_contact_email: final_enc_email,
                status: AccountStatus::Active,
                valid_until,
                created_at: existing.as_ref().map(|e| e.created_at).unwrap_or(now_secs),
                updated_at: now_secs,
                registration_gate: gate.to_string(),
            };
            reg_table.insert(pubkey, serde_json::to_vec(&rec)?.as_slice())?;
            rec
        };
        write_txn.commit()?;
        Ok(rec)
    }

    pub fn check_email_not_used_by_other(
        &self,
        raw_email: &str,
        pubkey: &str,
    ) -> Result<(), DbError> {
        let canon = canonicalize_email(raw_email)
            .ok_or_else(|| DbError::http(400, "Invalid email address"))?;
        let hmac = hmac_email(&self.pepper, &canon);
        let read_txn = self.db.begin_read()?;
        let email_idx = read_txn.open_table(EMAIL_INDEX)?;
        let reg_table = read_txn.open_table(REGISTERED_USERS)?;
        if let Some(bound_pk_guard) = email_idx.get(hmac.as_str())? {
            let bound_pk = bound_pk_guard.value();
            if bound_pk != pubkey && reg_table.get(bound_pk)?.is_some() {
                return Err(DbError::http(
                    409,
                    "This email address is already linked to another registered key",
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_redeem_codes(
        &self,
        cfg: &Config,
        count: usize,
        profile: &str,
        duration_days: Option<u32>,
        max_uses: u32,
        expires_in_days: Option<u32>,
        note: Option<String>,
        custom_prefix: Option<&str>,
        now_secs: u64,
    ) -> Result<Vec<RedeemCodeRecord>, DbError> {
        if !cfg.profiles.contains_key(profile) {
            return Err(DbError::http(400, format!("Unknown profile '{}'", profile)));
        }
        let prefix = custom_prefix
            .map(|p| p.trim().to_ascii_uppercase())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| {
                if profile == cfg.mode.default_public_profile {
                    "INVITE".to_string()
                } else {
                    profile.to_ascii_uppercase()
                }
            });

        let expires_at = expires_in_days.map(|d| now_secs.saturating_add((d as u64) * 86_400));
        let mut created = Vec::with_capacity(count);

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(REDEEM_CODES)?;
            for _ in 0..count {
                let part1 = random_hex(3).to_ascii_uppercase();
                let part2 = random_hex(3).to_ascii_uppercase();
                let code = format!("{}-{}-{}", prefix, part1, part2);
                let rec = RedeemCodeRecord {
                    code: code.clone(),
                    profile: profile.to_string(),
                    duration_days,
                    max_uses: max_uses.max(1),
                    used_count: 0,
                    expires_at,
                    created_at: now_secs,
                    note: note.clone(),
                };
                table.insert(code.as_str(), serde_json::to_vec(&rec)?.as_slice())?;
                created.push(rec);
            }
        }
        write_txn.commit()?;
        Ok(created)
    }

    pub fn redeem_code_for_pubkey(
        &self,
        cfg: &Config,
        pubkey: &str,
        raw_code: &str,
        now_secs: u64,
    ) -> Result<RegisteredUserRecord, DbError> {
        let code_norm = raw_code.trim().to_ascii_uppercase();
        if code_norm.is_empty() {
            return Err(DbError::http(400, "Empty redeem code"));
        }

        let write_txn = self.db.begin_write()?;
        let rec = {
            let mut code_table = write_txn.open_table(REDEEM_CODES)?;
            let mut reg_table = write_txn.open_table(REGISTERED_USERS)?;

            let mut code_rec: RedeemCodeRecord = match code_table.get(code_norm.as_str())? {
                Some(g) => serde_json::from_slice(g.value())?,
                None => return Err(DbError::http(404, "Invalid redeem code")),
            };

            if let Some(exp) = code_rec.expires_at {
                if now_secs > exp {
                    return Err(DbError::http(410, "Redeem code expired"));
                }
            }
            if code_rec.used_count >= code_rec.max_uses {
                return Err(DbError::http(409, "Redeem code already exhausted"));
            }
            if !cfg.profiles.contains_key(&code_rec.profile) {
                return Err(DbError::http(500, "Code points to non-existent profile"));
            }

            code_rec.used_count += 1;
            code_table.insert(
                code_norm.as_str(),
                serde_json::to_vec(&code_rec)?.as_slice(),
            )?;

            let existing: Option<RegisteredUserRecord> = match reg_table.get(pubkey)? {
                Some(g) => Some(serde_json::from_slice(g.value())?),
                None => None,
            };
            let target_prof = &cfg.profiles[&code_rec.profile];
            let valid_until = code_rec.duration_days.map(|days| {
                let add = (days as u64).saturating_mul(86_400);
                let base = existing
                    .as_ref()
                    .filter(|e| e.profile == code_rec.profile)
                    .and_then(|e| e.valid_until)
                    .filter(|&v| v > now_secs)
                    .unwrap_or(now_secs);
                base.saturating_add(add)
            });

            let enc_email = if target_prof.store_contact_email {
                existing
                    .as_ref()
                    .and_then(|e| e.encrypted_contact_email.clone())
            } else {
                None
            };

            let updated = RegisteredUserRecord {
                pubkey: pubkey.to_string(),
                profile: code_rec.profile.clone(),
                email_hmac: existing.as_ref().and_then(|e| e.email_hmac.clone()),
                encrypted_contact_email: enc_email,
                status: AccountStatus::Active,
                valid_until,
                created_at: existing.as_ref().map(|e| e.created_at).unwrap_or(now_secs),
                updated_at: now_secs,
                registration_gate: "code".to_string(),
            };
            reg_table.insert(pubkey, serde_json::to_vec(&updated)?.as_slice())?;
            updated
        };
        write_txn.commit()?;
        Ok(rec)
    }

    pub fn list_admin_users(
        &self,
        cfg: &Config,
        now_secs: u64,
    ) -> Result<Vec<AdminUserSummary>, DbError> {
        let read_txn = self.db.begin_read()?;
        let admin_table = read_txn.open_table(ADMIN_MEMBERS)?;
        let reg_table = read_txn.open_table(REGISTERED_USERS)?;
        let slot_meta = read_txn.open_table(SLOT_META)?;
        let media_meta = read_txn.open_table(MEDIA_META)?;

        let mut usage: BTreeMap<String, (u64, usize, usize)> = BTreeMap::new();
        for entry in slot_meta.iter()? {
            let (_, v) = entry?;
            let m: SlotMetaRecord = serde_json::from_slice(v.value())?;
            let u = usage.entry(m.owner_pubkey).or_default();
            u.0 += m.size as u64;
            u.1 += 1;
        }
        for entry in media_meta.iter()? {
            let (_, v) = entry?;
            let m: MediaMetaRecord = serde_json::from_slice(v.value())?;
            let u = usage.entry(m.owner_pubkey).or_default();
            u.0 += m.size as u64;
            u.2 += 1;
        }

        let mut out = Vec::new();
        for entry in reg_table.iter()? {
            let (_, v) = entry?;
            let rec: RegisteredUserRecord = serde_json::from_slice(v.value())?;
            let (eff_name, _, in_grace, grace_until) =
                Self::resolve_registered_profile(&rec, cfg, now_secs);
            let effective_profile = eff_name.to_string();
            let is_admin =
                !Self::admin_channels_for_pubkey_read(&admin_table, cfg, &rec.pubkey)?.is_empty();
            let (used_bytes, slot_count, media_count) =
                usage.get(&rec.pubkey).copied().unwrap_or((0, 0, 0));
            let contact_email = rec
                .encrypted_contact_email
                .as_deref()
                .and_then(|blob| decrypt_contact_email(&self.pepper, blob).ok());
            out.push(AdminUserSummary {
                pubkey: rec.pubkey,
                profile: rec.profile,
                effective_profile,
                status: rec.status,
                valid_until: rec.valid_until,
                in_grace_period: in_grace,
                grace_until,
                created_at: rec.created_at,
                updated_at: rec.updated_at,
                registration_gate: rec.registration_gate,
                has_email_hmac: rec.email_hmac.is_some(),
                contact_email,
                is_admin_member: is_admin,
                used_bytes,
                slot_count,
                media_count,
            });
        }
        out.sort_by_key(|u| std::cmp::Reverse(u.updated_at));
        Ok(out)
    }

    pub fn get_admin_user_summary(
        &self,
        cfg: &Config,
        pubkey: &str,
        now_secs: u64,
    ) -> Result<Option<AdminUserSummary>, DbError> {
        let all = self.list_admin_users(cfg, now_secs)?;
        Ok(all.into_iter().find(|u| u.pubkey == pubkey))
    }

    pub fn list_redeem_codes(&self) -> Result<Vec<RedeemCodeRecord>, DbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(REDEEM_CODES)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (_, v) = entry?;
            let rec: RedeemCodeRecord = serde_json::from_slice(v.value())?;
            out.push(rec);
        }
        out.sort_by_key(|c| std::cmp::Reverse(c.created_at));
        Ok(out)
    }

    pub fn set_user_status(
        &self,
        pubkey: &str,
        status: AccountStatus,
        now_secs: u64,
    ) -> Result<(), DbError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut reg_table = write_txn.open_table(REGISTERED_USERS)?;
            let mut rec: RegisteredUserRecord = match reg_table.get(pubkey)? {
                Some(g) => serde_json::from_slice(g.value())?,
                None => return Err(DbError::http(404, "Registered user not found")),
            };
            rec.status = status;
            rec.updated_at = now_secs;
            reg_table.insert(pubkey, serde_json::to_vec(&rec)?.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Background maintenance: prunes expired nonces, expired JTIs, expired TTL slots/media,
    /// and completes overdue paid -> free downgrades past `downgrade_grace_days`.
    pub fn run_maintenance(&self, cfg: &Config, now_secs: u64) -> Result<(), DbError> {
        let write_txn = self.db.begin_write()?;
        {
            let admin_table = write_txn.open_table(ADMIN_MEMBERS)?;
            let mut reg_table = write_txn.open_table(REGISTERED_USERS)?;
            let mut nonces = write_txn.open_table(NONCES)?;
            let mut jtis = write_txn.open_table(USED_ACTION_JTIS)?;
            let mut slot_meta = write_txn.open_table(SLOT_META)?;
            let mut slot_data = write_txn.open_table(SLOT_DATA)?;
            let mut media_meta = write_txn.open_table(MEDIA_META)?;
            let mut media_data = write_txn.open_table(MEDIA_DATA)?;

            // 1. Expired nonces
            let mut expired_nonces = Vec::new();
            for entry in nonces.iter()? {
                let (k, v) = entry?;
                if v.value() < now_secs {
                    expired_nonces.push(k.value().to_string());
                }
            }
            for k in expired_nonces {
                nonces.remove(k.as_str())?;
            }

            // 2. Expired action JTIs
            let mut expired_jtis = Vec::new();
            for entry in jtis.iter()? {
                let (k, v) = entry?;
                if v.value() < now_secs {
                    expired_jtis.push(k.value().to_string());
                }
            }
            for k in expired_jtis {
                jtis.remove(k.as_str())?;
            }

            // 3. Finalize overdue downgrades after grace period
            let default_prof = &cfg.mode.default_public_profile;
            let default_stores_email = cfg.profiles[default_prof].store_contact_email;
            let grace_secs = (cfg.storage.downgrade_grace_days as u64).saturating_mul(86_400);
            let mut updates = Vec::new();
            for entry in reg_table.iter()? {
                let (k, v) = entry?;
                let mut rec: RegisteredUserRecord = serde_json::from_slice(v.value())?;
                if let Some(exp) = rec.valid_until {
                    if rec.profile != *default_prof && now_secs > exp.saturating_add(grace_secs) {
                        rec.profile = default_prof.clone();
                        rec.valid_until = None;
                        rec.updated_at = now_secs;
                        if !default_stores_email {
                            rec.encrypted_contact_email = None;
                        }
                        updates.push((k.value().to_string(), serde_json::to_vec(&rec)?));
                    }
                }
            }
            for (k, v) in updates {
                reg_table.insert(k.as_str(), v.as_slice())?;
            }

            // 4. Prune expired slots & media by TTL
            let mut exp_slots = Vec::new();
            for entry in slot_meta.iter()? {
                let (k, v) = entry?;
                let m: SlotMetaRecord = serde_json::from_slice(v.value())?;
                let ttl_days = Self::resolve_member_access_in_txn(
                    &admin_table,
                    &reg_table,
                    cfg,
                    &m.owner_pubkey,
                    now_secs,
                )?
                .and_then(|a| a.profile.channels.get(&m.channel).map(|q| q.ttl_days))
                .unwrap_or(0);
                if ttl_days > 0 {
                    let ttl_secs = (ttl_days as u64).saturating_mul(86_400);
                    if m.mtime.saturating_add(ttl_secs) < now_secs {
                        exp_slots.push(k.value().to_string());
                    }
                }
            }
            for k in exp_slots {
                slot_meta.remove(k.as_str())?;
                slot_data.remove(k.as_str())?;
            }

            let mut exp_media = Vec::new();
            for entry in media_meta.iter()? {
                let (k, v) = entry?;
                let m: MediaMetaRecord = serde_json::from_slice(v.value())?;
                let ttl_days = Self::resolve_member_access_in_txn(
                    &admin_table,
                    &reg_table,
                    cfg,
                    &m.owner_pubkey,
                    now_secs,
                )?
                .and_then(|a| a.profile.channels.get("media").map(|q| q.ttl_days))
                .unwrap_or(cfg.media.ttl_days);
                if ttl_days > 0 {
                    let ttl_secs = (ttl_days as u64).saturating_mul(86_400);
                    if m.created_at.saturating_add(ttl_secs) < now_secs {
                        exp_media.push(k.value().to_string());
                    }
                }
            }
            for k in exp_media {
                media_meta.remove(k.as_str())?;
                media_data.remove(k.as_str())?;
            }
        }
        write_txn.commit()?;
        let _ = self.run_lock_gc(now_secs)?;
        Ok(())
    }
}

fn admin_member_key(channel: &str, pubkey: &str) -> String {
    format!("{}:{}", channel, pubkey)
}

fn slot_key(channel: &str, slot_id: &str) -> String {
    format!("{}:{}", channel, slot_id)
}

#[allow(clippy::too_many_arguments)]
fn ensure_quota_with_media_eviction<
    R1: ReadableTable<&'static str, &'static [u8]>,
    R2: ReadableTable<&'static str, &'static [u8]>,
    R3: ReadableTable<&'static str, &'static [u8]>,
>(
    cfg: &Config,
    admin_table: &R1,
    reg_table: &R2,
    slot_meta: &R3,
    media_meta: &mut redb::Table<&str, &[u8]>,
    media_data: &mut redb::Table<&str, &[u8]>,
    pubkey: &str,
    access: &EffectiveAccess,
    delta_bytes: u64,
    skip_media_id: Option<&str>,
    now_secs: u64,
) -> Result<usize, DbError> {
    let mut evicted = 0usize;

    // 1. Account total bytes budget (`profile.max_total_bytes`)
    loop {
        let mut acct_used = 0u64;
        for entry in slot_meta.iter()? {
            let (_, v) = entry?;
            let m: SlotMetaRecord = serde_json::from_slice(v.value())?;
            if m.owner_pubkey == pubkey {
                acct_used += m.size as u64;
            }
        }
        let mut acct_media = Vec::new();
        for entry in media_meta.iter()? {
            let (_, v) = entry?;
            let m: MediaMetaRecord = serde_json::from_slice(v.value())?;
            if m.owner_pubkey == pubkey {
                acct_used += m.size as u64;
                if Some(m.media_id.as_str()) != skip_media_id {
                    acct_media.push(m);
                }
            }
        }
        if acct_used + delta_bytes <= access.profile.max_total_bytes {
            break;
        }
        acct_media.sort_by_key(|m| (m.last_access_at, m.created_at, m.media_id.clone()));
        if let Some(victim) = acct_media.first() {
            media_meta.remove(victim.media_id.as_str())?;
            media_data.remove(victim.media_id.as_str())?;
            evicted += 1;
        } else {
            return Err(DbError::http(507, "Account total quota exceeded"));
        }
    }

    // 2. Free pool isolation budget (`storage.max_free_pool_mb`)
    if access.profile.is_free_pool {
        let free_cap = cfg.max_free_pool_bytes();
        loop {
            let mut free_used = 0u64;
            let mut free_media = Vec::new();
            let mut free_cache: BTreeMap<String, bool> = BTreeMap::new();

            for entry in slot_meta.iter()? {
                let (_, v) = entry?;
                let m: SlotMetaRecord = serde_json::from_slice(v.value())?;
                if is_owner_free_pool(
                    cfg,
                    admin_table,
                    reg_table,
                    &mut free_cache,
                    &m.owner_pubkey,
                    now_secs,
                )? {
                    free_used += m.size as u64;
                }
            }
            for entry in media_meta.iter()? {
                let (_, v) = entry?;
                let m: MediaMetaRecord = serde_json::from_slice(v.value())?;
                if is_owner_free_pool(
                    cfg,
                    admin_table,
                    reg_table,
                    &mut free_cache,
                    &m.owner_pubkey,
                    now_secs,
                )? {
                    free_used += m.size as u64;
                    if Some(m.media_id.as_str()) != skip_media_id {
                        free_media.push(m);
                    }
                }
            }
            if free_used + delta_bytes <= free_cap {
                break;
            }
            free_media.sort_by_key(|m| (m.last_access_at, m.created_at, m.media_id.clone()));
            if let Some(victim) = free_media.first() {
                media_meta.remove(victim.media_id.as_str())?;
                media_data.remove(victim.media_id.as_str())?;
                evicted += 1;
            } else {
                return Err(DbError::http(507, "Free storage pool capacity reached"));
            }
        }
    }

    // 3. Global total storage limit (`storage.max_total_storage_mb`)
    let global_cap = cfg.max_total_bytes();
    loop {
        let mut total_used = 0u64;
        let mut candidates = Vec::new();
        let mut free_cache: BTreeMap<String, bool> = BTreeMap::new();

        for entry in slot_meta.iter()? {
            let (_, v) = entry?;
            let m: SlotMetaRecord = serde_json::from_slice(v.value())?;
            total_used += m.size as u64;
        }
        for entry in media_meta.iter()? {
            let (_, v) = entry?;
            let m: MediaMetaRecord = serde_json::from_slice(v.value())?;
            total_used += m.size as u64;
            if Some(m.media_id.as_str()) != skip_media_id {
                let is_free = is_owner_free_pool(
                    cfg,
                    admin_table,
                    reg_table,
                    &mut free_cache,
                    &m.owner_pubkey,
                    now_secs,
                )?;
                candidates.push((m, is_free));
            }
        }
        if total_used + delta_bytes <= global_cap {
            break;
        }
        // Always evict free-pool media before paid/friends media.
        // Free-pool accounts must NEVER evict paid/friends media!
        candidates.sort_by_key(|(m, is_free)| {
            (
                !*is_free,
                m.last_access_at,
                m.created_at,
                m.media_id.clone(),
            )
        });
        if let Some((victim, victim_free)) = candidates.first() {
            if access.profile.is_free_pool && !*victim_free {
                return Err(DbError::http(507, "Server storage limit reached"));
            }
            media_meta.remove(victim.media_id.as_str())?;
            media_data.remove(victim.media_id.as_str())?;
            evicted += 1;
        } else {
            return Err(DbError::http(507, "Server storage limit reached"));
        }
    }

    Ok(evicted)
}

fn is_owner_free_pool<
    R1: ReadableTable<&'static str, &'static [u8]>,
    R2: ReadableTable<&'static str, &'static [u8]>,
>(
    cfg: &Config,
    admin_table: &R1,
    reg_table: &R2,
    cache: &mut BTreeMap<String, bool>,
    owner_pubkey: &str,
    now_secs: u64,
) -> Result<bool, DbError> {
    if let Some(&b) = cache.get(owner_pubkey) {
        return Ok(b);
    }
    let is_free =
        SyncDb::resolve_member_access_in_txn(admin_table, reg_table, cfg, owner_pubkey, now_secs)?
            .map(|a| a.profile.is_free_pool)
            .unwrap_or(true);
    cache.insert(owner_pubkey.to_string(), is_free);
    Ok(is_free)
}
