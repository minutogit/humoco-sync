use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::ProfileConfig;

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
pub struct AdminConfigOverrides {
    pub max_total_storage_mb: u64,
    pub max_members: usize,
    pub max_user_storage_mb: u64,
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
    pub max_members: usize,
    pub max_user_bytes: u64,
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
    IfMatchAbsent,
    IfNoneMatchStar,
    IfNoneMatch(Vec<String>),
    All(Vec<ConditionalPrecondition>),
}

impl ConditionalPrecondition {
    pub fn from_headers(if_match: Option<&str>, if_none_match: Option<&str>) -> Self {
        let mut checks = Vec::new();
        if let Some(nm) = if_none_match {
            let mut has_star = false;
            let mut tags = Vec::new();
            for part in nm.split(',') {
                let cand = part.trim();
                if cand.is_empty() {
                    continue;
                }
                if cand == "*" {
                    has_star = true;
                    break;
                }
                let norm = normalize_etag(cand);
                if !norm.is_empty() {
                    tags.push(norm);
                }
            }
            if has_star {
                checks.push(Self::IfNoneMatchStar);
            } else if !tags.is_empty() {
                checks.push(Self::IfNoneMatch(tags));
            }
        }
        if let Some(m) = if_match {
            let clean = normalize_etag(m);
            if clean.is_empty() || clean == "none" {
                checks.push(Self::IfMatchAbsent);
            } else {
                checks.push(Self::IfMatch(clean));
            }
        }
        match checks.len() {
            0 => Self::None,
            1 => checks.into_iter().next().unwrap_or(Self::None),
            _ => Self::All(checks),
        }
    }

    pub fn evaluate(&self, live_etag: Option<&str>) -> Result<(), DbError> {
        match self {
            Self::None => Ok(()),
            Self::IfMatch(expected) => match live_etag {
                Some(cur) if cur == expected => Ok(()),
                Some(cur) => Err(DbError::http(412, format!("ETAG_MISMATCH:{}", cur))),
                None => Err(DbError::http(412, "ETAG_MISMATCH:")),
            },
            Self::IfMatchAbsent | Self::IfNoneMatchStar => match live_etag {
                Some(cur) => Err(DbError::http(412, format!("ETAG_MISMATCH:{}", cur))),
                None => Ok(()),
            },
            Self::IfNoneMatch(tags) => match live_etag {
                Some(cur) if tags.iter().any(|t| t == cur) => {
                    Err(DbError::http(412, format!("ETAG_MISMATCH:{}", cur)))
                }
                _ => Ok(()),
            },
            Self::All(list) => {
                for item in list {
                    item.evaluate(live_etag)?;
                }
                Ok(())
            }
        }
    }
}

pub fn normalize_etag(raw: &str) -> String {
    let trimmed = raw.trim();
    let no_weak = trimmed.strip_prefix("W/").unwrap_or(trimmed);
    no_weak
        .trim_matches(|c| matches!(c, '"' | ' ' | '\t' | '\n' | '\r' | '\0' | '\x0B'))
        .to_string()
}
