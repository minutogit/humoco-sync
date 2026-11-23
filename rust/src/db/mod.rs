use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use rand::rngs::OsRng;
use rand::RngCore;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use zeroize::{Zeroize, Zeroizing};

use crate::config::Config;
use crate::crypto::{RevocationNotice, NONCE_TTL_SECS};

mod admin;
mod config_access;
mod maintenance;
mod media;
mod quota;
mod slots;
mod types;
mod users_redeem;

pub use types::*;

pub(crate) const SERVER_META: TableDefinition<&str, &[u8]> = TableDefinition::new("server_meta");
pub(crate) const NONCES: TableDefinition<&str, u64> = TableDefinition::new("nonces");
pub(crate) const ADMIN_MEMBERS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("admin_members");
pub(super) const ADMIN_MEDIA_CONFIGURED_KEY: &str = "media:__configured__";
pub(crate) const REGISTERED_USERS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("registered_users");
pub(super) const EMAIL_INDEX: TableDefinition<&str, &str> = TableDefinition::new("email_index");
pub(super) const SLOT_META: TableDefinition<&str, &[u8]> = TableDefinition::new("slot_meta");
pub(super) const SLOT_DATA: TableDefinition<&str, &[u8]> = TableDefinition::new("slot_data");
pub(super) const MEDIA_META: TableDefinition<&str, &[u8]> = TableDefinition::new("media_meta");
pub(super) const MEDIA_DATA: TableDefinition<&str, &[u8]> = TableDefinition::new("media_data");
pub(super) const REDEEM_CODES: TableDefinition<&str, &[u8]> = TableDefinition::new("redeem_codes");
pub(super) const USED_ACTION_JTIS: TableDefinition<&str, u64> =
    TableDefinition::new("used_action_jtis");

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

pub struct SyncDb {
    db: Database,
    pepper: [u8; 32],
    fallback_drop_pub: String,
}

impl Drop for SyncDb {
    fn drop(&mut self) {
        self.pepper.zeroize();
    }
}

impl SyncDb {
    pub fn open(db_path: &Path, config_pepper_hex: &str) -> Result<Self, DbError> {
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                let parent_existed = parent.exists();
                fs::create_dir_all(parent)?;
                #[cfg(unix)]
                if !parent_existed {
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                }
            }
        }
        let db = Database::create(db_path)?;
        #[cfg(unix)]
        fs::set_permissions(db_path, fs::Permissions::from_mode(0o600))?;

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
            let lock_key_len = server_meta.get("lock_key")?.map(|g| g.value().len());
            match lock_key_len {
                Some(len) => {
                    if len != 32 {
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
                    let mut sk_bytes = Zeroizing::new([0u8; 32]);
                    OsRng.fill_bytes(sk_bytes.as_mut());
                    server_meta.insert("lock_key", sk_bytes.as_slice())?;
                }
            }

            if !config_pepper_hex.is_empty() {
                let bytes = Zeroizing::new(
                    hex::decode(config_pepper_hex)
                        .map_err(|_| DbError::http(500, "Invalid configured server_pepper_hex"))?,
                );
                let hash = blake3::hash(&bytes);
                pepper.copy_from_slice(hash.as_bytes());
            } else {
                let existing = server_meta
                    .get("pepper")?
                    .map(|g| Zeroizing::new(g.value().to_vec()));
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

        let derived_sk_bytes = Zeroizing::new(blake3::derive_key(
            "humoco-sync server-drop-pub v1",
            &pepper,
        ));
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
                if exp >= now_secs {
                    false
                } else {
                    table.insert(nonce_hex, now_secs.saturating_add(NONCE_TTL_SECS))?;
                    true
                }
            } else {
                table.insert(nonce_hex, now_secs.saturating_add(NONCE_TTL_SECS))?;
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
}
