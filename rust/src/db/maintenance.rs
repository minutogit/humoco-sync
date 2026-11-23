use redb::ReadableTable;

use super::*;
use crate::config::Config;

impl SyncDb {
    /// Background maintenance: prunes expired nonces, expired JTIs, expired TTL slots/media,
    /// and completes overdue paid -> free downgrades past `downgrade_grace_days`.
    pub fn run_maintenance(&self, cfg: &Config, now_secs: u64) -> Result<(), DbError> {
        let write_txn = self.db.begin_write()?;
        {
            let server_meta = write_txn.open_table(SERVER_META)?;
            let effective_cfg = Self::effective_config_in_txn(cfg, &server_meta)?;
            let cfg = effective_cfg.as_ref();
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
            let default_stores_email = cfg
                .profiles
                .get(default_prof)
                .ok_or_else(|| {
                    DbError::http(
                        500,
                        format!("Missing configured default profile '{}'", default_prof),
                    )
                })?
                .store_contact_email;
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
                let ttl_days = Self::effective_channel_ttl_days_in_txn(
                    &admin_table,
                    &reg_table,
                    cfg,
                    &m.owner_pubkey,
                    &m.channel,
                    now_secs,
                )?;
                if is_ttl_expired(m.mtime, ttl_days, now_secs) {
                    exp_slots.push(k.value().to_string());
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
                let ttl_days = Self::effective_channel_ttl_days_in_txn(
                    &admin_table,
                    &reg_table,
                    cfg,
                    &m.owner_pubkey,
                    "media",
                    now_secs,
                )?;
                if is_ttl_expired(m.created_at, ttl_days, now_secs) {
                    exp_media.push(k.value().to_string());
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

pub(super) fn is_ttl_expired(ts: u64, ttl_days: u32, now_secs: u64) -> bool {
    ttl_days > 0 && ts.saturating_add((ttl_days as u64).saturating_mul(86_400)) < now_secs
}

pub(super) fn admin_member_key(channel: &str, pubkey: &str) -> String {
    format!("{}:{}", channel, pubkey)
}

pub(super) fn slot_key(channel: &str, slot_id: &str) -> String {
    format!("{}:{}", channel, slot_id)
}
