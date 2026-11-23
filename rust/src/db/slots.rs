use redb::ReadableTable;

use super::maintenance::{is_ttl_expired, slot_key};
use super::quota::ensure_quota_with_media_eviction;
use super::*;
use crate::config::Config;
use crate::crypto::sha256_hex;

impl SyncDb {
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
        if data.is_empty() {
            return Err(DbError::http(400, "Empty payload"));
        }
        let slot_id = crate::crypto::format_slot_id(pubkey, prefix);
        let skey = slot_key(channel, &slot_id);

        let write_txn = self.db.begin_write()?;
        let outcome = {
            let server_meta = write_txn.open_table(SERVER_META)?;
            let effective_cfg = Self::effective_config_in_txn(cfg, &server_meta)?;
            let cfg = effective_cfg.as_ref();
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

            let ch_quota = access
                .profile
                .channels
                .get(channel)
                .ok_or_else(|| DbError::http(403, "Channel disabled in profile"))?;
            let max_ch_bytes = ch_quota.max_bytes;
            let ch_ttl_days = ch_quota.ttl_days;

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

            let live_meta = existing_meta
                .as_ref()
                .filter(|em| !is_ttl_expired(em.mtime, ch_ttl_days, now_secs));

            precondition.evaluate(live_meta.map(|em| em.etag.as_str()))?;

            let old_size = existing_meta.as_ref().map(|m| m.size).unwrap_or(0);
            let mut evicted_media = 0usize;

            if data.len() > old_size {
                let delta_u = (data.len() - old_size) as u64;
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
            let server_meta = write_txn.open_table(SERVER_META)?;
            let effective_cfg = Self::effective_config_in_txn(cfg, &server_meta)?;
            let cfg = effective_cfg.as_ref();
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

    pub fn get_slot_blob(
        &self,
        cfg: &Config,
        channel: &str,
        slot_id: &str,
        now_secs: u64,
    ) -> Result<Option<(SlotMetaRecord, Vec<u8>)>, DbError> {
        let skey = slot_key(channel, slot_id);
        let read_txn = self.db.begin_read()?;
        let server_meta = read_txn.open_table(SERVER_META)?;
        let effective_cfg = Self::effective_config_in_txn(cfg, &server_meta)?;
        let cfg = effective_cfg.as_ref();
        let admin_table = read_txn.open_table(ADMIN_MEMBERS)?;
        let reg_table = read_txn.open_table(REGISTERED_USERS)?;
        let slot_meta = read_txn.open_table(SLOT_META)?;
        let slot_data = read_txn.open_table(SLOT_DATA)?;

        let Some(meta_guard) = slot_meta.get(skey.as_str())? else {
            return Ok(None);
        };
        let meta: SlotMetaRecord = serde_json::from_slice(meta_guard.value())?;

        // Respect TTL expiration (including Suspended or inactive accounts via profile fallback)
        let ttl_days = Self::effective_channel_ttl_days_in_txn(
            &admin_table,
            &reg_table,
            cfg,
            &meta.owner_pubkey,
            channel,
            now_secs,
        )?;
        if is_ttl_expired(meta.mtime, ttl_days, now_secs) {
            return Ok(None);
        }

        let Some(data_guard) = slot_data.get(skey.as_str())? else {
            return Ok(None);
        };
        Ok(Some((meta, data_guard.value().to_vec())))
    }
}
