use std::collections::BTreeMap;

use redb::ReadableTable;

use super::maintenance::is_ttl_expired;
use super::quota::{ensure_quota_with_media_eviction, is_owner_free_pool};
use super::*;
use crate::config::Config;
use crate::crypto::sha256_hex;

impl SyncDb {
    pub fn put_media(
        &self,
        cfg: &Config,
        pubkey: &str,
        media_id: &str,
        data: &[u8],
        precondition: &ConditionalPrecondition,
        now_secs: u64,
    ) -> Result<PutOutcome, DbError> {
        if data.is_empty() {
            return Err(DbError::http(400, "Empty payload"));
        }
        let write_txn = self.db.begin_write()?;
        let outcome = {
            let server_meta = write_txn.open_table(SERVER_META)?;
            let effective_cfg = Self::effective_config_in_txn(cfg, &server_meta)?;
            let cfg = effective_cfg.as_ref();
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

            let media_ttl_days = media_q.map(|q| q.ttl_days).unwrap_or(cfg.media.ttl_days);
            let live_existing = existing
                .as_ref()
                .filter(|em| !is_ttl_expired(em.created_at, media_ttl_days, now_secs));

            precondition.evaluate(live_existing.map(|em| em.etag.as_str()))?;

            if max_user_count == 0 {
                return Err(DbError::http(507, "Media user quota exceeded"));
            }
            let max_channel_bytes = cfg.media_channel_max_bytes();
            if max_channel_bytes == 0 || (data.len() as u64) > max_channel_bytes {
                return Err(DbError::http(
                    507,
                    "Media exceeds total media channel capacity",
                ));
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
                        user_bytes = user_bytes.saturating_add(m.size as u64);
                        user_media.push(m);
                    }
                }
                let need_count = user_media.len() >= max_user_count;
                let need_bytes = user_bytes.saturating_add(data.len() as u64) > max_user_bytes;
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
            let mut free_cache: BTreeMap<String, bool> = BTreeMap::new();
            loop {
                let mut all_media: Vec<(MediaMetaRecord, bool)> = Vec::new();
                let mut total_media_bytes = 0u64;
                for entry in media_meta.iter()? {
                    let (_, val) = entry?;
                    let m: MediaMetaRecord = serde_json::from_slice(val.value())?;
                    if m.media_id != media_id {
                        total_media_bytes = total_media_bytes.saturating_add(m.size as u64);
                        let is_free = is_owner_free_pool(
                            cfg,
                            &admin_table,
                            &reg_table,
                            &mut free_cache,
                            &m.owner_pubkey,
                            now_secs,
                        )?;
                        all_media.push((m, is_free));
                    }
                }
                if total_media_bytes.saturating_add(data.len() as u64) <= max_channel_bytes {
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

            let old_size = existing.as_ref().map(|m| m.size).unwrap_or(0);
            if data.len() > old_size {
                evicted += ensure_quota_with_media_eviction(
                    cfg,
                    &admin_table,
                    &reg_table,
                    &slot_meta,
                    &mut media_meta,
                    &mut media_data,
                    pubkey,
                    &access,
                    (data.len() - old_size) as u64,
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
                created_at: live_existing.map(|m| m.created_at).unwrap_or(now_secs),
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

    pub fn delete_media(
        &self,
        cfg: &Config,
        pubkey: &str,
        media_id: Option<&str>,
        now_secs: u64,
    ) -> Result<usize, DbError> {
        let write_txn = self.db.begin_write()?;
        let deleted_count = {
            let server_meta = write_txn.open_table(SERVER_META)?;
            let effective_cfg = Self::effective_config_in_txn(cfg, &server_meta)?;
            let cfg = effective_cfg.as_ref();
            let admin_table = write_txn.open_table(ADMIN_MEMBERS)?;
            let reg_table = write_txn.open_table(REGISTERED_USERS)?;
            let mut media_meta = write_txn.open_table(MEDIA_META)?;
            let mut media_data = write_txn.open_table(MEDIA_DATA)?;

            let access = Self::resolve_member_access_in_txn(
                &admin_table,
                &reg_table,
                cfg,
                pubkey,
                now_secs,
            )?;
            let authorized = access
                .as_ref()
                .is_some_and(|a| a.allowed_channels.contains("media"));

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
                } else if !authorized {
                    return Err(DbError::http(403, "Not authorized"));
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
                if to_remove.is_empty() && !authorized {
                    return Err(DbError::http(403, "Not authorized"));
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

    pub fn get_media_blob(
        &self,
        cfg: &Config,
        media_id: &str,
        now_secs: u64,
    ) -> Result<Option<(MediaMetaRecord, Vec<u8>)>, DbError> {
        let read_txn = self.db.begin_read()?;
        let server_meta = read_txn.open_table(SERVER_META)?;
        let effective_cfg = Self::effective_config_in_txn(cfg, &server_meta)?;
        let cfg = effective_cfg.as_ref();
        let admin_table = read_txn.open_table(ADMIN_MEMBERS)?;
        let reg_table = read_txn.open_table(REGISTERED_USERS)?;
        let media_meta = read_txn.open_table(MEDIA_META)?;
        let media_data = read_txn.open_table(MEDIA_DATA)?;

        let Some(meta_guard) = media_meta.get(media_id)? else {
            return Ok(None);
        };
        let meta: MediaMetaRecord = serde_json::from_slice(meta_guard.value())?;

        let ttl_days = Self::effective_channel_ttl_days_in_txn(
            &admin_table,
            &reg_table,
            cfg,
            &meta.owner_pubkey,
            "media",
            now_secs,
        )?;
        if is_ttl_expired(meta.created_at, ttl_days, now_secs) {
            return Ok(None);
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
}
