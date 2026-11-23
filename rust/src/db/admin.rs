use std::collections::{BTreeMap, BTreeSet};

use redb::{ReadableTable, ReadableTableMetadata};

use super::maintenance::{admin_member_key, is_ttl_expired};
use super::quota::is_owner_free_pool;
use super::*;
use crate::config::Config;
use crate::crypto::sha256_hex;

impl SyncDb {
    /// Deletes a registered account (and removes all slots + media blobs owned by pubkey).
    pub fn delete_account_and_data(&self, pubkey: &str) -> Result<(usize, usize, bool), DbError> {
        let write_txn = self.db.begin_write()?;
        let (deleted_slots, deleted_media, deleted_account) = {
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
        let target_set: BTreeSet<String> = pubkeys.iter().cloned().collect();

        let write_txn = self.db.begin_write()?;
        {
            let server_meta = write_txn.open_table(SERVER_META)?;
            let effective_cfg = Self::effective_config_in_txn(cfg, &server_meta)?;
            let cfg = effective_cfg.as_ref();
            if target_set.len() > cfg.mode.max_admin_members {
                return Err(DbError::http(
                    507,
                    "Insufficient Storage: Exceeds max_members limit",
                ));
            }
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
                    if pk != "__configured__" {
                        old_pubkeys.push(pk.to_string());
                    }
                }
            }

            let mut removed_pubkeys = Vec::new();
            for old_pk in old_pubkeys {
                if !target_set.contains(&old_pk) {
                    admin_table.remove(admin_member_key(channel, &old_pk).as_str())?;
                    removed_pubkeys.push(old_pk);
                }
            }

            if channel == "media" {
                admin_table.insert(ADMIN_MEDIA_CONFIGURED_KEY, b"1".as_slice())?;
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

            // Prune orphaned slots in `channel` ONLY for removed pubkeys NOT present in REGISTERED_USERS
            let removed_set: BTreeSet<String> = removed_pubkeys.into_iter().collect();
            if !removed_set.is_empty() {
                let mut slots_to_delete = Vec::new();
                for entry in slot_meta.iter()? {
                    let (k, v) = entry?;
                    let meta: SlotMetaRecord = serde_json::from_slice(v.value())?;
                    if meta.channel == channel && removed_set.contains(&meta.owner_pubkey) {
                        if reg_table.get(meta.owner_pubkey.as_str())?.is_some() {
                            continue;
                        }
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
            }

            // Prune orphaned media when `card` or `media` membership changes (matching PHP sync.php)
            if channel == "card" || channel == "media" {
                let mut media_auth_cache: BTreeMap<String, bool> = BTreeMap::new();
                let mut media_to_del = Vec::new();
                for entry in media_meta.iter()? {
                    let (k, v) = entry?;
                    let m: MediaMetaRecord = serde_json::from_slice(v.value())?;
                    let allowed = if let Some(&cached) = media_auth_cache.get(&m.owner_pubkey) {
                        cached
                    } else {
                        let ok = if reg_table.get(m.owner_pubkey.as_str())?.is_some() {
                            true
                        } else {
                            Self::resolve_member_access_in_txn(
                                &admin_table,
                                &reg_table,
                                cfg,
                                &m.owner_pubkey,
                                now_secs,
                            )?
                            .is_some_and(|a| a.allowed_channels.contains("media"))
                        };
                        media_auth_cache.insert(m.owner_pubkey.clone(), ok);
                        ok
                    };
                    if !allowed {
                        media_to_del.push(k.value().to_string());
                    }
                }
                for mid in media_to_del {
                    media_meta.remove(mid.as_str())?;
                    media_data.remove(mid.as_str())?;
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
        let now_secs = crate::crypto::unix_now();
        let read_txn = self.db.begin_read()?;
        let server_meta = read_txn.open_table(SERVER_META)?;
        let effective_cfg = Self::effective_config_in_txn(cfg, &server_meta)?;
        let cfg = effective_cfg.as_ref();
        let admin_table = read_txn.open_table(ADMIN_MEMBERS)?;
        let reg_table = read_txn.open_table(REGISTERED_USERS)?;
        let slot_meta = read_txn.open_table(SLOT_META)?;

        let mut entries = Vec::new();
        if cfg.mode.enable_admin_app {
            let mut owner_access_cache: BTreeMap<String, Option<EffectiveAccess>> = BTreeMap::new();
            for entry in slot_meta.iter()? {
                let (_, v) = entry?;
                let meta: SlotMetaRecord = serde_json::from_slice(v.value())?;
                if meta.channel == "media" {
                    continue;
                }
                // Hybrid invariant: ONLY admin_app member slots appear in index.json!
                let key = admin_member_key(&meta.channel, &meta.owner_pubkey);
                if admin_table.get(key.as_str())?.is_some() {
                    if !owner_access_cache.contains_key(&meta.owner_pubkey) {
                        let resolved = Self::resolve_member_access_in_txn(
                            &admin_table,
                            &reg_table,
                            cfg,
                            &meta.owner_pubkey,
                            now_secs,
                        )?;
                        owner_access_cache.insert(meta.owner_pubkey.clone(), resolved);
                    }
                    let ttl_days = owner_access_cache
                        .get(&meta.owner_pubkey)
                        .and_then(|opt| opt.as_ref())
                        .and_then(|a| a.profile.channels.get(&meta.channel).map(|q| q.ttl_days))
                        .unwrap_or(0);
                    if is_ttl_expired(meta.mtime, ttl_days, now_secs) {
                        continue;
                    }
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

    pub fn admin_status(
        &self,
        cfg: &Config,
        now_secs: u64,
    ) -> Result<AdminStatusResponse, DbError> {
        let read_txn = self.db.begin_read()?;
        let server_meta = read_txn.open_table(SERVER_META)?;
        let effective_cfg = Self::effective_config_in_txn(cfg, &server_meta)?;
        let cfg = effective_cfg.as_ref();
        let admin_table = read_txn.open_table(ADMIN_MEMBERS)?;
        let reg_table = read_txn.open_table(REGISTERED_USERS)?;
        let slot_meta = read_txn.open_table(SLOT_META)?;
        let media_meta = read_txn.open_table(MEDIA_META)?;

        let mut admin_unique_pks = BTreeSet::new();
        for entry in admin_table.iter()? {
            let (k, _) = entry?;
            if k.value() == ADMIN_MEDIA_CONFIGURED_KEY {
                continue;
            }
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
            used_bytes = used_bytes.saturating_add(meta.size as u64);
            *channel_counts.entry(meta.channel.clone()).or_insert(0) += 1;
            if is_owner_free_pool(
                cfg,
                &admin_table,
                &reg_table,
                &mut owner_free_cache,
                &meta.owner_pubkey,
                now_secs,
            )? {
                free_pool_used_bytes = free_pool_used_bytes.saturating_add(meta.size as u64);
            }
        }

        for entry in media_meta.iter()? {
            let (_, v) = entry?;
            let m: MediaMetaRecord = serde_json::from_slice(v.value())?;
            slot_count += 1;
            used_bytes = used_bytes.saturating_add(m.size as u64);
            *channel_counts.entry("media".to_string()).or_insert(0) += 1;
            if is_owner_free_pool(
                cfg,
                &admin_table,
                &reg_table,
                &mut owner_free_cache,
                &m.owner_pubkey,
                now_secs,
            )? {
                free_pool_used_bytes = free_pool_used_bytes.saturating_add(m.size as u64);
            }
        }

        let max_bytes = cfg.max_total_bytes();
        let soft_limit_bytes = cfg.soft_limit_bytes();
        let max_user_bytes = cfg
            .profiles
            .get(&cfg.mode.admin_app_profile)
            .map(|p| p.max_total_bytes)
            .unwrap_or(25 * 1024 * 1024);

        Ok(AdminStatusResponse {
            used_bytes,
            max_bytes,
            soft_limit_bytes,
            soft_warning: used_bytes >= soft_limit_bytes,
            slot_count,
            channel_counts,
            admin_pubkey: cfg.server.admin_pubkey.clone(),
            max_members: cfg.mode.max_admin_members,
            max_user_bytes,
            admin_members_count: admin_unique_pks.len(),
            registered_users_count,
            free_pool_used_bytes,
            free_pool_max_bytes: cfg.max_free_pool_bytes(),
        })
    }
}
