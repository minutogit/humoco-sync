use std::collections::BTreeMap;

use redb::ReadableTable;

use super::*;
use crate::config::Config;

#[allow(clippy::too_many_arguments)]
pub(super) fn ensure_quota_with_media_eviction<
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
                acct_used = acct_used.saturating_add(m.size as u64);
            }
        }
        let mut acct_media = Vec::new();
        for entry in media_meta.iter()? {
            let (_, v) = entry?;
            let m: MediaMetaRecord = serde_json::from_slice(v.value())?;
            if m.owner_pubkey == pubkey {
                acct_used = acct_used.saturating_add(m.size as u64);
                if Some(m.media_id.as_str()) != skip_media_id {
                    acct_media.push(m);
                }
            }
        }
        if acct_used.saturating_add(delta_bytes) <= access.profile.max_total_bytes {
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
                    free_used = free_used.saturating_add(m.size as u64);
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
                    free_used = free_used.saturating_add(m.size as u64);
                    if Some(m.media_id.as_str()) != skip_media_id {
                        free_media.push(m);
                    }
                }
            }
            if free_used.saturating_add(delta_bytes) <= free_cap {
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
            total_used = total_used.saturating_add(m.size as u64);
        }
        for entry in media_meta.iter()? {
            let (_, v) = entry?;
            let m: MediaMetaRecord = serde_json::from_slice(v.value())?;
            total_used = total_used.saturating_add(m.size as u64);
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
        if total_used.saturating_add(delta_bytes) <= global_cap {
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

pub(super) fn is_owner_free_pool<
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
    let is_free = if let Some(access) =
        SyncDb::resolve_member_access_in_txn(admin_table, reg_table, cfg, owner_pubkey, now_secs)?
    {
        access.profile.is_free_pool
    } else if let Some(g) = reg_table.get(owner_pubkey)? {
        // Suspended or disabled-gate registered users keep their resolved profile's pool
        // classification so non-free accounts never pollute or starve the free pool.
        let rec: RegisteredUserRecord = serde_json::from_slice(g.value())?;
        SyncDb::resolve_registered_profile(&rec, cfg, now_secs)?
            .1
            .is_free_pool
    } else if SyncDb::has_any_raw_admin_membership(admin_table, owner_pubkey)? {
        cfg.profiles
            .get(&cfg.mode.admin_app_profile)
            .is_none_or(|p| p.is_free_pool)
    } else {
        true
    };
    cache.insert(owner_pubkey.to_string(), is_free);
    Ok(is_free)
}
