use std::borrow::Cow;
use std::collections::BTreeSet;

use redb::ReadableTable;

use super::maintenance::{admin_member_key, is_ttl_expired, slot_key};
use super::*;
use crate::config::{Config, ProfileConfig, ADMIN_MEMBER_CHANNELS};

impl SyncDb {
    pub fn get_admin_config_overrides(&self) -> Result<Option<AdminConfigOverrides>, DbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SERVER_META)?;
        if let Some(guard) = table.get("admin_config")? {
            let ov: AdminConfigOverrides = serde_json::from_slice(guard.value())?;
            Ok(Some(ov))
        } else {
            Ok(None)
        }
    }

    pub fn set_admin_config_overrides(&self, ov: &AdminConfigOverrides) -> Result<(), DbError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SERVER_META)?;
            let json = serde_json::to_vec(ov)?;
            table.insert("admin_config", json.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub(super) fn apply_admin_config_overrides(cfg: &mut Config, ov: &AdminConfigOverrides) {
        cfg.storage.max_total_storage_mb = ov.max_total_storage_mb;
        cfg.storage.max_free_pool_mb = cfg.storage.max_free_pool_mb.min(ov.max_total_storage_mb);
        cfg.mode.max_admin_members = ov.max_members;
        let user_bytes = ov.max_user_storage_mb.saturating_mul(1024 * 1024);
        if let Some(prof) = cfg.profiles.get_mut(&cfg.mode.admin_app_profile) {
            prof.max_total_bytes = user_bytes;
            if let Some(mq) = prof.channels.get_mut("media") {
                if let Some(ref mut ubytes) = mq.max_user_bytes {
                    *ubytes = (*ubytes).min(user_bytes);
                }
            }
        }
    }

    pub(super) fn effective_config_in_txn<'a, R: ReadableTable<&'static str, &'static [u8]>>(
        base: &'a Config,
        server_meta: &R,
    ) -> Result<Cow<'a, Config>, DbError> {
        if let Some(guard) = server_meta.get("admin_config")? {
            let ov: AdminConfigOverrides = serde_json::from_slice(guard.value())?;
            let mut cfg = base.clone();
            Self::apply_admin_config_overrides(&mut cfg, &ov);
            Ok(Cow::Owned(cfg))
        } else {
            Ok(Cow::Borrowed(base))
        }
    }

    pub fn effective_config(&self, base: &Config) -> Result<Config, DbError> {
        let mut cfg = base.clone();
        if let Some(ov) = self.get_admin_config_overrides()? {
            Self::apply_admin_config_overrides(&mut cfg, &ov);
        }
        Ok(cfg)
    }

    pub(super) fn has_any_raw_admin_membership<R: ReadableTable<&'static str, &'static [u8]>>(
        admin_table: &R,
        pubkey: &str,
    ) -> Result<bool, DbError> {
        for ch in ADMIN_MEMBER_CHANNELS {
            let key = admin_member_key(ch, pubkey);
            if admin_table.get(key.as_str())?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn admin_channels_for_pubkey_read<R: ReadableTable<&'static str, &'static [u8]>>(
        admin_table: &R,
        cfg: &Config,
        pubkey: &str,
    ) -> Result<BTreeSet<String>, DbError> {
        let mut out = BTreeSet::new();
        if !cfg.mode.enable_admin_app {
            return Ok(out);
        }
        for ch in ADMIN_MEMBER_CHANNELS {
            if ch == "lock" && !cfg.lock.enabled {
                continue;
            }
            let key = admin_member_key(ch, pubkey);
            if admin_table.get(key.as_str())?.is_some() {
                out.insert(ch.to_string());
            }
        }
        Ok(out)
    }

    pub(super) fn resolve_registered_profile<'a>(
        rec: &'a RegisteredUserRecord,
        cfg: &'a Config,
        now_secs: u64,
    ) -> Result<(&'a str, &'a ProfileConfig, bool, Option<u64>), DbError> {
        let default_name = cfg.mode.default_public_profile.as_str();
        let default_prof = cfg.profiles.get(default_name).ok_or_else(|| {
            DbError::http(
                500,
                format!("Missing configured default profile '{}'", default_name),
            )
        })?;
        let (requested_name, requested_prof) = match cfg.profiles.get(&rec.profile) {
            Some(p) => (rec.profile.as_str(), p),
            None => (default_name, default_prof),
        };

        if let Some(valid_until) = rec.valid_until {
            if now_secs > valid_until && requested_name != default_name {
                let grace_secs = (cfg.storage.downgrade_grace_days as u64).saturating_mul(86_400);
                let grace_until = valid_until.saturating_add(grace_secs);
                if now_secs <= grace_until {
                    return Ok((requested_name, requested_prof, true, Some(grace_until)));
                } else {
                    return Ok((default_name, default_prof, false, None));
                }
            }
        }
        Ok((requested_name, requested_prof, false, None))
    }

    pub(super) fn effective_channel_ttl_days_in_txn<
        R1: ReadableTable<&'static str, &'static [u8]>,
        R2: ReadableTable<&'static str, &'static [u8]>,
    >(
        admin_table: &R1,
        reg_table: &R2,
        cfg: &Config,
        owner_pubkey: &str,
        channel: &str,
        now_secs: u64,
    ) -> Result<u32, DbError> {
        let fallback_ttl = if channel == "media" {
            cfg.media.ttl_days
        } else {
            0
        };
        if let Some(access) =
            Self::resolve_member_access_in_txn(admin_table, reg_table, cfg, owner_pubkey, now_secs)?
        {
            return Ok(access
                .profile
                .channels
                .get(channel)
                .map(|q| q.ttl_days)
                .unwrap_or(fallback_ttl));
        }
        if let Some(g) = reg_table.get(owner_pubkey)? {
            let rec: RegisteredUserRecord = serde_json::from_slice(g.value())?;
            let (_, prof, _, _) = Self::resolve_registered_profile(&rec, cfg, now_secs)?;
            return Ok(prof
                .channels
                .get(channel)
                .map(|q| q.ttl_days)
                .unwrap_or(fallback_ttl));
        }
        if Self::has_any_raw_admin_membership(admin_table, owner_pubkey)? {
            if let Some(prof) = cfg.profiles.get(&cfg.mode.admin_app_profile) {
                return Ok(prof
                    .channels
                    .get(channel)
                    .map(|q| q.ttl_days)
                    .unwrap_or(fallback_ttl));
            }
        }
        Ok(cfg
            .profiles
            .get(&cfg.mode.default_public_profile)
            .and_then(|p| p.channels.get(channel).map(|q| q.ttl_days))
            .unwrap_or(fallback_ttl))
    }

    pub(super) fn resolve_member_access_in_txn<
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
                let prof = cfg
                    .profiles
                    .get(&prof_name)
                    .ok_or_else(|| {
                        DbError::http(500, format!("Missing configured profile '{}'", prof_name))
                    })?
                    .clone();
                let media_explicit = admin_table.get(ADMIN_MEDIA_CONFIGURED_KEY)?.is_some();
                let mut allowed = admin_channels;
                // Parity with PHP load_channel_members('media'): fallback ONLY from 'card' when
                // 'media' membership has not been explicitly configured via PUT ?members&channel=media.
                if prof.channels.contains_key("media")
                    && !media_explicit
                    && allowed.contains("card")
                {
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
                    Self::resolve_registered_profile(rec, cfg, now_secs)?;
                let mut allowed: BTreeSet<String> = eff_prof.channels.keys().cloned().collect();
                if cfg.lock.enabled && rec.valid_until.is_none_or(|v| now_secs <= v) {
                    allowed.insert("lock".to_string());
                }
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
                    Self::resolve_registered_profile(rec, cfg, now_secs)?;
                let admin_prof_name = cfg.mode.admin_app_profile.as_str();
                let admin_prof = cfg.profiles.get(admin_prof_name).ok_or_else(|| {
                    DbError::http(
                        500,
                        format!("Missing configured profile '{}'", admin_prof_name),
                    )
                })?;
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
                if cfg.lock.enabled && rec.valid_until.is_none_or(|v| now_secs <= v) {
                    allowed.insert("lock".to_string());
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
        let server_meta = read_txn.open_table(SERVER_META)?;
        let eff_cfg = Self::effective_config_in_txn(cfg, &server_meta)?;
        let admin_table = read_txn.open_table(ADMIN_MEMBERS)?;
        let reg_table = read_txn.open_table(REGISTERED_USERS)?;
        Self::resolve_member_access_in_txn(&admin_table, &reg_table, &eff_cfg, pubkey, now_secs)
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
        let server_meta = read_txn.open_table(SERVER_META)?;
        let effective_cfg = Self::effective_config_in_txn(cfg, &server_meta)?;
        let cfg = effective_cfg.as_ref();
        let admin_table = read_txn.open_table(ADMIN_MEMBERS)?;
        let reg_table = read_txn.open_table(REGISTERED_USERS)?;
        let slot_meta = read_txn.open_table(SLOT_META)?;
        let media_meta = read_txn.open_table(MEDIA_META)?;

        let access =
            Self::resolve_member_access_in_txn(&admin_table, &reg_table, cfg, pubkey, now_secs)?;
        let caller_media_ttl = if let Some(ref a) = access {
            a.profile
                .channels
                .get("media")
                .map(|q| q.ttl_days)
                .unwrap_or(cfg.media.ttl_days)
        } else {
            Self::effective_channel_ttl_days_in_txn(
                &admin_table,
                &reg_table,
                cfg,
                pubkey,
                "media",
                now_secs,
            )?
        };

        let mut media_used_count = 0usize;
        let mut media_used_bytes = 0u64;
        for entry in media_meta.iter()? {
            let (_, val) = entry?;
            let meta: MediaMetaRecord = serde_json::from_slice(val.value())?;
            if meta.owner_pubkey == pubkey
                && !is_ttl_expired(meta.created_at, caller_media_ttl, now_secs)
            {
                media_used_count += 1;
                media_used_bytes = media_used_bytes.saturating_add(meta.size as u64);
            }
        }

        let is_lock_server_admin = cfg.lock.enabled
            && !cfg.server.admin_pubkey.is_empty()
            && pubkey == cfg.server.admin_pubkey;

        let Some(access) = access else {
            let allowed_channels = if is_lock_server_admin {
                vec!["lock".to_string()]
            } else {
                Vec::new()
            };
            let authorized = match channel {
                Some(ch) => allowed_channels.iter().any(|allowed| allowed == ch),
                None => !allowed_channels.is_empty(),
            };
            return Ok(HeadCapability {
                authorized,
                allowed_channels,
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
            .filter(|ch| {
                access.allowed_channels.contains(**ch) || (**ch == "lock" && is_lock_server_admin)
            })
            .map(|s| s.to_string())
            .collect();

        let requested_authorized = match channel {
            Some(ch) => allowed_channels.iter().any(|allowed| allowed == ch),
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
                        let ttl_days = Self::effective_channel_ttl_days_in_txn(
                            &admin_table,
                            &reg_table,
                            cfg,
                            &meta.owner_pubkey,
                            "media",
                            now_secs,
                        )?;
                        if is_ttl_expired(meta.created_at, ttl_days, now_secs) {
                            (Some(false), None)
                        } else if meta.owner_pubkey == pubkey {
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
            Some(ch) if ch != "lock" => {
                let slot_id = crate::crypto::format_slot_id(pubkey, prefix);
                let skey = slot_key(ch, &slot_id);
                if let Some(g) = slot_meta.get(skey.as_str())? {
                    let meta: SlotMetaRecord = serde_json::from_slice(g.value())?;
                    let ttl_days = access
                        .profile
                        .channels
                        .get(ch)
                        .map(|q| q.ttl_days)
                        .unwrap_or(0);
                    if is_ttl_expired(meta.mtime, ttl_days, now_secs) {
                        (Some(false), None)
                    } else {
                        (Some(true), Some(meta.etag))
                    }
                } else {
                    (Some(false), None)
                }
            }
            None | Some(_) => (None, None),
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
}
