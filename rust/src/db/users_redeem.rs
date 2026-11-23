use std::collections::BTreeMap;

use redb::ReadableTable;

use super::*;
use crate::config::Config;
use crate::crypto::{
    canonicalize_email, decrypt_contact_email, encrypt_contact_email, hmac_email, random_hex,
};

impl SyncDb {
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

            if gate != "admin" {
                if let Some(ref rec) = existing {
                    if rec.status == AccountStatus::Suspended {
                        return Err(DbError::http(403, "Account is suspended"));
                    }
                    return Err(DbError::http(409, "Public key is already registered"));
                }
            }

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
        if count == 0 || count > 500 {
            return Err(DbError::http(400, "Code count must be between 1 and 500"));
        }
        if max_uses == 0 {
            return Err(DbError::http(400, "Code max_uses must be >= 1"));
        }
        if !cfg.profiles.contains_key(profile) {
            return Err(DbError::http(400, format!("Unknown profile '{}'", profile)));
        }
        let prefix = match custom_prefix.map(str::trim).filter(|p| !p.is_empty()) {
            Some(trimmed) => {
                if trimmed.len() > 24
                    || !trimmed
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(DbError::http(
                        400,
                        "Invalid code prefix (1..=24 ASCII alphanumeric, '-' or '_' chars)",
                    ));
                }
                trimmed.to_ascii_uppercase()
            }
            None => {
                if profile == cfg.mode.default_public_profile {
                    "INVITE".to_string()
                } else {
                    profile.to_ascii_uppercase()
                }
            }
        };

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
                    max_uses,
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
            let server_meta = write_txn.open_table(SERVER_META)?;
            let effective_cfg = Self::effective_config_in_txn(cfg, &server_meta)?;
            let cfg = effective_cfg.as_ref();
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
            let Some(target_prof) = cfg.profiles.get(&code_rec.profile) else {
                return Err(DbError::http(500, "Code points to non-existent profile"));
            };

            let existing: Option<RegisteredUserRecord> = match reg_table.get(pubkey)? {
                Some(g) => Some(serde_json::from_slice(g.value())?),
                None => None,
            };
            if let Some(ref rec) = existing {
                if rec.status == AccountStatus::Suspended {
                    return Err(DbError::http(403, "Account is suspended"));
                }
                if rec.profile == code_rec.profile {
                    if rec.valid_until.is_none() {
                        return Err(DbError::http(
                            409,
                            "Account already has an unlimited subscription for this profile",
                        ));
                    }
                } else {
                    let (_, eff_prof, _, _) = Self::resolve_registered_profile(rec, cfg, now_secs)?;
                    if target_prof.max_total_bytes <= eff_prof.max_total_bytes {
                        return Err(DbError::http(
                            409,
                            "Cannot downgrade or overwrite existing higher-or-equal tier account",
                        ));
                    }
                }
            }

            code_rec.used_count += 1;
            code_table.insert(
                code_norm.as_str(),
                serde_json::to_vec(&code_rec)?.as_slice(),
            )?;
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
            u.0 = u.0.saturating_add(m.size as u64);
            u.1 += 1;
        }
        for entry in media_meta.iter()? {
            let (_, v) = entry?;
            let m: MediaMetaRecord = serde_json::from_slice(v.value())?;
            let u = usage.entry(m.owner_pubkey).or_default();
            u.0 = u.0.saturating_add(m.size as u64);
            u.2 += 1;
        }

        let mut out = Vec::new();
        for entry in reg_table.iter()? {
            let (_, v) = entry?;
            let rec: RegisteredUserRecord = serde_json::from_slice(v.value())?;
            let (eff_name, _, in_grace, grace_until) =
                Self::resolve_registered_profile(&rec, cfg, now_secs)?;
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
}
