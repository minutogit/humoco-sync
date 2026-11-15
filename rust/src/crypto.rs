use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::is_hex_exact;

type HmacSha256 = Hmac<Sha256>;

pub const TIMESTAMP_WINDOW_SECS: i64 = 60;
pub const NONCE_TTL_SECS: u64 = 120;
pub const EMPTY_SHA256_HEX: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn random_hex(bytes_len: usize) -> String {
    let mut buf = vec![0u8; bytes_len];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn normalize_pubkey_hex(raw: &str) -> Option<String> {
    let lower = raw.trim().to_ascii_lowercase();
    if is_hex_exact(&lower, 64) {
        Some(lower)
    } else {
        None
    }
}

pub fn validate_nonce_hex(raw: &str) -> Option<String> {
    let lower = raw.trim().to_ascii_lowercase();
    if is_hex_exact(&lower, 32) {
        Some(lower)
    } else {
        None
    }
}

pub fn validate_channel(raw: &str) -> Option<String> {
    let clean = raw.trim();
    if matches!(clean, "card" | "wot" | "backup" | "post" | "media") {
        Some(clean.to_string())
    } else {
        None
    }
}

/// Validates `X-Drop-Prefix`: `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`, no `--`.
pub fn validate_drop_prefix(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 63 || s.contains("--") {
        return None;
    }
    let bytes = s.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return None;
    }
    if bytes.iter().all(|&b| is_alnum(b) || b == b'-') {
        Some(s.to_string())
    } else {
        None
    }
}

pub fn format_slot_id(pubkey_hex: &str, prefix: Option<&str>) -> String {
    match prefix {
        Some(p) if !p.is_empty() => format!("{}_{}", pubkey_hex, p),
        _ => pubkey_hex.to_string(),
    }
}

pub fn parse_member_message(
    method: &str,
    channel_target: &str,
    prefix: &str,
    timestamp: i64,
    nonce: &str,
    body_sha256_hex: &str,
) -> String {
    format!(
        "HUMOCO-DROP-REQ-V1\n{}\n{}\n{}\n{}\n{}\n{}",
        method, channel_target, prefix, timestamp, nonce, body_sha256_hex
    )
}

pub fn format_delete_account_message(timestamp: i64, nonce: &str) -> String {
    format!(
        "HUMOCO-DROP-REQ-V1\nDELETE_ACCOUNT\n\n{}\n{}\n{}",
        timestamp, nonce, EMPTY_SHA256_HEX
    )
}

pub fn format_admin_put_members_message(
    channel: &str,
    timestamp: i64,
    nonce: &str,
    body_sha256_hex: &str,
) -> String {
    format!(
        "HUMOCO-DROP-ADMIN-V1\nPUT_MEMBERS\n{}\n{}\n{}\n{}",
        channel, timestamp, nonce, body_sha256_hex
    )
}

pub fn format_admin_status_message(timestamp: i64, nonce: &str) -> String {
    format!(
        "HUMOCO-DROP-ADMIN-V1\nSTATUS\n\n{}\n{}\n{}",
        timestamp, nonce, EMPTY_SHA256_HEX
    )
}

pub fn format_admin_put_revoke_message(
    timestamp: i64,
    nonce: &str,
    body_sha256_hex: &str,
) -> String {
    format!(
        "HUMOCO-DROP-ADMIN-V1\nPUT_REVOKE\n{}\n{}\n{}",
        timestamp, nonce, body_sha256_hex
    )
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RevocationReplacementTarget {
    pub write_url: String,
    pub read_url: String,
    pub drop_pub: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RevocationNotice {
    pub drop_pub: String,
    pub issued_at: u64,
    pub effective_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<RevocationReplacementTarget>,
    pub signature: String,
}

pub fn canonical_revocation_message(notice: &RevocationNotice) -> String {
    let (rep_w, rep_r, rep_p) = match &notice.replacement {
        Some(r) => (
            r.write_url.as_str(),
            r.read_url.as_str(),
            r.drop_pub.to_ascii_lowercase(),
        ),
        None => ("", "", String::new()),
    };
    format!(
        "HUMOCO-DROP-REVOKE-V1\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        notice.drop_pub.to_ascii_lowercase(),
        notice.issued_at,
        notice.effective_at,
        rep_w,
        rep_r,
        rep_p,
        notice.reason.as_deref().unwrap_or("")
    )
}

pub fn verify_revocation_notice(
    notice: &RevocationNotice,
    expected_drop_pub: &str,
) -> Result<(), String> {
    let expected = normalize_pubkey_hex(expected_drop_pub)
        .ok_or_else(|| "Invalid admin pubkey".to_string())?;
    if notice.drop_pub.trim().to_ascii_lowercase() != expected {
        return Err("Revocation drop_pub mismatch".to_string());
    }
    if notice.issued_at == 0 || notice.effective_at == 0 {
        return Err("Missing revocation timestamps".to_string());
    }
    if let Some(ref reason) = notice.reason {
        if reason.len() > 200 || reason.contains('\n') || reason.contains('\r') || reason.contains('\0') {
            return Err("Invalid revocation reason".to_string());
        }
    }
    if let Some(ref rep) = notice.replacement {
        if normalize_pubkey_hex(&rep.drop_pub).is_none() {
            return Err("Invalid replacement drop_pub".to_string());
        }
        if !(rep.write_url.starts_with("http://") || rep.write_url.starts_with("https://"))
            || !(rep.read_url.starts_with("http://") || rep.read_url.starts_with("https://"))
        {
            return Err("Invalid replacement URLs".to_string());
        }
    }
    let msg = canonical_revocation_message(notice);
    verify_ed25519_hex(&expected, &notice.signature, msg.as_bytes())
        .then_some(())
        .ok_or_else(|| "Invalid revocation signature".to_string())
}

pub fn verify_ed25519_hex(pubkey_hex: &str, sig_hex: &str, message: &[u8]) -> bool {
    let pk_bytes = match hex::decode(pubkey_hex.trim()) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let sig_bytes = match hex::decode(sig_hex.trim()) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message, &sig).is_ok()
}

pub fn check_timestamp_window(timestamp: i64, now_secs: u64) -> bool {
    let now = now_secs as i64;
    (now - timestamp).abs() <= TIMESTAMP_WINDOW_SECS
}

/// Canonicalizes email addresses so Gmail dot/plus tricks and case variants map consistently,
/// while returning None on invalid input.
pub fn canonicalize_email(raw: &str) -> Option<String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 254 || trimmed.contains(char::is_whitespace) {
        return None;
    }
    let (local, domain) = trimmed.split_once('@')?;
    if local.is_empty() || domain.is_empty() || !domain.contains('.') || domain.contains('@') {
        return None;
    }
    if !domain
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return None;
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return None;
    }
    let base_local = local.split('+').next().unwrap_or(local);
    let norm_local = if domain == "gmail.com" || domain == "googlemail.com" {
        base_local.replace('.', "")
    } else {
        base_local.to_string()
    };
    if norm_local.is_empty() {
        return None;
    }
    let norm_domain = if domain == "googlemail.com" {
        "gmail.com"
    } else {
        domain
    };
    Some(format!("{}@{}", norm_local, norm_domain))
}

pub fn hmac_email(pepper: &[u8; 32], canonical_email: &str) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(pepper).expect("HMAC key size valid");
    mac.update(b"humoco-sync-email-v1:");
    mac.update(canonical_email.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn encrypt_contact_email(pepper: &[u8; 32], email: &str) -> Result<Vec<u8>, String> {
    let key_material = blake3::derive_key("humoco-sync contact-email xchacha20poly1305 v1", pepper);
    let cipher = XChaCha20Poly1305::new((&key_material).into());
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, email.as_bytes())
        .map_err(|_| "failed to encrypt email".to_string())?;
    let mut out = Vec::with_capacity(24 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_contact_email(pepper: &[u8; 32], blob: &[u8]) -> Result<String, String> {
    if blob.len() < 24 {
        return Err("corrupt email ciphertext".to_string());
    }
    let key_material = blake3::derive_key("humoco-sync contact-email xchacha20poly1305 v1", pepper);
    let cipher = XChaCha20Poly1305::new((&key_material).into());
    let nonce = XNonce::from_slice(&blob[..24]);
    let plaintext = cipher
        .decrypt(nonce, &blob[24..])
        .map_err(|_| "failed to decrypt email".to_string())?;
    String::from_utf8(plaintext).map_err(|_| "invalid utf8 email".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedActionToken {
    pub action: String,
    pub pubkey: String,
    pub email_hmac: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
    pub profile: String,
    pub exp: u64,
    pub jti: String,
}

pub fn sign_stateless_token(pepper: &[u8; 32], claims: &SignedActionToken) -> String {
    let payload_json = serde_json::to_vec(claims).expect("token serialization cannot fail");
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    let mac_key = blake3::derive_key("humoco-sync action-token hmac v1", pepper);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&mac_key).expect("HMAC key valid");
    mac.update(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{}.{}", payload_b64, sig_b64)
}

pub fn verify_stateless_token(
    pepper: &[u8; 32],
    token: &str,
    expected_action: &str,
    now_secs: u64,
) -> Result<SignedActionToken, String> {
    let (payload_b64, sig_b64) = token
        .trim()
        .split_once('.')
        .ok_or_else(|| "Malformed token".to_string())?;
    let provided_sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "Malformed token signature".to_string())?;
    let mac_key = blake3::derive_key("humoco-sync action-token hmac v1", pepper);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&mac_key).expect("HMAC key valid");
    mac.update(payload_b64.as_bytes());
    let expected_sig = mac.finalize().into_bytes();
    if provided_sig.len() != expected_sig.len()
        || !bool::from(provided_sig.as_slice().ct_eq(expected_sig.as_slice()))
    {
        return Err("Invalid token signature".to_string());
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| "Malformed token payload".to_string())?;
    let claims: SignedActionToken =
        serde_json::from_slice(&payload_bytes).map_err(|_| "Invalid token claims".to_string())?;
    if claims.action != expected_action {
        return Err("Token action mismatch".to_string());
    }
    if claims.exp < now_secs {
        return Err("Token expired".to_string());
    }
    Ok(claims)
}

pub fn create_pow_challenge(pepper: &[u8; 32], pubkey: &str, difficulty_bits: u8, now_secs: u64) -> String {
    let rand_hex = random_hex(12);
    let exp = now_secs + 300;
    let body = format!("{}.{}.{}.{}", pubkey, difficulty_bits, exp, rand_hex);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(pepper).expect("HMAC key valid");
    mac.update(b"humoco-sync-pow-v1:");
    mac.update(body.as_bytes());
    let tag = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{}.{}", body, tag)
}

pub fn verify_pow_solution(
    pepper: &[u8; 32],
    challenge: &str,
    expected_pubkey: &str,
    nonce_str: &str,
    now_secs: u64,
) -> Result<(), String> {
    let parts: Vec<&str> = challenge.trim().split('.').collect();
    if parts.len() != 5 {
        return Err("Malformed PoW challenge".to_string());
    }
    let (pk, diff_str, exp_str, _rand, tag_b64) =
        (parts[0], parts[1], parts[2], parts[3], parts[4]);
    if pk != expected_pubkey {
        return Err("PoW challenge bound to a different key".to_string());
    }
    let body = format!("{}.{}.{}.{}", pk, diff_str, exp_str, parts[3]);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(pepper).expect("HMAC key valid");
    mac.update(b"humoco-sync-pow-v1:");
    mac.update(body.as_bytes());
    let expected_tag = mac.finalize().into_bytes();
    let provided_tag = URL_SAFE_NO_PAD
        .decode(tag_b64)
        .map_err(|_| "Malformed PoW signature".to_string())?;
    if provided_tag.len() != expected_tag.len()
        || !bool::from(provided_tag.as_slice().ct_eq(expected_tag.as_slice()))
    {
        return Err("Invalid PoW challenge signature".to_string());
    }
    let exp: u64 = exp_str.parse().map_err(|_| "Invalid PoW expiry".to_string())?;
    if now_secs > exp {
        return Err("PoW challenge expired".to_string());
    }
    let difficulty: u8 = diff_str
        .parse()
        .map_err(|_| "Invalid PoW difficulty".to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(challenge.as_bytes());
    hasher.update(b":");
    hasher.update(nonce_str.trim().as_bytes());
    let digest = hasher.finalize();
    if leading_zero_bits(&digest) < difficulty {
        return Err("PoW solution insufficient leading zero bits".to_string());
    }
    Ok(())
}

pub fn leading_zero_bits(bytes: &[u8]) -> u8 {
    let mut count = 0u8;
    for &b in bytes {
        if b == 0 {
            count = count.saturating_add(8);
        } else {
            count = count.saturating_add(b.leading_zeros() as u8);
            break;
        }
    }
    count
}

pub fn hash_admin_token(token: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(token.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Argon2 hash failed: {}", e))
}

#[derive(Default)]
pub struct TokenVerifierCache {
    verified_digests: Mutex<HashMap<[u8; 32], u64>>,
}

impl TokenVerifierCache {
    pub fn verify_token(&self, configured_hash: &str, candidate: &str) -> bool {
        let cfg = configured_hash.trim();
        if cfg.is_empty() || candidate.is_empty() {
            return false;
        }
        if let Some(hex_digest) = cfg.strip_prefix("sha256:") {
            let Ok(expected) = hex::decode(hex_digest.trim()) else {
                return false;
            };
            let candidate_hash = Sha256::digest(candidate.as_bytes());
            return expected.len() == candidate_hash.len()
                && bool::from(expected.as_slice().ct_eq(candidate_hash.as_slice()));
        }

        let mut cache_key_hasher = blake3::Hasher::new();
        cache_key_hasher.update(cfg.as_bytes());
        cache_key_hasher.update(b"\0");
        cache_key_hasher.update(candidate.as_bytes());
        let cache_key: [u8; 32] = *cache_key_hasher.finalize().as_bytes();
        let now = unix_now();
        {
            let guard = self.verified_digests.lock();
            if let Some(&exp) = guard.get(&cache_key) {
                if exp > now {
                    return true;
                }
            }
        }

        let Ok(parsed) = PasswordHash::new(cfg) else {
            return false;
        };
        let ok = Argon2::default()
            .verify_password(candidate.as_bytes(), &parsed)
            .is_ok();
        if ok {
            let mut guard = self.verified_digests.lock();
            if guard.len() > 256 {
                guard.retain(|_, exp| *exp > now);
            }
            guard.insert(cache_key, now + 300);
        }
        ok
    }
}

pub fn generate_session_csrf_pair(pepper: &[u8; 32], session_id: &str) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(pepper).expect("HMAC key valid");
    mac.update(b"humoco-sync-csrf-v1:");
    mac.update(session_id.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
