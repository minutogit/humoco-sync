use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;
use parking_lot::Mutex;

use crate::crypto::unix_now;

#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    last_refill_secs: u64,
}

#[derive(Debug, Clone)]
struct SubnetCounter {
    day_bucket: u64,
    count: u32,
}

#[derive(Debug)]
pub struct RateLimiter {
    ip_per_min: u32,
    pubkey_per_min: u32,
    max_ipv4_24_per_day: u32,
    max_ipv6_48_per_day: u32,
    ip_buckets: Mutex<HashMap<String, Bucket>>,
    pubkey_buckets: Mutex<HashMap<String, Bucket>>,
    subnet_registrations: Mutex<HashMap<String, SubnetCounter>>,
    admin_sessions: Mutex<HashMap<String, u64>>,
}

impl RateLimiter {
    pub fn new(
        ip_per_min: u32,
        pubkey_per_min: u32,
        max_ipv4_24_per_day: u32,
        max_ipv6_48_per_day: u32,
    ) -> Self {
        Self {
            ip_per_min: ip_per_min.max(1),
            pubkey_per_min: pubkey_per_min.max(1),
            max_ipv4_24_per_day,
            max_ipv6_48_per_day,
            ip_buckets: Mutex::new(HashMap::new()),
            pubkey_buckets: Mutex::new(HashMap::new()),
            subnet_registrations: Mutex::new(HashMap::new()),
            admin_sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow_ip(&self, ip: IpAddr) -> bool {
        self.consume(&self.ip_buckets, &ip.to_string(), self.ip_per_min)
    }

    pub fn allow_pubkey(&self, pubkey: &str) -> bool {
        self.consume(&self.pubkey_buckets, pubkey, self.pubkey_per_min)
    }

    pub fn check_and_record_registration_subnet(&self, ip: IpAddr) -> bool {
        let now = unix_now();
        let day_bucket = now / 86_400;
        let (key, limit) = match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                (
                    format!("v4:{}.{}.{}", o[0], o[1], o[2]),
                    self.max_ipv4_24_per_day,
                )
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                (
                    format!("v6:{:04x}:{:04x}:{:04x}", s[0], s[1], s[2]),
                    self.max_ipv6_48_per_day,
                )
            }
        };
        if limit == 0 {
            return true;
        }
        let mut guard = self.subnet_registrations.lock();
        if guard.len() > 4096 {
            guard.retain(|_, v| v.day_bucket == day_bucket);
        }
        let entry = guard.entry(key).or_insert(SubnetCounter {
            day_bucket,
            count: 0,
        });
        if entry.day_bucket != day_bucket {
            entry.day_bucket = day_bucket;
            entry.count = 0;
        }
        if entry.count >= limit {
            return false;
        }
        entry.count += 1;
        true
    }

    pub fn create_admin_session(&self, session_id: String, ttl_secs: u64) {
        let now = unix_now();
        let mut guard = self.admin_sessions.lock();
        guard.retain(|_, exp| *exp > now);
        guard.insert(session_id, now + ttl_secs);
    }

    pub fn validate_admin_session(&self, session_id: &str) -> bool {
        let now = unix_now();
        let mut guard = self.admin_sessions.lock();
        match guard.get_mut(session_id) {
            Some(exp) if *exp > now => {
                *exp = now + 3600;
                true
            }
            Some(_) => {
                guard.remove(session_id);
                false
            }
            None => false,
        }
    }

    pub fn revoke_admin_session(&self, session_id: &str) {
        self.admin_sessions.lock().remove(session_id);
    }

    fn consume(&self, map: &Mutex<HashMap<String, Bucket>>, key: &str, per_min: u32) -> bool {
        let now = unix_now();
        let cap = per_min as f64;
        let refill_rate = cap / 60.0;
        let mut guard = map.lock();
        if guard.len() > 8192 {
            guard.retain(|_, b| now.saturating_sub(b.last_refill_secs) < 600);
        }
        let bucket = guard.entry(key.to_string()).or_insert(Bucket {
            tokens: cap,
            last_refill_secs: now,
        });
        let elapsed = now.saturating_sub(bucket.last_refill_secs) as f64;
        if elapsed > 0.0 {
            bucket.tokens = (bucket.tokens + elapsed * refill_rate).min(cap);
            bucket.last_refill_secs = now;
        }
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub fn extract_client_ip(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxy_hops: u8,
) -> IpAddr {
    let peer_ip = peer
        .map(|s| s.ip())
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));
    if trusted_proxy_hops == 0 {
        return peer_ip;
    }
    let is_trusted_peer = match peer_ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    if !is_trusted_peer {
        return peer_ip;
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let parts: Vec<&str> = xff.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        if !parts.is_empty() {
            let hops = trusted_proxy_hops as usize;
            let idx = parts.len().saturating_sub(hops);
            if let Ok(ip) = parts[idx].parse::<IpAddr>() {
                return ip;
            }
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = real_ip.trim().parse::<IpAddr>() {
            return ip;
        }
    }
    peer_ip
}
