use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;
use parking_lot::Mutex;

use crate::crypto::unix_now;

const MAX_RATE_BUCKETS: usize = 65_536;
const MAX_SUBNET_ENTRIES: usize = 16_384;
const MAX_ADMIN_SESSIONS: usize = 4_096;
const BUCKET_STALE_SECS: u64 = 600;

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
    ip_buckets: Mutex<HashMap<IpAddr, Bucket>>,
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
        let norm = rate_limit_ip_key(ip);
        Self::consume_key(&self.ip_buckets, &norm, || norm, self.ip_per_min)
    }

    pub fn allow_pubkey(&self, pubkey: &str) -> bool {
        Self::consume_key(
            &self.pubkey_buckets,
            pubkey,
            || pubkey.to_string(),
            self.pubkey_per_min,
        )
    }

    pub fn check_and_record_registration_subnet(&self, ip: IpAddr) -> bool {
        let now = unix_now();
        let day_bucket = now / 86_400;
        let ip = normalize_ip(ip);
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
        if !guard.contains_key(&key) && guard.len() >= MAX_SUBNET_ENTRIES {
            guard.retain(|_, v| v.day_bucket == day_bucket);
            if guard.len() >= MAX_SUBNET_ENTRIES {
                let target_len = MAX_SUBNET_ENTRIES * 3 / 4;
                let remove_n = guard.len().saturating_sub(target_len);
                let mut candidates: Vec<(String, bool, u32)> = guard
                    .iter()
                    .map(|(k, v)| {
                        let entry_limit = if k.starts_with("v6:") {
                            self.max_ipv6_48_per_day
                        } else {
                            self.max_ipv4_24_per_day
                        };
                        let saturated = entry_limit > 0 && v.count >= entry_limit;
                        (k.clone(), saturated, v.count)
                    })
                    .collect();
                candidates.sort_by_key(|(_, saturated, count)| (*saturated, *count));
                for (k, _, _) in candidates.into_iter().take(remove_n) {
                    guard.remove(&k);
                }
            }
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
        if guard.len() >= MAX_ADMIN_SESSIONS && !guard.contains_key(&session_id) {
            if let Some(oldest_k) = guard
                .iter()
                .min_by_key(|(_, exp)| *exp)
                .map(|(k, _)| k.clone())
            {
                guard.remove(&oldest_k);
            }
        }
        guard.insert(session_id, now.saturating_add(ttl_secs));
    }

    pub fn validate_admin_session(&self, session_id: &str) -> bool {
        let now = unix_now();
        let mut guard = self.admin_sessions.lock();
        match guard.get_mut(session_id) {
            Some(exp) if *exp > now => {
                *exp = now.saturating_add(3600);
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

    fn consume_key<K, Q>(
        map: &Mutex<HashMap<K, Bucket>>,
        key: &Q,
        to_owned: impl FnOnce() -> K,
        per_min: u32,
    ) -> bool
    where
        K: Eq + Hash + Clone + Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        let now = unix_now();
        let cap = per_min as f64;
        let refill_rate = cap / 60.0;
        let mut guard = map.lock();
        if let Some(bucket) = guard.get_mut(key) {
            return Self::take_token(bucket, now, cap, refill_rate);
        }
        Self::evict_buckets_if_full(&mut guard, now);
        let mut bucket = Bucket {
            tokens: cap,
            last_refill_secs: now,
        };
        let allowed = Self::take_token(&mut bucket, now, cap, refill_rate);
        guard.insert(to_owned(), bucket);
        allowed
    }

    fn take_token(bucket: &mut Bucket, now: u64, cap: f64, refill_rate: f64) -> bool {
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

    fn evict_buckets_if_full<K: Eq + Hash + Clone>(guard: &mut HashMap<K, Bucket>, now: u64) {
        if guard.len() < MAX_RATE_BUCKETS {
            return;
        }
        guard.retain(|_, b| now.saturating_sub(b.last_refill_secs) < BUCKET_STALE_SECS);
        if guard.len() >= MAX_RATE_BUCKETS {
            let target_len = MAX_RATE_BUCKETS * 3 / 4;
            let remove_n = guard.len().saturating_sub(target_len);
            let mut candidates: Vec<(K, bool, u64)> = guard
                .iter()
                .map(|(k, b)| (k.clone(), b.tokens < 1.0, b.last_refill_secs))
                .collect();
            candidates.sort_by_key(|(_, throttled, ts)| (*throttled, *ts));
            for (k, _, _) in candidates.into_iter().take(remove_n) {
                guard.remove(&k);
            }
        }
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn rate_limit_ip_key(ip: IpAddr) -> IpAddr {
    match normalize_ip(ip) {
        IpAddr::V6(v6) if !v6.is_loopback() => {
            let s = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        other => other,
    }
}

pub fn extract_client_ip(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxy_hops: u8,
) -> IpAddr {
    let peer_ip = normalize_ip(
        peer.map(|s| s.ip())
            .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1])),
    );
    if trusted_proxy_hops == 0 {
        return peer_ip;
    }
    let is_trusted_peer = match peer_ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    };
    if !is_trusted_peer {
        return peer_ip;
    }
    let parts: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if !parts.is_empty() {
        let hops = trusted_proxy_hops as usize;
        let idx = parts.len().saturating_sub(hops);
        if let Ok(ip) = parts[idx].parse::<IpAddr>() {
            return normalize_ip(ip);
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = real_ip.trim().parse::<IpAddr>() {
            return normalize_ip(ip);
        }
    }
    peer_ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::net::Ipv6Addr;

    #[test]
    fn test_s04_extract_client_ip_multi_xff_and_dualstack_mapped_v6() {
        // 1. Multiple X-Forwarded-For headers (client spoofed first, proxy appended second)
        let mut hdrs = HeaderMap::new();
        hdrs.append("x-forwarded-for", HeaderValue::from_static("198.51.100.99"));
        hdrs.append("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
        let loop_peer: SocketAddr = "127.0.0.1:4444".parse().unwrap();
        assert_eq!(
            extract_client_ip(Some(loop_peer), &hdrs, 1),
            IpAddr::from([203, 0, 113, 7]),
            "Must consider ALL X-Forwarded-For header instances, not just the first"
        );

        // 2. Dual-stack IPv4-mapped IPv6 proxy peer (::ffff:127.0.0.1, ::ffff:172.18.0.2) and ULA (fd00::1)
        let mapped_loop: SocketAddr = "[::ffff:127.0.0.1]:4444".parse().unwrap();
        assert_eq!(
            extract_client_ip(Some(mapped_loop), &hdrs, 1),
            IpAddr::from([203, 0, 113, 7]),
            "IPv4-mapped loopback peer must be trusted as proxy"
        );
        let mapped_priv: SocketAddr = "[::ffff:172.18.0.2]:4444".parse().unwrap();
        assert_eq!(
            extract_client_ip(Some(mapped_priv), &hdrs, 1),
            IpAddr::from([203, 0, 113, 7]),
            "IPv4-mapped Docker private peer must be trusted as proxy"
        );
        let ula_peer: SocketAddr = "[fd00::1]:4444".parse().unwrap();
        assert_eq!(
            extract_client_ip(Some(ula_peer), &hdrs, 1),
            IpAddr::from([203, 0, 113, 7]),
            "IPv6 ULA peer must be trusted as proxy"
        );

        // 3. Untrusted public peer must NEVER trust X-Forwarded-For
        let pub_peer: SocketAddr = "192.0.2.50:4444".parse().unwrap();
        assert_eq!(
            extract_client_ip(Some(pub_peer), &hdrs, 1),
            IpAddr::from([192, 0, 2, 50])
        );

        // 4. Dual-stack IPv4-mapped IPv6 clients must NOT collapse into v6:0000:0000:0000
        let rl = RateLimiter::new(10, 10, 1, 1);
        let mapped_a = IpAddr::V6("::ffff:192.0.2.1".parse::<Ipv6Addr>().unwrap());
        let mapped_b = IpAddr::V6("::ffff:198.51.100.1".parse::<Ipv6Addr>().unwrap());
        let plain_a2 = IpAddr::from([192, 0, 2, 2]);
        assert!(rl.check_and_record_registration_subnet(mapped_a));
        assert!(
            rl.check_and_record_registration_subnet(mapped_b),
            "Distinct IPv4-mapped /24 subnets must not collide in v6:0000:0000:0000"
        );
        assert!(
            !rl.check_and_record_registration_subnet(plain_a2),
            "Plain IPv4 in same /24 as mapped IPv4 must share the /24 subnet cap"
        );
    }

    #[test]
    fn test_s04_ratelimiter_bounded_maps_and_preserves_throttled() {
        let rl = RateLimiter::new(2, 2, 2, 2);
        let attacker_ip = IpAddr::from([198, 51, 100, 1]);
        assert!(rl.allow_ip(attacker_ip));
        assert!(rl.allow_ip(attacker_ip));
        assert!(!rl.allow_ip(attacker_ip));

        // Flood 70,000 unique IPs within the active window (< 600s), each taking 1 token
        for i in 0u32..70_000 {
            let b1 = ((i >> 16) & 0xff) as u8;
            let b2 = ((i >> 8) & 0xff) as u8;
            let b3 = (i & 0xff) as u8;
            let _ = rl.allow_ip(IpAddr::from([10, b1, b2, b3]));
        }
        assert!(
            rl.ip_buckets.lock().len() <= 65_536,
            "ip_buckets must stay bounded under active IP flood"
        );
        assert!(
            !rl.allow_ip(attacker_ip),
            "Throttled IP bucket must be preserved ahead of idle unthrottled flood IPs"
        );

        let blocked_subnet_ip = IpAddr::from([192, 0, 2, 10]);
        assert!(rl.check_and_record_registration_subnet(blocked_subnet_ip));
        assert!(rl.check_and_record_registration_subnet(blocked_subnet_ip));
        assert!(!rl.check_and_record_registration_subnet(blocked_subnet_ip));

        for i in 0u32..20_000 {
            let b1 = ((i >> 8) & 0xff) as u8;
            let b2 = (i & 0xff) as u8;
            let _ = rl.check_and_record_registration_subnet(IpAddr::from([172, b1, b2, 1]));
        }
        assert!(
            rl.subnet_registrations.lock().len() <= 16_384,
            "subnet_registrations must stay bounded under /24 flood"
        );
        assert!(
            !rl.check_and_record_registration_subnet(blocked_subnet_ip),
            "Saturated /24 subnet cap must remain enforced under flood"
        );
    }

    #[test]
    fn test_s04_ipv6_slash64_rate_limit_grouping() {
        let rl = RateLimiter::new(2, 10, 10, 10);
        let a1: IpAddr = "2001:db8:abcd:0001::1".parse().unwrap();
        let a2: IpAddr = "2001:db8:abcd:0001:ffff:ffff:ffff:9999".parse().unwrap();
        let b1: IpAddr = "2001:db8:abcd:0002::1".parse().unwrap();
        let lo: IpAddr = "::1".parse().unwrap();

        assert!(rl.allow_ip(a1));
        assert!(rl.allow_ip(a2));
        assert!(
            !rl.allow_ip(a2),
            "Distinct /128 addresses in the same /64 must share one rate-limit bucket"
        );
        assert!(
            rl.allow_ip(b1),
            "Different /64 prefix must have an independent bucket"
        );
        assert!(
            rl.allow_ip(lo),
            "IPv6 loopback ::1 must stay isolated from 0000:0000:0000:0000::/64"
        );
    }
}
