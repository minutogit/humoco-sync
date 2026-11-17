use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ALLOWED_CHANNELS: [&str; 5] = ["card", "wot", "backup", "post", "media"];
pub const ADMIN_MEMBER_CHANNELS: [&str; 6] = ["card", "wot", "backup", "post", "media", "lock"];
pub const ALLOWED_GATES: [&str; 4] = ["email", "code", "pow", "open"];

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse TOML config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub mode: ModeConfig,
    pub storage: StorageConfig,
    pub media: MediaConfig,
    pub security: SecurityConfig,
    pub email: EmailConfig,
    pub lock: LockConfig,
    pub profiles: BTreeMap<String, ProfileConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            mode: ModeConfig::default(),
            storage: StorageConfig::default(),
            media: MediaConfig::default(),
            security: SecurityConfig::default(),
            email: EmailConfig::default(),
            lock: LockConfig::default(),
            profiles: default_profiles(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LockConfig {
    pub enabled: bool,
    pub max_retention_quarter: u16,
    pub pow_base_bits: u32,
    pub allow_pow_tickets: bool,
    pub ticket_pow_bits: u32,
    pub max_inodes: u64,
}

impl Default for LockConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_retention_quarter: 8159, // 2039-Q4
            pow_base_bits: humoco_proto::DEFAULT_LOCK_POW_BASE_BITS,
            allow_pow_tickets: false,
            ticket_pow_bits: 16,
            max_inodes: 50_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind: String,
    pub public_base_url: String,
    pub data_dir: String,
    pub db_path: PathBuf,
    pub admin_pubkey: String,
    pub server_pepper_hex: String,
    pub soft_warning_percent: u8,
    pub trusted_proxy_hops: u8,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".to_string(),
            public_base_url: "http://127.0.0.1:8080".to_string(),
            data_dir: "humoco_sync_data".to_string(),
            db_path: PathBuf::from("./data/humoco-sync.redb"),
            admin_pubkey: String::new(),
            server_pepper_hex: String::new(),
            soft_warning_percent: 80,
            trusted_proxy_hops: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ModeConfig {
    pub enable_admin_app: bool,
    pub admin_app_profile: String,
    pub max_admin_members: usize,
    pub enable_public_registration: bool,
    pub default_public_profile: String,
    pub registration_gates: Vec<String>,
    pub enable_builtin_ui: bool,
    pub service_name: String,
    pub operator_contact: String,
    pub register_path: String,
}

impl Default for ModeConfig {
    fn default() -> Self {
        Self {
            enable_admin_app: true,
            admin_app_profile: "friends".to_string(),
            max_admin_members: 300,
            enable_public_registration: false,
            default_public_profile: "free".to_string(),
            registration_gates: vec!["email".to_string(), "code".to_string()],
            enable_builtin_ui: true,
            service_name: "HuMoCo Sync Service".to_string(),
            operator_contact: String::new(),
            register_path: "/register".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub max_total_storage_mb: u64,
    pub max_free_pool_mb: u64,
    pub downgrade_grace_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_total_storage_mb: 2048,
            max_free_pool_mb: 1024,
            downgrade_grace_days: 7,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MediaConfig {
    pub max_bytes: usize,
    pub max_user_count: usize,
    pub max_user_bytes: u64,
    pub max_channel_mb: u64,
    pub ttl_days: u32,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            max_bytes: 524_288,
            max_user_count: 12,
            max_user_bytes: 3_145_728,
            max_channel_mb: 512,
            ttl_days: 90,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub admin_token_hash: String,
    pub api_bearer_token_hash: String,
    pub pow_difficulty_bits: u8,
    pub max_registrations_per_ipv4_24_per_day: u32,
    pub max_registrations_per_ipv6_48_per_day: u32,
    pub ip_requests_per_minute: u32,
    pub pubkey_requests_per_minute: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            admin_token_hash: String::new(),
            api_bearer_token_hash: String::new(),
            pow_difficulty_bits: 20,
            max_registrations_per_ipv4_24_per_day: 10,
            max_registrations_per_ipv6_48_per_day: 10,
            ip_requests_per_minute: 120,
            pubkey_requests_per_minute: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailConfig {
    pub enabled: bool,
    pub transport: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_tls_mode: String,
    pub from_address: String,
    pub from_name: String,
    pub token_ttl_minutes: u32,
    pub sendmail_path: String,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            transport: "log".to_string(),
            smtp_host: "localhost".to_string(),
            smtp_port: 587,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_tls_mode: "starttls".to_string(),
            from_address: "noreply@localhost".to_string(),
            from_name: "HuMoCo Sync".to_string(),
            token_ttl_minutes: 30,
            sendmail_path: "/usr/sbin/sendmail".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub display_name: String,
    pub max_total_bytes: u64,
    #[serde(default)]
    pub is_free_pool: bool,
    #[serde(default)]
    pub store_contact_email: bool,
    #[serde(default)]
    pub channels: BTreeMap<String, ChannelQuotaConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelQuotaConfig {
    pub max_bytes: usize,
    #[serde(default)]
    pub ttl_days: u32,
    #[serde(default)]
    pub max_user_count: Option<usize>,
    #[serde(default)]
    pub max_user_bytes: Option<u64>,
}

pub fn default_profiles() -> BTreeMap<String, ProfileConfig> {
    let mut map = BTreeMap::new();

    map.insert(
        "free".to_string(),
        ProfileConfig {
            display_name: "Community Free".to_string(),
            max_total_bytes: 1_572_864, // 1.5 MiB
            is_free_pool: true,
            store_contact_email: false,
            channels: BTreeMap::from([
                (
                    "card".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 524_288,
                        ttl_days: 90,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "wot".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 131_072,
                        ttl_days: 90,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "backup".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 524_288,
                        ttl_days: 180,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "post".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 131_072,
                        ttl_days: 30,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "media".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 524_288,
                        ttl_days: 60,
                        max_user_count: Some(6),
                        max_user_bytes: Some(1_048_576),
                    },
                ),
            ]),
        },
    );

    map.insert(
        "friends".to_string(),
        ProfileConfig {
            display_name: "Friends & Host Circle".to_string(),
            max_total_bytes: 20_971_520, // 20 MiB
            is_free_pool: false,
            store_contact_email: false,
            channels: BTreeMap::from([
                (
                    "card".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 1_048_576,
                        ttl_days: 0,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "wot".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 262_144,
                        ttl_days: 0,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "backup".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 4_194_304,
                        ttl_days: 0,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "post".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 262_144,
                        ttl_days: 90,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "media".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 524_288,
                        ttl_days: 90,
                        max_user_count: Some(16),
                        max_user_bytes: Some(6_291_456),
                    },
                ),
            ]),
        },
    );

    map.insert(
        "pro".to_string(),
        ProfileConfig {
            display_name: "Supporter Pro".to_string(),
            max_total_bytes: 104_857_600, // 100 MiB
            is_free_pool: false,
            store_contact_email: true,
            channels: BTreeMap::from([
                (
                    "card".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 2_097_152,
                        ttl_days: 365,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "wot".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 524_288,
                        ttl_days: 365,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "backup".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 16_777_216,
                        ttl_days: 365,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "post".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 524_288,
                        ttl_days: 180,
                        max_user_count: None,
                        max_user_bytes: None,
                    },
                ),
                (
                    "media".to_string(),
                    ChannelQuotaConfig {
                        max_bytes: 2_097_152,
                        ttl_days: 365,
                        max_user_count: Some(64),
                        max_user_bytes: Some(52_428_800),
                    },
                ),
            ]),
        },
    );

    map
}

impl Config {
    pub fn load_from_path(path: &Path) -> Result<Self, ConfigError> {
        let raw = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut cfg: Config = toml::from_str(&raw)?;
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn normalize(&mut self) {
        self.server.public_base_url = self
            .server
            .public_base_url
            .trim()
            .trim_end_matches('/')
            .to_string();
        self.server.data_dir = self.server.data_dir.trim().trim_matches('/').to_string();
        self.server.admin_pubkey = self.server.admin_pubkey.trim().to_ascii_lowercase();
        self.server.server_pepper_hex = self.server.server_pepper_hex.trim().to_ascii_lowercase();

        if !self.mode.register_path.starts_with('/') {
            self.mode.register_path = format!("/{}", self.mode.register_path);
        }
        self.mode.register_path = self.mode.register_path.trim_end_matches('/').to_string();
        if self.mode.register_path.is_empty() {
            self.mode.register_path = "/register".to_string();
        }
        for gate in &mut self.mode.registration_gates {
            *gate = gate.trim().to_ascii_lowercase();
        }
        self.email.transport = self.email.transport.trim().to_ascii_lowercase();
        self.email.smtp_tls_mode = self.email.smtp_tls_mode.trim().to_ascii_lowercase();
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.data_dir.is_empty()
            || self.server.data_dir.len() > 64
            || !self
                .server
                .data_dir
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        {
            return Err(ConfigError::Validation(
                "server.data_dir must match [a-z0-9_-]{1,64}".to_string(),
            ));
        }

        if self.server.public_base_url.is_empty()
            || (!self.server.public_base_url.starts_with("http://")
                && !self.server.public_base_url.starts_with("https://"))
        {
            return Err(ConfigError::Validation(
                "server.public_base_url must start with http:// or https://".to_string(),
            ));
        }

        if !self.server.admin_pubkey.is_empty() && !is_hex_exact(&self.server.admin_pubkey, 64) {
            return Err(ConfigError::Validation(
                "server.admin_pubkey must be 64 lowercase hex chars".to_string(),
            ));
        }

        if self.mode.enable_admin_app && self.server.admin_pubkey.is_empty() {
            return Err(ConfigError::Validation(
                "server.admin_pubkey is required when mode.enable_admin_app is true".to_string(),
            ));
        }

        if !self.server.server_pepper_hex.is_empty()
            && (self.server.server_pepper_hex.len() < 64
                || !self
                    .server
                    .server_pepper_hex
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
                || !self.server.server_pepper_hex.len().is_multiple_of(2))
        {
            return Err(ConfigError::Validation(
                "server.server_pepper_hex must be at least 64 even hex chars".to_string(),
            ));
        }

        if !self.profiles.contains_key(&self.mode.admin_app_profile) {
            return Err(ConfigError::Validation(format!(
                "mode.admin_app_profile '{}' not found in [profiles]",
                self.mode.admin_app_profile
            )));
        }

        if !self
            .profiles
            .contains_key(&self.mode.default_public_profile)
        {
            return Err(ConfigError::Validation(format!(
                "mode.default_public_profile '{}' not found in [profiles]",
                self.mode.default_public_profile
            )));
        }

        for gate in &self.mode.registration_gates {
            if !ALLOWED_GATES.contains(&gate.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "unsupported registration gate '{}'",
                    gate
                )));
            }
        }

        for (name, profile) in &self.profiles {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
            {
                return Err(ConfigError::Validation(format!(
                    "profile name '{}' must match [a-z0-9_-]+",
                    name
                )));
            }
            for ch in profile.channels.keys() {
                if !ALLOWED_CHANNELS.contains(&ch.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "unsupported channel '{}' in profile '{}'",
                        ch, name
                    )));
                }
            }
        }

        if self.storage.max_free_pool_mb > self.storage.max_total_storage_mb {
            return Err(ConfigError::Validation(
                "storage.max_free_pool_mb must not exceed storage.max_total_storage_mb".to_string(),
            ));
        }

        if self.security.pow_difficulty_bits > 32 {
            return Err(ConfigError::Validation(
                "security.pow_difficulty_bits must be <= 32".to_string(),
            ));
        }

        if humoco_proto::decode_quarter(self.lock.max_retention_quarter).is_err() {
            return Err(ConfigError::Validation(
                "lock.max_retention_quarter must encode YYYY-QN with year in 2020..=9999"
                    .to_string(),
            ));
        }
        if self.lock.pow_base_bits > humoco_proto::MAX_LOCK_POW_BITS {
            return Err(ConfigError::Validation(
                "lock.pow_base_bits must be <= 24".to_string(),
            ));
        }
        if self.lock.ticket_pow_bits > 28 {
            return Err(ConfigError::Validation(
                "lock.ticket_pow_bits must be <= 28".to_string(),
            ));
        }
        if self.lock.max_inodes == 0 {
            return Err(ConfigError::Validation(
                "lock.max_inodes must be >= 1".to_string(),
            ));
        }

        Ok(())
    }

    pub fn read_url(&self) -> String {
        format!("{}/{}", self.server.public_base_url, self.server.data_dir)
    }

    pub fn register_url(&self) -> Option<String> {
        if self.mode.enable_public_registration {
            Some(format!(
                "{}{}",
                self.server.public_base_url, self.mode.register_path
            ))
        } else {
            None
        }
    }

    pub fn max_total_bytes(&self) -> u64 {
        self.storage
            .max_total_storage_mb
            .saturating_mul(1024 * 1024)
    }

    pub fn max_free_pool_bytes(&self) -> u64 {
        self.storage.max_free_pool_mb.saturating_mul(1024 * 1024)
    }

    pub fn soft_limit_bytes(&self) -> u64 {
        let pct = self.server.soft_warning_percent.clamp(1, 100) as u64;
        self.max_total_bytes().saturating_mul(pct) / 100
    }

    pub fn media_channel_max_bytes(&self) -> u64 {
        self.media.max_channel_mb.saturating_mul(1024 * 1024)
    }

    pub fn max_upload_body_bytes(&self) -> usize {
        let profile_max = self
            .profiles
            .values()
            .flat_map(|p| p.channels.values().map(|c| c.max_bytes))
            .max()
            .unwrap_or(self.media.max_bytes);
        profile_max.max(self.media.max_bytes).max(65_536)
    }

    pub fn supported_channels(&self) -> Vec<String> {
        let mut out = Vec::new();
        for ch in ALLOWED_CHANNELS {
            if self.profiles.values().any(|p| p.channels.contains_key(ch)) || ch == "media" {
                out.push(ch.to_string());
            }
        }
        if self.lock.enabled {
            out.push("lock".to_string());
        }
        out
    }

    pub fn gate_enabled(&self, gate: &str) -> bool {
        self.mode.enable_public_registration
            && self.mode.registration_gates.iter().any(|g| g == gate)
    }
}

pub fn is_hex_exact(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
