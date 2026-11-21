use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use zeroize::Zeroize;

pub const ALLOWED_CHANNELS: [&str; 5] = ["card", "wot", "backup", "post", "media"];
pub const ADMIN_MEMBER_CHANNELS: [&str; 6] = ["card", "wot", "backup", "post", "media", "lock"];
pub const ALLOWED_GATES: [&str; 4] = ["email", "code", "pow", "open"];
const RESERVED_DATA_DIRS: [&str; 4] = ["anchors", "sync", "admin", "api"];
const RESERVED_ROUTE_PREFIXES: [&str; 5] = ["anchors", "sync", "sync.php", "admin", "api"];
const ALLOWED_EMAIL_TRANSPORTS: [&str; 3] = ["log", "sendmail", "smtp"];
const ALLOWED_SMTP_TLS_MODES: [&str; 3] = ["tls", "starttls", "plain"];
const MAX_TOTAL_STORAGE_MB: u64 = 10_485_760;
const MAX_ADMIN_MEMBERS_CAP: usize = 100_000;

fn redacted_marker(s: &str) -> &'static str {
    if s.is_empty() {
        ""
    } else {
        "[REDACTED]"
    }
}

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
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub mode: ModeConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub media: MediaConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub email: EmailConfig,
    #[serde(default)]
    pub lock: LockConfig,
    #[serde(default = "default_profiles")]
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
    pub max_buckets: u64,
    pub pre_freeze_ttl_secs: u64,
    pub proposal_timelock_secs: u64,
    pub creator_inactivity_secs: u64,
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
            max_buckets: 50_000,
            pre_freeze_ttl_secs: humoco_proto::PRE_PROPOSAL_FREEZE_TTL_SECS,
            proposal_timelock_secs: humoco_proto::PROPOSAL_TIMELOCK_SECS,
            creator_inactivity_secs: humoco_proto::CREATOR_INACTIVITY_TAKEOVER_SECS,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
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

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("bind", &self.bind)
            .field("public_base_url", &self.public_base_url)
            .field("data_dir", &self.data_dir)
            .field("db_path", &self.db_path)
            .field("admin_pubkey", &self.admin_pubkey)
            .field(
                "server_pepper_hex",
                &redacted_marker(&self.server_pepper_hex),
            )
            .field("soft_warning_percent", &self.soft_warning_percent)
            .field("trusted_proxy_hops", &self.trusted_proxy_hops)
            .finish()
    }
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
    pub max_admin_user_storage_mb: Option<u64>,
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
            max_admin_user_storage_mb: None,
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

#[derive(Clone, Serialize, Deserialize)]
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

impl fmt::Debug for SecurityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityConfig")
            .field("admin_token_hash", &redacted_marker(&self.admin_token_hash))
            .field(
                "api_bearer_token_hash",
                &redacted_marker(&self.api_bearer_token_hash),
            )
            .field("pow_difficulty_bits", &self.pow_difficulty_bits)
            .field(
                "max_registrations_per_ipv4_24_per_day",
                &self.max_registrations_per_ipv4_24_per_day,
            )
            .field(
                "max_registrations_per_ipv6_48_per_day",
                &self.max_registrations_per_ipv6_48_per_day,
            )
            .field("ip_requests_per_minute", &self.ip_requests_per_minute)
            .field(
                "pubkey_requests_per_minute",
                &self.pubkey_requests_per_minute,
            )
            .finish()
    }
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

#[derive(Clone, Serialize, Deserialize)]
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

impl fmt::Debug for EmailConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailConfig")
            .field("enabled", &self.enabled)
            .field("transport", &self.transport)
            .field("smtp_host", &self.smtp_host)
            .field("smtp_port", &self.smtp_port)
            .field("smtp_username", &self.smtp_username)
            .field("smtp_password", &redacted_marker(&self.smtp_password))
            .field("smtp_tls_mode", &self.smtp_tls_mode)
            .field("from_address", &self.from_address)
            .field("from_name", &self.from_name)
            .field("token_ttl_minutes", &self.token_ttl_minutes)
            .field("sendmail_path", &self.sendmail_path)
            .finish()
    }
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
            max_total_bytes: 26_214_400, // 25 MiB
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

impl Drop for Config {
    fn drop(&mut self) {
        self.server.server_pepper_hex.zeroize();
        self.email.smtp_password.zeroize();
        self.security.admin_token_hash.zeroize();
        self.security.api_bearer_token_hash.zeroize();
    }
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

        self.mode.register_path = self.mode.register_path.trim().to_string();
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
        if let Some(mb) = self.mode.max_admin_user_storage_mb {
            if let Some(prof) = self.profiles.get_mut(&self.mode.admin_app_profile) {
                prof.max_total_bytes = mb.saturating_mul(1024 * 1024);
                if let Some(mq) = prof.channels.get_mut("media") {
                    if let Some(ref mut ubytes) = mq.max_user_bytes {
                        *ubytes = (*ubytes).min(prof.max_total_bytes);
                    }
                }
            }
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.bind.parse::<SocketAddr>().is_err() {
            return Err(ConfigError::Validation(format!(
                "server.bind '{}' must be a valid socket address (host:port)",
                self.server.bind
            )));
        }

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

        if RESERVED_DATA_DIRS.contains(&self.server.data_dir.as_str()) {
            return Err(ConfigError::Validation(format!(
                "server.data_dir '{}' is reserved and collides with daemon routes",
                self.server.data_dir
            )));
        }

        validate_public_base_url(&self.server.public_base_url)?;
        validate_register_path(&self.mode.register_path, &self.server.data_dir)?;

        if !(1..=100).contains(&self.server.soft_warning_percent) {
            return Err(ConfigError::Validation(
                "server.soft_warning_percent must be between 1 and 100".to_string(),
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

        if !(1..=MAX_ADMIN_MEMBERS_CAP).contains(&self.mode.max_admin_members) {
            return Err(ConfigError::Validation(format!(
                "mode.max_admin_members must be between 1 and {}",
                MAX_ADMIN_MEMBERS_CAP
            )));
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

        if self
            .mode
            .max_admin_user_storage_mb
            .is_some_and(|mb| mb < 10)
        {
            return Err(ConfigError::Validation(
                "mode.max_admin_user_storage_mb must be >= 10".to_string(),
            ));
        }

        if !(1..=MAX_TOTAL_STORAGE_MB).contains(&self.storage.max_total_storage_mb) {
            return Err(ConfigError::Validation(format!(
                "storage.max_total_storage_mb must be between 1 and {}",
                MAX_TOTAL_STORAGE_MB
            )));
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
        if self.security.ip_requests_per_minute == 0 {
            return Err(ConfigError::Validation(
                "security.ip_requests_per_minute must be >= 1".to_string(),
            ));
        }
        if self.security.pubkey_requests_per_minute == 0 {
            return Err(ConfigError::Validation(
                "security.pubkey_requests_per_minute must be >= 1".to_string(),
            ));
        }

        if !ALLOWED_EMAIL_TRANSPORTS.contains(&self.email.transport.as_str()) {
            return Err(ConfigError::Validation(format!(
                "email.transport '{}' must be one of: log, sendmail, smtp",
                self.email.transport
            )));
        }
        if !ALLOWED_SMTP_TLS_MODES.contains(&self.email.smtp_tls_mode.as_str()) {
            return Err(ConfigError::Validation(format!(
                "email.smtp_tls_mode '{}' must be one of: tls, starttls, plain",
                self.email.smtp_tls_mode
            )));
        }
        if !is_safe_email_addr(self.email.from_address.trim()) {
            return Err(ConfigError::Validation(
                "email.from_address must be a valid sender address without control/delimiter chars"
                    .to_string(),
            ));
        }
        if self.email.transport == "smtp" {
            let host = self.email.smtp_host.trim();
            if host.is_empty()
                || host.chars().any(|c| c.is_control() || c.is_whitespace())
                || self.email.smtp_port == 0
            {
                return Err(ConfigError::Validation(
                    "email.smtp_host and non-zero email.smtp_port are required for smtp transport"
                        .to_string(),
                ));
            }
        } else if self.email.transport == "sendmail" {
            let path = self.email.sendmail_path.trim();
            if path.is_empty() || path.chars().any(|c| c.is_control()) {
                return Err(ConfigError::Validation(
                    "email.sendmail_path must be non-empty without control chars for sendmail transport"
                        .to_string(),
                ));
            }
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
        if self.lock.ticket_pow_bits > humoco_proto::MAX_LOCK_POW_BITS {
            return Err(ConfigError::Validation(
                "lock.ticket_pow_bits must be <= 24".to_string(),
            ));
        }
        if self.lock.max_inodes == 0 {
            return Err(ConfigError::Validation(
                "lock.max_inodes must be >= 1".to_string(),
            ));
        }
        if self.lock.max_buckets == 0 {
            return Err(ConfigError::Validation(
                "lock.max_buckets must be >= 1".to_string(),
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
        if !self.mode.enable_public_registration {
            return false;
        }
        if gate == "email" && !self.email.enabled {
            return false;
        }
        self.mode.registration_gates.iter().any(|g| g == gate)
    }
}

fn validate_public_base_url(raw: &str) -> Result<(), ConfigError> {
    if raw.is_empty() || raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(ConfigError::Validation(
            "server.public_base_url must be a valid non-empty http/https URL without whitespace or control chars"
                .to_string(),
        ));
    }
    let parsed = Url::parse(raw).map_err(|_| {
        ConfigError::Validation("server.public_base_url is not a valid URL".to_string())
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.has_host()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigError::Validation(
            "server.public_base_url must be an http/https origin/path URL without credentials, query, or fragment"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_register_path(path: &str, data_dir: &str) -> Result<(), ConfigError> {
    if !path.starts_with('/') || path.len() < 2 || path.len() > 64 || path.ends_with('/') {
        return Err(ConfigError::Validation(
            "mode.register_path must start with '/', be 2..=64 bytes, and not end with '/'"
                .to_string(),
        ));
    }
    let rest = &path[1..];
    let mut segments = rest.split('/');
    let Some(first_seg) = segments.next() else {
        return Err(ConfigError::Validation(
            "mode.register_path must contain at least one path segment".to_string(),
        ));
    };
    for seg in std::iter::once(first_seg).chain(segments) {
        if seg.is_empty()
            || seg == "."
            || seg == ".."
            || !seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(ConfigError::Validation(
                "mode.register_path segments must match [a-zA-Z0-9._-]+ (not '.' or '..')"
                    .to_string(),
            ));
        }
    }
    let first_lower = first_seg.to_ascii_lowercase();
    if RESERVED_ROUTE_PREFIXES.contains(&first_lower.as_str()) || first_lower == data_dir {
        return Err(ConfigError::Validation(format!(
            "mode.register_path '/{}' collides with reserved daemon route prefix",
            first_seg
        )));
    }
    Ok(())
}

fn is_safe_email_addr(addr: &str) -> bool {
    if addr.is_empty()
        || addr.len() > 254
        || addr
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '<' | '>' | ',' | ';'))
    {
        return false;
    }
    let Some((local, domain)) = addr.split_once('@') else {
        return false;
    };
    !local.is_empty() && !domain.is_empty() && !domain.contains('@')
}

pub fn is_hex_exact(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_base_cfg() -> Config {
        let mut cfg = Config::default();
        cfg.server.admin_pubkey = "a".repeat(64);
        cfg
    }

    #[test]
    fn test_s08_config_validation_routes_email_urls_bounds_and_secret_debug() {
        // 1. data_dir must reject reserved routes (anchors panic / sync / admin / api)
        for bad_dir in ["anchors", "sync", "admin", "api"] {
            let mut cfg = valid_base_cfg();
            cfg.server.data_dir = bad_dir.to_string();
            cfg.normalize();
            assert!(
                cfg.validate().is_err(),
                "expected server.data_dir={bad_dir:?} to be rejected"
            );
        }

        // 2. register_path must reject route collisions, matchit wildcards, and URL-unsafe chars
        for bad_reg in [
            "/admin",
            "/admin/login",
            "/sync",
            "/sync.php",
            "/anchors",
            "/api",
            "/api/v1/admin/users",
            "/humoco_sync_data",
            "/humoco_sync_data/anchors",
            "/:id",
            "/*wild",
            "/reg/{x}",
            "/reg//sub",
            "/reg?foo=bar",
            "/reg#frag",
            "/reg\r\nx",
            "/reg space",
            "/..",
        ] {
            let mut cfg = valid_base_cfg();
            cfg.mode.register_path = bad_reg.to_string();
            cfg.normalize();
            assert!(
                cfg.validate().is_err(),
                "expected mode.register_path={bad_reg:?} to be rejected"
            );
        }

        let mut spaced_reg = valid_base_cfg();
        spaced_reg.mode.register_path = "  signup/ ".to_string();
        spaced_reg.normalize();
        assert_eq!(spaced_reg.mode.register_path, "/signup");
        assert!(spaced_reg.validate().is_ok());

        // 3. email.transport, email.smtp_tls_mode, and transport-specific fields
        for bad_t in ["", "smpt", "mailgun"] {
            let mut cfg = valid_base_cfg();
            cfg.email.transport = bad_t.to_string();
            cfg.normalize();
            assert!(
                cfg.validate().is_err(),
                "expected email.transport={bad_t:?} to be rejected"
            );
        }
        for bad_tls in ["", "ssl", "none"] {
            let mut cfg = valid_base_cfg();
            cfg.email.smtp_tls_mode = bad_tls.to_string();
            cfg.normalize();
            assert!(
                cfg.validate().is_err(),
                "expected email.smtp_tls_mode={bad_tls:?} to be rejected"
            );
        }
        let mut empty_smtp = valid_base_cfg();
        empty_smtp.email.transport = "smtp".to_string();
        empty_smtp.email.smtp_host = "  ".to_string();
        assert!(empty_smtp.validate().is_err());

        let mut zero_port_smtp = valid_base_cfg();
        zero_port_smtp.email.transport = "smtp".to_string();
        zero_port_smtp.email.smtp_port = 0;
        assert!(zero_port_smtp.validate().is_err());

        let mut bad_sendmail = valid_base_cfg();
        bad_sendmail.email.transport = "sendmail".to_string();
        bad_sendmail.email.sendmail_path = "/usr/sbin/sendmail\n-evil".to_string();
        assert!(bad_sendmail.validate().is_err());

        let mut bad_from = valid_base_cfg();
        bad_from.email.from_address = "bad>addr@example.org".to_string();
        assert!(bad_from.validate().is_err());

        // 4. server.public_base_url strict URL parsing
        for bad_url in [
            "https://",
            "https://example.org?q=1",
            "https://example.org#frag",
            "https://user:pass@example.org",
            "https://ex ample.org",
            "https://example.org\r\nInject: 1",
        ] {
            let mut cfg = valid_base_cfg();
            cfg.server.public_base_url = bad_url.to_string();
            cfg.normalize();
            assert!(
                cfg.validate().is_err(),
                "expected public_base_url={bad_url:?} to be rejected"
            );
        }
        let mut subpath_url = valid_base_cfg();
        subpath_url.server.public_base_url = "https://sync.example.org/sub/".to_string();
        subpath_url.normalize();
        assert_eq!(
            subpath_url.server.public_base_url,
            "https://sync.example.org/sub"
        );
        assert!(subpath_url.validate().is_ok());

        // 5. Bind & numeric bounds
        let mut bad_bind = valid_base_cfg();
        bad_bind.server.bind = "localhost:8080".to_string();
        assert!(bad_bind.validate().is_err());

        for pct in [0u8, 101] {
            let mut cfg = valid_base_cfg();
            cfg.server.soft_warning_percent = pct;
            assert!(cfg.validate().is_err());
        }
        for mm in [0usize, 100_001] {
            let mut cfg = valid_base_cfg();
            cfg.mode.max_admin_members = mm;
            assert!(cfg.validate().is_err());
        }
        for total_mb in [0u64, 10_485_761] {
            let mut cfg = valid_base_cfg();
            cfg.storage.max_total_storage_mb = total_mb;
            assert!(cfg.validate().is_err());
        }
        let mut zero_ip_rl = valid_base_cfg();
        zero_ip_rl.security.ip_requests_per_minute = 0;
        assert!(zero_ip_rl.validate().is_err());

        let mut zero_pk_rl = valid_base_cfg();
        zero_pk_rl.security.pubkey_requests_per_minute = 0;
        assert!(zero_pk_rl.validate().is_err());

        let mut zero_buckets = valid_base_cfg();
        zero_buckets.lock.max_buckets = 0;
        assert!(zero_buckets.validate().is_err());

        // EmailConfig.enabled controls gate_enabled("email")
        let mut mail_gate_cfg = valid_base_cfg();
        mail_gate_cfg.mode.enable_public_registration = true;
        mail_gate_cfg.mode.registration_gates = vec!["email".to_string(), "code".to_string()];
        mail_gate_cfg.email.enabled = false;
        assert!(!mail_gate_cfg.gate_enabled("email"));
        assert!(mail_gate_cfg.gate_enabled("code"));
        mail_gate_cfg.email.enabled = true;
        assert!(mail_gate_cfg.gate_enabled("email"));

        // 6. Debug output must redact secrets
        let mut sec_cfg = valid_base_cfg();
        sec_cfg.server.server_pepper_hex = "ab".repeat(32);
        sec_cfg.email.smtp_password = "super-secret-smtp-password".to_string();
        sec_cfg.security.admin_token_hash = "$argon2id$secret-admin-hash".to_string();
        sec_cfg.security.api_bearer_token_hash = "sha256:secret-bearer-digest".to_string();
        let dbg = format!("{:?}", sec_cfg);
        assert!(!dbg.contains(&"ab".repeat(32)));
        assert!(!dbg.contains("super-secret-smtp-password"));
        assert!(!dbg.contains("secret-admin-hash"));
        assert!(!dbg.contains("secret-bearer-digest"));

        // 7. config.example.toml parses and validates cleanly
        let example_raw = include_str!("../../config.example.toml");
        let mut ex: Config = toml::from_str(example_raw).expect("parse config.example.toml");
        ex.server.admin_pubkey = "b".repeat(64);
        ex.normalize();
        ex.validate().expect("config.example.toml must validate");
    }
}
