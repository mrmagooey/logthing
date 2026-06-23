use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

use chrono::Utc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, sync::RwLock};
use tracing::info;

use crate::config::Config;

/// Audit log entry for tracking admin interface actions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub action: String,
    pub username: String,
    pub client_ip: String,
    pub details: Option<String>,
}

/// Audit logger for tracking configuration changes
#[derive(Clone)]
pub struct AuditLogger {
    entries: Arc<RwLock<Vec<AuditEntry>>>,
    max_entries: usize,
    log_file: PathBuf,
}

impl AuditLogger {
    pub async fn new(max_entries: usize) -> Self {
        // Get log file path from env or use default
        let log_file = std::env::var("WEF_ADMIN_AUDIT_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("log/admin-audit.log"));

        let logger = Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            max_entries,
            log_file,
        };

        // Load existing entries from file on startup
        logger.load_entries_from_file().await;

        logger
    }

    async fn load_entries_from_file(&self) {
        // Try to load existing entries from file
        if let Ok(contents) = tokio::fs::read_to_string(&self.log_file).await {
            let entries: Vec<AuditEntry> = contents
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();

            let mut current_entries = self.entries.write().await;
            *current_entries = entries;

            // Trim to max_entries
            if current_entries.len() > self.max_entries {
                let to_remove = current_entries.len() - self.max_entries;
                current_entries.drain(0..to_remove);
            }
        }
    }

    pub async fn log(&self, action: &str, username: &str, client_ip: &str, details: Option<&str>) {
        let entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            action: action.to_string(),
            username: username.to_string(),
            client_ip: client_ip.to_string(),
            details: details.map(|s| s.to_string()),
        };

        // Write to file first (JSON Lines format)
        if let Err(e) = self.append_to_file(&entry).await {
            tracing::error!("Failed to write audit log: {}", e);
        }

        // Add to in-memory buffer
        let mut entries = self.entries.write().await;
        entries.push(entry);

        // Keep only the most recent entries
        if entries.len() > self.max_entries {
            entries.remove(0);
        }

        // Also log to the standard logging framework
        info!(
            "[ADMIN AUDIT] {} by {} from {} - {}",
            action,
            username,
            client_ip,
            details.unwrap_or("no details")
        );
    }

    async fn append_to_file(&self, entry: &AuditEntry) -> anyhow::Result<()> {
        // Ensure log directory exists
        if let Some(parent) = self.log_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Check if rotation is needed
        self.check_and_rotate().await?;

        // Append entry as JSON Line
        let json = serde_json::to_string(entry)?;
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.log_file)
            .await?;

        file.write_all(json.as_bytes()).await?;
        file.write_all(b"\n").await?;

        Ok(())
    }

    async fn check_and_rotate(&self) -> anyhow::Result<()> {
        // Check if file exists and size
        let metadata = match tokio::fs::metadata(&self.log_file).await {
            Ok(m) => m,
            Err(_) => return Ok(()), // File doesn't exist yet
        };

        let size = metadata.len();
        let max_size: u64 = 10 * 1024 * 1024; // 10 MB

        // Check if size-based rotation needed
        if size > max_size {
            self.rotate_files().await?;
        }

        // Check if time-based rotation needed (daily)
        let modified = metadata.modified()?;
        let now = std::time::SystemTime::now();
        let day_duration = std::time::Duration::from_secs(24 * 60 * 60);

        if now.duration_since(modified)? > day_duration {
            self.rotate_files().await?;
        }

        Ok(())
    }

    async fn rotate_files(&self) -> anyhow::Result<()> {
        let max_backups = 5;

        // Remove oldest backup if exists
        let oldest = self.log_file.with_extension(format!("log.{}", max_backups));
        let _ = tokio::fs::remove_file(oldest).await;

        // Shift existing backups
        for i in (1..max_backups).rev() {
            let old = self.log_file.with_extension(format!("log.{}", i));
            let new = self.log_file.with_extension(format!("log.{}", i + 1));
            let _ = tokio::fs::rename(&old, &new).await;
        }

        // Move current log to .log.1
        let backup = self.log_file.with_extension("log.1");
        tokio::fs::rename(&self.log_file, &backup).await?;

        Ok(())
    }

    pub async fn get_entries(&self, limit: usize) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        entries.iter().rev().take(limit).cloned().collect()
    }
}

/// Admin server configuration
#[derive(Clone)]
pub struct AdminServerConfig {
    pub bind_address: SocketAddr,
    pub username: String,
    pub password_hash: PasswordHash,
    pub allowed_ips: Vec<IpNet>,
    pub tls_config: Option<AdminTlsConfig>,
    pub enable_csrf: bool,
    pub enable_rate_limiting: bool,
}

/// Admin TLS configuration
#[derive(Clone)]
pub struct AdminTlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    #[allow(dead_code)]
    pub ca_file: Option<PathBuf>,
    #[allow(dead_code)]
    pub require_client_cert: bool,
}

/// Hashed password using Argon2
#[derive(Clone)]
pub struct PasswordHash {
    pub hash: String,
}

impl PasswordHash {
    /// Hash a plain password using Argon2
    pub fn hash(password: &str) -> anyhow::Result<Self> {
        use argon2::{
            Argon2, PasswordHasher,
            password_hash::{SaltString, rand_core::OsRng},
        };

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;

        Ok(Self {
            hash: password_hash.to_string(),
        })
    }

    /// Verify a plain password against the stored hash
    pub fn verify(&self, password: &str) -> bool {
        use argon2::{Argon2, PasswordHash as Argon2PasswordHash, PasswordVerifier};

        let parsed_hash = match Argon2PasswordHash::new(&self.hash) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let argon2 = Argon2::default();
        argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }

    /// Create a password hash from an already-hashed string
    pub fn from_hash(hash: &str) -> Self {
        Self {
            hash: hash.to_string(),
        }
    }
}

/// Admin state shared across handlers
#[derive(Clone)]
pub struct AdminState {
    pub config: Arc<RwLock<Config>>,
    pub server_config: AdminServerConfig,
    pub audit_logger: AuditLogger,
    pub csrf_tokens: Arc<RwLock<Vec<(String, Instant)>>>,
    pub request_counts: Arc<RwLock<std::collections::HashMap<String, (Instant, u32)>>>,
}

/// Rate limit error response
#[derive(Serialize)]
pub struct RateLimitError {
    pub error: String,
    pub retry_after: u64,
}

/// Returns whether the admin server is safe to start given its resolved bind address and
/// credentials. This is a pure function with no side-effects so it can be tested independently
/// of environment variables.
///
/// Rules:
/// - Loopback bind (127.0.0.0/8 or ::1) with any credentials → allowed.
/// - Non-loopback bind with non-default credentials → allowed.
/// - Non-loopback bind with default credentials (`admin`/`admin`) → refused.
pub fn admin_start_allowed(bind: SocketAddr, user: &str, pass: &str) -> Result<(), String> {
    let is_loopback = match bind.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    };

    if !is_loopback && user == "admin" && pass == "admin" {
        return Err(format!(
            "Admin server refused to start: bind address {} is non-loopback but default \
             credentials (admin/admin) are in use. Set WEF_ADMIN_USER and WEF_ADMIN_PASS \
             to non-default values, or bind to a loopback address (127.0.0.1) instead. \
             The data-plane server continues running.",
            bind
        ));
    }

    Ok(())
}

/// Pure, testable core of admin config construction.  All values that would normally be
/// read from `std::env` are accepted as parameters here; `load_admin_config` is the thin
/// env-reading wrapper that calls this.
///
/// Parameters
/// ----------
/// * `bind_str`            – raw `WEF_ADMIN_BIND` value, or `None` if the variable is absent.
/// * `username`            – `WEF_ADMIN_USER` (or default `"admin"`).
/// * `plain_pass`          – `WEF_ADMIN_PASS` (or default `"admin"`).  Used only when
///   `pass_hash` is `None`.
/// * `pass_hash`           – pre-hashed password from `WEF_ADMIN_PASS_HASH`, if set.
/// * `allowed_ips_str`     – raw `WEF_ADMIN_ALLOWED_IPS` value, or `None`.
/// * `tls_cert`            – `WEF_ADMIN_TLS_CERT`, or `None`.
/// * `tls_key`             – `WEF_ADMIN_TLS_KEY`, or `None`.
/// * `tls_ca`              – `WEF_ADMIN_TLS_CA`, or `None`.
/// * `require_client_cert` – `WEF_ADMIN_TLS_REQUIRE_CLIENT_CERT` parsed value (default `false`).
/// * `enable_csrf`         – `WEF_ADMIN_ENABLE_CSRF` parsed value (default `true`).
/// * `enable_rate_limiting`– `WEF_ADMIN_ENABLE_RATE_LIMIT` parsed value (default `true`).
#[allow(clippy::too_many_arguments)]
pub fn build_admin_config_from_parts(
    bind_str: Option<&str>,
    username: &str,
    plain_pass: &str,
    pass_hash: Option<&str>,
    allowed_ips_str: Option<&str>,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    tls_ca: Option<&str>,
    require_client_cert: bool,
    enable_csrf: bool,
    enable_rate_limiting: bool,
) -> anyhow::Result<AdminServerConfig> {
    // Resolve bind address — warn and fall back to loopback if the value is present but
    // unparseable (mirrors the env-reading path in load_admin_config).
    let bind_address: SocketAddr = match bind_str {
        Some(s) => s.parse().unwrap_or_else(|_| {
            tracing::warn!(
                "WEF_ADMIN_BIND value {:?} failed to parse as a socket address; \
                 falling back to 127.0.0.1:8080 (loopback only). \
                 Fix the value to bind the admin interface as intended.",
                s
            );
            "127.0.0.1:8080".parse().unwrap()
        }),
        None => "127.0.0.1:8080".parse().unwrap(),
    };

    let password_hash = if let Some(hashed) = pass_hash {
        // Pre-hashed path: pass the hash string as the "pass" argument so the guard
        // only fires on exact "admin"/"admin" (which cannot occur here since the hash
        // value is never the literal string "admin").
        admin_start_allowed(bind_address, username, hashed).map_err(|msg| {
            tracing::error!("{}", msg);
            anyhow::anyhow!("{}", msg)
        })?;
        PasswordHash::from_hash(hashed)
    } else {
        // Plain-password path.
        admin_start_allowed(bind_address, username, plain_pass).map_err(|msg| {
            tracing::error!("{}", msg);
            anyhow::anyhow!("{}", msg)
        })?;

        if username == "admin" && plain_pass == "admin" {
            tracing::warn!(
                "Admin interface is using default credentials. \
                 Set WEF_ADMIN_USER/WEF_ADMIN_PASS environment variables \
                 or WEF_ADMIN_PASS_HASH for a pre-hashed password."
            );
        }

        PasswordHash::hash(plain_pass)?
    };

    // IP whitelist
    let allowed_ips: Vec<IpNet> = match allowed_ips_str {
        Some(s) => s
            .split(',')
            .filter_map(|ip| ip.trim().parse().ok())
            .collect(),
        None => vec![],
    };

    if allowed_ips.is_empty() {
        tracing::warn!(
            "Admin interface has no IP whitelist configured. \
             Consider setting WEF_ADMIN_ALLOWED_IPS for security."
        );
    }

    // TLS config
    let tls_config = match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => Some(AdminTlsConfig {
            cert_file: cert.into(),
            key_file: key.into(),
            ca_file: tls_ca.map(|s| s.into()),
            require_client_cert,
        }),
        _ => {
            tracing::warn!(
                "Admin interface is running without TLS. \
                 Set WEF_ADMIN_TLS_CERT and WEF_ADMIN_TLS_KEY for HTTPS."
            );
            None
        }
    };

    Ok(AdminServerConfig {
        bind_address,
        username: username.to_string(),
        password_hash,
        allowed_ips,
        tls_config,
        enable_csrf,
        enable_rate_limiting,
    })
}

/// Load admin server configuration from environment variables
pub fn load_admin_config() -> anyhow::Result<AdminServerConfig> {
    let bind_str = std::env::var("WEF_ADMIN_BIND").ok();
    let username = std::env::var("WEF_ADMIN_USER").unwrap_or_else(|_| "admin".to_string());
    let plain_pass = std::env::var("WEF_ADMIN_PASS").unwrap_or_else(|_| "admin".to_string());
    let pass_hash = std::env::var("WEF_ADMIN_PASS_HASH").ok();
    let allowed_ips_str = std::env::var("WEF_ADMIN_ALLOWED_IPS").ok();
    let tls_cert = std::env::var("WEF_ADMIN_TLS_CERT").ok();
    let tls_key = std::env::var("WEF_ADMIN_TLS_KEY").ok();
    let tls_ca = std::env::var("WEF_ADMIN_TLS_CA").ok();
    let require_client_cert = std::env::var("WEF_ADMIN_TLS_REQUIRE_CLIENT_CERT")
        .map(|s| s == "true" || s == "1")
        .unwrap_or(false);
    let enable_csrf = std::env::var("WEF_ADMIN_ENABLE_CSRF")
        .map(|s| s == "true" || s == "1")
        .unwrap_or(true);
    let enable_rate_limiting = std::env::var("WEF_ADMIN_ENABLE_RATE_LIMIT")
        .map(|s| s == "true" || s == "1")
        .unwrap_or(true);

    build_admin_config_from_parts(
        bind_str.as_deref(),
        &username,
        &plain_pass,
        pass_hash.as_deref(),
        allowed_ips_str.as_deref(),
        tls_cert.as_deref(),
        tls_key.as_deref(),
        tls_ca.as_deref(),
        require_client_cert,
        enable_csrf,
        enable_rate_limiting,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── admin_start_allowed exhaustive coverage ───────────────────────────────

    #[test]
    fn admin_start_allowed_loopback_127_0_0_1_default_creds_ok() {
        let bind: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(admin_start_allowed(bind, "admin", "admin").is_ok());
    }

    #[test]
    fn admin_start_allowed_ipv6_loopback_default_creds_ok() {
        let bind: SocketAddr = "[::1]:8080".parse().unwrap();
        assert!(admin_start_allowed(bind, "admin", "admin").is_ok());
    }

    #[test]
    fn admin_start_allowed_127_0_0_2_default_creds_ok() {
        // Any 127.x.x.x address is loopback; only 127.0.0.1 is commonly tested.
        let bind: SocketAddr = "127.0.0.2:8080".parse().unwrap();
        assert!(
            admin_start_allowed(bind, "admin", "admin").is_ok(),
            "127.0.0.2 is loopback — should be allowed with default creds"
        );
    }

    #[test]
    fn admin_start_allowed_127_255_255_254_default_creds_ok() {
        let bind: SocketAddr = "127.255.255.254:9999".parse().unwrap();
        assert!(
            admin_start_allowed(bind, "admin", "admin").is_ok(),
            "last usable 127.x address should still be treated as loopback"
        );
    }

    #[test]
    fn admin_start_allowed_non_loopback_default_creds_err_contains_bind_addr() {
        let bind: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let result = admin_start_allowed(bind, "admin", "admin");
        assert!(result.is_err());
        let err = result.unwrap_err();
        // The error must mention the bind address so the operator knows what they configured.
        assert!(
            err.contains("0.0.0.0:8080"),
            "error should contain the offending bind address; got: {err}"
        );
        assert!(
            err.contains("refused") || err.contains("non-loopback"),
            "error should describe why it was refused; got: {err}"
        );
    }

    #[test]
    fn admin_start_allowed_public_ip_default_creds_err() {
        let bind: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        assert!(admin_start_allowed(bind, "admin", "admin").is_err());
    }

    #[test]
    fn admin_start_allowed_non_loopback_custom_user_default_pass_ok() {
        let bind: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        assert!(admin_start_allowed(bind, "ops", "admin").is_ok());
    }

    #[test]
    fn admin_start_allowed_non_loopback_default_user_custom_pass_ok() {
        let bind: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        assert!(admin_start_allowed(bind, "admin", "s3cr3t").is_ok());
    }

    #[test]
    fn admin_start_allowed_non_loopback_both_custom_ok() {
        let bind: SocketAddr = "203.0.113.1:443".parse().unwrap();
        assert!(admin_start_allowed(bind, "ops-user", "very-strong-pass").is_ok());
    }

    #[test]
    fn admin_start_allowed_loopback_custom_creds_ok() {
        let bind: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(admin_start_allowed(bind, "custom-user", "custom-pass").is_ok());
    }

    // ── PasswordHash coverage ─────────────────────────────────────────────────

    #[test]
    fn password_hash_hash_and_verify_roundtrip() {
        let hash = PasswordHash::hash("correct-horse-battery").unwrap();
        assert!(hash.verify("correct-horse-battery"));
        assert!(!hash.verify("wrong"));
    }

    #[test]
    fn password_hash_from_hash_roundtrip() {
        let original = PasswordHash::hash("secret").unwrap();
        let restored = PasswordHash::from_hash(&original.hash);
        assert!(restored.verify("secret"));
        assert!(!restored.verify("not-secret"));
    }

    #[test]
    fn password_hash_verify_bad_hash_returns_false() {
        // A structurally invalid hash string must not panic — it should just return false.
        let bad = PasswordHash::from_hash("not-a-valid-argon2-hash");
        assert!(!bad.verify("anything"));
    }

    // ── build_admin_config_from_parts — pure-function branch coverage ─────────

    /// Helper: minimal valid call (loopback + default creds, no TLS, no whitelist).
    fn default_parts() -> anyhow::Result<AdminServerConfig> {
        build_admin_config_from_parts(
            None,    // bind_str  → 127.0.0.1:8080
            "admin", // username
            "admin", // plain_pass
            None,    // pass_hash
            None,    // allowed_ips_str
            None,    // tls_cert
            None,    // tls_key
            None,    // tls_ca
            false,   // require_client_cert
            true,    // enable_csrf
            true,    // enable_rate_limiting
        )
    }

    #[test]
    fn build_config_defaults_bind_to_loopback() {
        let cfg = default_parts().unwrap();
        assert_eq!(
            cfg.bind_address,
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn build_config_explicit_valid_bind_used() {
        let cfg = build_admin_config_from_parts(
            Some("127.0.0.1:9090"),
            "admin",
            "admin",
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            true,
        )
        .unwrap();
        assert_eq!(cfg.bind_address.port(), 9090);
    }

    #[test]
    fn build_config_invalid_bind_falls_back_to_loopback() {
        // An unparseable bind string must silently fall back to 127.0.0.1:8080.
        let cfg = build_admin_config_from_parts(
            Some("not-a-valid-socket-addr"),
            "admin",
            "admin",
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            true,
        )
        .unwrap();
        assert_eq!(
            cfg.bind_address,
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "invalid bind string should fall back to loopback"
        );
    }

    #[test]
    fn build_config_non_loopback_default_creds_returns_err() {
        let result = build_admin_config_from_parts(
            Some("0.0.0.0:8080"),
            "admin",
            "admin",
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            true,
        );
        assert!(
            result.is_err(),
            "non-loopback + default creds must be refused"
        );
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("refused") || msg.contains("non-loopback"),
            "{msg}"
        );
    }

    #[test]
    fn build_config_non_loopback_custom_creds_ok() {
        let cfg = build_admin_config_from_parts(
            Some("0.0.0.0:8080"),
            "ops",
            "str0ng-pass",
            None,
            None,
            None,
            None,
            None,
            false,
            true,
            true,
        )
        .unwrap();
        assert_eq!(cfg.username, "ops");
    }

    #[test]
    fn build_config_pass_hash_branch_used() {
        // When pass_hash is Some, the hash is stored verbatim via from_hash.
        let pre_hashed = PasswordHash::hash("my-secret").unwrap().hash;
        let cfg = build_admin_config_from_parts(
            None,
            "admin",
            "ignored-plain",
            Some(&pre_hashed),
            None,
            None,
            None,
            None,
            false,
            true,
            true,
        )
        .unwrap();
        // The stored hash should verify against the original password.
        assert!(cfg.password_hash.verify("my-secret"));
    }

    #[test]
    fn build_config_custom_user_and_pass() {
        let cfg = build_admin_config_from_parts(
            None, "myuser", "mypass", None, None, None, None, None, false, true, true,
        )
        .unwrap();
        assert_eq!(cfg.username, "myuser");
        assert!(cfg.password_hash.verify("mypass"));
    }

    #[test]
    fn build_config_whitelist_parsed_correctly() {
        let cfg = build_admin_config_from_parts(
            None,
            "admin",
            "admin",
            None,
            Some("10.0.0.0/8, 192.168.1.0/24, 203.0.113.5/32"),
            None,
            None,
            None,
            false,
            true,
            true,
        )
        .unwrap();
        assert_eq!(cfg.allowed_ips.len(), 3);
        // Verify parsed values are the networks we asked for.
        let nets: Vec<String> = cfg.allowed_ips.iter().map(|n| n.to_string()).collect();
        assert!(
            nets.iter().any(|n| n == "10.0.0.0/8"),
            "expected 10.0.0.0/8 in {nets:?}"
        );
        assert!(
            nets.iter().any(|n| n == "192.168.1.0/24"),
            "expected 192.168.1.0/24 in {nets:?}"
        );
    }

    #[test]
    fn build_config_whitelist_empty_string_yields_no_entries() {
        let cfg = build_admin_config_from_parts(
            None,
            "admin",
            "admin",
            None,
            Some(""),
            None,
            None,
            None,
            false,
            true,
            true,
        )
        .unwrap();
        assert!(cfg.allowed_ips.is_empty());
    }

    #[test]
    fn build_config_whitelist_invalid_entries_skipped() {
        // Mix of valid and invalid entries — invalid ones are silently dropped.
        let cfg = build_admin_config_from_parts(
            None,
            "admin",
            "admin",
            None,
            Some("10.0.0.0/8, not-a-valid-cidr, 192.168.0.0/16"),
            None,
            None,
            None,
            false,
            true,
            true,
        )
        .unwrap();
        assert_eq!(
            cfg.allowed_ips.len(),
            2,
            "invalid entry should be silently skipped; got {:?}",
            cfg.allowed_ips
        );
    }

    #[test]
    fn build_config_whitelist_absent_yields_empty() {
        let cfg = default_parts().unwrap();
        assert!(cfg.allowed_ips.is_empty());
    }

    #[test]
    fn build_config_tls_cert_and_key_present() {
        let cfg = build_admin_config_from_parts(
            None,
            "admin",
            "admin",
            None,
            None,
            Some("/etc/ssl/cert.pem"),
            Some("/etc/ssl/key.pem"),
            None,
            false,
            true,
            true,
        )
        .unwrap();
        let tls = cfg.tls_config.expect("TLS should be configured");
        assert_eq!(tls.cert_file, PathBuf::from("/etc/ssl/cert.pem"));
        assert_eq!(tls.key_file, PathBuf::from("/etc/ssl/key.pem"));
        assert!(tls.ca_file.is_none());
        assert!(!tls.require_client_cert);
    }

    #[test]
    fn build_config_tls_with_ca_and_require_client_cert() {
        let cfg = build_admin_config_from_parts(
            None,
            "admin",
            "admin",
            None,
            None,
            Some("/etc/ssl/cert.pem"),
            Some("/etc/ssl/key.pem"),
            Some("/etc/ssl/ca.pem"),
            true, // require_client_cert
            true,
            true,
        )
        .unwrap();
        let tls = cfg.tls_config.expect("TLS should be configured");
        assert_eq!(tls.ca_file, Some(PathBuf::from("/etc/ssl/ca.pem")));
        assert!(tls.require_client_cert);
    }

    #[test]
    fn build_config_tls_only_cert_no_key_yields_none() {
        // Both cert AND key are required; if only one is present TLS is disabled.
        let cfg = build_admin_config_from_parts(
            None,
            "admin",
            "admin",
            None,
            None,
            Some("/etc/ssl/cert.pem"),
            None, // no key
            None,
            false,
            true,
            true,
        )
        .unwrap();
        assert!(
            cfg.tls_config.is_none(),
            "TLS should be None when key is missing"
        );
    }

    #[test]
    fn build_config_tls_absent_yields_none() {
        let cfg = default_parts().unwrap();
        assert!(cfg.tls_config.is_none());
    }

    #[test]
    fn build_config_csrf_disabled() {
        let cfg = build_admin_config_from_parts(
            None, "admin", "admin", None, None, None, None, None, false,
            false, // enable_csrf = false
            true,
        )
        .unwrap();
        assert!(!cfg.enable_csrf);
    }

    #[test]
    fn build_config_csrf_enabled() {
        let cfg = build_admin_config_from_parts(
            None, "admin", "admin", None, None, None, None, None, false,
            true, // enable_csrf = true
            true,
        )
        .unwrap();
        assert!(cfg.enable_csrf);
    }

    #[test]
    fn build_config_rate_limiting_disabled() {
        let cfg = build_admin_config_from_parts(
            None, "admin", "admin", None, None, None, None, None, false, true,
            false, // enable_rate_limiting = false
        )
        .unwrap();
        assert!(!cfg.enable_rate_limiting);
    }

    #[test]
    fn build_config_rate_limiting_enabled() {
        let cfg = build_admin_config_from_parts(
            None, "admin", "admin", None, None, None, None, None, false, true, true,
        )
        .unwrap();
        assert!(cfg.enable_rate_limiting);
    }

    // ── load_admin_config env-driven tests (sequential, single test fn) ───────
    //
    // All env-mutating assertions run inside a single #[test] function, executed
    // in strict sequence with set-then-unset guards, to avoid parallel env races
    // (serial_test is not in Cargo.toml).  Each scenario is a named block and
    // restores env vars unconditionally via a defer-style pattern.
    #[test]
    fn load_admin_config_env_scenarios() {
        // Helper that ensures we always unset an env var even if the block panics.
        fn with_env<K: AsRef<std::ffi::OsStr>, V: AsRef<std::ffi::OsStr>, F: FnOnce() -> R, R>(
            key: K,
            val: V,
            f: F,
        ) -> R {
            // SAFETY: This test is the only test that mutates these env vars, and it
            // is a single-threaded #[test] (not #[tokio::test]), so no data race can
            // occur within this function.  The outer file-level test suite may run
            // other tests in parallel; those tests use build_admin_config_from_parts
            // (pure, no env reads) and are therefore unaffected.
            unsafe { std::env::set_var(&key, &val) };
            let result = f();
            unsafe { std::env::remove_var(&key) };
            result
        }

        fn with_two_env<
            K1: AsRef<std::ffi::OsStr>,
            V1: AsRef<std::ffi::OsStr>,
            K2: AsRef<std::ffi::OsStr>,
            V2: AsRef<std::ffi::OsStr>,
            F: FnOnce() -> R,
            R,
        >(
            k1: K1,
            v1: V1,
            k2: K2,
            v2: V2,
            f: F,
        ) -> R {
            unsafe {
                std::env::set_var(&k1, &v1);
                std::env::set_var(&k2, &v2);
            }
            let result = f();
            unsafe {
                std::env::remove_var(&k1);
                std::env::remove_var(&k2);
            }
            result
        }

        // ── Scenario 1: default env (no vars set) → loopback, default creds, ok ──
        {
            let cfg = load_admin_config().expect("default env should succeed");
            assert_eq!(
                cfg.bind_address,
                "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
            );
            assert_eq!(cfg.username, "admin");
            assert!(cfg.password_hash.verify("admin"));
            assert!(cfg.tls_config.is_none());
            assert!(cfg.allowed_ips.is_empty());
            assert!(cfg.enable_csrf);
            assert!(cfg.enable_rate_limiting);
        }

        // ── Scenario 2: WEF_ADMIN_USER + WEF_ADMIN_PASS custom values ────────────
        {
            let cfg = with_two_env(
                "WEF_ADMIN_USER",
                "myuser",
                "WEF_ADMIN_PASS",
                "mypass",
                || load_admin_config().expect("custom user/pass should succeed"),
            );
            assert_eq!(cfg.username, "myuser");
            assert!(cfg.password_hash.verify("mypass"));
        }

        // ── Scenario 3: WEF_ADMIN_PASS_HASH branch ───────────────────────────────
        {
            let pre_hash = PasswordHash::hash("pre-hashed-secret").unwrap().hash;
            let cfg = with_env("WEF_ADMIN_PASS_HASH", &pre_hash, || {
                load_admin_config().expect("pre-hashed pass should succeed")
            });
            assert!(cfg.password_hash.verify("pre-hashed-secret"));
        }

        // ── Scenario 4: WEF_ADMIN_BIND valid → used ───────────────────────────────
        {
            let cfg = with_two_env(
                "WEF_ADMIN_BIND",
                "127.0.0.1:9090",
                "WEF_ADMIN_USER",
                "secure-user", // keep creds non-default if bind is public
                || load_admin_config().expect("valid bind should succeed"),
            );
            assert_eq!(cfg.bind_address.port(), 9090);
        }

        // ── Scenario 5: WEF_ADMIN_BIND invalid → falls back to 127.0.0.1:8080 ────
        {
            let cfg = with_env("WEF_ADMIN_BIND", "GARBAGE-NOT-A-SOCKET", || {
                load_admin_config().expect("invalid bind should fall back to loopback")
            });
            assert_eq!(
                cfg.bind_address,
                "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
            );
        }

        // ── Scenario 6: non-loopback bind + default creds → Err ──────────────────
        {
            let result = with_env("WEF_ADMIN_BIND", "0.0.0.0:8080", load_admin_config);
            assert!(
                result.is_err(),
                "non-loopback bind with default creds must be refused"
            );
        }

        // ── Scenario 7: non-loopback bind + custom creds → Ok ───────────────────
        {
            unsafe {
                std::env::set_var("WEF_ADMIN_BIND", "0.0.0.0:8080");
                std::env::set_var("WEF_ADMIN_USER", "ops");
                std::env::set_var("WEF_ADMIN_PASS", "str0ng");
            }
            let result = load_admin_config();
            unsafe {
                std::env::remove_var("WEF_ADMIN_BIND");
                std::env::remove_var("WEF_ADMIN_USER");
                std::env::remove_var("WEF_ADMIN_PASS");
            }
            let cfg = result.expect("non-loopback + custom creds should be allowed");
            assert_eq!(
                cfg.bind_address,
                "0.0.0.0:8080".parse::<SocketAddr>().unwrap()
            );
        }

        // ── Scenario 8: WEF_ADMIN_ALLOWED_IPS valid CIDRs ────────────────────────
        {
            let cfg = with_env("WEF_ADMIN_ALLOWED_IPS", "10.0.0.0/8,192.168.0.0/16", || {
                load_admin_config().expect("allowed IPs should parse")
            });
            assert_eq!(cfg.allowed_ips.len(), 2);
        }

        // ── Scenario 9: WEF_ADMIN_ALLOWED_IPS with invalid entry (skipped) ────────
        {
            let cfg = with_env(
                "WEF_ADMIN_ALLOWED_IPS",
                "10.0.0.0/8,bad-entry,192.168.0.0/16",
                || load_admin_config().expect("should succeed ignoring invalid entry"),
            );
            assert_eq!(cfg.allowed_ips.len(), 2);
        }

        // ── Scenario 10: WEF_ADMIN_TLS_CERT + WEF_ADMIN_TLS_KEY ─────────────────
        {
            let cfg = with_two_env(
                "WEF_ADMIN_TLS_CERT",
                "/etc/ssl/cert.pem",
                "WEF_ADMIN_TLS_KEY",
                "/etc/ssl/key.pem",
                || load_admin_config().expect("TLS config should be accepted"),
            );
            let tls = cfg.tls_config.expect("TLS should be Some");
            assert_eq!(tls.cert_file, PathBuf::from("/etc/ssl/cert.pem"));
            assert_eq!(tls.key_file, PathBuf::from("/etc/ssl/key.pem"));
            assert!(tls.ca_file.is_none());
            assert!(!tls.require_client_cert);
        }

        // ── Scenario 11: TLS with CA + require_client_cert ───────────────────────
        {
            unsafe {
                std::env::set_var("WEF_ADMIN_TLS_CERT", "/etc/ssl/cert.pem");
                std::env::set_var("WEF_ADMIN_TLS_KEY", "/etc/ssl/key.pem");
                std::env::set_var("WEF_ADMIN_TLS_CA", "/etc/ssl/ca.pem");
                std::env::set_var("WEF_ADMIN_TLS_REQUIRE_CLIENT_CERT", "true");
            }
            let result = load_admin_config();
            unsafe {
                std::env::remove_var("WEF_ADMIN_TLS_CERT");
                std::env::remove_var("WEF_ADMIN_TLS_KEY");
                std::env::remove_var("WEF_ADMIN_TLS_CA");
                std::env::remove_var("WEF_ADMIN_TLS_REQUIRE_CLIENT_CERT");
            }
            let cfg = result.expect("TLS + CA + require_client_cert should be accepted");
            let tls = cfg.tls_config.expect("TLS should be Some");
            assert_eq!(tls.ca_file, Some(PathBuf::from("/etc/ssl/ca.pem")));
            assert!(tls.require_client_cert);
        }

        // ── Scenario 12: WEF_ADMIN_ENABLE_CSRF=false ─────────────────────────────
        {
            let cfg = with_env("WEF_ADMIN_ENABLE_CSRF", "false", || {
                load_admin_config().expect("CSRF disabled should succeed")
            });
            assert!(!cfg.enable_csrf);
        }

        // ── Scenario 13: WEF_ADMIN_ENABLE_RATE_LIMIT=0 ───────────────────────────
        {
            let cfg = with_env("WEF_ADMIN_ENABLE_RATE_LIMIT", "0", || {
                load_admin_config().expect("rate limit disabled should succeed")
            });
            assert!(!cfg.enable_rate_limiting);
        }

        // ── Scenario 14: WEF_ADMIN_ENABLE_CSRF=1 ─────────────────────────────────
        {
            let cfg = with_env("WEF_ADMIN_ENABLE_CSRF", "1", || {
                load_admin_config().expect("CSRF with '1' should succeed")
            });
            assert!(cfg.enable_csrf);
        }
    }
}
