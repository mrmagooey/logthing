use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

use chrono::Utc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt,
    sync::RwLock,
};
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
    pub ca_file: Option<PathBuf>,
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
            Argon2,
            PasswordHasher,
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

/// Load admin server configuration from environment variables
pub fn load_admin_config() -> anyhow::Result<AdminServerConfig> {
    // Admin bind address (default: 0.0.0.0:8080)
    let bind_address = std::env::var("WEF_ADMIN_BIND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "0.0.0.0:8080".parse().unwrap());

    // Admin credentials
    let username = std::env::var("WEF_ADMIN_USER").unwrap_or_else(|_| "admin".to_string());
    let password_hash = if let Ok(hashed) = std::env::var("WEF_ADMIN_PASS_HASH") {
        // Use pre-hashed password
        PasswordHash::from_hash(&hashed)
    } else {
        // Hash the plain password (for backward compatibility)
        let password = std::env::var("WEF_ADMIN_PASS").unwrap_or_else(|_| "admin".to_string());

        if username == "admin" && password == "admin" {
            tracing::warn!(
                "Admin interface is using default credentials. \
                 Set WEF_ADMIN_USER/WEF_ADMIN_PASS environment variables \
                 or WEF_ADMIN_PASS_HASH for a pre-hashed password."
            );
        }

        PasswordHash::hash(&password)?
    };

    // IP whitelist for admin access
    let allowed_ips: Vec<IpNet> = std::env::var("WEF_ADMIN_ALLOWED_IPS")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|ip| ip.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default();

    if allowed_ips.is_empty() {
        tracing::warn!(
            "Admin interface has no IP whitelist configured. \
             Consider setting WEF_ADMIN_ALLOWED_IPS for security."
        );
    }

    // TLS configuration for admin interface
    let tls_config = if let (Ok(cert_file), Ok(key_file)) = (
        std::env::var("WEF_ADMIN_TLS_CERT"),
        std::env::var("WEF_ADMIN_TLS_KEY"),
    ) {
        Some(AdminTlsConfig {
            cert_file: cert_file.into(),
            key_file: key_file.into(),
            ca_file: std::env::var("WEF_ADMIN_TLS_CA").ok().map(|s| s.into()),
            require_client_cert: std::env::var("WEF_ADMIN_TLS_REQUIRE_CLIENT_CERT")
                .map(|s| s == "true" || s == "1")
                .unwrap_or(false),
        })
    } else {
        tracing::warn!(
            "Admin interface is running without TLS. \
             Set WEF_ADMIN_TLS_CERT and WEF_ADMIN_TLS_KEY for HTTPS."
        );
        None
    };

    // Security features
    let enable_csrf = std::env::var("WEF_ADMIN_ENABLE_CSRF")
        .map(|s| s == "true" || s == "1")
        .unwrap_or(true);

    let enable_rate_limiting = std::env::var("WEF_ADMIN_ENABLE_RATE_LIMIT")
        .map(|s| s == "true" || s == "1")
        .unwrap_or(true);

    Ok(AdminServerConfig {
        bind_address,
        username,
        password_hash,
        allowed_ips,
        tls_config,
        enable_csrf,
        enable_rate_limiting,
    })
}
