use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub const ADMIN_OVERRIDE_FILE: &str = "logthing.admin.toml";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: SocketAddr,

    #[serde(default)]
    pub tls: TlsConfig,

    #[serde(default)]
    pub security: SecurityConfig,

    #[serde(default)]
    pub forwarding: ForwardingConfig,

    #[serde(default)]
    pub logging: LoggingConfig,

    #[serde(default)]
    pub metrics: MetricsConfig,

    #[serde(default)]
    pub syslog: SyslogConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    #[serde(default = "default_tls_enabled")]
    pub enabled: bool,

    #[serde(default = "default_tls_port")]
    pub port: u16,

    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub ca_file: Option<PathBuf>,

    #[serde(default = "default_require_client_cert")]
    pub require_client_cert: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub allowed_ips: Vec<String>,

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_connection_timeout_secs")]
    pub connection_timeout_secs: u64,

    #[serde(default)]
    pub kerberos: KerberosSecurityConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ForwardingConfig {
    #[serde(default)]
    pub destinations: Vec<DestinationConfig>,

    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DestinationConfig {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub protocol: ForwardProtocol,
    #[serde(default = "default_destination_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct KerberosSecurityConfig {
    #[serde(default)]
    pub enabled: bool,
    pub spn: Option<String>,
    pub keytab: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ForwardProtocol {
    #[default]
    Http,
    Https,
    Tcp,
    Udp,
    Syslog,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,

    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Pretty,
    Json,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,

    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyslogConfig {
    #[serde(default = "default_syslog_enabled")]
    pub enabled: bool,

    #[serde(default = "default_syslog_udp_port")]
    pub udp_port: u16,

    #[serde(default = "default_syslog_tcp_port")]
    pub tcp_port: u16,

    #[serde(default = "default_syslog_parse_dns")]
    pub parse_dns: bool,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: default_syslog_enabled(),
            udp_port: default_syslog_udp_port(),
            tcp_port: default_syslog_tcp_port(),
            parse_dns: default_syslog_parse_dns(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            tls: TlsConfig::default(),
            security: SecurityConfig::default(),
            forwarding: ForwardingConfig::default(),
            logging: LoggingConfig::default(),
            metrics: MetricsConfig::default(),
            syslog: SyslogConfig::default(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: default_tls_enabled(),
            port: default_tls_port(),
            cert_file: None,
            key_file: None,
            ca_file: None,
            require_client_cert: default_require_client_cert(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allowed_ips: Vec::new(),
            max_connections: default_max_connections(),
            connection_timeout_secs: default_connection_timeout_secs(),
            kerberos: KerberosSecurityConfig::default(),
        }
    }
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            destinations: Vec::new(),
            buffer_size: default_buffer_size(),
            retry_attempts: default_retry_attempts(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: default_metrics_enabled(),
            port: default_metrics_port(),
        }
    }
}

// Default value functions
fn default_bind_address() -> SocketAddr {
    "0.0.0.0:5985".parse().unwrap()
}

fn default_tls_enabled() -> bool {
    true
}

fn default_tls_port() -> u16 {
    5986
}

fn default_require_client_cert() -> bool {
    false
}

fn default_max_connections() -> usize {
    10000
}

fn default_connection_timeout_secs() -> u64 {
    300
}

fn default_buffer_size() -> usize {
    10000
}

fn default_retry_attempts() -> u32 {
    3
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_metrics_port() -> u16 {
    9090
}

fn default_destination_enabled() -> bool {
    true
}

fn default_syslog_enabled() -> bool {
    true
}

fn default_syslog_udp_port() -> u16 {
    514
}

fn default_syslog_tcp_port() -> u16 {
    601
}

fn default_syslog_parse_dns() -> bool {
    true
}

impl Config {
    /// Load configuration from files and environment variables.
    ///
    /// Configuration is loaded from the following sources (in order of precedence):
    /// 1. Default values
    /// 2. `logthing.toml` file (optional)
    /// 3. Admin override file (`logthing.admin.toml`, optional)
    /// 4. `/etc/logthing/config.toml` (optional)
    /// 5. Environment variables with `WEF__` prefix
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wef_server::config::Config;
    ///
    /// // Load configuration from default locations
    /// let config = Config::load()?;
    /// println!("Server will bind to: {}", config.bind_address);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn load() -> anyhow::Result<Self> {
        let mut builder = config::Config::builder();

        // Add default config
        builder = builder.set_default("bind_address", "0.0.0.0:5985")?;

        // Try to load from file
        builder = builder.add_source(config::File::with_name("logthing").required(false));
        builder =
            builder.add_source(config::File::from(Path::new(ADMIN_OVERRIDE_FILE)).required(false));
        builder =
            builder.add_source(config::File::with_name("/etc/logthing/config").required(false));

        // Add environment variables with prefix WEF_
        builder = builder.add_source(config::Environment::with_prefix("WEF").separator("__"));

        let config = builder.build()?;
        Ok(config.try_deserialize()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values_match_expectations() {
        let cfg = Config::default();
        assert_eq!(cfg.bind_address, "0.0.0.0:5985".parse().unwrap());
        assert!(cfg.tls.enabled);
        assert_eq!(cfg.metrics.port, 9090);
        assert!(cfg.syslog.enabled);
    }

    #[test]
    fn load_reads_configuration_file() {
        // Temporarily rename admin override file if it exists to test base config loading
        let admin_override = Path::new(ADMIN_OVERRIDE_FILE);
        let admin_override_backup = Path::new("logthing.admin.toml.bak");
        let had_override = admin_override.exists();

        if had_override {
            std::fs::rename(admin_override, admin_override_backup).expect("rename override file");
        }

        let result = std::panic::catch_unwind(|| {
            let cfg = Config::load().expect("config loads");
            assert!(!cfg.tls.enabled, "logthing.toml disables TLS");
            assert!(cfg.forwarding.destinations.len() >= 1);
        });

        // Restore admin override file
        if had_override {
            std::fs::rename(admin_override_backup, admin_override).expect("restore override file");
        }

        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }
}
