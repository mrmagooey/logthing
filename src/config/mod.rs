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

    #[serde(default)]
    pub ipfix: IpfixConfig,
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

    /// Optional S3 persistence for syslog messages.
    /// Absent from TOML → `None` → no S3 persistence (backward compatible).
    #[serde(default)]
    pub s3: Option<SyslogS3Config>,
}

/// Per-source S3 persistence config for the syslog listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyslogS3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    /// S3 key prefix, e.g. `"syslog/"`.
    #[serde(default = "default_syslog_s3_key_prefix")]
    pub key_prefix: String,
    /// Flush when row count reaches this threshold (default 10 000).
    #[serde(default = "default_syslog_s3_max_rows")]
    pub max_buffer_rows: usize,
    /// Flush after this many seconds regardless of row count (default 900 = 15 min).
    #[serde(default = "default_syslog_s3_flush_interval_secs")]
    pub flush_interval_secs: u64,
}

fn default_syslog_s3_key_prefix() -> String {
    "syslog/".to_string()
}
fn default_syslog_s3_max_rows() -> usize {
    10_000
}
fn default_syslog_s3_flush_interval_secs() -> u64 {
    900
}

impl SyslogS3Config {
    /// Convert to `ParquetS3Config` so we can construct an `S3Sink` via Phase-2 API.
    pub fn to_parquet_s3_config(&self) -> crate::forwarding::parquet_s3::ParquetS3Config {
        crate::forwarding::parquet_s3::ParquetS3Config {
            endpoint: self.endpoint.clone(),
            bucket: self.bucket.clone(),
            region: self.region.clone(),
            access_key: self.access_key.clone(),
            secret_key: self.secret_key.clone(),
            max_file_size_mb: 0, // unused by S3Sink directly
            flush_interval_secs: self.flush_interval_secs,
            local_buffer_path: std::path::PathBuf::new(), // unused by S3Sink directly
        }
    }
}

/// Configuration for the IPFIX / NetFlow UDP listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpfixConfig {
    #[serde(default = "default_ipfix_enabled")]
    pub enabled: bool,

    #[serde(default = "default_ipfix_udp_port")]
    pub udp_port: u16,

    #[serde(default = "default_ipfix_bind_address")]
    pub bind_address: String,

    /// Optional S3 persistence for IPFIX flows.
    /// Absent from TOML → `None` → no S3 persistence (backward compatible).
    #[serde(default)]
    pub s3: Option<crate::forwarding::ipfix_s3::IpfixS3Config>,
}

impl Default for IpfixConfig {
    fn default() -> Self {
        Self {
            enabled: default_ipfix_enabled(),
            udp_port: default_ipfix_udp_port(),
            bind_address: default_ipfix_bind_address(),
            s3: None,
        }
    }
}

fn default_ipfix_enabled() -> bool {
    false
}
fn default_ipfix_udp_port() -> u16 {
    4739
}
fn default_ipfix_bind_address() -> String {
    "0.0.0.0".to_string()
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: default_syslog_enabled(),
            udp_port: default_syslog_udp_port(),
            tcp_port: default_syslog_tcp_port(),
            parse_dns: default_syslog_parse_dns(),
            s3: None, // backward-compatible default
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
            ipfix: IpfixConfig::default(),
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
    fn syslog_s3_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.syslog.s3.is_none(),
            "absent [syslog.s3] must deserialize to None"
        );
    }

    #[test]
    fn syslog_s3_present_parses_correctly() {
        let toml_str = r#"
[syslog.s3]
endpoint   = "http://minio:9000"
bucket     = "syslog-bucket"
region     = "us-east-1"
access_key = "KEY"
secret_key = "SECRET"
key_prefix = "syslog/"
max_buffer_rows = 5000
flush_interval_secs = 300
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse config");
        let s3 = cfg.syslog.s3.expect("s3 config present");
        assert_eq!(s3.bucket, "syslog-bucket");
        assert_eq!(s3.key_prefix, "syslog/");
        assert_eq!(s3.max_buffer_rows, 5000);
        assert_eq!(s3.flush_interval_secs, 300);
    }

    #[test]
    fn syslog_s3_defaults_apply_when_sub_keys_absent() {
        let toml_str = r#"
[syslog.s3]
endpoint   = "http://minio:9000"
bucket     = "syslog-bucket"
region     = "us-east-1"
access_key = "KEY"
secret_key = "SECRET"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        let s3 = cfg.syslog.s3.expect("present");
        assert_eq!(s3.key_prefix, "syslog/");
        assert_eq!(s3.max_buffer_rows, 10_000);
        assert_eq!(s3.flush_interval_secs, 900);
    }

    #[test]
    fn default_ipfix_config_disabled_on_port_4739() {
        let cfg = Config::default();
        assert!(!cfg.ipfix.enabled, "ipfix disabled by default");
        assert_eq!(cfg.ipfix.udp_port, 4739);
        assert_eq!(cfg.ipfix.bind_address, "0.0.0.0");
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

    #[test]
    fn ipfix_config_defaults() {
        let cfg = Config::default();
        assert!(!cfg.ipfix.enabled);
        assert_eq!(cfg.ipfix.udp_port, 4739);
        assert_eq!(cfg.ipfix.bind_address, "0.0.0.0");
        assert!(cfg.ipfix.s3.is_none(), "absent [ipfix.s3] must be None");
    }

    #[test]
    fn ipfix_disabled_by_default() {
        let cfg = Config::default();
        assert!(!cfg.ipfix.enabled, "IPFIX must be opt-in");
    }

    #[test]
    fn ipfix_s3_config_deserializes_from_toml() {
        let toml_str = r#"
[ipfix]
enabled = true
udp_port = 4739
[ipfix.s3]
endpoint = "http://minio:9000"
bucket = "ipfix-flows"
region = "us-east-1"
access_key = "key"
secret_key = "secret"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(cfg.ipfix.enabled);
        let s3 = cfg.ipfix.s3.expect("s3 present");
        assert_eq!(s3.bucket, "ipfix-flows");
        assert_eq!(s3.prefix, "ipfix"); // default
        assert_eq!(s3.flush_interval_secs, 900); // default
    }

    #[test]
    fn ipfix_s3_absent_means_no_persistence() {
        let toml_str = "[ipfix]\nenabled = true\n";
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(
            cfg.ipfix.s3.is_none(),
            "absent [ipfix.s3] must yield None for backward compat"
        );
    }
}
