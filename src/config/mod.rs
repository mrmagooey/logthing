use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub const ADMIN_OVERRIDE_FILE: &str = "logthing.admin.toml";

/// Shared S3 connection parameters embedded (via `#[serde(flatten)]`) into
/// `SyslogS3Config` and `IpfixS3Config`. This keeps the TOML surface flat
/// (e.g. `[syslog.s3]\nendpoint = …`) while ensuring the client-construction
/// logic lives in one place (`S3Sink::from_connection`).
#[derive(Clone, Deserialize, Serialize)]
pub struct S3ConnectionConfig {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
}

/// Manual Debug impl for S3ConnectionConfig that masks secret fields so they
/// never appear in logs, panic messages, or anyhow error chains.
impl std::fmt::Debug for S3ConnectionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3ConnectionConfig")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("access_key", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

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

    #[serde(default)]
    pub zeek: ZeekConfig,

    #[serde(default)]
    pub wef: WefConfig,
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
    pub s3: Option<crate::forwarding::syslog_s3::SyslogS3Config>,
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

/// Configuration for the Zeek NDJSON TCP listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZeekConfig {
    #[serde(default = "default_zeek_enabled")]
    pub enabled: bool,

    #[serde(default = "default_zeek_tcp_port")]
    pub tcp_port: u16,

    #[serde(default = "default_zeek_bind_address")]
    pub bind_address: String,

    /// Optional S3 persistence. Absent from TOML → `None` → no persistence.
    #[serde(default)]
    pub s3: Option<ZeekS3Config>,
}

impl Default for ZeekConfig {
    fn default() -> Self {
        Self {
            enabled: default_zeek_enabled(),
            tcp_port: default_zeek_tcp_port(),
            bind_address: default_zeek_bind_address(),
            s3: None,
        }
    }
}

fn default_zeek_enabled() -> bool {
    false
}
fn default_zeek_tcp_port() -> u16 {
    47760
}
fn default_zeek_bind_address() -> String {
    "0.0.0.0".to_string()
}

/// Per-source S3 persistence config for the Zeek listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZeekS3Config {
    /// Shared S3 connection fields. Flattened so TOML stays flat: `[zeek.s3]\nendpoint = …`
    #[serde(flatten)]
    pub connection: S3ConnectionConfig,
    /// S3 key prefix, slash-free (default: `"zeek"`).
    #[serde(default = "default_zeek_s3_prefix")]
    pub prefix: String,
    /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
    #[serde(default = "default_zeek_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless of buffer size (default: 900).
    #[serde(default = "default_zeek_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default: 256).
    #[serde(default = "default_zeek_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum buffered rows before hard cap kicks in (default: 100_000).
    #[serde(default = "default_zeek_max_buffer_rows")]
    pub max_buffer_rows: usize,
}

fn default_zeek_s3_prefix() -> String {
    "zeek".to_string()
}
fn default_zeek_flush_bytes() -> usize {
    100 * 1024 * 1024
}
fn default_zeek_flush_secs() -> u64 {
    900
}
fn default_zeek_channel_capacity() -> usize {
    256
}
fn default_zeek_max_buffer_rows() -> usize {
    100_000
}

/// Per-source S3 persistence config for WEF (Windows Event Forwarding).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WefS3Config {
    /// Shared S3 connection fields.
    #[serde(flatten)]
    pub connection: S3ConnectionConfig,
    /// S3 key prefix, slash-free. Default: `""` (empty) — preserves the
    /// `event_type=<id>/year=…` root layout from the legacy writer.
    #[serde(default)]
    pub prefix: String,
    /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
    #[serde(default = "default_wef_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless (default: 900).
    #[serde(default = "default_wef_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default: 10_000).
    #[serde(default = "default_wef_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum buffered rows before hard cap (default: 100_000).
    #[serde(default = "default_wef_max_buffer_rows")]
    pub max_buffer_rows: usize,
}

fn default_wef_flush_bytes() -> usize {
    100 * 1024 * 1024
}
fn default_wef_flush_secs() -> u64 {
    900
}
fn default_wef_channel_capacity() -> usize {
    10_000
}
fn default_wef_max_buffer_rows() -> usize {
    100_000
}

/// Top-level [wef] config section (WEF ingest + optional S3 persistence).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WefConfig {
    /// Optional S3 persistence. Absent from TOML → `None` → no S3 persistence.
    #[serde(default)]
    pub s3: Option<WefS3Config>,
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
            zeek: ZeekConfig::default(),
            wef: WefConfig::default(),
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
    /// use logthing::config::Config;
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
prefix = "syslog"
max_buffer_rows = 5000
flush_interval_secs = 300
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse config");
        let s3 = cfg.syslog.s3.expect("s3 config present");
        assert_eq!(s3.connection.bucket, "syslog-bucket");
        assert_eq!(s3.prefix, "syslog");
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
        assert_eq!(s3.prefix, "syslog");
        assert_eq!(s3.max_buffer_rows, 10_000);
        assert_eq!(s3.flush_interval_secs, 900);
        assert_eq!(s3.channel_capacity, 4096);
    }

    #[test]
    fn syslog_s3_flat_toml_deserializes_correctly() {
        // Verify that #[serde(flatten)] keeps the TOML surface flat.
        let toml_str = r#"
[syslog.s3]
endpoint   = "http://minio:9000"
bucket     = "log-bucket"
region     = "eu-west-1"
access_key = "AKEY"
secret_key = "SKEY"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        let s3 = cfg.syslog.s3.expect("present");
        assert_eq!(s3.connection.endpoint, "http://minio:9000");
        assert_eq!(s3.connection.bucket, "log-bucket");
        assert_eq!(s3.connection.region, "eu-west-1");
        assert_eq!(s3.connection.access_key, "AKEY");
        assert_eq!(s3.connection.secret_key, "SKEY");
    }

    #[test]
    fn ipfix_s3_flat_toml_deserializes_correctly() {
        // Verify that #[serde(flatten)] keeps the TOML surface flat.
        let toml_str = r#"
[ipfix.s3]
endpoint   = "http://minio:9001"
bucket     = "flow-bucket"
region     = "ap-east-1"
access_key = "FKEY"
secret_key = "FSKEY"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        let s3 = cfg.ipfix.s3.expect("present");
        assert_eq!(s3.connection.endpoint, "http://minio:9001");
        assert_eq!(s3.connection.bucket, "flow-bucket");
        assert_eq!(s3.connection.region, "ap-east-1");
        assert_eq!(s3.connection.access_key, "FKEY");
    }

    #[test]
    fn default_ipfix_config_disabled_on_port_4739() {
        let cfg = Config::default();
        assert!(!cfg.ipfix.enabled, "ipfix disabled by default");
        assert_eq!(cfg.ipfix.udp_port, 4739);
        assert_eq!(cfg.ipfix.bind_address, "0.0.0.0");
    }

    #[test]
    fn zeek_s3_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.zeek.s3.is_none(),
            "absent [zeek.s3] must deserialize to None"
        );
    }

    #[test]
    fn zeek_s3_flat_toml_deserializes_correctly() {
        let toml_str = r#"
[zeek]
enabled = true
tcp_port = 47760
[zeek.s3]
endpoint   = "http://minio:9000"
bucket     = "zeek-logs"
region     = "us-east-1"
access_key = "KEY"
secret_key = "SECRET"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse config");
        assert!(cfg.zeek.enabled);
        let s3 = cfg.zeek.s3.expect("s3 present");
        assert_eq!(s3.connection.bucket, "zeek-logs");
        assert_eq!(s3.prefix, "zeek");
        assert_eq!(s3.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(s3.flush_interval_secs, 900);
        assert_eq!(s3.channel_capacity, 256);
        assert_eq!(s3.max_buffer_rows, 100_000);
    }

    #[test]
    fn zeek_s3_absent_section_means_no_persistence() {
        let toml_str = "[zeek]\nenabled = true\n";
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(cfg.zeek.s3.is_none(), "absent [zeek.s3] must yield None");
    }

    #[test]
    fn default_zeek_config_disabled_on_port_47760() {
        let cfg = Config::default();
        assert!(!cfg.zeek.enabled, "zeek disabled by default");
        assert_eq!(cfg.zeek.tcp_port, 47760);
        assert_eq!(cfg.zeek.bind_address, "0.0.0.0");
    }

    #[test]
    fn wef_s3_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.wef.s3.is_none(),
            "absent [wef.s3] must deserialize to None"
        );
    }

    #[test]
    fn wef_s3_flat_toml_deserializes_correctly() {
        let toml_str = r#"
[wef.s3]
endpoint   = "http://minio:9000"
bucket     = "wef-events"
region     = "us-east-1"
access_key = "KEY"
secret_key = "SECRET"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse config");
        let s3 = cfg.wef.s3.expect("s3 present");
        assert_eq!(s3.connection.bucket, "wef-events");
        assert_eq!(s3.prefix, ""); // default: empty prefix preserves old layout
        assert_eq!(s3.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(s3.flush_interval_secs, 900);
        assert_eq!(s3.channel_capacity, 10_000);
        assert_eq!(s3.max_buffer_rows, 100_000);
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
            assert!(!cfg.forwarding.destinations.is_empty());
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
        assert_eq!(s3.connection.bucket, "ipfix-flows");
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

    // H-5: Debug output must never expose S3 credentials.
    #[test]
    fn s3_connection_config_debug_masks_secrets() {
        let cfg = S3ConnectionConfig {
            endpoint: "http://minio:9000".to_string(),
            bucket: "my-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "SUPERSECRETKEY".to_string(),
            secret_key: "TOPSECRETPASSWORD".to_string(),
        };
        let debug_str = format!("{:?}", cfg);
        assert!(
            !debug_str.contains("SUPERSECRETKEY"),
            "access_key must not appear in Debug output: {debug_str}"
        );
        assert!(
            !debug_str.contains("TOPSECRETPASSWORD"),
            "secret_key must not appear in Debug output: {debug_str}"
        );
        // Non-secret fields must still be visible.
        assert!(debug_str.contains("http://minio:9000"));
        assert!(debug_str.contains("my-bucket"));
        assert!(debug_str.contains("us-east-1"));
        assert!(debug_str.contains("<redacted>"));
    }
}
