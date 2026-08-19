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
    pub logging: LoggingConfig,

    #[serde(default)]
    pub metrics: MetricsConfig,

    #[serde(default)]
    pub syslog: SyslogConfig,

    #[serde(default)]
    pub ipfix: IpfixConfig,

    #[serde(default)]
    pub sflow: SflowConfig,

    #[serde(default)]
    pub zeek: ZeekConfig,

    #[serde(default)]
    pub suricata: SuricataConfig,

    #[serde(default)]
    pub wef: WefConfig,

    #[serde(default)]
    pub hec: HecConfig,

    #[serde(default)]
    pub otlp: OtlpConfig,

    #[serde(default)]
    pub iceberg: IcebergConfig,

    #[serde(default)]
    pub aggregate: AggregateConfig,
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

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct KerberosSecurityConfig {
    #[serde(default)]
    pub enabled: bool,
    pub spn: Option<String>,
    pub keytab: Option<PathBuf>,
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

    /// Enable syslog payload sub-parsing (CEF, LEEF, auditd, DHCP, RADIUS,
    /// web_access, DNS).  Default false (backward compatible).
    #[serde(default)]
    pub parse_payloads: bool,

    /// Optional S3 persistence for syslog messages.
    /// Absent from TOML → `None` → no S3 persistence (backward compatible).
    #[serde(default)]
    pub s3: Option<SyslogS3Config>,

    /// Optional S3 persistence for structured (parsed) syslog records.
    /// Requires `parse_payloads = true` to produce any output.
    #[serde(default)]
    pub structured_s3: Option<SyslogS3Config>,

    /// Optional local-disk persistence for raw syslog messages. Absent from
    /// TOML → `None` → no local persistence (backward compatible).
    /// Independent of `s3` — both may be configured simultaneously, in which
    /// case messages are written to both.
    #[serde(default)]
    pub local: Option<SyslogLocalConfig>,
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
    pub s3: Option<IpfixS3Config>,

    /// Optional local-disk persistence. Absent from TOML → `None` → no
    /// persistence. Independent of `s3` — both may be configured
    /// simultaneously, in which case records are written to both.
    #[serde(default)]
    pub local: Option<IpfixLocalConfig>,
}

impl Default for IpfixConfig {
    fn default() -> Self {
        Self {
            enabled: default_ipfix_enabled(),
            udp_port: default_ipfix_udp_port(),
            bind_address: default_ipfix_bind_address(),
            s3: None,
            local: None,
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

    /// Optional local-disk persistence. Absent from TOML → `None` → no
    /// persistence. Independent of `s3` — both may be configured
    /// simultaneously, in which case records are written to both.
    #[serde(default)]
    pub local: Option<ZeekLocalConfig>,
}

impl Default for ZeekConfig {
    fn default() -> Self {
        Self {
            enabled: default_zeek_enabled(),
            tcp_port: default_zeek_tcp_port(),
            bind_address: default_zeek_bind_address(),
            s3: None,
            local: None,
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
/// Bounded channel depth, derived from the shared 100 MiB per-channel budget
/// (`channel_budget::CHANNEL_BUDGET_BYTES`) and the measured per-record
/// footprint. Was a hardcoded 256 — roughly 60-250 ms of burst headroom,
/// which is what caused the production channel-full drops.
fn default_zeek_channel_capacity() -> usize {
    crate::forwarding::channel_budget::capacity_for(
        crate::forwarding::channel_budget::ZEEK_RECORD_BYTES,
    )
}
fn default_zeek_max_buffer_rows() -> usize {
    100_000
}

/// Per-source local-disk persistence config for the Zeek listener. Mirrors
/// `ZeekS3Config`'s flush-policy shape (reusing the same default functions),
/// swapping the S3 connection for a root directory. Independent of `s3`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZeekLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `"zeek"` — same default as `zeek.s3`).
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

/// Configuration for the Suricata EVE JSON TCP listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuricataConfig {
    #[serde(default = "default_suricata_enabled")]
    pub enabled: bool,

    #[serde(default = "default_suricata_tcp_port")]
    pub tcp_port: u16,

    #[serde(default = "default_suricata_bind_address")]
    pub bind_address: String,

    /// Optional S3 persistence. Absent from TOML → `None` → no persistence.
    #[serde(default)]
    pub s3: Option<SuricataS3Config>,

    /// Optional local-disk persistence. Absent from TOML → `None` → no
    /// persistence. Independent of `s3` — both may be configured
    /// simultaneously, in which case records are written to both.
    #[serde(default)]
    pub local: Option<SuricataLocalConfig>,
}

impl Default for SuricataConfig {
    fn default() -> Self {
        Self {
            enabled: default_suricata_enabled(),
            tcp_port: default_suricata_tcp_port(),
            bind_address: default_suricata_bind_address(),
            s3: None,
            local: None,
        }
    }
}

fn default_suricata_enabled() -> bool {
    false
}
fn default_suricata_tcp_port() -> u16 {
    47761
}
fn default_suricata_bind_address() -> String {
    "0.0.0.0".to_string()
}

/// Per-source S3 persistence config for the Suricata listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuricataS3Config {
    #[serde(flatten)]
    pub connection: S3ConnectionConfig,
    #[serde(default = "default_suricata_s3_prefix")]
    pub prefix: String,
    #[serde(default = "default_suricata_flush_bytes")]
    pub flush_threshold_bytes: usize,
    #[serde(default = "default_suricata_flush_secs")]
    pub flush_interval_secs: u64,
    #[serde(default = "default_suricata_channel_capacity")]
    pub channel_capacity: usize,
    #[serde(default = "default_suricata_max_buffer_rows")]
    pub max_buffer_rows: usize,
}

fn default_suricata_s3_prefix() -> String {
    "suricata".to_string()
}
fn default_suricata_flush_bytes() -> usize {
    100 * 1024 * 1024
}
fn default_suricata_flush_secs() -> u64 {
    900
}
/// Bounded channel depth, derived from the shared 100 MiB per-channel budget
/// (`channel_budget::CHANNEL_BUDGET_BYTES`) and the measured per-record
/// footprint. Was a hardcoded 256 — roughly 60-250 ms of burst headroom,
/// which is what caused the production channel-full drops.
fn default_suricata_channel_capacity() -> usize {
    crate::forwarding::channel_budget::capacity_for(
        crate::forwarding::channel_budget::SURICATA_RECORD_BYTES,
    )
}
fn default_suricata_max_buffer_rows() -> usize {
    100_000
}

/// Per-source local-disk persistence config for the Suricata listener.
/// Mirrors `SuricataS3Config`'s flush-policy shape (reusing the same
/// default functions), swapping the S3 connection for a root directory.
/// Independent of `s3`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuricataLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `"suricata"` — same default as `suricata.s3`).
    #[serde(default = "default_suricata_s3_prefix")]
    pub prefix: String,
    /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
    #[serde(default = "default_suricata_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless of buffer size (default: 900).
    #[serde(default = "default_suricata_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default: 256).
    #[serde(default = "default_suricata_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum buffered rows before hard cap kicks in (default: 100_000).
    #[serde(default = "default_suricata_max_buffer_rows")]
    pub max_buffer_rows: usize,
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
/// Bounded channel depth, derived from the shared 100 MiB per-channel budget
/// (`channel_budget::CHANNEL_BUDGET_BYTES`) and the measured per-record
/// footprint. Was a hardcoded 10_000 — roughly 600ms of burst headroom.
fn default_wef_channel_capacity() -> usize {
    crate::forwarding::channel_budget::capacity_for(
        crate::forwarding::channel_budget::WEF_EVENT_BYTES,
    )
}
fn default_wef_max_buffer_rows() -> usize {
    100_000
}

/// Per-source local-disk persistence config for WEF (Windows Event Forwarding).
/// Mirrors `WefS3Config`'s flush-policy shape (reusing the same default
/// functions), swapping the S3 connection for a root directory. Independent
/// of `s3`. `prefix` defaults to empty (bare `#[serde(default)]`, no default
/// function), preserving the same `event_type=<id>/year=…` root layout as
/// `WefS3Config`'s empty-prefix default.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WefLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free. Default: `""` (empty) — preserves the
    /// `event_type=<id>/year=…` root layout, same as `WefS3Config`.
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

/// Top-level [wef] config section (WEF ingest + optional S3 persistence).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WefConfig {
    /// Optional S3 persistence. Absent from TOML → `None` → no S3 persistence.
    #[serde(default)]
    pub s3: Option<WefS3Config>,
    /// Optional local-disk persistence. Absent from TOML → `None` → no
    /// local persistence. Independent of `s3` — both may be configured
    /// simultaneously, in which case events are written to both.
    #[serde(default)]
    pub local: Option<WefLocalConfig>,
}

/// Per-source S3 persistence config for HEC ingest.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HecS3Config {
    /// Shared S3 connection fields (flattened: `[hec.s3]\nendpoint = …`).
    #[serde(flatten)]
    pub connection: S3ConnectionConfig,
    /// S3 key prefix, slash-free (default: `"hec"`).
    #[serde(default = "default_hec_s3_prefix")]
    pub prefix: String,
    /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
    #[serde(default = "default_hec_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless (default: 900).
    #[serde(default = "default_hec_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default: 256).
    #[serde(default = "default_hec_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum buffered rows before hard cap (default: 100_000).
    #[serde(default = "default_hec_max_buffer_rows")]
    pub max_buffer_rows: usize,
}

fn default_hec_s3_prefix() -> String {
    "hec".to_string()
}
fn default_hec_flush_bytes() -> usize {
    100 * 1024 * 1024
}
fn default_hec_flush_secs() -> u64 {
    900
}
/// Bounded channel depth, derived from the shared 100 MiB per-channel budget
/// (`channel_budget::CHANNEL_BUDGET_BYTES`) and the measured per-record
/// footprint. Was a hardcoded 256 — roughly 60-250 ms of burst headroom,
/// which is what caused the production channel-full drops.
fn default_hec_channel_capacity() -> usize {
    crate::forwarding::channel_budget::capacity_for(
        crate::forwarding::channel_budget::GENERIC_RECORD_BYTES,
    )
}
fn default_hec_max_buffer_rows() -> usize {
    100_000
}

/// Per-source local-disk persistence config for HEC/generic ingest.
/// Mirrors `HecS3Config`'s flush-policy shape (reusing the same default
/// functions), swapping the S3 connection for a root directory.
/// Independent of `s3`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GenericLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `"hec"` — same default as `hec.s3`).
    #[serde(default = "default_hec_s3_prefix")]
    pub prefix: String,
    /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
    #[serde(default = "default_hec_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless of buffer size (default: 900).
    #[serde(default = "default_hec_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default: 256).
    #[serde(default = "default_hec_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum buffered rows before hard cap kicks in (default: 100_000).
    #[serde(default = "default_hec_max_buffer_rows")]
    pub max_buffer_rows: usize,
}

/// Top-level `[hec]` config section.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HecConfig {
    /// Enable the HEC ingest routes (default: false).
    #[serde(default = "default_hec_enabled")]
    pub enabled: bool,
    /// Shared secret compared against `Authorization: Splunk <token>`.
    /// Empty string means any token is accepted — only useful for local dev.
    #[serde(default)]
    pub token: String,
    /// Maximum distinct `sourcetype` partitions before overflow (default: 64).
    #[serde(default = "default_hec_max_sourcetype_partitions")]
    pub max_sourcetype_partitions: usize,
    /// Optional S3 persistence. `None` → records are accepted but not stored.
    #[serde(default)]
    pub s3: Option<HecS3Config>,
    /// Optional local-disk persistence. `None` → not persisted to local disk.
    /// Independent of `s3` — both may be configured simultaneously, in which
    /// case records are written to both.
    #[serde(default)]
    pub local: Option<GenericLocalConfig>,
}

fn default_hec_enabled() -> bool {
    false
}
fn default_hec_max_sourcetype_partitions() -> usize {
    64
}

impl Default for HecConfig {
    fn default() -> Self {
        Self {
            enabled: default_hec_enabled(),
            token: String::new(),
            max_sourcetype_partitions: default_hec_max_sourcetype_partitions(),
            s3: None,
            local: None,
        }
    }
}

/// Top-level [otlp] config section (OTLP/HTTP log ingest).
/// Only present when the `otlp` Cargo feature is enabled; always compiled
/// into Config so the TOML surface is consistent (the field is inert when
/// the feature is off — the route is never registered).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OtlpConfig {
    /// Enable the `POST /v1/logs` OTLP endpoint. Default: false.
    #[serde(default = "default_otlp_enabled")]
    pub enabled: bool,

    /// Optional bearer token for the `Authorization: Bearer <token>` header.
    /// If `None`, no bearer auth is enforced (IP whitelist + TLS still apply).
    #[serde(default)]
    pub bearer_token: Option<String>,
}

fn default_otlp_enabled() -> bool {
    false
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            enabled: default_otlp_enabled(),
            bearer_token: None,
        }
    }
}

/// Top-level `[iceberg]` config section — emits a small JSON "descriptor"
/// alongside each Parquet flush from every source, describing the file
/// for an external Iceberg committer (logthing has no Iceberg library
/// dependency and never talks to a catalog itself). Absent from TOML →
/// both `s3`/`local` are `None` → the feature is off (zero behavior
/// change to existing Parquet writing).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct IcebergConfig {
    /// Optional S3 destination for descriptors. Configuring this AND
    /// `local` simultaneously is a config error (see `validate_iceberg_config`)
    /// — unlike every other source's `.s3`/`.local` pair, which may both be
    /// configured and both get written to, `[iceberg]` requires exactly one
    /// destination: a descriptor is a lightweight pointer, not data at risk
    /// of loss, so dual-write isn't needed.
    #[serde(default)]
    pub s3: Option<IcebergDescriptorS3Config>,
    /// Optional local-disk destination for descriptors. See `s3` docs.
    #[serde(default)]
    pub local: Option<IcebergDescriptorLocalConfig>,
}

/// S3 destination config for Iceberg descriptors. Deliberately simpler
/// than other sources' `*S3Config` structs — no buffering fields, since
/// descriptors are uploaded synchronously as part of a flush that already
/// happened (nothing to batch).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IcebergDescriptorS3Config {
    #[serde(flatten)]
    pub connection: S3ConnectionConfig,
    /// Key prefix, slash-free (default: `""`).
    #[serde(default)]
    pub prefix: String,
}

/// Local-disk destination config for Iceberg descriptors. See
/// `IcebergDescriptorS3Config` docs.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IcebergDescriptorLocalConfig {
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `""`).
    #[serde(default)]
    pub prefix: String,
}

/// Rejects a config where both `iceberg.s3` and `iceberg.local` are
/// configured simultaneously. Because `config::Config::builder()` merges
/// all layers (file → admin-override-file → env vars) before
/// `try_deserialize()` runs, which *layer* set which value is not
/// recoverable here — the error names the resolved values instead, which
/// is the most an operator can be told given that constraint.
pub fn validate_iceberg_config(cfg: &IcebergConfig) -> anyhow::Result<()> {
    if let (Some(s3), Some(local)) = (cfg.s3.as_ref(), cfg.local.as_ref()) {
        anyhow::bail!(
            "iceberg.s3.bucket = '{}' and iceberg.local.directory = '{}' are both configured; \
             set only one — the [iceberg] descriptor sink does not support writing to both \
             destinations simultaneously",
            s3.connection.bucket,
            local.directory.display()
        );
    }
    Ok(())
}

/// Per-source S3 persistence config for the syslog listener.
/// Absent from TOML → `None` → no S3 persistence (backward compatible).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SyslogS3Config {
    /// Shared S3 connection fields (endpoint, bucket, region, access_key, secret_key).
    /// Flattened so the TOML block stays flat: `[syslog.s3]\nendpoint = …`
    #[serde(flatten)]
    pub connection: S3ConnectionConfig,
    /// S3 key prefix for syslog objects, slash-free (default: `"syslog"`); builder inserts `/`.
    #[serde(default = "default_syslog_s3_prefix")]
    pub prefix: String,
    /// Flush when row count reaches this threshold (default 10 000).
    #[serde(default = "default_syslog_s3_max_rows")]
    pub max_buffer_rows: usize,
    /// Flush after this many seconds regardless of row count (default 900 = 15 min).
    #[serde(default = "default_syslog_s3_flush_interval_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (number of messages; default 4096).
    #[serde(default = "default_syslog_s3_channel_capacity")]
    pub channel_capacity: usize,
}

fn default_syslog_s3_prefix() -> String {
    "syslog".to_string()
}
fn default_syslog_s3_max_rows() -> usize {
    10_000
}
fn default_syslog_s3_flush_interval_secs() -> u64 {
    900
}
/// Bounded channel depth, derived from the shared 100 MiB per-channel budget
/// (`channel_budget::CHANNEL_BUDGET_BYTES`) and the measured per-message
/// footprint. Was a hardcoded 4_096 — roughly 4 seconds of burst headroom.
fn default_syslog_s3_channel_capacity() -> usize {
    crate::forwarding::channel_budget::capacity_for(
        crate::forwarding::channel_budget::SYSLOG_MESSAGE_BYTES,
    )
}

/// Per-source local-disk persistence config for the syslog listener.
/// Mirrors `SyslogS3Config`'s flush-policy shape (reusing the same
/// default functions), swapping the S3 connection for a root directory.
/// Independent of `s3`. No `flush_threshold_bytes` field — syslog uses
/// row-count + age triggers only, same as `SyslogS3Config`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyslogLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `"syslog"` — same default as `syslog.s3`).
    #[serde(default = "default_syslog_s3_prefix")]
    pub prefix: String,
    /// Flush when row count reaches this threshold (default 10 000).
    #[serde(default = "default_syslog_s3_max_rows")]
    pub max_buffer_rows: usize,
    /// Flush after this many seconds regardless of row count (default 900).
    #[serde(default = "default_syslog_s3_flush_interval_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default 4096).
    #[serde(default = "default_syslog_s3_channel_capacity")]
    pub channel_capacity: usize,
}

/// Per-source S3 persistence config for the IPFIX listener.
/// Absent from TOML → `None` → no S3 persistence (backward compatible).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct IpfixS3Config {
    /// Shared S3 connection fields (endpoint, bucket, region, access_key, secret_key).
    /// Flattened so the TOML block stays flat: `[ipfix.s3]\nendpoint = …`
    #[serde(flatten)]
    pub connection: S3ConnectionConfig,
    /// S3 key prefix for IPFIX objects, slash-free (default: `"ipfix"`); builder inserts `/`.
    #[serde(default = "default_ipfix_s3_prefix")]
    pub prefix: String,
    /// Max buffer size in bytes before an eager flush (default: 100 MiB)
    #[serde(default = "default_ipfix_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Max age of buffered records in seconds before a time-triggered flush (default: 900)
    #[serde(default = "default_ipfix_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (number of batches; default: 256)
    #[serde(default = "default_ipfix_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum number of buffered rows before hard cap kicks in (default: 100 000)
    #[serde(default = "default_ipfix_max_buffer_rows")]
    pub max_buffer_rows: usize,
}

fn default_ipfix_s3_prefix() -> String {
    "ipfix".to_string()
}
fn default_ipfix_flush_bytes() -> usize {
    100 * 1024 * 1024 // 100 MiB
}
fn default_ipfix_flush_secs() -> u64 {
    900
}
/// Bounded channel depth, derived from the shared 100 MiB per-channel budget
/// (`channel_budget::CHANNEL_BUDGET_BYTES`) and the measured per-datagram
/// footprint. Was a hardcoded 256 — roughly 60-250 ms of burst headroom,
/// which is what caused the production channel-full drops.
fn default_ipfix_channel_capacity() -> usize {
    crate::forwarding::channel_budget::capacity_for(
        crate::forwarding::channel_budget::IPFIX_DATAGRAM_BYTES,
    )
}
fn default_ipfix_max_buffer_rows() -> usize {
    100_000
}

/// Per-source local-disk persistence config for the IPFIX listener. Mirrors
/// `IpfixS3Config`'s flush-policy shape (reusing the same default
/// functions), swapping the S3 connection for a root directory.
/// Independent of `s3`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpfixLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `"ipfix"` — same default as `ipfix.s3`).
    #[serde(default = "default_ipfix_s3_prefix")]
    pub prefix: String,
    /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
    #[serde(default = "default_ipfix_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless of buffer size (default: 900).
    #[serde(default = "default_ipfix_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default: 256).
    #[serde(default = "default_ipfix_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum buffered rows before hard cap kicks in (default: 100_000).
    #[serde(default = "default_ipfix_max_buffer_rows")]
    pub max_buffer_rows: usize,
}

// ── SflowConfig ───────────────────────────────────────────────────────────

/// Configuration for the sFlow v5 UDP listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SflowConfig {
    #[serde(default = "default_sflow_enabled")]
    pub enabled: bool,

    #[serde(default = "default_sflow_udp_port")]
    pub udp_port: u16,

    #[serde(default = "default_sflow_bind_address")]
    pub bind_address: String,

    /// Optional S3 persistence. Absent from TOML → `None` (backward compatible).
    #[serde(default)]
    pub s3: Option<SflowS3Config>,

    /// Optional local-disk persistence. Absent from TOML → `None` → no
    /// persistence. Independent of `s3` — both may be configured
    /// simultaneously, in which case records are written to both.
    #[serde(default)]
    pub local: Option<SflowLocalConfig>,
}

impl Default for SflowConfig {
    fn default() -> Self {
        Self {
            enabled: default_sflow_enabled(),
            udp_port: default_sflow_udp_port(),
            bind_address: default_sflow_bind_address(),
            s3: None,
            local: None,
        }
    }
}

fn default_sflow_enabled() -> bool {
    false
}
fn default_sflow_udp_port() -> u16 {
    6343
}
fn default_sflow_bind_address() -> String {
    "0.0.0.0".to_string()
}

/// Per-source S3 persistence config for the sFlow listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SflowS3Config {
    #[serde(flatten)]
    pub connection: S3ConnectionConfig,
    #[serde(default = "default_sflow_s3_prefix")]
    pub prefix: String,
    #[serde(default = "default_sflow_flush_bytes")]
    pub flush_threshold_bytes: usize,
    #[serde(default = "default_sflow_flush_secs")]
    pub flush_interval_secs: u64,
    #[serde(default = "default_sflow_channel_capacity")]
    pub channel_capacity: usize,
    #[serde(default = "default_sflow_max_buffer_rows")]
    pub max_buffer_rows: usize,
}

fn default_sflow_s3_prefix() -> String {
    "sflow".to_string()
}
fn default_sflow_flush_bytes() -> usize {
    100 * 1024 * 1024
}
fn default_sflow_flush_secs() -> u64 {
    900
}
/// Bounded channel depth, derived from the shared 100 MiB per-channel budget
/// (`channel_budget::CHANNEL_BUDGET_BYTES`) and the measured per-record
/// footprint. Was a hardcoded 256 — roughly 60-250 ms of burst headroom,
/// which is what caused the production channel-full drops.
fn default_sflow_channel_capacity() -> usize {
    crate::forwarding::channel_budget::capacity_for(
        crate::forwarding::channel_budget::SFLOW_RECORD_BYTES,
    )
}
fn default_sflow_max_buffer_rows() -> usize {
    100_000
}

/// Per-source local-disk persistence config for the sFlow listener. Mirrors
/// `SflowS3Config`'s flush-policy shape (reusing the same default
/// functions), swapping the S3 connection for a root directory.
/// Independent of `s3`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SflowLocalConfig {
    /// Root directory Parquet files are written under (created if missing).
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `"sflow"` — same default as `sflow.s3`).
    #[serde(default = "default_sflow_s3_prefix")]
    pub prefix: String,
    /// Flush when estimated buffer bytes exceeds this (default: 100 MiB).
    #[serde(default = "default_sflow_flush_bytes")]
    pub flush_threshold_bytes: usize,
    /// Flush after this many seconds regardless of buffer size (default: 900).
    #[serde(default = "default_sflow_flush_secs")]
    pub flush_interval_secs: u64,
    /// Bounded channel capacity (default: 256).
    #[serde(default = "default_sflow_channel_capacity")]
    pub channel_capacity: usize,
    /// Maximum buffered rows before hard cap kicks in (default: 100_000).
    #[serde(default = "default_sflow_max_buffer_rows")]
    pub max_buffer_rows: usize,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: default_syslog_enabled(),
            udp_port: default_syslog_udp_port(),
            tcp_port: default_syslog_tcp_port(),
            parse_dns: default_syslog_parse_dns(),
            parse_payloads: false,
            s3: None,
            structured_s3: None,
            local: None,
        }
    }
}

/// Optional aggregation: count records as they arrive, grouped by configured
/// columns, and write the counted table to Parquet instead of the raw rows.
/// Disabled by default — absent from TOML means nothing changes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AggregateConfig {
    #[serde(default = "default_aggregate_enabled")]
    pub enabled: bool,
    /// Window length: drives both the emit tick and the writer's flush age.
    #[serde(default = "default_aggregate_flush_secs")]
    pub flush_interval_secs: u64,
    /// Per-rule, per-window distinct-group cap. Beyond this, new keys fold
    /// into that rule's single `_other` row.
    #[serde(default = "default_aggregate_max_groups")]
    pub max_groups: usize,
    #[serde(default = "default_aggregate_channel_capacity")]
    pub channel_capacity: usize,
    #[serde(default)]
    pub s3: Option<AggregateS3Config>,
    #[serde(default)]
    pub local: Option<AggregateLocalConfig>,
    #[serde(default)]
    pub rules: Vec<AggregateRule>,
}

impl Default for AggregateConfig {
    fn default() -> Self {
        Self {
            enabled: default_aggregate_enabled(),
            flush_interval_secs: default_aggregate_flush_secs(),
            max_groups: default_aggregate_max_groups(),
            channel_capacity: default_aggregate_channel_capacity(),
            s3: None,
            local: None,
            rules: Vec::new(),
        }
    }
}

fn default_aggregate_enabled() -> bool {
    false
}
fn default_aggregate_flush_secs() -> u64 {
    900
}
fn default_aggregate_max_groups() -> usize {
    100_000
}
fn default_aggregate_channel_capacity() -> usize {
    4096
}
fn default_aggregate_prefix() -> String {
    "aggregate".to_string()
}

/// S3 destination for aggregated tables. One writer serves every rule
/// regardless of which source the rule reads from — `AggregateRow` is
/// source-agnostic.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AggregateS3Config {
    #[serde(flatten)]
    pub connection: S3ConnectionConfig,
    #[serde(default = "default_aggregate_prefix")]
    pub prefix: String,
}

/// Local-disk destination for aggregated tables. Independent of `s3` — both
/// may be set, in which case rows are written to both.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AggregateLocalConfig {
    pub directory: PathBuf,
    #[serde(default = "default_aggregate_prefix")]
    pub prefix: String,
}

/// One `GROUP BY` rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AggregateRule {
    /// Unique; becomes the output partition segment.
    pub name: String,
    /// One of: zeek, suricata, syslog, ipfix, sflow.
    pub source: String,
    /// Optional stream filter — zeek `_path`, suricata `event_type`, syslog
    /// `app_name`, sflow `"flow"`/`"counter"`, ipfix `"flows"`. Omitted means
    /// every record from that source.
    #[serde(default)]
    pub stream: Option<String>,
    pub group_by: Vec<String>,
    #[serde(default)]
    pub sum: Vec<String>,
    #[serde(default)]
    pub min: Vec<String>,
    #[serde(default)]
    pub max: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            tls: TlsConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            metrics: MetricsConfig::default(),
            syslog: SyslogConfig::default(),
            ipfix: IpfixConfig::default(),
            sflow: SflowConfig::default(),
            zeek: ZeekConfig::default(),
            suricata: SuricataConfig::default(),
            wef: WefConfig::default(),
            hec: HecConfig::default(),
            otlp: OtlpConfig::default(),
            iceberg: IcebergConfig::default(),
            aggregate: AggregateConfig::default(),
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

fn default_log_level() -> String {
    "info".to_string()
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_metrics_port() -> u16 {
    9090
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
        let config: Config = config.try_deserialize()?;
        validate_iceberg_config(&config.iceberg)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding::channel_budget::{
        GENERIC_RECORD_BYTES, IPFIX_DATAGRAM_BYTES, SFLOW_RECORD_BYTES, SURICATA_RECORD_BYTES,
        SYSLOG_MESSAGE_BYTES, WEF_EVENT_BYTES, ZEEK_RECORD_BYTES, capacity_for,
    };

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
        assert_eq!(s3.channel_capacity, capacity_for(SYSLOG_MESSAGE_BYTES));
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
    fn syslog_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.syslog.local.is_none(),
            "absent [syslog.local] must deserialize to None"
        );
    }

    #[test]
    fn syslog_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/syslog"
prefix = "syslog"
max_buffer_rows = 5000
flush_interval_secs = 300
channel_capacity = 512
"#;
        let cfg: SyslogLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            cfg.directory,
            std::path::PathBuf::from("/var/log/logthing/syslog")
        );
        assert_eq!(cfg.prefix, "syslog");
        assert_eq!(cfg.max_buffer_rows, 5_000);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
    }

    #[test]
    fn syslog_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/syslog""#;
        let cfg: SyslogLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.prefix, "syslog");
        assert_eq!(cfg.max_buffer_rows, 10_000);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, capacity_for(SYSLOG_MESSAGE_BYTES));
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
    fn ipfix_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.ipfix.local.is_none(),
            "absent [ipfix.local] must deserialize to None"
        );
    }

    #[test]
    fn ipfix_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/ipfix"
prefix = "ipfix"
flush_threshold_bytes = 52428800
flush_interval_secs = 300
channel_capacity = 512
max_buffer_rows = 50000
"#;
        let cfg: IpfixLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            cfg.directory,
            std::path::PathBuf::from("/var/log/logthing/ipfix")
        );
        assert_eq!(cfg.prefix, "ipfix");
        assert_eq!(cfg.flush_threshold_bytes, 52_428_800);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
        assert_eq!(cfg.max_buffer_rows, 50_000);
    }

    #[test]
    fn ipfix_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/ipfix""#;
        let cfg: IpfixLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.prefix, "ipfix");
        assert_eq!(cfg.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, capacity_for(IPFIX_DATAGRAM_BYTES));
        assert_eq!(cfg.max_buffer_rows, 100_000);
    }

    #[test]
    fn ipfix_s3_and_local_can_both_be_configured_simultaneously() {
        let toml_str = r#"
[ipfix]
enabled = true

[ipfix.s3]
endpoint = "http://minio:9000"
bucket = "b"
region = "us-east-1"
access_key = "k"
secret_key = "s"

[ipfix.local]
directory = "/data/ipfix"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("deserialize");
        assert!(
            cfg.ipfix.s3.is_some(),
            "s3 must deserialize when both present"
        );
        assert!(
            cfg.ipfix.local.is_some(),
            "local must deserialize when both present"
        );
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
        assert_eq!(s3.channel_capacity, capacity_for(ZEEK_RECORD_BYTES));
        assert_eq!(s3.max_buffer_rows, 100_000);
    }

    #[test]
    fn zeek_s3_absent_section_means_no_persistence() {
        let toml_str = "[zeek]\nenabled = true\n";
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(cfg.zeek.s3.is_none(), "absent [zeek.s3] must yield None");
    }

    #[test]
    fn zeek_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.zeek.local.is_none(),
            "absent [zeek.local] must deserialize to None"
        );
    }

    #[test]
    fn zeek_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/zeek"
prefix = "zeek"
flush_threshold_bytes = 52428800
flush_interval_secs = 300
channel_capacity = 512
max_buffer_rows = 50000
"#;
        let cfg: ZeekLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            cfg.directory,
            std::path::PathBuf::from("/var/log/logthing/zeek")
        );
        assert_eq!(cfg.prefix, "zeek");
        assert_eq!(cfg.flush_threshold_bytes, 52_428_800);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
        assert_eq!(cfg.max_buffer_rows, 50_000);
    }

    #[test]
    fn zeek_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/zeek""#;
        let cfg: ZeekLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.prefix, "zeek");
        assert_eq!(cfg.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, capacity_for(ZEEK_RECORD_BYTES));
        assert_eq!(cfg.max_buffer_rows, 100_000);
    }

    #[test]
    fn zeek_s3_and_local_can_both_be_configured_simultaneously() {
        let toml_str = r#"
[zeek]
enabled = true

[zeek.s3]
endpoint = "http://minio:9000"
bucket = "b"
region = "us-east-1"
access_key = "k"
secret_key = "s"

[zeek.local]
directory = "/data/zeek"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("deserialize");
        assert!(
            cfg.zeek.s3.is_some(),
            "s3 must deserialize when both present"
        );
        assert!(
            cfg.zeek.local.is_some(),
            "local must deserialize when both present"
        );
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
        assert_eq!(s3.channel_capacity, capacity_for(WEF_EVENT_BYTES));
        assert_eq!(s3.max_buffer_rows, 100_000);
    }

    #[test]
    fn wef_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.wef.local.is_none(),
            "absent [wef.local] must deserialize to None"
        );
    }

    #[test]
    fn wef_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/wef"
prefix = "wef"
flush_threshold_bytes = 52428800
flush_interval_secs = 300
channel_capacity = 512
max_buffer_rows = 50000
"#;
        let cfg: WefLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            cfg.directory,
            std::path::PathBuf::from("/var/log/logthing/wef")
        );
        assert_eq!(cfg.prefix, "wef");
        assert_eq!(cfg.flush_threshold_bytes, 52_428_800);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
        assert_eq!(cfg.max_buffer_rows, 50_000);
    }

    #[test]
    fn wef_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/wef""#;
        let cfg: WefLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            cfg.prefix, "",
            "prefix defaults to empty, preserving legacy layout"
        );
        assert_eq!(cfg.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, capacity_for(WEF_EVENT_BYTES));
        assert_eq!(cfg.max_buffer_rows, 100_000);
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
    fn env_vars_override_bind_ports_for_all_log_types() {
        // `WEF__<SECTION>__<FIELD>` env vars are process-global, and cargo
        // runs unit tests in this file's binary on multiple threads by
        // default. No other test in this file (or reachable from this test
        // binary) reads these particular fields, so no cross-test lock is
        // needed — but we still wrap set/load/assert in catch_unwind and
        // guarantee cleanup runs even on a failed assertion, so a panic here
        // can never leak `WEF__*` state into a test added later. This
        // mirrors the `load_reads_configuration_file` test's rename/restore
        // safety pattern above.
        let vars: &[(&str, &str)] = &[
            ("WEF__BIND_ADDRESS", "127.0.0.1:15985"),
            ("WEF__TLS__PORT", "15986"),
            ("WEF__METRICS__PORT", "19090"),
            ("WEF__SYSLOG__UDP_PORT", "15140"),
            ("WEF__SYSLOG__TCP_PORT", "16010"),
            ("WEF__IPFIX__UDP_PORT", "14739"),
            ("WEF__IPFIX__BIND_ADDRESS", "127.0.0.2"),
            ("WEF__ZEEK__TCP_PORT", "14776"),
            ("WEF__ZEEK__BIND_ADDRESS", "127.0.0.3"),
            ("WEF__SURICATA__TCP_PORT", "14777"),
            ("WEF__SURICATA__BIND_ADDRESS", "127.0.0.4"),
            ("WEF__SFLOW__UDP_PORT", "16343"),
            ("WEF__SFLOW__BIND_ADDRESS", "127.0.0.5"),
        ];

        for (k, v) in vars {
            unsafe { std::env::set_var(k, v) };
        }

        let result = std::panic::catch_unwind(|| {
            let cfg = Config::load().expect("config loads with env overrides");
            assert_eq!(cfg.bind_address, "127.0.0.1:15985".parse().unwrap());
            assert_eq!(cfg.tls.port, 15986);
            assert_eq!(cfg.metrics.port, 19090);
            assert_eq!(cfg.syslog.udp_port, 15140);
            assert_eq!(cfg.syslog.tcp_port, 16010);
            assert_eq!(cfg.ipfix.udp_port, 14739);
            assert_eq!(cfg.ipfix.bind_address, "127.0.0.2");
            assert_eq!(cfg.zeek.tcp_port, 14776);
            assert_eq!(cfg.zeek.bind_address, "127.0.0.3");
            assert_eq!(cfg.suricata.tcp_port, 14777);
            assert_eq!(cfg.suricata.bind_address, "127.0.0.4");
            assert_eq!(cfg.sflow.udp_port, 16343);
            assert_eq!(cfg.sflow.bind_address, "127.0.0.5");
        });

        for (k, _) in vars {
            unsafe { std::env::remove_var(k) };
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

    #[test]
    fn default_suricata_config_disabled_on_port_47761() {
        let cfg = Config::default();
        assert!(!cfg.suricata.enabled, "suricata disabled by default");
        assert_eq!(cfg.suricata.tcp_port, 47761);
        assert_eq!(cfg.suricata.bind_address, "0.0.0.0");
        assert!(
            cfg.suricata.s3.is_none(),
            "absent [suricata.s3] must be None"
        );
    }

    #[test]
    fn suricata_s3_flat_toml_deserializes_correctly() {
        let toml_str = r#"
[suricata]
enabled = true
tcp_port = 47761
[suricata.s3]
endpoint   = "http://minio:9000"
bucket     = "suricata-logs"
region     = "us-east-1"
access_key = "KEY"
secret_key = "SECRET"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse config");
        assert!(cfg.suricata.enabled);
        let s3 = cfg.suricata.s3.expect("s3 present");
        assert_eq!(s3.connection.bucket, "suricata-logs");
        assert_eq!(s3.prefix, "suricata");
        assert_eq!(s3.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(s3.flush_interval_secs, 900);
        assert_eq!(s3.channel_capacity, capacity_for(SURICATA_RECORD_BYTES));
        assert_eq!(s3.max_buffer_rows, 100_000);
    }

    #[test]
    fn suricata_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.suricata.local.is_none(),
            "absent [suricata.local] must deserialize to None"
        );
    }

    #[test]
    fn suricata_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/suricata"
prefix = "suricata"
flush_threshold_bytes = 52428800
flush_interval_secs = 300
channel_capacity = 512
max_buffer_rows = 50000
"#;
        let cfg: SuricataLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            cfg.directory,
            std::path::PathBuf::from("/var/log/logthing/suricata")
        );
        assert_eq!(cfg.prefix, "suricata");
        assert_eq!(cfg.flush_threshold_bytes, 52_428_800);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
        assert_eq!(cfg.max_buffer_rows, 50_000);
    }

    #[test]
    fn suricata_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/suricata""#;
        let cfg: SuricataLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.prefix, "suricata");
        assert_eq!(cfg.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, capacity_for(SURICATA_RECORD_BYTES));
        assert_eq!(cfg.max_buffer_rows, 100_000);
    }

    #[test]
    fn suricata_s3_and_local_can_both_be_configured_simultaneously() {
        let toml_str = r#"
[suricata]
enabled = true

[suricata.s3]
endpoint = "http://minio:9000"
bucket = "b"
region = "us-east-1"
access_key = "k"
secret_key = "s"

[suricata.local]
directory = "/data/suricata"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("deserialize");
        assert!(
            cfg.suricata.s3.is_some(),
            "s3 must deserialize when both present"
        );
        assert!(
            cfg.suricata.local.is_some(),
            "local must deserialize when both present"
        );
    }

    #[test]
    fn suricata_s3_absent_section_means_no_persistence() {
        let toml_str = "[suricata]\nenabled = true\n";
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(
            cfg.suricata.s3.is_none(),
            "absent [suricata.s3] must yield None"
        );
    }

    #[test]
    fn suricata_config_does_not_affect_other_defaults() {
        // Adding suricata must not change zeek, ipfix, or syslog defaults.
        let cfg = Config::default();
        assert!(!cfg.zeek.enabled);
        assert!(!cfg.ipfix.enabled);
        assert!(!cfg.suricata.enabled);
        // syslog is enabled by default — must remain so
        assert!(cfg.syslog.enabled);
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

    #[test]
    fn syslog_parse_payloads_defaults_to_false() {
        let cfg = Config::default();
        assert!(
            !cfg.syslog.parse_payloads,
            "parse_payloads must default to false"
        );
    }

    #[test]
    fn syslog_structured_s3_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.syslog.structured_s3.is_none(),
            "structured_s3 must default to None"
        );
    }

    #[test]
    fn syslog_parse_payloads_can_be_set_in_toml() {
        let toml_str = "[syslog]\nparse_payloads = true\n";
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(cfg.syslog.parse_payloads);
    }

    #[test]
    fn syslog_structured_s3_parses_from_toml() {
        let toml_str = r#"
[syslog.structured_s3]
endpoint   = "http://minio:9000"
bucket     = "structured-syslog"
region     = "us-east-1"
access_key = "KEY"
secret_key = "SECRET"
prefix     = "syslog-structured"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        let s3 = cfg.syslog.structured_s3.expect("structured_s3 present");
        assert_eq!(s3.connection.bucket, "structured-syslog");
        assert_eq!(s3.prefix, "syslog-structured");
    }

    #[test]
    fn sflow_config_defaults_disabled_on_port_6343() {
        let cfg = Config::default();
        assert!(!cfg.sflow.enabled, "sflow disabled by default");
        assert_eq!(cfg.sflow.udp_port, 6343);
        assert_eq!(cfg.sflow.bind_address, "0.0.0.0");
        assert!(cfg.sflow.s3.is_none());
    }

    #[test]
    fn sflow_s3_flat_toml_deserializes_correctly() {
        let toml_str = r#"
[sflow.s3]
endpoint   = "http://minio:9002"
bucket     = "sflow-samples"
region     = "us-east-1"
access_key = "SKEY"
secret_key = "SSECRET"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        let s3 = cfg.sflow.s3.expect("present");
        assert_eq!(s3.connection.endpoint, "http://minio:9002");
        assert_eq!(s3.connection.bucket, "sflow-samples");
        assert_eq!(s3.prefix, "sflow");
        assert_eq!(s3.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(s3.flush_interval_secs, 900);
        assert_eq!(s3.channel_capacity, capacity_for(SFLOW_RECORD_BYTES));
        assert_eq!(s3.max_buffer_rows, 100_000);
    }

    #[test]
    fn sflow_s3_absent_means_no_persistence() {
        let toml_str = "[sflow]\nenabled = true\n";
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(cfg.sflow.s3.is_none());
    }

    #[test]
    fn sflow_is_disabled_by_default_in_main_config() {
        let cfg = Config::default();
        assert!(
            !cfg.sflow.enabled,
            "sflow must be opt-in (enabled=false by default)"
        );
    }

    #[test]
    fn sflow_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.sflow.local.is_none(),
            "absent [sflow.local] must deserialize to None"
        );
    }

    #[test]
    fn sflow_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/sflow"
prefix = "sflow"
flush_threshold_bytes = 52428800
flush_interval_secs = 300
channel_capacity = 512
max_buffer_rows = 50000
"#;
        let cfg: SflowLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            cfg.directory,
            std::path::PathBuf::from("/var/log/logthing/sflow")
        );
        assert_eq!(cfg.prefix, "sflow");
        assert_eq!(cfg.flush_threshold_bytes, 52_428_800);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
        assert_eq!(cfg.max_buffer_rows, 50_000);
    }

    #[test]
    fn sflow_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/sflow""#;
        let cfg: SflowLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.prefix, "sflow");
        assert_eq!(cfg.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, capacity_for(SFLOW_RECORD_BYTES));
        assert_eq!(cfg.max_buffer_rows, 100_000);
    }

    #[test]
    fn sflow_s3_and_local_can_both_be_configured_simultaneously() {
        let toml_str = r#"
[sflow]
enabled = true

[sflow.s3]
endpoint = "http://minio:9000"
bucket = "b"
region = "us-east-1"
access_key = "k"
secret_key = "s"

[sflow.local]
directory = "/data/sflow"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("deserialize");
        assert!(
            cfg.sflow.s3.is_some(),
            "s3 must deserialize when both present"
        );
        assert!(
            cfg.sflow.local.is_some(),
            "local must deserialize when both present"
        );
    }

    #[test]
    fn hec_disabled_by_default() {
        let cfg = Config::default();
        assert!(!cfg.hec.enabled, "hec must be disabled by default");
        assert_eq!(
            cfg.hec.max_sourcetype_partitions, 64,
            "default max_sourcetype_partitions must be 64"
        );
        assert!(cfg.hec.s3.is_none(), "absent [hec.s3] must yield None");
    }

    #[test]
    fn hec_s3_flat_toml_deserializes_correctly() {
        let toml_str = r#"
[hec]
enabled = true
token = "super-secret-token"
max_sourcetype_partitions = 32
[hec.s3]
endpoint   = "http://minio:9000"
bucket     = "hec-events"
region     = "us-east-1"
access_key = "KEY"
secret_key = "SECRET"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse hec config");
        assert!(cfg.hec.enabled);
        assert_eq!(cfg.hec.token, "super-secret-token");
        assert_eq!(cfg.hec.max_sourcetype_partitions, 32);
        let s3 = cfg.hec.s3.expect("s3 section present");
        assert_eq!(s3.connection.bucket, "hec-events");
        assert_eq!(s3.prefix, "hec"); // default prefix
        assert_eq!(s3.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(s3.flush_interval_secs, 900);
        assert_eq!(s3.channel_capacity, capacity_for(GENERIC_RECORD_BYTES));
        assert_eq!(s3.max_buffer_rows, 100_000);
    }

    #[test]
    fn hec_s3_absent_section_means_no_persistence() {
        let toml_str = "[hec]\nenabled = true\ntoken = \"tok\"\n";
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(cfg.hec.s3.is_none(), "absent [hec.s3] must yield None");
    }

    #[test]
    fn hec_local_absent_gives_none() {
        let cfg = Config::default();
        assert!(
            cfg.hec.local.is_none(),
            "absent [hec.local] must deserialize to None"
        );
    }

    #[test]
    fn hec_local_config_deserializes_from_toml() {
        let toml_str = r#"
directory = "/var/log/logthing/hec"
prefix = "hec"
flush_threshold_bytes = 52428800
flush_interval_secs = 300
channel_capacity = 512
max_buffer_rows = 50000
"#;
        let cfg: GenericLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(
            cfg.directory,
            std::path::PathBuf::from("/var/log/logthing/hec")
        );
        assert_eq!(cfg.prefix, "hec");
        assert_eq!(cfg.flush_threshold_bytes, 52_428_800);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.channel_capacity, 512);
        assert_eq!(cfg.max_buffer_rows, 50_000);
    }

    #[test]
    fn hec_local_config_defaults_apply_when_only_directory_given() {
        let toml_str = r#"directory = "/data/hec""#;
        let cfg: GenericLocalConfig = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(cfg.prefix, "hec");
        assert_eq!(cfg.flush_threshold_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.channel_capacity, capacity_for(GENERIC_RECORD_BYTES));
        assert_eq!(cfg.max_buffer_rows, 100_000);
    }

    #[test]
    fn otlp_config_defaults_disabled_no_token() {
        let cfg = Config::default();
        assert!(!cfg.otlp.enabled, "otlp must be opt-in (default false)");
        assert!(
            cfg.otlp.bearer_token.is_none(),
            "no bearer_token by default"
        );
    }

    #[test]
    fn otlp_config_parses_from_toml() {
        let toml_str = r#"
[otlp]
enabled = true
bearer_token = "s3cr3t"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(cfg.otlp.enabled);
        assert_eq!(cfg.otlp.bearer_token.as_deref(), Some("s3cr3t"));
    }

    #[test]
    fn otlp_config_absent_section_yields_defaults() {
        let toml_str = "[syslog]\nenabled = true\n";
        let cfg: Config = toml::from_str(toml_str).expect("parse");
        assert!(!cfg.otlp.enabled);
        assert!(cfg.otlp.bearer_token.is_none());
    }

    #[test]
    fn iceberg_config_absent_gives_none_none() {
        let cfg = Config::default();
        assert!(cfg.iceberg.s3.is_none());
        assert!(cfg.iceberg.local.is_none());
    }

    #[test]
    fn iceberg_s3_flat_toml_deserializes_correctly() {
        let toml_str = r#"
[iceberg.s3]
endpoint   = "http://minio:9000"
bucket     = "iceberg-descriptors"
region     = "us-east-1"
access_key = "KEY"
secret_key = "SECRET"
prefix     = "_iceberg_descriptors"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse config");
        let s3 = cfg.iceberg.s3.expect("s3 present");
        assert_eq!(s3.connection.bucket, "iceberg-descriptors");
        assert_eq!(s3.prefix, "_iceberg_descriptors");
        assert!(cfg.iceberg.local.is_none());
    }

    #[test]
    fn iceberg_s3_prefix_defaults_to_empty_when_absent() {
        let toml_str = r#"
[iceberg.s3]
endpoint   = "http://minio:9000"
bucket     = "iceberg-descriptors"
region     = "us-east-1"
access_key = "KEY"
secret_key = "SECRET"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse config");
        assert_eq!(cfg.iceberg.s3.unwrap().prefix, "");
    }

    #[test]
    fn iceberg_local_config_deserializes_from_toml() {
        let toml_str = r#"
[iceberg.local]
directory = "/var/log/logthing/iceberg-descriptors"
prefix    = "_iceberg_descriptors"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse config");
        let local = cfg.iceberg.local.expect("local present");
        assert_eq!(
            local.directory,
            std::path::PathBuf::from("/var/log/logthing/iceberg-descriptors")
        );
        assert_eq!(local.prefix, "_iceberg_descriptors");
    }

    #[test]
    fn validate_iceberg_config_ok_when_only_s3_set() {
        let cfg = IcebergConfig {
            s3: Some(IcebergDescriptorS3Config {
                connection: S3ConnectionConfig {
                    endpoint: "http://minio:9000".to_string(),
                    bucket: "b".to_string(),
                    region: "us-east-1".to_string(),
                    access_key: "k".to_string(),
                    secret_key: "s".to_string(),
                },
                prefix: String::new(),
            }),
            local: None,
        };
        assert!(validate_iceberg_config(&cfg).is_ok());
    }

    #[test]
    fn validate_iceberg_config_ok_when_neither_set() {
        assert!(validate_iceberg_config(&IcebergConfig::default()).is_ok());
    }

    #[test]
    fn validate_iceberg_config_errs_when_both_s3_and_local_set() {
        let cfg = IcebergConfig {
            s3: Some(IcebergDescriptorS3Config {
                connection: S3ConnectionConfig {
                    endpoint: "http://minio:9000".to_string(),
                    bucket: "my-bucket".to_string(),
                    region: "us-east-1".to_string(),
                    access_key: "k".to_string(),
                    secret_key: "s".to_string(),
                },
                prefix: String::new(),
            }),
            local: Some(IcebergDescriptorLocalConfig {
                directory: std::path::PathBuf::from("/data/iceberg"),
                prefix: String::new(),
            }),
        };
        let err = validate_iceberg_config(&cfg).expect_err("must reject both configured");
        let msg = err.to_string();
        assert!(
            msg.contains("my-bucket"),
            "error must name the s3 bucket: {msg}"
        );
        assert!(
            msg.contains("/data/iceberg"),
            "error must name the local directory: {msg}"
        );
    }

    #[test]
    fn env_vars_override_iceberg_s3_config() {
        let vars: &[(&str, &str)] = &[
            ("WEF__ICEBERG__S3__ENDPOINT", "http://minio-test:9000"),
            ("WEF__ICEBERG__S3__BUCKET", "env-override-bucket"),
            ("WEF__ICEBERG__S3__REGION", "eu-west-1"),
            ("WEF__ICEBERG__S3__ACCESS_KEY", "envkey"),
            ("WEF__ICEBERG__S3__SECRET_KEY", "envsecret"),
            ("WEF__ICEBERG__S3__PREFIX", "env-prefix"),
        ];
        for (k, v) in vars {
            unsafe { std::env::set_var(k, v) };
        }
        let result = std::panic::catch_unwind(|| {
            let cfg = Config::load().expect("config loads with env overrides");
            let s3 = cfg
                .iceberg
                .s3
                .expect("iceberg.s3 must be present via env vars");
            assert_eq!(s3.connection.endpoint, "http://minio-test:9000");
            assert_eq!(s3.connection.bucket, "env-override-bucket");
            assert_eq!(s3.connection.region, "eu-west-1");
            assert_eq!(s3.prefix, "env-prefix");
        });
        for (k, _) in vars {
            unsafe { std::env::remove_var(k) };
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[test]
    fn channel_capacity_defaults_derive_from_the_budget() {
        assert_eq!(
            default_zeek_channel_capacity(),
            capacity_for(ZEEK_RECORD_BYTES)
        );
        assert_eq!(
            default_suricata_channel_capacity(),
            capacity_for(SURICATA_RECORD_BYTES)
        );
        assert_eq!(
            default_hec_channel_capacity(),
            capacity_for(GENERIC_RECORD_BYTES)
        );
        assert_eq!(
            default_syslog_s3_channel_capacity(),
            capacity_for(SYSLOG_MESSAGE_BYTES)
        );
        assert_eq!(
            default_sflow_channel_capacity(),
            capacity_for(SFLOW_RECORD_BYTES)
        );
        assert_eq!(
            default_ipfix_channel_capacity(),
            capacity_for(IPFIX_DATAGRAM_BYTES)
        );
        assert_eq!(
            default_wef_channel_capacity(),
            capacity_for(WEF_EVENT_BYTES)
        );
    }

    #[test]
    fn channel_capacity_defaults_are_far_above_the_old_256() {
        // The incident this change addresses: 256 records is ~60-250ms of burst
        // headroom at realistic sensor rates.
        assert!(default_zeek_channel_capacity() > 10_000);
        assert!(default_suricata_channel_capacity() > 10_000);
    }

    #[test]
    fn aggregate_config_defaults_to_disabled_and_inert() {
        let cfg: AggregateConfig = toml::from_str("").expect("empty aggregate section parses");
        assert!(!cfg.enabled, "aggregation must default to off");
        assert_eq!(cfg.flush_interval_secs, 900);
        assert_eq!(cfg.max_groups, 100_000);
        assert!(cfg.rules.is_empty());
        assert!(cfg.s3.is_none());
        assert!(cfg.local.is_none());
    }

    #[test]
    fn aggregate_rule_parses_full_toml_shape() {
        let toml_src = r#"
enabled = true
flush_interval_secs = 300
max_groups = 5000

[local]
directory = "/data/agg"
prefix = "aggregate"

[[rules]]
name = "dns_by_query"
source = "zeek"
stream = "dns"
group_by = ["query", "id.orig_h"]

[[rules]]
name = "flow_talkers"
source = "ipfix"
group_by = ["src_addr", "dst_addr"]
sum = ["octet_delta_count"]
"#;
        let cfg: AggregateConfig = toml::from_str(toml_src).expect("parses");
        assert!(cfg.enabled);
        assert_eq!(cfg.flush_interval_secs, 300);
        assert_eq!(cfg.max_groups, 5000);
        assert_eq!(cfg.rules.len(), 2);

        assert_eq!(cfg.rules[0].name, "dns_by_query");
        assert_eq!(cfg.rules[0].stream.as_deref(), Some("dns"));
        assert_eq!(cfg.rules[0].group_by, vec!["query", "id.orig_h"]);
        assert!(
            cfg.rules[0].sum.is_empty(),
            "omitted sum must default empty"
        );

        assert_eq!(cfg.rules[1].source, "ipfix");
        assert_eq!(
            cfg.rules[1].stream, None,
            "omitted stream means all records"
        );
        assert_eq!(cfg.rules[1].sum, vec!["octet_delta_count"]);

        let local = cfg.local.expect("local target present");
        assert_eq!(local.directory, std::path::PathBuf::from("/data/agg"));
        assert_eq!(local.prefix, "aggregate");
    }

    #[test]
    fn aggregate_local_prefix_defaults_to_aggregate() {
        let cfg: AggregateLocalConfig =
            toml::from_str(r#"directory = "/tmp/x""#).expect("parses without prefix");
        assert_eq!(cfg.prefix, "aggregate");
    }

    #[test]
    fn aggregate_s3_prefix_defaults_to_aggregate() {
        let toml_src = r#"
endpoint = "http://localhost:9000"
bucket = "agg-bucket"
region = "us-east-1"
access_key = "minioadmin"
secret_key = "minioadmin"
"#;
        let cfg: AggregateS3Config =
            toml::from_str(toml_src).expect("parses s3 config with flattened connection fields");
        assert_eq!(cfg.connection.endpoint, "http://localhost:9000");
        assert_eq!(cfg.connection.bucket, "agg-bucket");
        assert_eq!(cfg.connection.region, "us-east-1");
        assert_eq!(cfg.connection.access_key, "minioadmin");
        assert_eq!(cfg.connection.secret_key, "minioadmin");
        assert_eq!(
            cfg.prefix, "aggregate",
            "prefix defaults to aggregate when omitted"
        );
    }
}
