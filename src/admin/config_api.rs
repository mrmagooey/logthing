use crate::config::{Config, S3ConnectionConfig};

const REDACTED: &str = "***REDACTED***";

/// Test-only helpers shared across `admin::*` test modules.
///
/// `LOGTHING_ADMIN_AUDIT_LOG` is a process-global env var, but cargo runs
/// `#[tokio::test]` functions concurrently within one process. Every test
/// (in this module or `admin::mod`) that points the var at a temp path must
/// serialize against every other such test crate-wide, or one test's
/// cleanup can clear another's override mid-flight and let its
/// `AuditLogger::new()` call fall through to the real on-disk audit log.
#[cfg(test)]
pub(crate) mod test_support {
    static AUDIT_LOG_ENV_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    /// Locks the shared mutex serializing every test that points
    /// `LOGTHING_ADMIN_AUDIT_LOG` at a temp path.
    pub(crate) async fn lock_audit_log_env() -> tokio::sync::MutexGuard<'static, ()> {
        AUDIT_LOG_ENV_LOCK.lock().await
    }
}

/// Return a copy of an `S3ConnectionConfig` with credentials replaced by a
/// placeholder so they can never appear in API responses.
fn redact_s3_connection(conn: &S3ConnectionConfig) -> S3ConnectionConfig {
    S3ConnectionConfig {
        endpoint: conn.endpoint.clone(),
        bucket: conn.bucket.clone(),
        region: conn.region.clone(),
        access_key: REDACTED.to_string(),
        secret_key: REDACTED.to_string(),
    }
}

/// Redact a shared-secret token field (`hec.token`, `syslog.http_token`).
///
/// An empty token is each field's documented "auth disabled" default — not a
/// secret. Masking it would turn "no auth configured" into the literal
/// sentinel string on every `GET /config`, which a client (or a re-imported
/// export) would then treat as a real, enforced token. So only a non-empty
/// token is replaced with the sentinel; empty stays empty.
fn redact_token(token: &str) -> String {
    if token.is_empty() {
        String::new()
    } else {
        REDACTED.to_string()
    }
}

/// Same as `redact_token`, for the `Option<String>` shape used by
/// `otlp.bearer_token`, where both `None` and `Some("")` mean auth is
/// disabled (see `OtlpConfig::bearer_token`'s doc comment).
fn redact_optional_token(token: &Option<String>) -> Option<String> {
    match token {
        Some(t) if !t.is_empty() => Some(REDACTED.to_string()),
        other => other.clone(),
    }
}

/// Produce a sanitised copy of `cfg` where every `access_key` / `secret_key`
/// field, and every configured ingest shared-secret token
/// (`hec.token`, `otlp.bearer_token`, `syslog.http_token`), is replaced with
/// `***REDACTED***`.
///
/// NOTE: export → import round-trips will lose the real credentials — that is
/// intentional.  A security-export must never contain live secrets.
pub fn redacted_config(cfg: &Config) -> Config {
    let mut out = cfg.clone();

    if let Some(ref mut s3) = out.syslog.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.ipfix.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.zeek.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.syslog.structured_s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.suricata.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.wef.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.hec.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.sflow.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.aggregate.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }
    if let Some(ref mut s3) = out.iceberg.s3 {
        s3.connection = redact_s3_connection(&s3.connection);
    }

    out.hec.token = redact_token(&out.hec.token);
    out.otlp.bearer_token = redact_optional_token(&out.otlp.bearer_token);
    out.syslog.http_token = redact_token(&out.syslog.http_token);

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::state::{AdminServerConfig, AdminState, AuditLogger, PasswordHash};
    use crate::config::SyslogS3Config;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    async fn make_state_with_s3_secrets() -> AdminState {
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_rate_limiting: false,
            trusted_header: None,
        };

        let mut cfg = Config::default();
        cfg.syslog.s3 = Some(SyslogS3Config {
            connection: S3ConnectionConfig {
                endpoint: "http://minio:9000".to_string(),
                bucket: "logs".to_string(),
                region: "us-east-1".to_string(),
                access_key: "REAL_ACCESS_KEY".to_string(),
                secret_key: "REAL_SECRET_KEY".to_string(),
            },
            prefix: "syslog".to_string(),
            max_buffer_rows: 10_000,
            flush_interval_secs: 900,
            channel_capacity: 4_096,
        });

        AdminState {
            config: Arc::new(RwLock::new(cfg)),
            server_config,
            audit_logger: AuditLogger::new(100).await,
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
        }
    }

    // H-6: redacted_config must replace credentials with placeholder.
    #[tokio::test]
    async fn redacted_config_masks_syslog_s3_secrets() {
        let state = make_state_with_s3_secrets().await;
        let cfg = state.config.read().await.clone();
        let out = redacted_config(&cfg);

        let s3 = out.syslog.s3.expect("s3 present");
        assert_eq!(s3.connection.access_key, REDACTED);
        assert_eq!(s3.connection.secret_key, REDACTED);
        // Non-secret fields are preserved.
        assert_eq!(s3.connection.bucket, "logs");
        assert_eq!(s3.connection.endpoint, "http://minio:9000");
    }

    // H-6: the JSON serialised by get_config must not contain real secrets.
    #[tokio::test]
    async fn redacted_config_json_contains_no_real_secrets() {
        let state = make_state_with_s3_secrets().await;
        let cfg = state.config.read().await.clone();
        let out = redacted_config(&cfg);

        let json = serde_json::to_string(&out).unwrap();
        assert!(
            !json.contains("REAL_ACCESS_KEY"),
            "access_key must not appear in JSON: {json}"
        );
        assert!(
            !json.contains("REAL_SECRET_KEY"),
            "secret_key must not appear in JSON: {json}"
        );
        assert!(json.contains(REDACTED));
    }

    // H-6: export serialises to TOML and must not contain real secrets.
    #[tokio::test]
    async fn redacted_config_toml_contains_no_real_secrets() {
        let state = make_state_with_s3_secrets().await;
        let cfg = state.config.read().await.clone();
        let out = redacted_config(&cfg);

        let toml_str = toml::to_string_pretty(&out).unwrap();
        assert!(
            !toml_str.contains("REAL_ACCESS_KEY"),
            "access_key must not appear in TOML export: {toml_str}"
        );
        assert!(
            !toml_str.contains("REAL_SECRET_KEY"),
            "secret_key must not appear in TOML export: {toml_str}"
        );
        assert!(toml_str.contains(REDACTED));
    }

    // A3: redacted_config (what GET /config, /config/export, and
    // /config/reload all return) must mask the three ingest shared-secret
    // tokens the same way it masks S3 credentials.
    #[test]
    fn redacted_config_masks_ingest_tokens() {
        let mut cfg = Config::default();
        cfg.hec.token = "REAL_HEC_TOKEN".to_string();
        cfg.otlp.bearer_token = Some("REAL_OTLP_TOKEN".to_string());
        cfg.syslog.http_token = "REAL_SYSLOG_TOKEN".to_string();

        let out = redacted_config(&cfg);

        assert_eq!(out.hec.token, REDACTED);
        assert_eq!(out.otlp.bearer_token.as_deref(), Some(REDACTED));
        assert_eq!(out.syslog.http_token, REDACTED);

        let json = serde_json::to_string(&out).unwrap();
        assert!(!json.contains("REAL_HEC_TOKEN"), "hec.token leaked: {json}");
        assert!(
            !json.contains("REAL_OTLP_TOKEN"),
            "otlp.bearer_token leaked: {json}"
        );
        assert!(
            !json.contains("REAL_SYSLOG_TOKEN"),
            "syslog.http_token leaked: {json}"
        );
    }

    // A3: an unset token (empty string / None) means auth is disabled for that
    // route — it must stay empty, not become the literal sentinel, otherwise a
    // round trip would turn "no auth configured" into a live-looking token.
    #[test]
    fn redacted_config_leaves_unset_ingest_tokens_empty() {
        let cfg = Config::default();
        assert_eq!(cfg.hec.token, "");
        assert_eq!(cfg.otlp.bearer_token, None);
        assert_eq!(cfg.syslog.http_token, "");

        let out = redacted_config(&cfg);

        assert_eq!(out.hec.token, "", "unset hec.token must stay empty");
        assert_eq!(
            out.otlp.bearer_token, None,
            "unset otlp.bearer_token must stay None"
        );
        assert_eq!(
            out.syslog.http_token, "",
            "unset syslog.http_token must stay empty"
        );
    }

    /// Sets every S3-bearing config section's `access_key`/`secret_key` to
    /// the given sentinels. Each `*S3Config` struct flattens
    /// `S3ConnectionConfig` and defaults every other field via
    /// `#[serde(default)]`, so deserializing a bare connection JSON object
    /// into it fills in real (non-secret) defaults for the rest — no need to
    /// hand-list every struct's non-secret fields here, and it stays correct
    /// if those structs grow more fields later.
    fn populate_all_s3_sections(cfg: &mut Config, access_key: &str, secret_key: &str) {
        let conn = serde_json::json!({
            "endpoint": "http://minio:9000",
            "bucket": "logs",
            "region": "us-east-1",
            "access_key": access_key,
            "secret_key": secret_key,
        });
        cfg.syslog.s3 = Some(serde_json::from_value(conn.clone()).unwrap());
        cfg.syslog.structured_s3 = Some(serde_json::from_value(conn.clone()).unwrap());
        cfg.ipfix.s3 = Some(serde_json::from_value(conn.clone()).unwrap());
        cfg.zeek.s3 = Some(serde_json::from_value(conn.clone()).unwrap());
        cfg.suricata.s3 = Some(serde_json::from_value(conn.clone()).unwrap());
        cfg.wef.s3 = Some(serde_json::from_value(conn.clone()).unwrap());
        cfg.hec.s3 = Some(serde_json::from_value(conn.clone()).unwrap());
        cfg.sflow.s3 = Some(serde_json::from_value(conn.clone()).unwrap());
        cfg.aggregate.s3 = Some(serde_json::from_value(conn.clone()).unwrap());
        cfg.iceberg.s3 = Some(serde_json::from_value(conn).unwrap());
    }

    /// Every S3-bearing config section must be redacted, not just the three that
    /// were originally covered. This test enumerates all ten so that adding an
    /// eleventh section without redacting it fails here.
    #[test]
    fn redacted_config_masks_every_s3_section() {
        const SENTINEL_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
        const SENTINEL_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

        let mut cfg = Config::default();
        populate_all_s3_sections(&mut cfg, SENTINEL_KEY, SENTINEL_SECRET);

        let redacted = redacted_config(&cfg);
        let json = serde_json::to_string(&redacted).expect("serialize redacted config");

        assert!(
            !json.contains(SENTINEL_KEY),
            "a plaintext access_key survived redaction: {json}"
        );
        assert!(
            !json.contains(SENTINEL_SECRET),
            "a plaintext secret_key survived redaction: {json}"
        );
    }
}
