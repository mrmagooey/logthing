use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Basic};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;

use crate::admin::auth::ensure_authorized;
use crate::admin::state::AdminState;
use crate::config::{ADMIN_OVERRIDE_FILE, Config, S3ConnectionConfig};

const REDACTED: &str = "***REDACTED***";

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

/// Produce a sanitised copy of `cfg` where every `access_key` / `secret_key`
/// field is replaced with `***REDACTED***`.
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

    out
}

/// Structural validation of a candidate `Config` that must hold before the
/// config is accepted by any write path (update / import / reload).
///
/// Returns `Ok(())` if the config is acceptable, or `Err(message)` describing
/// the first/all invariant violations found.
///
/// Invariants checked:
/// - `bind_address.port() != 0` — port 0 is a hard error (unknown OS port).
/// - If `tls.enabled`, both `cert_file` and `key_file` must be present —
///   without them `run_tls()` would `.expect()` and panic at startup.
pub fn validate_config_invariants(cfg: &Config) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();

    if cfg.bind_address.port() == 0 {
        errors.push("bind_address port cannot be 0".to_string());
    }

    if cfg.tls.enabled {
        if cfg.tls.cert_file.is_none() {
            errors.push("tls.enabled is true but tls.cert_file is not set".to_string());
        }
        if cfg.tls.key_file.is_none() {
            errors.push("tls.enabled is true but tls.key_file is not set".to_string());
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Validation result for configuration
#[derive(Serialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Validate configuration endpoint
pub async fn validate_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    Json(config_to_validate): Json<Config>,
) -> Result<Json<ValidationResult>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, auth, &client_ip).await?;

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Validate bind address
    if config_to_validate.bind_address.port() == 0 {
        errors.push("Bind address port cannot be 0".to_string());
    }

    // Validate TLS configuration
    if config_to_validate.tls.enabled {
        if config_to_validate.tls.cert_file.is_none() {
            errors.push("TLS is enabled but cert_file is not set".to_string());
        }
        if config_to_validate.tls.key_file.is_none() {
            errors.push("TLS is enabled but key_file is not set".to_string());
        }
        if config_to_validate.tls.require_client_cert && config_to_validate.tls.ca_file.is_none() {
            errors.push("TLS client cert is required but ca_file is not set".to_string());
        }
    }

    // Validate forwarding destinations
    for dest in &config_to_validate.forwarding.destinations {
        if dest.name.is_empty() {
            errors.push("Forwarding destination name cannot be empty".to_string());
        }
        if dest.url.is_empty() {
            errors.push(format!(
                "Forwarding destination '{}' URL cannot be empty",
                dest.name
            ));
        }
    }

    // Validate metrics port
    if config_to_validate.metrics.enabled && config_to_validate.metrics.port == 0 {
        warnings.push("Metrics port is set to 0, metrics server may fail to start".to_string());
    }

    // Validate syslog ports
    if config_to_validate.syslog.enabled
        && config_to_validate.syslog.udp_port == 0
        && config_to_validate.syslog.tcp_port == 0
    {
        warnings.push("Syslog is enabled but both UDP and TCP ports are 0".to_string());
    }

    // Check if ports conflict
    let current_cfg = state.config.read().await;
    let admin_port = state.server_config.bind_address.port();
    if config_to_validate.bind_address.port() == admin_port {
        warnings.push(format!(
            "Main server port {} conflicts with admin interface port",
            admin_port
        ));
    }
    drop(current_cfg);

    let result = ValidationResult {
        valid: errors.is_empty(),
        errors,
        warnings,
    };

    state
        .audit_logger
        .log(
            "CONFIG_VALIDATED",
            &username,
            &client_ip,
            Some(&format!("Valid: {}", result.valid)),
        )
        .await;

    Ok(Json(result))
}

/// Config diff result
#[derive(Serialize)]
pub struct ConfigDiff {
    pub changed: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub unchanged: Vec<String>,
}

/// Diff configuration endpoint
pub async fn diff_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    Json(proposed_config): Json<Config>,
) -> Result<Json<ConfigDiff>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, auth, &client_ip).await?;

    let current = state.config.read().await.clone();

    let current_json = serde_json::to_value(&current).unwrap();
    let proposed_json = serde_json::to_value(&proposed_config).unwrap();

    let mut diff = ConfigDiff {
        changed: Vec::new(),
        added: Vec::new(),
        removed: Vec::new(),
        unchanged: Vec::new(),
    };

    fn compare_values(
        path: &str,
        current: &serde_json::Value,
        proposed: &serde_json::Value,
        diff: &mut ConfigDiff,
    ) {
        match (current, proposed) {
            (serde_json::Value::Object(curr_map), serde_json::Value::Object(prop_map)) => {
                // Check for added keys
                for (key, value) in prop_map {
                    let new_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };

                    if let Some(curr_val) = curr_map.get(key) {
                        if curr_val != value {
                            diff.changed.push(new_path);
                        } else {
                            diff.unchanged.push(new_path);
                        }
                    } else {
                        diff.added.push(new_path);
                    }
                }

                // Check for removed keys
                for (key, _) in curr_map {
                    if !prop_map.contains_key(key) {
                        let new_path = if path.is_empty() {
                            key.clone()
                        } else {
                            format!("{}.{}", path, key)
                        };
                        diff.removed.push(new_path);
                    }
                }
            }
            _ => {
                if current != proposed {
                    diff.changed.push(path.to_string());
                } else {
                    diff.unchanged.push(path.to_string());
                }
            }
        }
    }

    compare_values("", &current_json, &proposed_json, &mut diff);

    state
        .audit_logger
        .log(
            "CONFIG_DIFF",
            &username,
            &client_ip,
            Some(&format!("{} changes", diff.changed.len())),
        )
        .await;

    Ok(Json(diff))
}

/// Export configuration endpoint
pub async fn export_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Response, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, auth, &client_ip).await?;

    let cfg = redacted_config(&*state.config.read().await);

    // Export as TOML (primary format).
    // NOTE: Credentials are redacted in the export; an import of this file will
    // require re-entering secrets.  This is intentional — a security export
    // must never contain live credentials.
    let toml_content = match toml::to_string_pretty(&cfg) {
        Ok(content) => content,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to serialize config: {}", e),
            )
                .into_response());
        }
    };

    state
        .audit_logger
        .log("CONFIG_EXPORTED", &username, &client_ip, None)
        .await;

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/toml"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"logthing-backup.toml\"",
            ),
        ],
        toml_content,
    )
        .into_response())
}

/// Import configuration endpoint
pub async fn import_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    body: Bytes,
) -> Result<Json<Config>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, auth, &client_ip).await?;

    // Try to parse as TOML first, then JSON
    let imported_config: Config = if let Ok(content_str) = std::str::from_utf8(&body) {
        if let Ok(config) = toml::from_str(content_str) {
            config
        } else if let Ok(config) = serde_json::from_str(content_str) {
            config
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                "Failed to parse config: invalid TOML or JSON format",
            )
                .into_response());
        }
    } else {
        return Err((StatusCode::BAD_REQUEST, "Invalid UTF-8 content").into_response());
    };

    // H-7: validate before touching shared state.
    if let Err(msg) = validate_config_invariants(&imported_config) {
        return Err((StatusCode::BAD_REQUEST, format!("Validation failed: {msg}")).into_response());
    }

    // H-7: persist first; only swap in-memory state on success so on-disk and
    // running configs never diverge.
    if let Err(err) = persist_config(&imported_config).await {
        tracing::error!("Failed to persist imported config: {}", err);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to persist imported configuration",
        )
            .into_response());
    }

    // Persist succeeded — now update in-memory state.
    let updated_config = {
        let mut cfg = state.config.write().await;
        *cfg = imported_config;
        cfg.clone()
    };

    state
        .audit_logger
        .log("CONFIG_IMPORTED", &username, &client_ip, None)
        .await;

    tracing::info!("Configuration imported by {} from {}", username, client_ip);

    Ok(Json(redacted_config(&updated_config)))
}

/// Reload configuration endpoint (re-read from disk)
pub async fn reload_config(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Json<Config>, Response> {
    let client_ip = addr.ip().to_string();
    let username = ensure_authorized(&state, auth, &client_ip).await?;

    // Reload config from disk
    let reloaded_config = match Config::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::error!("Failed to reload config: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to reload configuration: {}", e),
            )
                .into_response());
        }
    };

    // H-7: validate the on-disk config before replacing the running one.
    if let Err(msg) = validate_config_invariants(&reloaded_config) {
        tracing::error!("Reloaded config failed validation: {}", msg);
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Reloaded configuration is invalid: {msg}"),
        )
            .into_response());
    }

    // Validation passed — swap in-memory state.
    let updated_config = {
        let mut cfg = state.config.write().await;
        *cfg = reloaded_config;
        cfg.clone()
    };

    state
        .audit_logger
        .log("CONFIG_RELOADED", &username, &client_ip, None)
        .await;

    tracing::info!("Configuration reloaded by {} from {}", username, client_ip);

    Ok(Json(redacted_config(&updated_config)))
}

/// Partial config update request
#[derive(Deserialize, Default, Serialize)]
pub struct PartialConfigUpdate {
    pub bind_address: Option<std::net::SocketAddr>,
    pub tls_enabled: Option<bool>,
    pub tls_port: Option<u16>,
    pub logging_level: Option<String>,
    pub metrics_enabled: Option<bool>,
    pub metrics_port: Option<u16>,
    pub syslog_enabled: Option<bool>,
    pub syslog_udp_port: Option<u16>,
    pub syslog_tcp_port: Option<u16>,
}

/// Persist configuration to file
pub async fn persist_config(config: &Config) -> anyhow::Result<()> {
    let path = std::env::var("WEF_ADMIN_OVERRIDE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(ADMIN_OVERRIDE_FILE));

    write_config_to_path(config, &path).await
}

/// Write configuration to a specific path
pub async fn write_config_to_path(config: &Config, path: &std::path::Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).await.ok();
    }
    let contents = toml::to_string_pretty(config)?;
    fs::write(path, contents).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::state::{AdminServerConfig, AdminState, AuditLogger, PasswordHash};
    use crate::config::{S3ConnectionConfig, SyslogS3Config};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    async fn make_state_with_s3_secrets() -> AdminState {
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "admin".to_string(),
            password_hash: PasswordHash::hash("admin").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_csrf: false,
            enable_rate_limiting: false,
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
            csrf_tokens: Arc::new(RwLock::new(Vec::new())),
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
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

    // H-6: the JSON serialised by get_config / export_config must not contain real secrets.
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

    // H-7: validate_config_invariants rejects port 0.
    #[test]
    fn validate_config_invariants_rejects_port_zero() {
        let mut cfg = Config::default();
        cfg.bind_address = "127.0.0.1:0".parse().unwrap();
        cfg.tls.enabled = false;
        assert!(
            validate_config_invariants(&cfg).is_err(),
            "port 0 must be rejected"
        );
        let msg = validate_config_invariants(&cfg).unwrap_err();
        assert!(msg.contains("port cannot be 0"), "error: {msg}");
    }

    // H-7: validate_config_invariants rejects TLS enabled without cert/key.
    #[test]
    fn validate_config_invariants_rejects_tls_without_cert() {
        let mut cfg = Config::default();
        cfg.tls.enabled = true;
        cfg.tls.cert_file = None;
        cfg.tls.key_file = None;
        let result = validate_config_invariants(&cfg);
        assert!(result.is_err(), "TLS without cert/key must be rejected");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("cert_file") || msg.contains("key_file"),
            "error: {msg}"
        );
    }

    // H-7: validate_config_invariants accepts a valid config.
    #[test]
    fn validate_config_invariants_accepts_valid_config() {
        let mut cfg = Config::default();
        cfg.tls.enabled = false; // TLS off → no cert required
        assert!(
            validate_config_invariants(&cfg).is_ok(),
            "valid config must be accepted"
        );
    }

    // H-7: validate_config_invariants accepts TLS enabled with cert+key present.
    #[test]
    fn validate_config_invariants_accepts_tls_with_cert_and_key() {
        let mut cfg = Config::default();
        cfg.tls.enabled = true;
        cfg.tls.cert_file = Some(std::path::PathBuf::from("/etc/certs/server.crt"));
        cfg.tls.key_file = Some(std::path::PathBuf::from("/etc/certs/server.key"));
        assert!(
            validate_config_invariants(&cfg).is_ok(),
            "TLS with cert+key must be accepted"
        );
    }

    // H-7: import_config rejects a config with port 0 (running config unchanged).
    #[tokio::test]
    async fn import_config_rejects_port_zero_and_leaves_running_config_unchanged() {
        let state = make_state_with_s3_secrets().await;

        use axum_extra::extract::TypedHeader;
        use headers::Authorization;
        let auth = TypedHeader(Authorization::basic("admin", "admin"));
        let addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let invalid_toml = br#"bind_address = "127.0.0.1:0""#;

        let result = import_config(
            axum::extract::State(state.clone()),
            axum::extract::ConnectInfo(addr),
            Some(auth),
            axum::body::Bytes::from_static(invalid_toml),
        )
        .await;

        // Must be rejected.
        assert!(result.is_err(), "port-0 config must be rejected");

        // Running config must be unchanged.
        let running_port = state.config.read().await.bind_address.port();
        assert_ne!(running_port, 0, "running config must not have been swapped");
    }

    // H-7: import_config rejects TLS-without-cert config.
    #[tokio::test]
    async fn import_config_rejects_tls_without_cert() {
        let state = make_state_with_s3_secrets().await;

        use axum_extra::extract::TypedHeader;
        use headers::Authorization;
        let auth = TypedHeader(Authorization::basic("admin", "admin"));
        let addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let invalid_toml = br#"
bind_address = "0.0.0.0:5985"
[tls]
enabled = true
"#;

        let result = import_config(
            axum::extract::State(state),
            axum::extract::ConnectInfo(addr),
            Some(auth),
            axum::body::Bytes::from_static(invalid_toml),
        )
        .await;

        // Must be rejected.
        assert!(result.is_err(), "TLS-without-cert config must be rejected");
    }
}
