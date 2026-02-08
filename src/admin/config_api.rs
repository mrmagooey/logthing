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
use crate::config::{ADMIN_OVERRIDE_FILE, Config};

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
            errors.push(format!("Forwarding destination '{}' URL cannot be empty", dest.name));
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
        .log("CONFIG_VALIDATED", &username, &client_ip, Some(&format!("Valid: {}", result.valid)))
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
        .log("CONFIG_DIFF", &username, &client_ip, Some(&format!("{} changes", diff.changed.len())))
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

    let cfg = state.config.read().await.clone();

    // Export as TOML (primary format)
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
            (header::CONTENT_DISPOSITION, "attachment; filename=\"wef-server-backup.toml\""),
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
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid UTF-8 content",
        )
            .into_response());
    };

    // Validate before applying
    let mut errors = Vec::new();
    if imported_config.bind_address.port() == 0 {
        errors.push("Bind address port cannot be 0".to_string());
    }

    if !errors.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Validation failed: {}", errors.join(", ")),
        )
            .into_response());
    }

    // Apply the imported config
    let updated_config = {
        let mut cfg = state.config.write().await;
        *cfg = imported_config;
        cfg.clone()
    };

    // Persist to file
    if let Err(err) = persist_config(&updated_config).await {
        tracing::error!("Failed to persist imported config: {}", err);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to persist imported configuration",
        )
            .into_response());
    }

    state
        .audit_logger
        .log("CONFIG_IMPORTED", &username, &client_ip, None)
        .await;

    tracing::info!("Configuration imported by {} from {}", username, client_ip);

    Ok(Json(updated_config))
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

    // Apply the reloaded config
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

    Ok(Json(updated_config))
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
