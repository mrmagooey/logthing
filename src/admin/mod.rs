use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Basic};
use std::path::Path;
use tokio::{fs, net::TcpListener, sync::RwLock};
use tracing::{error, info, warn};

use crate::config::{ADMIN_OVERRIDE_FILE, Config};

#[derive(Clone)]
struct AdminState {
    config: Arc<RwLock<Config>>,
    username: Arc<String>,
    password: Arc<String>,
}

pub fn spawn_admin_server(config: Arc<RwLock<Config>>) {
    let username = std::env::var("WEF_ADMIN_USER").unwrap_or_else(|_| "admin".to_string());
    let password = std::env::var("WEF_ADMIN_PASS").unwrap_or_else(|_| "admin".to_string());

    if username == "admin" && password == "admin" {
        warn!("Admin interface is using default credentials; set WEF_ADMIN_USER/WEF_ADMIN_PASS");
    }

    tokio::spawn(async move {
        if let Err(err) = run_admin_server(config, username, password).await {
            error!("Admin server error: {}", err);
        }
    });
}

async fn run_admin_server(
    config: Arc<RwLock<Config>>,
    username: String,
    password: String,
) -> anyhow::Result<()> {
    let addr: SocketAddr = "0.0.0.0:8080".parse()?;
    let app = Router::new()
        .route("/", get(admin_page))
        .route("/config", get(get_config).put(update_config))
        .with_state(AdminState {
            config,
            username: Arc::new(username),
            password: Arc::new(password),
        });

    let listener = TcpListener::bind(addr).await?;
    info!("Admin interface available on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn get_config(
    State(state): State<AdminState>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Json<Config>, Response> {
    ensure_authorized(&state, auth).await?;
    let cfg = state.config.read().await;
    Ok(Json(cfg.clone()))
}

async fn admin_page(
    State(state): State<AdminState>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<Html<&'static str>, Response> {
    ensure_authorized(&state, auth).await?;
    Ok(Html(ADMIN_PAGE))
}

async fn update_config(
    State(state): State<AdminState>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    Json(new_config): Json<Config>,
) -> Result<Json<Config>, Response> {
    ensure_authorized(&state, auth).await?;
    let updated_config = {
        let mut cfg = state.config.write().await;
        *cfg = new_config;
        cfg.clone()
    };

    if let Err(err) = persist_config(&updated_config).await {
        error!("Failed to persist admin config: {}", err);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Persist failed").into_response());
    }

    info!("Configuration updated via admin API");
    Ok(Json(updated_config))
}

async fn persist_config(config: &Config) -> anyhow::Result<()> {
    if let Ok(path) = std::env::var("WEF_ADMIN_OVERRIDE_FILE") {
        write_config_to_path(config, Path::new(&path)).await
    } else {
        write_config_to_path(config, Path::new(ADMIN_OVERRIDE_FILE)).await
    }
}

async fn write_config_to_path(config: &Config, path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).await.ok();
        }
    }
    let contents = toml::to_string_pretty(config)?;
    fs::write(path, contents).await?;
    Ok(())
}

async fn ensure_authorized(
    state: &AdminState,
    auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Result<(), Response> {
    let Some(auth) = auth else {
        return Err(unauthorized());
    };
    let creds = auth.0;
    if creds.username() == state.username.as_str() && creds.password() == state.password.as_str() {
        Ok(())
    } else {
        Err(unauthorized())
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"WEF Admin\", charset=\"UTF-8\"",
        )],
        "Unauthorized",
    )
        .into_response()
}

const ADMIN_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>WEF Admin Console</title>
    <style>
        :root {
            color-scheme: light dark;
            --bg: linear-gradient(135deg, #101726 0%, #1e1c2a 45%, #1f2f3a 100%);
            --panel-bg: rgba(17, 24, 39, 0.75);
            --accent: #64d2ff;
            --accent-strong: #14b8a6;
            --text: #f4f6fb;
            --muted: #9ba5be;
            font-family: "Space Grotesk", "Segoe UI", system-ui, sans-serif;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            background: var(--bg);
            color: var(--text);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }
        .shell {
            width: min(1100px, 100%);
            background: var(--panel-bg);
            border-radius: 24px;
            padding: 2.5rem;
            box-shadow: 0 20px 50px rgba(0,0,0,0.35);
            border: 1px solid rgba(255,255,255,0.08);
            backdrop-filter: blur(12px);
        }
        h1 {
            margin: 0 0 0.5rem;
            font-size: 1.9rem;
            letter-spacing: 0.04em;
        }
        p.subtitle {
            margin: 0 0 2rem;
            color: var(--muted);
        }
        form {
            display: grid;
            gap: 1.5rem;
        }
        fieldset {
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 18px;
            padding: 1.5rem;
            background: rgba(255,255,255,0.01);
        }
        legend {
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            color: var(--accent);
            padding: 0 0.5rem;
        }
        label {
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
            font-size: 0.95rem;
            color: var(--muted);
        }
        input[type="text"],
        input[type="number"],
        textarea,
        select {
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 12px;
            padding: 0.65rem 0.85rem;
            font-size: 1rem;
            background: rgba(0,0,0,0.25);
            color: var(--text);
            font-family: inherit;
        }
        textarea { min-height: 5.5rem; resize: vertical; }
        .grid-2 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
        }
        .grid-3 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
        }
        .check-row {
            display: flex;
            align-items: center;
            gap: 0.6rem;
        }
        .check-row label {
            flex-direction: row;
            align-items: center;
            gap: 0.4rem;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--text);
        }
        .actions {
            display: flex;
            gap: 1rem;
            align-items: center;
            flex-wrap: wrap;
        }
        button {
            background: linear-gradient(120deg, var(--accent), var(--accent-strong));
            border: none;
            color: #051923;
            font-weight: 600;
            font-size: 1rem;
            letter-spacing: 0.04em;
            padding: 0.85rem 1.8rem;
            border-radius: 999px;
            cursor: pointer;
            transition: transform 120ms ease;
        }
        button:hover { transform: translateY(-1px) scale(1.01); }
        #status {
            font-size: 0.95rem;
            min-height: 1.2rem;
        }
        #status.ok { color: #5befc0; }
        #status.err { color: #ff6b6b; }
        @media (max-width: 700px) {
            body { padding: 1rem; }
            .shell { padding: 1.5rem; }
        }
    </style>
</head>
<body>
    <div class="shell">
        <h1>WEF Admin Console</h1>
        <p class="subtitle">Inspect and adjust runtime configuration. Changes persist to <code>wef-server.admin.toml</code>.</p>
        <form id="config-form">
            <fieldset>
                <legend>Core</legend>
                <div class="grid-2">
                    <label>Bind Address
                        <input type="text" name="bind_address" required />
                    </label>
                    <label>Log Level
                        <select name="logging_level">
                            <option value="trace">trace</option>
                            <option value="debug">debug</option>
                            <option value="info">info</option>
                            <option value="warn">warn</option>
                            <option value="error">error</option>
                        </select>
                    </label>
                    <label>Log Format
                        <select name="logging_format">
                            <option value="pretty">pretty</option>
                            <option value="json">json</option>
                        </select>
                    </label>
                </div>
            </fieldset>

            <fieldset>
                <legend>TLS</legend>
                <div class="grid-3">
                    <label>Port
                        <input type="number" name="tls_port" min="1" max="65535" />
                    </label>
                    <label>Certificate File
                        <input type="text" name="tls_cert" />
                    </label>
                    <label>Key File
                        <input type="text" name="tls_key" />
                    </label>
                    <label>CA File
                        <input type="text" name="tls_ca" />
                    </label>
                </div>
                <div class="check-row">
                    <label><input type="checkbox" name="tls_enabled" /> TLS Enabled</label>
                    <label><input type="checkbox" name="tls_require_client" /> Require Client Cert</label>
                </div>
            </fieldset>

            <fieldset>
                <legend>Security</legend>
                <div class="grid-3">
                    <label>Max Connections
                        <input type="number" name="security_max_connections" min="1" />
                    </label>
                    <label>Connection Timeout (secs)
                        <input type="number" name="security_timeout" min="0" />
                    </label>
                </div>
                <label>Allowed IPs (one per line)
                    <textarea name="security_allowed_ips" placeholder="192.168.0.0/24"></textarea>
                </label>
            </fieldset>

            <fieldset>
                <legend>Forwarding</legend>
                <div class="grid-3">
                    <label>Buffer Size
                        <input type="number" name="forwarding_buffer_size" min="0" />
                    </label>
                    <label>Retry Attempts
                        <input type="number" name="forwarding_retry_attempts" min="0" />
                    </label>
                </div>
                <label>Destinations (JSON array)
                    <textarea name="forwarding_destinations" placeholder='[{"name":"siem","url":"https://..."}]'></textarea>
                </label>
            </fieldset>

            <fieldset>
                <legend>Metrics</legend>
                <div class="grid-2">
                    <label>Port
                        <input type="number" name="metrics_port" min="1" max="65535" />
                    </label>
                </div>
                <div class="check-row">
                    <label><input type="checkbox" name="metrics_enabled" /> Metrics Enabled</label>
                </div>
            </fieldset>

            <fieldset>
                <legend>Syslog</legend>
                <div class="grid-3">
                    <label>UDP Port
                        <input type="number" name="syslog_udp_port" min="1" max="65535" />
                    </label>
                    <label>TCP Port
                        <input type="number" name="syslog_tcp_port" min="1" max="65535" />
                    </label>
                </div>
                <div class="check-row">
                    <label><input type="checkbox" name="syslog_enabled" /> Syslog Enabled</label>
                    <label><input type="checkbox" name="syslog_parse_dns" /> Parse DNS Logs</label>
                </div>
            </fieldset>

            <div class="actions">
                <button type="submit">Save Configuration</button>
                <span id="status"></span>
            </div>
        </form>
    </div>

    <script>
        const form = document.getElementById('config-form');
        const statusEl = document.getElementById('status');
        let currentConfig = null;

        const setStatus = (message, ok = false) => {
            statusEl.textContent = message;
            statusEl.className = ok ? 'ok' : 'err';
        };

        const toInt = (value, fallback) => {
            const parsed = parseInt(value, 10);
            return Number.isFinite(parsed) ? parsed : fallback;
        };

        const fillForm = (cfg) => {
            form.bind_address.value = cfg.bind_address || '';
            form.logging_level.value = cfg.logging?.level || 'info';
            form.logging_format.value = (cfg.logging?.format || 'Pretty').toString().toLowerCase();

            form.tls_enabled.checked = cfg.tls?.enabled ?? false;
            form.tls_port.value = cfg.tls?.port ?? '';
            form.tls_cert.value = cfg.tls?.cert_file || '';
            form.tls_key.value = cfg.tls?.key_file || '';
            form.tls_ca.value = cfg.tls?.ca_file || '';
            form.tls_require_client.checked = cfg.tls?.require_client_cert ?? false;

            form.security_allowed_ips.value = (cfg.security?.allowed_ips || []).join('\n');
            form.security_max_connections.value = cfg.security?.max_connections ?? '';
            form.security_timeout.value = cfg.security?.connection_timeout_secs ?? '';

            form.forwarding_buffer_size.value = cfg.forwarding?.buffer_size ?? '';
            form.forwarding_retry_attempts.value = cfg.forwarding?.retry_attempts ?? '';
            form.forwarding_destinations.value = JSON.stringify(cfg.forwarding?.destinations || [], null, 2);

            form.metrics_enabled.checked = cfg.metrics?.enabled ?? false;
            form.metrics_port.value = cfg.metrics?.port ?? '';

            form.syslog_enabled.checked = cfg.syslog?.enabled ?? false;
            form.syslog_udp_port.value = cfg.syslog?.udp_port ?? '';
            form.syslog_tcp_port.value = cfg.syslog?.tcp_port ?? '';
            form.syslog_parse_dns.checked = cfg.syslog?.parse_dns ?? false;
        };

        const textareaToList = (value) =>
            value.split('\n').map((line) => line.trim()).filter(Boolean);

        const buildPayload = () => {
            const payload = JSON.parse(JSON.stringify(currentConfig));
            payload.bind_address = form.bind_address.value.trim();
            payload.logging.level = form.logging_level.value;
            payload.logging.format = form.logging_format.value;

            payload.tls.enabled = form.tls_enabled.checked;
            payload.tls.port = toInt(form.tls_port.value, payload.tls.port);
            payload.tls.cert_file = form.tls_cert.value.trim() || null;
            payload.tls.key_file = form.tls_key.value.trim() || null;
            payload.tls.ca_file = form.tls_ca.value.trim() || null;
            payload.tls.require_client_cert = form.tls_require_client.checked;

            payload.security.allowed_ips = textareaToList(form.security_allowed_ips.value);
            payload.security.max_connections = toInt(form.security_max_connections.value, payload.security.max_connections);
            payload.security.connection_timeout_secs = toInt(form.security_timeout.value, payload.security.connection_timeout_secs);

            payload.forwarding.buffer_size = toInt(form.forwarding_buffer_size.value, payload.forwarding.buffer_size);
            payload.forwarding.retry_attempts = toInt(form.forwarding_retry_attempts.value, payload.forwarding.retry_attempts);
            const parsedDestinations = JSON.parse(form.forwarding_destinations.value || '[]');
            if (!Array.isArray(parsedDestinations)) {
                throw new Error('Destinations must be a JSON array');
            }
            payload.forwarding.destinations = parsedDestinations;

            payload.metrics.enabled = form.metrics_enabled.checked;
            payload.metrics.port = toInt(form.metrics_port.value, payload.metrics.port);

            payload.syslog.enabled = form.syslog_enabled.checked;
            payload.syslog.udp_port = toInt(form.syslog_udp_port.value, payload.syslog.udp_port);
            payload.syslog.tcp_port = toInt(form.syslog_tcp_port.value, payload.syslog.tcp_port);
            payload.syslog.parse_dns = form.syslog_parse_dns.checked;

            return payload;
        };

        const loadConfig = async () => {
            try {
                const res = await fetch('/config');
                if (!res.ok) throw new Error('Failed to load config');
                currentConfig = await res.json();
                fillForm(currentConfig);
                setStatus('Configuration loaded', true);
            } catch (err) {
                setStatus(err.message || 'Unable to fetch configuration');
            }
        };

        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            if (!currentConfig) return;

            let payload;
            try {
                payload = buildPayload();
            } catch (err) {
                setStatus(`Invalid form data: ${err.message}`);
                return;
            }

            try {
                const res = await fetch('/config', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                if (!res.ok) {
                    const body = await res.text();
                    throw new Error(body || 'Save failed');
                }
                currentConfig = await res.json();
                fillForm(currentConfig);
                setStatus('Configuration saved', true);
            } catch (err) {
                setStatus(err.message || 'Unable to save configuration');
            }
        });

        loadConfig();
    </script>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_state() -> AdminState {
        AdminState {
            config: Arc::new(RwLock::new(Config::default())),
            username: Arc::new("user".into()),
            password: Arc::new("pass".into()),
        }
    }

    #[tokio::test]
    async fn ensure_authorized_checks_credentials() {
        let state = test_state();
        let good = Some(TypedHeader(Authorization::basic("user", "pass")));
        let bad = Some(TypedHeader(Authorization::basic("user", "nope")));

        assert!(ensure_authorized(&state, good).await.is_ok());
        assert!(ensure_authorized(&state, bad).await.is_err());
        assert!(ensure_authorized(&state, None).await.is_err());
    }

    #[tokio::test]
    async fn write_config_outputs_toml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("override.toml");
        let cfg = Config::default();

        write_config_to_path(&cfg, &path)
            .await
            .expect("write succeeds");
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("bind_address"));
    }

    #[tokio::test]
    async fn get_config_requires_auth() {
        let state = test_state();
        let auth = Some(TypedHeader(Authorization::basic("user", "pass")));
        let Json(cfg) = get_config(State(state.clone()), auth)
            .await
            .expect("authorized");
        assert_eq!(cfg.bind_address, Config::default().bind_address);

        let unauthorized = get_config(State(state), None).await;
        assert!(unauthorized.is_err());
    }

    #[tokio::test]
    async fn update_config_persists_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("override.toml");
        unsafe {
            std::env::set_var("WEF_ADMIN_OVERRIDE_FILE", &path);
        }

        let state = test_state();
        let mut updated = Config::default();
        updated.bind_address = "127.0.0.1:7777".parse().unwrap();
        let auth = Some(TypedHeader(Authorization::basic("user", "pass")));

        let Json(saved) = update_config(State(state), auth, Json(updated.clone()))
            .await
            .expect("updated");
        assert_eq!(saved.bind_address, updated.bind_address);
        let file = std::fs::read_to_string(&path).unwrap();
        assert!(file.contains("127.0.0.1:7777"));

        unsafe {
            std::env::remove_var("WEF_ADMIN_OVERRIDE_FILE");
        }
    }
}
