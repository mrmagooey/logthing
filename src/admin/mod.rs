//! Admin HTTP interface for logthing server configuration management
//!
//! This module provides a secure web interface for managing server configuration,
//! viewing audit logs, and monitoring system status.

mod auth;
mod config_api;
mod metrics_view;
mod middleware;
mod routes;
mod state;

// Re-export public API
pub use routes::spawn_admin_server;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::state::{AdminServerConfig, AdminState, AuditLogger, PasswordHash};
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::sync::RwLock;

    use crate::config::Config;

    async fn test_state() -> AdminState {
        let server_config = AdminServerConfig {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            username: "user".to_string(),
            password_hash: PasswordHash::hash("pass").unwrap(),
            allowed_ips: vec![],
            tls_config: None,
            enable_rate_limiting: false,
            trusted_header: None,
        };

        AdminState {
            config: Arc::new(RwLock::new(Config::default())),
            server_config,
            audit_logger: AuditLogger::new(100).await,
            request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
            source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
        }
    }

    #[test]
    fn password_hashing_works() {
        let password = "mysecretpassword";
        let hash = PasswordHash::hash(password).unwrap();

        assert!(hash.verify(password));
        assert!(!hash.verify("wrongpassword"));
    }

    #[test]
    fn password_hash_from_string_works() {
        let password = "testpassword";
        let hash1 = PasswordHash::hash(password).unwrap();
        let hash2 = PasswordHash::from_hash(&hash1.hash);

        assert!(hash2.verify(password));
    }

    #[tokio::test]
    async fn ensure_authorized_checks_credentials() {
        use axum_extra::extract::TypedHeader;
        use headers::Authorization;

        let state = test_state().await;
        let client_ip = "127.0.0.1";

        let good = Some(TypedHeader(Authorization::basic("user", "pass")));
        let bad = Some(TypedHeader(Authorization::basic("user", "nope")));

        assert!(
            auth::ensure_authorized(&state, None, good, client_ip)
                .await
                .is_ok()
        );
        assert!(
            auth::ensure_authorized(&state, None, bad, client_ip)
                .await
                .is_err()
        );
        assert!(
            auth::ensure_authorized(&state, None, None, client_ip)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn ensure_authorized_trusted_identity_short_circuits_basic_auth() {
        let state = test_state().await;
        let client_ip = "127.0.0.1";
        let trusted = Some(crate::admin::state::TrustedIdentity {
            username: "proxied-user".to_string(),
        });

        // No Authorization header at all — must still succeed via the
        // trusted identity, proving Basic Auth is not consulted when a
        // trusted identity is already present.
        let result = auth::ensure_authorized(&state, trusted, None, client_ip).await;
        assert_eq!(result.unwrap(), "proxied-user");
    }

    #[tokio::test]
    async fn audit_logger_records_entries() {
        // LOGTHING_ADMIN_AUDIT_LOG is process-global; serialize against every
        // other test that touches it crate-wide (see config_api::test_support).
        let _lock = config_api::test_support::lock_audit_log_env().await;

        // Use a temp directory to avoid loading existing entries
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test-audit.log");
        unsafe {
            std::env::set_var("LOGTHING_ADMIN_AUDIT_LOG", &log_path);
        }

        let logger = AuditLogger::new(10).await;

        logger
            .log("TEST_ACTION", "testuser", "127.0.0.1", Some("test details"))
            .await;

        let entries = logger.get_entries(10).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "TEST_ACTION");
        assert_eq!(entries[0].username, "testuser");
        assert_eq!(entries[0].client_ip, "127.0.0.1");
        assert_eq!(entries[0].details, Some("test details".to_string()));

        unsafe {
            std::env::remove_var("LOGTHING_ADMIN_AUDIT_LOG");
        }
    }

    /// Regression test for the ADMIN AUDIT log sink: a failed-login username
    /// containing a mid-line `\r`, a `\n`, and an ANSI escape must not carry
    /// any of them raw into the `info!` line `AuditLogger::log` emits. This
    /// is the same attacker-controlled string F2 already had to defend
    /// against on the HTML-rendering side (`1f23979`); this test covers the
    /// log-sink side. Uses the shared `test_support` capture subscriber (see
    /// its doc comment for why a bespoke `set_default` doesn't work here).
    #[tokio::test]
    async fn audit_log_sanitizes_control_characters_in_username() {
        // LOGTHING_ADMIN_AUDIT_LOG is process-global; serialize against every
        // other test that touches it crate-wide (see config_api::test_support).
        let _lock = config_api::test_support::lock_audit_log_env().await;

        crate::test_support::install_and_clear();

        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test-audit-sanitize.log");
        unsafe {
            std::env::set_var("LOGTHING_ADMIN_AUDIT_LOG", &log_path);
        }

        let logger = AuditLogger::new(10).await;
        let forged_username = "admin\rERROR fake entry\n\u{1b}[31minjected\u{1b}[0m";

        logger
            .log("AUTH_FAILED", forged_username, "127.0.0.1", None)
            .await;

        let events = crate::test_support::captured_events();
        let audit_line = events
            .iter()
            .find(|m| m.contains("[ADMIN AUDIT]"))
            .unwrap_or_else(|| panic!("no [ADMIN AUDIT] event captured; got: {events:?}"));

        assert!(
            !audit_line.contains('\r'),
            "raw CR leaked into the log line: {audit_line:?}"
        );
        assert!(
            !audit_line.contains('\n'),
            "raw LF leaked into the log line (forged a second log entry): {audit_line:?}"
        );
        assert!(
            !audit_line.contains('\u{1b}'),
            "raw ESC leaked into the log line: {audit_line:?}"
        );
        assert!(
            audit_line.contains('\u{fffd}'),
            "expected U+FFFD replacement characters in the log line: {audit_line:?}"
        );

        // The stored/rendered-in-UI copy (fixed separately by F2, via
        // textContent rather than sanitizing the string itself) must still
        // carry the raw username — only the log sink truncates/replaces.
        let entries = logger.get_entries(10).await;
        assert_eq!(entries[0].username, forged_username);

        unsafe {
            std::env::remove_var("LOGTHING_ADMIN_AUDIT_LOG");
        }
    }

    #[tokio::test]
    async fn audit_logger_respects_max_entries() {
        // LOGTHING_ADMIN_AUDIT_LOG is process-global; serialize against every
        // other test that touches it crate-wide (see config_api::test_support).
        let _lock = config_api::test_support::lock_audit_log_env().await;

        // Use a temp directory to avoid loading existing entries
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("test-audit.log");
        unsafe {
            std::env::set_var("LOGTHING_ADMIN_AUDIT_LOG", &log_path);
        }

        let logger = AuditLogger::new(2).await;

        logger.log("ACTION1", "user", "127.0.0.1", None).await;
        logger.log("ACTION2", "user", "127.0.0.1", None).await;
        logger.log("ACTION3", "user", "127.0.0.1", None).await;

        let entries = logger.get_entries(10).await;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "ACTION3");
        assert_eq!(entries[1].action, "ACTION2");

        unsafe {
            std::env::remove_var("LOGTHING_ADMIN_AUDIT_LOG");
        }
    }

    // Auth module tests
    mod auth_tests {
        use super::*;

        #[test]
        fn unauthorized_returns_correct_response() {
            let response = auth::unauthorized();
            // Check it's a valid response type
            let _ = response;
        }
    }

    // State module tests
    mod state_tests {
        use super::*;

        // ── admin_start_allowed unit tests ────────────────────────────────────────

        #[test]
        fn admin_allowed_loopback_default_creds() {
            // Loopback bind + default credentials → permitted (local dev workflow).
            let bind: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
            assert!(
                state::admin_start_allowed(bind, "admin", "admin").is_ok(),
                "loopback + default creds must be allowed"
            );
        }

        #[test]
        fn admin_refused_non_loopback_default_creds() {
            // Non-loopback bind + default credentials → must be refused.
            let bind: std::net::SocketAddr = "0.0.0.0:8080".parse().unwrap();
            let result = state::admin_start_allowed(bind, "admin", "admin");
            assert!(
                result.is_err(),
                "non-loopback + default creds must be refused"
            );
            let msg = result.unwrap_err();
            assert!(
                msg.contains("non-loopback") || msg.contains("refused"),
                "error message should describe the refusal: {msg}"
            );
        }

        #[test]
        fn admin_allowed_non_loopback_custom_creds() {
            // Non-loopback bind + explicit non-default credentials → permitted.
            let bind: std::net::SocketAddr = "0.0.0.0:8080".parse().unwrap();
            assert!(
                state::admin_start_allowed(bind, "ops-user", "s3cr3tP@ss").is_ok(),
                "non-loopback + custom creds must be allowed"
            );
        }

        #[test]
        fn admin_allowed_ipv6_loopback_default_creds() {
            // IPv6 loopback (::1) + default credentials → also permitted.
            let bind: std::net::SocketAddr = "[::1]:8080".parse().unwrap();
            assert!(
                state::admin_start_allowed(bind, "admin", "admin").is_ok(),
                "IPv6 loopback + default creds must be allowed"
            );
        }

        #[test]
        fn admin_refused_only_when_both_username_and_password_are_default() {
            // Non-loopback bind where only the username is changed → allowed (password differs).
            let bind: std::net::SocketAddr = "10.0.0.1:8080".parse().unwrap();
            assert!(
                state::admin_start_allowed(bind, "admin", "changed-pass").is_ok(),
                "non-loopback + custom password must be allowed even if username is 'admin'"
            );
            // Non-loopback bind where only the password is changed → allowed.
            assert!(
                state::admin_start_allowed(bind, "changed-user", "admin").is_ok(),
                "non-loopback + custom username must be allowed even if password is 'admin'"
            );
        }

        #[tokio::test]
        async fn audit_logger_persists_to_json_lines() {
            // LOGTHING_ADMIN_AUDIT_LOG is process-global; serialize against every
            // other test that touches it crate-wide (see config_api::test_support).
            let _lock = config_api::test_support::lock_audit_log_env().await;

            let dir = tempdir().unwrap();
            let log_path = dir.path().join("test-persist.log");
            unsafe {
                std::env::set_var("LOGTHING_ADMIN_AUDIT_LOG", &log_path);
            }

            let logger = AuditLogger::new(10).await;
            logger
                .log("TEST", "user", "127.0.0.1", Some("details"))
                .await;

            // Force a small delay to ensure file write
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // Check file exists and contains JSON
            assert!(log_path.exists());
            let contents = std::fs::read_to_string(&log_path).unwrap();
            assert!(contents.contains("TEST"));
            assert!(contents.contains("user"));

            unsafe {
                std::env::remove_var("LOGTHING_ADMIN_AUDIT_LOG");
            }
        }

        #[tokio::test]
        async fn audit_logger_loads_from_file_on_init() {
            // LOGTHING_ADMIN_AUDIT_LOG is process-global; serialize against every
            // other test that touches it crate-wide (see config_api::test_support).
            let _lock = config_api::test_support::lock_audit_log_env().await;

            let dir = tempdir().unwrap();
            let log_path = dir.path().join("test-load.log");

            // Pre-populate log file
            let entry = state::AuditEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                action: "PRELOADED".to_string(),
                username: "test".to_string(),
                client_ip: "127.0.0.1".to_string(),
                details: None,
            };
            let json = serde_json::to_string(&entry).unwrap();
            std::fs::create_dir_all(dir.path()).unwrap();
            std::fs::write(&log_path, json + "\n").unwrap();

            unsafe {
                std::env::set_var("LOGTHING_ADMIN_AUDIT_LOG", &log_path);
            }

            let logger = AuditLogger::new(10).await;
            let entries = logger.get_entries(10).await;

            assert!(!entries.is_empty());
            assert!(entries.iter().any(|e| e.action == "PRELOADED"));

            unsafe {
                std::env::remove_var("LOGTHING_ADMIN_AUDIT_LOG");
            }
        }

        #[test]
        fn load_admin_config_uses_defaults() {
            // Test that default config loads without environment variables
            let _ = state::load_admin_config();
            // Should not panic
        }

        #[test]
        fn admin_server_config_is_cloneable() {
            let config = AdminServerConfig {
                bind_address: "0.0.0.0:8080".parse().unwrap(),
                username: "admin".to_string(),
                password_hash: PasswordHash::hash("test").unwrap(),
                allowed_ips: vec![],
                tls_config: None,
                enable_rate_limiting: true,
                trusted_header: None,
            };

            let _cloned = config.clone();
        }
    }

    // Route handler tests
    mod route_tests {
        use super::*;

        #[tokio::test]
        async fn test_state_helper_creates_valid_state() {
            let state = test_state().await;

            // Verify all fields are initialized
            assert_eq!(state.server_config.username, "user");
            assert!(state.server_config.password_hash.verify("pass"));
            assert!(state.server_config.allowed_ips.is_empty());
        }
    }

    // Integration tests for routes
    mod route_integration_tests {
        use super::*;

        #[tokio::test]
        async fn health_check_returns_ok() {
            let response = routes::health_check().await;
            assert_eq!(response, "OK");
        }
    }
}
