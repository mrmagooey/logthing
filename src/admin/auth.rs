use axum::{
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Basic};
use subtle::ConstantTimeEq;

use crate::admin::state::{AdminState, TrustedIdentity};

/// Constant-time string equality to prevent timing side-channels.
///
/// Returns `true` iff `a == b`.  The byte comparison itself runs in time
/// proportional to `min(a.len(), b.len())` with no early exit, so an
/// attacker cannot distinguish a length mismatch from a content mismatch
/// via timing.  Length mismatches are rejected immediately (acceptable
/// here: usernames and CSRF tokens are not secret-length-sensitive).
fn ct_str_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Resolve a caller identity from trusted reverse-proxy headers, or `None`
/// if trusted-header auth is disabled, the shared secret is missing/wrong,
/// the username header is missing/empty, or no incoming group matches the
/// configured allowlist.
///
/// The secret comparison is constant-time (`ct_str_eq`) since it's the one
/// value here that's actually sensitive. Username/group comparisons use
/// plain equality — group and user names aren't secrets, so a constant-time
/// compare there would add no security benefit.
///
/// Header values that aren't valid UTF-8 are treated identically to a
/// missing header (`None`) — same fail-safe posture, no separate error path.
pub fn verify_trusted_header(state: &AdminState, headers: &HeaderMap) -> Option<TrustedIdentity> {
    let cfg = state.server_config.trusted_header.as_ref()?;

    let secret = headers.get(&cfg.secret_header)?.to_str().ok()?;
    if !ct_str_eq(secret, &cfg.secret) {
        return None;
    }

    let username = headers.get(&cfg.username_header)?.to_str().ok()?.trim();
    if username.is_empty() {
        return None;
    }

    let groups_raw = headers.get(&cfg.groups_header)?.to_str().ok()?;
    // Authentik's exact delimiter for this header was not confirmed against
    // live docs at design time — accept both `,` and `|` as a best-effort
    // default (see docs/admin-security.md for the operator-facing caveat).
    let matched = groups_raw
        .split([',', '|'])
        .map(str::trim)
        .filter(|g| !g.is_empty())
        .any(|g| cfg.allowed_groups.iter().any(|allowed| allowed == g));
    if !matched {
        return None;
    }

    Some(TrustedIdentity {
        username: username.to_string(),
    })
}

/// Verify authentication and authorize access
pub async fn ensure_authorized(
    state: &AdminState,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    client_ip: &str,
) -> Result<String, Response> {
    let Some(auth) = auth else {
        return Err(unauthorized());
    };

    let creds = auth.0;
    let username = creds.username();
    let password = creds.password();

    if ct_str_eq(username, &state.server_config.username)
        && state.server_config.password_hash.verify(password)
    {
        Ok(username.to_string())
    } else {
        state
            .audit_logger
            .log("AUTH_FAILED", username, client_ip, None)
            .await;
        Err(unauthorized())
    }
}

/// Generate unauthorized response
pub fn unauthorized() -> Response {
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

/// Generate CSRF token
pub async fn generate_csrf_token(state: &AdminState) -> String {
    use rand::{Rng, distr::Alphanumeric};

    // Clean expired tokens first
    let now = std::time::Instant::now();
    {
        let mut tokens = state.csrf_tokens.write().await;
        tokens.retain(|(_, exp)| *exp > now);
    }

    let token: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let expiry = std::time::Instant::now() + std::time::Duration::from_secs(3600);
    state
        .csrf_tokens
        .write()
        .await
        .push((token.clone(), expiry));

    token
}

/// Verify CSRF token
pub async fn verify_csrf_token(state: &AdminState, token: &str) -> bool {
    if !state.server_config.enable_csrf {
        return true;
    }

    let now = std::time::Instant::now();
    let tokens = state.csrf_tokens.read().await;
    tokens
        .iter()
        .any(|(t, exp)| ct_str_eq(t, token) && *exp > now)
}

#[cfg(test)]
mod tests {
    use super::ct_str_eq;

    #[test]
    fn ct_str_eq_equal_strings() {
        assert!(ct_str_eq("admin", "admin"));
        assert!(ct_str_eq("", ""));
        assert!(ct_str_eq("abc123XYZ", "abc123XYZ"));
    }

    #[test]
    fn ct_str_eq_unequal_same_length() {
        assert!(!ct_str_eq("admin", "Admin"));
        assert!(!ct_str_eq("abcde", "abcdX"));
        assert!(!ct_str_eq("token1", "token2"));
    }

    #[test]
    fn ct_str_eq_different_length() {
        assert!(!ct_str_eq("admin", "admin1"));
        assert!(!ct_str_eq("admin1", "admin"));
        assert!(!ct_str_eq("", "x"));
        assert!(!ct_str_eq("x", ""));
    }

    mod verify_trusted_header_tests {
        use super::super::verify_trusted_header;
        use crate::admin::state::{
            AdminServerConfig, AdminState, AuditLogger, PasswordHash, TrustedHeaderConfig,
        };
        use axum::http::{HeaderMap, HeaderName, HeaderValue};
        use std::sync::Arc;
        use tokio::sync::RwLock;

        fn trusted_cfg() -> TrustedHeaderConfig {
            TrustedHeaderConfig {
                username_header: HeaderName::from_static("x-authentik-username"),
                groups_header: HeaderName::from_static("x-authentik-groups"),
                secret_header: HeaderName::from_static("x-admin-proxy-secret"),
                secret: "shhh".to_string(),
                allowed_groups: vec!["admins".to_string(), "ops".to_string()],
            }
        }

        async fn state_with(trusted_header: Option<TrustedHeaderConfig>) -> AdminState {
            let server_config = AdminServerConfig {
                bind_address: "127.0.0.1:8080".parse().unwrap(),
                username: "admin".to_string(),
                password_hash: PasswordHash::hash("admin").unwrap(),
                allowed_ips: vec![],
                tls_config: None,
                enable_csrf: false,
                enable_rate_limiting: false,
                trusted_header,
            };
            AdminState {
                config: Arc::new(RwLock::new(crate::config::Config::default())),
                server_config,
                audit_logger: AuditLogger::new(10).await,
                csrf_tokens: Arc::new(RwLock::new(Vec::new())),
                request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
                source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
                flush_registry: crate::forwarding::flush_registry::FlushIntervalRegistry::new(),
            }
        }

        fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
            let mut h = HeaderMap::new();
            for (k, v) in pairs {
                h.insert(
                    HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                );
            }
            h
        }

        #[tokio::test]
        async fn disabled_returns_none_even_with_valid_headers() {
            let state = state_with(None).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-authentik-username", "alice"),
                ("x-authentik-groups", "admins"),
            ]);
            assert!(verify_trusted_header(&state, &h).is_none());
        }

        #[tokio::test]
        async fn wrong_secret_returns_none() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "wrong"),
                ("x-authentik-username", "alice"),
                ("x-authentik-groups", "admins"),
            ]);
            assert!(verify_trusted_header(&state, &h).is_none());
        }

        #[tokio::test]
        async fn missing_secret_returns_none() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-authentik-username", "alice"),
                ("x-authentik-groups", "admins"),
            ]);
            assert!(verify_trusted_header(&state, &h).is_none());
        }

        #[tokio::test]
        async fn missing_username_returns_none() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-authentik-groups", "admins"),
            ]);
            assert!(verify_trusted_header(&state, &h).is_none());
        }

        #[tokio::test]
        async fn empty_username_returns_none() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-authentik-username", "   "),
                ("x-authentik-groups", "admins"),
            ]);
            assert!(verify_trusted_header(&state, &h).is_none());
        }

        #[tokio::test]
        async fn no_matching_group_returns_none() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-authentik-username", "alice"),
                ("x-authentik-groups", "guests,visitors"),
            ]);
            assert!(verify_trusted_header(&state, &h).is_none());
        }

        #[tokio::test]
        async fn matching_group_comma_delimited_returns_identity() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-authentik-username", "alice"),
                ("x-authentik-groups", "guests,admins,visitors"),
            ]);
            let identity = verify_trusted_header(&state, &h).expect("should match");
            assert_eq!(identity.username, "alice");
        }

        #[tokio::test]
        async fn matching_group_pipe_delimited_returns_identity() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-authentik-username", "bob"),
                ("x-authentik-groups", "guests|ops|visitors"),
            ]);
            let identity = verify_trusted_header(&state, &h).expect("should match");
            assert_eq!(identity.username, "bob");
        }

        #[tokio::test]
        async fn non_utf8_header_value_treated_as_absent() {
            let state = state_with(Some(trusted_cfg())).await;
            let mut h = headers(&[
                ("x-authentik-username", "alice"),
                ("x-authentik-groups", "admins"),
            ]);
            h.insert(
                HeaderName::from_static("x-admin-proxy-secret"),
                HeaderValue::from_bytes(&[0xff, 0xfe, 0xfd]).unwrap(),
            );
            assert!(verify_trusted_header(&state, &h).is_none());
        }
    }
}
