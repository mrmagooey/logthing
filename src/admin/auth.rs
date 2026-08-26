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

/// Returns `true` iff trusted-header auth is configured AND the request
/// carries a secret header value that constant-time-matches the configured
/// secret. This is the single trust boundary shared by `verify_trusted_header`
/// (full identity + group verification) and `resolve_client_ip` (whether
/// `X-Forwarded-For` may be believed) — factored out so the two can never
/// silently diverge on what counts as "this request genuinely came through
/// our trusted proxy."
fn secret_header_matches(state: &AdminState, headers: &HeaderMap) -> bool {
    let Some(cfg) = state.server_config.trusted_header.as_ref() else {
        return false;
    };
    let Some(secret) = headers.get(&cfg.secret_header).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    ct_str_eq(secret, &cfg.secret)
}

/// Resolve the real client IP for this request.
///
/// Only trusts `X-Forwarded-For` when [`secret_header_matches`] returns
/// `true` — i.e. only on requests proven to have come through the trusted
/// reverse proxy. This is the critical security boundary: honoring
/// `X-Forwarded-For` on arbitrary traffic would let any attacker spoof their
/// logged/rate-limited/allowlisted IP simply by setting the header
/// themselves. When the secret doesn't match (trust-mode off, header
/// missing, or wrong), `X-Forwarded-For` is never even inspected — the raw
/// `ConnectInfo` peer address is returned unconditionally.
///
/// When trusted, takes the leftmost (client-facing) hop of `X-Forwarded-For`
/// — the standard single-proxy convention — trimmed and parsed as an
/// `IpAddr`. Falls back to the peer address if the header is absent, empty,
/// or fails to parse.
pub fn resolve_client_ip(
    state: &AdminState,
    addr: std::net::SocketAddr,
    headers: &HeaderMap,
) -> std::net::IpAddr {
    if !secret_header_matches(state, headers) {
        return addr.ip();
    }

    let xff = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(v) => v,
        None => return addr.ip(),
    };
    let first_hop = xff.split(',').next().unwrap_or("").trim();
    first_hop.parse::<std::net::IpAddr>().unwrap_or_else(|_| addr.ip())
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

    if !secret_header_matches(state, headers) {
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

/// Verify authentication and authorize access.
///
/// Checks a trusted reverse-proxy identity first (if present — see
/// `verify_trusted_header`), and only falls back to Basic Auth if none was
/// resolved. This keeps Basic Auth fully working as a fallback for direct/
/// local access when the trusted-header proxy isn't in the request path.
pub async fn ensure_authorized(
    state: &AdminState,
    trusted: Option<TrustedIdentity>,
    auth: Option<TypedHeader<Authorization<Basic>>>,
    client_ip: &str,
) -> Result<String, Response> {
    if let Some(identity) = trusted {
        return Ok(identity.username);
    }

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

    mod resolve_client_ip_tests {
        use super::super::resolve_client_ip;
        use crate::admin::state::{
            AdminServerConfig, AdminState, AuditLogger, PasswordHash, TrustedHeaderConfig,
        };
        use axum::http::{HeaderMap, HeaderName, HeaderValue};
        use std::net::{IpAddr, SocketAddr};
        use std::sync::Arc;
        use tokio::sync::RwLock;

        fn trusted_cfg() -> TrustedHeaderConfig {
            TrustedHeaderConfig {
                username_header: HeaderName::from_static("x-authentik-username"),
                groups_header: HeaderName::from_static("x-authentik-groups"),
                secret_header: HeaderName::from_static("x-admin-proxy-secret"),
                secret: "shhh".to_string(),
                allowed_groups: vec!["admins".to_string()],
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

        fn peer_addr() -> SocketAddr {
            "10.9.9.9:12345".parse().unwrap()
        }

        #[tokio::test]
        async fn secret_matches_valid_xff_returns_xff_ip() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-forwarded-for", "203.0.113.42"),
            ]);
            let ip = resolve_client_ip(&state, peer_addr(), &h);
            assert_eq!(ip, "203.0.113.42".parse::<IpAddr>().unwrap());
        }

        #[tokio::test]
        async fn secret_matches_no_xff_header_falls_back_to_peer_addr() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[("x-admin-proxy-secret", "shhh")]);
            let ip = resolve_client_ip(&state, peer_addr(), &h);
            assert_eq!(ip, peer_addr().ip());
        }

        #[tokio::test]
        async fn secret_matches_malformed_xff_falls_back_to_peer_addr() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-forwarded-for", "not-an-ip-address"),
            ]);
            let ip = resolve_client_ip(&state, peer_addr(), &h);
            assert_eq!(ip, peer_addr().ip());
        }

        #[tokio::test]
        async fn secret_matches_multi_hop_xff_takes_first_hop() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-forwarded-for", "198.51.100.7, 10.0.0.1, 10.0.0.2"),
            ]);
            let ip = resolve_client_ip(&state, peer_addr(), &h);
            assert_eq!(ip, "198.51.100.7".parse::<IpAddr>().unwrap());
        }

        /// The security boundary: a wrong/missing secret must mean
        /// `X-Forwarded-For` is completely ignored, even if it's present
        /// and points at a plausible-looking IP. Otherwise any attacker
        /// could spoof their logged/rate-limited IP by just setting the
        /// header themselves.
        #[tokio::test]
        async fn secret_does_not_match_xff_present_still_returns_peer_addr() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "totally-wrong"),
                ("x-forwarded-for", "203.0.113.42"),
            ]);
            let ip = resolve_client_ip(&state, peer_addr(), &h);
            assert_eq!(
                ip,
                peer_addr().ip(),
                "XFF must be completely ignored when the secret doesn't match"
            );
        }

        #[tokio::test]
        async fn trust_mode_disabled_xff_present_returns_peer_addr() {
            let state = state_with(None).await;
            let h = headers(&[("x-forwarded-for", "203.0.113.42")]);
            let ip = resolve_client_ip(&state, peer_addr(), &h);
            assert_eq!(ip, peer_addr().ip());
        }
    }
}
