use std::sync::LazyLock;

use axum::{
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Basic};
use subtle::ConstantTimeEq;

use crate::admin::state::{AdminState, PasswordHash, TrustedIdentity};

/// Constant-time string equality to prevent timing side-channels.
///
/// Returns `true` iff `a == b`.  The byte comparison itself runs in time
/// proportional to `min(a.len(), b.len())` with no early exit, so an
/// attacker cannot distinguish a length mismatch from a content mismatch
/// via timing.  Length mismatches are rejected immediately (acceptable
/// here: usernames are not secret-length-sensitive).
fn ct_str_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Hash verified in place of the real one when the username is wrong, so a
/// wrong-user attempt costs the same Argon2 work as a wrong-password one.
static DUMMY_HASH: LazyLock<PasswordHash> = LazyLock::new(|| {
    PasswordHash::hash("logthing-dummy-password").expect("hashing a constant cannot fail")
});

/// Check Basic Auth credentials in constant work: Argon2 always runs (against
/// [`DUMMY_HASH`] for an unknown user) on the blocking pool, and the two
/// outcomes are combined without short-circuiting.
async fn credentials_valid(state: &AdminState, username: &str, password: &str) -> bool {
    let user_ok = ct_str_eq(username, &state.server_config.username);
    let hash = if user_ok {
        state.server_config.password_hash.clone()
    } else {
        DUMMY_HASH.clone()
    };
    let password = password.to_string();
    let pass_ok = tokio::task::spawn_blocking(move || hash.verify(&password))
        .await
        .unwrap_or_else(|e| {
            tracing::error!("admin password verification task failed: {e}");
            false
        });
    user_ok & pass_ok
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
    let Some(secret) = headers
        .get(&cfg.secret_header)
        .and_then(|v| v.to_str().ok())
    else {
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
/// When trusted, takes the RIGHTMOST hop of `X-Forwarded-For` — the address
/// the trusted proxy itself appended — trimmed and parsed as an `IpAddr`.
/// Earlier hops are client-supplied and can be forged, so they are never
/// believed. This assumes exactly one trusted proxy in front of the admin
/// server. Falls back to the peer address if the header is absent, empty, or
/// fails to parse. If the header appears on several lines, only the last line
/// (the one nearest the proxy) is read.
pub fn resolve_client_ip(
    state: &AdminState,
    addr: std::net::SocketAddr,
    headers: &HeaderMap,
) -> std::net::IpAddr {
    if !secret_header_matches(state, headers) {
        return addr.ip();
    }

    // A proxy may append its hop as a separate header line rather than extending
    // the first one, so the first line is client-controlled: read the LAST line.
    let xff = match headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v,
        None => return addr.ip(),
    };
    let last_hop = xff.rsplit(',').next().unwrap_or("").trim();
    last_hop
        .parse::<std::net::IpAddr>()
        .unwrap_or_else(|_| addr.ip())
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
    // default (see docs/admin.md for the operator-facing caveat).
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

    if credentials_valid(state, username, password).await {
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
            "Basic realm=\"logthing Admin\", charset=\"UTF-8\"",
        )],
        "Unauthorized",
    )
        .into_response()
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
                enable_rate_limiting: false,
                trusted_header,
            };
            AdminState {
                config: Arc::new(RwLock::new(crate::config::Config::default())),
                server_config,
                audit_logger: AuditLogger::new(10).await,
                request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
                source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
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

    mod credential_work_tests {
        use super::super::credentials_valid;
        use crate::admin::state::{AdminServerConfig, AdminState, AuditLogger, PasswordHash};
        use std::sync::Arc;
        use std::time::Instant;
        use tokio::sync::RwLock;

        async fn state() -> AdminState {
            AdminState {
                config: Arc::new(RwLock::new(crate::config::Config::default())),
                server_config: AdminServerConfig {
                    bind_address: "127.0.0.1:8080".parse().unwrap(),
                    username: "admin".to_string(),
                    password_hash: PasswordHash::hash("correct-horse").unwrap(),
                    allowed_ips: vec![],
                    tls_config: None,
                    enable_rate_limiting: false,
                    trusted_header: None,
                },
                audit_logger: AuditLogger::new(10).await,
                request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
                source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
            }
        }

        #[tokio::test]
        async fn test_credentials_valid_accepts_only_exact_pair() {
            let st = state().await;
            assert!(credentials_valid(&st, "admin", "correct-horse").await);
            assert!(!credentials_valid(&st, "admin", "wrong").await);
            assert!(!credentials_valid(&st, "nobody", "correct-horse").await);
        }

        /// An unknown username must cost the same Argon2 work as a wrong
        /// password; otherwise response time reveals which usernames exist.
        #[tokio::test]
        async fn test_verify_runs_argon2_for_unknown_user() {
            let st = state().await;
            // Warm the dummy-hash LazyLock so its one-time cost is not measured.
            let _ = credentials_valid(&st, "nobody", "x").await;

            let mut wrong_pass = std::time::Duration::MAX;
            let mut wrong_user = std::time::Duration::MAX;
            for _ in 0..3 {
                let t = Instant::now();
                assert!(!credentials_valid(&st, "admin", "wrong").await);
                wrong_pass = wrong_pass.min(t.elapsed());
                let t = Instant::now();
                assert!(!credentials_valid(&st, "nobody", "wrong").await);
                wrong_user = wrong_user.min(t.elapsed());
            }

            assert!(
                wrong_user * 5 > wrong_pass,
                "unknown-user attempt took {wrong_user:?} vs {wrong_pass:?} for wrong password"
            );
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
                enable_rate_limiting: false,
                trusted_header,
            };
            AdminState {
                config: Arc::new(RwLock::new(crate::config::Config::default())),
                server_config,
                audit_logger: AuditLogger::new(10).await,
                request_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
                source_stats: Arc::new(crate::stats::SourceHourlyStats::new()),
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
        async fn test_resolve_client_ip_uses_rightmost_xff_hop() {
            let state = state_with(Some(trusted_cfg())).await;
            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-forwarded-for", "10.0.0.5, 198.51.100.7"),
            ]);
            let ip = resolve_client_ip(&state, peer_addr(), &h);
            assert_eq!(ip, "198.51.100.7".parse::<IpAddr>().unwrap());

            let h = headers(&[
                ("x-admin-proxy-secret", "shhh"),
                ("x-forwarded-for", "198.51.100.7, 10.0.0.1, 10.0.0.2"),
            ]);
            let ip = resolve_client_ip(&state, peer_addr(), &h);
            assert_eq!(ip, "10.0.0.2".parse::<IpAddr>().unwrap());
        }

        /// A proxy that appends its hop as a second header line: the first
        /// line is client-forged and must be ignored.
        #[tokio::test]
        async fn test_resolve_client_ip_uses_last_xff_header_line() {
            let state = state_with(Some(trusted_cfg())).await;
            let mut h = headers(&[("x-admin-proxy-secret", "shhh")]);
            h.append("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
            h.append("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));
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
