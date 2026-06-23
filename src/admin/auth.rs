use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Basic};
use subtle::ConstantTimeEq;

use crate::admin::state::AdminState;

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
}
