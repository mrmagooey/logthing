use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::TypedHeader;
use headers::{Authorization, authorization::Basic};

use crate::admin::state::AdminState;

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

    if username == state.server_config.username
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
    state.csrf_tokens.write().await.push((token.clone(), expiry));

    token
}

/// Verify CSRF token
pub async fn verify_csrf_token(state: &AdminState, token: &str) -> bool {
    if !state.server_config.enable_csrf {
        return true;
    }

    let now = std::time::Instant::now();
    let tokens = state.csrf_tokens.read().await;
    tokens.iter().any(|(t, exp)| t == token && *exp > now)
}
