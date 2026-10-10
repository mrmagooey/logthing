//! Kerberos / SPNEGO authentication.
//!
//! Two independent mechanisms live here:
//!
//! * [`wsman_auth_middleware`]: per-TCP-connection authentication plus MS-WSMV message
//!   encryption for `/wsman/**` (what Windows Event Forwarding clients speak). The GSS
//!   machinery is behind the [`GssAcceptor`] / [`GssAcceptorFactory`] traits so the state
//!   machine is testable with fakes; the libgssapi adapter is feature-gated.
//! * `kerberos_auth_middleware` (feature `kerberos-auth`): the stateless per-request
//!   `Negotiate` check used by every other protected route.

use super::conn::{ConnAuthState, ConnSlot};
use crate::wef::multipart::{self, EncProtocol};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, Version, header},
    middleware::Next,
    response::Response,
};
use base64::Engine;
use std::sync::Arc;
use tracing::{debug, warn};

/// Cap on any `/wsman/**` request or response body buffered by the auth layer. Windows'
/// MaxEnvelopeSize is 512000 bytes, so 4 MiB is ample even with GSS overhead; it keeps one
/// ticket-holding host from making the (outermost, pre-body-budget) layer buffer 64 MiB.
pub(crate) const WSMAN_MAX_BODY: usize = 4 * 1024 * 1024;

/// True when `e` (a body-read error) is the length limit being exceeded.
fn is_length_limit(e: &axum::Error) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        if err.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        cur = err.source();
    }
    false
}

/// Content type given to a decrypted request body and to plaintext SOAP responses.
const SOAP_UTF16: &str = "application/soap+xml;charset=UTF-16";

/// HTTP authentication scheme a client used to start a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    /// `Authorization: Kerberos <raw KRB5 AP-REQ>` (what Windows WinRM sends).
    Kerberos,
    /// `Authorization: Negotiate <SPNEGO token>`.
    Negotiate,
}

impl AuthScheme {
    fn as_str(self) -> &'static str {
        match self {
            AuthScheme::Kerberos => "Kerberos",
            AuthScheme::Negotiate => "Negotiate",
        }
    }
}

/// One server-side GSS security context (one authentication attempt).
pub trait GssAcceptor: Send + std::fmt::Debug {
    /// One accept step. Returns `(complete, output_token)`. Must never be called again once
    /// it has reported `complete`.
    fn step(&mut self, token: &[u8]) -> anyhow::Result<(bool, Option<Vec<u8>>)>;
    /// Authenticated client principal (valid once complete).
    fn principal(&mut self) -> anyhow::Result<String>;
    /// Whether the context negotiated confidentiality, integrity and mutual authentication.
    fn has_conf_integ_mutual(&mut self) -> anyhow::Result<bool>;
    /// Decrypts a `header`/`data` wrap token (consuming `data`, decrypted in place); returns the
    /// plaintext.
    fn unwrap_iov(&mut self, header: &[u8], data: Vec<u8>) -> anyhow::Result<Vec<u8>>;
    /// Encrypts `plaintext`; returns `(header, data + padding)`.
    fn wrap_iov(&mut self, plaintext: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)>;
}

/// Builds one [`GssAcceptor`] per authentication attempt.
pub trait GssAcceptorFactory: Send + Sync + std::fmt::Debug {
    /// MUST acquire a fresh credential and build a fresh context on every call: a completed
    /// context short-circuits `step` and would authenticate any later token (auth bypass).
    fn new_acceptor(&self) -> anyhow::Result<Box<dyn GssAcceptor>>;
}

/// Why a `/wsman/**` request failed authentication or decryption. Bounded: this is the only
/// source of the `reason` metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    /// No `Authorization` header on an unauthenticated connection.
    Missing,
    /// `Authorization` header with a scheme other than Kerberos/Negotiate.
    BadScheme,
    /// Malformed base64, empty token, or a handshake needing more legs.
    BadToken,
    /// The GSS library rejected the token or failed internally.
    GssError,
    /// The context lacks confidentiality, integrity or mutual authentication.
    MissingFlags,
    /// Encrypted payload could not be framed, unwrapped or has the wrong length.
    DecryptError,
    /// An HTTP/2 request carried an encrypted body.
    H2Encrypted,
}

impl AuthFailure {
    /// Every variant, for exhaustive tests.
    pub const ALL: [AuthFailure; 7] = [
        AuthFailure::Missing,
        AuthFailure::BadScheme,
        AuthFailure::BadToken,
        AuthFailure::GssError,
        AuthFailure::MissingFlags,
        AuthFailure::DecryptError,
        AuthFailure::H2Encrypted,
    ];

    /// The fixed metric label value.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthFailure::Missing => "missing",
            AuthFailure::BadScheme => "bad_scheme",
            AuthFailure::BadToken => "bad_token",
            AuthFailure::GssError => "gss_error",
            AuthFailure::MissingFlags => "missing_flags",
            AuthFailure::DecryptError => "decrypt_error",
            AuthFailure::H2Encrypted => "h2_encrypted",
        }
    }
}

fn record_failure(reason: AuthFailure) {
    metrics::counter!("wef_auth_failures_total", "reason" => reason.as_str()).increment(1);
}

/// Request extension marking a request whose body arrived encrypted.
#[derive(Debug, Clone, Copy)]
pub struct Encrypted(pub EncProtocol);

/// State for [`wsman_auth_middleware`].
#[derive(Debug)]
pub struct WsmanAuth {
    factory: Arc<dyn GssAcceptorFactory>,
}

impl WsmanAuth {
    /// Authentication state backed by `factory`.
    pub fn new(factory: Arc<dyn GssAcceptorFactory>) -> Self {
        Self { factory }
    }
}

/// Parsed `Authorization` header.
#[derive(Debug, PartialEq, Eq)]
enum Authz {
    Absent,
    BadScheme,
    BadToken,
    Token(AuthScheme, Vec<u8>),
}

fn classify_authorization(header: Option<&str>) -> Authz {
    let Some(value) = header else {
        return Authz::Absent;
    };
    let Some((scheme, b64)) = value.split_once(' ') else {
        return Authz::BadScheme;
    };
    let scheme = if scheme.eq_ignore_ascii_case("kerberos") {
        AuthScheme::Kerberos
    } else if scheme.eq_ignore_ascii_case("negotiate") {
        AuthScheme::Negotiate
    } else {
        return Authz::BadScheme;
    };
    match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
        Ok(tok) if !tok.is_empty() => Authz::Token(scheme, tok),
        _ => Authz::BadToken,
    }
}

fn empty(code: StatusCode) -> Response {
    Response::builder()
        .status(code)
        .body(Body::empty())
        .expect("static response")
}

/// 401 offering both schemes (Windows picks `Kerberos`, other clients `Negotiate`).
fn wsman_unauthorized() -> Response {
    let mut resp = empty(StatusCode::UNAUTHORIZED);
    let h = resp.headers_mut();
    h.append(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Kerberos"),
    );
    h.append(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Negotiate"),
    );
    resp
}

fn reject(reason: AuthFailure) -> Response {
    record_failure(reason);
    wsman_unauthorized()
}

/// Result of a completed handshake.
struct Handshake {
    acceptor: Box<dyn GssAcceptor>,
    out_token: Option<Vec<u8>>,
    principal: String,
}

/// Runs one handshake on a fresh acceptor, on a blocking thread (keytab I/O and crypto).
async fn handshake(
    factory: &Arc<dyn GssAcceptorFactory>,
    token: Vec<u8>,
) -> Result<Handshake, AuthFailure> {
    let factory = factory.clone();
    let joined =
        tokio::task::spawn_blocking(move || -> Result<Option<Handshake>, anyhow::Error> {
            let mut acceptor = factory.new_acceptor()?;
            let (complete, out_token) = acceptor.step(&token)?;
            if !complete {
                return Ok(None);
            }
            let principal = acceptor.principal()?;
            Ok(Some(Handshake {
                acceptor,
                out_token,
                principal,
            }))
        })
        .await;
    match joined {
        Ok(Ok(Some(h))) => Ok(h),
        // Multi-leg negotiation would need state carried across requests; Windows Kerberos
        // is single-leg, so an incomplete context is just a bad token.
        Ok(Ok(None)) => Err(AuthFailure::BadToken),
        Ok(Err(e)) => {
            warn!(
                "WEF Kerberos handshake failed: {}",
                crate::sanitize_for_log(&format!("{e:#}"), 128)
            );
            Err(AuthFailure::GssError)
        }
        Err(join_err) => {
            tracing::error!("WEF Kerberos worker task panicked: {}", join_err);
            Err(AuthFailure::GssError)
        }
    }
}

/// Why decrypting a request body failed.
enum DecryptError {
    MissingFlags,
    Gss,
    Framing,
    Length,
}

/// Decrypts an encrypted multipart body with `ctx`. Returns the context back so the caller
/// can restore it into the slot (the closure owns it while on the blocking thread).
fn decrypt_body(
    mut ctx: Box<dyn GssAcceptor>,
    body: &[u8],
) -> (Box<dyn GssAcceptor>, Result<Vec<u8>, DecryptError>) {
    let result = (|| {
        match ctx.has_conf_integ_mutual() {
            Ok(true) => {}
            _ => return Err(DecryptError::MissingFlags),
        }
        let payload = multipart::parse(body).map_err(|_| DecryptError::Framing)?;
        let plain = ctx
            .unwrap_iov(&payload.header, payload.data)
            .map_err(|_| DecryptError::Gss)?;
        if plain.len() != payload.original_length {
            return Err(DecryptError::Length);
        }
        Ok(plain)
    })();
    (ctx, result)
}

/// Authentication and message-encryption middleware for `/wsman/**`.
///
/// State machine per request (all slot access under the slot mutex, which is held for the
/// whole request: HTTP/1.1 requests on one connection are sequential):
///
/// 1. HTTP/2 requests never touch the connection slot: each must carry `Authorization`
///    and uses a throwaway slot; encrypted bodies are refused (400).
/// 2. An `Authorization: Kerberos|Negotiate` header always builds a brand-new acceptor
///    (fresh credential and context), whatever the slot held; success replaces the slot and
///    answers with the mutual-auth token; any failure leaves the slot unauthenticated.
/// 3. No header: allowed only if the slot is already authenticated, otherwise 401 with
///    both `Kerberos` and `Negotiate` challenges.
/// 4. `multipart/encrypted` bodies are decrypted (requires confidentiality, integrity and
///    mutual flags); the handler sees the plaintext with a SOAP content type.
/// 5. Non-empty responses to encrypted requests are encrypted; empty ones pass through.
pub async fn wsman_auth_middleware(
    State(auth): State<Arc<WsmanAuth>>,
    req: Request,
    next: Next,
) -> Response {
    let is_h2 = req.version() == Version::HTTP_2;
    let slot = if is_h2 {
        ConnSlot::default()
    } else {
        // A missing slot (router used without `with_conn_slots`) fails closed: the throwaway
        // slot can never carry authentication from one request to the next.
        req.extensions()
            .get::<ConnSlot>()
            .cloned()
            .unwrap_or_default()
    };
    let mut state = slot.0.lock().await;
    let (mut parts, body) = req.into_parts();

    let authz = classify_authorization(
        parts
            .headers
            .get(header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap_or("")),
    );
    let mut mutual_token: Option<HeaderValue> = None;
    match authz {
        Authz::Absent => {
            if !matches!(*state, ConnAuthState::Authenticated { .. }) {
                return reject(AuthFailure::Missing);
            }
        }
        Authz::BadScheme => {
            *state = ConnAuthState::Unauthenticated;
            return reject(AuthFailure::BadScheme);
        }
        Authz::BadToken => {
            *state = ConnAuthState::Unauthenticated;
            return reject(AuthFailure::BadToken);
        }
        Authz::Token(scheme, token) => {
            // Reset first: whatever happens below, the old context is gone.
            *state = ConnAuthState::Unauthenticated;
            let hs = match handshake(&auth.factory, token).await {
                Ok(hs) => hs,
                Err(reason) => return reject(reason),
            };
            debug!(
                "WEF client {} authenticated via {}",
                crate::sanitize_for_log(&hs.principal, 128),
                scheme.as_str()
            );
            mutual_token = hs.out_token.and_then(|tok| {
                let b64 = base64::engine::general_purpose::STANDARD.encode(tok);
                HeaderValue::from_str(&format!("{} {b64}", scheme.as_str())).ok()
            });
            *state = ConnAuthState::Authenticated {
                scheme,
                principal: hs.principal,
                ctx: hs.acceptor,
            };
        }
    }

    // Oversize is counted as `decrypt_error` (no extra label value) and leaves the slot as is:
    // nothing was decrypted, so the connection's authentication is unaffected.
    let bytes = match axum::body::to_bytes(body, WSMAN_MAX_BODY).await {
        Ok(b) => b,
        Err(e) if is_length_limit(&e) => {
            record_failure(AuthFailure::DecryptError);
            return empty(StatusCode::PAYLOAD_TOO_LARGE);
        }
        Err(_) => return empty(StatusCode::BAD_REQUEST),
    };
    if bytes.is_empty()
        && let Some(tok) = mutual_token.clone()
    {
        // The handshake request itself carries no SOAP; answer it without running the handler.
        let mut resp = empty(StatusCode::OK);
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, tok);
        return resp;
    }

    let enc = multipart::detect(
        parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
    );
    let body = match enc {
        None => Body::from(bytes),
        Some(_) if is_h2 => {
            record_failure(AuthFailure::H2Encrypted);
            return empty(StatusCode::BAD_REQUEST);
        }
        Some(proto) => {
            let ConnAuthState::Authenticated {
                scheme,
                principal,
                ctx,
            } = std::mem::take(&mut *state)
            else {
                return reject(AuthFailure::Missing);
            };
            let joined = tokio::task::spawn_blocking(move || decrypt_body(ctx, &bytes)).await;
            let (ctx, result) = match joined {
                Ok(v) => v,
                Err(_) => return reject(AuthFailure::GssError),
            };
            match result {
                Ok(plain) => {
                    *state = ConnAuthState::Authenticated {
                        scheme,
                        principal,
                        ctx,
                    };
                    parts.headers.remove(header::CONTENT_LENGTH);
                    parts
                        .headers
                        .insert(header::CONTENT_TYPE, HeaderValue::from_static(SOAP_UTF16));
                    parts.extensions.insert(Encrypted(proto));
                    Body::from(plain)
                }
                // A context that cannot protect the session, or that failed to unwrap, is
                // dropped (slot stays Unauthenticated): the client must re-authenticate.
                Err(DecryptError::MissingFlags) => return reject(AuthFailure::MissingFlags),
                Err(DecryptError::Gss) => return reject(AuthFailure::DecryptError),
                // Framing/length faults leave the context intact: nothing was unwrapped, or
                // unwrapping succeeded.
                Err(DecryptError::Framing | DecryptError::Length) => {
                    *state = ConnAuthState::Authenticated {
                        scheme,
                        principal,
                        ctx,
                    };
                    record_failure(AuthFailure::DecryptError);
                    return empty(StatusCode::BAD_REQUEST);
                }
            }
        }
    };

    let encrypted = parts.extensions.get::<Encrypted>().copied();
    let mut resp = next.run(Request::from_parts(parts, body)).await;
    if let Some(Encrypted(proto)) = encrypted {
        resp = encrypt_response(&mut state, proto, resp).await;
    }
    if let Some(tok) = mutual_token {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, tok);
    }
    resp
}

/// Encrypts a non-empty response body; empty bodies pass through untouched. On any failure
/// the plaintext is never sent: the client gets an empty 500 and the slot is reset.
async fn encrypt_response(
    state: &mut ConnAuthState,
    proto: EncProtocol,
    resp: Response,
) -> Response {
    let (mut parts, body) = resp.into_parts();
    let plain = match axum::body::to_bytes(body, WSMAN_MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return empty(StatusCode::INTERNAL_SERVER_ERROR),
    };
    if plain.is_empty() {
        return Response::from_parts(parts, Body::empty());
    }
    let ConnAuthState::Authenticated {
        scheme,
        principal,
        mut ctx,
    } = std::mem::take(state)
    else {
        return empty(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let joined = tokio::task::spawn_blocking(move || {
        let wrapped = ctx.wrap_iov(&plain);
        (ctx, plain.len(), wrapped)
    })
    .await;
    let Ok((ctx, original_length, Ok((hdr, data)))) = joined else {
        warn!("WEF response encryption failed; dropping connection authentication");
        return empty(StatusCode::INTERNAL_SERVER_ERROR);
    };
    *state = ConnAuthState::Authenticated {
        scheme,
        principal,
        ctx,
    };
    let framed = multipart::build(proto, original_length, &hdr, &data);
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.remove(header::CONTENT_ENCODING);
    if let Ok(ct) = HeaderValue::from_str(&proto.content_type()) {
        parts.headers.insert(header::CONTENT_TYPE, ct);
    }
    Response::from_parts(parts, Body::from(framed))
}

#[cfg(feature = "kerberos-auth")]
use anyhow::anyhow;
#[cfg(feature = "kerberos-auth")]
use axum::extract::ConnectInfo;
#[cfg(feature = "kerberos-auth")]
use std::net::SocketAddr;
#[cfg(feature = "kerberos-auth")]
use tracing::error;

/// Acquire a GSSAPI server (acceptor) credential for `spn`, restricted to the
/// raw Kerberos 5 and SPNEGO mechanisms (Windows sends raw KRB5 tokens with
/// `Authorization: Kerberos`; other clients wrap them in SPNEGO).
///
/// Deliberately re-acquired for every request (see `accept_kerberos_token`)
/// rather than acquired once and shared, even though that means reading the
/// local keytab per request:
///
/// * `libgssapi::credential::Cred` has no `Clone`/`Copy`, and its raw-handle
///   constructor/accessor (`from_c`/`to_c`) are `pub(crate)` inside the
///   `libgssapi` crate (credential.rs:239,243) — application code cannot
///   duplicate a `Cred` or hand out a borrowed view of one.
/// * `ServerCtx::new(cred: Cred)` takes the credential by value
///   (context.rs:506) and never gives it back — no `&Cred` constructor, no
///   way to reclaim the `Cred` afterward. Whatever `Cred` it's given dies
///   (releasing the GSSAPI handle via `Cred`'s `Drop`, credential.rs:81-95)
///   when that `ServerCtx` is dropped at the end of the request.
/// * Reusing one long-lived `ServerCtx` across many requests instead of
///   reusing the `Cred` is not a safe workaround either: once `step()`
///   reaches `ServerCtxState::Complete` it short-circuits and returns
///   `Ok(None)` without even inspecting the new token (context.rs:522-527).
///   A second, unrelated client hitting that same already-complete context
///   would be silently authenticated regardless of what — if anything — it
///   sent: an auth bypass.
///
/// So: one `Cred`, thrown away with its `ServerCtx`, per request.
/// `Cred::acquire` for an acceptor credential reads the local keytab and
/// does not contact a KDC, and `/wsman` is a low-QPS endpoint, so this is an
/// acceptable cost for correctness. Do not add a cache in front of this — a
/// cache is exactly the shared-handle problem above, just deferred.
#[cfg(feature = "kerberos-auth")]
pub(super) fn acquire_kerberos_cred(spn: &str) -> anyhow::Result<libgssapi::credential::Cred> {
    use libgssapi::{
        credential::{Cred, CredUsage},
        name::Name,
        oid::{GSS_MECH_KRB5, GSS_MECH_SPNEGO, GSS_NT_KRB5_PRINCIPAL, OidSet},
    };

    let name = Name::new(spn.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL))
        .map_err(|e| anyhow!("invalid Kerberos SPN {:?}: {}", spn, e))?;
    // Canonicalize against krb5 so `Cred::acquire` gets an unambiguous
    // mechanism name, matching the crate's own server-setup example.
    let name = name
        .canonicalize(Some(&GSS_MECH_KRB5))
        .map_err(|e| anyhow!("failed to canonicalize Kerberos SPN {:?}: {}", spn, e))?;

    let mut mechs =
        OidSet::new().map_err(|e| anyhow!("gssapi OID set allocation failed: {}", e))?;
    mechs
        .add(&GSS_MECH_KRB5)
        .map_err(|e| anyhow!("failed to build Kerberos mechanism set: {}", e))?;
    mechs
        .add(&GSS_MECH_SPNEGO)
        .map_err(|e| anyhow!("failed to build SPNEGO mechanism set: {}", e))?;

    Cred::acquire(Some(&name), None, CredUsage::Accept, Some(&mechs)).map_err(|e| {
        anyhow!(
            "failed to acquire Kerberos credential for SPN {:?}: {}",
            spn,
            e
        )
    })
}

/// Outcome of one SPNEGO `accept_sec_context` step.
#[cfg(feature = "kerberos-auth")]
enum AcceptOutcome {
    Authenticated {
        /// Mutual-auth response token (RFC 4559), if the mechanism produced one.
        response_token: Option<Vec<u8>>,
        principal: String,
    },
    /// The context needs another leg. Multi-leg negotiation is unsupported
    /// (see `kerberos_auth_middleware` docs) — callers must reject this.
    ContinueNeeded,
}

/// Run one SPNEGO accept step against a freshly acquired credential.
///
/// Blocking: `gss_acquire_cred`/`gss_accept_sec_context` are synchronous
/// GSSAPI calls (keytab I/O, crypto). Callers must run this via
/// `tokio::task::spawn_blocking`, never directly on the async runtime.
#[cfg(feature = "kerberos-auth")]
fn accept_kerberos_token(spn: &str, token: &[u8]) -> anyhow::Result<AcceptOutcome> {
    use libgssapi::context::{SecurityContext, ServerCtx};

    let cred = acquire_kerberos_cred(spn)?;
    let mut ctx = ServerCtx::new(cred);
    let response_token = ctx.step(token)?;

    if !ctx.is_complete() {
        return Ok(AcceptOutcome::ContinueNeeded);
    }

    let principal = ctx
        .source_name()
        .map(|n| n.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());

    Ok(AcceptOutcome::Authenticated {
        response_token: response_token.map(|tok| tok.to_vec()),
        principal,
    })
}

/// Classification of an `Authorization` header for SPNEGO purposes. Pure and
/// GSSAPI-free on purpose, so the challenge/rejection logic is unit-testable
/// without a keytab or KDC.
#[cfg(feature = "kerberos-auth")]
#[derive(Debug, PartialEq, Eq)]
enum NegotiateHeader {
    Missing,
    WrongScheme,
    MalformedBase64,
    Token(Vec<u8>),
}

#[cfg(feature = "kerberos-auth")]
fn classify_negotiate_header(header: Option<&str>) -> NegotiateHeader {
    let Some(value) = header else {
        return NegotiateHeader::Missing;
    };
    let Some(b64) = value.strip_prefix("Negotiate ") else {
        return NegotiateHeader::WrongScheme;
    };
    use base64::Engine;
    match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
        Ok(tok) => NegotiateHeader::Token(tok),
        Err(_) => NegotiateHeader::MalformedBase64,
    }
}

#[cfg(feature = "kerberos-auth")]
fn kerberos_unauthorized() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Negotiate")
        .body(axum::body::Body::from("Unauthorized"))
        .unwrap()
}

/// RFC 4559 SPNEGO ("Negotiate") authentication middleware.
///
/// Deliberately two-pass only: real Kerberos-over-HTTP is inherently
/// two-legged (the client already holds a ticket from the KDC before it
/// ever talks to us), so a single `Authorization: Negotiate` header carrying
/// a complete token is all a genuine client ever sends. Multi-leg
/// negotiation — which NTLM fallback would need — requires carrying GSSAPI
/// state across requests; this middleware does not do that. A `step()` that
/// comes back continue-needed is rejected with 401, not tracked for a
/// follow-up leg. The LGPL `axum-negotiate` crate this replaced documented
/// the same limitation.
#[cfg(feature = "kerberos-auth")]
pub(super) async fn kerberos_auth_middleware(
    State(spn): State<Arc<String>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let token = match classify_negotiate_header(header.as_deref()) {
        NegotiateHeader::Token(tok) => tok,
        NegotiateHeader::Missing
        | NegotiateHeader::WrongScheme
        | NegotiateHeader::MalformedBase64 => {
            return kerberos_unauthorized();
        }
    };

    // GSSAPI work is blocking (keytab I/O + crypto) — never run it inline on
    // the async runtime.
    let result = tokio::task::spawn_blocking(move || accept_kerberos_token(&spn, &token)).await;

    match result {
        Ok(Ok(AcceptOutcome::Authenticated {
            response_token,
            principal,
        })) => {
            debug!("Kerberos authenticated client principal: {}", principal);
            let mut response = next.run(request).await;
            if let Some(tok) = response_token {
                use base64::Engine;
                let value = format!(
                    "Negotiate {}",
                    base64::engine::general_purpose::STANDARD.encode(tok)
                );
                if let Ok(value) = axum::http::HeaderValue::from_str(&value) {
                    response.headers_mut().insert("WWW-Authenticate", value);
                }
            }
            response
        }
        Ok(Ok(AcceptOutcome::ContinueNeeded)) => {
            warn!(
                "Kerberos: client at {} needs multi-leg negotiation, which is unsupported; rejecting",
                addr
            );
            kerberos_unauthorized()
        }
        Ok(Err(e)) => {
            // Log server-side only — the response body must not leak GSSAPI
            // internals to the client.
            warn!("Kerberos authentication failed for {}: {}", addr, e);
            kerberos_unauthorized()
        }
        Err(join_err) => {
            error!("Kerberos auth worker task panicked: {}", join_err);
            kerberos_unauthorized()
        }
    }
}

/// Factory that builds libgssapi-backed acceptors for one service principal.
#[cfg(feature = "kerberos-auth")]
#[derive(Debug)]
pub struct LibGssFactory {
    spn: String,
}

#[cfg(feature = "kerberos-auth")]
impl LibGssFactory {
    /// Factory for acceptors of `spn` (e.g. `HTTP/host@REALM`). Nothing is acquired here;
    /// every [`GssAcceptorFactory::new_acceptor`] call reads the keytab afresh.
    pub fn new(spn: impl Into<String>) -> Self {
        Self { spn: spn.into() }
    }
}

#[cfg(feature = "kerberos-auth")]
impl GssAcceptorFactory for LibGssFactory {
    fn new_acceptor(&self) -> anyhow::Result<Box<dyn GssAcceptor>> {
        let cred = acquire_kerberos_cred(&self.spn)?;
        Ok(Box::new(LibGssAcceptor {
            ctx: libgssapi::context::ServerCtx::new(cred),
        }))
    }
}

/// libgssapi server context. Owns its credential (see `acquire_kerberos_cred`).
#[cfg(feature = "kerberos-auth")]
struct LibGssAcceptor {
    ctx: libgssapi::context::ServerCtx,
}

#[cfg(feature = "kerberos-auth")]
impl std::fmt::Debug for LibGssAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use libgssapi::context::SecurityContext;
        f.debug_struct("LibGssAcceptor")
            .field("complete", &self.ctx.is_complete())
            .finish()
    }
}

#[cfg(feature = "kerberos-auth")]
impl GssAcceptor for LibGssAcceptor {
    fn step(&mut self, token: &[u8]) -> anyhow::Result<(bool, Option<Vec<u8>>)> {
        use libgssapi::context::SecurityContext;
        // `ServerCtx::step` on a complete context returns Ok(None) without looking at the
        // token, i.e. it would accept anything: refuse outright.
        if self.ctx.is_complete() {
            anyhow::bail!("security context is already complete");
        }
        let out = self.ctx.step(token)?;
        Ok((self.ctx.is_complete(), out.map(|b| b.to_vec())))
    }

    fn principal(&mut self) -> anyhow::Result<String> {
        use libgssapi::context::SecurityContext;
        Ok(self.ctx.source_name()?.to_string())
    }

    fn has_conf_integ_mutual(&mut self) -> anyhow::Result<bool> {
        use libgssapi::context::{CtxFlags, SecurityContext};
        let need =
            CtxFlags::GSS_C_CONF_FLAG | CtxFlags::GSS_C_INTEG_FLAG | CtxFlags::GSS_C_MUTUAL_FLAG;
        Ok(self.ctx.flags()?.contains(need))
    }

    fn unwrap_iov(&mut self, header: &[u8], mut data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        use libgssapi::context::SecurityContext;
        use libgssapi::util::{GssIov, GssIovType};
        let mut header = header.to_vec();
        let mut iov = [
            GssIov::new(GssIovType::Header, &mut header),
            GssIov::new(GssIovType::Data, &mut data),
        ];
        self.ctx.unwrap_iov(&mut iov)?;
        drop(iov);
        Ok(data)
    }

    fn wrap_iov(&mut self, plaintext: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        use libgssapi::context::SecurityContext;
        use libgssapi::util::{GssIov, GssIovType};
        let mut data = plaintext.to_vec();
        // Header and padding are allocated by GSSAPI (it sizes them itself); the plaintext is
        // encrypted in place.
        let mut iov = [
            GssIov::new_alloc(GssIovType::Header),
            GssIov::new(GssIovType::Data, &mut data),
            GssIov::new_alloc(GssIovType::Padding),
        ];
        self.ctx.wrap_iov(true, &mut iov)?;
        let header = iov[0].to_vec();
        let padding = iov[2].to_vec();
        drop(iov);
        data.extend_from_slice(&padding);
        Ok((header, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Bytes;
    use axum::extract::ConnectInfo;
    use axum::http::Request as HttpRequest;
    use axum::middleware;
    use axum::routing::post;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tower::ServiceExt;

    // ---- fakes -------------------------------------------------------------------------

    /// Fake "encryption": XOR 0x5A, with an 8-byte header carrying the context id so a
    /// context can only unwrap what was wrapped for it.
    fn fake_wrap(id: u64, plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
        (
            id.to_be_bytes().to_vec(),
            plain.iter().map(|b| b ^ 0x5A).collect(),
        )
    }

    fn fake_unwrap(id: u64, header: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(header == id.to_be_bytes(), "header is for another context");
        Ok(data.iter().map(|b| b ^ 0x5A).collect())
    }

    #[derive(Debug)]
    struct FakeAcceptor {
        id: u64,
        complete: bool,
        principal: String,
        flags_ok: bool,
        violated: Arc<AtomicBool>,
    }

    impl GssAcceptor for FakeAcceptor {
        fn step(&mut self, token: &[u8]) -> anyhow::Result<(bool, Option<Vec<u8>>)> {
            if self.complete {
                self.violated.store(true, Ordering::SeqCst);
                panic!("step called on a completed context");
            }
            let text = String::from_utf8_lossy(token).to_string();
            if text == "partial" {
                return Ok((false, Some(b"more".to_vec())));
            }
            let Some(name) = text.strip_prefix("principal:") else {
                anyhow::bail!("fake: rejected token");
            };
            self.principal = name.to_string();
            self.complete = true;
            Ok((true, Some(format!("aprep-{}", self.id).into_bytes())))
        }
        fn principal(&mut self) -> anyhow::Result<String> {
            Ok(self.principal.clone())
        }
        fn has_conf_integ_mutual(&mut self) -> anyhow::Result<bool> {
            Ok(self.flags_ok)
        }
        fn unwrap_iov(&mut self, header: &[u8], data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
            fake_unwrap(self.id, header, &data)
        }
        fn wrap_iov(&mut self, plaintext: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
            Ok(fake_wrap(self.id, plaintext))
        }
    }

    #[derive(Debug, Default)]
    struct FakeFactory {
        created: AtomicUsize,
        flags_missing: AtomicBool,
        violated: Arc<AtomicBool>,
    }

    impl GssAcceptorFactory for FakeFactory {
        fn new_acceptor(&self) -> anyhow::Result<Box<dyn GssAcceptor>> {
            let id = self.created.fetch_add(1, Ordering::SeqCst) as u64 + 1;
            Ok(Box::new(FakeAcceptor {
                id,
                complete: false,
                principal: String::new(),
                flags_ok: !self.flags_missing.load(Ordering::SeqCst),
                violated: self.violated.clone(),
            }))
        }
    }

    // ---- harness -----------------------------------------------------------------------

    /// Records what the handler saw: (content-type, body).
    type Seen = Arc<Mutex<Vec<(Option<String>, Vec<u8>)>>>;

    struct Harness {
        router: Router,
        factory: Arc<FakeFactory>,
        seen: Seen,
        slot: ConnSlot,
    }

    fn router_with(factory: Arc<FakeFactory>, seen: Seen) -> Router {
        let seen_echo = seen.clone();
        let echo = move |headers: axum::http::HeaderMap, body: Bytes| {
            let seen = seen_echo.clone();
            async move {
                let ct = headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                seen.lock().unwrap().push((ct, body.to_vec()));
                let mut out = b"echo:".to_vec();
                out.extend_from_slice(&body);
                Response::builder()
                    .status(200)
                    .header(header::CONTENT_TYPE, SOAP_UTF16)
                    .body(Body::from(out))
                    .unwrap()
            }
        };
        Router::new()
            .route("/wsman", post(echo))
            .route("/wsman/end", post(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state(
                Arc::new(WsmanAuth::new(factory)),
                wsman_auth_middleware,
            ))
    }

    impl Harness {
        fn new() -> Self {
            let factory = Arc::new(FakeFactory::default());
            let seen: Seen = Arc::default();
            Harness {
                router: router_with(factory.clone(), seen.clone()),
                factory,
                seen,
                slot: ConnSlot::default(),
            }
        }

        async fn send(&self, req: HttpRequest<Body>) -> Response {
            self.send_on(&self.slot, req).await
        }

        async fn send_on(&self, slot: &ConnSlot, mut req: HttpRequest<Body>) -> Response {
            req.extensions_mut().insert(slot.clone());
            let addr: SocketAddr = "127.0.0.1:40001".parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            self.router.clone().oneshot(req).await.unwrap()
        }
    }

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    fn auth_req(scheme: &str, token: &str, uri: &str, body: Vec<u8>) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("{scheme} {}", b64(token)))
            .body(Body::from(body))
            .unwrap()
    }

    fn plain_req(uri: &str, body: &[u8]) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method("POST")
            .uri(uri)
            .body(Body::from(body.to_vec()))
            .unwrap()
    }

    fn enc_req(uri: &str, id: u64, plain: &[u8], announced_len: usize) -> HttpRequest<Body> {
        let (h, d) = fake_wrap(id, plain);
        let body = multipart::build(EncProtocol::Kerberos, announced_len, &h, &d);
        HttpRequest::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, EncProtocol::Kerberos.content_type())
            .body(Body::from(body))
            .unwrap()
    }

    async fn body_bytes(resp: Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    fn www_auth(resp: &Response) -> Vec<String> {
        resp.headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    /// Authenticates the harness connection as `name`; returns the context id used.
    async fn login(h: &Harness, name: &str) -> u64 {
        let resp = h
            .send(auth_req(
                "Kerberos",
                &format!("principal:{name}"),
                "/wsman",
                vec![],
            ))
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        h.factory.created.load(Ordering::SeqCst) as u64
    }

    // ---- tests -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_auth_post_empty_body_returns_200_with_mutual_token() {
        let h = Harness::new();
        let resp = h
            .send(auth_req("Kerberos", "principal:alice", "/wsman", vec![]))
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            www_auth(&resp),
            vec![format!("Kerberos {}", b64("aprep-1"))]
        );
        assert!(body_bytes(resp).await.is_empty());
        assert!(h.seen.lock().unwrap().is_empty(), "handler must not run");
    }

    #[tokio::test]
    async fn test_auth_header_kerberos_scheme_mirrored() {
        let h = Harness::new();
        let resp = h
            .send(auth_req("kerberos", "principal:a", "/wsman", vec![]))
            .await;
        assert!(www_auth(&resp)[0].starts_with("Kerberos "));
    }

    #[tokio::test]
    async fn test_auth_header_negotiate_scheme_mirrored() {
        let h = Harness::new();
        let resp = h
            .send(auth_req("Negotiate", "principal:a", "/wsman", vec![]))
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(www_auth(&resp)[0].starts_with("Negotiate "));
    }

    #[tokio::test]
    async fn test_unauthenticated_no_header_401_with_both_challenges() {
        let h = Harness::new();
        let resp = h.send(plain_req("/wsman", b"x")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(www_auth(&resp), vec!["Kerberos", "Negotiate"]);
        assert!(h.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_authenticated_connection_headerless_request_passes() {
        let h = Harness::new();
        login(&h, "alice").await;
        let resp = h.send(plain_req("/wsman", b"hello")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"echo:hello");
    }

    #[tokio::test]
    async fn test_new_header_on_authenticated_connection_builds_fresh_acceptor() {
        let h = Harness::new();
        login(&h, "alice").await;
        assert_eq!(h.factory.created.load(Ordering::SeqCst), 1);
        let resp = h
            .send(auth_req("Kerberos", "principal:bob", "/wsman", vec![]))
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(h.factory.created.load(Ordering::SeqCst), 2);
        // The slot now holds the second context: ciphertext for context 1 no longer opens.
        let old = h.send(enc_req("/wsman", 1, b"x", 1)).await;
        assert_eq!(old.status(), StatusCode::UNAUTHORIZED);
        login(&h, "bob").await; // new ctx (id 3) just to prove the slot is usable again
        let fresh = h.send(enc_req("/wsman", 3, b"x", 1)).await;
        assert_eq!(fresh.status(), StatusCode::OK);
        let slot = h.slot.0.lock().await;
        let ConnAuthState::Authenticated { principal, .. } = &*slot else {
            panic!("expected authenticated");
        };
        assert_eq!(principal, "bob");
    }

    #[tokio::test]
    async fn test_bad_token_after_success_401_and_slot_reset() {
        let h = Harness::new();
        login(&h, "alice").await;
        let resp = h
            .send(auth_req("Kerberos", "garbage", "/wsman", vec![]))
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(www_auth(&resp), vec!["Kerberos", "Negotiate"]);
        let next = h.send(plain_req("/wsman", b"x")).await;
        assert_eq!(next.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_incomplete_handshake_is_401_and_not_authenticated() {
        let h = Harness::new();
        let resp = h
            .send(auth_req("Kerberos", "partial", "/wsman", vec![]))
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let next = h.send(plain_req("/wsman", b"x")).await;
        assert_eq!(next.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_bad_scheme_and_bad_base64_401_and_slot_reset() {
        for header_value in ["Basic dXNlcjpwYXNz", "Kerberos !!!not-base64", "Kerberos "] {
            let h = Harness::new();
            login(&h, "alice").await;
            let req = HttpRequest::builder()
                .method("POST")
                .uri("/wsman")
                .header("Authorization", header_value)
                .body(Body::empty())
                .unwrap();
            assert_eq!(h.send(req).await.status(), StatusCode::UNAUTHORIZED);
            let next = h.send(plain_req("/wsman", b"x")).await;
            assert_eq!(next.status(), StatusCode::UNAUTHORIZED, "{header_value}");
        }
    }

    #[tokio::test]
    async fn test_never_steps_completed_ctx() {
        let h = Harness::new();
        login(&h, "alice").await;
        for _ in 0..3 {
            assert_eq!(
                h.send(plain_req("/wsman", b"x")).await.status(),
                StatusCode::OK
            );
        }
        login(&h, "bob").await;
        login(&h, "carol").await;
        assert!(!h.factory.violated.load(Ordering::SeqCst));
        assert_eq!(h.factory.created.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_encrypted_body_decrypted_and_response_encrypted() {
        let h = Harness::new();
        let id = login(&h, "alice").await;
        let plain = b"<soap>\xff\xfe payload</soap>";
        let resp = h.send(enc_req("/wsman", id, plain, plain.len())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(ct, EncProtocol::Kerberos.content_type());
        let wire = body_bytes(resp).await;
        let parsed = multipart::parse(&wire).unwrap();
        let out = fake_unwrap(id, &parsed.header, &parsed.data).unwrap();
        assert_eq!(parsed.original_length, out.len());
        let mut expect = b"echo:".to_vec();
        expect.extend_from_slice(plain);
        assert_eq!(out, expect);
        let seen = h.seen.lock().unwrap();
        assert_eq!(seen[0].0.as_deref(), Some(SOAP_UTF16));
        assert_eq!(seen[0].1, plain);
    }

    #[tokio::test]
    async fn test_encrypted_body_length_mismatch_400() {
        let h = Harness::new();
        let id = login(&h, "alice").await;
        let resp = h.send(enc_req("/wsman", id, b"abcd", 5)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(h.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_oversize_encrypted_body_413_keeps_slot() {
        let h = Harness::new();
        let id = login(&h, "alice").await;
        let big = vec![b'a'; WSMAN_MAX_BODY + 1];
        let resp = h.send(enc_req("/wsman", id, &big, big.len())).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(h.seen.lock().unwrap().is_empty());
        // Nothing was decrypted, so the connection stays authenticated.
        let ok = h.send(plain_req("/wsman", b"x")).await;
        assert_eq!(ok.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_oversize_response_not_sent_in_plaintext() {
        let factory = Arc::new(FakeFactory::default());
        let router = Router::new()
            .route("/wsman", post(|| async { vec![b'z'; WSMAN_MAX_BODY + 1] }))
            .layer(middleware::from_fn_with_state(
                Arc::new(WsmanAuth::new(factory.clone())),
                wsman_auth_middleware,
            ));
        let slot = ConnSlot::default();
        let mut auth = auth_req("Kerberos", "principal:a", "/wsman", vec![]);
        auth.extensions_mut().insert(slot.clone());
        assert_eq!(
            router.clone().oneshot(auth).await.unwrap().status(),
            StatusCode::OK
        );
        let mut req = enc_req("/wsman", 1, b"abcd", 4);
        req.extensions_mut().insert(slot);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body_bytes(resp).await.is_empty());
    }

    #[tokio::test]
    async fn test_malformed_multipart_400() {
        let h = Harness::new();
        login(&h, "alice").await;
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/wsman")
            .header(header::CONTENT_TYPE, EncProtocol::Kerberos.content_type())
            .body(Body::from("not multipart"))
            .unwrap();
        assert_eq!(h.send(req).await.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_decrypt_failure_401_and_slot_reset() {
        let h = Harness::new();
        let id = login(&h, "alice").await;
        let resp = h.send(enc_req("/wsman", id + 41, b"abcd", 4)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let next = h.send(plain_req("/wsman", b"x")).await;
        assert_eq!(next.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_encrypted_body_without_conf_flags_401() {
        let h = Harness::new();
        h.factory.flags_missing.store(true, Ordering::SeqCst);
        let id = login(&h, "alice").await;
        let resp = h.send(enc_req("/wsman", id, b"abcd", 4)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(h.seen.lock().unwrap().is_empty());
        let next = h.send(plain_req("/wsman", b"x")).await;
        assert_eq!(next.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_plaintext_body_on_authenticated_connection_accepted() {
        let h = Harness::new();
        login(&h, "alice").await;
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/wsman")
            .header(header::CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .body(Body::from("plain"))
            .unwrap();
        let resp = h.send(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        // Responses to plaintext requests stay plaintext.
        assert_eq!(resp.headers()[header::CONTENT_TYPE], SOAP_UTF16);
        assert_eq!(body_bytes(resp).await, b"echo:plain");
        assert_eq!(
            h.seen.lock().unwrap()[0].0.as_deref(),
            Some("application/soap+xml;charset=UTF-8")
        );
    }

    #[tokio::test]
    async fn test_empty_response_not_encrypted() {
        let h = Harness::new();
        let id = login(&h, "alice").await;
        let resp = h.send(enc_req("/wsman/end", id, b"abcd", 4)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::CONTENT_TYPE).is_none());
        assert!(body_bytes(resp).await.is_empty());
    }

    #[tokio::test]
    async fn test_h2_request_encrypted_body_400() {
        let h = Harness::new();
        let mut req = enc_req("/wsman", 1, b"abcd", 4);
        *req.version_mut() = Version::HTTP_2;
        req.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Kerberos {}", b64("principal:alice"))).unwrap(),
        );
        assert_eq!(h.send(req).await.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_h2_request_no_slot_reuse() {
        let h = Harness::new();
        let mut auth = auth_req("Kerberos", "principal:alice", "/wsman", vec![]);
        *auth.version_mut() = Version::HTTP_2;
        assert_eq!(h.send(auth).await.status(), StatusCode::OK);
        let mut headerless = plain_req("/wsman", b"x");
        *headerless.version_mut() = Version::HTTP_2;
        assert_eq!(h.send(headerless).await.status(), StatusCode::UNAUTHORIZED);
        // The h2 auth must not have authenticated the shared connection slot either.
        assert_eq!(
            h.send(plain_req("/wsman", b"x")).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn test_request_without_conn_slot_fails_closed() {
        let h = Harness::new();
        let mut req = auth_req("Kerberos", "principal:a", "/wsman", vec![]);
        req.extensions_mut()
            .insert(ConnectInfo::<SocketAddr>("127.0.0.1:1".parse().unwrap()));
        assert_eq!(
            h.router.clone().oneshot(req).await.unwrap().status(),
            StatusCode::OK
        );
        let mut next = plain_req("/wsman", b"x");
        next.extensions_mut()
            .insert(ConnectInfo::<SocketAddr>("127.0.0.1:1".parse().unwrap()));
        assert_eq!(
            h.router.clone().oneshot(next).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    /// D38: authenticating `/wsman/**` on a connection does not authenticate other routes.
    #[cfg(feature = "kerberos-auth")]
    #[tokio::test]
    async fn test_syslog_on_wsman_authenticated_connection_requires_own_auth() {
        let factory = Arc::new(FakeFactory::default());
        let syslog = Router::new()
            .route("/syslog", post(|| async { "syslog-ok" }))
            .layer(middleware::from_fn_with_state(
                Arc::new("HTTP/test.invalid@EXAMPLE.COM".to_string()),
                kerberos_auth_middleware,
            ));
        let router = router_with(factory.clone(), Arc::default()).merge(syslog);
        let slot = ConnSlot::default();
        let send = |mut req: HttpRequest<Body>| {
            req.extensions_mut().insert(slot.clone());
            req.extensions_mut()
                .insert(ConnectInfo::<SocketAddr>("127.0.0.1:2".parse().unwrap()));
            router.clone().oneshot(req)
        };
        let ok = send(auth_req("Kerberos", "principal:alice", "/wsman", vec![]))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        let syslog = send(plain_req("/syslog", b"msg")).await.unwrap();
        assert_eq!(syslog.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(www_auth(&syslog), vec!["Negotiate"]);
    }

    #[test]
    fn test_auth_failure_metric_reasons_bounded() {
        let labels: Vec<&str> = AuthFailure::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            labels,
            [
                "missing",
                "bad_scheme",
                "bad_token",
                "gss_error",
                "missing_flags",
                "decrypt_error",
                "h2_encrypted"
            ]
        );
    }

    #[test]
    fn test_classify_authorization_cases() {
        assert_eq!(classify_authorization(None), Authz::Absent);
        assert_eq!(classify_authorization(Some("Basic abc")), Authz::BadScheme);
        assert_eq!(classify_authorization(Some("Kerberos")), Authz::BadScheme);
        assert_eq!(classify_authorization(Some("Kerberos !!")), Authz::BadToken);
        assert_eq!(classify_authorization(Some("Kerberos ")), Authz::BadToken);
        assert_eq!(
            classify_authorization(Some("NEGOTIATE dGVzdA==")),
            Authz::Token(AuthScheme::Negotiate, b"test".to_vec())
        );
    }

    // ---- real TCP connections ------------------------------------------------------------

    async fn read_response(s: &mut tokio::net::TcpStream) -> (u16, String, Vec<u8>) {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let head_end = loop {
            let mut chunk = [0u8; 1024];
            let n = s.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed early");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let len = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        let mut body = buf[head_end + 4..].to_vec();
        while body.len() < len {
            let mut chunk = [0u8; 1024];
            let n = s.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            body.extend_from_slice(&chunk[..n]);
        }
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        (status, head, body)
    }

    async fn post_raw(s: &mut tokio::net::TcpStream, auth: Option<&str>) {
        use tokio::io::AsyncWriteExt;
        let auth = auth
            .map(|a| format!("Authorization: {a}\r\n"))
            .unwrap_or_default();
        let req = format!("POST /wsman HTTP/1.1\r\nHost: t\r\n{auth}Content-Length: 0\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
    }

    #[tokio::test]
    async fn test_connections_do_not_share_slots() {
        let factory = Arc::new(FakeFactory::default());
        let router = router_with(factory.clone(), Arc::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let make = crate::server::conn::with_conn_slots(
                router.into_make_service_with_connect_info::<SocketAddr>(),
            );
            axum::serve(listener, make).await.unwrap();
        });
        let mut a = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut b = tokio::net::TcpStream::connect(addr).await.unwrap();

        let token = format!("Kerberos {}", b64("principal:alice"));
        post_raw(&mut a, Some(&token)).await;
        let (status, head, _) = read_response(&mut a).await;
        assert_eq!(status, 200, "{head}");

        // Connection B never authenticated.
        post_raw(&mut b, None).await;
        assert_eq!(read_response(&mut b).await.0, 401);
        // Connection A keeps its authentication across requests.
        post_raw(&mut a, None).await;
        let (status, _, body) = read_response(&mut a).await;
        assert_eq!((status, body.as_slice()), (200, &b"echo:"[..]));
        // And B is still unauthenticated afterwards.
        post_raw(&mut b, None).await;
        assert_eq!(read_response(&mut b).await.0, 401);
        assert_eq!(factory.created.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "kerberos-auth")]
    #[test]
    fn test_lib_gss_factory_constructs_without_touching_gssapi() {
        let f = LibGssFactory::new("HTTP/test.invalid@EXAMPLE.COM");
        assert!(format!("{f:?}").contains("HTTP/test.invalid"));
    }

    /// Without a keytab for the SPN the factory reports an error instead of panicking or
    /// handing out a half-built context.
    #[cfg(feature = "kerberos-auth")]
    #[test]
    fn test_lib_gss_factory_errors_without_keytab() {
        let f = LibGssFactory::new("HTTP/test.invalid@EXAMPLE.COM");
        assert!(f.new_acceptor().is_err());
    }

    // ------------------------------------------------------------------ //
    // Kerberos SPNEGO middleware                                         //
    //                                                                    //
    // There is no KDC or keytab in this test environment (deliberate:    //
    // a full KDC harness was cut as disproportionate, since this sim     //
    // env isn't invoked by any CI workflow), so only the paths that      //
    // never need a real GSSAPI exchange are covered here:                //
    //   * `classify_negotiate_header` — pure, GSSAPI-free header parsing //
    //   * missing header / wrong scheme / malformed base64 — all three  //
    //     short-circuit in the middleware before any GSSAPI call runs   //
    //   * a well-formed-but-bogus token, which still exercises the      //
    //     "the GSSAPI pipeline failed" branch end to end (whether it     //
    //     fails at `Cred::acquire` for lack of a keytab, or at `step()`  //
    //     for lack of a valid token, both map to 401 the same way)       //
    //                                                                    //
    // NOT covered, and cannot be from `cargo test`: a real SPNEGO        //
    // handshake succeeding (needs a live KDC + keytab), and the mutual-  //
    // auth `WWW-Authenticate` response header on success.                //
    // ------------------------------------------------------------------ //
    #[cfg(feature = "kerberos-auth")]
    mod kerberos_auth_tests {
        use super::*;
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use tower::ServiceExt;

        const TEST_SPN: &str = "HTTP/test.invalid@EXAMPLE.COM";

        fn kerberos_router() -> Router {
            Router::new()
                .route("/protected", axum::routing::get(|| async { "ok" }))
                .layer(middleware::from_fn_with_state(
                    Arc::new(TEST_SPN.to_string()),
                    kerberos_auth_middleware,
                ))
        }

        fn with_connect_info(mut req: HttpRequest<Body>) -> HttpRequest<Body> {
            let addr: SocketAddr = "127.0.0.1:40001".parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(addr));
            req
        }

        #[test]
        fn classify_missing_header() {
            assert_eq!(classify_negotiate_header(None), NegotiateHeader::Missing);
        }

        #[test]
        fn classify_wrong_scheme() {
            assert_eq!(
                classify_negotiate_header(Some("Basic dXNlcjpwYXNz")),
                NegotiateHeader::WrongScheme
            );
        }

        #[test]
        fn classify_malformed_base64() {
            assert_eq!(
                classify_negotiate_header(Some("Negotiate not-valid-base64!!!")),
                NegotiateHeader::MalformedBase64
            );
        }

        #[test]
        fn classify_well_formed_token() {
            assert_eq!(
                classify_negotiate_header(Some("Negotiate dGVzdA==")),
                NegotiateHeader::Token(b"test".to_vec())
            );
        }

        /// No `Authorization` header at all -> 401 with a `WWW-Authenticate:
        /// Negotiate` challenge, not a panic or a 5xx.
        #[tokio::test]
        async fn missing_authorization_header_returns_401_with_challenge() {
            let req = with_connect_info(
                HttpRequest::builder()
                    .uri("/protected")
                    .body(Body::empty())
                    .unwrap(),
            );
            let resp = kerberos_router().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(resp.headers().get("WWW-Authenticate").unwrap(), "Negotiate");
        }

        /// A non-Negotiate scheme (e.g. HTTP Basic) must be rejected with 401.
        #[tokio::test]
        async fn non_negotiate_scheme_returns_401() {
            let req = with_connect_info(
                HttpRequest::builder()
                    .uri("/protected")
                    .header("Authorization", "Basic dXNlcjpwYXNz")
                    .body(Body::empty())
                    .unwrap(),
            );
            let resp = kerberos_router().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        /// Malformed base64 after `Negotiate ` must be rejected with 401, not
        /// a panic.
        #[tokio::test]
        async fn malformed_base64_returns_401() {
            let req = with_connect_info(
                HttpRequest::builder()
                    .uri("/protected")
                    .header("Authorization", "Negotiate not-valid-base64!!!")
                    .body(Body::empty())
                    .unwrap(),
            );
            let resp = kerberos_router().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        /// A well-formed-but-bogus Negotiate token must be rejected with
        /// 401 — never the old fail-closed stub's 501, and never a panic.
        /// In this keytab-less sandbox this exercises "the GSSAPI pipeline
        /// failed" (acquire or step, whichever fails first), not
        /// specifically "a live ServerCtx rejected a garbage token" — that
        /// needs a real credential this environment cannot provide.
        #[tokio::test]
        async fn bogus_token_returns_401_not_501_or_panic() {
            let req = with_connect_info(
                HttpRequest::builder()
                    .uri("/protected")
                    .header("Authorization", "Negotiate dGVzdA==")
                    .body(Body::empty())
                    .unwrap(),
            );
            let resp = kerberos_router().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert_ne!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        }
    }
}
