//! Per-TCP-connection state for `/wsman/**` authentication.
//!
//! Windows authenticates the TCP connection once (first request) and then sends later
//! requests on that connection without credentials. The server therefore needs somewhere
//! to remember "this connection is authenticated" that is private to the connection. Each
//! accepted connection gets a fresh [`ConnSlot`], injected as a request extension on every
//! request of that connection by [`ConnSlotMakeService`].

use super::kerberos::{AuthScheme, GssAcceptor};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::Service;

/// Authentication state of one TCP connection.
#[derive(Debug, Default)]
pub enum ConnAuthState {
    /// No successful authentication on this connection (or it was reset by a failure).
    #[default]
    Unauthenticated,
    /// The connection completed a GSS handshake; `ctx` wraps and unwraps its messages.
    Authenticated {
        /// Scheme the client authenticated with.
        scheme: AuthScheme,
        /// Authenticated client principal.
        principal: String,
        /// The completed security context (never stepped again).
        ctx: Box<dyn GssAcceptor>,
    },
}

/// Handle to one connection's [`ConnAuthState`], cloned onto every request of the connection.
///
/// The middleware holds the mutex for the whole request: requests on one HTTP/1.1
/// connection are strictly sequential, so this never contends and keeps the state
/// transitions (authenticate, decrypt, run handler, encrypt) atomic per request.
#[derive(Debug, Clone, Default)]
pub struct ConnSlot(pub Arc<tokio::sync::Mutex<ConnAuthState>>);

/// Wrap a make-service (typically `Router::into_make_service_with_connect_info`) so every
/// accepted connection gets its own fresh [`ConnSlot`].
pub fn with_conn_slots<M>(make: M) -> ConnSlotMakeService<M> {
    ConnSlotMakeService { inner: make }
}

/// Make-service produced by [`with_conn_slots`].
#[derive(Debug, Clone)]
pub struct ConnSlotMakeService<M> {
    inner: M,
}

impl<M, T> Service<T> for ConnSlotMakeService<M>
where
    M: Service<T>,
    M::Future: Send + 'static,
    M::Response: Send + 'static,
    M::Error: Send + 'static,
{
    type Response = ConnSlotService<M::Response>;
    type Error = M::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, target: T) -> Self::Future {
        let fut = self.inner.call(target);
        Box::pin(async move {
            Ok(ConnSlotService {
                inner: fut.await?,
                slot: ConnSlot::default(),
            })
        })
    }
}

/// Per-connection service: the inner service plus this connection's [`ConnSlot`].
#[derive(Debug, Clone)]
pub struct ConnSlotService<S> {
    inner: S,
    slot: ConnSlot,
}

impl<S, B> Service<axum::http::Request<B>> for ConnSlotService<S>
where
    S: Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<B>) -> Self::Future {
        // Overwrite, never trust: a slot can only come from the connection, not the wire.
        req.extensions_mut().insert(self.slot.clone());
        self.inner.call(req)
    }
}
