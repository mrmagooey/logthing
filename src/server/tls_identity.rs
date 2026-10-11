//! TLS acceptor that records the client certificate's fingerprint as the connection's
//! [`ClientIdentity`], so WEF bookmarks can be keyed by it.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::http::Request;
use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsAcceptor;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::Service;

use crate::wef::identity::{ClientIdentity, cert_fingerprint};

/// Wraps [`RustlsAcceptor`]; after the handshake, wraps the connection's service in
/// [`WithIdentity`] carrying the leaf client certificate's fingerprint (if one was presented).
#[derive(Debug, Clone)]
pub struct IdentityAcceptor {
    inner: RustlsAcceptor,
}

impl IdentityAcceptor {
    /// Wraps an existing rustls acceptor.
    pub fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S> Accept<I, S> for IdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = WithIdentity<S>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let fut = self.inner.accept(stream, service);
        Box::pin(async move {
            let (tls, svc) = fut.await?;
            let identity = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|leaf| ClientIdentity::Certificate(cert_fingerprint(leaf.as_ref())));
            Ok((tls, WithIdentity::new(svc, identity)))
        })
    }
}

/// Per-connection service that inserts the connection's [`ClientIdentity`] into each request.
#[derive(Debug, Clone)]
pub struct WithIdentity<S> {
    inner: S,
    identity: Option<ClientIdentity>,
}

impl<S> WithIdentity<S> {
    /// Wraps `inner`; `identity` is `None` when the client presented no certificate.
    pub fn new(inner: S, identity: Option<ClientIdentity>) -> Self {
        Self { inner, identity }
    }
}

impl<S, B> Service<Request<B>> for WithIdentity<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if let Some(id) = &self.identity {
            req.extensions_mut().insert(id.clone());
        }
        self.inner.call(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::{ServiceExt, service_fn};

    #[tokio::test]
    async fn test_with_identity_inserts_extension_on_every_request() {
        let inner = service_fn(|req: Request<Body>| async move {
            Ok::<_, std::convert::Infallible>(req.extensions().get::<ClientIdentity>().cloned())
        });
        let svc = WithIdentity::new(inner, Some(ClientIdentity::Certificate([1; 32])));
        for _ in 0..2 {
            let got = svc
                .clone()
                .oneshot(Request::new(Body::empty()))
                .await
                .unwrap();
            assert_eq!(got, Some(ClientIdentity::Certificate([1; 32])));
        }
    }

    #[tokio::test]
    async fn test_with_identity_none_inserts_nothing() {
        let inner = service_fn(|req: Request<Body>| async move {
            Ok::<_, std::convert::Infallible>(req.extensions().get::<ClientIdentity>().is_some())
        });
        let svc = WithIdentity::new(inner, None);
        assert!(!svc.oneshot(Request::new(Body::empty())).await.unwrap());
    }
}
