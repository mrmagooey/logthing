//! gzip request-body decoding for the HEC, NDJSON and OTLP routes.
//!
//! Layering contract: `body_budget_middleware` is an OUTER layer on the whole protected router,
//! so it sees (and charges) the compressed WIRE bytes. `post_gzip` wraps ONE route in a
//! `RequestDecompressionLayer`, and an innermost `charge_decompressed` layer charges the
//! DECOMPRESSED frames against the same body-byte budget (a request whose body was gzip-decoded
//! is marked by `normalize_content_encoding`); when the budget runs dry the body stream errors
//! (400) instead of buffering. The handler's `Bytes` extractor then reads the DECOMPRESSED
//! stream through `http_body_util::Limited` configured by the router-wide `DefaultBodyLimit`
//! (`MAX_BODY_SIZE`), so a gzip bomb is cut off while streaming and answered with 413
//! (`Content-Length` is stripped by the decompressor, so nothing is enforced up front).
//! WEF and syslog routes are deliberately not wrapped.
//!
//! Status mapping: absent/`identity` passes through; `gzip`/`x-gzip` (any case, surrounding
//! spaces) is decoded; anything else (`deflate`, `br`, `zstd`, `gzip, gzip`, garbage) is 415;
//! a corrupt gzip stream is 400; a decompressed size over the limit is 413.

use crate::server::BodyBudgetHandles;
use axum::{
    extract::Request,
    handler::Handler,
    http::{HeaderValue, header},
    middleware::{self, Next},
    response::Response,
    routing::{MethodRouter, post},
};
use tower_http::decompression::RequestDecompressionLayer;

/// Request-extension marker: the client declared `gzip`, so the layer below decodes the body.
#[derive(Clone, Copy, Debug)]
struct GzipDecoded;

/// Innermost layer of `post_gzip`: charge the decompressed frames against the shared body-byte
/// budget. A no-op when the request was not gzip-decoded (already charged as wire bytes) or no
/// budget is installed (unit-test routers).
async fn charge_decompressed(mut req: Request, next: Next) -> Response {
    if req.extensions().get::<GzipDecoded>().is_some()
        && let Some(handles) = req.extensions().get::<BodyBudgetHandles>().cloned()
    {
        let body = std::mem::take(req.body_mut());
        *req.body_mut() = handles.charge(body);
    }
    next.run(req).await
}

/// Canonicalise `Content-Encoding` before tower-http inspects it: trim, lowercase, and map the
/// legacy alias `x-gzip` to `gzip` (tower-http only matches the exact lowercase bytes
/// `gzip`). Anything it still does not recognise (`deflate`, `br`, `gzip, gzip`, ...) is
/// answered with 415 by the layer.
/// Only the first `Content-Encoding` header line is considered (matching tower-http).
pub async fn normalize_content_encoding(mut req: Request, next: Next) -> Response {
    let canonical = req
        .headers()
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|raw| {
            let lowered = raw.trim().to_ascii_lowercase();
            if lowered == "x-gzip" {
                "gzip".to_string()
            } else {
                lowered
            }
        });
    if canonical.as_deref() == Some("gzip") {
        req.extensions_mut().insert(GzipDecoded);
    }
    if let Some(value) = canonical.and_then(|c| HeaderValue::from_str(&c).ok()) {
        req.headers_mut().insert(header::CONTENT_ENCODING, value);
    }
    next.run(req).await
}

/// `post(handler)` that transparently accepts `Content-Encoding: gzip` request bodies.
///
/// See the module docs for how the wire-byte budget and the decompressed-size limit compose.
pub fn post_gzip<H, T, S>(handler: H) -> MethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    post(handler)
        // Innermost: charge the decoded bytes against the body budget.
        .layer::<_, std::convert::Infallible>(middleware::from_fn(charge_decompressed))
        // Decode (and 415 anything it cannot decode).
        .layer(RequestDecompressionLayer::new())
        // Outer: normalise the header first.
        .layer(middleware::from_fn(normalize_content_encoding))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::{Body, Bytes},
        extract::DefaultBodyLimit,
        http::{Request, StatusCode},
    };
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    use tower::ServiceExt;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    async fn echo_len(body: Bytes) -> String {
        body.len().to_string()
    }

    fn app(limit: usize) -> Router {
        Router::new()
            .route("/x", post_gzip(echo_len))
            .layer(DefaultBodyLimit::max(limit))
    }

    async fn send(encoding: Option<&str>, body: Vec<u8>, limit: usize) -> (StatusCode, String) {
        let mut b = Request::builder().method("POST").uri("/x");
        if let Some(e) = encoding {
            b = b.header("content-encoding", e);
        }
        let resp = app(limit)
            .oneshot(b.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn gzip_body_reaches_handler_decompressed() {
        let (s, b) = send(Some("gzip"), gzip(&[b'a'; 500]), 1024).await;
        assert_eq!((s, b.as_str()), (StatusCode::OK, "500"));
    }

    #[tokio::test]
    async fn encoding_name_is_case_and_space_insensitive_and_accepts_x_gzip() {
        for enc in ["GZIP", "Gzip", " gzip ", "x-gzip", "X-GZIP"] {
            let (s, b) = send(Some(enc), gzip(b"hello"), 1024).await;
            assert_eq!((s, b.as_str()), (StatusCode::OK, "5"), "encoding {enc:?}");
        }
    }

    #[tokio::test]
    async fn absent_or_identity_encoding_passes_through() {
        assert_eq!(send(None, b"hello".to_vec(), 1024).await.1, "5");
        assert_eq!(send(Some("identity"), b"hello".to_vec(), 1024).await.1, "5");
    }

    #[tokio::test]
    async fn unsupported_or_stacked_encodings_get_415() {
        for enc in [
            "deflate",
            "br",
            "zstd",
            "compress",
            "gzip, gzip",
            "gzip, br",
            "",
            "bogus",
        ] {
            let (s, _) = send(Some(enc), gzip(b"hello"), 1024).await;
            assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE, "encoding {enc:?}");
        }
    }

    #[tokio::test]
    async fn corrupt_gzip_stream_gets_400() {
        let mut bad = gzip(&[b'a'; 500]);
        let n = bad.len();
        bad[n / 2] ^= 0xFF; // flip a byte mid-stream
        bad.truncate(n - 4); // and cut the CRC trailer
        let (s, _) = send(Some("gzip"), bad, 1024).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = send(Some("gzip"), b"not gzip at all".to_vec(), 1024).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn decompressed_size_limit_is_enforced_exactly() {
        // Small on the wire, 2 MiB decompressed, limit 1 KiB -> 413 (the zip-bomb case).
        let bomb = gzip(&vec![0u8; 2 * 1024 * 1024]);
        assert!(
            bomb.len() < 10_000,
            "test premise: bomb is tiny on the wire"
        );
        assert_eq!(
            send(Some("gzip"), bomb, 1024).await.0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        // Exactly at the limit passes; one byte over fails.
        assert_eq!(
            send(Some("gzip"), gzip(&[0u8; 1024]), 1024).await,
            (StatusCode::OK, "1024".into())
        );
        assert_eq!(
            send(Some("gzip"), gzip(&[0u8; 1025]), 1024).await.0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
