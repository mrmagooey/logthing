//! 503 backpressure handling shared by every HTTP subcommand.
//!
//! logthing answers `503` (HEC code 9 / OTLP) with `Retry-After: 1` when a writer channel is
//! full. That is flow control, not a failure: the generator waits as told and retries the SAME
//! body, counting each 503 in `throttled`. Only an eventual 2xx counts as "sent". A request
//! still refused after `max_retries` retries is `abandoned` (and the caller counts it as an
//! error). Retrying holds the caller's concurrency permit, which is the natural slowdown.

use reqwest::{
    RequestBuilder, StatusCode,
    header::{HeaderMap, RETRY_AFTER},
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Sleep used when `Retry-After` is missing or not an integer number of seconds.
pub const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(1);
/// Upper bound on any single `Retry-After` sleep, so a hostile or buggy value cannot stall a run.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Run-wide counters for backpressure, shared by all in-flight request tasks.
#[derive(Debug, Default)]
pub struct Backpressure {
    /// Number of 503 responses received (every attempt counts).
    pub throttled: AtomicU64,
    /// Requests still answered 503 after the final retry.
    pub abandoned: AtomicU64,
}

impl Backpressure {
    /// The summary line the harness parses, e.g.
    /// `loadgen hec-http: backpressure: 12 503 responses, 0 requests abandoned after 5 retries`.
    pub fn summary(&self, sub: &str, max_retries: u32) -> String {
        format!(
            "loadgen {sub}: backpressure: {} 503 responses, {} requests abandoned after {} retries",
            self.throttled.load(Ordering::Relaxed),
            self.abandoned.load(Ordering::Relaxed),
            max_retries
        )
    }
}

/// What one logical request (including its retries) ended as.
#[derive(Debug)]
pub enum SendOutcome {
    /// A 2xx response.
    Accepted,
    /// A non-2xx, non-503 response (never retried).
    Rejected(StatusCode),
    /// 503 on every attempt.
    Abandoned,
    /// Connection/transport failure.
    TransportError(reqwest::Error),
}

/// Parse `Retry-After` as integer seconds; anything else yields [`DEFAULT_RETRY_AFTER`];
/// the result never exceeds [`MAX_RETRY_AFTER`].
pub fn retry_after_delay(headers: &HeaderMap) -> Duration {
    headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_RETRY_AFTER)
        .min(MAX_RETRY_AFTER)
}

/// Send the request built by `build` (called once per attempt, so the body is re-sent
/// identically), retrying 503s up to `max_retries` times, sleeping per `Retry-After`.
pub async fn send_with_retry(
    build: impl Fn() -> RequestBuilder,
    bp: &Backpressure,
    max_retries: u32,
) -> SendOutcome {
    let mut attempt = 0u32;
    loop {
        let resp = match build().send().await {
            Ok(r) => r,
            Err(e) => return SendOutcome::TransportError(e),
        };
        let status = resp.status();
        if status.is_success() {
            return SendOutcome::Accepted;
        }
        if status != StatusCode::SERVICE_UNAVAILABLE {
            return SendOutcome::Rejected(status);
        }
        bp.throttled.fetch_add(1, Ordering::Relaxed);
        if attempt >= max_retries {
            bp.abandoned.fetch_add(1, Ordering::Relaxed);
            return SendOutcome::Abandoned;
        }
        attempt += 1;
        tokio::time::sleep(retry_after_delay(resp.headers())).await;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::StatusCode as AxStatus, response::IntoResponse};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn hm(v: Option<&str>) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        if let Some(v) = v {
            h.insert(reqwest::header::RETRY_AFTER, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn retry_after_integer_seconds_is_honoured() {
        assert_eq!(retry_after_delay(&hm(Some("3"))), Duration::from_secs(3));
        assert_eq!(retry_after_delay(&hm(Some("0"))), Duration::from_secs(0));
    }

    #[test]
    fn retry_after_missing_or_unparseable_falls_back_to_default() {
        assert_eq!(retry_after_delay(&hm(None)), DEFAULT_RETRY_AFTER);
        assert_eq!(retry_after_delay(&hm(Some("soon"))), DEFAULT_RETRY_AFTER);
        // HTTP-date form is legal per RFC 9110 but logthing never sends it.
        assert_eq!(
            retry_after_delay(&hm(Some("Wed, 21 Oct 2026 07:28:00 GMT"))),
            DEFAULT_RETRY_AFTER
        );
    }

    #[test]
    fn retry_after_is_capped() {
        assert_eq!(retry_after_delay(&hm(Some("99999"))), MAX_RETRY_AFTER);
    }

    /// Stub server: answers statuses[i] to request i (last status repeats), always with
    /// `Retry-After: 0` so tests do not sleep. Returns (addr, requests-seen counter).
    async fn stub(statuses: Vec<u16>) -> (SocketAddr, Arc<AtomicUsize>) {
        let seen = Arc::new(AtomicUsize::new(0));
        let s2 = seen.clone();
        let app = Router::new().fallback(move || {
            let i = s2.fetch_add(1, Ordering::SeqCst);
            let code = *statuses.get(i).unwrap_or_else(|| statuses.last().unwrap());
            async move {
                (
                    AxStatus::from_u16(code).unwrap(),
                    [("retry-after", "0")],
                    "",
                )
                    .into_response()
            }
        });
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (addr, seen)
    }

    fn post(addr: SocketAddr) -> impl Fn() -> reqwest::RequestBuilder {
        let c = reqwest::Client::new();
        move || c.post(format!("http://{addr}/x")).body("b")
    }

    #[tokio::test]
    async fn two_503s_then_200_is_accepted_and_counted_as_throttled() {
        let (addr, seen) = stub(vec![503, 503, 200]).await;
        let bp = Backpressure::default();
        let out = send_with_retry(post(addr), &bp, 5).await;
        assert!(matches!(out, SendOutcome::Accepted));
        assert_eq!(bp.throttled.load(Ordering::Relaxed), 2);
        assert_eq!(bp.abandoned.load(Ordering::Relaxed), 0);
        assert_eq!(seen.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn permanent_503_is_abandoned_after_max_retries_without_hanging() {
        let (addr, seen) = stub(vec![503]).await;
        let bp = Backpressure::default();
        let out = send_with_retry(post(addr), &bp, 2).await;
        assert!(matches!(out, SendOutcome::Abandoned));
        assert_eq!(bp.throttled.load(Ordering::Relaxed), 3); // 1 try + 2 retries
        assert_eq!(bp.abandoned.load(Ordering::Relaxed), 1);
        assert_eq!(seen.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn non_503_errors_are_rejected_not_throttled_and_not_retried() {
        for code in [400u16, 401, 413, 415, 500] {
            let (addr, seen) = stub(vec![code]).await;
            let bp = Backpressure::default();
            let out = send_with_retry(post(addr), &bp, 5).await;
            assert!(
                matches!(out, SendOutcome::Rejected(s) if s.as_u16() == code),
                "{code}"
            );
            assert_eq!(bp.throttled.load(Ordering::Relaxed), 0, "{code}");
            assert_eq!(seen.load(Ordering::SeqCst), 1, "{code}");
        }
    }
}
