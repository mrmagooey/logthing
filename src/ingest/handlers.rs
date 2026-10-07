//! Axum handler functions for the three HEC / NDJSON ingest routes.
//!
//! All three handlers share the same auth + dispatch pattern:
//! 1. Extract and validate `Authorization: Splunk <token>` header against
//!    `hec.token`, read from the shared config on every request (same
//!    pattern as `syslog.http_token` / `otlp.bearer_token` in
//!    `src/server/mod.rs`). The token is effectively fixed at startup — nothing
//!    writes the config at runtime now that the admin interface is read-only,
//!    so changing it requires a restart.
//!    NOTE: If the configured token is empty, auth is skipped entirely
//!    (dev-only mode). See [hec] config docs.
//! 2. Parse the body with the appropriate helper.
//! 3. Increment metrics counters.
//! 4. If `ingest.generic_s3` is `Some`, call `try_send` for each record.
//! 5. Return the HEC canonical success envelope or an error response; `503` (`code 9`,
//!    `Retry-After: 1`) when a writer channel is full.

use crate::config::Config;
use crate::forwarding::drop_log::{DropKind, DropSite};
use crate::ingest::{
    IngestState, assign_event_uuids, check_hec_token,
    parse::{parse_hec_event_body, parse_hec_raw_body, parse_ndjson_body},
};
use axum::http::header::RETRY_AFTER;
use axum::{
    Json,
    body::Bytes,
    extract::{Extension, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Query parameters accepted by all three ingest routes.
#[derive(Debug, Deserialize)]
pub struct HecQueryParams {
    /// Explicit sourcetype override; used by `/services/collector/raw` and `/ingest`.
    pub sourcetype: Option<String>,
}

/// Default sourcetype when neither the body envelope nor a query param supplies one.
const DEFAULT_SOURCETYPE: &str = "generic";

// ---------------------------------------------------------------------------
// Shared response helpers
// ---------------------------------------------------------------------------

fn hec_success() -> Response {
    (StatusCode::OK, Json(json!({"text": "Success", "code": 0}))).into_response()
}

/// 503 sent when a writer channel is full: HEC "Server is busy" (code 9) plus `Retry-After`.
fn hec_busy() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(RETRY_AFTER, "1")],
        Json(json!({"text": "Server is busy", "code": 9})),
    )
        .into_response()
}

fn hec_auth_error() -> Response {
    metrics::counter!("hec_auth_failures").increment(1);
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"text": "Token required", "code": 2})),
    )
        .into_response()
}

fn hec_parse_error(msg: &str) -> Response {
    metrics::counter!("hec_parse_errors").increment(1);
    tracing::warn!("HEC parse error: {}", msg);
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"text": "Invalid data format", "code": 6})),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Shared dispatch — try both persistence targets independently
// ---------------------------------------------------------------------------

/// Try-send one record to every configured HEC/generic persistence target
/// (`.s3` and/or `.local`), independently. A full/closed channel on one
/// target does not affect delivery to the other — each is attempted and
/// logged separately. `context` is a short phrase describing what was
/// dropped (e.g. `"1 record"`, `"raw record"`), reused in both targets' log
/// lines to match the wording already used for the S3-only path.
///
/// HEC/generic has no `Handler` trait to abstract a fan-out over (unlike
/// Zeek/Suricata/IPFIX/sFlow/syslog) — `IngestState` holds concrete sibling
/// `Option<GenericS3Handler>` fields instead, per the architecture review's
/// explicit rejection of a `MultiHandler`-style wrapper for this source.
fn dispatch_generic_record(
    ingest: &IngestState,
    record: crate::ingest::GenericRecord,
    context: &str,
) -> bool {
    let mut full = false;
    if let Some(ref handler) = ingest.generic_s3
        && let Err(e) = handler.try_send(record.clone())
    {
        metrics::counter!("hec_events_dropped").increment(1);
        let kind = DropKind::from(&e);
        full |= matches!(kind, DropKind::Full);
        if let Some(dropped_total) = handler.drop_log_due(DropSite::Hec, kind) {
            match kind {
                DropKind::Full => {
                    tracing::warn!(dropped_total, "HEC S3 channel full; dropped {context}");
                }
                DropKind::Closed => {
                    tracing::error!(dropped_total, "HEC S3 channel closed; dropped {context}");
                }
            }
        }
    }
    if let Some(ref handler) = ingest.generic_local
        && let Err(e) = handler.try_send(record)
    {
        metrics::counter!("hec_events_dropped").increment(1);
        let kind = DropKind::from(&e);
        full |= matches!(kind, DropKind::Full);
        if let Some(dropped_total) = handler.drop_log_due(DropSite::Hec, kind) {
            match kind {
                DropKind::Full => {
                    tracing::warn!(dropped_total, "HEC local channel full; dropped {context}");
                }
                DropKind::Closed => {
                    tracing::error!(dropped_total, "HEC local channel closed; dropped {context}");
                }
            }
        }
    }
    full
}

/// Offer a request's records in order, STOPPING at the first one that meets a full channel.
///
/// "Overloaded" means `try_send` returned `Full` on ANY configured sink (instantaneous, no
/// averaging); a record accepted by one sink and rejected by the other is also a 503
/// (at-least-once toward the client). `Err(n)` = `n` records (the full one plus those never
/// offered) were not accepted and the request must be answered 503. Records already enqueued
/// stay enqueued: a client retry re-sends them and they get NEW `event_uuid`s (retries cannot
/// be de-duplicated). A `Closed` channel (writer gone) is counted and logged but does not cause
/// an `Err`: retrying against a dead writer cannot help, so the request is still answered 200.
fn dispatch_generic_batch(
    ingest: &IngestState,
    records: Vec<crate::ingest::GenericRecord>,
    context: &str,
) -> Result<(), usize> {
    let total = records.len();
    for (i, record) in records.into_iter().enumerate() {
        if dispatch_generic_record(ingest, record, context) {
            let never_offered = total - i - 1;
            if never_offered > 0 {
                metrics::counter!("hec_events_dropped").increment(never_offered as u64);
            }
            return Err(total - i);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// POST /services/collector/event
// ---------------------------------------------------------------------------

/// HEC event endpoint: one or more newline-delimited event envelope objects.
///
/// Each line: `{"event": <any>, "time": <epoch_float>, "host": "h", "sourcetype": "t"}`
///
/// DEVIATION FROM BRIEF: if `hec.token` is empty, auth check is skipped
/// entirely (dev-only no-auth mode; see [hec] config docs). The token is
/// read from `config` on every request, but the value is effectively fixed
/// at startup — nothing writes the config at runtime now that the admin
/// interface is read-only, so changing it requires a restart.
pub async fn handle_hec_event(
    headers: HeaderMap,
    Query(params): Query<HecQueryParams>,
    Extension(config): Extension<Arc<RwLock<Config>>>,
    Extension(ingest): Extension<IngestState>,
    body: Bytes,
) -> impl IntoResponse {
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
    {
        let cfg = config.read().await;
        if !cfg.hec.token.is_empty() && !check_hec_token(auth, &cfg.hec.token) {
            return hec_auth_error();
        }
    }

    let default_st = params.sourcetype.as_deref().unwrap_or(DEFAULT_SOURCETYPE);
    let mut records = match parse_hec_event_body(&body, default_st) {
        Ok(r) => r,
        Err(e) => return hec_parse_error(&e.to_string()),
    };
    // Identity is assigned after parse (and, in a later phase, after redaction).
    assign_event_uuids(&mut records);

    metrics::counter!("hec_events_received").increment(records.len() as u64);

    if dispatch_generic_batch(&ingest, records, "1 record").is_err() {
        return hec_busy();
    }
    hec_success()
}

// ---------------------------------------------------------------------------
// POST /services/collector/raw
// ---------------------------------------------------------------------------

/// HEC raw endpoint: the entire body is stored as a single raw string record.
///
/// Sourcetype is taken from `?sourcetype=` query param; falls back to `DEFAULT_SOURCETYPE`.
///
/// DEVIATION FROM BRIEF: if `hec.token` is empty, auth check is skipped
/// entirely (dev-only no-auth mode; see [hec] config docs). The token is
/// read from `config` on every request, but the value is effectively fixed
/// at startup — nothing writes the config at runtime now that the admin
/// interface is read-only, so changing it requires a restart.
pub async fn handle_hec_raw(
    headers: HeaderMap,
    Query(params): Query<HecQueryParams>,
    Extension(config): Extension<Arc<RwLock<Config>>>,
    Extension(ingest): Extension<IngestState>,
    body: Bytes,
) -> impl IntoResponse {
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
    {
        let cfg = config.read().await;
        if !cfg.hec.token.is_empty() && !check_hec_token(auth, &cfg.hec.token) {
            return hec_auth_error();
        }
    }

    let st = params.sourcetype.as_deref().unwrap_or(DEFAULT_SOURCETYPE);
    let mut record = match parse_hec_raw_body(&body, st) {
        Ok(r) => r,
        Err(e) => return hec_parse_error(&e.to_string()),
    };
    assign_event_uuids(std::slice::from_mut(&mut record));

    metrics::counter!("hec_events_received").increment(1);

    if dispatch_generic_batch(&ingest, vec![record], "raw record").is_err() {
        return hec_busy();
    }
    hec_success()
}

// ---------------------------------------------------------------------------
// POST /ingest
// ---------------------------------------------------------------------------

/// Plain NDJSON ingest: each line is a JSON object stored as-is in `fields`.
///
/// Sourcetype is taken from `?sourcetype=` query param; falls back to `DEFAULT_SOURCETYPE`.
///
/// DEVIATION FROM BRIEF: if `hec.token` is empty, auth check is skipped
/// entirely (dev-only no-auth mode; see [hec] config docs). The token is
/// read from `config` on every request, but the value is effectively fixed
/// at startup — nothing writes the config at runtime now that the admin
/// interface is read-only, so changing it requires a restart.
pub async fn handle_ndjson(
    headers: HeaderMap,
    Query(params): Query<HecQueryParams>,
    Extension(config): Extension<Arc<RwLock<Config>>>,
    Extension(ingest): Extension<IngestState>,
    body: Bytes,
) -> impl IntoResponse {
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
    {
        let cfg = config.read().await;
        if !cfg.hec.token.is_empty() && !check_hec_token(auth, &cfg.hec.token) {
            return hec_auth_error();
        }
    }

    let st = params.sourcetype.as_deref().unwrap_or(DEFAULT_SOURCETYPE);
    let mut records = match parse_ndjson_body(&body, st) {
        Ok(r) => r,
        Err(e) => return hec_parse_error(&e.to_string()),
    };
    assign_event_uuids(&mut records);

    metrics::counter!("hec_events_received").increment(records.len() as u64);

    if dispatch_generic_batch(&ingest, records, "1 NDJSON record").is_err() {
        return hec_busy();
    }
    hec_success()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    fn make_router(token: &str) -> axum::Router {
        let mut cfg = Config::default();
        cfg.hec.token = token.to_string();
        make_router_with_config(Arc::new(RwLock::new(cfg)))
    }

    /// Like `make_router`, but the caller keeps the `Arc<RwLock<Config>>` so
    /// it can mutate `hec.token` mid-test and prove the change is picked up
    /// live — no router rebuild, matching the live-reload contract in
    /// `handle_hec_event`/`handle_hec_raw`/`handle_ndjson`'s doc comments.
    fn make_router_with_config(config: Arc<RwLock<Config>>) -> axum::Router {
        make_router_with_ingest(config, IngestState::default())
    }

    fn make_router_with_ingest(
        config: Arc<RwLock<Config>>,
        ingest_state: IngestState,
    ) -> axum::Router {
        use axum::{Extension, Router, routing::post};
        Router::new()
            .route("/services/collector/event", post(handle_hec_event))
            .route("/services/collector/raw", post(handle_hec_raw))
            .route("/ingest", post(handle_ndjson))
            .layer(Extension(config))
            .layer(Extension(ingest_state))
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let b = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        serde_json::from_slice(&b).unwrap()
    }

    // --- Auth tests (non-empty token configured) ---

    #[tokio::test]
    async fn hec_event_missing_auth_returns_401() {
        let app = make_router("secret");
        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/event")
            .body(Body::from(
                br#"{"event":{"k":1},"sourcetype":"t"}"#.as_ref(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp).await;
        assert_eq!(body["code"], 2);
    }

    #[tokio::test]
    async fn hec_event_wrong_token_returns_401() {
        let app = make_router("secret");
        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/event")
            .header("Authorization", "Splunk wrong-token")
            .body(Body::from(
                br#"{"event":{"k":1},"sourcetype":"t"}"#.as_ref(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp).await;
        assert_eq!(body["code"], 2);
    }

    #[tokio::test]
    async fn hec_raw_missing_auth_returns_401() {
        let app = make_router("secret");
        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/raw")
            .body(Body::from("raw log line"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp).await;
        assert_eq!(body["code"], 2);
    }

    #[tokio::test]
    async fn hec_raw_wrong_token_returns_401() {
        let app = make_router("secret");
        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/raw")
            .header("Authorization", "Splunk wrong-token")
            .body(Body::from("raw log line"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ndjson_missing_auth_returns_401() {
        let app = make_router("secret");
        let req = Request::builder()
            .method("POST")
            .uri("/ingest")
            .body(Body::from("{\"k\":1}\n"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp).await;
        assert_eq!(body["code"], 2);
    }

    #[tokio::test]
    async fn ndjson_wrong_token_returns_401() {
        let app = make_router("secret");
        let req = Request::builder()
            .method("POST")
            .uri("/ingest")
            .header("Authorization", "Splunk wrong-token")
            .body(Body::from("{\"k\":1}\n"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn hec_event_valid_token_returns_200() {
        let app = make_router("correct-token");
        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/event")
            .header("Authorization", "Splunk correct-token")
            .body(Body::from(
                br#"{"event":{"action":"test"},"sourcetype":"myapp"}"#.as_ref(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["text"], "Success");
        assert_eq!(body["code"], 0);
    }

    // --- Parse error tests ---

    #[tokio::test]
    async fn hec_event_invalid_json_returns_400() {
        let app = make_router("tok");
        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/event")
            .header("Authorization", "Splunk tok")
            .body(Body::from("not json at all"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["code"], 6);
    }

    // --- Raw endpoint ---

    #[tokio::test]
    async fn hec_raw_valid_returns_200() {
        let app = make_router("tok");
        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/raw?sourcetype=myraw")
            .header("Authorization", "Splunk tok")
            .body(Body::from("raw log line here"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["text"], "Success");
    }

    #[tokio::test]
    async fn hec_raw_uses_default_sourcetype_when_query_absent() {
        let app = make_router("tok");
        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/raw")
            .header("Authorization", "Splunk tok")
            .body(Body::from("some raw bytes"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // --- NDJSON endpoint ---

    #[tokio::test]
    async fn ndjson_valid_returns_200() {
        let app = make_router("tok");
        let body = b"{\"host\":\"h1\",\"msg\":\"a\"}\n{\"host\":\"h2\",\"msg\":\"b\"}\n";
        let req = Request::builder()
            .method("POST")
            .uri("/ingest?sourcetype=mytype")
            .header("Authorization", "Splunk tok")
            .body(Body::from(body.as_ref()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ndjson_invalid_json_returns_400() {
        let app = make_router("tok");
        let req = Request::builder()
            .method("POST")
            .uri("/ingest")
            .header("Authorization", "Splunk tok")
            .body(Body::from("not json\n"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["code"], 6);
    }

    // NOTE: hec_raw has no parse-error path. `parse_hec_raw_body` wraps any
    // bytes via `String::from_utf8_lossy` and always returns Ok, so the raw
    // endpoint cannot produce a 400. No parse-error test exists for it.

    // --- Metrics counter smoke-test ---
    #[tokio::test]
    async fn hec_event_increments_received_counter() {
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let app = make_router("tok");
        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/event")
            .header("Authorization", "Splunk tok")
            .body(Body::from(
                br#"{"event":{"k":1},"sourcetype":"t"}"#.as_ref(),
            ))
            .unwrap();
        let _ = app.oneshot(req).await.unwrap();

        let snapshot = snapshotter.snapshot();
        // metrics_util::CompositeKey contains AtomicBool (interior mutability); the
        // HashMap is read-only after construction so this lint is a false positive.
        #[allow(clippy::mutable_key_type)]
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_name("hec_events_received"),
        );
        let count = map
            .get(&key)
            .map(|(_, _, v)| {
                if let metrics_util::debugging::DebugValue::Counter(c) = v {
                    *c
                } else {
                    0
                }
            })
            .unwrap_or(0);
        assert!(
            count >= 1,
            "hec_events_received must be >= 1 after one POST"
        );
    }

    // --- Empty-token dev mode tests ---

    /// When the configured token is empty, ALL requests are accepted regardless
    /// of Authorization header (local dev only — no-auth mode).
    #[tokio::test]
    async fn empty_token_hec_event_no_auth_returns_200() {
        let app = make_router(""); // empty token → dev mode
        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/event")
            // NO Authorization header
            .body(Body::from(
                br#"{"event":{"k":1},"sourcetype":"t"}"#.as_ref(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["code"], 0);
    }

    #[tokio::test]
    async fn empty_token_hec_raw_no_auth_returns_200() {
        let app = make_router(""); // empty token → dev mode
        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/raw")
            // NO Authorization header
            .body(Body::from("raw log line"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["code"], 0);
    }

    #[tokio::test]
    async fn empty_token_ndjson_no_auth_returns_200() {
        let app = make_router(""); // empty token → dev mode
        let req = Request::builder()
            .method("POST")
            .uri("/ingest")
            // NO Authorization header
            .body(Body::from("{\"k\":1}\n"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["code"], 0);
    }

    // --- Live hec.token reload (no restart) ---

    /// A `hec.token` change written through the shared `Arc<RwLock<Config>>`
    /// must take effect on the very next request — no router rebuild
    /// required. Mirrors the finding this fixes: before it, `hec.token` was
    /// snapshotted into an `Extension<Arc<String>>` at router-construction
    /// time, so a changed value was never actually enforced without
    /// rebuilding the router.
    #[tokio::test]
    async fn hec_token_change_takes_effect_on_next_request_without_restart() {
        let mut cfg = Config::default();
        cfg.hec.token = "old-token".to_string();
        let shared_config = Arc::new(RwLock::new(cfg));
        let app = make_router_with_config(shared_config.clone());

        let request_with = |token: &str| {
            Request::builder()
                .method("POST")
                .uri("/services/collector/event")
                .header("Authorization", format!("Splunk {token}"))
                .body(Body::from(
                    br#"{"event":{"k":1},"sourcetype":"t"}"#.as_ref(),
                ))
                .unwrap()
        };

        // Old token works before the change.
        let resp = app
            .clone()
            .oneshot(request_with("old-token"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Write straight through the SAME `Arc<RwLock<Config>>` the
        // router's `Extension` holds, exactly as a future config-reload
        // mechanism would.
        {
            let mut cfg = shared_config.write().await;
            cfg.hec.token = "new-token".to_string();
        }

        // Old (leaked) token is now rejected by the handler on the next request.
        let resp = app
            .clone()
            .oneshot(request_with("old-token"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "the old token must stop working immediately after an admin rotates it"
        );

        // New token is accepted on the very next request.
        let resp = app.oneshot(request_with("new-token")).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the new token must work immediately, without a process restart"
        );
    }

    #[tokio::test]
    async fn hec_routes_assign_event_uuid_and_keep_envelope_fields() {
        use crate::forwarding::buffered_writer::ParquetWriterHandle;
        use crate::forwarding::generic_s3::GenericSink;
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let ingest = IngestState {
            generic_s3: Some(ParquetWriterHandle::<GenericSink>::for_test(
                tx, "hec", "test",
            )),
            ..Default::default()
        };
        let app = make_router_with_ingest(Arc::new(RwLock::new(Config::default())), ingest);

        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/event")
            .body(Body::from(
                r#"{"event":{"k":1},"source":"s1","index":"main","fields":{"a":"b"}}
{"event":"two"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let first = rx.recv().await.unwrap();
        let second = rx.recv().await.unwrap();
        assert_eq!(first.source.as_deref(), Some("s1"));
        assert_eq!(first.index.as_deref(), Some("main"));
        assert_eq!(first.indexed_fields, Some(serde_json::json!({"a": "b"})));
        let (a, b) = (first.event_uuid.unwrap(), second.event_uuid.unwrap());
        assert_ne!(a, b);
        assert_eq!(uuid::Uuid::parse_str(&a).unwrap().get_version_num(), 7);

        // raw and NDJSON routes assign too.
        for (uri, body) in [
            ("/services/collector/raw", "plain text"),
            ("/ingest", "{\"x\":1}\n"),
        ] {
            let req = Request::builder()
                .method("POST")
                .uri(uri)
                .body(Body::from(body))
                .unwrap();
            assert_eq!(
                app.clone().oneshot(req).await.unwrap().status(),
                StatusCode::OK
            );
            let rec = rx.recv().await.unwrap();
            assert!(rec.event_uuid.is_some(), "{uri} must assign event_uuid");
        }
    }

    fn stalled_ingest(
        capacity: usize,
    ) -> (
        IngestState,
        tokio::sync::mpsc::Receiver<crate::ingest::GenericRecord>,
    ) {
        use crate::forwarding::buffered_writer::ParquetWriterHandle;
        use crate::forwarding::generic_s3::GenericSink;
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        (
            IngestState {
                generic_s3: Some(ParquetWriterHandle::<GenericSink>::for_test(
                    tx, "hec", "test",
                )),
                ..Default::default()
            },
            rx,
        )
    }

    fn post(uri: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn hec_event_full_channel_returns_503_code_9_with_retry_after() {
        let (ingest, mut rx) = stalled_ingest(1);
        let app = make_router_with_ingest(Arc::new(RwLock::new(Config::default())), ingest);
        let ok = app
            .clone()
            .oneshot(post("/services/collector/event", r#"{"event":"one"}"#))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        let busy = app
            .oneshot(post("/services/collector/event", r#"{"event":"two"}"#))
            .await
            .unwrap();
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(busy.headers().get("retry-after").unwrap(), "1");
        assert_eq!(
            body_json(busy).await,
            serde_json::json!({"text": "Server is busy", "code": 9})
        );
        assert!(rx.try_recv().is_ok(), "first record stayed enqueued");
        assert!(rx.try_recv().is_err(), "rejected record was not enqueued");
    }

    #[tokio::test]
    async fn hec_event_partial_batch_stops_at_first_full_and_returns_503() {
        let (ingest, mut rx) = stalled_ingest(2);
        let app = make_router_with_ingest(Arc::new(RwLock::new(Config::default())), ingest);
        let resp = app
            .oneshot(post(
                "/services/collector/event",
                "{\"event\":1}\n{\"event\":2}\n{\"event\":3}\n{\"event\":4}",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let mut n = 0;
        while rx.try_recv().is_ok() {
            n += 1;
        }
        assert_eq!(
            n, 2,
            "the prefix that fit stays enqueued; the rest is never offered"
        );
    }

    #[tokio::test]
    async fn raw_and_ndjson_full_channel_return_503() {
        for (uri, body) in [
            ("/services/collector/raw", "plain"),
            ("/ingest", "{\"a\":1}\n"),
        ] {
            let (ingest, _rx) = stalled_ingest(1);
            let app = make_router_with_ingest(Arc::new(RwLock::new(Config::default())), ingest);
            assert_eq!(
                app.clone().oneshot(post(uri, body)).await.unwrap().status(),
                StatusCode::OK
            );
            let busy = app.oneshot(post(uri, body)).await.unwrap();
            assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
            assert_eq!(busy.headers().get("retry-after").unwrap(), "1");
        }
    }

    #[tokio::test]
    async fn closed_channel_keeps_returning_200() {
        let (ingest, rx) = stalled_ingest(1);
        drop(rx); // writer gone
        let app = make_router_with_ingest(Arc::new(RwLock::new(Config::default())), ingest);
        let resp = app
            .oneshot(post("/services/collector/event", r#"{"event":"x"}"#))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn hec_one_sink_full_other_ok_is_503() {
        use crate::forwarding::buffered_writer::ParquetWriterHandle;
        use crate::forwarding::generic_s3::GenericSink;
        let (full_tx, _full_rx) = tokio::sync::mpsc::channel(1);
        let (roomy_tx, mut roomy_rx) = tokio::sync::mpsc::channel(16);
        let ingest = IngestState {
            generic_s3: Some(ParquetWriterHandle::<GenericSink>::for_test(
                full_tx, "hec", "s3",
            )),
            generic_local: Some(ParquetWriterHandle::<GenericSink>::for_test(
                roomy_tx, "hec", "local",
            )),
            ..Default::default()
        };
        let app = make_router_with_ingest(Arc::new(RwLock::new(Config::default())), ingest);
        let uri = "/services/collector/event";
        assert_eq!(
            app.clone()
                .oneshot(post(uri, r#"{"event":1}"#))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let busy = app.oneshot(post(uri, r#"{"event":2}"#)).await.unwrap();
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(roomy_rx.try_recv().is_ok());
        assert!(roomy_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn hec_events_dropped_counts_full_and_never_offered_records() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let (ingest, _rx) = stalled_ingest(1);
        let app = make_router_with_ingest(Arc::new(RwLock::new(Config::default())), ingest);
        let resp = app
            .oneshot(post(
                "/services/collector/event",
                "{\"event\":1}\n{\"event\":2}\n{\"event\":3}",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let dropped: u64 = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter(|(k, ..)| k.key().name() == "hec_events_dropped")
            .map(|(_, _, _, v)| match v {
                metrics_util::debugging::DebugValue::Counter(c) => c,
                _ => 0,
            })
            .sum();
        assert_eq!(dropped, 2, "record 2 hit Full, record 3 never offered");
    }
}
