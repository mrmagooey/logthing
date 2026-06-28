//! Axum handler functions for the three HEC / NDJSON ingest routes.
//!
//! All three handlers share the same auth + dispatch pattern:
//! 1. Extract and validate `Authorization: Splunk <token>` header.
//!    NOTE: If the configured token is empty, auth is skipped entirely
//!    (dev-only mode). See [hec] config docs.
//! 2. Parse the body with the appropriate helper.
//! 3. Increment metrics counters.
//! 4. If `ingest.generic_s3` is `Some`, call `try_send` for each record.
//! 5. Return the HEC canonical success envelope or an error response.

use crate::ingest::{
    IngestState,
    check_hec_token,
    parse::{parse_hec_event_body, parse_hec_raw_body, parse_ndjson_body},
};
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
// POST /services/collector/event
// ---------------------------------------------------------------------------

/// HEC event endpoint: one or more newline-delimited event envelope objects.
///
/// Each line: `{"event": <any>, "time": <epoch_float>, "host": "h", "sourcetype": "t"}`
///
/// DEVIATION FROM BRIEF: if `cfg_token` is empty, auth check is skipped entirely
/// (dev-only no-auth mode; see [hec] config docs).
pub async fn handle_hec_event(
    headers: HeaderMap,
    Query(params): Query<HecQueryParams>,
    Extension(cfg_token): Extension<Arc<String>>,
    Extension(ingest): Extension<IngestState>,
    body: Bytes,
) -> impl IntoResponse {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    if !cfg_token.is_empty() && !check_hec_token(auth, &cfg_token) {
        return hec_auth_error();
    }

    let default_st = params.sourcetype.as_deref().unwrap_or(DEFAULT_SOURCETYPE);
    let records = match parse_hec_event_body(&body, default_st) {
        Ok(r) => r,
        Err(e) => return hec_parse_error(&e.to_string()),
    };

    metrics::counter!("hec_events_received").increment(records.len() as u64);

    if let Some(ref handler) = ingest.generic_s3 {
        for rec in records {
            if handler.try_send(rec).is_err() {
                metrics::counter!("hec_events_dropped").increment(1);
                tracing::warn!("HEC S3 channel full; dropped 1 record");
            }
        }
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
/// DEVIATION FROM BRIEF: if `cfg_token` is empty, auth check is skipped entirely
/// (dev-only no-auth mode; see [hec] config docs).
pub async fn handle_hec_raw(
    headers: HeaderMap,
    Query(params): Query<HecQueryParams>,
    Extension(cfg_token): Extension<Arc<String>>,
    Extension(ingest): Extension<IngestState>,
    body: Bytes,
) -> impl IntoResponse {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    if !cfg_token.is_empty() && !check_hec_token(auth, &cfg_token) {
        return hec_auth_error();
    }

    let st = params.sourcetype.as_deref().unwrap_or(DEFAULT_SOURCETYPE);
    let record = match parse_hec_raw_body(&body, st) {
        Ok(r) => r,
        Err(e) => return hec_parse_error(&e.to_string()),
    };

    metrics::counter!("hec_events_received").increment(1);

    if let Some(ref handler) = ingest.generic_s3 {
        if handler.try_send(record).is_err() {
            metrics::counter!("hec_events_dropped").increment(1);
            tracing::warn!("HEC S3 channel full; dropped raw record");
        }
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
/// DEVIATION FROM BRIEF: if `cfg_token` is empty, auth check is skipped entirely
/// (dev-only no-auth mode; see [hec] config docs).
pub async fn handle_ndjson(
    headers: HeaderMap,
    Query(params): Query<HecQueryParams>,
    Extension(cfg_token): Extension<Arc<String>>,
    Extension(ingest): Extension<IngestState>,
    body: Bytes,
) -> impl IntoResponse {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    if !cfg_token.is_empty() && !check_hec_token(auth, &cfg_token) {
        return hec_auth_error();
    }

    let st = params.sourcetype.as_deref().unwrap_or(DEFAULT_SOURCETYPE);
    let records = match parse_ndjson_body(&body, st) {
        Ok(r) => r,
        Err(e) => return hec_parse_error(&e.to_string()),
    };

    metrics::counter!("hec_events_received").increment(records.len() as u64);

    if let Some(ref handler) = ingest.generic_s3 {
        for rec in records {
            if handler.try_send(rec).is_err() {
                metrics::counter!("hec_events_dropped").increment(1);
                tracing::warn!("HEC S3 channel full; dropped 1 NDJSON record");
            }
        }
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
        use axum::{Extension, Router, routing::post};
        let cfg_token = Arc::new(token.to_string());
        let ingest_state = IngestState { generic_s3: None };
        Router::new()
            .route("/services/collector/event", post(handle_hec_event))
            .route("/services/collector/raw", post(handle_hec_raw))
            .route("/ingest", post(handle_ndjson))
            .layer(Extension(cfg_token))
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
            .body(Body::from(br#"{"event":{"k":1},"sourcetype":"t"}"#.as_ref()))
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
            .body(Body::from(br#"{"event":{"k":1},"sourcetype":"t"}"#.as_ref()))
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
        assert!(count >= 1, "hec_events_received must be >= 1 after one POST");
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
}
