//! `/wsman/**` handlers: the Windows-compatible WEF subscription manager and delivery
//! endpoints (plaintext path).
//!
//! A request is decoded in four stages (SLDC decode-or-raw, charset decode, SOAP parse,
//! dispatch). Delivery acknowledgements are built only after the events were handed to the
//! forwarding sinks; a full sink channel is a counted drop, not a failure (the sinks'
//! drop semantics are unchanged).

use super::{AppState, MAX_BODY_SIZE, process_events};
use crate::wef::soap::{self, SoapRequest, WefAction};
use crate::wef::subscription::{Subscription, render_subscription_item};
use crate::wef::{encoding, event, sldc};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::Response,
    routing::post,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Content type of every non-empty `/wsman/**` response on the plaintext path.
const SOAP_UTF16: &str = "application/soap+xml;charset=UTF-16";

/// Routes mounted on the protected router.
pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/wsman", post(handle_wsman))
        .route("/wsman/*rest", post(handle_wsman))
}

/// Where a `/wsman/**` path leads.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// Subscription manager (anything outside `/wsman/subscriptions/`).
    Manager,
    /// Delivery endpoint for one subscription.
    Delivery(Uuid),
    /// Malformed delivery path.
    NotFound,
}

fn route_target(path: &str) -> Target {
    let Some(rest) = path.strip_prefix("/wsman/subscriptions/") else {
        return Target::Manager;
    };
    let mut segs = rest.split('/');
    let uuid = segs.next().and_then(|s| Uuid::parse_str(s).ok());
    // A fourth path segment is the subscription version counter Windows appends; it must be
    // numeric and nothing may follow it.
    let tail_ok = match (segs.next(), segs.next()) {
        (None, _) => true,
        (Some(n), None) => !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()),
        _ => false,
    };
    match uuid {
        Some(u) if tail_ok => Target::Delivery(u),
        _ => Target::NotFound,
    }
}

fn status(code: StatusCode) -> Response {
    Response::builder()
        .status(code)
        .body(Body::empty())
        .expect("static response")
}

/// 200 with no `Content-Type` and no body.
fn empty_ok() -> Response {
    status(StatusCode::OK)
}

fn soap_ok(bytes: Vec<u8>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, SOAP_UTF16)
        .body(Body::from(bytes))
        .expect("static response")
}

/// Fixed label per action; wire text never reaches a metric label.
fn action_label(a: WefAction) -> &'static str {
    match a {
        WefAction::Enumerate => "enumerate",
        WefAction::Heartbeat => "heartbeat",
        WefAction::Events => "events",
        WefAction::SubscriptionEnd => "subscription_end",
        WefAction::End => "end",
        WefAction::Unknown => "unknown",
    }
}

/// Entry point for every `POST /wsman` and `POST /wsman/**`.
async fn handle_wsman(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if state.wef.is_none() {
        return status(StatusCode::NOT_FOUND);
    }
    let target = route_target(uri.path());
    if target == Target::NotFound {
        return status(StatusCode::NOT_FOUND);
    }

    let sldc_encoded = match headers.get(header::CONTENT_ENCODING) {
        None => false,
        Some(v) if v.as_bytes().eq_ignore_ascii_case(b"sldc") => true,
        Some(_) => return status(StatusCode::UNSUPPORTED_MEDIA_TYPE),
    };
    if body.is_empty() {
        return empty_ok();
    }
    let raw = if sldc_encoded {
        sldc::decode_or_raw(&body, MAX_BODY_SIZE)
    } else {
        std::borrow::Cow::Borrowed(&body[..])
    };
    let text = match encoding::decode_body(&raw) {
        Ok(t) => t,
        Err(e) => {
            warn!(
                "WEF body from {} has an undecodable charset: {}",
                addr.ip(),
                crate::sanitize_for_log(&format!("{e:#}"), 128)
            );
            return status(StatusCode::BAD_REQUEST);
        }
    };
    let req = match soap::parse(&text) {
        Ok(r) => r,
        Err(e) => {
            // The parser error embeds wire element names, so it is sanitised like any wire text.
            warn!(
                "WEF request from {} is not valid SOAP: {}",
                addr.ip(),
                crate::sanitize_for_log(&format!("{e:#}"), 128)
            );
            return status(StatusCode::BAD_REQUEST);
        }
    };
    metrics::counter!("wef_requests_total", "action" => action_label(req.action)).increment(1);

    match target {
        Target::Delivery(uuid) => delivery(&state, addr, uuid, &req).await,
        _ => manager(&state, &req),
    }
}

fn manager(state: &AppState, req: &SoapRequest) -> Response {
    match req.action {
        WefAction::Enumerate => {
            if req.message_id.is_none() {
                return status(StatusCode::BAD_REQUEST);
            }
            let Some(rt) = state.wef.as_ref() else {
                return status(StatusCode::NOT_FOUND);
            };
            let items: Vec<String> = rt
                .subscriptions
                .iter()
                .map(|s| {
                    let bookmark = req
                        .machine_id
                        .as_deref()
                        .and_then(|m| state.bookmarks.get(m, s.cfg.uuid));
                    render_subscription_item(rt, s, bookmark.as_deref())
                })
                .collect();
            match soap::build_enumerate_response(req, &items) {
                Ok(b) => soap_ok(b),
                Err(_) => status(StatusCode::BAD_REQUEST),
            }
        }
        WefAction::End => empty_ok(),
        _ => status(StatusCode::BAD_REQUEST),
    }
}

async fn delivery(
    state: &Arc<AppState>,
    addr: SocketAddr,
    uuid: Uuid,
    req: &SoapRequest,
) -> Response {
    let Some(sub) = state
        .wef
        .as_ref()
        .and_then(|rt| rt.subscriptions.iter().find(|s| s.cfg.uuid == uuid))
    else {
        return status(StatusCode::NOT_FOUND);
    };
    match req.action {
        WefAction::Heartbeat => {
            debug!(
                "WEF heartbeat from {} for subscription {}",
                crate::sanitize_for_log(req.machine_id.as_deref().unwrap_or("-"), 128),
                crate::sanitize_for_log(&sub.cfg.name, 128)
            );
            ack(req)
        }
        WefAction::Events => {
            // Reject before ingesting: an un-ackable batch would be redelivered and duplicated.
            if req.message_id.is_none() {
                return status(StatusCode::BAD_REQUEST);
            }
            ingest(state, addr, sub, req).await;
            ack(req)
        }
        WefAction::SubscriptionEnd | WefAction::End => empty_ok(),
        _ => status(StatusCode::BAD_REQUEST),
    }
}

async fn ingest(state: &Arc<AppState>, addr: SocketAddr, sub: &Subscription, req: &SoapRequest) {
    let events = event::extract_events(&req.events, &addr.ip().to_string(), &sub.cfg.name);
    info!(
        "WEF: {} events from {} for subscription {}",
        events.len(),
        crate::sanitize_for_log(req.machine_id.as_deref().unwrap_or("-"), 128),
        crate::sanitize_for_log(&sub.cfg.name, 128)
    );
    process_events(state, events).await;
    if let (Some(bookmark), Some(machine)) = (&req.bookmark, &req.machine_id)
        && !state.bookmarks.put(machine, sub.cfg.uuid, bookmark.clone())
    {
        debug!(
            "WEF bookmark from {} rejected",
            crate::sanitize_for_log(machine, 128)
        );
    }
}

fn ack(req: &SoapRequest) -> Response {
    match soap::build_ack(req) {
        Ok(b) => soap_ok(b),
        Err(_) => status(StatusCode::BAD_REQUEST),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ContentFormat, WefSubscriptionConfig};
    use crate::forwarding::buffered_writer::ParquetWriterHandle;
    use crate::stats::ThroughputStats;
    use crate::wef::bookmarks::BookmarkStore;
    use crate::wef::subscription::validate_wef_topology;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    const SUB_UUID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
    const ENUMERATE: &str = include_str!("../../tests/fixtures/wef/golden/enumerate.xml");
    const HEARTBEAT: &str = include_str!("../../tests/fixtures/wef/golden/heartbeat.xml");
    const EVENTS: &str = include_str!("../../tests/fixtures/wef/golden/events.xml");
    const SUB_END: &str = include_str!("../../tests/fixtures/wef/golden/subscription_end.xml");
    const END: &str = include_str!("../../tests/fixtures/wef/golden/end.xml");

    fn config() -> Config {
        let mut c = Config::default();
        c.tls.enabled = false;
        c.wef.collector_url = Some("http://logthing.example.com:5985".into());
        c.wef.allow_unauthenticated = true;
        c.wef.subscriptions = vec![WefSubscriptionConfig {
            name: "security".into(),
            uuid: SUB_UUID.parse().unwrap(),
            channels: vec!["Security".into()],
            query: None,
            content_format: ContentFormat::Raw,
            heartbeat_interval_secs: 3600,
            max_latency_secs: 30,
            max_envelope_size: 512_000,
            read_existing_events: false,
            enabled: true,
        }];
        c
    }

    fn state_with(
        wef: bool,
        s3: Option<ParquetWriterHandle<crate::forwarding::parquet_s3::WefSink>>,
    ) -> Arc<AppState> {
        let cfg = config();
        let rt = validate_wef_topology(&cfg, false)
            .unwrap()
            .filter(|_| wef)
            .map(Arc::new);
        Arc::new(AppState {
            config: Arc::new(RwLock::new(cfg)),
            throughput: Arc::new(ThroughputStats::new()),
            wef_cardinality_watchers: Vec::new(),
            wef: rt,
            bookmarks: Arc::new(BookmarkStore::new(16)),
            event_parser: None,
            parquet_s3_sender: s3,
            parquet_local_sender: None,
        })
    }

    fn app(state: &Arc<AppState>) -> Router {
        let addr: SocketAddr = "192.0.2.7:5985".parse().unwrap();
        routes()
            .with_state(state.clone())
            .layer(MockConnectInfo(addr))
    }

    fn utf16(s: &str) -> Vec<u8> {
        encoding::encode_utf16le_bom(s)
    }

    async fn post(
        app: &Router,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut b = Request::builder().method("POST").uri(path);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let resp = app
            .clone()
            .oneshot(b.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        (parts.status, parts.headers, bytes.to_vec())
    }

    fn text(bytes: &[u8]) -> String {
        encoding::decode_body(bytes).unwrap()
    }

    fn delivery_path() -> String {
        format!("/wsman/subscriptions/{SUB_UUID}")
    }

    #[tokio::test]
    async fn test_wsman_enumerate_returns_subscription_items() {
        let app = app(&state_with(true, None));
        let (st, h, body) = post(&app, "/wsman", &[], utf16(ENUMERATE)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(h[header::CONTENT_TYPE], SOAP_UTF16);
        let s = text(&body);
        assert_eq!(s.matches("<m:Subscription").count(), 1, "{s}");
        assert!(s.contains(&format!("/wsman/subscriptions/{SUB_UUID}")));
    }

    #[tokio::test]
    async fn test_wsman_enumerate_utf16_response_relates_to() {
        let app = app(&state_with(true, None));
        let (_, _, body) = post(
            &app,
            "/wsman/SubscriptionManager/WEC",
            &[],
            utf16(ENUMERATE),
        )
        .await;
        assert_eq!(&body[..2], &[0xFF, 0xFE]);
        let s = text(&body);
        assert!(!s.starts_with("<?xml"));
        let req = soap::parse(ENUMERATE).unwrap();
        let mid = req.message_id.unwrap();
        assert!(s.contains(&format!("<a:RelatesTo>{mid}</a:RelatesTo>")));
    }

    #[tokio::test]
    async fn test_wsman_end_returns_empty_200() {
        let app = app(&state_with(true, None));
        let (st, h, body) = post(&app, "/wsman", &[], utf16(END)).await;
        assert_eq!(st, StatusCode::OK);
        assert!(h.get(header::CONTENT_TYPE).is_none());
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn test_wsman_empty_body_returns_empty_200() {
        let app = app(&state_with(true, None));
        let (st, h, body) = post(&app, "/wsman", &[], Vec::new()).await;
        assert_eq!(st, StatusCode::OK);
        assert!(h.get(header::CONTENT_TYPE).is_none() && body.is_empty());
    }

    #[tokio::test]
    async fn test_wsman_disabled_returns_404() {
        let app = app(&state_with(false, None));
        for path in ["/wsman", "/wsman/x", &delivery_path()] {
            let (st, _, _) = post(&app, path, &[], utf16(ENUMERATE)).await;
            assert_eq!(st, StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[tokio::test]
    async fn test_delivery_heartbeat_acks() {
        let app = app(&state_with(true, None));
        let (st, h, body) = post(&app, &delivery_path(), &[], utf16(HEARTBEAT)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(h[header::CONTENT_TYPE], SOAP_UTF16);
        let s = text(&body);
        assert!(s.contains(soap::ACTION_ACK));
        let mid = soap::parse(HEARTBEAT).unwrap().message_id.unwrap();
        assert!(s.contains(&format!("<a:RelatesTo>{mid}</a:RelatesTo>")));
    }

    #[tokio::test]
    async fn test_delivery_events_acks_and_ingests() {
        let state = state_with(true, None);
        let app = app(&state);
        let (st, _, body) = post(&app, &delivery_path(), &[], utf16(EVENTS)).await;
        assert_eq!(st, StatusCode::OK);
        assert!(text(&body).contains(soap::ACTION_ACK));
        let total: u64 = state
            .throughput
            .snapshot()
            .await
            .iter()
            .map(|e| e.total_events)
            .sum();
        assert_eq!(total, 2);
    }

    #[tokio::test]
    async fn test_delivery_events_stores_bookmark_and_enumerate_replays_it() {
        let state = state_with(true, None);
        let app = app(&state);
        post(&app, &delivery_path(), &[], utf16(EVENTS)).await;
        let uuid: Uuid = SUB_UUID.parse().unwrap();
        let stored = state.bookmarks.get("win10.example.com", uuid).unwrap();
        assert!(stored.contains("RecordId=\"1042\""));
        let (_, _, body) = post(&app, "/wsman", &[], utf16(ENUMERATE)).await;
        // The replayed bookmark is embedded as verbatim XML in the Subscribe envelope.
        let s = text(&body);
        assert!(
            s.contains(
                "<w:Bookmark><BookmarkList><Bookmark Channel=\"Security\" RecordId=\"1042\""
            ),
            "{s}"
        );
    }

    #[tokio::test]
    async fn test_delivery_unknown_uuid_404() {
        let app = app(&state_with(true, None));
        let p = "/wsman/subscriptions/11111111-2222-3333-4444-555555555555";
        let (st, _, _) = post(&app, p, &[], utf16(HEARTBEAT)).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        let (st, _, _) = post(
            &app,
            "/wsman/subscriptions/not-a-uuid",
            &[],
            utf16(HEARTBEAT),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delivery_trailing_segment_accepted() {
        let app = app(&state_with(true, None));
        let lower = format!("/wsman/subscriptions/{}/1", SUB_UUID.to_lowercase());
        let (st, _, _) = post(&app, &lower, &[], utf16(HEARTBEAT)).await;
        assert_eq!(st, StatusCode::OK);
        let (st, _, _) = post(
            &app,
            &format!("{}/x", delivery_path()),
            &[],
            utf16(HEARTBEAT),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_wsman_sldc_header_on_plain_body_is_accepted() {
        let app = app(&state_with(true, None));
        let (st, _, _) = post(
            &app,
            &delivery_path(),
            &[("Content-Encoding", "sldc")],
            utf16(HEARTBEAT),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_wsman_sldc_compressed_body_is_decoded() {
        let app = app(&state_with(true, None));
        let enc = sldc::compress_literals_and_copies(&utf16(HEARTBEAT));
        let (st, _, body) =
            post(&app, &delivery_path(), &[("Content-Encoding", "SLDC")], enc).await;
        assert_eq!(st, StatusCode::OK);
        assert!(text(&body).contains(soap::ACTION_ACK));
    }

    #[tokio::test]
    async fn test_wsman_unknown_content_encoding_415() {
        let app = app(&state_with(true, None));
        for enc in ["gzip", "br"] {
            let (st, _, _) = post(
                &app,
                "/wsman",
                &[("Content-Encoding", enc)],
                utf16(ENUMERATE),
            )
            .await;
            assert_eq!(st, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{enc}");
        }
    }

    #[tokio::test]
    async fn test_wsman_bad_xml_400() {
        let app = app(&state_with(true, None));
        let (st, _, _) = post(&app, "/wsman", &[], b"<not-soap/>".to_vec()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, _, _) = post(&app, "/wsman", &[], vec![0xFF, 0xFE, 0x00]).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let truncated = &ENUMERATE[..ENUMERATE.len() / 2];
        let (st, _, _) = post(&app, "/wsman", &[], utf16(truncated)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_legacy_bare_events_post_to_wsman_events_is_400() {
        let app = app(&state_with(true, None));
        let bare = "<Envelope><Body><Events><Event><System><Provider>Security</Provider>\
                    <EventID>4624</EventID></System></Event></Events></Body></Envelope>";
        let (st, _, _) = post(&app, "/wsman/events", &[], bare.as_bytes().to_vec()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_wrong_action_for_endpoint_400() {
        let app = app(&state_with(true, None));
        let (st, _, _) = post(&app, "/wsman", &[], utf16(HEARTBEAT)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, _, _) = post(&app, &delivery_path(), &[], utf16(ENUMERATE)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, _, body) = post(&app, &delivery_path(), &[], utf16(SUB_END)).await;
        assert_eq!(st, StatusCode::OK);
        assert!(body.is_empty());
    }

    fn counter(snap: metrics_util::debugging::Snapshotter, name: &str) -> Vec<(String, u64)> {
        use metrics_util::debugging::DebugValue;
        snap.snapshot()
            .into_vec()
            .into_iter()
            .filter(|(k, ..)| k.key().name() == name)
            .map(|(k, _, _, v)| {
                let labels = k
                    .key()
                    .labels()
                    .map(|l| format!("{}={}", l.key(), l.value()))
                    .collect::<Vec<_>>()
                    .join(",");
                let n = if let DebugValue::Counter(c) = v { c } else { 0 };
                (labels, n)
            })
            .collect()
    }

    #[test]
    fn test_wef_requests_total_labels_bounded() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let app = app(&state_with(true, None));
                post(&app, "/wsman", &[], utf16(ENUMERATE)).await;
                post(&app, "/wsman", &[], utf16(END)).await;
                post(&app, &delivery_path(), &[], utf16(HEARTBEAT)).await;
                post(&app, &delivery_path(), &[], utf16(EVENTS)).await;
                post(&app, &delivery_path(), &[], utf16(SUB_END)).await;
                let weird = ENUMERATE.replace(soap::ACTION_ENUMERATE, "urn:attacker-controlled");
                post(&app, "/wsman", &[], utf16(&weird)).await;
            })
        });
        let mut got = counter(snap, "wef_requests_total");
        got.sort();
        let labels: Vec<&str> = got.iter().map(|(l, _)| l.as_str()).collect();
        assert!(got.iter().all(|(_, n)| *n == 1), "{got:?}");
        assert_eq!(
            labels,
            [
                "action=end",
                "action=enumerate",
                "action=events",
                "action=heartbeat",
                "action=subscription_end",
                "action=unknown"
            ]
        );
    }

    #[test]
    fn test_delivery_events_dropped_when_sink_full_still_acks_and_counts() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let st = metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let handle = ParquetWriterHandle::for_test(tx, "wef", "s3");
                let app = app(&state_with(true, Some(handle)));
                let (st, _, body) = post(&app, &delivery_path(), &[], utf16(EVENTS)).await;
                assert!(text(&body).contains(soap::ACTION_ACK));
                st
            })
        });
        assert_eq!(st, StatusCode::OK);
        assert!(rx.try_recv().is_ok());
        let dropped = counter(snap, "parquet_s3_dropped");
        assert!(
            dropped
                .iter()
                .any(|(l, n)| l.contains("source=wef") && *n >= 1),
            "{dropped:?}"
        );
    }

    #[tokio::test]
    async fn test_parse_error_log_sanitizes_wire_element_names() {
        crate::test_support::install_and_clear();
        let app = app(&state_with(true, None));
        let evil = "<Ev\u{1b}[31mil>";
        let (st, _, _) = post(&app, "/wsman", &[], evil.as_bytes().to_vec()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let events = crate::test_support::captured_events();
        assert!(
            events.iter().any(|m| m.contains("not valid SOAP")),
            "{events:?}"
        );
        assert!(
            events.iter().all(|m| !m.contains('\u{1b}')),
            "raw ESC leaked: {events:?}"
        );
    }

    #[tokio::test]
    async fn test_machine_id_log_sanitized_in_heartbeat_and_events() {
        crate::test_support::install_and_clear();
        let app = app(&state_with(true, None));
        let evil = |x: &str| x.replace("win10.example.com", "wi\u{1b}[31mn");
        post(&app, &delivery_path(), &[], utf16(&evil(HEARTBEAT))).await;
        post(&app, &delivery_path(), &[], utf16(&evil(EVENTS))).await;
        let events = crate::test_support::captured_events();
        let lines: Vec<_> = events
            .iter()
            .filter(|m| m.starts_with("WEF") && m.contains(" from "))
            .collect();
        assert!(lines.len() == 2, "{events:?}");
        assert!(lines.iter().all(|m| !m.contains('\u{1b}')), "{lines:?}");
        assert!(lines.iter().all(|m| m.contains('\u{fffd}')), "{lines:?}");
    }

    #[tokio::test]
    async fn test_delivery_events_without_message_id_400_and_not_ingested() {
        let state = state_with(true, None);
        let app = app(&state);
        let mid = soap::parse(EVENTS).unwrap().message_id.unwrap();
        let no_mid = EVENTS.replace(&format!("<a:MessageID>{mid}</a:MessageID>"), "");
        assert_ne!(no_mid, EVENTS);
        let (st, _, _) = post(&app, &delivery_path(), &[], utf16(&no_mid)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(state.throughput.snapshot().await.is_empty());
    }

    #[test]
    fn test_route_target_classification() {
        assert_eq!(route_target("/wsman"), Target::Manager);
        assert_eq!(route_target("/wsman/subscriptions"), Target::Manager);
        assert_eq!(route_target("/wsman/subscriptions/x/1/2"), Target::NotFound);
        let u: Uuid = SUB_UUID.parse().unwrap();
        assert_eq!(route_target(&delivery_path()), Target::Delivery(u));
        assert_eq!(
            route_target(&format!("{}/12", delivery_path())),
            Target::Delivery(u)
        );
    }
}
