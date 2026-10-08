//! A full writer channel must surface as HTTP 503 (+ Retry-After) on HEC, NDJSON and OTLP over
//! real HTTP; once the consumer drains, the same request succeeds again. The consumer is
//! stalled deterministically with `ParquetWriterHandle::for_test` (a capacity-1 channel whose
//! receiver the test controls).

use axum::{Extension, Router, routing::post};
use logthing::config::Config;
use logthing::forwarding::buffered_writer::ParquetWriterHandle;
use logthing::forwarding::generic_s3::GenericSink;
use logthing::ingest::{
    GenericRecord, IngestState,
    handlers::{handle_hec_event, handle_hec_raw, handle_ndjson},
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, mpsc};

async fn serve(router: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    base
}

fn hec_router(ingest: IngestState) -> Router {
    Router::new()
        .route("/services/collector/event", post(handle_hec_event))
        .route("/services/collector/raw", post(handle_hec_raw))
        .route("/ingest", post(handle_ndjson))
        .layer(Extension(Arc::new(RwLock::new(Config::default()))))
        .layer(Extension(ingest))
}

#[tokio::test]
async fn hec_and_ndjson_answer_503_when_full_and_recover_after_drain() {
    let (tx, mut rx) = mpsc::channel::<GenericRecord>(1);
    let ingest = IngestState {
        generic_local: Some(ParquetWriterHandle::<GenericSink>::for_test(
            tx, "hec", "test",
        )),
        ..Default::default()
    };
    let base = serve(hec_router(ingest)).await;
    let c = reqwest::Client::new();

    let first = c
        .post(format!("{base}/services/collector/event"))
        .body(r#"{"event":"a"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);

    for (path, body) in [
        ("/services/collector/event", r#"{"event":"b"}"#),
        ("/services/collector/raw", "raw"),
        ("/ingest", "{\"k\":1}\n"),
    ] {
        let r = c
            .post(format!("{base}{path}"))
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 503, "{path}");
        assert_eq!(r.headers().get("retry-after").unwrap(), "1");
        let v: serde_json::Value = r.json().await.unwrap();
        assert_eq!(v, serde_json::json!({"text": "Server is busy", "code": 9}));
    }

    // Drain the stalled consumer: the very same request now succeeds.
    rx.recv().await.unwrap();
    let again = c
        .post(format!("{base}/ingest"))
        .body("{\"k\":1}\n")
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 200);
}

#[cfg(feature = "otlp")]
#[tokio::test]
async fn otlp_answers_503_when_full_and_recovers_after_drain() {
    use logthing::config::OtlpConfig;
    use logthing::forwarding::otlp_s3::{OtlpRecord, OtlpSink};
    use logthing::protocol::WefParser;
    use logthing::server::{AppState, handle_otlp_logs};
    use logthing::stats::ThroughputStats;
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use prost::Message as _;

    let (tx, mut rx) = mpsc::channel::<OtlpRecord>(1);
    let ingest = IngestState {
        otlp_s3: Some(ParquetWriterHandle::<OtlpSink>::for_test(
            tx, "otlp", "test",
        )),
        ..Default::default()
    };
    let config = Config {
        otlp: OtlpConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let app_state = Arc::new(AppState {
        config: Arc::new(RwLock::new(config)),
        throughput: Arc::new(ThroughputStats::new()),
        wef_cardinality_watchers: Vec::new(),
        parser: WefParser::new(),
        event_parser: None,
        parquet_s3_sender: None,
        parquet_local_sender: None,
    });
    let router = Router::new()
        .route("/v1/logs", post(handle_otlp_logs))
        .layer(Extension(ingest))
        .with_state(app_state);
    let base = serve(router).await;

    let body = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord::default()],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
    .encode_to_vec();
    let c = reqwest::Client::new();
    let send = || {
        c.post(format!("{base}/v1/logs"))
            .header("content-type", "application/x-protobuf")
            .body(body.clone())
            .send()
    };
    assert_eq!(send().await.unwrap().status(), 200);
    let busy = send().await.unwrap();
    assert_eq!(busy.status(), 503);
    assert_eq!(busy.headers().get("retry-after").unwrap(), "1");
    rx.recv().await.unwrap();
    assert_eq!(send().await.unwrap().status(), 200);
}
