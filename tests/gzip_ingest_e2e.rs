//! gzip request bodies through the REAL binary: HEC event, NDJSON, OTLP protobuf and JSON land
//! in real local sinks; a gzip bomb gets 413; unsupported encodings 415; corrupt gzip 400.

mod common;

use flate2::{Compression, write::GzEncoder};
use std::io::Write;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");

const CONFIG: &str = r#"
bind_address = "127.0.0.1:{HTTP}"
[tls]
enabled = false
[syslog]
enabled = false
[metrics]
enabled = false

[hec]
enabled = true
[hec.local]
directory = "{DIR}/out/hec"
flush_threshold_bytes = 1
flush_interval_secs = 1

[otlp]
enabled = true
[otlp.local]
directory = "{DIR}/out/otlp"
flush_threshold_bytes = 1
flush_interval_secs = 1
"#;

fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

async fn up() -> common::Proc {
    let mut p = common::Proc::spawn(BIN, CONFIG, &[]);
    p.wait_healthy().await;
    p
}

fn column_values(batches: &[arrow::record_batch::RecordBatch], col: &str) -> Vec<String> {
    batches
        .iter()
        .flat_map(|b| {
            let c = common::str_col(b, col);
            (0..b.num_rows())
                .map(|i| c.value(i).to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[tokio::test]
async fn gzip_hec_event_and_ndjson_are_decoded_and_persisted() {
    let p = up().await;
    let c = reqwest::Client::new();
    let r = c
        .post(format!("{}/services/collector/event", p.base()))
        .header("Content-Encoding", "gzip")
        .body(gz(
            br#"{"event":{"marker":"gzip-hec-event"},"sourcetype":"gz"}"#,
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = c
        .post(format!("{}/ingest?sourcetype=gz_nd", p.base()))
        .header("Content-Encoding", "GZIP")
        .body(gz(
            b"{\"event\":{\"marker\":\"gzip-ndjson-1\"}}\n{\"event\":{\"marker\":\"gzip-ndjson-2\"}}\n",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let dir = p.dir.path().join("out").join("hec");
    let batches = common::wait_for_rows(&dir, 3, Duration::from_secs(20)).await;
    let all = column_values(&batches, "fields").join("\n");
    for m in ["gzip-hec-event", "gzip-ndjson-1", "gzip-ndjson-2"] {
        assert!(all.contains(m), "missing {m} in {all}");
    }
}

#[cfg(feature = "otlp")]
#[tokio::test]
async fn gzip_otlp_protobuf_and_json_are_decoded_and_persisted() {
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use prost::Message as _;

    let p = up().await;
    let sv = |s: &str| AnyValue {
        value: Some(Value::StringValue(s.into())),
    };
    let mk = |body: &str| ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "service.name".into(),
                    value: Some(sv("gz-svc")),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    body: Some(sv(body)),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let c = reqwest::Client::new();
    let proto = c
        .post(format!("{}/v1/logs", p.base()))
        .header("Content-Type", "application/x-protobuf")
        .header("Content-Encoding", "gzip")
        .body(gz(&mk("gzip-otlp-proto").encode_to_vec()))
        .send()
        .await
        .unwrap();
    assert_eq!(proto.status(), 200);
    let json = c
        .post(format!("{}/v1/logs", p.base()))
        .header("Content-Type", "application/json")
        .header("Content-Encoding", "x-gzip")
        .body(gz(&serde_json::to_vec(&mk("gzip-otlp-json")).unwrap()))
        .send()
        .await
        .unwrap();
    assert_eq!(json.status(), 200);

    let dir = p.dir.path().join("out").join("otlp");
    let batches = common::wait_for_rows(&dir, 2, Duration::from_secs(20)).await;
    let mut bodies = column_values(&batches, "body");
    bodies.sort();
    assert_eq!(bodies, vec!["gzip-otlp-json", "gzip-otlp-proto"]);
    assert!(
        column_values(&batches, "service_name")
            .iter()
            .all(|s| s == "gz-svc")
    );
}

#[tokio::test]
async fn gzip_bomb_413_unsupported_encoding_415_corrupt_gzip_400() {
    let p = up().await;
    let c = reqwest::Client::new();
    let bomb = gz(&vec![0u8; 64 * 1024 * 1024 + 1]);
    assert!(bomb.len() < 1024 * 1024, "premise: tiny on the wire");
    let r = c
        .post(format!("{}/services/collector/raw", p.base()))
        .header("Content-Encoding", "gzip")
        .body(bomb)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);

    for enc in ["br", "deflate", "gzip, gzip"] {
        let r = c
            .post(format!("{}/ingest", p.base()))
            .header("Content-Encoding", enc)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 415, "encoding {enc}");
    }

    let r = c
        .post(format!("{}/ingest", p.base()))
        .header("Content-Encoding", "gzip")
        .body("definitely not gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    // The server survived all of that.
    assert!(
        reqwest::get(format!("{}/health", p.base()))
            .await
            .unwrap()
            .status()
            .is_success()
    );
}
