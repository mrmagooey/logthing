//! E2E: the real binary redacts HEC and OTLP before anything is written to disk.

mod common;

use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");
const KEY_ENV: (&str, &str) = ("E2E_HASH_KEY", "0123456789abcdef");

const HEC_TOML: &str = r#"
bind_address = "127.0.0.1:{HTTP}"
[tls]
enabled = false
[syslog]
enabled = false
[metrics]
enabled = false

[hec]
enabled = true
token = "tok"
[hec.local]
directory = "{DIR}/hec"
prefix = "hec"
max_buffer_rows = 1
flush_threshold_bytes = 1
flush_interval_secs = 1
[hec.redaction]
drop_fields = ["password"]
hash_fields = ["user.email"]
hash_key_env = "E2E_HASH_KEY"
mask_patterns = ['\d{3}-\d{2}-\d{4}']
"#;

#[tokio::test]
async fn test_hec_redaction_applies_over_real_http() {
    let mut p = common::Proc::spawn(BIN, HEC_TOML, &[KEY_ENV]);
    p.wait_healthy().await;
    let resp = tokio::time::timeout(
        Duration::from_secs(10),
        reqwest::Client::new()
            .post(format!("{}/services/collector/event", p.base()))
            .header("Authorization", "Splunk tok")
            .json(&serde_json::json!({
                "sourcetype": "app",
                "event": {"password": "hunter2", "user": {"email": "alice@example.com"},
                          "note": "ssn 123-45-6789"}
            }))
            .send(),
    )
    .await
    .expect("request timed out")
    .unwrap();
    assert_eq!(resp.status(), 200);
    let dir = p.dir().join("hec");
    let batches = common::wait_for_rows(&dir, 1, Duration::from_secs(20)).await;
    let fields: serde_json::Value =
        serde_json::from_str(common::str_col(&batches[0], "fields").value(0)).unwrap();
    assert!(fields.get("password").is_none(), "{fields}");
    assert_eq!(fields["note"], "ssn [REDACTED]", "{fields}");
    assert_eq!(
        fields["user"]["email"],
        "f3d6ddc7dbf9be2eb667360a5a9a43434c54e345f522bbb433afeba094d74aa2"
    );
    assert!(
        !common::str_col(&batches[0], "event_uuid")
            .value(0)
            .is_empty()
    );
}

#[tokio::test]
async fn test_hec_raw_and_ndjson_redaction_over_real_http() {
    let mut p = common::Proc::spawn(BIN, HEC_TOML, &[KEY_ENV]);
    p.wait_healthy().await;
    let c = reqwest::Client::new();
    let r = c
        .post(format!("{}/services/collector/raw?sourcetype=r", p.base()))
        .header("Authorization", "Splunk tok")
        .body("caller ssn 123-45-6789 ok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = c
        .post(format!("{}/ingest?sourcetype=n", p.base()))
        .header("Authorization", "Splunk tok")
        .body("{\"password\":\"hunter2\",\"keep\":\"yes\"}\n")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let dir = p.dir().join("hec");
    let batches = common::wait_for_rows(&dir, 2, Duration::from_secs(20)).await;
    let mut all: Vec<serde_json::Value> = batches
        .iter()
        .flat_map(|b| {
            let c = common::str_col(b, "fields");
            (0..b.num_rows())
                .map(|i| serde_json::from_str(c.value(i)).unwrap())
                .collect::<Vec<_>>()
        })
        .collect();
    all.sort_by_key(|v| v.to_string());
    assert_eq!(
        all,
        vec![
            serde_json::json!({"keep": "yes"}),
            serde_json::json!({"raw": "caller ssn [REDACTED] ok"}),
        ]
    );
}

/// `run_to_exit` does not expand placeholders; the process must fail before binding anyway.
fn no_placeholders(toml: &str) -> String {
    toml.replace("{HTTP}", &common::free_port().to_string())
        .replace("{DIR}", &std::env::temp_dir().display().to_string())
}

#[test]
fn test_startup_fails_when_hash_key_env_is_missing() {
    let (status, stderr) = common::run_to_exit(BIN, &no_placeholders(HEC_TOML), &[]);
    assert!(!status.success());
    assert!(stderr.contains("E2E_HASH_KEY"), "{stderr}");
}

#[test]
fn test_startup_fails_on_invalid_mask_regex() {
    let toml = no_placeholders(&HEC_TOML.replace(r"'\d{3}-\d{2}-\d{4}'", "'('"));
    let (status, stderr) = common::run_to_exit(BIN, &toml, &[KEY_ENV]);
    assert!(!status.success());
    assert!(stderr.contains("mask_patterns"), "{stderr}");
}

#[cfg(feature = "otlp")]
const OTLP_TOML: &str = r#"
bind_address = "127.0.0.1:{HTTP}"
[tls]
enabled = false
[syslog]
enabled = false
[metrics]
enabled = false

[otlp]
enabled = true
[otlp.local]
directory = "{DIR}/otlp"
flush_threshold_bytes = 1
flush_interval_secs = 1
[otlp.redaction]
drop_fields = ["user.email"]
hash_fields = ["@host_name"]
hash_key_env = "E2E_HASH_KEY"
mask_patterns = ["secret"]
"#;

#[cfg(feature = "otlp")]
#[tokio::test]
async fn test_otlp_redaction_applies_over_real_http() {
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::resource::v1::Resource;

    let sv = |s: &str| AnyValue {
        value: Some(Value::StringValue(s.into())),
    };
    let kv = |k: &str, v: &str| KeyValue {
        key: k.into(),
        value: Some(sv(v)),
        ..Default::default()
    };
    let req = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![kv("service.name", "checkout"), kv("host.name", "web01")],
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    body: Some(sv("my secret")),
                    attributes: vec![kv("user.email", "alice@example.com"), kv("keep", "yes")],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let mut p = common::Proc::spawn(BIN, OTLP_TOML, &[KEY_ENV]);
    p.wait_healthy().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/logs", p.base()))
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&req).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let dir = p.dir().join("otlp");
    let batches = common::wait_for_rows(&dir, 1, Duration::from_secs(20)).await;
    let b = &batches[0];
    assert_eq!(common::str_col(b, "body").value(0), "my [REDACTED]");
    let attrs: serde_json::Value =
        serde_json::from_str(common::str_col(b, "attributes").value(0)).unwrap();
    assert!(attrs.get("user.email").is_none(), "{attrs}");
    assert_eq!(attrs["keep"], "yes");
    // Typed column: untouched by rules that do not name it; host_name was hashed.
    assert_eq!(common::str_col(b, "service_name").value(0), "checkout");
    assert_eq!(
        common::str_col(b, "host_name").value(0),
        "25f2a24da268ab10b8c45dcc9f7461923726f3b169f3030c808e821365c7a536"
    );
    assert!(!common::str_col(b, "event_uuid").value(0).is_empty());
}
