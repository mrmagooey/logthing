//! E2E: the real binary writes an Iceberg descriptor whose `schema_version` is the stable,
//! nullability-aware hash of the HEC (generic) schema. The expected value is hard-coded so a
//! change to the hashing scheme or to that schema fails loudly here.

mod common;

use common::fake_s3::FakeS3;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");
const ENVS: [(&str, &str); 1] = [("AWS_MAX_ATTEMPTS", "1")];

/// First 16 hex chars of SHA-256 over the canonical form of the 10-column HEC schema
/// (computed independently of the Rust implementation).
const HEC_SCHEMA_VERSION: &str = "5443403d335eba27";

#[tokio::test]
async fn test_descriptor_schema_version_matches_hard_coded_hec_value() {
    let fake = FakeS3::start().await;
    let ep = fake.endpoint();
    let cfg = format!(
        r#"
bind_address = "127.0.0.1:{{HTTP}}"
[tls]
enabled = false
[metrics]
enabled = false
[syslog]
enabled = false
[hec]
enabled = true
token = "tok"
[hec.s3]
endpoint = "{ep}"
bucket = "b"
region = "us-east-1"
access_key = "k"
secret_key = "s"
prefix = "hec"
max_buffer_rows = 1
flush_threshold_bytes = 1
flush_interval_secs = 3600
[iceberg.s3]
endpoint = "{ep}"
bucket = "b"
region = "us-east-1"
access_key = "k"
secret_key = "s"
prefix = "desc"
"#
    );
    let p = common::Proc::spawn_healthy(BIN, &cfg, &ENVS).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/services/collector/event", p.base()))
        .header("Authorization", "Splunk tok")
        .json(&serde_json::json!({"sourcetype": "app", "event": {"n": 1}}))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), 200);

    let desc_key = || {
        fake.put_keys()
            .into_iter()
            .find(|k| k.starts_with("desc/") && k.ends_with(".json"))
    };
    assert!(
        common::wait_until(Duration::from_secs(40), || desc_key().is_some()).await,
        "no descriptor uploaded; keys={:?}\n{}",
        fake.put_keys(),
        p.logs()
    );
    let body = fake.body(&desc_key().unwrap()).expect("descriptor body");
    let v: serde_json::Value = serde_json::from_slice(&body).expect("descriptor json");
    assert_eq!(v["schema_version"], HEC_SCHEMA_VERSION);
}
