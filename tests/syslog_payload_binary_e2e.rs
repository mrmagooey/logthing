//! E2E: the real binary parses edge-case syslog payloads (LEEF literal-tab delimiter with `|`
//! in data, CEF `=` inside a value) and writes the parsed JSON to the structured S3 sink
//! (a fake S3), driven over UDP.

mod common;

use bytes::Bytes;
use common::fake_s3::FakeS3;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::collections::HashMap;
use std::time::Duration;
use tokio::net::UdpSocket;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");

fn toml(endpoint: &str, udp: u16, tcp: u16) -> String {
    format!(
        r#"
bind_address = "127.0.0.1:{{HTTP}}"
[tls]
enabled = false
[metrics]
enabled = false
[syslog]
enabled = true
udp_port = {udp}
tcp_port = {tcp}
bind_address = "127.0.0.1"
parse_payloads = true
[syslog.structured_s3]
endpoint = "{endpoint}"
bucket = "b"
region = "us-east-1"
access_key = "k"
secret_key = "s"
prefix = "structured"
max_buffer_rows = 1
flush_interval_secs = 1
"#
    )
}

fn parsed_by_type(fake: &FakeS3) -> HashMap<String, serde_json::Value> {
    let mut out = HashMap::new();
    for (key, body) in fake.puts() {
        if !key.ends_with(".parquet") {
            continue;
        }
        let Ok(builder) = ParquetRecordBatchReaderBuilder::try_new(Bytes::from(body)) else {
            continue;
        };
        for b in builder.build().unwrap() {
            let b = b.unwrap();
            let t = common::str_col(&b, "payload_type");
            let p = common::str_col(&b, "parsed");
            for i in 0..b.num_rows() {
                out.insert(
                    t.value(i).to_string(),
                    serde_json::from_str(p.value(i)).unwrap(),
                );
            }
        }
    }
    out
}

#[tokio::test]
async fn test_leef_tab_and_cef_equals_payloads_parsed_by_real_binary() {
    let fake = FakeS3::start().await;
    let (udp, tcp) = (common::free_port(), common::free_port());
    let mut p = common::Proc::spawn(BIN, &toml(&fake.endpoint(), udp, tcp), &[]);
    p.wait_healthy().await;

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let lines = [
        "<134>Jan 15 10:30:45 h1 LEEF:2.0|V|P|1|E|\tsrc=1\turl=a|b",
        "<134>Jan 15 10:30:45 h2 CEF:0|V|P|1|100|N|5|msg=a=b src=1.2.3.4",
    ];
    let dest = format!("127.0.0.1:{udp}");

    // Resend every poll: the UDP socket may bind after the health check. Assertions are
    // idempotent (map keyed by payload type).
    let mut got = HashMap::new();
    let end = std::time::Instant::now() + Duration::from_secs(30);
    let mut ok = false;
    while std::time::Instant::now() < end {
        for l in &lines {
            sock.send_to(l.as_bytes(), &dest).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        got = parsed_by_type(&fake);
        if got.contains_key("leef") && got.contains_key("cef") {
            ok = true;
            break;
        }
    }
    assert!(ok, "payloads never reached S3: {got:?}\n{}", p.logs());
    assert_eq!(got["leef"]["delimiter"], "\t");
    assert_eq!(got["leef"]["attributes"]["src"], "1");
    assert_eq!(got["leef"]["attributes"]["url"], "a|b");
    assert_eq!(got["cef"]["extensions"]["msg"], "a=b");
    assert_eq!(got["cef"]["extensions"]["src"], "1.2.3.4");
}
