//! End-to-end: `[[filter.rules]]` through the real `logthing` binary.
//!
//! One process has all eight sources enabled with a local Parquet sink and one filter rule per
//! source. For each source one matching and one non-matching event are sent over the source's
//! real interface (syslog/IPFIX/sFlow UDP, Zeek/Suricata TCP, HEC/OTLP/WEF HTTP). After a
//! SIGTERM flush the Parquet must hold only the non-matching event, and `/metrics` must show
//! `events_filtered{rule="f-<src>",source="<src>"} 1` for every source.
//!
//! Without the `otlp` feature the OTLP source cannot be driven, so that test is compiled out.

mod common;
mod sflow_fixture;

use arrow::util::display::array_value_to_string;
use std::path::Path;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");

/// Every row under `dir` rendered as one string (all columns joined), for substring checks.
fn row_texts(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for b in common::read_all(dir) {
        for i in 0..b.num_rows() {
            let cells: Vec<String> = b
                .columns()
                .iter()
                .map(|c| array_value_to_string(c, i).unwrap_or_default())
                .collect();
            out.push(cells.join("|"));
        }
    }
    out
}

/// Assert `dir` holds exactly `rows` rows, every one containing none of `dropped` and, for each
/// of `kept`, at least one row containing it.
fn assert_only_kept(src: &str, dir: &Path, rows: usize, kept: &[&str], dropped: &[&str]) {
    let texts = row_texts(dir);
    assert_eq!(texts.len(), rows, "{src}: rows were {texts:#?}");
    for k in kept {
        assert!(
            texts.iter().any(|t| t.contains(k)),
            "{src}: kept marker {k} missing from {texts:#?}"
        );
    }
    for d in dropped {
        assert!(
            !texts.iter().any(|t| t.contains(d)),
            "{src}: filtered marker {d} was stored: {texts:#?}"
        );
    }
}

/// True when the scrape has `events_filtered` for `source`/`rule` with value 1.
fn filtered_once(metrics: &str, source: &str, rule: &str) -> bool {
    metrics.lines().any(|l| {
        l.starts_with("events_filtered{")
            && l.contains(&format!("source=\"{source}\""))
            && l.contains(&format!("rule=\"{rule}\""))
            && l.trim_end().ends_with(" 1")
    })
}

fn ipfix_message(sets: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = sets.concat();
    let mut v = vec![0x00, 0x0A];
    v.extend_from_slice(&((16 + body.len()) as u16).to_be_bytes());
    v.extend_from_slice(&[0x67, 0x5C, 0xB0, 0x20, 0, 0, 0, 1, 0, 0, 0, 0]);
    v.extend_from_slice(&body);
    v
}

fn ipfix_set(set_id: u16, body: &[u8]) -> Vec<u8> {
    let mut v = set_id.to_be_bytes().to_vec();
    v.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// Template 256 = srcIPv4 (8), dstIPv4 (12), srcPort (7), dstPort (11), then two records:
/// 10.0.0.1 -> 10.0.0.2 port 53 (filtered) and 10.0.0.3 -> 10.0.0.4 port 80 (kept).
fn ipfix_datagram() -> Vec<u8> {
    let template = [
        &[1u8, 0, 0, 4][..],
        &[0, 8, 0, 4, 0, 12, 0, 4, 0, 7, 0, 2, 0, 11, 0, 2],
    ]
    .concat();
    let data = [
        [10u8, 0, 0, 1, 10, 0, 0, 2, 0x13, 0x88, 0, 53],
        [10u8, 0, 0, 3, 10, 0, 0, 4, 0x13, 0x89, 0, 80],
    ]
    .concat();
    ipfix_message(&[ipfix_set(2, &template), ipfix_set(256, &data)])
}

#[cfg(feature = "otlp")]
fn otlp_request() -> Vec<u8> {
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use prost::Message;

    let s = |v: &str| AnyValue {
        value: Some(Value::StringValue(v.to_string())),
    };
    let record = |body: &str, route: &str| LogRecord {
        time_unix_nano: 1_700_000_000_000_000_000,
        body: Some(s(body)),
        attributes: vec![KeyValue {
            key: "http.route".to_string(),
            value: Some(s(route)),
            key_strindex: 0,
        }],
        ..Default::default()
    };
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: None,
            scope_logs: vec![ScopeLogs {
                scope: None,
                log_records: vec![
                    record("otlp-DROP", "/healthz"),
                    record("otlp-KEEP", "/orders"),
                ],
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    }
    .encode_to_vec()
}

fn config_toml(ports: &Ports) -> String {
    let local = "flush_threshold_bytes = 1\nflush_interval_secs = 1\n";
    let mut t = format!(
        r#"
bind_address = "127.0.0.1:{{HTTP}}"

[tls]
enabled = false

[metrics]
enabled = true
port = {metrics}

[syslog]
enabled = true
udp_port = {syslog_udp}
tcp_port = {syslog_tcp}
bind_address = "127.0.0.1"
[syslog.local]
directory = "{{DIR}}/syslog"
{local}
[zeek]
enabled = true
tcp_port = {zeek}
bind_address = "127.0.0.1"
[zeek.local]
directory = "{{DIR}}/zeek"
{local}
[suricata]
enabled = true
tcp_port = {suricata}
bind_address = "127.0.0.1"
[suricata.local]
directory = "{{DIR}}/suricata"
{local}
[ipfix]
enabled = true
udp_port = {ipfix}
bind_address = "127.0.0.1"
[ipfix.local]
directory = "{{DIR}}/ipfix"
{local}
[sflow]
enabled = true
udp_port = {sflow}
bind_address = "127.0.0.1"
[sflow.local]
directory = "{{DIR}}/sflow"
{local}
[hec]
enabled = true
token = ""
[hec.local]
directory = "{{DIR}}/hec"
{local}
[otlp]
enabled = true
[otlp.local]
directory = "{{DIR}}/otlp"
{local}
[wef.local]
directory = "{{DIR}}/wef"
flush_interval_secs = 1

[[filter.rules]]
name = "f-syslog"
source = "syslog"
match = {{ app_name = "noisy" }}
[[filter.rules]]
name = "f-zeek"
source = "zeek"
match = {{ log_path = "dns", query = "wpad" }}
[[filter.rules]]
name = "f-suricata"
source = "suricata"
match = {{ event_type = "stats" }}
[[filter.rules]]
name = "f-ipfix"
source = "ipfix"
match = {{ dst_port = 53 }}
[[filter.rules]]
name = "f-sflow"
source = "sflow"
match = {{ sample_type = "counter" }}
[[filter.rules]]
name = "f-wef"
source = "wef"
match = {{ event_id = 5156 }}
[[filter.rules]]
name = "f-hec"
source = "hec"
match = {{ "fields.level" = "debug" }}
[[filter.rules]]
name = "f-otlp"
source = "otlp"
match = {{ "attributes.http.route" = "/healthz" }}
"#,
        metrics = ports.metrics,
        syslog_udp = ports.syslog_udp,
        syslog_tcp = ports.syslog_tcp,
        zeek = ports.zeek,
        suricata = ports.suricata,
        ipfix = ports.ipfix,
        sflow = ports.sflow,
    );
    t.push_str(&common::wef_toml("http://127.0.0.1:{HTTP}"));
    t
}

struct Ports {
    metrics: u16,
    syslog_udp: u16,
    syslog_tcp: u16,
    zeek: u16,
    suricata: u16,
    ipfix: u16,
    sflow: u16,
}

async fn wait_tcp(port: u16) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("nothing listening on TCP {port}");
}

async fn send_tcp_lines(port: u16, lines: &[String]) {
    use tokio::io::AsyncWriteExt;
    wait_tcp(port).await;
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    for l in lines {
        s.write_all(l.as_bytes()).await.unwrap();
        s.write_all(b"\n").await.unwrap();
    }
    s.flush().await.unwrap();
}

#[cfg(feature = "otlp")]
#[tokio::test]
async fn filter_drops_matching_events_on_every_source() {
    let ports = Ports {
        metrics: common::free_port(),
        syslog_udp: common::free_port(),
        syslog_tcp: common::free_port(),
        zeek: common::free_port(),
        suricata: common::free_port(),
        ipfix: common::free_port(),
        sflow: common::free_port(),
    };
    let mut p = common::Proc::spawn_healthy(BIN, &config_toml(&ports), &[]).await;
    let client = reqwest::Client::new();
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // syslog (UDP): app_name "noisy" is filtered.
    for line in [
        "<134>Jan 15 10:30:45 hostx noisy: syslog-DROP",
        "<134>Jan 15 10:30:46 hostx quiet: syslog-KEEP",
    ] {
        udp.send_to(line.as_bytes(), ("127.0.0.1", ports.syslog_udp))
            .await
            .unwrap();
    }

    // Zeek (TCP NDJSON): dns/wpad is filtered.
    let zeek = |q: &str| {
        serde_json::json!({"_path": "dns", "ts": 1700000100.0, "uid": "C1",
            "id.orig_h": "192.168.1.100", "id.orig_p": 12345, "id.resp_h": "8.8.8.8",
            "id.resp_p": 53, "query": q})
        .to_string()
    };
    send_tcp_lines(ports.zeek, &[zeek("wpad"), zeek("keep.example")]).await;

    // Suricata (TCP EVE): event_type stats is filtered.
    let eve = |ty: &str, sig: &str| {
        serde_json::json!({"event_type": ty, "src_ip": "10.0.0.1", "dest_ip": "8.8.8.8",
            "alert": {"signature": sig}, "timestamp": "2024-01-15T10:30:00Z"})
        .to_string()
    };
    send_tcp_lines(
        ports.suricata,
        &[eve("stats", "suri-DROP"), eve("alert", "suri-KEEP")],
    )
    .await;

    // IPFIX (UDP): template + two records, dst_port 53 filtered.
    udp.send_to(&ipfix_datagram(), ("127.0.0.1", ports.ipfix))
        .await
        .unwrap();

    // sFlow (UDP): one counter sample (filtered), two flow samples (kept).
    udp.send_to(
        &sflow_fixture::mixed_datagram(7),
        ("127.0.0.1", ports.sflow),
    )
    .await
    .unwrap();

    // HEC (HTTP): fields.level debug is filtered.
    for (msg, level) in [("hec-DROP", "debug"), ("hec-KEEP", "info")] {
        let r = client
            .post(format!("{}/services/collector/event", p.base()))
            .json(&serde_json::json!({"event": {"msg": msg, "level": level}}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "hec {msg}: {}", p.logs());
    }

    // OTLP (HTTP protobuf): attributes.http.route /healthz is filtered.
    let r = client
        .post(format!("{}/v1/logs", p.base()))
        .header("content-type", "application/x-protobuf")
        .body(otlp_request())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "otlp: {}", p.logs());

    // WEF (SOAP over HTTP): EventID 5156 is filtered; the batch is still acknowledged.
    let base = common::wef_fixture("security_4624");
    let drop_xml = base
        .replace("<EventID>4624</EventID>", "<EventID>5156</EventID>")
        .replace("WIN-WFBHIBE5GXZ", "wef-DROP-host");
    let keep_xml = base.replace("WIN-WFBHIBE5GXZ", "wef-KEEP-host");
    let r = client
        .post(format!(
            "{}/wsman/subscriptions/{}",
            p.base(),
            common::TEST_SUB_UUID
        ))
        .header("Content-Type", "application/soap+xml;charset=UTF-16")
        .body(common::utf16(&common::events_envelope(
            "uuid:1C2D3E4F-5061-4728-8394-A5B6C7D8E9F0",
            "win10.example.com",
            1,
            &[drop_xml.as_str(), keep_xml.as_str()],
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "wef: {}", p.logs());

    // The kept events must land; then give any wrongly kept ones time to arrive.
    let secs = Duration::from_secs(30);
    for (src, rows) in [
        ("syslog", 1),
        ("zeek", 1),
        ("suricata", 1),
        ("ipfix", 1),
        ("sflow", 2),
        ("hec", 1),
        ("otlp", 1),
        ("wef", 1),
    ] {
        common::wait_for_rows(&p.dir().join(src), rows, secs).await;
    }
    tokio::time::sleep(Duration::from_millis(2500)).await;

    let metrics_url = format!("http://127.0.0.1:{}/metrics", ports.metrics);
    let metrics = client
        .get(&metrics_url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for src in [
        "syslog", "zeek", "suricata", "ipfix", "sflow", "wef", "hec", "otlp",
    ] {
        assert!(
            filtered_once(&metrics, src, &format!("f-{src}")),
            "events_filtered for {src} missing:\n{metrics}"
        );
    }

    let status = p.terminate(Duration::from_secs(20));
    assert!(status.success(), "unclean exit {status}: {}", p.logs());

    let d = |s: &str| p.dir().join(s);
    assert_only_kept(
        "syslog",
        &d("syslog"),
        1,
        &["syslog-KEEP"],
        &["syslog-DROP"],
    );
    assert_only_kept("zeek", &d("zeek"), 1, &["keep.example"], &["wpad"]);
    assert_only_kept(
        "suricata",
        &d("suricata"),
        1,
        &["suri-KEEP"],
        &["suri-DROP"],
    );
    assert_only_kept("ipfix", &d("ipfix"), 1, &["10.0.0.3"], &["10.0.0.1"]);
    let sflow = row_texts(&d("sflow"));
    assert_eq!(sflow.len(), 2, "sflow rows: {sflow:#?}");
    assert!(
        sflow.iter().all(|t| !t.contains("counter")),
        "counter sample stored: {sflow:#?}"
    );
    assert_only_kept("hec", &d("hec"), 1, &["hec-KEEP"], &["hec-DROP"]);
    assert_only_kept("otlp", &d("otlp"), 1, &["otlp-KEEP"], &["otlp-DROP"]);
    assert_only_kept("wef", &d("wef"), 1, &["wef-KEEP-host"], &["wef-DROP-host"]);
}

#[test]
fn filter_invalid_rule_fails_startup() {
    let toml = format!(
        r#"
bind_address = "127.0.0.1:{http}"
[tls]
enabled = false
[metrics]
enabled = false
[syslog]
enabled = true
udp_port = {udp}
tcp_port = {tcp}
bind_address = "127.0.0.1"

[[filter.rules]]
name = "bad-regex-rule"
source = "syslog"
match = {{ message = {{ regex = "^" }} }}
"#,
        http = common::free_port(),
        udp = common::free_port(),
        tcp = common::free_port(),
    );
    let (status, stderr) = common::run_to_exit(BIN, &toml, &[]);
    assert!(!status.success(), "startup must fail; stderr:\n{stderr}");
    assert!(
        stderr.contains("bad-regex-rule"),
        "stderr must name the rule:\n{stderr}"
    );
}
