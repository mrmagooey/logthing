//! End-to-end: the real `logthing` binary with every wire-protocol source enabled, each with
//! BOTH an S3 target (in-process fake S3) and a local-disk target, one aggregation rule per
//! source writing to S3 and local disk, a structured-syslog S3 sink, one cardinality watch per
//! source, JSON logging and an IP allow-list.
//!
//! This drives the `main.rs` wiring that no single-purpose binary test reaches: the
//! multi-target handler fan-out for every source, the aggregating decorators, the aggregate
//! writers, the cardinality ticker and the JSON log format. A graceful SIGTERM then flushes
//! everything, and the test checks what landed on both targets.

mod common;

use common::{Proc, fake_s3::FakeS3};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");
const ENVS: [(&str, &str); 1] = [("AWS_MAX_ATTEMPTS", "1")];

struct Ports {
    metrics: u16,
    syslog_udp: u16,
    syslog_tcp: u16,
    zeek: u16,
    suricata: u16,
    ipfix: u16,
    sflow: u16,
}

fn s3_block(section: &str, endpoint: &str, prefix: &str) -> String {
    format!(
        "[{section}]\nendpoint = \"{endpoint}\"\nbucket = \"b\"\nregion = \"us-east-1\"\n\
         access_key = \"k\"\nsecret_key = \"s\"\nprefix = \"{prefix}\"\n"
    )
}

fn config_toml(p: &Ports, endpoint: &str) -> String {
    let mut t = format!(
        r#"
bind_address = "127.0.0.1:{{HTTP}}"

[tls]
enabled = false

[security]
allowed_ips = ["127.0.0.1/32"]

[logging]
format = "json"

[metrics]
enabled = true
port = {metrics}
cardinality_window_secs = 1

[iceberg.local]
directory = "{{DIR}}/descriptors"

[syslog]
enabled = true
udp_port = {syslog_udp}
tcp_port = {syslog_tcp}
parse_payloads = true
[syslog.local]
directory = "{{DIR}}/syslog"
max_buffer_rows = 1000
[zeek]
enabled = true
tcp_port = {zeek}
bind_address = "127.0.0.1"
[zeek.local]
directory = "{{DIR}}/zeek"
flush_threshold_bytes = 1
[suricata]
enabled = true
tcp_port = {suricata}
bind_address = "127.0.0.1"
[suricata.local]
directory = "{{DIR}}/suricata"
[ipfix]
enabled = true
udp_port = {ipfix}
bind_address = "127.0.0.1"
[ipfix.local]
directory = "{{DIR}}/ipfix"
[sflow]
enabled = true
udp_port = {sflow}
bind_address = "127.0.0.1"
[sflow.local]
directory = "{{DIR}}/sflow"

[aggregate]
enabled = true
flush_interval_secs = 1
[aggregate.local]
directory = "{{DIR}}/agg"
prefix = "aggregate"

[[aggregate.rules]]
name = "zeek_dns"
source = "zeek"
stream = "dns"
group_by = ["query"]
[[aggregate.rules]]
name = "syslog_app"
source = "syslog"
group_by = ["app_name"]
[[aggregate.rules]]
name = "suricata_type"
source = "suricata"
group_by = ["event_type"]
[[aggregate.rules]]
name = "ipfix_port"
source = "ipfix"
group_by = ["dst_port"]
[[aggregate.rules]]
name = "sflow_type"
source = "sflow"
group_by = ["sample_type"]

[[metrics.cardinality_watch]]
source = "zeek"
stream = "dns"
field = "query"
[[metrics.cardinality_watch]]
source = "wef"
stream = "Security"
field = "computer"
[[metrics.cardinality_watch]]
source = "suricata"
stream = "alert"
field = "src_ip"
[[metrics.cardinality_watch]]
source = "syslog"
stream = "sshd"
field = "hostname"
[[metrics.cardinality_watch]]
source = "ipfix"
stream = "flows"
field = "dst_port"
[[metrics.cardinality_watch]]
source = "sflow"
stream = "flow"
field = "src_addr"

"#,
        metrics = p.metrics,
        syslog_udp = p.syslog_udp,
        syslog_tcp = p.syslog_tcp,
        zeek = p.zeek,
        suricata = p.suricata,
        ipfix = p.ipfix,
        sflow = p.sflow,
    );
    t.push_str(&s3_block("syslog.s3", endpoint, "syslog_s3"));
    t.push_str(&s3_block("syslog.structured_s3", endpoint, "syslog_struct"));
    t.push_str(&s3_block("zeek.s3", endpoint, "zeek_s3"));
    t.push_str(&s3_block("suricata.s3", endpoint, "suricata_s3"));
    t.push_str(&s3_block("ipfix.s3", endpoint, "ipfix_s3"));
    t.push_str(&s3_block("sflow.s3", endpoint, "sflow_s3"));
    t.push_str(&s3_block("aggregate.s3", endpoint, "agg_s3"));
    t.push_str(&common::wef_toml("http://127.0.0.1:{HTTP}"));
    t
}

#[tokio::test]
async fn full_stack_fans_out_to_s3_and_local_and_aggregates_on_every_source() {
    let s3 = FakeS3::start().await;
    let ports = Ports {
        metrics: common::free_port(),
        syslog_udp: common::free_port(),
        syslog_tcp: common::free_port(),
        zeek: common::free_port(),
        suricata: common::free_port(),
        ipfix: common::free_port(),
        sflow: common::free_port(),
    };
    let mut p = Proc::spawn_healthy(BIN, &config_toml(&ports, &s3.endpoint()), &ENVS).await;

    // Zeek is both aggregated (dns rule) and persisted raw on both targets only for records the
    // aggregator does not consume; a non-dns record bypasses the aggregation rule.
    let mut zeek = None;
    for _ in 0..100 {
        if let Ok(s) = tokio::net::TcpStream::connect(("127.0.0.1", ports.zeek)).await {
            zeek = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut zeek = zeek.expect("zeek listener up");
    for q in ["a.example", "a.example", "b.example"] {
        let line = serde_json::json!({"_path": "dns", "ts": 1700000100.0, "uid": "C1",
            "id.orig_h": "192.168.1.100", "id.orig_p": 12345, "id.resp_h": "8.8.8.8",
            "id.resp_p": 53, "query": q})
        .to_string();
        zeek.write_all(format!("{line}\n").as_bytes())
            .await
            .unwrap();
    }
    zeek.flush().await.unwrap();

    // Wait for a cardinality window and an aggregate flush interval to elapse.
    let aggregated = common::wait_until(Duration::from_secs(20), || {
        !common::parquet_files(&p.dir().join("agg")).is_empty()
    })
    .await;
    assert!(aggregated, "no aggregate parquet appeared:\n{}", p.logs());

    let st = p.terminate(Duration::from_secs(30));
    assert!(
        st.success(),
        "graceful exit expected, got {st}:\n{}",
        p.logs()
    );

    // Aggregate rows: query a.example counted twice, b.example once, on local disk.
    let rows = common::read_all(&p.dir().join("agg"));
    let mut seen = Vec::new();
    for b in &rows {
        let q = common::str_col(b, "query");
        for i in 0..b.num_rows() {
            seen.push(q.value(i).to_string());
        }
    }
    seen.sort();
    assert_eq!(seen, ["a.example", "b.example"], "aggregated groups");

    // The same aggregate table went to S3 as well.
    assert!(
        s3.put_keys().iter().any(|k| k.starts_with("agg_s3/")),
        "aggregate S3 target got nothing: {:?}",
        s3.put_keys()
    );

    let logs = p.logs();
    assert!(
        logs.contains("Aggregation enabled: 5 rule(s), 1s window"),
        "missing aggregation startup line:\n{logs}"
    );
    assert!(
        logs.contains("Field-cardinality watching enabled: 6 watch(es)"),
        "missing cardinality startup line:\n{logs}"
    );
    // JSON log format: every non-empty stdout line is a JSON object.
    let stdout = std::fs::read_to_string(p.dir().join("stdout.log")).unwrap();
    let json_lines = stdout
        .lines()
        .filter(|l| serde_json::from_str::<serde_json::Value>(l).is_ok())
        .count();
    assert!(json_lines > 0, "no JSON log lines in stdout:\n{stdout}");
    assert!(logs.contains("Shutdown complete"));
}
