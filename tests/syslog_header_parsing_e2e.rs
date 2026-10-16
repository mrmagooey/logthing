//! E2E: the real binary parses syslog headers correctly (RFC 5424 NILVALUE structured data,
//! CEF after an RFC 3164 header, out-of-range PRI) and writes the parsed columns to Parquet.

mod common;

use arrow::array::{Array, UInt8Array};
use std::time::Duration;
use tokio::net::UdpSocket;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");

const CEF_BODY: &str = "CEF:0|Vendor|FW|1.0|SIG001|Firewall Accept|6|src=10.0.0.1 dst=8.8.8.8";

fn toml(udp: u16, tcp: u16) -> String {
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
[syslog.local]
directory = "{{DIR}}/syslog"
prefix = "syslog"
max_buffer_rows = 1
flush_interval_secs = 1
"#
    )
}

#[tokio::test]
async fn test_syslog_headers_parsed_into_parquet_columns_by_real_binary() {
    let (udp, tcp) = (common::free_port(), common::free_port());
    let mut p = common::Proc::spawn(BIN, &toml(udp, tcp), &[]);
    p.wait_healthy().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let lines = [
        format!("<134>1 2024-01-15T10:30:45.000Z fw5424 - - - - {CEF_BODY}"),
        format!("<134>Jan 15 10:30:45 fw3164 {CEF_BODY}"),
        "<200>Jan 15 10:30:45 hostx too-big-pri".to_string(),
    ];
    for l in &lines {
        sock.send_to(l.as_bytes(), format!("127.0.0.1:{udp}"))
            .await
            .unwrap();
    }

    let dir = p.dir().join("syslog");
    let batches = common::wait_for_rows(&dir, 3, Duration::from_secs(20)).await;
    // (hostname, app_name, message, priority, facility) per row.
    let mut rows = Vec::new();
    for b in &batches {
        let host = common::str_col(b, "hostname");
        let app = common::str_col(b, "app_name");
        let msg = common::str_col(b, "message");
        let pri = b
            .column_by_name("priority")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt8Array>()
            .unwrap();
        let fac = b
            .column_by_name("facility")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt8Array>()
            .unwrap();
        for i in 0..b.num_rows() {
            rows.push((
                (!host.is_null(i)).then(|| host.value(i).to_string()),
                (!app.is_null(i)).then(|| app.value(i).to_string()),
                msg.value(i).to_string(),
                pri.value(i),
                fac.value(i),
            ));
        }
    }
    rows.sort();

    let want_5424 = (
        Some("fw5424".to_string()),
        None,
        CEF_BODY.to_string(),
        134,
        16,
    );
    let want_3164 = (
        Some("fw3164".to_string()),
        None,
        CEF_BODY.to_string(),
        134,
        16,
    );
    let want_bad = (None, None, lines[2].clone(), 13, 1);
    assert_eq!(rows.len(), 3, "{rows:?}");
    for want in [want_5424, want_3164, want_bad] {
        assert!(rows.contains(&want), "missing {want:?} in {rows:?}");
    }
}
