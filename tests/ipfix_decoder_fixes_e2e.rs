//! End-to-end test: IPFIX decoder fixes across a real `logthing` process.
//!
//! Crafted IPFIX datagrams are sent over UDP to the spawned binary (IPFIX
//! listener + local Parquet sink) and the rows are read back from disk:
//!
//! * post-NAT IEs (225/227) must not overwrite the original tuple;
//! * an options data set must not become a null-tuple row;
//! * a datagram holding a valid data set followed by a malformed template
//!   set must still land the valid rows.

mod common;

use arrow::array::{Array, StringArray, UInt16Array};
use common::{Proc, wait_for_rows};
use std::time::Duration;
use tokio::net::UdpSocket;

fn set(set_id: u16, body: &[u8]) -> Vec<u8> {
    let mut v = set_id.to_be_bytes().to_vec();
    v.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn message(sets: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = sets.concat();
    let mut v = vec![0x00, 0x0A];
    v.extend_from_slice(&((16 + body.len()) as u16).to_be_bytes());
    v.extend_from_slice(&[0x67, 0x5C, 0xB0, 0x20, 0, 0, 0, 1, 0, 0, 0, 0]);
    v.extend_from_slice(&body);
    v
}

fn udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
}

#[tokio::test]
async fn ipfix_decoder_fixes_hold_on_the_real_binary() {
    let ipfix_port = udp_port();
    let toml = format!(
        r#"
bind_address = "127.0.0.1:{{HTTP}}"

[tls]
enabled = false

[syslog]
enabled = false

[ipfix]
enabled = true
udp_port = {ipfix_port}
bind_address = "127.0.0.1"

[ipfix.local]
directory = "{{DIR}}/ipfix"
max_buffer_rows = 1
flush_threshold_bytes = 1
flush_interval_secs = 3600
"#
    );
    let p = Proc::spawn_healthy(env!("CARGO_BIN_EXE_logthing"), &toml, &[]).await;
    let out = p.dir().join("ipfix");
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = format!("127.0.0.1:{ipfix_port}");

    // Template [8, 225, 7, 227] and its data in one datagram.
    let template = [
        &[1u8, 0, 0, 4][..],
        &[0, 8, 0, 4, 0, 225, 0, 4, 0, 7, 0, 2, 0, 227, 0, 2],
    ]
    .concat();
    let data = [10, 0, 0, 1, 203, 0, 113, 9, 0x1F, 0x90, 0xC3, 0x50];
    sock.send_to(&message(&[set(2, &template), set(256, &data)]), &target)
        .await
        .unwrap();
    // The template must be cached before datagram 3 relies on it.
    wait_for_rows(&out, 1, Duration::from_secs(20)).await;

    // Options template + options data: must add no row.
    let opt_tmpl = [1u8, 0x2C, 0, 2, 0, 1, 0, 144, 0, 4, 0, 160, 0, 8];
    let opt_data = [0u8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2];
    sock.send_to(&message(&[set(3, &opt_tmpl), set(300, &opt_data)]), &target)
        .await
        .unwrap();

    // Valid data set (reusing template 256) followed by a truncated template
    // set (declares 2 fields, carries 1): the valid row must still land.
    let data2 = [10, 0, 0, 2, 198, 51, 100, 7, 0x00, 0x50, 0x00, 0x51];
    let bad_template = [1u8, 1, 0, 2, 0, 8, 0, 4];
    sock.send_to(
        &message(&[set(256, &data2), set(2, &bad_template)]),
        &target,
    )
    .await
    .unwrap();

    wait_for_rows(&out, 2, Duration::from_secs(20)).await;
    // Let any (incorrect) extra rows from the options datagram arrive.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let batches = common::read_all(&out);

    let mut seen: Vec<(String, u16, String)> = Vec::new();
    for b in &batches {
        let addr = common::str_col(b, "src_addr");
        let port = b
            .column_by_name("src_port")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt16Array>()
            .unwrap();
        let extra = b
            .column_by_name("extra")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        for i in 0..b.num_rows() {
            assert!(!addr.is_null(i), "options data produced a null-tuple row");
            seen.push((
                addr.value(i).to_string(),
                port.value(i),
                extra.value(i).to_string(),
            ));
        }
    }
    seen.sort();
    assert_eq!(seen.len(), 2, "rows: {seen:?}");
    let (a1, p1, e1) = &seen[0];
    assert_eq!((a1.as_str(), *p1), ("10.0.0.1", 8080));
    let e1: serde_json::Value = serde_json::from_str(e1).unwrap();
    assert_eq!(e1["postNATSourceIPv4Address"], "203.0.113.9");
    assert_eq!(e1["postNAPTSourceTransportPort"], 50000);
    let (a2, p2, e2) = &seen[1];
    assert_eq!((a2.as_str(), *p2), ("10.0.0.2", 80));
    let e2: serde_json::Value = serde_json::from_str(e2).unwrap();
    assert_eq!(e2["postNATSourceIPv4Address"], "198.51.100.7");
}
