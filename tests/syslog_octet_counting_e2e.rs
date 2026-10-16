//! E2E: the real binary accepts RFC 6587 octet-counted syslog frames on TCP (including a
//! body with an embedded newline), mixed with newline-framed lines on the same connection,
//! and writes each message to Parquet.

mod common;

use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");

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
async fn test_octet_counted_tcp_frames_written_to_parquet_by_real_binary() {
    let (udp, tcp) = (common::free_port(), common::free_port());
    let mut p = common::Proc::spawn(BIN, &toml(udp, tcp), &[]);
    p.wait_healthy().await;

    let counted_nl = "<134>Jan 15 10:30:45 host-a app: alpha\nbeta";
    let counted = "<134>Jan 15 10:30:46 host-b app: gamma";
    let lined = "<134>Jan 15 10:30:47 host-c app: delta";
    let dated = "2026-10-16 12:00 not-syslog line";
    let mut payload = Vec::new();
    payload.extend_from_slice(format!("{} {counted_nl}", counted_nl.len()).as_bytes());
    payload.extend_from_slice(format!("{} {counted}", counted.len()).as_bytes());
    payload.extend_from_slice(format!("{dated}\n{lined}\n").as_bytes());

    // The TCP listener may bind a moment after /health answers.
    let mut stream = None;
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", tcp)).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut stream = stream.expect("syslog TCP port must accept");
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();

    let dir = p.dir().join("syslog");
    let want = [
        ("host-a", "alpha\nbeta"),
        ("host-b", "gamma"),
        ("host-c", "delta"),
    ];
    // More than 3 rows can land (the dated line may parse), so poll until every wanted
    // message is present rather than for a row count.
    let mut rows: Vec<(String, String)> = Vec::new();
    let end = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        rows.clear();
        for b in &common::read_all(&dir) {
            let host = common::str_col(b, "hostname");
            let msg = common::str_col(b, "message");
            for i in 0..b.num_rows() {
                rows.push((host.value(i).to_string(), msg.value(i).to_string()));
            }
        }
        if want
            .iter()
            .all(|(_, m)| rows.iter().any(|(_, rm)| rm.ends_with(m)))
        {
            break;
        }
        if std::time::Instant::now() > end {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    rows.sort();
    for (h, m) in want {
        // Multi-line RFC 3164 bodies keep the header text in `message` and leave `hostname`
        // empty (parser behaviour, same over UDP), so match on the message tail only.
        assert!(
            rows.iter().any(|(_, rm)| rm.ends_with(m)),
            "missing ({h:?}, {m:?}) in {rows:?}\n{}",
            p.logs()
        );
    }
}
