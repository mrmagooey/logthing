//! End-to-end test: sFlow decoder fixes across a real `logthing` process.
//!
//! One datagram holding a short generic_if_counters record, an ethernet
//! counter record, a valid generic_if_counters record and an IPv6
//! hop-by-hop TCP flow sample is sent over UDP to the spawned binary; the
//! counter row and the flow row (with ports) must both land in Parquet.

mod common;
mod sflow_fixture;

use common::{Proc, wait_for_rows};
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn sflow_bad_counter_record_does_not_lose_the_rest_on_the_real_binary() {
    let port = common::free_port();
    let toml = format!(
        r#"
bind_address = "127.0.0.1:{{HTTP}}"

[tls]
enabled = false
[metrics]
enabled = false

[syslog]
enabled = false

[sflow]
enabled = true
udp_port = {port}
bind_address = "127.0.0.1"

[sflow.local]
directory = "{{DIR}}/sflow"
max_buffer_rows = 1
flush_threshold_bytes = 1
flush_interval_secs = 3600
"#
    );
    let p = Proc::spawn_healthy(env!("CARGO_BIN_EXE_logthing"), &toml, &[]).await;
    let out = p.dir().join("sflow");
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(
        &sflow_fixture::mixed_datagram(7),
        format!("127.0.0.1:{port}"),
    )
    .await
    .unwrap();

    let batches = wait_for_rows(&out, 3, Duration::from_secs(20)).await;
    sflow_fixture::assert_rows(&batches, 7);
}
