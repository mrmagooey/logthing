//! End-to-end: the real `logthing` binary receives HEC envelopes whose `time` is a string or
//! epoch milliseconds, behind a UTF-8 BOM, and writes the right `time` column.

mod common;

use arrow::array::{Array, TimestampMicrosecondArray};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");

#[tokio::test]
async fn binary_hec_event_accepts_bom_string_and_millis_times() {
    let toml = "bind_address = \"127.0.0.1:{HTTP}\"\n[tls]\nenabled = false\n\
                [syslog]\nenabled = false\n[metrics]\nenabled = false\n\
                [hec]\nenabled = true\ntoken = \"\"\n\
                [hec.local]\ndirectory = \"{DIR}/hec\"\nflush_threshold_bytes = 1\n\
                flush_interval_secs = 1\n";
    let proc = common::Proc::spawn_healthy(BIN, toml, &[]).await;

    let mut body = vec![0xEF, 0xBB, 0xBF];
    body.extend_from_slice(
        b"{\"event\":{\"n\":1},\"time\":\"1700000000.5\"}\n\
          {\"event\":{\"n\":2},\"time\":1700000001000}\n\
          {\"event\":{\"n\":3},\"time\":-1.5}\n",
    );
    let resp = reqwest::Client::new()
        .post(format!("{}/services/collector/event", proc.base()))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "logs:\n{}", proc.logs());

    let mut ndjson = vec![0xEF, 0xBB, 0xBF];
    ndjson.extend_from_slice(b"{\"n\":4}\n{\"n\":5}\n");
    let resp = reqwest::Client::new()
        .post(format!("{}/ingest", proc.base()))
        .body(ndjson)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "logs:\n{}", proc.logs());

    let dir = proc.dir().join("hec");
    let batches = common::wait_for_rows(&dir, 5, Duration::from_secs(20)).await;
    let mut times: Vec<i64> = batches
        .iter()
        .flat_map(|b| {
            let col = b
                .column_by_name("time")
                .unwrap()
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .unwrap();
            (0..col.len())
                .filter(|&i| col.is_valid(i))
                .map(|i| col.value(i))
                .collect::<Vec<_>>()
        })
        .collect();
    times.sort();
    assert_eq!(times.len(), 3, "{times:?}");
    assert_eq!(times[0], -1_500_000);
    assert!((times[1] - 1_700_000_000_500_000).abs() < 10, "{times:?}");
    assert_eq!(times[2], 1_700_000_001_000_000);
}
