//! Integration test: a WEF batch with a malformed trailing event still
//! survives to Parquet for the events that parsed cleanly, exercising the
//! fix in `WefParser::parse_events` (src/protocol/mod.rs) end to end through
//! `wef_local_start` (pattern: `tests/wef_local_integration.rs`).
//!
//! The malformed event itself (`</Mismatch>` inside `<System>`, same trigger
//! as the unit tests in `src/protocol/mod.rs`) becomes one raw, *unparsed*
//! `WindowsEvent` (`WindowsEvent::new` with no `.with_parsed`) per the fix —
//! `WefAccumulator::append_event`/`try_append` (src/forwarding/parquet_s3.rs)
//! silently skip unparsed events (pre-existing behavior, unrelated to this
//! fix), so it never becomes a Parquet row itself. What this test proves is
//! that the fix does not lose or corrupt the well-formed events around it:
//! both land as real rows.

use bytes::Bytes;
use logthing::config::WefLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::parquet_s3::wef_local_start;
use logthing::protocol::{WefMessage, WefParser};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::sync::Arc;

/// Well-formed `<Event>` for event number `n`, matching real WEF shape —
/// same helper shape as the unit tests in `src/protocol/mod.rs`.
fn wef_event(n: u32) -> String {
    format!(
        "<Event><System><Provider>P</Provider><EventID>{n}</EventID><Level>4</Level>\
         </System></Event>"
    )
}

/// Malformed `<Event>`: a stray `</Mismatch>` end tag inside `<System>`
/// trips quick-xml's default `check_end_names` and returns `Err` from
/// `read_event_into`.
fn wef_malformed_event() -> &'static str {
    "<Event><System><Provider>P</Provider></Mismatch><EventID>99</EventID>\
     <Level>4</Level></System></Event>"
}

#[tokio::test]
async fn malformed_trailing_event_does_not_drop_the_good_events_around_it() {
    let body = format!(
        "<Envelope><Body><Events>{}{}{}</Events></Body></Envelope>",
        wef_event(1),
        wef_event(3),
        wef_malformed_event()
    );

    let parser = WefParser::new();
    let WefMessage::Events(events) = parser
        .parse_message(&body, "host-a".into())
        .expect("parse_message must not error even on a malformed trailing event")
    else {
        panic!("expected Events");
    };

    // event(1), event(3), and one raw fallback event for the malformed tail.
    assert_eq!(events.len(), 3, "events: {events:?}");

    let tmp = tempfile::tempdir().unwrap();
    let sink = Arc::new(
        LocalDiskSink::new(tmp.path().to_path_buf())
            .await
            .expect("LocalDiskSink constructs"),
    );

    let cfg = WefLocalConfig {
        directory: tmp.path().to_path_buf(),
        prefix: "".to_string(),
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 256,
        max_buffer_rows: 100_000,
    };

    let (handle, join_handle) = wef_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    for event in events {
        handle.try_send(Arc::new(event)).expect("send event");
    }

    // Drop the handle to close the channel and trigger the shutdown flush.
    drop(handle);
    tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
        .await
        .expect("writer task must exit within 5s")
        .expect("writer task must not panic");

    // Find the single Parquet file under the tempdir.
    let mut all_files = Vec::new();
    let mut stack = vec![tmp.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                all_files.push(path);
            }
        }
    }
    let parquet_files: Vec<_> = all_files
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect();
    // event(1) and event(3) partition into separate `event_type=<id>/`
    // directories (unlike `wef_local_integration.rs`, whose two events share
    // one event_id), so 2 files are expected here — the malformed tail's raw
    // fallback event has no parsed data and produces no file at all.
    assert_eq!(
        parquet_files.len(),
        2,
        "expected 2 Parquet files (event_type=1 and event_type=3 partitions); \
         found {parquet_files:?}"
    );

    use arrow::array::{Array, StringArray};
    let mut total_rows = 0usize;
    let mut found_event_id_3 = false;
    for path in &parquet_files {
        let raw = std::fs::read(path).unwrap();
        let buf = Bytes::from(raw);
        let builder = ParquetRecordBatchReaderBuilder::try_new(buf).unwrap();
        let reader = builder.build().unwrap();
        for rb in reader {
            let rb = rb.unwrap();
            total_rows += rb.num_rows();
            let event_data = rb
                .column_by_name("event_data")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..event_data.len() {
                if event_data.value(i).contains("<EventID>3</EventID>") {
                    found_event_id_3 = true;
                }
            }
        }
    }

    assert_eq!(
        total_rows, 2,
        "only the 2 well-formed events must land as Parquet rows; the malformed tail's raw \
         fallback event has no parsed data and is skipped by WefSink, matching pre-existing \
         behavior"
    );
    assert!(
        found_event_id_3,
        "one row's raw XML (event_data column) must contain <EventID>3</EventID>"
    );
}
