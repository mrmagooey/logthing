//! E2E test: syslog messages spanning a UTC day boundary, ingested through
//! the public `SyslogHandler::handle_message` entry point (the same call
//! path a real UDP/TCP listener uses via `syslog_local_start`) -- not
//! `PartitionedParquetWriter` directly -- must produce one day-clean
//! Parquet file per day, including for a message with no parseable
//! `timestamp`, which must fall back to `received_at` rather than silently
//! landing in whichever day the process happened to be in when the buffer
//! last flushed. Every assertion reads back the actual on-disk Parquet
//! bytes, not just the schema or an in-memory batch.
//!
//! `SyslogMessage` is constructed directly here with `timestamp` already
//! populated (as `SyslogHandler::handle_message` receives it from the real
//! parser) -- no syslog header text is parsed in this test, so
//! `parse_rfc3164_timestamp`'s "missing year resolves from the current
//! year" behaviour never comes into play regardless of `protocol`. RFC 5424
//! is used anyway (the protocol tag is the more realistic choice, since its
//! wire format is the one that actually carries an explicit year).
//!
//! Two fixed past days (2023-11-14 and 2023-11-15) are used for the
//! straddling pair -- not "today"/"tomorrow" -- so that a total failure of
//! day derivation (e.g. everything silently falling back to `Utc::now()`)
//! cannot coincidentally produce a passing result.

use logthing::config::SyslogLocalConfig;
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::syslog_s3::syslog_local_start;
use logthing::syslog::listener::SyslogHandler;
use logthing::syslog::{SyslogMessage, SyslogProtocol};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn msg(text: &str, ts: Option<chrono::DateTime<chrono::Utc>>) -> SyslogMessage {
    SyslogMessage {
        priority: 13,
        severity: 5,
        facility: 1,
        timestamp: ts,
        hostname: Some("host1".to_string()),
        app_name: Some("app1".to_string()),
        proc_id: None,
        msg_id: None,
        message: text.to_string(),
        structured_data: None,
        protocol: SyslogProtocol::Rfc5424,
    }
}

fn walk_all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk_all_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// Parse the UTC calendar day implied by a `.../year=YYYY/month=MM/day=DD/<file>`
/// path -- the directory the writer chose to file this Parquet file under.
fn day_from_path(path: &Path) -> chrono::NaiveDate {
    let mut year = None;
    let mut month = None;
    let mut day = None;
    for component in path.components() {
        let s = component.as_os_str().to_string_lossy();
        if let Some(v) = s.strip_prefix("year=") {
            year = v.parse::<i32>().ok();
        } else if let Some(v) = s.strip_prefix("month=") {
            month = v.parse::<u32>().ok();
        } else if let Some(v) = s.strip_prefix("day=") {
            day = v.parse::<u32>().ok();
        }
    }
    chrono::NaiveDate::from_ymd_opt(
        year.unwrap_or_else(|| panic!("no year= segment in {path:?}")),
        month.unwrap_or_else(|| panic!("no month= segment in {path:?}")),
        day.unwrap_or_else(|| panic!("no day= segment in {path:?}")),
    )
    .unwrap_or_else(|| panic!("invalid date in {path:?}"))
}

/// Read a single-row Parquet file back off disk and return the UTC
/// calendar day held in `column`'s row 0. Fails the test outright if the
/// column is absent, not a timestamp array, or null -- this is meant to
/// prove the value is genuinely present in the on-disk bytes, not merely
/// that a directory with the right name exists.
fn read_day_column(path: &Path, column: &str) -> chrono::NaiveDate {
    let raw = std::fs::read(path).expect("read parquet file");
    let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(raw))
        .expect("parquet builder for on-disk bytes");
    let mut reader = builder.build().expect("build parquet reader");
    let batch = reader
        .next()
        .expect("at least one record batch")
        .expect("record batch reads without error");

    use arrow::array::{Array, TimestampMicrosecondArray};
    let col = batch
        .column_by_name(column)
        .unwrap_or_else(|| panic!("column {column:?} present in {path:?}"))
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .unwrap_or_else(|| panic!("column {column:?} is a microsecond timestamp array"));
    assert!(
        !col.is_null(0),
        "column {column:?} row 0 must not be null in {path:?}"
    );
    chrono::DateTime::from_timestamp_micros(col.value(0))
        .expect("valid micros")
        .date_naive()
}

#[tokio::test]
async fn syslog_ingest_spanning_midnight_is_day_clean() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = SyslogLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "syslog".to_string(),
        max_buffer_rows: 1, // flush every message immediately: deterministic, no flush-timing races
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, writer_task) = syslog_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: std::net::SocketAddr = "127.0.0.1:47762".parse().unwrap();
    use chrono::TimeZone;
    let day1_ts = chrono::Utc
        .with_ymd_and_hms(2023, 11, 14, 23, 59, 0)
        .unwrap();
    let day2_ts = chrono::Utc.with_ymd_and_hms(2023, 11, 15, 0, 1, 0).unwrap();
    let expected_day1 = day1_ts.date_naive();
    let expected_day2 = day2_ts.date_naive();

    // Bracket the no-timestamp push with wall-clock reads so the test can
    // confirm the fallback lands near "now" without hardcoding an exact
    // date -- avoiding flakiness if the test happens to straddle a real
    // midnight itself.
    handler
        .handle_message(msg("before midnight", Some(day1_ts)), src)
        .await;
    handler
        .handle_message(msg("after midnight", Some(day2_ts)), src)
        .await;
    let before_fallback = chrono::Utc::now().date_naive();
    handler
        .handle_message(msg("no parseable timestamp", None), src)
        .await;
    let after_fallback = chrono::Utc::now().date_naive();

    // Close the channel and wait for the final shutdown flush so all three
    // pushes are guaranteed to have been written before inspecting disk.
    drop(handler);
    tokio::time::timeout(std::time::Duration::from_secs(5), writer_task)
        .await
        .expect("writer task must exit within 5s")
        .expect("writer task must not panic");

    let mut all_files = Vec::new();
    walk_all_files(dir.path(), &mut all_files);
    let parquet_files: Vec<_> = all_files
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .cloned()
        .collect();
    assert_eq!(
        parquet_files.len(),
        3,
        "expected exactly 3 Parquet files (one per message, one per day); found {parquet_files:?}"
    );

    // Every file must live under a distinct day directory: three messages,
    // three separate days, by construction of the buffer key -- no file is
    // allowed to hold rows spanning more than one day, and here that means
    // no two of these three messages may share a directory.
    let mut by_day: std::collections::HashMap<chrono::NaiveDate, PathBuf> =
        std::collections::HashMap::new();
    for path in &parquet_files {
        let day = day_from_path(path);
        assert!(
            by_day.insert(day, path.clone()).is_none(),
            "two Parquet files landed under the same day directory ({day}); \
             expected exactly one file per day: {parquet_files:?}"
        );
    }
    assert_eq!(by_day.len(), 3, "expected 3 distinct day directories");

    // Property: the "before midnight" message's file lives under
    // 2023-11-14, and its `timestamp` column -- read back from the actual
    // on-disk Parquet bytes -- itself decodes to that same day.
    let day1_path = by_day
        .get(&expected_day1)
        .unwrap_or_else(|| panic!("no file under {expected_day1}; found {by_day:?}"));
    assert_eq!(
        read_day_column(day1_path, "timestamp"),
        expected_day1,
        "day1 file's on-disk timestamp column must decode to its own directory's day"
    );

    // Property: the "after midnight" message's file lives under
    // 2023-11-15, one day later, not merged into the same file as day1.
    let day2_path = by_day
        .get(&expected_day2)
        .unwrap_or_else(|| panic!("no file under {expected_day2}; found {by_day:?}"));
    assert_eq!(
        read_day_column(day2_path, "timestamp"),
        expected_day2,
        "day2 file's on-disk timestamp column must decode to its own directory's day"
    );

    // Property: the message with NO parseable timestamp must NOT have
    // landed under day1 or day2 (which would mean it silently inherited
    // whichever day the buffer/process happened to be in), and its file's
    // `received_at` column -- not `timestamp`, which is null for this row
    // -- must itself decode to that same fallback day, landing within the
    // [before_fallback, after_fallback] wall-clock bracket taken around the
    // push.
    let fallback_day = *by_day
        .keys()
        .find(|d| **d != expected_day1 && **d != expected_day2)
        .expect("a third, distinct day directory for the no-timestamp message");
    assert!(
        fallback_day == before_fallback || fallback_day == after_fallback,
        "no-timestamp message's directory day {fallback_day} must fall within the \
         wall-clock bracket [{before_fallback}, {after_fallback}] taken around its push"
    );
    let fallback_path = &by_day[&fallback_day];
    assert_eq!(
        read_day_column(fallback_path, "received_at"),
        fallback_day,
        "no-timestamp file's on-disk received_at column must decode to its own \
         directory's day (the fallback source day_from_batch actually used)"
    );

    // No leftover .tmp- files after all flushes complete.
    assert!(
        !all_files
            .iter()
            .any(|p| p.file_name().unwrap().to_string_lossy().contains(".tmp-")),
        "no leftover .tmp- files should remain after flush: {all_files:?}"
    );
}
