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
//! The straddling pair is anchored 2 days before the real `Utc::now()` at
//! test-run time (not a hardcoded calendar date, and not "today"/"tomorrow")
//! so it lands inside `partition_time`'s `[received_at - 30d, received_at +
//! 1d]` clamp window (see `buffered_writer::partition_time`) -- outside that
//! window, an event instant is *supposed* to collapse onto `received_at` by
//! design, which would make a hardcoded far-past date coincidentally pass
//! even with a broken derivation. Anchoring 2 days back, rather than at
//! "today", also means a test run starting right at a real UTC midnight
//! cannot put both instants on the same side of the boundary.

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
    // Anchor 2 days before the real "now" so both instants sit safely
    // inside the clamp window relative to the REAL `received_at` the mapper
    // stamps at push time (which is close to `now`), while still landing on
    // two different UTC calendar days determined by the real clock rather
    // than a hardcoded date -- see the module doc comment above.
    let now = chrono::Utc::now();
    let anchor_midnight = (now - chrono::TimeDelta::days(2))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc();
    let day1_ts = anchor_midnight - chrono::TimeDelta::minutes(1); // 23:59:00 the day before
    let day2_ts = anchor_midnight + chrono::TimeDelta::minutes(1); // 00:01:00 the anchor day
    let expected_day1 = day1_ts.date_naive();
    let expected_day2 = day2_ts.date_naive();

    // Accept either of the two adjacent UTC dates for the no-timestamp
    // fallback rather than hardcoding one, so a run that straddles a real
    // midnight cannot flake.
    //
    // Note these two reads do NOT literally bracket the push's own clock
    // read. `handle_message` has no `.await` suspension point and this is a
    // current-thread `#[tokio::test]`, so the writer task -- where `push()`
    // actually reads `Utc::now()` -- is not scheduled until the final
    // `drop(handler)` / `timeout(..).await` below. All three pushes' real
    // clock reads therefore happen just AFTER `after_fallback`, within a
    // few milliseconds of it. The assertion holds because that gap is far
    // smaller than a day, not because of any ordering guarantee.
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

    // Property: the "before midnight" message's file lives under the
    // anchor day minus one, and its `partition_time` column -- read back
    // from the actual on-disk Parquet bytes, the column the external
    // Iceberg committer's day() transform is declared against -- itself
    // decodes to that same day.
    let day1_path = by_day
        .get(&expected_day1)
        .unwrap_or_else(|| panic!("no file under {expected_day1}; found {by_day:?}"));
    assert_eq!(
        read_day_column(day1_path, "partition_time"),
        expected_day1,
        "day1 file's on-disk partition_time column must decode to its own directory's day"
    );

    // Property: the "after midnight" message's file lives under the anchor
    // day, one day later, not merged into the same file as day1.
    let day2_path = by_day
        .get(&expected_day2)
        .unwrap_or_else(|| panic!("no file under {expected_day2}; found {by_day:?}"));
    assert_eq!(
        read_day_column(day2_path, "partition_time"),
        expected_day2,
        "day2 file's on-disk partition_time column must decode to its own directory's day"
    );

    // Property: the message with NO parseable timestamp must NOT have
    // landed under day1 or day2 (which would mean it silently inherited
    // whichever day the buffer/process happened to be in), and its file's
    // `partition_time` column -- non-null by construction even though
    // `timestamp` is null for this row -- must itself decode to that same
    // fallback day, landing within the [before_fallback, after_fallback]
    // wall-clock bracket taken around the push.
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
        read_day_column(fallback_path, "partition_time"),
        fallback_day,
        "no-timestamp file's on-disk partition_time column must decode to its own \
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

/// Regression test for the bug this addendum exists to close: a
/// `timestamp`-bearing message and a `timestamp: None` message
/// (`timestamp: None` -- what a CEF/LEEF payload yields, see
/// `src/syslog/mod.rs:313`) must each get `partition_time` derived from
/// their OWN day, not silently collapsed onto whichever day the process
/// happened to be in.
///
/// Before `partition_time` existed, the day-clean guarantee (and the
/// Iceberg partition column) was derived straight from the nullable
/// `timestamp` column: a file holding one row with a real `timestamp` and
/// one row with `timestamp: null` would make Iceberg's `day(timestamp)`
/// transform see TWO distinct values -- a real date and `null` -- in one
/// file, which Iceberg refuses to register. `partition_time` is non-null by
/// construction (see `syslog_message_to_batch`) and buffers are keyed on
/// `(partition, day)`, so a null `timestamp` and a real one that fall on
/// DIFFERENT days must land in two separate day-clean files rather than
/// one file mixing two `day()` values.
///
/// The timestamped message is deliberately anchored 2 days before the real
/// `Utc::now()` (inside `partition_time`'s 30-day backfill clamp, but a
/// different UTC calendar day from receipt) rather than at "now" itself.
/// An earlier version of this test used `Some(chrono::Utc::now())` for the
/// timestamped message, which put both rows' EXPECTED `partition_time` day
/// on the receipt day -- so a `partition_time` implementation that always
/// returned `received_at` (i.e. `partition_time` was never wired up at
/// all) would still pass every assertion. Anchoring 2 days back means a
/// broken derivation merges both messages into the SAME (receipt-day)
/// file, which the file-count assertion below catches.
#[tokio::test]
async fn mixed_timestamped_and_timestampless_messages_land_in_distinct_day_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = SyslogLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "syslog".to_string(),
        max_buffer_rows: 10_000, // do NOT flush between the two pushes below
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, writer_task) = syslog_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: std::net::SocketAddr = "127.0.0.1:47763".parse().unwrap();

    // A CEF/LEEF-shaped message: the parser produced no `timestamp` at all,
    // so this row's `timestamp` column is null; its `partition_time` falls
    // back to `received_at`, stamped internally as `Utc::now()` at push
    // time. Bracket the push with wall-clock reads (rather than asserting
    // one hardcoded day) so a run straddling a real UTC midnight cannot
    // flake -- same technique as `syslog_ingest_spanning_midnight_is_day_clean`.
    let before_fallback = chrono::Utc::now().date_naive();
    handler
        .handle_message(msg("no parseable timestamp", None), src)
        .await;
    let after_fallback = chrono::Utc::now().date_naive();

    // An ordinary message WITH a parseable timestamp, 2 days before the
    // real "now" -- inside the clamp, but a different UTC day from receipt
    // in every realistic run (including one starting right at midnight,
    // since the two instants are 2 whole days apart).
    let event_ts = chrono::Utc::now() - chrono::TimeDelta::days(2);
    let expected_event_day = event_ts.date_naive();
    handler
        .handle_message(msg("has a timestamp", Some(event_ts)), src)
        .await;

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
        2,
        "the timestamped message's event day differs from the no-timestamp \
         message's receipt day, so they must land in two separate day-clean \
         files, not merged into one; found {parquet_files:?}"
    );

    use arrow::array::{Array, TimestampMicrosecondArray};

    // Every file must be internally day-clean (exactly one distinct
    // `partition_time` day), and the two files' days must differ from each
    // other -- the property this addendum establishes.
    let mut days_seen = std::collections::HashSet::new();
    for path in &parquet_files {
        let raw = std::fs::read(path).unwrap();
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(raw))
            .expect("parquet builder");
        let reader = builder.build().expect("build parquet reader");

        let mut partition_time_days = std::collections::HashSet::new();
        let mut total_rows = 0;
        for batch in reader {
            let batch = batch.expect("record batch reads without error");
            total_rows += batch.num_rows();

            let pt_col = batch
                .column_by_name("partition_time")
                .unwrap()
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .unwrap();
            for i in 0..pt_col.len() {
                assert!(
                    !pt_col.is_null(i),
                    "partition_time must never be null (row {i}) in {path:?}"
                );
                partition_time_days.insert(
                    chrono::DateTime::from_timestamp_micros(pt_col.value(i))
                        .expect("valid micros")
                        .date_naive(),
                );
            }
        }

        assert_eq!(total_rows, 1, "expected exactly 1 row per file in {path:?}");
        assert_eq!(
            partition_time_days.len(),
            1,
            "partition_time must hold exactly one distinct UTC day within a \
             single file; got {partition_time_days:?} in {path:?}"
        );
        days_seen.extend(partition_time_days);
    }

    assert_eq!(
        days_seen.len(),
        2,
        "the two files must hold two DISTINCT partition_time days, not the \
         same day twice; got {days_seen:?}"
    );
    assert!(
        days_seen.contains(&expected_event_day),
        "one file's partition_time day must equal the timestamped message's \
         own event day ({expected_event_day}); got {days_seen:?}"
    );
    assert!(
        days_seen.contains(&before_fallback) || days_seen.contains(&after_fallback),
        "the no-timestamp message's file's partition_time day must fall within \
         the wall-clock bracket [{before_fallback}, {after_fallback}] taken \
         around its push; got {days_seen:?}"
    );
}
