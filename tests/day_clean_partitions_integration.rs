//! Integration tests for the day-clean Parquet partitions mechanism: a Zeek
//! `conn` stream whose records straddle a UTC day boundary must produce two
//! separate, single-day Parquet files -- not one file whose rows span two
//! days -- and every artifact this branch touches (the S3 key layout, the
//! Iceberg descriptor, and the retry path) must stay day-clean too. Local
//! disk, no external service, runs unconditionally in CI (see
//! `zeek_local_integration.rs`).
//!
//! Covers four properties:
//! 1. A buffer whose records span two UTC days produces two separate files,
//!    each internally single-day (`conn_records_spanning_midnight_produce_two_day_clean_files`).
//! 2. Each Parquet file gets its own descriptor, paired by name
//!    (`conn_records_spanning_midnight_produce_paired_day_clean_descriptors`).
//! 3. The descriptor's `partition` field carries the partition segment only,
//!    never the day (same test as property 2).
//! 4. The retry path returns a failed flush's batch to its ORIGINAL day's
//!    buffer, not whatever day is current at retry time
//!    (`failed_flush_for_one_day_retries_into_that_same_day_not_elsewhere`).

use logthing::config::{S3ConnectionConfig, ZeekLocalConfig};
use logthing::forwarding::buffered_writer::{
    BufferedWriterConfig, FlushPolicy, LiveInterval, UploadSink,
};
use logthing::forwarding::local_sink::LocalDiskSink;
use logthing::forwarding::zeek_s3::{ZeekS3Handler, ZeekSink, zeek_local_start};
use logthing::zeek::ZeekRecord;
use logthing::zeek::listener::ZeekHandler;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn make_conn_record(uid: &str, ts_epoch_secs: f64) -> ZeekRecord {
    ZeekRecord {
        log_path: "conn".to_string(),
        fields: serde_json::json!({
            "_path": "conn",
            "ts": ts_epoch_secs,
            "uid": uid,
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 12345,
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
        }),
        received_at: chrono::Utc::now(),
    }
}

/// Recursively find every `.parquet` file under `root`, paired with its
/// parent directory (so callers can assert on the `year=/month=/day=`
/// segment it landed under).
fn find_parquet_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "parquet") {
                out.push(path);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Property 1: a straddling buffer produces two separate, single-day files.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn conn_records_spanning_midnight_produce_two_day_clean_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = Arc::new(
        LocalDiskSink::new(dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new"),
    );
    let cfg = ZeekLocalConfig {
        directory: dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: 1, // flush immediately on every push
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, _writer_task) = zeek_local_start(
        &cfg,
        sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    let src: std::net::SocketAddr = "127.0.0.1:47761".parse().unwrap();
    // 1700000000 -> 2023-11-14 22:13:20 UTC; +7200s -> 2023-11-15.
    handler
        .handle_record(make_conn_record("CDay1", 1700000000.0), src)
        .await;
    handler
        .handle_record(make_conn_record("CDay2", 1700000000.0 + 7200.0), src)
        .await;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let day1_dir = dir.path().join("zeek/conn/year=2023/month=11/day=14");
    let day2_dir = dir.path().join("zeek/conn/year=2023/month=11/day=15");
    assert!(day1_dir.is_dir(), "expected {day1_dir:?} to exist");
    assert!(day2_dir.is_dir(), "expected {day2_dir:?} to exist");

    let day1_files: Vec<_> = std::fs::read_dir(&day1_dir).unwrap().collect();
    let day2_files: Vec<_> = std::fs::read_dir(&day2_dir).unwrap().collect();
    assert_eq!(day1_files.len(), 1, "day 1 must contain exactly one file");
    assert_eq!(day2_files.len(), 1, "day 2 must contain exactly one file");

    // Read each file back and confirm every row's ts decodes to that
    // file's own directory day -- the actual day-clean property, not
    // just "the file landed in the right directory."
    use parquet::file::reader::{FileReader, SerializedFileReader};
    for (path_entry, expected_ymd) in [
        (day1_files.into_iter().next().unwrap(), (2023, 11, 14)),
        (day2_files.into_iter().next().unwrap(), (2023, 11, 15)),
    ] {
        let path = path_entry.unwrap().path();
        let file = std::fs::File::open(&path).unwrap();
        let reader = SerializedFileReader::new(file).unwrap();
        let metadata = reader.metadata();
        for rg in 0..metadata.num_row_groups() {
            let rg_meta = metadata.row_group(rg);
            for col in 0..rg_meta.num_columns() {
                if rg_meta.column(col).column_path().string() == "ts" {
                    let stats = rg_meta.column(col).statistics().expect("ts has stats");
                    // min and max must decode to the SAME day as the
                    // directory this file lives in.
                    let (y, m, d) = expected_ymd;
                    let expected = chrono::NaiveDate::from_ymd_opt(y, m, d).unwrap();
                    if let parquet::file::statistics::Statistics::Int64(s) = stats {
                        for micros in [*s.min_opt().unwrap(), *s.max_opt().unwrap()] {
                            let day = chrono::DateTime::from_timestamp_micros(micros)
                                .unwrap()
                                .date_naive();
                            assert_eq!(day, expected, "row in {path:?} is not day-clean");
                        }
                    } else {
                        panic!("expected Int64 statistics for ts column, got {stats:?}");
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Properties 2 & 3: descriptors are paired 1:1 by name with their Parquet
// file, and the descriptor's `partition` field never carries the day.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn conn_records_spanning_midnight_produce_paired_day_clean_descriptors() {
    let parquet_dir = tempfile::tempdir().expect("parquet tempdir");
    let descriptor_dir = tempfile::tempdir().expect("descriptor tempdir");

    let parquet_sink = Arc::new(
        LocalDiskSink::new(parquet_dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new (parquet)"),
    );
    let descriptor_sink: Arc<dyn UploadSink> = Arc::new(
        LocalDiskSink::new(descriptor_dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new (descriptor)"),
    );

    let cfg = ZeekLocalConfig {
        directory: parquet_dir.path().to_path_buf(),
        prefix: "zeek".to_string(),
        max_buffer_rows: 1, // flush immediately on every push
        flush_threshold_bytes: 1,
        flush_interval_secs: 3600,
        channel_capacity: 256,
    };

    let (handler, writer_task) = zeek_local_start(
        &cfg,
        parquet_sink,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        Some(descriptor_sink),
    );

    let src: std::net::SocketAddr = "127.0.0.1:47762".parse().unwrap();
    // Same midnight-straddling pair as the file-count test above.
    handler
        .handle_record(make_conn_record("DDay1", 1700000000.0), src)
        .await;
    handler
        .handle_record(make_conn_record("DDay2", 1700000000.0 + 7200.0), src)
        .await;

    // Drop the handler and wait for the final shutdown flush so both
    // records are guaranteed to have been flushed (and their descriptors
    // uploaded) before we inspect the disk.
    drop(handler);
    tokio::time::timeout(std::time::Duration::from_secs(5), writer_task)
        .await
        .expect("writer task exits within 5s")
        .expect("writer task must not panic");

    let parquet_files = find_parquet_files(&parquet_dir.path().join("zeek/conn"));
    assert_eq!(
        parquet_files.len(),
        2,
        "expected exactly 2 Parquet files (one per day), found {parquet_files:?}"
    );

    for parquet_path in &parquet_files {
        // The day segment this Parquet file lives under (e.g. "day=14").
        let day_component = parquet_path
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert!(
            day_component.starts_with("day="),
            "expected parent dir to be a day= segment, got {day_component:?}"
        );

        // The descriptor must be paired by name: same relative path,
        // `.parquet` swapped for `.json`, under the descriptor sink's root
        // (see `build_descriptor_key`).
        let relative = parquet_path
            .strip_prefix(parquet_dir.path())
            .expect("parquet path is under parquet_dir");
        let descriptor_relative = relative.with_extension("json");
        let descriptor_path = descriptor_dir.path().join(&descriptor_relative);
        assert!(
            descriptor_path.is_file(),
            "expected a paired descriptor at {descriptor_path:?} for Parquet file {parquet_path:?}"
        );

        let descriptor_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&descriptor_path).expect("read descriptor json"),
        )
        .expect("descriptor is valid JSON");

        // Property 3: `partition` is the bare segment "conn" -- never a
        // value carrying the day (e.g. NOT "conn/year=2023/month=11/day=14"
        // and NOT "conn" with any day suffix).
        assert_eq!(
            descriptor_json["partition"], "conn",
            "descriptor partition field must be the bare partition segment, \
             never composed with the day, for {descriptor_path:?}"
        );

        // file_path must reference the exact same relative key (fully
        // qualified with the sink's location hint), proving the pairing is
        // by the correct file, not just "a" file that happens to exist.
        let file_path_field = descriptor_json["file_path"]
            .as_str()
            .expect("file_path is a string");
        assert!(
            file_path_field.ends_with(relative.to_str().unwrap()),
            "descriptor file_path {file_path_field:?} must reference the paired \
             Parquet file's own relative key {relative:?}"
        );

        // Independently decode the descriptor's own raw column-stats bytes
        // for the `ts` column (NOT re-reading the Parquet file's row-group
        // stats a second time -- this proves `build_descriptor` extracted
        // the stats for the SAME row group it just encoded, not a stale or
        // mismatched one) and confirm both min and max fall on the day
        // implied by this file's own directory segment.
        let bytes = std::fs::read(parquet_path).expect("read parquet file");
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .expect("parquet builder");
        let schema = builder.schema().clone();
        let ts_idx = schema
            .fields()
            .iter()
            .position(|f| f.name() == "ts")
            .expect("schema has a ts column");

        let column_stats = descriptor_json["column_stats"][ts_idx.to_string()]
            .as_object()
            .unwrap_or_else(|| panic!("expected column_stats[{ts_idx}] for {descriptor_path:?}"));
        assert_eq!(column_stats["physical_type"], "INT64");

        use base64::Engine;
        use chrono::Datelike as _;
        let expected_day_num: u32 = day_component.strip_prefix("day=").unwrap().parse().unwrap();
        for field in ["min", "max"] {
            let encoded = column_stats[field].as_str().unwrap();
            let raw = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .expect("valid base64");
            let micros = i64::from_le_bytes(raw.try_into().expect("8-byte INT64 stat"));
            let day = chrono::DateTime::from_timestamp_micros(micros)
                .unwrap()
                .date_naive();
            assert_eq!(
                day.day(),
                expected_day_num,
                "descriptor {field} for {descriptor_path:?} does not fall on the \
                 file's own directory day"
            );
            assert_eq!(day.format("%Y-%m").to_string(), "2023-11");
        }
    }
}

// ---------------------------------------------------------------------------
// Property 4: a failed flush's batch returns to its ORIGINAL day's buffer.
// ---------------------------------------------------------------------------

/// Wraps a real `LocalDiskSink` but fails the FIRST upload attempt whose key
/// falls under `day=14`, succeeding on every other call (including any
/// retry of that same day, and every `day=15` upload). Keying the failure
/// off the day segment in the key -- rather than a raw call counter -- makes
/// the test's outcome independent of which of the two concurrently-spawned
/// flushes (day 14's or day 15's) happens to reach `upload()` first.
struct FlakySink {
    inner: LocalDiskSink,
    day14_failed_once: AtomicBool,
}

#[async_trait::async_trait]
impl UploadSink for FlakySink {
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
        if key.contains("day=14") && !self.day14_failed_once.swap(true, Ordering::SeqCst) {
            anyhow::bail!("simulated transient upload failure for day=14 (first attempt only)");
        }
        self.inner.upload(key, body).await
    }

    fn target_label(&self) -> &'static str {
        self.inner.target_label()
    }

    fn location_hint(&self) -> String {
        self.inner.location_hint()
    }
}

#[tokio::test]
async fn failed_flush_for_one_day_retries_into_that_same_day_not_elsewhere() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inner = LocalDiskSink::new(dir.path().to_path_buf())
        .await
        .expect("LocalDiskSink::new");
    let flaky: Arc<dyn UploadSink> = Arc::new(FlakySink {
        inner,
        day14_failed_once: AtomicBool::new(false),
    });

    let cfg = BufferedWriterConfig {
        connection: S3ConnectionConfig {
            endpoint: String::new(),
            bucket: String::new(),
            region: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
        },
        prefix: "zeek".to_string(),
        max_buffer_rows: 1,
        flush_threshold_bytes: 1,
        flush_interval_secs: 900,
        channel_capacity: 64,
        max_partitions: 0,
    };
    let policy = FlushPolicy {
        max_rows: 1,
        max_bytes: 1,
        interval: LiveInterval::new(std::time::Duration::from_secs(900)),
    };

    let (handle, writer_task) = ZeekS3Handler::start_with_stats(
        ZeekSink,
        flaky,
        cfg,
        policy,
        Arc::new(logthing::stats::SourceHourlyStats::new()),
        None,
    );

    // 1700000000 -> 2023-11-14 22:13:20 UTC (this partition/day's flush will
    // fail on its first attempt); +7200s -> 2023-11-15 (this one always
    // succeeds first try).
    handle
        .try_send(make_conn_record("CRetryDay1", 1700000000.0))
        .expect("try_send day1");
    handle
        .try_send(make_conn_record("CDay2Only", 1700000000.0 + 7200.0))
        .expect("try_send day2");

    // Give the writer task's background flush tasks time to run and be
    // reaped (day 14's flush fails and is merged back via
    // `apply_flush_outcome`; day 15's flush succeeds outright).
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Drop the handle to close the channel; the writer's shutdown path
    // performs one final, synchronous `flush_all`, which retries day 14's
    // now-idle buffer (the FlakySink lets it through this time) and would
    // silently produce NO day=14 file at all if `apply_flush_outcome` had
    // merged the failed batch back under the wrong (e.g. current-wall-clock)
    // day instead of its original captured `BufKey`.
    drop(handle);
    tokio::time::timeout(std::time::Duration::from_secs(5), writer_task)
        .await
        .expect("writer task exits within 5s")
        .expect("writer task must not panic");

    let day1_dir = dir.path().join("zeek/conn/year=2023/month=11/day=14");
    let day2_dir = dir.path().join("zeek/conn/year=2023/month=11/day=15");
    assert!(
        day1_dir.is_dir(),
        "expected {day1_dir:?} to exist -- the failed flush's batch must have \
         been retried back into its ORIGINAL day's buffer, not lost or \
         merged into a different day"
    );
    assert!(day2_dir.is_dir(), "expected {day2_dir:?} to exist");

    use arrow::array::StringArray;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let read_uids = |file_dir: &std::path::Path| -> Vec<String> {
        let files: Vec<_> = std::fs::read_dir(file_dir).unwrap().collect();
        assert_eq!(
            files.len(),
            1,
            "expected exactly one file under {file_dir:?}"
        );
        let path = files.into_iter().next().unwrap().unwrap().path();
        let bytes = std::fs::read(&path).unwrap();
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes)).unwrap();
        let mut uids = Vec::new();
        for rb in builder.build().unwrap() {
            let rb = rb.unwrap();
            let col = rb
                .column_by_name("uid")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..rb.num_rows() {
                uids.push(col.value(i).to_string());
            }
        }
        uids
    };

    assert_eq!(
        read_uids(&day1_dir),
        vec!["CRetryDay1".to_string()],
        "day=14's file must contain exactly the record that originally \
         belonged to day 14, surviving the failed-then-retried flush"
    );
    assert_eq!(
        read_uids(&day2_dir),
        vec!["CDay2Only".to_string()],
        "day=15's file must be unaffected by day 14's failure/retry -- no \
         cross-day contamination"
    );
}
