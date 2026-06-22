//! Zeek → S3 Parquet persistence.
//!
//! `ZeekS3Writer` maintains a per-`log_path` buffer of Arrow RecordBatches,
//! each keyed by the stream's schema (typed or envelope fallback from the registry).
//! It mirrors the hardened `IpfixS3Writer` pattern:
//! - `VecDeque<BufferedBatch>` per stream with `flush_then_cap` / `drop_oldest_to_cap`.
//! - S3 key pattern: `{prefix}/{log_path}/year={Y}/month={MM}/day={DD}/{uuid}.parquet`.
//! - Bounded `mpsc` channel in `ZeekS3Handler`; overflow drops + `zeek_s3_dropped`.

use crate::forwarding::s3_sink::{S3Sink, flush_check_interval};
use crate::zeek::ZeekRecord;
use crate::zeek::schema::get_schema_entry;
use arrow::datatypes::Schema;
use arrow::record_batch::RecordBatch;
use chrono::{Datelike, Utc};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::warn;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Writer configuration (derived from `ZeekS3Config`).
pub struct ZeekS3WriterConfig {
    pub flush_threshold_bytes: usize,
    pub flush_interval: Duration,
    pub key_prefix: String,
    pub max_buffer_rows: usize,
}

impl ZeekS3WriterConfig {
    pub fn hard_cap_rows(&self) -> usize {
        self.max_buffer_rows.saturating_mul(4)
    }
}

impl Default for ZeekS3WriterConfig {
    fn default() -> Self {
        Self {
            flush_threshold_bytes: 100 * 1024 * 1024,
            flush_interval: Duration::from_secs(900),
            key_prefix: "zeek".to_string(),
            max_buffer_rows: 100_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-stream buffer
// ---------------------------------------------------------------------------

struct BufferedBatch {
    batch: RecordBatch,
    est_bytes: usize,
}

struct StreamBuffer {
    schema: Arc<Schema>,
    buffer: VecDeque<BufferedBatch>,
    buffer_row_count: usize,
    buffered_bytes: usize,
    last_flush: Instant,
    last_drop_warn: Option<Instant>,
}

impl StreamBuffer {
    fn new(schema: Arc<Schema>) -> Self {
        Self {
            schema,
            buffer: VecDeque::new(),
            buffer_row_count: 0,
            buffered_bytes: 0,
            last_flush: Instant::now(),
            last_drop_warn: None,
        }
    }

    fn push(&mut self, batch: RecordBatch, est_bytes: usize) {
        self.buffer_row_count += batch.num_rows();
        self.buffered_bytes += est_bytes;
        self.buffer.push_back(BufferedBatch { batch, est_bytes });
    }

    fn drop_oldest_to_cap(&mut self, cap: usize) {
        let mut dropped_rows: usize = 0;
        while self.buffer_row_count > cap {
            if self.buffer.is_empty() {
                break;
            }
            let oldest = self.buffer.pop_front().expect("non-empty");
            let n = oldest.batch.num_rows();
            self.buffer_row_count = self.buffer_row_count.saturating_sub(n);
            self.buffered_bytes = self.buffered_bytes.saturating_sub(oldest.est_bytes);
            dropped_rows += n;
        }
        if dropped_rows > 0 {
            metrics::counter!("zeek_s3_buffer_dropped").increment(dropped_rows as u64);
            let should_warn = self
                .last_drop_warn
                .map(|t| t.elapsed().as_secs() >= 30)
                .unwrap_or(true);
            if should_warn {
                warn!(
                    dropped_rows,
                    buffer_row_count = self.buffer_row_count,
                    "ZeekS3Writer: S3 upload failing — dropped oldest rows to stay within hard cap"
                );
                self.last_drop_warn = Some(Instant::now());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// S3 key builder
// ---------------------------------------------------------------------------

pub(crate) fn build_zeek_s3_key(
    prefix: &str,
    log_path: &str,
    now: chrono::DateTime<Utc>,
) -> String {
    let id = uuid::Uuid::new_v4();
    format!(
        "{}/{}/year={}/month={:02}/day={:02}/{}.parquet",
        prefix,
        log_path,
        now.year(),
        now.month(),
        now.day(),
        id,
    )
}

// ---------------------------------------------------------------------------
// Parquet encoding (accepts any schema)
// ---------------------------------------------------------------------------

fn encode_batches(batches: &[RecordBatch], schema: Arc<Schema>) -> anyhow::Result<Vec<u8>> {
    if batches.is_empty() {
        return Ok(Vec::new());
    }
    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
        .build();
    let mut buf = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut buf, schema, Some(props))?;
    for batch in batches {
        writer.write(batch)?;
    }
    writer.close()?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// ZeekS3Writer
// ---------------------------------------------------------------------------

/// Buffers `ZeekRecord`s per stream as Arrow RecordBatches and flushes to S3.
pub struct ZeekS3Writer {
    config: ZeekS3WriterConfig,
    sink: Arc<S3Sink>,
    streams: HashMap<String, StreamBuffer>,
}

impl ZeekS3Writer {
    pub fn new(config: ZeekS3WriterConfig, sink: Arc<S3Sink>) -> Self {
        Self {
            config,
            sink,
            streams: HashMap::new(),
        }
    }

    /// Push one ZeekRecord: map to RecordBatch, append to per-stream buffer, flush if needed.
    pub async fn push_record(&mut self, record: &ZeekRecord) -> anyhow::Result<()> {
        let entry = get_schema_entry(&record.log_path);
        let batch = match (entry.mapper)(&record.fields) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "ZeekS3Writer: row mapper error for '{}': {e}",
                    record.log_path
                );
                return Ok(()); // Never drop the connection; just skip this record
            }
        };

        let est_bytes = record.fields.to_string().len() + 128;
        let log_path = record.log_path.clone();
        let stream = self
            .streams
            .entry(log_path.clone())
            .or_insert_with(|| StreamBuffer::new(entry.schema.clone()));

        stream.push(batch, est_bytes);

        if stream.buffered_bytes >= self.config.flush_threshold_bytes {
            let cap = self.config.hard_cap_rows();
            if let Err(e) = self.flush_stream(&log_path).await {
                if let Some(s) = self
                    .streams
                    .get_mut(&log_path)
                    .filter(|s| s.buffer_row_count > cap)
                {
                    s.drop_oldest_to_cap(cap);
                }
                return Err(e);
            }
        }
        Ok(())
    }

    /// Flush all streams whose age or byte threshold is exceeded.
    pub async fn flush_all_if_needed(&mut self) -> anyhow::Result<()> {
        let keys: Vec<String> = self.streams.keys().cloned().collect();
        for key in keys {
            let should_flush = {
                let s = &self.streams[&key];
                !s.buffer.is_empty()
                    && (s.last_flush.elapsed() >= self.config.flush_interval
                        || s.buffered_bytes >= self.config.flush_threshold_bytes)
            };
            if should_flush {
                let flush_result = self.flush_stream(&key).await;
                if let Err(e) = flush_result {
                    warn!("ZeekS3Writer: flush_all_if_needed error for '{key}': {e}");
                }
            }
        }
        Ok(())
    }

    /// Unconditionally flush all streams.
    pub async fn flush_all(&mut self) -> anyhow::Result<()> {
        let keys: Vec<String> = self.streams.keys().cloned().collect();
        for key in keys {
            if let Err(e) = self.flush_stream(&key).await {
                warn!("ZeekS3Writer: flush_all error for '{key}': {e}");
            }
        }
        Ok(())
    }

    async fn flush_stream(&mut self, log_path: &str) -> anyhow::Result<()> {
        let stream = match self.streams.get_mut(log_path) {
            Some(s) if !s.buffer.is_empty() => s,
            _ => return Ok(()),
        };

        let batches: Vec<RecordBatch> = stream.buffer.iter().map(|b| b.batch.clone()).collect();
        let row_count = stream.buffer_row_count;
        let schema = stream.schema.clone();
        let bytes = encode_batches(&batches, schema)?;
        let key = build_zeek_s3_key(&self.config.key_prefix, log_path, Utc::now());

        match self.sink.upload(&key, bytes).await {
            Ok(()) => {
                metrics::counter!("zeek_s3_records_written").increment(row_count as u64);
                metrics::counter!("zeek_s3_uploads").increment(1);
                let stream = self.streams.get_mut(log_path).unwrap();
                stream.buffer.clear();
                stream.buffer_row_count = 0;
                stream.buffered_bytes = 0;
                stream.last_flush = Instant::now();
                Ok(())
            }
            Err(e) => {
                metrics::counter!("zeek_s3_upload_errors").increment(1);
                Err(e)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn stream_row_count(&self, log_path: &str) -> usize {
        self.streams
            .get(log_path)
            .map(|s| s.buffer_row_count)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// ZeekS3Handler — channel + background writer
// ---------------------------------------------------------------------------

pub const ZEEK_S3_CHANNEL_CAPACITY: usize = 256;

/// `ZeekHandler` implementation that forwards records via a bounded channel to a
/// background `ZeekS3Writer` task.
pub struct ZeekS3Handler {
    sender: mpsc::Sender<ZeekRecord>,
}

impl ZeekS3Handler {
    pub fn start(config: ZeekS3WriterConfig, sink: Arc<S3Sink>) -> Self {
        Self::start_with_capacity(config, sink, ZEEK_S3_CHANNEL_CAPACITY)
    }

    pub fn start_with_capacity(
        config: ZeekS3WriterConfig,
        sink: Arc<S3Sink>,
        capacity: usize,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<ZeekRecord>(capacity);
        let flush_check = flush_check_interval(config.flush_interval);
        tokio::spawn(async move {
            let mut writer = ZeekS3Writer::new(config, sink);
            let mut interval = tokio::time::interval(flush_check);
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(record) => {
                                if let Err(e) = writer.push_record(&record).await {
                                    warn!("ZeekS3Writer::push_record error: {e}");
                                }
                            }
                            None => {
                                if let Err(e) = writer.flush_all().await {
                                    warn!("ZeekS3Writer::flush_all on shutdown: {e}");
                                }
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        if let Err(e) = writer.flush_all_if_needed().await {
                            warn!("ZeekS3Writer::flush_all_if_needed error: {e}");
                        }
                    }
                }
            }
        });
        Self { sender: tx }
    }
}

#[async_trait::async_trait]
impl crate::zeek::listener::ZeekHandler for ZeekS3Handler {
    async fn handle_record(&self, record: ZeekRecord, source: std::net::SocketAddr) {
        match self.sender.try_send(record) {
            Ok(()) => {}
            Err(_dropped) => {
                metrics::counter!("zeek_s3_dropped").increment(1);
                warn!("Zeek S3 channel full; dropped 1 record from {}", source);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zeek::ZeekRecord;
    use chrono::Utc;

    async fn unreachable_sink() -> Arc<S3Sink> {
        use crate::config::S3ConnectionConfig;
        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "AKIATEST".to_string(),
            secret_key: "SECRETTEST".to_string(),
        };
        Arc::new(S3Sink::from_connection(&conn).await.expect("constructs"))
    }

    fn make_conn_record(uid: &str) -> ZeekRecord {
        ZeekRecord {
            log_path: "conn".to_string(),
            fields: serde_json::json!({
                "_path": "conn",
                "ts": 1700000000.0,
                "uid": uid,
                "id.orig_h": "10.0.0.1",
                "id.orig_p": 12345,
                "id.resp_h": "10.0.0.2",
                "id.resp_p": 80,
                "proto": "tcp",
                "conn_state": "SF",
                "orig_bytes": 512,
                "resp_bytes": 4096,
            }),
            received_at: Utc::now(),
        }
    }

    fn make_dns_record(uid: &str) -> ZeekRecord {
        ZeekRecord {
            log_path: "dns".to_string(),
            fields: serde_json::json!({
                "_path": "dns",
                "ts": 1700000100.0,
                "uid": uid,
                "id.orig_h": "192.168.1.100",
                "id.orig_p": 12345,
                "id.resp_h": "8.8.8.8",
                "id.resp_p": 53,
                "query": "example.com",
                "qtype_name": "A",
                "rcode_name": "NOERROR",
            }),
            received_at: Utc::now(),
        }
    }

    fn make_unknown_record() -> ZeekRecord {
        ZeekRecord {
            log_path: "unknown".to_string(),
            fields: serde_json::json!({
                "_path": "unknown",
                "ts": 1700000200.0,
                "uid": "CUnk1",
                "raw_data": "some weird log"
            }),
            received_at: Utc::now(),
        }
    }

    // -- S3 key structure --

    #[test]
    fn zeek_s3_key_has_correct_structure() {
        let now = chrono::DateTime::from_timestamp(1700000000, 0).unwrap();
        let key = build_zeek_s3_key("zeek", "conn", now);
        assert!(key.starts_with("zeek/conn/year="), "key: {key}");
        assert!(key.contains("/month="), "key: {key}");
        assert!(key.contains("/day="), "key: {key}");
        assert!(key.ends_with(".parquet"), "key: {key}");
    }

    // -- Writer accumulates per-stream --

    #[tokio::test]
    async fn writer_accumulates_per_stream_buffers() {
        let sink = unreachable_sink().await;
        let config = ZeekS3WriterConfig {
            flush_threshold_bytes: usize::MAX, // never flush by size
            flush_interval: Duration::from_secs(3600),
            key_prefix: "zeek".to_string(),
            max_buffer_rows: 100_000,
        };
        let mut writer = ZeekS3Writer::new(config, sink);

        writer.push_record(&make_conn_record("C1")).await.ok();
        writer.push_record(&make_conn_record("C2")).await.ok();
        writer.push_record(&make_dns_record("D1")).await.ok();
        writer.push_record(&make_unknown_record()).await.ok();

        assert_eq!(
            writer.stream_row_count("conn"),
            2,
            "conn buffer should have 2 rows"
        );
        assert_eq!(
            writer.stream_row_count("dns"),
            1,
            "dns buffer should have 1 row"
        );
        assert_eq!(
            writer.stream_row_count("unknown"),
            1,
            "unknown buffer should have 1 row"
        );
    }

    // -- Writer bounded under S3 outage --

    #[tokio::test]
    async fn writer_bounded_under_s3_outage() {
        let sink = unreachable_sink().await;
        let max_rows = 2usize;
        let config = ZeekS3WriterConfig {
            flush_threshold_bytes: 1, // force flush on every push
            flush_interval: Duration::from_secs(3600),
            key_prefix: "zeek".to_string(),
            max_buffer_rows: max_rows,
        };
        let hard_cap = config.hard_cap_rows();
        let mut writer = ZeekS3Writer::new(config, sink);

        let total = hard_cap * 3;
        let mut errors = 0usize;
        for i in 0..total {
            let rec = make_conn_record(&format!("C{i}"));
            if writer.push_record(&rec).await.is_err() {
                errors += 1;
            }
        }
        assert!(errors > 0, "expected flush errors under S3 outage");
        assert!(
            writer.stream_row_count("conn") <= hard_cap,
            "conn buffer must stay at or below hard cap ({hard_cap}), got {}",
            writer.stream_row_count("conn")
        );
    }

    // -- Handler overflow drops and counts --

    #[tokio::test]
    async fn handler_overflow_increments_dropped_counter() {
        use crate::zeek::listener::ZeekHandler;
        use metrics::set_default_local_recorder;
        use metrics_util::CompositeKey;
        use metrics_util::MetricKind;
        use metrics_util::debugging::DebuggingRecorder;
        use std::net::SocketAddr;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let sink = unreachable_sink().await;
        let config = ZeekS3WriterConfig {
            flush_threshold_bytes: 1,
            flush_interval: Duration::from_secs(3600),
            key_prefix: "zeek".to_string(),
            max_buffer_rows: 1,
        };
        let handler = ZeekS3Handler::start_with_capacity(config, sink, 1);
        tokio::task::yield_now().await;

        let src: SocketAddr = "127.0.0.1:47760".parse().unwrap();
        for i in 0..50usize {
            let rec = make_conn_record(&format!("C{i}"));
            handler.handle_record(rec, src).await;
        }
        tokio::task::yield_now().await;

        let snapshot = snapshotter.snapshot();
        let map = snapshot.into_hashmap();
        let key = CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_name("zeek_s3_dropped"),
        );
        let dropped = map
            .get(&key)
            .map(|(_, _, v)| {
                if let metrics_util::debugging::DebugValue::Counter(c) = v {
                    *c
                } else {
                    0
                }
            })
            .unwrap_or(0);
        assert!(dropped >= 1, "expected zeek_s3_dropped >= 1; got {dropped}");
    }

    // -- Integration test (gated on env var) --

    #[tokio::test]
    async fn integration_records_produce_parquet_in_s3() {
        if std::env::var("ZEEK_S3_INTEGRATION_TEST").is_err() {
            eprintln!("skipping; set ZEEK_S3_INTEGRATION_TEST=1 to run against local MinIO");
            return;
        }
        use crate::config::S3ConnectionConfig;
        use crate::zeek::listener::ZeekHandler;

        let bucket = std::env::var("ZEEK_S3_BUCKET").unwrap_or_else(|_| "zeek-test".to_string());
        let conn = S3ConnectionConfig {
            endpoint: "http://localhost:9000".to_string(),
            bucket: bucket.clone(),
            region: "us-east-1".to_string(),
            access_key: "minioadmin".to_string(),
            secret_key: "minioadmin".to_string(),
        };
        let sink = Arc::new(
            S3Sink::from_connection(&conn)
                .await
                .expect("S3Sink construct"),
        );
        let config = ZeekS3WriterConfig {
            flush_threshold_bytes: 1,
            flush_interval: Duration::from_secs(1),
            key_prefix: "zeek".to_string(),
            max_buffer_rows: 100_000,
        };
        let handler = ZeekS3Handler::start(config, sink);
        let src: std::net::SocketAddr = "127.0.0.1:47760".parse().unwrap();

        for i in 0..5usize {
            handler
                .handle_record(make_conn_record(&format!("CInteg{i}")), src)
                .await;
        }
        for i in 0..3usize {
            handler
                .handle_record(make_dns_record(&format!("DInteg{i}")), src)
                .await;
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        use aws_config::meta::region::RegionProviderChain;
        use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
        use aws_sdk_s3::Client as S3Client;
        use aws_sdk_s3::config::Builder as S3ConfigBuilder;

        let region = RegionProviderChain::first_try(aws_sdk_s3::config::Region::new(
            "us-east-1".to_string(),
        ));
        let sdk_cfg = aws_config::from_env()
            .region(region)
            .endpoint_url("http://localhost:9000")
            .load()
            .await;
        let creds = SharedCredentialsProvider::new(Credentials::new(
            "minioadmin",
            "minioadmin",
            None,
            None,
            "test",
        ));
        let s3_cfg = S3ConfigBuilder::from(&sdk_cfg)
            .credentials_provider(creds)
            .force_path_style(true)
            .build();
        let client = S3Client::from_conf(s3_cfg);

        for prefix in &["zeek/conn/", "zeek/dns/"] {
            let resp = client
                .list_objects_v2()
                .bucket(&bucket)
                .prefix(*prefix)
                .send()
                .await
                .expect("list_objects_v2");
            assert!(
                !resp.contents().is_empty(),
                "expected >= 1 Parquet object under {prefix}"
            );
        }
    }
}
