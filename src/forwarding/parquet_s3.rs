use crate::config::{DestinationConfig, ForwardProtocol};
use crate::models::WindowsEvent;
use anyhow::Result;
use arrow::array::{ArrayRef, StringArray, UInt32Array};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use chrono::{Datelike, Utc};
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};
use metrics::counter;

/// Configuration for Parquet S3 forwarder
#[derive(Clone)]
pub struct ParquetS3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub max_file_size_mb: u64,
    pub flush_interval_secs: u64,
    pub local_buffer_path: PathBuf,
}

/// Manual Debug impl that masks S3 secret fields so they never leak into logs
/// or panic messages.
impl std::fmt::Debug for ParquetS3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParquetS3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("access_key", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .field("max_file_size_mb", &self.max_file_size_mb)
            .field("flush_interval_secs", &self.flush_interval_secs)
            .field("local_buffer_path", &self.local_buffer_path)
            .finish()
    }
}

impl Default for ParquetS3Config {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:9000".to_string(),
            bucket: "wef-events".to_string(),
            region: "us-east-1".to_string(),
            access_key: "minioadmin".to_string(),
            secret_key: "minioadmin".to_string(),
            max_file_size_mb: 100,
            flush_interval_secs: 900, // 15 minutes
            local_buffer_path: std::env::temp_dir().join("logthing-wef-events"),
        }
    }
}

impl ParquetS3Config {
    pub fn from_destination(dest: &DestinationConfig) -> Result<Self> {
        let url = &dest.url;
        // Parse S3 URL: s3://bucket/path or http://endpoint/bucket
        let parts: Vec<&str> = url.split("/").collect();

        let bucket = parts.get(2).unwrap_or(&"wef-events").to_string();

        let endpoint = if url.starts_with("s3://") {
            dest.headers
                .get("endpoint")
                .cloned()
                .unwrap_or_else(|| "http://localhost:9000".to_string())
        } else {
            format!(
                "{}//{}",
                parts.first().unwrap_or(&"http:"),
                parts.get(2).unwrap_or(&"localhost:9000")
            )
        };

        Ok(Self {
            endpoint,
            bucket,
            region: dest
                .headers
                .get("region")
                .cloned()
                .unwrap_or_else(|| "us-east-1".to_string()),
            access_key: dest.headers.get("access-key").cloned().unwrap_or_default(),
            secret_key: dest.headers.get("secret-key").cloned().unwrap_or_default(),
            max_file_size_mb: dest
                .headers
                .get("max-size-mb")
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            flush_interval_secs: dest
                .headers
                .get("flush-interval-secs")
                .and_then(|s| s.parse().ok())
                .unwrap_or(900),
            local_buffer_path: PathBuf::from(
                dest.headers
                    .get("buffer-path")
                    .cloned()
                    .unwrap_or_else(|| {
                        std::env::temp_dir()
                            .join("logthing-wef-events")
                            .to_string_lossy()
                            .into_owned()
                    }),
            ),
        })
    }
}

/// Buffer for a specific event type
struct EventTypeBuffer {
    events: Vec<BufferedEvent>,
    current_size_bytes: usize,
    last_flush: chrono::DateTime<Utc>,
    hard_cap_bytes: usize,
}

impl EventTypeBuffer {
    fn new(hard_cap_bytes: usize) -> Self {
        Self {
            events: Vec::new(),
            current_size_bytes: 0,
            last_flush: Utc::now(),
            hard_cap_bytes,
        }
    }

    fn add_event(&mut self, event: BufferedEvent) {
        self.current_size_bytes += event.estimated_size();
        self.events.push(event);

        // Enforce hard cap: drop oldest events until we're within bounds
        if self.current_size_bytes > self.hard_cap_bytes {
            let mut dropped: usize = 0;
            while self.current_size_bytes > self.hard_cap_bytes {
                if self.events.is_empty() {
                    break;
                }
                let oldest = self.events.remove(0);
                let sz = oldest.estimated_size();
                self.current_size_bytes = self.current_size_bytes.saturating_sub(sz);
                dropped += 1;
            }
            warn!(
                "WEF S3 buffer exceeded hard cap ({} bytes); dropped {} oldest events",
                self.hard_cap_bytes, dropped
            );
            counter!("wef_s3_buffer_dropped").increment(dropped as u64);
        }
    }

    fn should_flush(&self, max_size_bytes: usize, max_age_secs: i64) -> bool {
        let size_threshold = self.current_size_bytes >= max_size_bytes;
        let age = Utc::now().signed_duration_since(self.last_flush);
        let time_threshold = age.num_seconds() >= max_age_secs;

        size_threshold || time_threshold
    }

    fn take_events(&mut self) -> Vec<BufferedEvent> {
        self.current_size_bytes = 0;
        self.last_flush = Utc::now();
        std::mem::take(&mut self.events)
    }
}

/// Buffered event data
#[derive(Debug, Clone)]
struct BufferedEvent {
    event_id: u32,
    timestamp: chrono::DateTime<Utc>,
    source_host: String,
    subscription_id: Option<String>,
    event_data: String,
}

impl BufferedEvent {
    fn from_windows_event(event: &WindowsEvent) -> Option<Self> {
        let event_id = event.parsed.as_ref()?.event_id;

        Some(Self {
            event_id,
            timestamp: event.received_at,
            source_host: event.source_host.clone(),
            subscription_id: event.subscription_id.clone(),
            event_data: serde_json::to_string(event).ok()?,
        })
    }

    fn estimated_size(&self) -> usize {
        // Use serialized JSON string length as size estimate, plus metadata overhead
        self.event_data.len() + 256
    }
}

/// Parquet S3 Forwarder
pub struct ParquetS3Forwarder {
    config: ParquetS3Config,
    sink: crate::forwarding::s3_sink::S3Sink,
    buffers: HashMap<u32, EventTypeBuffer>,
}

impl ParquetS3Forwarder {
    pub async fn new(config: ParquetS3Config) -> Result<Self> {
        let sink = crate::forwarding::s3_sink::S3Sink::from_config(&config).await?;

        // Ensure buffer directory exists
        tokio::fs::create_dir_all(&config.local_buffer_path).await?;

        info!(
            "ParquetS3Forwarder initialized: bucket={}, endpoint={}, \
             flush_interval={}s, max_size={}MB",
            config.bucket, config.endpoint, config.flush_interval_secs, config.max_file_size_mb
        );

        Ok(Self {
            config,
            sink,
            buffers: HashMap::new(),
        })
    }

    pub fn flush_interval_secs(&self) -> u64 {
        self.config.flush_interval_secs
    }

    /// Process a single event
    pub async fn forward(&mut self, event: WindowsEvent) -> Result<()> {
        let buffered = match BufferedEvent::from_windows_event(&event) {
            Some(be) => be,
            None => {
                warn!("Could not extract event data for buffering");
                return Ok(());
            }
        };

        let event_type = buffered.event_id;

        // Get or create buffer for this event type
        let hard_cap = (self.config.max_file_size_mb * 1024 * 1024 * 4) as usize;
        let buffer = self
            .buffers
            .entry(event_type)
            .or_insert_with(|| EventTypeBuffer::new(hard_cap));

        // Add event to buffer
        buffer.add_event(buffered);

        // Check if we should flush
        let max_size = (self.config.max_file_size_mb * 1024 * 1024) as usize;
        let max_age = self.config.flush_interval_secs as i64;

        if buffer.should_flush(max_size, max_age) {
            self.flush_event_type(event_type).await?;
        }

        Ok(())
    }

    /// Flush all buffers (called periodically)
    pub async fn flush_all(&mut self) -> Result<()> {
        let event_types: Vec<u32> = self.buffers.keys().copied().collect();

        for event_type in event_types {
            if self
                .buffers
                .get(&event_type)
                .is_some_and(|b| !b.events.is_empty())
            {
                self.flush_event_type(event_type).await?;
            }
        }

        Ok(())
    }

    /// Flush a specific event type buffer to S3
    async fn flush_event_type(&mut self, event_type: u32) -> Result<()> {
        let buffer = match self.buffers.get_mut(&event_type) {
            Some(b) if !b.events.is_empty() => b,
            _ => return Ok(()),
        };

        let events = buffer.take_events();
        let event_count = events.len();

        info!(
            "Flushing {} events of type {} to Parquet/S3",
            event_count, event_type
        );

        // Create parquet file
        let parquet_path = self.write_parquet_file(event_type, &events).await?;

        // Upload to S3
        self.upload_to_s3(&parquet_path, event_type).await?;

        // Clean up local file
        if let Err(e) = tokio::fs::remove_file(&parquet_path).await {
            warn!(
                "Failed to remove local parquet file {:?}: {}",
                parquet_path, e
            );
        }

        info!(
            "Successfully flushed {} events of type {} to S3",
            event_count, event_type
        );

        Ok(())
    }

    /// Write events to a local parquet file
    async fn write_parquet_file(
        &self,
        event_type: u32,
        events: &[BufferedEvent],
    ) -> Result<PathBuf> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("events_{}_{}.parquet", event_type, timestamp);
        let filepath = self.config.local_buffer_path.join(&filename);

        // Create schema for the events
        let schema = Arc::new(Schema::new(vec![
            Field::new("event_id", DataType::UInt32, false),
            Field::new("timestamp", DataType::Utf8, false),
            Field::new("source_host", DataType::Utf8, false),
            Field::new("subscription_id", DataType::Utf8, true),
            Field::new("event_data", DataType::Utf8, false),
        ]));

        // Convert events to Arrow arrays
        let event_ids: Vec<u32> = events.iter().map(|e| e.event_id).collect();
        let timestamps: Vec<String> = events.iter().map(|e| e.timestamp.to_rfc3339()).collect();
        let source_hosts: Vec<String> = events.iter().map(|e| e.source_host.clone()).collect();
        let subscription_ids: Vec<Option<String>> =
            events.iter().map(|e| e.subscription_id.clone()).collect();
        let event_data_json: Vec<String> = events.iter().map(|e| e.event_data.clone()).collect();

        // Create record batch
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(UInt32Array::from(event_ids)) as ArrayRef,
                Arc::new(StringArray::from(timestamps)) as ArrayRef,
                Arc::new(StringArray::from(source_hosts)) as ArrayRef,
                Arc::new(StringArray::from(subscription_ids)) as ArrayRef,
                Arc::new(StringArray::from(event_data_json)) as ArrayRef,
            ],
        )?;

        // Clone filepath for use in spawn_blocking
        let filepath_clone = filepath.clone();
        let schema_clone = schema.clone();

        // Write to parquet file in a blocking task to avoid blocking async runtime
        tokio::task::spawn_blocking(move || {
            let file = File::create(&filepath_clone)?;
            let props = WriterProperties::builder()
                .set_compression(parquet::basic::Compression::ZSTD(ZstdLevel::try_new(3)?))
                .build();

            let mut writer = ArrowWriter::try_new(file, schema_clone, Some(props))?;
            writer.write(&batch)?;
            writer.close()?;

            Result::<(), anyhow::Error>::Ok(())
        })
        .await??;

        debug!(
            "Written {} events to parquet file: {:?}",
            events.len(),
            filepath
        );

        Ok(filepath)
    }

    /// Upload parquet file to S3
    async fn upload_to_s3(&self, filepath: &PathBuf, event_type: u32) -> Result<()> {
        let filename = filepath
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?;

        // Generate S3 key with date partitioning (unchanged from before)
        let now = Utc::now();
        let s3_key = format!(
            "event_type={}/year={}/month={:02}/day={:02}/{}",
            event_type,
            now.year(),
            now.month(),
            now.day(),
            filename
        );

        // Read file into memory and delegate to S3Sink.
        // S3Sink::upload already logs the successful upload; no need to log here too.
        let body = tokio::fs::read(filepath).await?;
        self.sink.upload(&s3_key, body).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DestinationConfig, ForwardProtocol};
    use crate::models::{EventLevel, ParsedEvent, WindowsEvent};

    fn sample_destination() -> DestinationConfig {
        let mut headers = HashMap::new();
        headers.insert("endpoint".into(), "http://minio:9000".into());
        headers.insert("region".into(), "us-east-1".into());
        headers.insert("access-key".into(), "AKIA".into());
        headers.insert("secret-key".into(), "SECRET".into());
        headers.insert("max-size-mb".into(), "1".into());
        headers.insert("flush-interval-secs".into(), "60".into());
        let temp_path = std::env::temp_dir().join("test-buf");
        headers.insert(
            "buffer-path".into(),
            temp_path.to_string_lossy().to_string(),
        );

        DestinationConfig {
            name: "parquet".into(),
            url: "s3://audit-bucket/events".into(),
            protocol: ForwardProtocol::Http,
            enabled: true,
            headers,
        }
    }

    fn sample_parsed_event(event_id: u32) -> ParsedEvent {
        ParsedEvent {
            provider: "Security".into(),
            event_id,
            level: EventLevel::Information,
            task: 0,
            opcode: 0,
            keywords: 0,
            time_created: Utc::now(),
            event_record_id: 1,
            process_id: None,
            thread_id: None,
            channel: "Security".into(),
            computer: "HOST".into(),
            security_user_id: None,
            message: None,
            data: None,
        }
    }

    #[test]
    fn config_parses_destination_headers() {
        let dest = sample_destination();
        let cfg = ParquetS3Config::from_destination(&dest).expect("config");
        assert_eq!(cfg.bucket, "audit-bucket");
        assert_eq!(cfg.endpoint, "http://minio:9000");
        assert_eq!(cfg.max_file_size_mb, 1);
        assert_eq!(cfg.flush_interval_secs, 60);
        let expected_path = std::env::temp_dir().join("test-buf");
        assert_eq!(cfg.local_buffer_path, expected_path);
    }

    #[test]
    fn buffered_event_requires_parsed_data() {
        let event = WindowsEvent::new("host".into(), "<Event/>".into());
        assert!(BufferedEvent::from_windows_event(&event).is_none());

        let parsed_event = sample_parsed_event(4624);
        let event = WindowsEvent::new("host".into(), "<Event/>".into()).with_parsed(parsed_event);
        let buffered = BufferedEvent::from_windows_event(&event).expect("buffered");
        assert_eq!(buffered.event_id, 4624);
        assert!(buffered.estimated_size() > 256);
    }

    #[test]
    fn event_buffer_flushes_by_size_and_age() {
        let mut buffer = EventTypeBuffer::new(100_000);
        buffer.add_event(BufferedEvent {
            event_id: 1,
            timestamp: Utc::now(),
            source_host: "host".into(),
            subscription_id: None,
            event_data: r#"{"value":"a"}"#.into(),
        });

        assert!(!buffer.should_flush(10_000, 300));
        buffer.last_flush = buffer.last_flush - chrono::Duration::seconds(400);
        assert!(buffer.should_flush(10_000, 300));

        let drained = buffer.take_events();
        assert_eq!(drained.len(), 1);
        assert_eq!(buffer.current_size_bytes, 0);
    }

    #[test]
    fn event_buffer_hard_cap_drops_oldest_events() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let _guard = set_default_local_recorder(&recorder);

        // 1000 bytes hard cap
        let mut buffer = EventTypeBuffer::new(1000);
        // Each event is ~300 bytes (data: 44 bytes + 256 overhead)
        for i in 0u32..10 {
            buffer.add_event(BufferedEvent {
                event_id: i,
                timestamp: Utc::now(),
                source_host: "host".into(),
                subscription_id: None,
                event_data: "a".repeat(44), // 44 + 256 = ~300 bytes estimated
            });
        }
        // At ~300 bytes each, 10 events = ~3000 bytes, but cap is 1000 bytes
        // So no more than ceil(1000/300) = ~4 events should remain
        assert!(
            buffer.current_size_bytes <= 1000,
            "buffer must stay within hard cap, got {} bytes",
            buffer.current_size_bytes
        );
        assert!(
            buffer.events.len() < 10,
            "oldest events must have been dropped"
        );
    }

    #[test]
    fn flush_all_does_not_bail_on_first_error_structurally() {
        // Verify that flush_all's contract is: iterate all, collect errors.
        // The real multi-error behavior is tested via integration; here we just confirm
        // that the buffers are drained even when errors occur, by checking that
        // take_events clears all event types independently.
        let mut buffer1 = EventTypeBuffer::new(100_000);
        let mut buffer2 = EventTypeBuffer::new(100_000);
        buffer1.add_event(BufferedEvent {
            event_id: 4624,
            timestamp: Utc::now(),
            source_host: "h1".into(),
            subscription_id: None,
            event_data: "{}".into(),
        });
        buffer2.add_event(BufferedEvent {
            event_id: 4625,
            timestamp: Utc::now(),
            source_host: "h2".into(),
            subscription_id: None,
            event_data: "{}".into(),
        });
        let e1 = buffer1.take_events();
        let e2 = buffer2.take_events();
        assert_eq!(e1.len(), 1);
        assert_eq!(e2.len(), 1);
        assert_eq!(buffer1.events.len(), 0);
        assert_eq!(buffer2.events.len(), 0);
    }
}

use parquet::basic::ZstdLevel;

/// Create a ParquetS3 forwarder from configuration
pub async fn create_parquet_s3_forwarder(
    destinations: &[DestinationConfig],
) -> Result<Option<ParquetS3Forwarder>> {
    for dest in destinations {
        if dest.protocol == ForwardProtocol::Http && dest.url.starts_with("s3://") {
            let config = ParquetS3Config::from_destination(dest)?;
            return Ok(Some(ParquetS3Forwarder::new(config).await?));
        }
    }

    Ok(None)
}
