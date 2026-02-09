use crate::config::{DestinationConfig, ForwardProtocol};
use crate::models::WindowsEvent;
use anyhow::Result;
use arrow::array::{ArrayRef, StringArray, UInt32Array};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use aws_config::meta::region::RegionProviderChain;
use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::config::Builder as S3ConfigBuilder;
use aws_sdk_s3::primitives::ByteStream;
use chrono::{Datelike, Utc};
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Configuration for Parquet S3 forwarder
#[derive(Debug, Clone)]
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
            local_buffer_path: PathBuf::from("/tmp/wef-events"),
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
                parts.get(0).unwrap_or(&"http:"),
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
                    .unwrap_or_else(|| "/tmp/wef-events".to_string()),
            ),
        })
    }
}

/// Buffer for a specific event type
struct EventTypeBuffer {
    events: Vec<BufferedEvent>,
    current_size_bytes: usize,
    last_flush: chrono::DateTime<Utc>,
}

impl EventTypeBuffer {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            current_size_bytes: 0,
            last_flush: Utc::now(),
        }
    }

    fn add_event(&mut self, event: BufferedEvent) {
        self.current_size_bytes += event.estimated_size();
        self.events.push(event);
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
    event_data: serde_json::Value,
}

impl BufferedEvent {
    fn from_windows_event(event: &WindowsEvent) -> Option<Self> {
        let event_id = event.parsed.as_ref()?.event_id;

        Some(Self {
            event_id,
            timestamp: event.received_at,
            source_host: event.source_host.clone(),
            subscription_id: event.subscription_id.clone(),
            event_data: serde_json::to_value(event).ok()?,
        })
    }

    fn estimated_size(&self) -> usize {
        // Use raw_xml length as efficient size estimation
        // This avoids expensive JSON serialization
        self.event_data
            .get("raw_xml")
            .and_then(|v| v.as_str().map(|s| s.len()))
            .unwrap_or(512)
            + 256 // metadata overhead
    }
}

/// Parquet S3 Forwarder
pub struct ParquetS3Forwarder {
    config: ParquetS3Config,
    s3_client: S3Client,
    buffers: HashMap<u32, EventTypeBuffer>,
}

impl ParquetS3Forwarder {
    pub async fn new(config: ParquetS3Config) -> Result<Self> {
        // Create S3 client
        let region_provider =
            RegionProviderChain::first_try(aws_sdk_s3::config::Region::new(config.region.clone()));

        let credentials_provider = if !config.access_key.is_empty() && !config.secret_key.is_empty()
        {
            Some(SharedCredentialsProvider::new(Credentials::new(
                config.access_key.clone(),
                config.secret_key.clone(),
                None,
                None,
                "config",
            )))
        } else {
            None
        };

        let sdk_config = aws_config::from_env()
            .region(region_provider)
            .endpoint_url(&config.endpoint)
            .load()
            .await;

        let mut s3_conf_builder = S3ConfigBuilder::from(&sdk_config);
        if let Some(provider) = credentials_provider {
            s3_conf_builder = s3_conf_builder.credentials_provider(provider);
        }

        let s3_config = s3_conf_builder.force_path_style(true).build();

        let s3_client = S3Client::from_conf(s3_config);

        // Ensure buffer directory exists
        tokio::fs::create_dir_all(&config.local_buffer_path).await?;

        info!(
            "ParquetS3Forwarder initialized: bucket={}, endpoint={}, flush_interval={}s, max_size={}MB",
            config.bucket, config.endpoint, config.flush_interval_secs, config.max_file_size_mb
        );

        Ok(Self {
            config,
            s3_client,
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
        let buffer = self
            .buffers
            .entry(event_type)
            .or_insert_with(EventTypeBuffer::new);

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
            if let Some(buffer) = self.buffers.get(&event_type) {
                if !buffer.events.is_empty() {
                    self.flush_event_type(event_type).await?;
                }
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
        let event_data_json: Vec<String> = events
            .iter()
            .map(|e| serde_json::to_string(&e.event_data).unwrap_or_default())
            .collect();

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
        }).await??;

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

        // Generate S3 key with date partitioning
        let now = Utc::now();
        let s3_key = format!(
            "event_type={}/year={}/month={:02}/day={:02}/{}",
            event_type,
            now.year(),
            now.month(),
            now.day(),
            filename
        );

        // Read file
        let body = ByteStream::from_path(filepath).await?;

        // Upload to S3
        self.s3_client
            .put_object()
            .bucket(&self.config.bucket)
            .key(&s3_key)
            .body(body)
            .content_type("application/octet-stream")
            .send()
            .await?;

        info!(
            "Uploaded parquet file to S3: s3://{}/{}",
            self.config.bucket, s3_key
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DestinationConfig, ForwardProtocol};
    use crate::models::{EventLevel, ParsedEvent, WindowsEvent};
    use serde_json::json;

    fn sample_destination() -> DestinationConfig {
        let mut headers = HashMap::new();
        headers.insert("endpoint".into(), "http://minio:9000".into());
        headers.insert("region".into(), "us-east-1".into());
        headers.insert("access-key".into(), "AKIA".into());
        headers.insert("secret-key".into(), "SECRET".into());
        headers.insert("max-size-mb".into(), "1".into());
        headers.insert("flush-interval-secs".into(), "60".into());
        let temp_path = std::env::temp_dir().join("test-buf");
        headers.insert("buffer-path".into(), temp_path.to_string_lossy().to_string());

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
        let mut buffer = EventTypeBuffer::new();
        buffer.add_event(BufferedEvent {
            event_id: 1,
            timestamp: Utc::now(),
            source_host: "host".into(),
            subscription_id: None,
            event_data: json!({"value": "a"}),
        });

        assert!(!buffer.should_flush(10_000, 300));
        buffer.last_flush = buffer.last_flush - chrono::Duration::seconds(400);
        assert!(buffer.should_flush(10_000, 300));

        let drained = buffer.take_events();
        assert_eq!(drained.len(), 1);
        assert_eq!(buffer.current_size_bytes, 0);
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
