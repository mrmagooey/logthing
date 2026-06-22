use crate::config::S3ConnectionConfig;
use crate::forwarding::parquet_s3::ParquetS3Config;
use anyhow::Result;
use aws_config::meta::region::RegionProviderChain;
use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::config::Builder as S3ConfigBuilder;
use aws_sdk_s3::primitives::ByteStream;
use tracing::info;

/// Thin wrapper around an aws_sdk_s3::Client that provides bucket-scoped upload.
pub struct S3Sink {
    client: S3Client,
    pub bucket: String,
}

impl S3Sink {
    /// Construct an `S3Sink` from a shared [`S3ConnectionConfig`].
    ///
    /// This is the canonical client-construction path. All other constructors
    /// delegate here so the AWS SDK wiring lives in exactly one place.
    pub async fn from_connection(cfg: &S3ConnectionConfig) -> Result<Self> {
        let region_provider =
            RegionProviderChain::first_try(aws_sdk_s3::config::Region::new(cfg.region.clone()));

        let credentials_provider = if !cfg.access_key.is_empty() && !cfg.secret_key.is_empty() {
            Some(SharedCredentialsProvider::new(Credentials::new(
                cfg.access_key.clone(),
                cfg.secret_key.clone(),
                None,
                None,
                "config",
            )))
        } else {
            None
        };

        let sdk_config = aws_config::from_env()
            .region(region_provider)
            .endpoint_url(&cfg.endpoint)
            .load()
            .await;

        let mut s3_conf_builder = S3ConfigBuilder::from(&sdk_config);
        if let Some(provider) = credentials_provider {
            s3_conf_builder = s3_conf_builder.credentials_provider(provider);
        }
        let s3_config = s3_conf_builder.force_path_style(true).build();

        let client = S3Client::from_conf(s3_config);

        info!(
            "S3Sink initialized: bucket={}, endpoint={}",
            cfg.bucket, cfg.endpoint
        );

        Ok(Self {
            client,
            bucket: cfg.bucket.clone(),
        })
    }

    /// Construct an `S3Sink` from a [`ParquetS3Config`].
    ///
    /// Delegates to [`from_connection`][Self::from_connection] so the WEF/parquet
    /// path gets identical AWS client construction behaviour.
    pub async fn from_config(cfg: &ParquetS3Config) -> Result<Self> {
        let conn = S3ConnectionConfig {
            endpoint: cfg.endpoint.clone(),
            bucket: cfg.bucket.clone(),
            region: cfg.region.clone(),
            access_key: cfg.access_key.clone(),
            secret_key: cfg.secret_key.clone(),
        };
        Self::from_connection(&conn).await
    }

    /// Upload `body` bytes to `key` in the configured bucket.
    /// Mirrors the put_object logic currently in ParquetS3Forwarder::upload_to_s3,
    /// minus the key-generation and file-read (those remain in the caller).
    pub async fn upload(&self, key: &str, body: Vec<u8>) -> Result<()> {
        let byte_stream = ByteStream::from(body);

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(byte_stream)
            .content_type("application/octet-stream")
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("S3 put_object failed for key {}: {}", key, e))?;

        info!("Uploaded to S3: s3://{}/{}", self.bucket, key);
        Ok(())
    }
}

/// The cadence at which a writer's background task checks whether a time-based
/// flush is due. Honors the configured flush interval, but never ticks more
/// often than once per second (avoids a busy loop for very small intervals).
pub(crate) fn flush_check_interval(flush_interval: std::time::Duration) -> std::time::Duration {
    flush_interval.max(std::time::Duration::from_secs(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flush_check_interval_respects_configured_interval() {
        assert_eq!(
            flush_check_interval(std::time::Duration::from_secs(5)),
            std::time::Duration::from_secs(5)
        );
    }

    #[test]
    fn flush_check_interval_respects_large_interval() {
        assert_eq!(
            flush_check_interval(std::time::Duration::from_secs(900)),
            std::time::Duration::from_secs(900)
        );
    }

    #[test]
    fn flush_check_interval_clamps_sub_second_interval_up_to_one_second() {
        assert_eq!(
            flush_check_interval(std::time::Duration::from_millis(500)),
            std::time::Duration::from_secs(1)
        );
    }

    #[test]
    fn flush_check_interval_clamps_zero_up_to_one_second() {
        assert_eq!(
            flush_check_interval(std::time::Duration::from_secs(0)),
            std::time::Duration::from_secs(1)
        );
    }

    fn test_config() -> ParquetS3Config {
        ParquetS3Config {
            endpoint: "http://localhost:9000".to_string(),
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "AKIATEST".to_string(),
            secret_key: "SECRETTEST".to_string(),
            max_file_size_mb: 10,
            flush_interval_secs: 60,
            local_buffer_path: std::env::temp_dir().join("s3sink-test"),
        }
    }

    #[tokio::test]
    async fn from_config_stores_bucket() {
        let cfg = test_config();
        let sink = S3Sink::from_config(&cfg).await.expect("should construct");
        assert_eq!(sink.bucket, "test-bucket");
    }

    #[tokio::test]
    async fn from_config_empty_credentials_skips_explicit_provider() {
        // When access_key/secret_key are empty the SDK falls back to env-chain.
        // Construction should still succeed (no live network call happens here).
        let mut cfg = test_config();
        cfg.access_key = String::new();
        cfg.secret_key = String::new();
        let sink = S3Sink::from_config(&cfg)
            .await
            .expect("should construct with empty creds");
        assert_eq!(sink.bucket, "test-bucket");
    }

    #[tokio::test]
    async fn upload_returns_err_on_unreachable_endpoint() {
        // Uses an endpoint that will refuse the TCP connection immediately so
        // the test does not hang. This exercises the error-handling path of
        // upload without a live MinIO.
        let cfg = ParquetS3Config {
            endpoint: "http://127.0.0.1:1".to_string(), // port 1: always refused
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "AKIATEST".to_string(),
            secret_key: "SECRETTEST".to_string(),
            max_file_size_mb: 10,
            flush_interval_secs: 60,
            local_buffer_path: std::env::temp_dir().join("s3sink-upload-test"),
        };
        let sink = S3Sink::from_config(&cfg).await.expect("constructs");
        let result = sink.upload("some/key.parquet", b"hello".to_vec()).await;
        assert!(result.is_err(), "upload to unreachable endpoint must fail");
    }
}
