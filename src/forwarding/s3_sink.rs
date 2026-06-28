use crate::config::S3ConnectionConfig;
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

    /// List all object keys with the given prefix. Returns full S3 keys.
    pub async fn list_objects(&self, prefix: &str) -> Result<Vec<String>> {
        let resp = self.client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .send()
            .await?;
        let keys = resp
            .contents()
            .iter()
            .filter_map(|obj| obj.key().map(|k| k.to_string()))
            .collect();
        Ok(keys)
    }

    /// Download an object and return its raw bytes.
    pub async fn get_object(&self, key: &str) -> Result<Vec<u8>> {
        let resp = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;
        let bytes = resp.body.collect().await?.into_bytes().to_vec();
        Ok(bytes)
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

    #[tokio::test]
    async fn upload_returns_err_on_unreachable_endpoint() {
        use crate::config::S3ConnectionConfig;
        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(), // port 1: always refused
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "AKIATEST".to_string(),
            secret_key: "SECRETTEST".to_string(),
        };
        let sink = S3Sink::from_connection(&conn).await.expect("constructs");
        let result = sink.upload("some/key.parquet", b"hello".to_vec()).await;
        assert!(result.is_err(), "upload to unreachable endpoint must fail");
    }
}
