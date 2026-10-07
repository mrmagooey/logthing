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
    pub endpoint: String,
    object_lock: Option<(crate::config::ObjectLockMode, u32)>,
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

        let object_lock = cfg.object_lock_mode.zip(cfg.object_lock_retain_days);
        info!(
            "S3Sink initialized: bucket={}, endpoint={}, object_lock={:?}",
            cfg.bucket, cfg.endpoint, object_lock
        );

        Ok(Self {
            client,
            bucket: cfg.bucket.clone(),
            endpoint: cfg.endpoint.clone(),
            object_lock,
        })
    }

    /// List all object keys with the given prefix. Returns full S3 keys.
    pub async fn list_objects(&self, prefix: &str) -> Result<Vec<String>> {
        let resp = self
            .client
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
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;
        let bytes = resp.body.collect().await?.into_bytes().to_vec();
        Ok(bytes)
    }

    /// Configured Object Lock `(mode, retain_days)`, if any.
    pub fn object_lock(&self) -> Option<(crate::config::ObjectLockMode, u32)> {
        self.object_lock
    }

    /// Build the PutObject request. With Object Lock configured it also sets the lock mode,
    /// retain-until date (`now` + days) and a SHA-256 integrity checksum (S3 requires an
    /// integrity checksum on Object Lock puts).
    pub(crate) fn build_put(
        &self,
        key: &str,
        body: Vec<u8>,
        now: std::time::SystemTime,
    ) -> aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder {
        use aws_sdk_s3::types::{ChecksumAlgorithm, ObjectLockMode as Sdk};
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body))
            .content_type("application/octet-stream");
        if let Some((mode, days)) = self.object_lock {
            let until = now + std::time::Duration::from_secs(u64::from(days) * 86_400);
            req = req
                .object_lock_mode(match mode {
                    crate::config::ObjectLockMode::Governance => Sdk::Governance,
                    crate::config::ObjectLockMode::Compliance => Sdk::Compliance,
                })
                .object_lock_retain_until_date(aws_sdk_s3::primitives::DateTime::from(until))
                .checksum_algorithm(ChecksumAlgorithm::Sha256);
        }
        req
    }

    /// Upload `body` bytes to `key` in the configured bucket.
    /// Mirrors the put_object logic currently in ParquetS3Forwarder::upload_to_s3,
    /// minus the key-generation and file-read (those remain in the caller).
    pub async fn upload(&self, key: &str, body: Vec<u8>) -> Result<()> {
        self.build_put(key, body, std::time::SystemTime::now())
            .send()
            .await
            .map_err(|e| {
                anyhow::anyhow!(lock_hint_error(
                    key,
                    &aws_sdk_s3::error::DisplayErrorContext(&e).to_string(),
                    self.object_lock.is_some()
                ))
            })?;

        info!("Uploaded to S3: s3://{}/{}", self.bucket, key);
        Ok(())
    }
}

/// Format a put_object failure, adding an Object Lock hint when a lock is configured.
fn lock_hint_error(key: &str, cause: &str, lock_configured: bool) -> String {
    let base = format!("S3 put_object failed for key {key}: {cause}");
    if lock_configured {
        format!(
            "{base} (Object Lock is configured: the bucket must have Object Lock enabled and \
             the endpoint must support it; Garage does not -- see docs/object-lock.md)"
        )
    } else {
        base
    }
}

#[async_trait::async_trait]
impl crate::forwarding::buffered_writer::UploadSink for S3Sink {
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
        // Delegates to the inherent method above — kept as an inherent method too
        // so existing tests calling `sink.upload(...)` on a concrete `S3Sink`
        // keep compiling (inherent methods take priority over trait methods of
        // the same name at the call site).
        S3Sink::upload(self, key, body).await
    }

    fn target_label(&self) -> &'static str {
        "s3"
    }

    fn location_hint(&self) -> String {
        format!("{}/{}", self.endpoint.trim_end_matches('/'), self.bucket)
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
            object_lock_mode: None,
            object_lock_retain_days: None,
        };
        let sink = S3Sink::from_connection(&conn).await.expect("constructs");
        let result = sink.upload("some/key.parquet", b"hello".to_vec()).await;
        assert!(result.is_err(), "upload to unreachable endpoint must fail");
    }

    #[tokio::test]
    async fn s3_sink_satisfies_upload_sink_trait() {
        use crate::forwarding::buffered_writer::UploadSink;

        let conn = S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "AKIATEST".to_string(),
            secret_key: "SECRETTEST".to_string(),
            object_lock_mode: None,
            object_lock_retain_days: None,
        };
        let sink: std::sync::Arc<dyn UploadSink> =
            std::sync::Arc::new(S3Sink::from_connection(&conn).await.expect("constructs"));

        assert_eq!(sink.target_label(), "s3");
        // Unreachable endpoint — proves the trait method dispatches to the same
        // upload logic as the inherent method (same failure mode as the existing
        // `upload_returns_err_on_unreachable_endpoint` test).
        let result = sink.upload("some/key.parquet", b"hello".to_vec()).await;
        assert!(
            result.is_err(),
            "upload via trait object must fail the same way as the inherent method"
        );
    }

    #[tokio::test]
    async fn location_hint_combines_endpoint_and_bucket() {
        use crate::config::S3ConnectionConfig;
        let sink = S3Sink::from_connection(&S3ConnectionConfig {
            endpoint: "http://minio:9000/".to_string(), // trailing slash
            bucket: "my-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "K".to_string(),
            secret_key: "S".to_string(),
            object_lock_mode: None,
            object_lock_retain_days: None,
        })
        .await
        .unwrap();
        assert_eq!(
            crate::forwarding::buffered_writer::UploadSink::location_hint(&sink),
            "http://minio:9000/my-bucket"
        );
    }

    fn conn(mode: Option<crate::config::ObjectLockMode>, days: Option<u32>) -> S3ConnectionConfig {
        S3ConnectionConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "AKIATEST".to_string(),
            secret_key: "SECRETTEST".to_string(),
            object_lock_mode: mode,
            object_lock_retain_days: days,
        }
    }

    #[tokio::test]
    async fn build_put_without_lock_sets_no_lock_or_checksum_params() {
        let sink = S3Sink::from_connection(&conn(None, None)).await.unwrap();
        assert_eq!(sink.object_lock(), None);
        let req = sink.build_put("k", vec![1], std::time::SystemTime::UNIX_EPOCH);
        let input = req.as_input();
        assert!(input.get_object_lock_mode().is_none());
        assert!(input.get_object_lock_retain_until_date().is_none());
        assert!(input.get_checksum_algorithm().is_none());
        assert_eq!(input.get_key().as_deref(), Some("k"));
        assert_eq!(input.get_bucket().as_deref(), Some("test-bucket"));
    }

    #[tokio::test]
    async fn build_put_with_lock_sets_mode_retain_until_and_sha256_checksum() {
        use aws_sdk_s3::types::{ChecksumAlgorithm, ObjectLockMode as Sdk};
        let sink = S3Sink::from_connection(&conn(
            Some(crate::config::ObjectLockMode::Compliance),
            Some(30),
        ))
        .await
        .unwrap();
        assert_eq!(
            sink.object_lock(),
            Some((crate::config::ObjectLockMode::Compliance, 30))
        );
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        let req = sink.build_put("k", vec![1], now);
        let input = req.as_input();
        assert_eq!(input.get_object_lock_mode(), &Some(Sdk::Compliance));
        assert_eq!(
            input.get_checksum_algorithm(),
            &Some(ChecksumAlgorithm::Sha256)
        );
        let until = input.get_object_lock_retain_until_date().as_ref().unwrap();
        assert_eq!(until.secs(), 1_000 + 30 * 86_400);
    }

    #[tokio::test]
    async fn build_put_maps_governance_mode() {
        use aws_sdk_s3::types::ObjectLockMode as Sdk;
        let sink = S3Sink::from_connection(&conn(
            Some(crate::config::ObjectLockMode::Governance),
            Some(1),
        ))
        .await
        .unwrap();
        let req = sink.build_put("k", vec![], std::time::SystemTime::UNIX_EPOCH);
        assert_eq!(
            req.as_input().get_object_lock_mode(),
            &Some(Sdk::Governance)
        );
    }

    #[test]
    fn upload_error_message_names_object_lock_when_configured() {
        let msg = lock_hint_error("k", "boom", true);
        assert!(
            msg.contains("Object Lock") && msg.contains("boom") && msg.contains("k"),
            "{msg}"
        );
        assert!(!lock_hint_error("k", "boom", false).contains("Object Lock"));
    }

    #[tokio::test]
    async fn upload_failure_with_lock_configured_carries_the_object_lock_hint() {
        let sink = S3Sink::from_connection(&conn(
            Some(crate::config::ObjectLockMode::Governance),
            Some(1),
        ))
        .await
        .unwrap();
        let err = sink.upload("some/key", b"x".to_vec()).await.unwrap_err();
        assert!(err.to_string().contains("Object Lock"), "{err}");
        let plain = S3Sink::from_connection(&conn(None, None)).await.unwrap();
        let err = plain.upload("some/key", b"x".to_vec()).await.unwrap_err();
        assert!(!err.to_string().contains("Object Lock"), "{err}");
    }
}
