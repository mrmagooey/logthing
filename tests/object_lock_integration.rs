//! Integration test: S3 Object Lock parameters on `S3Sink::upload` against a real MinIO.
//!
//! Requires a running MinIO (or S3-compatible, Object-Lock-capable) instance. Set
//! `MINIO_ENDPOINT` (and optionally `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY`) to enable; when
//! `MINIO_ENDPOINT` is absent the tests skip.
//!
//! Locked objects cannot be deleted until retention expires, so the lock test leaves a small
//! bucket behind; CI runs MinIO ephemerally. Every network call is bounded by a timeout.

use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::types::{ChecksumMode, ObjectLockMode as SdkMode};
use logthing::config::{ObjectLockMode, S3ConnectionConfig};
use logthing::forwarding::s3_sink::S3Sink;
use std::time::Duration;

const T: Duration = Duration::from_secs(30);

fn conn(endpoint: &str, bucket: &str, locked: bool) -> S3ConnectionConfig {
    S3ConnectionConfig {
        endpoint: endpoint.to_string(),
        bucket: bucket.to_string(),
        region: "us-east-1".to_string(),
        access_key: std::env::var("MINIO_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".to_string()),
        secret_key: std::env::var("MINIO_SECRET_KEY").unwrap_or_else(|_| "minioadmin".to_string()),
        object_lock_mode: locked.then_some(ObjectLockMode::Governance),
        object_lock_retain_days: locked.then_some(1),
    }
}

async fn client(c: &S3ConnectionConfig) -> S3Client {
    let creds = aws_credential_types::Credentials::new(
        c.access_key.clone(),
        c.secret_key.clone(),
        None,
        None,
        "test",
    );
    let sdk = aws_config::from_env()
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(&c.endpoint)
        .credentials_provider(creds)
        .load()
        .await;
    S3Client::from_conf(
        aws_sdk_s3::config::Builder::from(&sdk)
            .force_path_style(true)
            .build(),
    )
}

fn bucket_name() -> String {
    format!("lock-{}", &uuid::Uuid::new_v4().simple().to_string()[..12])
}

async fn create_bucket(s3: &S3Client, name: &str, lock: bool) {
    tokio::time::timeout(
        T,
        s3.create_bucket()
            .bucket(name)
            .object_lock_enabled_for_bucket(lock)
            .send(),
    )
    .await
    .expect("create_bucket timed out")
    .unwrap_or_else(|e| panic!("create_bucket {name}: {e:?}"));
}

#[tokio::test]
async fn upload_with_lock_sets_retention_checksum_and_blocks_delete() {
    let Ok(endpoint) = std::env::var("MINIO_ENDPOINT") else {
        eprintln!("MINIO_ENDPOINT not set — skipping object_lock integration test");
        return;
    };
    let bucket = bucket_name();
    let cfg = conn(&endpoint, &bucket, true);
    let s3 = client(&cfg).await;
    create_bucket(&s3, &bucket, true).await;

    let sink = S3Sink::from_connection(&cfg).await.unwrap();
    let before = std::time::SystemTime::now();
    tokio::time::timeout(T, sink.upload("lock/test.bin", b"payload".to_vec()))
        .await
        .expect("upload timed out")
        .expect("upload to a lock-enabled bucket succeeds");

    let head = tokio::time::timeout(
        T,
        s3.head_object()
            .bucket(&bucket)
            .key("lock/test.bin")
            .checksum_mode(ChecksumMode::Enabled)
            .send(),
    )
    .await
    .expect("head timed out")
    .expect("head_object");
    assert_eq!(head.object_lock_mode(), Some(&SdkMode::Governance));
    let until = head
        .object_lock_retain_until_date()
        .expect("retain-until date set")
        .secs();
    let base = before
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        (base + 23 * 3600..=base + 25 * 3600).contains(&until),
        "retain-until {until} not ~now+1d ({base})"
    );
    assert!(
        head.checksum_sha256().is_some_and(|c| !c.is_empty()),
        "SHA-256 checksum must be stored with the object"
    );

    // Retention is enforced: deleting the specific version without the bypass header fails.
    let vid = head.version_id().expect("versioned bucket").to_string();
    let del = tokio::time::timeout(
        T,
        s3.delete_object()
            .bucket(&bucket)
            .key("lock/test.bin")
            .version_id(&vid)
            .send(),
    )
    .await
    .expect("delete timed out");
    assert!(del.is_err(), "locked version must not be deletable");
}

#[tokio::test]
async fn upload_with_lock_to_non_lock_bucket_reports_object_lock_hint_or_succeeds() {
    let Ok(endpoint) = std::env::var("MINIO_ENDPOINT") else {
        eprintln!("MINIO_ENDPOINT not set — skipping object_lock integration test");
        return;
    };
    let bucket = bucket_name();
    let cfg = conn(&endpoint, &bucket, true);
    let s3 = client(&cfg).await;
    create_bucket(&s3, &bucket, false).await;

    let sink = S3Sink::from_connection(&cfg).await.unwrap();
    let result = tokio::time::timeout(T, sink.upload("plain/test.bin", b"p".to_vec()))
        .await
        .expect("upload timed out");
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("Object Lock"),
                "error lacks the Object Lock hint: {msg}"
            );
            assert!(msg.contains("plain/test.bin"), "error lacks the key: {msg}");
        }
        Ok(()) => {
            // The endpoint accepted lock headers on a non-lock bucket: the object must exist.
            let head = tokio::time::timeout(
                T,
                s3.head_object()
                    .bucket(&bucket)
                    .key("plain/test.bin")
                    .send(),
            )
            .await
            .expect("head timed out")
            .expect("object written");
            assert_eq!(head.content_length(), Some(1));
        }
    }
}
