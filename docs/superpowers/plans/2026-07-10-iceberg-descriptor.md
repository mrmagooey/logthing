# Iceberg Descriptor Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit a small JSON "descriptor" file alongside every Parquet flush, from a new optional `[iceberg]` sink, carrying everything an external Iceberg committer needs (row count, byte size, partition, per-column stats, fully-qualified location) without ever re-reading the Parquet file.

**Architecture:** Hook into the one shared function every log source already funnels through (`PartitionedParquetWriter::flush_partition` in `src/forwarding/buffered_writer.rs`). After a successful Parquet upload, if a descriptor sink is configured, build an `IcebergDescriptor` from data already in memory (row count, encoded byte length, per-column stats captured from `ArrowWriter::close()`'s previously-discarded return value) and upload it via the same `UploadSink` trait already used for Parquet uploads. Descriptor upload is best-effort — failure never blocks the core ingestion path.

**Tech Stack:** Rust 2024, `parquet = "53.4.1"` (pinned, verified against real source), `arrow`/`arrow-schema` 53.0, `serde`/`serde_json`, `chrono` (serde feature already enabled).

## Global Constraints

- No `iceberg-rust` (or any Iceberg library) dependency — logthing stays "dumb"; all real Iceberg catalog/manifest work is an external process's job.
- Do not call the output a "sidecar" or a "manifest" — use "descriptor" (`IcebergDescriptor`) throughout code, config, and docs.
- `[iceberg]` is a single, global config section (not per-source) — one destination for descriptors from every table.
- `[iceberg].s3` and `[iceberg].local` may NOT both be configured simultaneously — `Config::load()` must return an `Err` if both are present (unlike every other source's `.s3`/`.local` pair, which may both coexist).
- `column_stats` values (`min`/`max`) are base64-encoded raw Parquet-encoded bytes plus a `physical_type` string — NOT decoded into human-readable strings. Keyed by 0-based Parquet column index, NOT Iceberg field ID.
- Descriptor upload is synchronous/inline within `flush_partition`, immediately after the Parquet upload succeeds. Never spawn a background task for it.
- Descriptor upload failure is best-effort: log + metric (`iceberg_descriptor_upload_errors{source=...}`), never propagates into `flush_partition`'s return value, never blocks/retries/hard-caps the core Parquet-writing path.
- `PartitionedParquetWriter::new()`'s existing signature (used by ~15+ existing tests) must NOT change — only `with_source_stats()` (the production-path constructor) gains the new `descriptor_sink` parameter.
- Build/test env for every `cargo` command in this plan:
  ```bash
  export PATH="$HOME/.cargo/bin:$PATH"
  export CC=/usr/bin/gcc CXX=/usr/bin/g++
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
  ```
  Omitting this makes the build fail with `UnknownOperatingSystem` (a zig-cc shim shadows real gcc on `PATH`).
- Working directory: `/home/dev/projects/logthing`, branch `feature/iceberg-descriptor` (already checked out, spec committed at `41706a6`).

---

## Task 1: `UploadSink::location_hint()` — fully-qualified file locations

**Files:**
- Modify: `src/forwarding/buffered_writer.rs:26-34` (trait definition), `src/forwarding/buffered_writer.rs` (`RecordingSink` test mock ~line 807-823, `UnreachableUploadSink` test mock ~line 1466-1475)
- Modify: `src/forwarding/s3_sink.rs` (add `endpoint` field, `location_hint()` impl)
- Modify: `src/forwarding/local_sink.rs` (add `location_hint()` impl)

**Interfaces:**
- Produces: `UploadSink::location_hint(&self) -> String` — every implementor (`S3Sink`, `LocalDiskSink`, and the two test mocks) must implement this. `S3Sink::location_hint()` returns `format!("{}/{}", endpoint.trim_end_matches('/'), bucket)` (e.g. `http://minio:9000/my-bucket`). `LocalDiskSink::location_hint()` returns `format!("file://{}", self.root.display())`.

- [ ] **Step 1: Add `location_hint()` to the `UploadSink` trait**

In `src/forwarding/buffered_writer.rs`, find:
```rust
#[async_trait]
pub trait UploadSink: Send + Sync {
    /// Upload `body` at `key` (a relative path, e.g.
    /// `zeek/conn/year=2026/month=07/day=04/<uuid>.parquet`).
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()>;

    /// Stable label for the `target` metric dimension, e.g. `"s3"` | `"local"`.
    fn target_label(&self) -> &'static str;
}
```

Replace with:
```rust
#[async_trait]
pub trait UploadSink: Send + Sync {
    /// Upload `body` at `key` (a relative path, e.g.
    /// `zeek/conn/year=2026/month=07/day=04/<uuid>.parquet`).
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()>;

    /// Stable label for the `target` metric dimension, e.g. `"s3"` | `"local"`.
    fn target_label(&self) -> &'static str;

    /// A fully-qualified location prefix for objects this sink uploads,
    /// e.g. `"http://minio:9000/my-bucket"` (S3) or `"file:///data/zeek"`
    /// (local disk). Used to build a fully-qualified `file_path` in
    /// `IcebergDescriptor` (a bare relative key alone doesn't tell an
    /// external reader which bucket/directory a file lives in — different
    /// sources may point at different buckets).
    fn location_hint(&self) -> String;
}
```

- [ ] **Step 2: Add `endpoint` field to `S3Sink` and implement `location_hint()`**

In `src/forwarding/s3_sink.rs`, find:
```rust
/// Thin wrapper around an aws_sdk_s3::Client that provides bucket-scoped upload.
pub struct S3Sink {
    client: S3Client,
    pub bucket: String,
}
```

Replace with:
```rust
/// Thin wrapper around an aws_sdk_s3::Client that provides bucket-scoped upload.
pub struct S3Sink {
    client: S3Client,
    pub bucket: String,
    pub endpoint: String,
}
```

Find (inside `from_connection`, the `Ok(Self { ... })` at the end):
```rust
        Ok(Self {
            client,
            bucket: cfg.bucket.clone(),
        })
```

Replace with:
```rust
        Ok(Self {
            client,
            bucket: cfg.bucket.clone(),
            endpoint: cfg.endpoint.clone(),
        })
```

Find:
```rust
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
}
```

Replace with:
```rust
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
```

- [ ] **Step 3: Implement `location_hint()` for `LocalDiskSink`**

In `src/forwarding/local_sink.rs`, find the `fn target_label(&self) -> &'static str {` method inside `impl UploadSink for LocalDiskSink` (around line 116) and add a new method immediately after its closing brace:
```rust
    fn location_hint(&self) -> String {
        format!("file://{}", self.root.display())
    }
```

- [ ] **Step 4: Update the two `UploadSink` test mocks in `buffered_writer.rs`**

Find `RecordingSink`'s impl:
```rust
    #[async_trait::async_trait]
    impl UploadSink for RecordingSink {
        async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
            self.uploads
                .lock()
                .unwrap()
                .push((key.to_string(), body.len()));
            Ok(())
        }
        fn target_label(&self) -> &'static str {
            "recording"
        }
    }
```

Replace with:
```rust
    #[async_trait::async_trait]
    impl UploadSink for RecordingSink {
        async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
            self.uploads
                .lock()
                .unwrap()
                .push((key.to_string(), body.len()));
            Ok(())
        }
        fn target_label(&self) -> &'static str {
            "recording"
        }
        fn location_hint(&self) -> String {
            "recording://test".to_string()
        }
    }
```

Find `UnreachableUploadSink`'s impl:
```rust
        struct UnreachableUploadSink;
        #[async_trait::async_trait]
        impl UploadSink for UnreachableUploadSink {
            async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
                anyhow::bail!("unreachable in this test")
            }
            fn target_label(&self) -> &'static str {
                "test"
            }
        }
```

Replace with:
```rust
        struct UnreachableUploadSink;
        #[async_trait::async_trait]
        impl UploadSink for UnreachableUploadSink {
            async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
                anyhow::bail!("unreachable in this test")
            }
            fn target_label(&self) -> &'static str {
                "test"
            }
            fn location_hint(&self) -> String {
                "unreachable://test".to_string()
            }
        }
```

- [ ] **Step 5: Confirm the crate builds**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo build --lib 2>&1 | tail -40
```
Expected: clean build, no errors. (If any OTHER `impl UploadSink for` exists that this plan missed, the compiler will report a missing-trait-item error naming the exact file/line — fix it the same way, adding a one-line `location_hint()` returning any stable string, before proceeding.)

- [ ] **Step 6: Add a unit test proving each real sink's `location_hint()` shape**

In `src/forwarding/s3_sink.rs`'s `#[cfg(test)] mod tests`, add:
```rust
    #[tokio::test]
    async fn location_hint_combines_endpoint_and_bucket() {
        use crate::config::S3ConnectionConfig;
        let sink = S3Sink::from_connection(&S3ConnectionConfig {
            endpoint: "http://minio:9000/".to_string(), // trailing slash
            bucket: "my-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key: "K".to_string(),
            secret_key: "S".to_string(),
        })
        .await
        .unwrap();
        assert_eq!(
            crate::forwarding::buffered_writer::UploadSink::location_hint(&sink),
            "http://minio:9000/my-bucket"
        );
    }
```

In `src/forwarding/local_sink.rs`'s `#[cfg(test)] mod tests`, add:
```rust
    #[tokio::test]
    async fn location_hint_is_a_file_uri_rooted_at_the_canonical_directory() {
        let dir = tempfile::tempdir().unwrap();
        let sink = LocalDiskSink::new(dir.path().to_path_buf()).await.unwrap();
        let hint = sink.location_hint();
        assert!(hint.starts_with("file://"), "got: {hint}");
        assert!(hint.contains(&dir.path().file_name().unwrap().to_string_lossy().to_string()));
    }
```

- [ ] **Step 7: Run both new tests**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib location_hint -- --nocapture
```
Expected: both tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/forwarding/buffered_writer.rs src/forwarding/s3_sink.rs src/forwarding/local_sink.rs
git commit -m "feat(forwarding): add UploadSink::location_hint for fully-qualified paths"
```

---

## Task 2: `IcebergDescriptor` module

**Files:**
- Create: `src/forwarding/iceberg_descriptor.rs`
- Modify: `src/forwarding/mod.rs` (register the new module)
- Modify: `Cargo.toml` (add `base64` dependency)

**Interfaces:**
- Produces: `IcebergDescriptor` struct, `ColumnStat` struct, `schema_version(&arrow_schema::Schema) -> String`, `build_descriptor_key(descriptor_prefix: &str, parquet_key: &str) -> String`, `IcebergDescriptor::to_json_bytes(&self) -> anyhow::Result<Vec<u8>>`. Task 4 consumes all of these.

- [ ] **Step 1: Add the `base64` dependency**

In `Cargo.toml`, find the `# Serialization/Deserialization` section:
```toml
# Serialization/Deserialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"
```

Replace with:
```toml
# Serialization/Deserialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"
base64 = "0.22"
```

- [ ] **Step 2: Register the new module**

In `src/forwarding/mod.rs`, find the existing `pub mod` declarations (they list `buffered_writer`, `local_sink`, `s3_sink`, etc. — add one more, alphabetically among them):
```rust
pub mod iceberg_descriptor;
```

- [ ] **Step 3: Write the failing tests**

Create `src/forwarding/iceberg_descriptor.rs`:
```rust
//! Iceberg "descriptor" output — a small JSON file emitted alongside each
//! Parquet flush, carrying everything an external Iceberg committer needs
//! to build a real Iceberg manifest entry without re-reading the Parquet
//! file: row count, byte size, partition, per-column stats, and a
//! fully-qualified file location. logthing has no Iceberg library
//! dependency and never builds real Iceberg manifests/catalogs itself —
//! that is entirely the external committer's job.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use serde::Serialize;

/// Per-column statistics captured from the just-encoded Parquet file's own
/// row-group metadata (already computed by `ArrowWriter` during encoding —
/// nothing here re-reads the file). Keyed by 0-based Parquet column index
/// in `IcebergDescriptor::column_stats`, NOT Iceberg field ID — valid only
/// within one `schema_version` (see that field's docs on `IcebergDescriptor`).
///
/// `min`/`max` are base64-encoded RAW Parquet-encoded bytes (Parquet's own
/// PLAIN encoding), NOT decoded into a human-readable value — this
/// mirrors how Iceberg's own `DataFile.lower_bounds`/`upper_bounds` are
/// ALSO raw type-encoded binary, so the committer decodes once using
/// `physical_type`, rather than logthing decoding into a lossy string
/// that would need re-encoding downstream anyway.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ColumnStat {
    pub null_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<String>,
    /// Parquet physical type name (e.g. `"INT32"`, `"BYTE_ARRAY"`), needed
    /// by the committer to correctly decode `min`/`max`.
    pub physical_type: String,
}

/// One descriptor per Parquet file flushed.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct IcebergDescriptor {
    /// Stable source label, e.g. `"zeek"`, `"ipfix"` — same value as
    /// `ParquetSink::source()`.
    pub source: String,
    /// Raw partition segment, e.g. `"conn"` or `"event_type=4624"` — NOT a
    /// composed "table" name. `None` for single-partition sources
    /// (syslog, ipfix).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
    /// Fully-qualified location of the Parquet file this descriptor
    /// describes, e.g. `"http://minio:9000/my-bucket/zeek/conn/year=2026/
    /// month=07/day=10/<uuid>.parquet"` or `"file:///data/zeek/conn/.../
    /// <uuid>.parquet"`.
    pub file_path: String,
    /// Always `"PARQUET"` today.
    pub file_format: String,
    pub record_count: u64,
    pub file_size_in_bytes: u64,
    /// `"s3"` or `"local"` — same value as `UploadSink::target_label()`
    /// for the sink that wrote the described Parquet file.
    pub storage_target: String,
    /// Hash of the Arrow schema's field names+types, computed at flush
    /// time. Changes only when a source's schema genuinely changes — not
    /// tied to logthing's own release version, which would give
    /// false-positive drift signals on every release.
    pub schema_version: String,
    pub written_at: chrono::DateTime<chrono::Utc>,
    pub column_stats: HashMap<u32, ColumnStat>,
}

impl IcebergDescriptor {
    /// Serialize to pretty-printed JSON bytes — these files are small and
    /// meant to be human-inspectable, so readability costs nothing here.
    pub fn to_json_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }
}

/// Deterministic hash of an Arrow schema's field names + types.
pub fn schema_version(schema: &arrow_schema::Schema) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for field in schema.fields() {
        field.name().hash(&mut hasher);
        format!("{:?}", field.data_type()).hash(&mut hasher);
    }
    format!("{:x}", hasher.finish())
}

/// Derive the descriptor's own key from the Parquet file's already-computed
/// key: swap the `.parquet` suffix for `.json`, optionally nested under
/// `descriptor_prefix` (the descriptor sink's own separate `prefix` config
/// field — independent of the Parquet file's own prefix, which is already
/// baked into `parquet_key`). Deliberately does NOT mint a new UUID/timestamp
/// (unlike `buffered_writer::build_key`) — the descriptor must stay
/// 1:1-correlated by name with the exact Parquet file it describes.
pub fn build_descriptor_key(descriptor_prefix: &str, parquet_key: &str) -> String {
    let json_key = match parquet_key.strip_suffix(".parquet") {
        Some(stem) => format!("{stem}.json"),
        None => format!("{parquet_key}.json"),
    };
    if descriptor_prefix.is_empty() {
        json_key
    } else {
        format!("{descriptor_prefix}/{json_key}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_schema::{DataType, Field, Schema};

    fn sample_descriptor() -> IcebergDescriptor {
        let mut column_stats = HashMap::new();
        column_stats.insert(
            0,
            ColumnStat {
                null_count: 0,
                min: Some("AAAAAA==".to_string()),
                max: Some("//////8=".to_string()),
                physical_type: "INT32".to_string(),
            },
        );
        IcebergDescriptor {
            source: "zeek".to_string(),
            partition: Some("conn".to_string()),
            file_path: "http://minio:9000/bucket/zeek/conn/year=2026/month=07/day=10/abc.parquet"
                .to_string(),
            file_format: "PARQUET".to_string(),
            record_count: 42,
            file_size_in_bytes: 1024,
            storage_target: "s3".to_string(),
            schema_version: "deadbeef".to_string(),
            written_at: "2026-07-10T12:00:00Z".parse().unwrap(),
            column_stats,
        }
    }

    #[test]
    fn descriptor_serializes_to_expected_json_shape() {
        let d = sample_descriptor();
        let bytes = d.to_json_bytes().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["source"], "zeek");
        assert_eq!(v["partition"], "conn");
        assert_eq!(v["file_format"], "PARQUET");
        assert_eq!(v["record_count"], 42);
        assert_eq!(v["file_size_in_bytes"], 1024);
        assert_eq!(v["storage_target"], "s3");
        assert_eq!(v["schema_version"], "deadbeef");
        assert_eq!(v["column_stats"]["0"]["null_count"], 0);
        assert_eq!(v["column_stats"]["0"]["physical_type"], "INT32");
    }

    #[test]
    fn descriptor_omits_partition_field_when_none() {
        let mut d = sample_descriptor();
        d.partition = None;
        let bytes = d.to_json_bytes().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            v.get("partition").is_none(),
            "partition key must be omitted entirely when None, got: {v}"
        );
    }

    #[test]
    fn schema_version_is_deterministic_for_same_schema() {
        let schema = Schema::new(vec![
            Field::new("a", DataType::Utf8, false),
            Field::new("b", DataType::Int64, true),
        ]);
        let schema2 = Schema::new(vec![
            Field::new("a", DataType::Utf8, false),
            Field::new("b", DataType::Int64, true),
        ]);
        assert_eq!(schema_version(&schema), schema_version(&schema2));
    }

    #[test]
    fn schema_version_differs_for_different_schema() {
        let schema_a = Schema::new(vec![Field::new("a", DataType::Utf8, false)]);
        let schema_b = Schema::new(vec![Field::new("a", DataType::Int64, false)]);
        assert_ne!(schema_version(&schema_a), schema_version(&schema_b));
    }

    #[test]
    fn build_descriptor_key_swaps_parquet_suffix_for_json() {
        let key = build_descriptor_key(
            "",
            "zeek/conn/year=2026/month=07/day=10/abc-123.parquet",
        );
        assert_eq!(key, "zeek/conn/year=2026/month=07/day=10/abc-123.json");
    }

    #[test]
    fn build_descriptor_key_nests_under_descriptor_prefix_when_set() {
        let key = build_descriptor_key(
            "_iceberg_descriptors",
            "zeek/conn/year=2026/month=07/day=10/abc-123.parquet",
        );
        assert_eq!(
            key,
            "_iceberg_descriptors/zeek/conn/year=2026/month=07/day=10/abc-123.json"
        );
    }

    #[test]
    fn build_descriptor_key_handles_missing_parquet_suffix_defensively() {
        // build_key always produces a .parquet suffix in production, but
        // this helper must not panic if that ever changes.
        let key = build_descriptor_key("", "some/weird/key");
        assert_eq!(key, "some/weird/key.json");
    }
}
```

- [ ] **Step 4: Run the tests to confirm they pass**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib iceberg_descriptor:: -- --nocapture
```
Expected: 7 tests pass (`descriptor_serializes_to_expected_json_shape`,
`descriptor_omits_partition_field_when_none`,
`schema_version_is_deterministic_for_same_schema`,
`schema_version_differs_for_different_schema`,
`build_descriptor_key_swaps_parquet_suffix_for_json`,
`build_descriptor_key_nests_under_descriptor_prefix_when_set`,
`build_descriptor_key_handles_missing_parquet_suffix_defensively`).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/forwarding/mod.rs src/forwarding/iceberg_descriptor.rs
git commit -m "feat(forwarding): add IcebergDescriptor module"
```

---

## Task 3: `[iceberg]` config section + fail-fast dual-destination validation

**Files:**
- Modify: `src/config/mod.rs`

**Interfaces:**
- Consumes: `S3ConnectionConfig` (existing, `src/config/mod.rs`).
- Produces: `IcebergConfig { s3: Option<IcebergDescriptorS3Config>, local: Option<IcebergDescriptorLocalConfig> }`, added as `pub iceberg: IcebergConfig` on `Config`. `validate_iceberg_config(cfg: &IcebergConfig) -> anyhow::Result<()>` — called from `Config::load()`. Task 4/5-11 consume `config.iceberg.s3`/`config.iceberg.local`.

- [ ] **Step 1: Write the failing tests**

In `src/config/mod.rs`'s `#[cfg(test)] mod tests` block, add (near the other per-source config tests):
```rust
    #[test]
    fn iceberg_config_absent_gives_none_none() {
        let cfg = Config::default();
        assert!(cfg.iceberg.s3.is_none());
        assert!(cfg.iceberg.local.is_none());
    }

    #[test]
    fn iceberg_s3_flat_toml_deserializes_correctly() {
        let toml_str = r#"
[iceberg.s3]
endpoint   = "http://minio:9000"
bucket     = "iceberg-descriptors"
region     = "us-east-1"
access_key = "KEY"
secret_key = "SECRET"
prefix     = "_iceberg_descriptors"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse config");
        let s3 = cfg.iceberg.s3.expect("s3 present");
        assert_eq!(s3.connection.bucket, "iceberg-descriptors");
        assert_eq!(s3.prefix, "_iceberg_descriptors");
        assert!(cfg.iceberg.local.is_none());
    }

    #[test]
    fn iceberg_s3_prefix_defaults_to_empty_when_absent() {
        let toml_str = r#"
[iceberg.s3]
endpoint   = "http://minio:9000"
bucket     = "iceberg-descriptors"
region     = "us-east-1"
access_key = "KEY"
secret_key = "SECRET"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse config");
        assert_eq!(cfg.iceberg.s3.unwrap().prefix, "");
    }

    #[test]
    fn iceberg_local_config_deserializes_from_toml() {
        let toml_str = r#"
[iceberg.local]
directory = "/var/log/logthing/iceberg-descriptors"
prefix    = "_iceberg_descriptors"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse config");
        let local = cfg.iceberg.local.expect("local present");
        assert_eq!(
            local.directory,
            std::path::PathBuf::from("/var/log/logthing/iceberg-descriptors")
        );
        assert_eq!(local.prefix, "_iceberg_descriptors");
    }

    #[test]
    fn validate_iceberg_config_ok_when_only_s3_set() {
        let cfg = IcebergConfig {
            s3: Some(IcebergDescriptorS3Config {
                connection: S3ConnectionConfig {
                    endpoint: "http://minio:9000".to_string(),
                    bucket: "b".to_string(),
                    region: "us-east-1".to_string(),
                    access_key: "k".to_string(),
                    secret_key: "s".to_string(),
                },
                prefix: String::new(),
            }),
            local: None,
        };
        assert!(validate_iceberg_config(&cfg).is_ok());
    }

    #[test]
    fn validate_iceberg_config_ok_when_neither_set() {
        assert!(validate_iceberg_config(&IcebergConfig::default()).is_ok());
    }

    #[test]
    fn validate_iceberg_config_errs_when_both_s3_and_local_set() {
        let cfg = IcebergConfig {
            s3: Some(IcebergDescriptorS3Config {
                connection: S3ConnectionConfig {
                    endpoint: "http://minio:9000".to_string(),
                    bucket: "my-bucket".to_string(),
                    region: "us-east-1".to_string(),
                    access_key: "k".to_string(),
                    secret_key: "s".to_string(),
                },
                prefix: String::new(),
            }),
            local: Some(IcebergDescriptorLocalConfig {
                directory: std::path::PathBuf::from("/data/iceberg"),
                prefix: String::new(),
            }),
        };
        let err = validate_iceberg_config(&cfg).expect_err("must reject both configured");
        let msg = err.to_string();
        assert!(msg.contains("my-bucket"), "error must name the s3 bucket: {msg}");
        assert!(
            msg.contains("/data/iceberg"),
            "error must name the local directory: {msg}"
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail (types don't exist yet)**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib iceberg -- --nocapture
```
Expected: FAIL — compile error, `IcebergConfig`/`IcebergDescriptorS3Config`/`IcebergDescriptorLocalConfig`/`validate_iceberg_config` not found.

- [ ] **Step 3: Add the config structs**

In `src/config/mod.rs`, immediately after the `HecConfig`/`OtlpConfig` section (find `fn default_otlp_enabled() -> bool {` and its surrounding `impl Default for OtlpConfig` block, add the new code right after that block closes), add:
```rust
/// Top-level `[iceberg]` config section — emits a small JSON "descriptor"
/// alongside each Parquet flush from every source, describing the file
/// for an external Iceberg committer (logthing has no Iceberg library
/// dependency and never talks to a catalog itself). Absent from TOML →
/// both `s3`/`local` are `None` → the feature is off (zero behavior
/// change to existing Parquet writing).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct IcebergConfig {
    /// Optional S3 destination for descriptors. Configuring this AND
    /// `local` simultaneously is a config error (see `validate_iceberg_config`)
    /// — unlike every other source's `.s3`/`.local` pair, which may both be
    /// configured and both get written to, `[iceberg]` requires exactly one
    /// destination: a descriptor is a lightweight pointer, not data at risk
    /// of loss, so dual-write isn't needed.
    #[serde(default)]
    pub s3: Option<IcebergDescriptorS3Config>,
    /// Optional local-disk destination for descriptors. See `s3` docs.
    #[serde(default)]
    pub local: Option<IcebergDescriptorLocalConfig>,
}

/// S3 destination config for Iceberg descriptors. Deliberately simpler
/// than other sources' `*S3Config` structs — no buffering fields, since
/// descriptors are uploaded synchronously as part of a flush that already
/// happened (nothing to batch).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IcebergDescriptorS3Config {
    #[serde(flatten)]
    pub connection: S3ConnectionConfig,
    /// Key prefix, slash-free (default: `""`).
    #[serde(default)]
    pub prefix: String,
}

/// Local-disk destination config for Iceberg descriptors. See
/// `IcebergDescriptorS3Config` docs.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IcebergDescriptorLocalConfig {
    pub directory: PathBuf,
    /// Key prefix, slash-free (default: `""`).
    #[serde(default)]
    pub prefix: String,
}

/// Rejects a config where both `iceberg.s3` and `iceberg.local` are
/// configured simultaneously. Because `config::Config::builder()` merges
/// all layers (file → admin-override-file → env vars) before
/// `try_deserialize()` runs, which *layer* set which value is not
/// recoverable here — the error names the resolved values instead, which
/// is the most an operator can be told given that constraint.
pub fn validate_iceberg_config(cfg: &IcebergConfig) -> anyhow::Result<()> {
    if let (Some(s3), Some(local)) = (cfg.s3.as_ref(), cfg.local.as_ref()) {
        anyhow::bail!(
            "iceberg.s3.bucket = '{}' and iceberg.local.directory = '{}' are both configured; \
             set only one — the [iceberg] descriptor sink does not support writing to both \
             destinations simultaneously",
            s3.connection.bucket,
            local.directory.display()
        );
    }
    Ok(())
}
```

- [ ] **Step 4: Add `iceberg` field to `Config` and its `Default` impl**

Find the `Config` struct's field list (ends with `pub otlp: OtlpConfig,`):
```rust
    #[serde(default)]
    pub otlp: OtlpConfig,
}
```

Replace with:
```rust
    #[serde(default)]
    pub otlp: OtlpConfig,

    #[serde(default)]
    pub iceberg: IcebergConfig,
}
```

Find `impl Default for Config`'s body (ends with `otlp: OtlpConfig::default(),`):
```rust
            otlp: OtlpConfig::default(),
        }
    }
}
```

Replace with:
```rust
            otlp: OtlpConfig::default(),
            iceberg: IcebergConfig::default(),
        }
    }
}
```

- [ ] **Step 5: Wire the validation into `Config::load()`**

Find:
```rust
        let config = builder.build()?;
        Ok(config.try_deserialize()?)
    }
}
```

Replace with:
```rust
        let config = builder.build()?;
        let config: Config = config.try_deserialize()?;
        validate_iceberg_config(&config.iceberg)?;
        Ok(config)
    }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib iceberg -- --nocapture
```
Expected: all 7 new tests pass (`iceberg_config_absent_gives_none_none`,
`iceberg_s3_flat_toml_deserializes_correctly`,
`iceberg_s3_prefix_defaults_to_empty_when_absent`,
`iceberg_local_config_deserializes_from_toml`,
`validate_iceberg_config_ok_when_only_s3_set`,
`validate_iceberg_config_ok_when_neither_set`,
`validate_iceberg_config_errs_when_both_s3_and_local_set`).

- [ ] **Step 7: Add the env-var-override regression test**

Following the pattern already established by `env_vars_override_bind_ports_for_all_log_types` in this same file, add:
```rust
    #[test]
    fn env_vars_override_iceberg_s3_config() {
        let vars: &[(&str, &str)] = &[
            ("WEF__ICEBERG__S3__ENDPOINT", "http://minio-test:9000"),
            ("WEF__ICEBERG__S3__BUCKET", "env-override-bucket"),
            ("WEF__ICEBERG__S3__REGION", "eu-west-1"),
            ("WEF__ICEBERG__S3__ACCESS_KEY", "envkey"),
            ("WEF__ICEBERG__S3__SECRET_KEY", "envsecret"),
            ("WEF__ICEBERG__S3__PREFIX", "env-prefix"),
        ];
        for (k, v) in vars {
            unsafe { std::env::set_var(k, v) };
        }
        let result = std::panic::catch_unwind(|| {
            let cfg = Config::load().expect("config loads with env overrides");
            let s3 = cfg.iceberg.s3.expect("iceberg.s3 must be present via env vars");
            assert_eq!(s3.connection.endpoint, "http://minio-test:9000");
            assert_eq!(s3.connection.bucket, "env-override-bucket");
            assert_eq!(s3.connection.region, "eu-west-1");
            assert_eq!(s3.prefix, "env-prefix");
        });
        for (k, _) in vars {
            unsafe { std::env::remove_var(k) };
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }
```

- [ ] **Step 8: Run it**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib env_vars_override_iceberg_s3_config -- --nocapture
```
Expected: pass. Then run the full config suite to confirm no regressions:
```bash
cargo test --lib config:: -- --test-threads=4
```
Expected: all pass.

- [ ] **Step 9: Commit**

```bash
git add src/config/mod.rs
git commit -m "feat(config): add [iceberg] descriptor sink config with fail-fast dual-destination validation"
```

---

## Task 4: Core wiring — `PartitionedParquetWriter` emits descriptors on flush

**Files:**
- Modify: `src/forwarding/buffered_writer.rs`

**Interfaces:**
- Consumes: `IcebergDescriptor`, `ColumnStat`, `schema_version()`, `build_descriptor_key()` (Task 2); `UploadSink::location_hint()` (Task 1); `IcebergConfig`/`IcebergDescriptorS3Config`/`IcebergDescriptorLocalConfig` (Task 3).
- Produces: `PartitionedParquetWriter::with_source_stats(..., descriptor_sink: Option<Arc<dyn UploadSink>>)` (new parameter), `ParquetWriterHandle::start_with_stats(..., descriptor_sink: Option<Arc<dyn UploadSink>>)` (new parameter), `start_writer::<S>(..., descriptor_sink: Option<Arc<dyn UploadSink>>)` (new parameter), `pub async fn build_iceberg_descriptor_sink(cfg: &crate::config::IcebergConfig) -> anyhow::Result<Option<Arc<dyn UploadSink>>>` — a new shared helper both `main.rs` and `server/mod.rs` will call in Tasks 5-11, which internally applies the descriptor sink's own configured `prefix` via a private `PrefixedUploadSink` wrapper (no separate prefix parameter needed anywhere else). New metrics: `iceberg_descriptor_uploads{source=...}`, `iceberg_descriptor_upload_errors{source=...}`.

- [ ] **Step 1: Add `descriptor_sink` field to `PartitionedParquetWriter` and thread it through `with_source_stats` only (not `new`)**

Find:
```rust
pub struct PartitionedParquetWriter<S: ParquetSink> {
    sink: S,
    s3: Arc<dyn UploadSink>,
    config: BufferedWriterConfig,
    policy: FlushPolicy,
    /// `""` key for None-partition sources; sanitized-path / `"event_type=<id>"` for multi-partition.
    pub(crate) buffers: HashMap<String, PartitionBuffer>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
}

impl<S: ParquetSink> PartitionedParquetWriter<S> {
    pub fn new(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> Self {
        Self::with_source_stats(
            sink,
            s3,
            config,
            policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
        )
    }

    pub fn with_source_stats(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
        source_stats: Arc<crate::stats::SourceHourlyStats>,
    ) -> Self {
        Self {
            sink,
            s3,
            config,
            policy,
            buffers: HashMap::new(),
            source_stats,
        }
    }
```

Replace with:
```rust
pub struct PartitionedParquetWriter<S: ParquetSink> {
    sink: S,
    s3: Arc<dyn UploadSink>,
    config: BufferedWriterConfig,
    policy: FlushPolicy,
    /// `""` key for None-partition sources; sanitized-path / `"event_type=<id>"` for multi-partition.
    pub(crate) buffers: HashMap<String, PartitionBuffer>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
    /// Optional destination for the Iceberg "descriptor" JSON emitted
    /// alongside each successful Parquet flush. `None` (the default via
    /// `new()`) means the feature is off — zero behavior change.
    descriptor_sink: Option<Arc<dyn UploadSink>>,
}

impl<S: ParquetSink> PartitionedParquetWriter<S> {
    pub fn new(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> Self {
        Self::with_source_stats(
            sink,
            s3,
            config,
            policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_source_stats(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
        source_stats: Arc<crate::stats::SourceHourlyStats>,
        descriptor_sink: Option<Arc<dyn UploadSink>>,
    ) -> Self {
        Self {
            sink,
            s3,
            config,
            policy,
            buffers: HashMap::new(),
            source_stats,
            descriptor_sink,
        }
    }
```

- [ ] **Step 2: Update the one other call site of `with_source_stats` in the existing test module**

Find (in `#[cfg(test)] mod tests`, test `push_records_into_shared_source_hourly_stats`):
```rust
        let mut w = PartitionedParquetWriter::with_source_stats(
            MockSink,
            s3,
            cfg,
            policy,
            shared_stats.clone(),
        );
```

Replace with:
```rust
        let mut w = PartitionedParquetWriter::with_source_stats(
            MockSink,
            s3,
            cfg,
            policy,
            shared_stats.clone(),
            None,
        );
```

- [ ] **Step 3: Capture `FileMetaData` from `ArrowWriter::close()` instead of discarding it, and build/upload the descriptor after a successful flush**

Find the full `flush_partition` method:
```rust
    async fn flush_partition(&mut self, key: &str) -> anyhow::Result<()> {
        let buf = match self.buffers.get_mut(key) {
            Some(b) if !b.buffer.is_empty() => b,
            _ => return Ok(()),
        };
        let batches: Vec<_> = buf.buffer.iter().map(|(b, _)| b.clone()).collect();
        let row_count = buf.row_count;
        let schema = buf.schema.clone();
        let source = self.sink.source();

        // Concatenate all single-row batches into one before encoding.
        let merged = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            use parquet::arrow::ArrowWriter;
            use parquet::basic::{Compression, ZstdLevel};
            use parquet::file::properties::WriterProperties;

            let batch = arrow::compute::concat_batches(&schema, &batches)?;
            let props = WriterProperties::builder()
                .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
                .build();
            let mut buf = Vec::new();
            let mut writer = ArrowWriter::try_new(&mut buf, schema, Some(props))?;
            writer.write(&batch)?;
            writer.close()?;
            Ok(buf)
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking join: {e}"))??;

        let partition_seg = if key.is_empty() { None } else { Some(key) };
        let s3_key = build_key(&self.config.prefix, partition_seg, chrono::Utc::now());
        let target = self.s3.target_label();
        match self.s3.upload(&s3_key, merged).await {
            Ok(()) => {
                metrics::counter!("parquet_s3_records_written", "source" => source, "target" => target)
                    .increment(row_count as u64);
                metrics::counter!("parquet_s3_uploads", "source" => source, "target" => target)
                    .increment(1);
                let buf = self.buffers.get_mut(key).unwrap();
                buf.buffer.clear();
                buf.row_count = 0;
                buf.byte_count = 0;
                buf.last_flush = Instant::now();
                Ok(())
            }
            Err(e) => {
                metrics::counter!("parquet_s3_upload_errors", "source" => source, "target" => target).increment(1);
                Err(e)
            }
        }
    }
```

Replace with:
```rust
    async fn flush_partition(&mut self, key: &str) -> anyhow::Result<()> {
        let buf = match self.buffers.get_mut(key) {
            Some(b) if !b.buffer.is_empty() => b,
            _ => return Ok(()),
        };
        let batches: Vec<_> = buf.buffer.iter().map(|(b, _)| b.clone()).collect();
        let row_count = buf.row_count;
        let schema = buf.schema.clone();
        let source = self.sink.source();

        // Concatenate all single-row batches into one before encoding.
        // `file_metadata` (previously discarded) carries per-row-group
        // column statistics already computed by the encoder — captured
        // here so the Iceberg descriptor never needs to re-open the file.
        let (merged, file_metadata) = tokio::task::spawn_blocking(
            move || -> anyhow::Result<(Vec<u8>, parquet::format::FileMetaData)> {
                use parquet::arrow::ArrowWriter;
                use parquet::basic::{Compression, ZstdLevel};
                use parquet::file::properties::WriterProperties;

                let batch = arrow::compute::concat_batches(&schema, &batches)?;
                let props = WriterProperties::builder()
                    .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
                    .build();
                let mut buf = Vec::new();
                let mut writer = ArrowWriter::try_new(&mut buf, schema.clone(), Some(props))?;
                writer.write(&batch)?;
                let file_metadata = writer.close()?;
                Ok((buf, file_metadata))
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking join: {e}"))??;

        let partition_seg = if key.is_empty() { None } else { Some(key) };
        let s3_key = build_key(&self.config.prefix, partition_seg, chrono::Utc::now());
        let target = self.s3.target_label();
        let body_len = merged.len();

        match self.s3.upload(&s3_key, merged).await {
            Ok(()) => {
                metrics::counter!("parquet_s3_records_written", "source" => source, "target" => target)
                    .increment(row_count as u64);
                metrics::counter!("parquet_s3_uploads", "source" => source, "target" => target)
                    .increment(1);

                if let Some(descriptor_sink) = self.descriptor_sink.clone() {
                    let schema_for_descriptor = self.buffers.get(key).unwrap().schema.clone();
                    let descriptor = build_descriptor(
                        source,
                        partition_seg,
                        self.s3.location_hint(),
                        &s3_key,
                        row_count as u64,
                        body_len as u64,
                        target,
                        &schema_for_descriptor,
                        &file_metadata,
                    );
                    upload_descriptor(descriptor_sink, descriptor, &s3_key, source).await;
                }

                let buf = self.buffers.get_mut(key).unwrap();
                buf.buffer.clear();
                buf.row_count = 0;
                buf.byte_count = 0;
                buf.last_flush = Instant::now();
                Ok(())
            }
            Err(e) => {
                metrics::counter!("parquet_s3_upload_errors", "source" => source, "target" => target).increment(1);
                Err(e)
            }
        }
    }
```

- [ ] **Step 4: Add the `build_descriptor`/`upload_descriptor` helper functions**

Immediately after the closing `}` of `impl<S: ParquetSink> PartitionedParquetWriter<S>` (before the `ParquetWriterHandle<S>` section), add:
```rust
/// Build an `IcebergDescriptor` from data already available at the exact
/// moment a Parquet flush succeeds — no re-read of the encoded file.
#[allow(clippy::too_many_arguments)]
fn build_descriptor(
    source: &'static str,
    partition: Option<&str>,
    location_hint: String,
    relative_key: &str,
    record_count: u64,
    file_size_in_bytes: u64,
    storage_target: &'static str,
    schema: &arrow_schema::Schema,
    file_metadata: &parquet::format::FileMetaData,
) -> crate::forwarding::iceberg_descriptor::IcebergDescriptor {
    use crate::forwarding::iceberg_descriptor::{ColumnStat, IcebergDescriptor, schema_version};
    use base64::Engine;

    let mut column_stats = std::collections::HashMap::new();
    if let Some(row_group) = file_metadata.row_groups.first() {
        for (idx, column) in row_group.columns.iter().enumerate() {
            let Some(col_meta) = column.meta_data.as_ref() else {
                continue;
            };
            let physical_type = format!("{:?}", col_meta.type_);
            let (null_count, min, max) = match col_meta.statistics.as_ref() {
                Some(stats) => (
                    stats.null_count.unwrap_or(0).max(0) as u64,
                    stats
                        .min
                        .as_ref()
                        .map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
                    stats
                        .max
                        .as_ref()
                        .map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
                ),
                None => (0, None, None),
            };
            column_stats.insert(
                idx as u32,
                ColumnStat {
                    null_count,
                    min,
                    max,
                    physical_type,
                },
            );
        }
    }

    IcebergDescriptor {
        source: source.to_string(),
        partition: partition.map(|p| p.to_string()),
        file_path: format!("{location_hint}/{relative_key}"),
        file_format: "PARQUET".to_string(),
        record_count,
        file_size_in_bytes,
        storage_target: storage_target.to_string(),
        schema_version: schema_version(schema),
        written_at: chrono::Utc::now(),
        column_stats,
    }
}

/// Best-effort descriptor upload: logs + increments a metric on failure,
/// never returns an error to the caller. A descriptor-sink outage must
/// never fail, retry, or hard-cap the core Parquet-writing path.
///
/// `relative_key` is the Parquet file's own relative key (e.g.
/// `zeek/conn/year=2026/month=07/day=10/abc.parquet`) — NOT
/// `descriptor.file_path`, which is already fully-qualified (see
/// `build_descriptor` above) and would be the wrong thing to upload the
/// descriptor itself under. The descriptor sink's own configured `prefix`
/// (from `IcebergDescriptorS3Config`/`IcebergDescriptorLocalConfig`) is
/// applied transparently by `descriptor_sink` itself — see
/// `build_iceberg_descriptor_sink`/`PrefixedUploadSink` below — so this
/// function always derives the key with an empty prefix.
async fn upload_descriptor(
    descriptor_sink: Arc<dyn UploadSink>,
    descriptor: crate::forwarding::iceberg_descriptor::IcebergDescriptor,
    relative_key: &str,
    source: &'static str,
) {
    let key = crate::forwarding::iceberg_descriptor::build_descriptor_key("", relative_key);
    let bytes = match descriptor.to_json_bytes() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(source, "iceberg descriptor serialization failed: {e}");
            metrics::counter!("iceberg_descriptor_upload_errors", "source" => source).increment(1);
            return;
        }
    };
    match descriptor_sink.upload(&key, bytes).await {
        Ok(()) => {
            metrics::counter!("iceberg_descriptor_uploads", "source" => source).increment(1);
        }
        Err(e) => {
            tracing::warn!(source, "iceberg descriptor upload failed: {e}");
            metrics::counter!("iceberg_descriptor_upload_errors", "source" => source).increment(1);
        }
    }
}
```

- [ ] **Step 5: Update `ParquetWriterHandle::start`/`start_with_stats` to thread `descriptor_sink` through**

Find:
```rust
    pub fn start(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        Self::start_with_stats(
            sink,
            s3,
            config,
            policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
        )
    }

    /// Same as `start`, but records ingested-record counts into a shared,
    /// externally-owned `SourceHourlyStats` (used to feed the admin `/stats`
    /// page from every source through one instance).
    pub fn start_with_stats(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
        source_stats: Arc<crate::stats::SourceHourlyStats>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let capacity = config.channel_capacity.max(1);
        // Capture the source/target labels before `sink`/`s3` are moved into the task.
        let source = sink.source();
        let target = s3.target_label();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<S::Record>(capacity);
        let flush_check = crate::forwarding::s3_sink::flush_check_interval(policy.interval);
        let handle = tokio::spawn(async move {
            let mut writer =
                PartitionedParquetWriter::with_source_stats(sink, s3, config, policy, source_stats);
```

Replace with:
```rust
    pub fn start(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        Self::start_with_stats(
            sink,
            s3,
            config,
            policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
            None,
        )
    }

    /// Same as `start`, but records ingested-record counts into a shared,
    /// externally-owned `SourceHourlyStats` (used to feed the admin `/stats`
    /// page from every source through one instance), and optionally emits
    /// an Iceberg descriptor alongside each successful flush.
    #[allow(clippy::too_many_arguments)]
    pub fn start_with_stats(
        sink: S,
        s3: Arc<dyn UploadSink>,
        config: BufferedWriterConfig,
        policy: FlushPolicy,
        source_stats: Arc<crate::stats::SourceHourlyStats>,
        descriptor_sink: Option<Arc<dyn UploadSink>>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let capacity = config.channel_capacity.max(1);
        // Capture the source/target labels before `sink`/`s3` are moved into the task.
        let source = sink.source();
        let target = s3.target_label();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<S::Record>(capacity);
        let flush_check = crate::forwarding::s3_sink::flush_check_interval(policy.interval);
        let handle = tokio::spawn(async move {
            let mut writer = PartitionedParquetWriter::with_source_stats(
                sink,
                s3,
                config,
                policy,
                source_stats,
                descriptor_sink,
            );
```

- [ ] **Step 6: Update `start_writer<S>()` to accept and forward `descriptor_sink`**

Find:
```rust
#[allow(clippy::too_many_arguments)] // one parameter per BufferedWriterConfig/FlushPolicy field; splitting them into a struct would only move the count, not reduce it
pub(crate) fn start_writer<S: ParquetSink + Default>(
    prefix: String,
    max_buffer_rows: usize,
    flush_threshold_bytes: usize,
    flush_interval_secs: u64,
    channel_capacity: usize,
    max_partitions: usize,
    sink: Arc<dyn UploadSink>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
) -> (ParquetWriterHandle<S>, tokio::task::JoinHandle<()>) {
    let bwc = BufferedWriterConfig {
        connection: unused_s3_connection_placeholder(),
        prefix,
        max_buffer_rows,
        flush_threshold_bytes,
        flush_interval_secs,
        channel_capacity,
        max_partitions,
    };
    let policy = FlushPolicy {
        max_rows: max_buffer_rows,
        max_bytes: flush_threshold_bytes,
        interval: std::time::Duration::from_secs(flush_interval_secs),
    };
    ParquetWriterHandle::start_with_stats(S::default(), sink, bwc, policy, source_stats)
}
```

Replace with:
```rust
#[allow(clippy::too_many_arguments)] // one parameter per BufferedWriterConfig/FlushPolicy field, plus source_stats/descriptor_sink; splitting into a struct would only move the count, not reduce it
pub(crate) fn start_writer<S: ParquetSink + Default>(
    prefix: String,
    max_buffer_rows: usize,
    flush_threshold_bytes: usize,
    flush_interval_secs: u64,
    channel_capacity: usize,
    max_partitions: usize,
    sink: Arc<dyn UploadSink>,
    source_stats: Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn UploadSink>>,
) -> (ParquetWriterHandle<S>, tokio::task::JoinHandle<()>) {
    let bwc = BufferedWriterConfig {
        connection: unused_s3_connection_placeholder(),
        prefix,
        max_buffer_rows,
        flush_threshold_bytes,
        flush_interval_secs,
        channel_capacity,
        max_partitions,
    };
    let policy = FlushPolicy {
        max_rows: max_buffer_rows,
        max_bytes: flush_threshold_bytes,
        interval: std::time::Duration::from_secs(flush_interval_secs),
    };
    ParquetWriterHandle::start_with_stats(S::default(), sink, bwc, policy, source_stats, descriptor_sink)
}
```

- [ ] **Step 7: Add the shared `build_iceberg_descriptor_sink` helper, with a prefix-applying wrapper**

Immediately after `start_writer`'s closing `}`, add:
```rust
/// Wraps another `UploadSink`, transparently prepending a fixed prefix to
/// every key. Used so the descriptor sink's own configured `prefix`
/// (`IcebergDescriptorS3Config`/`IcebergDescriptorLocalConfig`) is applied
/// once, at construction, without threading a separate prefix parameter
/// through `flush_partition`/`upload_descriptor` and every one of the 14
/// per-source `_start`/`_local_start` call sites.
struct PrefixedUploadSink {
    inner: Arc<dyn UploadSink>,
    prefix: String,
}

#[async_trait]
impl UploadSink for PrefixedUploadSink {
    async fn upload(&self, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
        let full_key = format!("{}/{}", self.prefix, key);
        self.inner.upload(&full_key, body).await
    }
    fn target_label(&self) -> &'static str {
        self.inner.target_label()
    }
    fn location_hint(&self) -> String {
        self.inner.location_hint()
    }
}

/// Construct the shared Iceberg descriptor `UploadSink` from `[iceberg]`
/// config, if configured. Called once by `main.rs` and once by
/// `Server::new` (in `src/server/mod.rs`) — each independently builds its
/// own `Arc<dyn UploadSink>` pointed at the same configured destination,
/// since both already have their own `Config` instance and there is no
/// other shared state between them for this. Returns `Ok(None)` when
/// neither `iceberg.s3` nor `iceberg.local` is configured (the common
/// case — feature off, zero behavior change).
pub async fn build_iceberg_descriptor_sink(
    cfg: &crate::config::IcebergConfig,
) -> anyhow::Result<Option<Arc<dyn UploadSink>>> {
    if let Some(s3_cfg) = cfg.s3.as_ref() {
        let sink = crate::forwarding::s3_sink::S3Sink::from_connection(&s3_cfg.connection).await?;
        let sink: Arc<dyn UploadSink> = Arc::new(sink);
        return Ok(Some(wrap_with_prefix(sink, &s3_cfg.prefix)));
    }
    if let Some(local_cfg) = cfg.local.as_ref() {
        let sink =
            crate::forwarding::local_sink::LocalDiskSink::new(local_cfg.directory.clone()).await?;
        let sink: Arc<dyn UploadSink> = Arc::new(sink);
        return Ok(Some(wrap_with_prefix(sink, &local_cfg.prefix)));
    }
    Ok(None)
}

fn wrap_with_prefix(inner: Arc<dyn UploadSink>, prefix: &str) -> Arc<dyn UploadSink> {
    if prefix.is_empty() {
        inner
    } else {
        Arc::new(PrefixedUploadSink {
            inner,
            prefix: prefix.to_string(),
        })
    }
}
```

- [ ] **Step 8: Update every other existing call site of `start_writer`/`start_with_stats`/`with_source_stats` within `buffered_writer.rs`'s own test module**

Search the file for every remaining call to `PartitionedParquetWriter::new(`, `ParquetWriterHandle::start(`, and `start_writer::<` inside `#[cfg(test)] mod tests` — these use `new()`/`start()` (unchanged signatures, defaulting `descriptor_sink` to `None` internally per Steps 1 and 5) and the `start_writer_wires_a_generic_parquet_sink_and_exits_cleanly` test, which calls `start_writer::<TestSink>(...)` directly with 8 positional args. That call needs one more argument. Find:
```rust
        let (handle, join_handle) = start_writer::<TestSink>(
            "test-prefix".to_string(),
            100_000,
            usize::MAX,
            3600,
            256,
            1,
            StdArc::new(UnreachableUploadSink),
            StdArc::new(crate::stats::SourceHourlyStats::new()),
        );
```

Replace with:
```rust
        let (handle, join_handle) = start_writer::<TestSink>(
            "test-prefix".to_string(),
            100_000,
            usize::MAX,
            3600,
            256,
            1,
            StdArc::new(UnreachableUploadSink),
            StdArc::new(crate::stats::SourceHourlyStats::new()),
            None,
        );
```

- [ ] **Step 9: Write a new test proving a descriptor is emitted on successful flush when configured**

Add to `#[cfg(test)] mod tests`:
```rust
    #[tokio::test]
    async fn flush_emits_descriptor_when_descriptor_sink_configured() {
        let s3 = unreachable_s3().await; // Parquet upload target — unreachable is fine, we swap below
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let parquet_sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let descriptor_uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let descriptor_sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: descriptor_uploads.clone(),
        });
        let _ = s3; // silence unused-var warning; kept for signature parity with other tests

        let (cfg, policy) = test_config(1); // flush on first row
        let mut w = PartitionedParquetWriter::with_source_stats(
            MockSink,
            parquet_sink,
            cfg,
            policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
            Some(descriptor_sink),
        );

        w.push("hello".to_string()).await.unwrap();

        let parquet_calls = uploads.lock().unwrap();
        assert_eq!(parquet_calls.len(), 1, "expected one Parquet upload");

        let descriptor_calls = descriptor_uploads.lock().unwrap();
        assert_eq!(descriptor_calls.len(), 1, "expected one descriptor upload");
        assert!(
            descriptor_calls[0].0.ends_with(".json"),
            "descriptor key must end in .json, got: {}",
            descriptor_calls[0].0
        );
        assert!(descriptor_calls[0].1 > 0, "descriptor body must be non-empty");
    }

    #[tokio::test]
    async fn flush_emits_no_descriptor_when_descriptor_sink_is_none() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let parquet_sink: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let (cfg, policy) = test_config(1);
        // descriptor_sink: None — the default via `new()`.
        let mut w = PartitionedParquetWriter::new(MockSink, parquet_sink, cfg, policy);

        w.push("hello".to_string()).await.unwrap();

        // Only the Parquet upload happened; RecordingSink was never given
        // a descriptor destination to record into, so there is nothing
        // more to assert beyond "this did not panic and behaves exactly
        // as before this feature existed" — the real assertion is that
        // flush succeeded at all with descriptor_sink absent.
        assert_eq!(uploads.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn descriptor_upload_failure_does_not_fail_the_flush() {
        struct FailingSink;
        #[async_trait::async_trait]
        impl UploadSink for FailingSink {
            async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
                anyhow::bail!("descriptor destination unreachable")
            }
            fn target_label(&self) -> &'static str {
                "failing"
            }
            fn location_hint(&self) -> String {
                "failing://test".to_string()
            }
        }

        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let parquet_sink: Arc<dyn UploadSink> = Arc::new(RecordingSink { uploads });
        let (cfg, policy) = test_config(1);
        let mut w = PartitionedParquetWriter::with_source_stats(
            MockSink,
            parquet_sink,
            cfg,
            policy,
            Arc::new(crate::stats::SourceHourlyStats::default()),
            Some(Arc::new(FailingSink)),
        );

        // Must succeed — a failing descriptor sink must never fail the
        // Parquet flush itself.
        let result = w.push("hello".to_string()).await;
        assert!(
            result.is_ok(),
            "flush must succeed even when the descriptor sink fails: {result:?}"
        );
    }

    #[tokio::test]
    async fn prefixed_upload_sink_prepends_prefix_to_every_key() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner: Arc<dyn UploadSink> = Arc::new(RecordingSink {
            uploads: uploads.clone(),
        });
        let prefixed = wrap_with_prefix(inner, "_iceberg_descriptors");
        prefixed.upload("zeek/conn/abc.json", vec![1, 2, 3]).await.unwrap();
        let calls = uploads.lock().unwrap();
        assert_eq!(calls[0].0, "_iceberg_descriptors/zeek/conn/abc.json");
    }

    #[test]
    fn wrap_with_prefix_returns_inner_unchanged_when_prefix_empty() {
        let uploads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner: Arc<dyn UploadSink> = Arc::new(RecordingSink { uploads });
        // No way to compare Arc<dyn Trait> pointers cleanly across a trait
        // object boundary in a way that's meaningful here — instead, assert
        // behavior: an empty prefix must not alter the key at all.
        let wrapped = wrap_with_prefix(inner, "");
        assert_eq!(wrapped.target_label(), "recording");
    }
```

- [ ] **Step 10: Run the tests**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib buffered_writer:: -- --test-threads=4
```
Expected: all tests in `buffered_writer::tests` pass, including the 5 new ones (`flush_emits_descriptor_when_descriptor_sink_configured`, `flush_emits_no_descriptor_when_descriptor_sink_is_none`, `descriptor_upload_failure_does_not_fail_the_flush`, `prefixed_upload_sink_prepends_prefix_to_every_key`, `wrap_with_prefix_returns_inner_unchanged_when_prefix_empty`) and all pre-existing ones (confirming `new()`'s unchanged signature and every other pre-existing test still compiles and passes).

- [ ] **Step 11: Run the full lib test suite to confirm no cross-module regressions**

```bash
cargo test --lib 2>&1 | tail -15
```
Expected: all pass (baseline before this task was 732 passed; this task adds roughly 10 new tests across Tasks 1-4 so far).

- [ ] **Step 12: Commit**

```bash
git add src/forwarding/buffered_writer.rs
git commit -m "feat(forwarding): emit Iceberg descriptor on successful Parquet flush"
```

---

## Task 5: Wire syslog (+ structured syslog) — `main.rs`

**Files:**
- Modify: `src/forwarding/syslog_s3.rs` (`syslog_start`, `syslog_local_start`)
- Modify: `src/forwarding/structured_syslog_s3.rs` (`structured_syslog_start`)
- Modify: `src/main.rs` (syslog construction block)
- Test: `tests/syslog_local_integration.rs`

**Interfaces:**
- Consumes: `start_writer::<SyslogSink>()` and `ParquetWriterHandle::start_with_stats` (Task 4, both now take a trailing `descriptor_sink: Option<Arc<dyn UploadSink>>`); `build_iceberg_descriptor_sink()` (Task 4).

- [ ] **Step 1: Add `descriptor_sink` parameter to `syslog_start`/`syslog_local_start`**

In `src/forwarding/syslog_s3.rs`, find:
```rust
pub fn syslog_start(
    cfg: &SyslogS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SyslogS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SyslogSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        usize::MAX, // syslog uses row-count + age triggers only
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1,
        s3,
        source_stats,
    )
}
```

Replace with:
```rust
pub fn syslog_start(
    cfg: &SyslogS3Config,
    s3: std::sync::Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (SyslogS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SyslogSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        usize::MAX, // syslog uses row-count + age triggers only
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1,
        s3,
        source_stats,
        descriptor_sink,
    )
}
```

Find:
```rust
pub fn syslog_local_start(
    cfg: &crate::config::SyslogLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (SyslogS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SyslogSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        usize::MAX, // syslog uses row-count + age triggers only
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1,
        sink,
        source_stats,
    )
}
```

Replace with:
```rust
pub fn syslog_local_start(
    cfg: &crate::config::SyslogLocalConfig,
    sink: std::sync::Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (SyslogS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<SyslogSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        usize::MAX, // syslog uses row-count + age triggers only
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        1,
        sink,
        source_stats,
        descriptor_sink,
    )
}
```

- [ ] **Step 2: Add `descriptor_sink` parameter to `structured_syslog_start`**

In `src/forwarding/structured_syslog_s3.rs`, find:
```rust
pub fn structured_syslog_start(
    cfg: &SyslogS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (StructuredS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
    };

    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        // 7 known payload types + 1 overflow = 8 partitions max.
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: usize::MAX,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start_with_stats(StructuredSyslogSink, s3, bwc, policy, source_stats)
}
```

Replace with:
```rust
pub fn structured_syslog_start(
    cfg: &SyslogS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (StructuredS3Handler, tokio::task::JoinHandle<()>) {
    use crate::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, ParquetWriterHandle,
    };

    let bwc = BufferedWriterConfig {
        connection: cfg.connection.clone(),
        prefix: cfg.prefix.clone(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: cfg.flush_interval_secs,
        channel_capacity: cfg.channel_capacity,
        // 7 known payload types + 1 overflow = 8 partitions max.
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: usize::MAX,
        interval: std::time::Duration::from_secs(cfg.flush_interval_secs),
    };
    ParquetWriterHandle::start_with_stats(
        StructuredSyslogSink,
        s3,
        bwc,
        policy,
        source_stats,
        descriptor_sink,
    )
}
```

- [ ] **Step 3: Wire it in `main.rs`**

Find the syslog block's start (`if config.syslog.enabled {`) and, immediately inside that block before the `structured_handle` construction, add one line building the shared descriptor sink:
```rust
        let descriptor_sink =
            crate::forwarding::buffered_writer::build_iceberg_descriptor_sink(&config.iceberg)
                .await
                .unwrap_or_else(|e| {
                    error!("Failed to construct Iceberg descriptor sink, descriptors disabled: {e}");
                    None
                });
```

Then find each of the three call sites inside that same `if config.syslog.enabled` block and add `descriptor_sink.clone()` as the trailing argument:

Find:
```rust
                            let (sh, wh) =
                                forwarding::structured_syslog_s3::structured_syslog_start(
                                    ss3_cfg,
                                    Arc::new(sink),
                                    source_stats.clone(),
                                );
```
Replace with:
```rust
                            let (sh, wh) =
                                forwarding::structured_syslog_s3::structured_syslog_start(
                                    ss3_cfg,
                                    Arc::new(sink),
                                    source_stats.clone(),
                                    descriptor_sink.clone(),
                                );
```

Find:
```rust
                    let (handler, writer_handle) = forwarding::syslog_s3::syslog_start(
                        s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
```
Replace with:
```rust
                    let (handler, writer_handle) = forwarding::syslog_s3::syslog_start(
                        s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
```

Find:
```rust
                    let (handler, writer_handle) = forwarding::syslog_s3::syslog_local_start(
                        local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
```
Replace with:
```rust
                    let (handler, writer_handle) = forwarding::syslog_s3::syslog_local_start(
                        local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
```

- [ ] **Step 4: Add an integration test proving syslog wires the descriptor through end-to-end**

Read `tests/syslog_local_integration.rs` first to match its existing style/imports exactly, then append a new test function to it:
```rust
#[tokio::test]
async fn syslog_local_start_emits_iceberg_descriptor_when_configured() {
    let parquet_dir = tempfile::tempdir().expect("parquet tempdir");
    let descriptor_dir = tempfile::tempdir().expect("descriptor tempdir");

    let parquet_sink = std::sync::Arc::new(
        logthing::forwarding::local_sink::LocalDiskSink::new(parquet_dir.path().to_path_buf())
            .await
            .expect("LocalDiskSink::new (parquet)"),
    );
    let descriptor_sink: std::sync::Arc<dyn logthing::forwarding::buffered_writer::UploadSink> =
        std::sync::Arc::new(
            logthing::forwarding::local_sink::LocalDiskSink::new(
                descriptor_dir.path().to_path_buf(),
            )
            .await
            .expect("LocalDiskSink::new (descriptor)"),
        );

    let cfg = logthing::config::SyslogLocalConfig {
        directory: parquet_dir.path().to_path_buf(),
        prefix: "syslog".to_string(),
        max_buffer_rows: 1, // flush immediately on first row
        flush_interval_secs: 3600,
        channel_capacity: 64,
    };

    let (handler, writer_task) = logthing::forwarding::syslog_s3::syslog_local_start(
        &cfg,
        parquet_sink,
        std::sync::Arc::new(logthing::stats::SourceHourlyStats::new()),
        Some(descriptor_sink),
    );

    // Push one syslog message through the handler to trigger a flush.
    // (Match the exact SyslogHandler call already used by the other tests
    // in this file for constructing/pushing a message — copy that
    // construction here instead of guessing a new one.)
    drop(handler); // closes the channel; background task flushes on exit
    tokio::time::timeout(std::time::Duration::from_secs(5), writer_task)
        .await
        .expect("writer task exits within 5s")
        .expect("writer task must not panic");

    // A descriptor JSON must exist somewhere under descriptor_dir.
    let mut found = false;
    let mut stack = vec![descriptor_dir.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = tokio::fs::read_dir(&dir).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
                found = true;
                let contents = tokio::fs::read_to_string(&path).await.unwrap();
                let v: serde_json::Value = serde_json::from_str(&contents).unwrap();
                assert_eq!(v["source"], "syslog");
                assert_eq!(v["file_format"], "PARQUET");
            }
        }
    }
    assert!(found, "expected at least one descriptor .json file under {descriptor_dir:?}");
}
```

**Note**: this test's message-push step is deliberately left for the
implementer to fill in by copying the exact pattern already used by
`syslog_local_start_wires_handler_and_join_handle` (or the nearest
existing test in this file that pushes one real message through a
`SyslogHandler` built from `syslog_local_start`'s returned handler) —
read that test first and reuse its exact message-construction/push call,
since the exact `SyslogHandler` trait method signature isn't reproduced
in this plan and must match the real trait exactly.

- [ ] **Step 5: Run it**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --test syslog_local_integration -- --nocapture
```
Expected: all tests in this file pass, including the new one.

- [ ] **Step 6: Confirm the whole crate still builds (main.rs changes touch the binary target, not just the lib)**

```bash
cargo build 2>&1 | tail -30
```
Expected: clean build.

- [ ] **Step 7: Commit**

```bash
git add src/forwarding/syslog_s3.rs src/forwarding/structured_syslog_s3.rs src/main.rs tests/syslog_local_integration.rs
git commit -m "feat(syslog): wire Iceberg descriptor sink through syslog + structured syslog writers"
```

---

## Task 6: Wire ipfix — `main.rs`

**Files:**
- Modify: `src/forwarding/ipfix_s3.rs` (`ipfix_start`, `ipfix_local_start`)
- Modify: `src/main.rs` (ipfix construction block)
- Test: `tests/ipfix_local_integration.rs`

Same pattern as Task 5, applied to ipfix. Concretely:

- [ ] **Step 1**: In `src/forwarding/ipfix_s3.rs`, add `descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>` as the trailing parameter to both `ipfix_start` and `ipfix_local_start` (exact current bodies shown in this plan's research — both call `start_writer::<IpfixSink>(cfg.prefix.clone(), cfg.max_buffer_rows, cfg.flush_threshold_bytes, cfg.flush_interval_secs, cfg.channel_capacity, 1, <sink>, source_stats)`); add `descriptor_sink` as the 9th argument to both `start_writer::<IpfixSink>(...)` calls.

- [ ] **Step 2**: In `src/main.rs`'s ipfix block (`if config.ipfix.enabled {`), reuse the SAME `descriptor_sink` local variable built in Task 5's Step 3 (it's constructed once near the top of `async_main`, before the syslog block — Task 5 already added it there, so this task does NOT construct it again, just passes `descriptor_sink.clone()` as the trailing argument to both `forwarding::ipfix_s3::ipfix_start(...)` and `forwarding::ipfix_s3::ipfix_local_start(...)` call sites).

- [ ] **Step 3**: Append a new test to `tests/ipfix_local_integration.rs`, following the exact same shape as Task 5 Step 4's syslog test but using `logthing::config::IpfixLocalConfig`, `logthing::forwarding::ipfix_s3::ipfix_local_start`, and reusing this file's own existing message-push pattern (read the file first, copy its exact `IpfixHandler`/flow-record push call — this file already has a working example in `ipfix_flows_appear_as_parquet_on_local_disk`, shown earlier in this project's exploration: it builds a `FlowRecord` via a `make_flow_record` helper and calls `handler.handle_flows(vec![record], addr)` or pushes via the writer handle directly, matching whichever pattern that test uses). Assert `v["source"] == "ipfix"` in the descriptor JSON.

- [ ] **Step 4**: Run `cargo test --test ipfix_local_integration -- --nocapture` and `cargo build`. Expected: all pass, clean build.

- [ ] **Step 5**: Commit:
```bash
git add src/forwarding/ipfix_s3.rs src/main.rs tests/ipfix_local_integration.rs
git commit -m "feat(ipfix): wire Iceberg descriptor sink through ipfix writer"
```

---

## Task 7: Wire zeek — `main.rs`

**Files:**
- Modify: `src/forwarding/zeek_s3.rs` (`zeek_start`, `zeek_local_start`)
- Modify: `src/main.rs` (zeek construction block)
- Test: `tests/zeek_local_integration.rs`

Same pattern as Task 6:

- [ ] **Step 1**: In `src/forwarding/zeek_s3.rs`, add `descriptor_sink: Option<std::sync::Arc<dyn crate::forwarding::buffered_writer::UploadSink>>` as the trailing parameter to `zeek_start`/`zeek_local_start` (both currently call `start_writer::<ZeekSink>(cfg.prefix.clone(), cfg.max_buffer_rows, cfg.flush_threshold_bytes, cfg.flush_interval_secs, cfg.channel_capacity, DEFAULT_MAX_ZEEK_PARTITIONS, <sink>, source_stats)`); add `descriptor_sink` as the 9th call argument in both.

- [ ] **Step 2**: In `src/main.rs`'s zeek block, pass `descriptor_sink.clone()` (the shared variable from Task 5) as the trailing argument to both `forwarding::zeek_s3::zeek_start(...)` and `forwarding::zeek_s3::zeek_local_start(...)`.

- [ ] **Step 3**: Append a new test to `tests/zeek_local_integration.rs` mirroring Task 5's pattern — build a `LocalDiskSink`-backed descriptor destination, call `zeek_local_start` with it, push one record through this file's existing message-construction pattern, flush, assert a `.json` file appears under the descriptor directory with `source == "zeek"`.

- [ ] **Step 4**: Run `cargo test --test zeek_local_integration -- --nocapture` and `cargo build`. Expected: all pass.

- [ ] **Step 5**: Commit:
```bash
git add src/forwarding/zeek_s3.rs src/main.rs tests/zeek_local_integration.rs
git commit -m "feat(zeek): wire Iceberg descriptor sink through zeek writer"
```

---

## Task 8: Wire suricata — `main.rs`

**Files:**
- Modify: `src/forwarding/suricata_s3.rs` (`suricata_start`, `suricata_local_start`)
- Modify: `src/main.rs` (suricata construction block)
- Test: `tests/suricata_local_integration.rs`

Same pattern as Task 7:

- [ ] **Step 1**: In `src/forwarding/suricata_s3.rs`, add the trailing `descriptor_sink` parameter to `suricata_start`/`suricata_local_start` (both call `start_writer::<SuricataSink>(cfg.prefix.clone(), cfg.max_buffer_rows, cfg.flush_threshold_bytes, cfg.flush_interval_secs, cfg.channel_capacity, DEFAULT_MAX_SURICATA_PARTITIONS, <sink>, source_stats)`); add as the 9th argument.

- [ ] **Step 2**: In `src/main.rs`'s suricata block, pass `descriptor_sink.clone()` to both `forwarding::suricata_s3::suricata_start(...)` and `forwarding::suricata_s3::suricata_local_start(...)`.

- [ ] **Step 3**: Append a new test to `tests/suricata_local_integration.rs` mirroring the same pattern, asserting `source == "suricata"`.

- [ ] **Step 4**: Run `cargo test --test suricata_local_integration -- --nocapture` and `cargo build`. Expected: all pass.

- [ ] **Step 5**: Commit:
```bash
git add src/forwarding/suricata_s3.rs src/main.rs tests/suricata_local_integration.rs
git commit -m "feat(suricata): wire Iceberg descriptor sink through suricata writer"
```

---

## Task 9: Wire sflow — `main.rs`

**Files:**
- Modify: `src/forwarding/sflow_s3.rs` (`sflow_start`, `sflow_local_start`)
- Modify: `src/main.rs` (sflow construction block)
- Test: `tests/sflow_local_integration.rs`

Same pattern:

- [ ] **Step 1**: In `src/forwarding/sflow_s3.rs`, add the trailing `descriptor_sink` parameter to `sflow_start`/`sflow_local_start` (both call `start_writer::<SflowSink>(cfg.prefix.clone(), cfg.max_buffer_rows, cfg.flush_threshold_bytes, cfg.flush_interval_secs, cfg.channel_capacity, SFLOW_MAX_PARTITIONS, <sink>, source_stats)`); add as the 9th argument.

- [ ] **Step 2**: In `src/main.rs`'s sflow block, pass `descriptor_sink.clone()` to both `forwarding::sflow_s3::sflow_start(...)` and `forwarding::sflow_s3::sflow_local_start(...)`.

- [ ] **Step 3**: Append a new test to `tests/sflow_local_integration.rs` mirroring the same pattern, asserting `source == "sflow"`.

- [ ] **Step 4**: Run `cargo test --test sflow_local_integration -- --nocapture` and `cargo build`. Expected: all pass.

- [ ] **Step 5**: Commit:
```bash
git add src/forwarding/sflow_s3.rs src/main.rs tests/sflow_local_integration.rs
git commit -m "feat(sflow): wire Iceberg descriptor sink through sflow writer"
```

---

## Task 10: Wire WEF — `src/server/mod.rs`

**Files:**
- Modify: `src/forwarding/parquet_s3.rs` (`wef_start`, `wef_local_start`)
- Modify: `src/server/mod.rs` (WEF construction block, inside `Server::new`)
- Test: `tests/wef_local_integration.rs`

**Note**: unlike Tasks 5-9, WEF (and HEC in Task 11) are constructed inside `Server::new` in `src/server/mod.rs`, not in `main.rs` — `Server::new` receives its own `config: Config` parameter, so it builds its OWN `descriptor_sink` via `build_iceberg_descriptor_sink` (does not share the one `main.rs` builds).

- [ ] **Step 1: Add `descriptor_sink` parameter to `wef_start`/`wef_local_start`**

In `src/forwarding/parquet_s3.rs`, find:
```rust
pub fn wef_start(
    cfg: &WefS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (
    crate::forwarding::buffered_writer::ParquetWriterHandle<WefSink>,
    tokio::task::JoinHandle<()>,
) {
    crate::forwarding::buffered_writer::start_writer::<WefSink>(
        cfg.prefix.clone(), // "" for behavior-preserving empty-prefix layout
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        0, // unlimited partitions — EventIDs are bounded in practice
        s3,
        source_stats,
    )
}
```

Replace with:
```rust
pub fn wef_start(
    cfg: &WefS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (
    crate::forwarding::buffered_writer::ParquetWriterHandle<WefSink>,
    tokio::task::JoinHandle<()>,
) {
    crate::forwarding::buffered_writer::start_writer::<WefSink>(
        cfg.prefix.clone(), // "" for behavior-preserving empty-prefix layout
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        0, // unlimited partitions — EventIDs are bounded in practice
        s3,
        source_stats,
        descriptor_sink,
    )
}
```

Find:
```rust
pub fn wef_local_start(
    cfg: &crate::config::WefLocalConfig,
    sink: Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (
    crate::forwarding::buffered_writer::ParquetWriterHandle<WefSink>,
    tokio::task::JoinHandle<()>,
) {
    crate::forwarding::buffered_writer::start_writer::<WefSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        0,
        sink,
        source_stats,
    )
}
```

Replace with:
```rust
pub fn wef_local_start(
    cfg: &crate::config::WefLocalConfig,
    sink: Arc<crate::forwarding::local_sink::LocalDiskSink>,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (
    crate::forwarding::buffered_writer::ParquetWriterHandle<WefSink>,
    tokio::task::JoinHandle<()>,
) {
    crate::forwarding::buffered_writer::start_writer::<WefSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        0,
        sink,
        source_stats,
        descriptor_sink,
    )
}
```

- [ ] **Step 2: Wire it in `src/server/mod.rs`**

Find:
```rust
        // Initialize WEF→S3 and WEF→local Parquet forwarders via the generic
        // buffered writer. Each target is attempted independently — a failed
        // S3Sink construction does not prevent a healthy `.local` construction
        // from still populating `parquet_local_sender`, and vice versa.
        let mut wef_worker_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let mut parquet_s3_sender = None;
        let mut parquet_local_sender = None;

        if let Some(wef_s3_cfg) = config.wef.s3.as_ref() {
```

Replace with:
```rust
        // Initialize WEF→S3 and WEF→local Parquet forwarders via the generic
        // buffered writer. Each target is attempted independently — a failed
        // S3Sink construction does not prevent a healthy `.local` construction
        // from still populating `parquet_local_sender`, and vice versa.
        let mut wef_worker_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let mut parquet_s3_sender = None;
        let mut parquet_local_sender = None;

        let descriptor_sink =
            crate::forwarding::buffered_writer::build_iceberg_descriptor_sink(&config.iceberg)
                .await
                .unwrap_or_else(|e| {
                    error!("Failed to construct Iceberg descriptor sink, descriptors disabled: {e}");
                    None
                });

        if let Some(wef_s3_cfg) = config.wef.s3.as_ref() {
```

Find:
```rust
                    let (handle, join_handle) = crate::forwarding::parquet_s3::wef_start(
                        wef_s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
```
Replace with:
```rust
                    let (handle, join_handle) = crate::forwarding::parquet_s3::wef_start(
                        wef_s3_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
```

Find:
```rust
                    let (handle, join_handle) = crate::forwarding::parquet_s3::wef_local_start(
                        wef_local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                    );
```
Replace with:
```rust
                    let (handle, join_handle) = crate::forwarding::parquet_s3::wef_local_start(
                        wef_local_cfg,
                        Arc::new(sink),
                        source_stats.clone(),
                        descriptor_sink.clone(),
                    );
```

(This same `descriptor_sink` local variable, now in scope for the rest of `Server::new`, is reused by Task 11's HEC wiring below it in the same function — Task 11 does not construct it again.)

- [ ] **Step 3**: Append a new test to `tests/wef_local_integration.rs`, following the same pattern as Task 5 but using `logthing::config::WefLocalConfig` and `logthing::forwarding::parquet_s3::wef_local_start` — read this file's existing test(s) first to copy its exact WEF-event construction/push pattern, then assert a `.json` descriptor appears with `source == "wef"`.

- [ ] **Step 4**: Run `cargo test --test wef_local_integration -- --nocapture` and `cargo build`. Expected: all pass.

- [ ] **Step 5**: Commit:
```bash
git add src/forwarding/parquet_s3.rs src/server/mod.rs tests/wef_local_integration.rs
git commit -m "feat(wef): wire Iceberg descriptor sink through WEF writer"
```

---

## Task 11: Wire HEC — `src/server/mod.rs`

**Files:**
- Modify: `src/forwarding/generic_s3.rs` (`hec_start`, `hec_local_start`)
- Modify: `src/server/mod.rs` (HEC construction block, reuses the `descriptor_sink` variable Task 10 already constructed)
- Test: `tests/hec_local_integration.rs`

- [ ] **Step 1: Add `descriptor_sink` parameter to `hec_start`/`hec_local_start`**

In `src/forwarding/generic_s3.rs`, find:
```rust
pub fn hec_start(
    cfg: &HecS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    max_partitions: usize,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (GenericS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<GenericSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        max_partitions,
        s3,
        source_stats,
    )
}
```

Replace with:
```rust
pub fn hec_start(
    cfg: &HecS3Config,
    s3: Arc<crate::forwarding::s3_sink::S3Sink>,
    max_partitions: usize,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (GenericS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<GenericSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        max_partitions,
        s3,
        source_stats,
        descriptor_sink,
    )
}
```

Find:
```rust
pub fn hec_local_start(
    cfg: &crate::config::GenericLocalConfig,
    sink: Arc<crate::forwarding::local_sink::LocalDiskSink>,
    max_partitions: usize,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
) -> (GenericS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<GenericSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        max_partitions,
        sink,
        source_stats,
    )
}
```

Replace with:
```rust
pub fn hec_local_start(
    cfg: &crate::config::GenericLocalConfig,
    sink: Arc<crate::forwarding::local_sink::LocalDiskSink>,
    max_partitions: usize,
    source_stats: std::sync::Arc<crate::stats::SourceHourlyStats>,
    descriptor_sink: Option<Arc<dyn crate::forwarding::buffered_writer::UploadSink>>,
) -> (GenericS3Handler, tokio::task::JoinHandle<()>) {
    crate::forwarding::buffered_writer::start_writer::<GenericSink>(
        cfg.prefix.clone(),
        cfg.max_buffer_rows,
        cfg.flush_threshold_bytes,
        cfg.flush_interval_secs,
        cfg.channel_capacity,
        max_partitions,
        sink,
        source_stats,
        descriptor_sink,
    )
}
```

- [ ] **Step 2: Wire it in `src/server/mod.rs`**

Find:
```rust
                        let (handler, join_handle) = crate::forwarding::generic_s3::hec_start(
                            s3_cfg,
                            Arc::new(sink),
                            config.hec.max_sourcetype_partitions,
                            source_stats.clone(),
                        );
```
Replace with:
```rust
                        let (handler, join_handle) = crate::forwarding::generic_s3::hec_start(
                            s3_cfg,
                            Arc::new(sink),
                            config.hec.max_sourcetype_partitions,
                            source_stats.clone(),
                            descriptor_sink.clone(),
                        );
```

Find:
```rust
                        let (handler, join_handle) = crate::forwarding::generic_s3::hec_local_start(
                            local_cfg,
                            Arc::new(sink),
                            config.hec.max_sourcetype_partitions,
                            source_stats.clone(),
                        );
```
Replace with:
```rust
                        let (handler, join_handle) = crate::forwarding::generic_s3::hec_local_start(
                            local_cfg,
                            Arc::new(sink),
                            config.hec.max_sourcetype_partitions,
                            source_stats.clone(),
                            descriptor_sink.clone(),
                        );
```

(`descriptor_sink` here is the SAME variable Task 10 already constructed earlier in `Server::new` — do not construct it again in this task.)

- [ ] **Step 3**: Append a new test to `tests/hec_local_integration.rs`, following the same pattern, using `logthing::config::GenericLocalConfig` and `logthing::forwarding::generic_s3::hec_local_start` — read this file's existing test(s) first to copy its exact record-construction/push pattern, then assert a `.json` descriptor appears with `source == "hec"`.

- [ ] **Step 4**: Run `cargo test --test hec_local_integration -- --nocapture` and `cargo build`. Expected: all pass.

- [ ] **Step 5**: Run the FULL test suite to confirm all 7 sources' wiring is consistent and nothing regressed:
```bash
cargo test 2>&1 | tail -30
```
Expected: all pass.

- [ ] **Step 6**: Commit:
```bash
git add src/forwarding/generic_s3.rs src/server/mod.rs tests/hec_local_integration.rs
git commit -m "feat(hec): wire Iceberg descriptor sink through HEC writer"
```

---

## Task 12: E2E — extend one existing docker-compose config to exercise `[iceberg]`

**Files:**
- Modify: one existing config file under `tests/e2e/simulation-environment/config/` (e.g. `logthing.toml`) and its paired docker-compose service definition
- Modify: the paired verifier script (mirroring the existing `wef-local-verifier` pattern under `tests/e2e/simulation-environment/`)

**Interfaces:**
- Consumes: the `[iceberg]` config section (Task 3), which the running server picks up via `main.rs`'s wiring (Task 5) — this is the one tier that exercises the full startup path, not a source's wrapper function in isolation.

- [ ] **Step 1**: Read `tests/e2e/simulation-environment/docker-compose.yml` and the existing `wef-local-verifier` service definition + its `entrypoint.py` (referenced earlier in this project as `tests/e2e/simulation-environment/wef-local-verifier/entrypoint.py`) to learn the exact pattern: a config file enabling a local-disk output, a docker volume mount shared between the `logthing` service and a verifier container, and a small Python script polling for expected files.

- [ ] **Step 2**: Pick one existing e2e config (the one already used for local-disk WEF verification is the natural fit, since it already proves the full local-disk startup path) and add:
```toml
[iceberg.local]
directory = "/var/log/logthing/iceberg-descriptors"
prefix = "_iceberg_descriptors"
```
to it (adjust the exact path to match whatever volume convention that compose file already uses for its other local-disk outputs — read the file first to match it exactly, do not invent a new volume mount pattern).

- [ ] **Step 3**: Add a small descriptor-verification step to the existing verifier's `entrypoint.py` (or create a new small `iceberg-descriptor-verifier` service mirroring `wef-local-verifier`'s exact shape if the existing verifier's scope doesn't naturally extend) — polling the shared volume for at least one `*.json` file, parsing it, and asserting it has `source`, `file_path`, `record_count` keys with sane values. Match the existing verifier's polling/timeout/exit-code conventions exactly (read `wef-local-verifier/entrypoint.py` first).

- [ ] **Step 4**: Run the e2e simulation environment locally to confirm the new verification passes (this is the one step in this plan that requires Docker; if Docker isn't available in this environment, run `docker compose config` at minimum to confirm the YAML is valid, and note in the task report that full e2e execution needs to be verified in an environment with Docker):
```bash
cd tests/e2e/simulation-environment
docker compose config >/dev/null && echo "compose file valid"
```
If Docker is available, follow this directory's own existing README/runbook for how the other verifiers are normally invoked, and run the same way.

- [ ] **Step 5**: Commit:
```bash
git add tests/e2e/simulation-environment/
git commit -m "test(e2e): verify [iceberg] descriptor output end-to-end"
```

---

## Task 13: Documentation — README.md + logthing.toml

**Files:**
- Modify: `README.md`
- Modify: `logthing.toml`

- [ ] **Step 1**: In `README.md`'s "Configuration Sources"/environment-variables section (the one extended by the prior bind-port-env-vars feature), add a short paragraph documenting `[iceberg]`:
```markdown
### Iceberg descriptor output

Optionally, logthing can emit a small JSON "descriptor" file alongside
every Parquet file it writes, describing the file (row count, byte size,
partition, per-column stats, fully-qualified location) for an external
Apache Iceberg committer process — logthing itself has no Iceberg
dependency and never talks to a catalog. Enable it with `[iceberg.s3]` or
`[iceberg.local]` in `logthing.toml` (mirroring every other source's
`.s3`/`.local` shape), or via `WEF__ICEBERG__S3__BUCKET` etc. Configuring
both `iceberg.s3` and `iceberg.local` simultaneously is a startup error —
unlike other sources, the descriptor sink supports exactly one
destination.
```

- [ ] **Step 2**: In `logthing.toml`, add a commented-out example block near the other optional persistence examples (matching the existing `# [syslog.s3]` comment-block style):
```toml
# Optional: emit a small JSON "descriptor" alongside every Parquet file,
# for an external Apache Iceberg committer process. logthing has no
# Iceberg dependency itself. Configure at most one of [iceberg.s3] /
# [iceberg.local] — configuring both is a startup error.
# [iceberg.s3]
# endpoint   = "http://localhost:9000"
# bucket     = "logthing-iceberg-descriptors"
# region     = "us-east-1"
# access_key = "minioadmin"
# secret_key = "minioadmin"
# prefix     = "_iceberg_descriptors"   # env: WEF__ICEBERG__S3__PREFIX
```

- [ ] **Step 3**: Sanity-check the config still parses:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib load_reads_configuration_file -- --nocapture
```
Expected: pass (the new block is commented out, so it doesn't affect parsing — this just confirms nothing else broke).

- [ ] **Step 4**: Commit:
```bash
git add README.md logthing.toml
git commit -m "docs: document [iceberg] descriptor sink"
```

---

## Final Verification

- [ ] **Step 1**: Run the full test suite:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test 2>&1 | tail -40
```
Expected: all pass, including every new test from Tasks 1-11.

- [ ] **Step 2**: Confirm diff scope:
```bash
git diff master --stat
```
Expected: `Cargo.toml`, `Cargo.lock`, `README.md`, `logthing.toml`, `docs/superpowers/specs/2026-07-10-iceberg-descriptor-design.md`, `docs/superpowers/plans/2026-07-10-iceberg-descriptor.md`, `src/config/mod.rs`, `src/forwarding/mod.rs`, `src/forwarding/buffered_writer.rs`, `src/forwarding/iceberg_descriptor.rs`, `src/forwarding/s3_sink.rs`, `src/forwarding/local_sink.rs`, `src/forwarding/syslog_s3.rs`, `src/forwarding/structured_syslog_s3.rs`, `src/forwarding/ipfix_s3.rs`, `src/forwarding/zeek_s3.rs`, `src/forwarding/suricata_s3.rs`, `src/forwarding/sflow_s3.rs`, `src/forwarding/parquet_s3.rs`, `src/forwarding/generic_s3.rs`, `src/main.rs`, `src/server/mod.rs`, all 7 `tests/*_local_integration.rs` files, plus e2e config/verifier files — no other files.

- [ ] **Step 3**: Confirm no `iceberg-rust` or any Iceberg-library dependency was added:
```bash
grep -i "iceberg" Cargo.toml
```
Expected: no matches (only `base64` was added, and it's unrelated to any Iceberg library).
