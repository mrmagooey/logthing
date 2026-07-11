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
        let key = build_descriptor_key("", "zeek/conn/year=2026/month=07/day=10/abc-123.parquet");
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
