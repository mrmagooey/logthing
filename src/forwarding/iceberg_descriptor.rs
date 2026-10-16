//! Iceberg "descriptor" output — a small JSON file emitted alongside each
//! Parquet flush, carrying everything an external Iceberg committer needs
//! to build a real Iceberg manifest entry without re-reading the Parquet
//! file: row count, byte size, partition, per-column stats, and a
//! fully-qualified file location. logthing has no Iceberg library
//! dependency and never builds real Iceberg manifests/catalogs itself —
//! that is entirely the external committer's job.

use std::collections::HashMap;

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
    /// Lowercase-hex SHA-256 of the exact Parquet bytes uploaded. A corruption /
    /// consistency check only: it sits beside the data, so it is NOT tamper evidence
    /// (see docs/object-lock.md).
    pub sha256: String,
    /// `"s3"` or `"local"` — same value as `UploadSink::target_label()`
    /// for the sink that wrote the described Parquet file.
    pub storage_target: String,
    /// Hash of the Arrow schema's field names, types and nullability, computed at flush
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

/// Field separator inside the canonical schema string.
const FIELD_SEP: char = '\x1f';
/// Record separator (end of one field) inside the canonical schema string.
const RECORD_SEP: char = '\x1e';

/// Hand-written canonical name of an Arrow type, independent of `Debug` output
/// (which is not a stability contract across arrow releases). `None` for a type
/// without an explicit mapping; callers decide how to degrade.
fn canonical_type(dt: &arrow_schema::DataType) -> Option<String> {
    use arrow_schema::{DataType as D, TimeUnit};
    let simple = match dt {
        D::Null => "null",
        D::Boolean => "bool",
        D::Int8 => "i8",
        D::Int16 => "i16",
        D::Int32 => "i32",
        D::Int64 => "i64",
        D::UInt8 => "u8",
        D::UInt16 => "u16",
        D::UInt32 => "u32",
        D::UInt64 => "u64",
        D::Float16 => "f16",
        D::Float32 => "f32",

        D::Float64 => "f64",
        D::Utf8 => "utf8",
        D::LargeUtf8 => "large_utf8",
        D::Binary => "binary",
        D::LargeBinary => "large_binary",
        D::Date32 => "date32",
        D::Date64 => "date64",
        D::Timestamp(unit, tz) => {
            let unit = match unit {
                TimeUnit::Second => "s",
                TimeUnit::Millisecond => "ms",
                TimeUnit::Microsecond => "us",
                TimeUnit::Nanosecond => "ns",
            };
            return Some(format!("ts({unit},{})", tz.as_deref().unwrap_or("")));
        }
        D::List(f) => return Some(format!("list<{}>", canonical_field(f)?)),
        D::LargeList(f) => return Some(format!("large_list<{}>", canonical_field(f)?)),
        D::Map(f, sorted) => {
            return Some(format!(
                "map<{},{}>",
                canonical_field(f)?,
                u8::from(*sorted)
            ));
        }
        _ => return None,
    };
    Some(simple.to_string())
}

/// Canonical `name:type:nullable` for a nested field.
fn canonical_field(f: &arrow_schema::Field) -> Option<String> {
    Some(format!(
        "{}:{}:{}",
        f.name(),
        canonical_type(f.data_type())?,
        u8::from(f.is_nullable())
    ))
}

/// Canonical string a schema hashes over: per field,
/// `name \x1f type \x1f nullable(0/1) \x1e`. A type without an explicit mapping
/// degrades to a prefixed `Debug` form (still deterministic per toolchain); a unit
/// test asserts no schema this crate builds takes that path.
fn canonical_schema(schema: &arrow_schema::Schema) -> String {
    let mut out = String::new();
    for field in schema.fields() {
        let ty = canonical_type(field.data_type())
            .unwrap_or_else(|| format!("unmapped:{:?}", field.data_type()));
        out.push_str(field.name());
        out.push(FIELD_SEP);
        out.push_str(&ty);
        out.push(FIELD_SEP);
        out.push(if field.is_nullable() { '1' } else { '0' });
        out.push(RECORD_SEP);
    }
    out
}

/// Deterministic version of an Arrow schema: the first 16 hex chars of the SHA-256
/// of its canonical form (field names, types and nullability, in order). Stable
/// across processes, toolchains and arrow upgrades; changes only when the schema does.
pub fn schema_version(schema: &arrow_schema::Schema) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(canonical_schema(schema).as_bytes())[..8])
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
    use arrow_schema::{DataType, Field, Schema, TimeUnit};
    use std::sync::Arc;

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
            sha256: SAMPLE_SHA256.to_string(),
            storage_target: "s3".to_string(),
            schema_version: "deadbeef".to_string(),
            written_at: "2026-07-10T12:00:00Z".parse().unwrap(),
            column_stats,
        }
    }

    const SAMPLE_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn test_descriptor_json_contains_sha256_field() {
        let d = sample_descriptor();
        let v: serde_json::Value = serde_json::from_slice(&d.to_json_bytes().unwrap()).unwrap();
        assert_eq!(v["sha256"], SAMPLE_SHA256);
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
    fn test_schema_version_changes_with_nullability() {
        let strict = Schema::new(vec![Field::new("a", DataType::Utf8, false)]);
        let loose = Schema::new(vec![Field::new("a", DataType::Utf8, true)]);
        assert_ne!(schema_version(&strict), schema_version(&loose));
    }

    #[test]
    fn test_schema_version_changes_with_field_order_and_name() {
        let ab = Schema::new(vec![
            Field::new("a", DataType::Utf8, true),
            Field::new("b", DataType::Utf8, true),
        ]);
        let ba = Schema::new(vec![
            Field::new("b", DataType::Utf8, true),
            Field::new("a", DataType::Utf8, true),
        ]);
        assert_ne!(schema_version(&ab), schema_version(&ba));
        // Separators prevent ("ab","c") colliding with ("a","bc") style merges.
        let x = Schema::new(vec![Field::new("a\x1futf8", DataType::Utf8, true)]);
        let y = Schema::new(vec![Field::new("a", DataType::Utf8, true)]);
        assert_ne!(schema_version(&x), schema_version(&y));
    }

    #[test]
    fn test_schema_version_changes_with_timestamp_unit_and_tz() {
        let v = |u, tz: Option<&str>| {
            schema_version(&Schema::new(vec![Field::new(
                "t",
                DataType::Timestamp(u, tz.map(Into::into)),
                false,
            )]))
        };
        let base = v(TimeUnit::Microsecond, Some("UTC"));
        assert_ne!(base, v(TimeUnit::Nanosecond, Some("UTC")));
        assert_ne!(base, v(TimeUnit::Microsecond, None));
        assert_ne!(base, v(TimeUnit::Microsecond, Some("Europe/Paris")));
    }

    #[test]
    fn test_schema_version_golden_value() {
        let schema = Schema::new(vec![
            Field::new("a", DataType::Utf8, false),
            Field::new("b", DataType::UInt16, true),
            Field::new(
                "t",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
        ]);
        assert_eq!(
            canonical_schema(&schema),
            "a\x1futf8\x1f0\x1eb\x1fu16\x1f1\x1et\x1fts(us,UTC)\x1f0\x1e"
        );
        assert_eq!(schema_version(&schema), "c158563d95a950f7");
        assert_eq!(schema_version(&schema).len(), 16);
    }

    #[test]
    fn test_canonical_type_recurses_into_list_and_map() {
        let item = Arc::new(Field::new("item", DataType::Int64, true));
        assert_eq!(
            canonical_type(&DataType::List(item.clone())).unwrap(),
            "list<item:i64:1>"
        );
        let entries = Arc::new(Field::new(
            "entries",
            DataType::Struct(vec![Field::new("k", DataType::Utf8, false)].into()),
            false,
        ));
        // Struct is not mapped, so a map over it is not either.
        assert!(canonical_type(&DataType::Map(entries, false)).is_none());
        assert_eq!(canonical_type(&DataType::Boolean).as_deref(), Some("bool"));
    }

    /// Every schema this crate builds hashes without touching the `Debug` fallback.
    #[test]
    fn test_every_crate_schema_is_fully_mapped() {
        use crate::{forwarding, suricata, zeek};
        let mut schemas = vec![
            forwarding::syslog_s3::syslog_schema(),
            forwarding::structured_syslog_s3::structured_syslog_schema(),
            forwarding::otlp_s3::otlp_schema(),
            forwarding::aggregate::rule_schema(&["g".to_string()], &[]),
            suricata::schema::envelope_schema(),
            zeek::schema::envelope_schema(),
        ];
        for p in ["conn", "dns", "http", "ssl", "files", "notice"] {
            schemas.push(zeek::schema::get_schema_entry(p).schema.clone());
        }
        for schema in schemas {
            for f in schema.fields() {
                assert!(
                    canonical_type(f.data_type()).is_some(),
                    "unmapped type {:?} in column {}",
                    f.data_type(),
                    f.name()
                );
            }
        }
    }

    /// Schemas held in private statics (generic, WEF, IPFIX, sFlow) are covered by
    /// scanning every `DataType::X` the sources name: each must have a mapping.
    #[test]
    fn test_every_datatype_named_in_src_is_mapped() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let mut files = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        let re = regex::Regex::new(r"DataType::([A-Za-z0-9]+)").unwrap();
        let mapped = [
            "Null",
            "Boolean",
            "Int8",
            "Int16",
            "Int32",
            "Int64",
            "UInt8",
            "UInt16",
            "UInt32",
            "UInt64",
            "Float16",
            "Float32",
            "Float64",
            "Utf8",
            "LargeUtf8",
            "Binary",
            "LargeBinary",
            "Date32",
            "Date64",
            "Timestamp",
            "List",
            "LargeList",
            "Map",
        ];
        let mut seen = std::collections::BTreeSet::new();
        for f in files
            .iter()
            .filter(|f| !f.ends_with("iceberg_descriptor.rs"))
        {
            let text = std::fs::read_to_string(f).unwrap();
            for c in re.captures_iter(&text) {
                seen.insert(c[1].to_string());
            }
        }
        assert!(
            seen.contains("Utf8") && seen.contains("Timestamp"),
            "scan found nothing"
        );
        for name in &seen {
            assert!(
                mapped.contains(&name.as_str()),
                "DataType::{name} has no canonical mapping"
            );
        }
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
