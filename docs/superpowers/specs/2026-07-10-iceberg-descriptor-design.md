# Iceberg descriptor output — design

**Date:** 2026-07-10
**Process:** `auto-develop` (autonomous brainstorming, reviewer-gated). Went through
3 full reject/revise cycles (the skill's maximum) plus one human checkpoint after
round 3 — see "Review record" at the end.

## Request (verbatim)

> Create the JSON file-descriptor output designed in this conversation, so
> logthing can slot more easily into an Iceberg system. Do not call it a
> "sidecar" (confusing in a k8s ecosystem) — use a different name. Implement
> it as a separate sink, controlled via env vars, following logthing's
> existing config conventions.

## Background

Prior investigation in this conversation converged on: logthing stays
"dumb" (no Iceberg library dependency), and a separate external process
(out of scope here) does real Iceberg catalog/manifest work. The mechanism:
logthing emits a small JSON file alongside each Parquet file, built purely
from data already in memory at flush time, so the external committer never
needs to re-open the Parquet file.

## Architecture

A new **descriptor** — not "sidecar", not "manifest" (both k8s-overloaded;
"manifest" is also a real, different Iceberg term, which would mislead) —
JSON file emitted once per Parquet flush, from the one shared write path
every source already funnels through (`PartitionedParquetWriter::flush_partition`
in `src/forwarding/buffered_writer.rs`), uploaded via the existing
`UploadSink` trait to a separate, globally-configured `[iceberg]` sink.

```
Parquet flush succeeds (existing code, unchanged)
  → build IcebergDescriptor from data already in memory (row count, byte
    size, partition, per-column stats already computed by ArrowWriter)
  → serialize to JSON
  → upload via the same UploadSink abstraction, to a key derived from the
    Parquet file's own key (.parquet → .json)
  → best-effort: failure is logged + metriced, never blocks/fails the
    Parquet write itself
```

## Config shape

```toml
[iceberg]
[iceberg.s3]
endpoint = "http://localhost:9000"
bucket = "logthing-iceberg-descriptors"
region = "us-east-1"
access_key = "minioadmin"
secret_key = "minioadmin"
prefix = "_iceberg_descriptors"   # optional, default ""

[iceberg.local]
directory = "/var/log/logthing/iceberg-descriptors"
prefix = "_iceberg_descriptors"   # optional, default ""
```

- `IcebergConfig { s3: Option<IcebergDescriptorS3Config>, local: Option<IcebergDescriptorLocalConfig> }`
  — presence of `.s3`/`.local` is the enable signal (no separate `enabled`
  bool), matching every other source's config in this codebase.
- **Unlike every other source's `.s3`/`.local` pair**, which may both be
  configured simultaneously (written to both), `[iceberg]` requires
  choosing exactly one. `Config::load()` gains its first-ever
  cross-field validation: if both `iceberg.s3` and `iceberg.local` are
  present after all config layers (file → admin-override-file → env vars)
  merge, return an `Err` naming both conflicting resolved values (e.g.
  `"iceberg.s3.bucket = 'x' and iceberg.local.directory = 'y' are both
  configured; set only one"`). This is deliberately NOT dual-write: the
  descriptor is a lightweight pointer, not data at risk of loss (unlike
  the raw-persistence targets that motivate dual-write elsewhere), so a
  `MultiUploadSink` combinator is out of scope. Because the `config` crate
  merges all layers before deserialization, *which* layer set which value
  is not recoverable at validation time — the error message states the
  resolved values, not provenance, which is the most this constraint
  allows.
- `IcebergDescriptorS3Config`/`IcebergDescriptorLocalConfig` are simpler
  than other sources' — no `max_buffer_rows`/`flush_threshold_bytes`/
  `flush_interval_secs`/`channel_capacity`, since descriptors aren't
  buffered (each is uploaded synchronously as part of a flush that
  already happened).
- `WEF__ICEBERG__S3__BUCKET` etc. becomes available automatically via the
  pre-existing generic `config::Environment::with_prefix("WEF").separator("__")`
  mechanism — no bespoke env-var code needed.

## `IcebergDescriptor` JSON shape (new module `src/forwarding/iceberg_descriptor.rs`)

```json
{
  "source": "zeek",
  "partition": "conn",
  "file_path": "http://minio:9000/wef-events/zeek/conn/year=2026/month=07/day=10/<uuid>.parquet",
  "file_format": "PARQUET",
  "record_count": 8421,
  "file_size_in_bytes": 1048576,
  "storage_target": "s3",
  "schema_version": "a1b2c3d4",
  "written_at": "2026-07-10T12:00:00Z",
  "column_stats": {
    "0": { "null_count": 0, "min": "Cgo0AAA=", "max": "CgoxAAA=", "physical_type": "INT32" },
    "1": { "null_count": 3, "min": null, "max": null, "physical_type": "BYTE_ARRAY" }
  }
}
```

- `source`/`partition`: raw values already used to build the Parquet key
  (`ParquetSink::source()`, the partition segment) — NOT a composed
  "table" name; that composition is left to the external committer.
- `file_path`: **fully-qualified**, not a bare relative key (fix applied
  after review — see below). Built from a new `UploadSink::location_hint()`
  method:
  - `S3Sink::location_hint()` → `format!("{}/{}", endpoint.trim_end_matches('/'), bucket)`.
    Requires **`S3Sink` to gain a new field storing `cfg.endpoint`**
    (currently discarded after being used to build the AWS SDK client —
    confirmed by reading `src/forwarding/s3_sink.rs`, `S3Sink` today only
    stores `client` and `bucket`). This is required so the descriptor
    resolves correctly against S3-compatible stores (MinIO, etc.), not
    just real AWS — this project's own example config targets MinIO.
  - `LocalDiskSink::location_hint()` → `format!("file://{}", self.root.display())`.
  - `file_path = format!("{}/{}", location_hint, relative_key)`.
  - `UploadSink` gains this as a new **required** trait method — every
    existing implementor (including test mocks, e.g. `RecordingSink` in
    `buffered_writer.rs`'s test module, and any mocks in other test
    files) needs a trivial implementation added.
- `column_stats`: keyed by **Parquet column index** (0-based physical
  position in the file), NOT Iceberg field ID. Sourced from
  `ArrowWriter::close()`'s return value — `Result<parquet::format::FileMetaData>`
  (verified against the actually-pinned `parquet = "53.4.1"` source, not
  assumed), which is currently discarded (only the encoded `Vec<u8>`
  bytes are kept today) — capture it instead.
  `FileMetaData.row_groups[0].columns[i].meta_data.statistics` (thrift
  `Statistics { min: Option<Vec<u8>>, max: Option<Vec<u8>>, null_count:
  Option<i64>, .. }`) is already computed by the encoder; no new
  computation needed, only capturing an already-computed value. **Min/max
  are base64-encoded raw bytes, exactly as Parquet's own PLAIN encoding
  stores them — NOT decoded into a human-readable string.** (Corrected
  during plan-writing after reading the real `parquet` crate source:
  `Statistics.min`/`max` are type-encoded binary, requiring per-physical-type
  decode logic to turn into a readable value — logthing does not do that
  decoding.) This is a **more correct** design than originally specified,
  not a scope cut: Iceberg's own `DataFile.lower_bounds`/`upper_bounds`
  spec fields are ALSO raw type-encoded binary, not human-readable
  strings — so passing the bytes through unchanged, plus the column's
  `physical_type` (e.g. `"INT32"`, `"BYTE_ARRAY"`) needed to decode them,
  is what the committer actually needs, and avoids logthing decoding into
  a lossy string that would need re-encoding downstream anyway.
  Index-keying is **valid only within one `schema_version`** — if a
  source's Arrow schema changes, column index-to-meaning can shift; the
  committer must key any cross-version aggregation by `schema_version`,
  not assume a stable index meaning forever. True Iceberg field-ID keying
  (which requires annotating every source's Arrow schema with field IDs,
  a 7+-file change) is deferred to a separate follow-up task — but that
  task becomes "remap index → field-ID," not "compute stats from
  scratch," since the stats already exist after this feature ships.
  Column-index-keying determinism relies on `concat_batches`/`ArrowWriter`
  preserving the schema's declared field order, which holds in arrow-rs
  (schemas must match exactly for `concat_batches` to succeed) — reviewed
  and considered sound, not just assumed.
- `schema_version`: hash of the Arrow schema's field names+types, computed
  at flush time — not the crate's release version (which would give
  false-positive drift signals on every logthing release regardless of
  whether a given source's schema actually changed).
- `written_at`: RFC3339 (`chrono` already has the `serde` feature enabled
  — confirmed via `Cargo.toml`).

## Hook point

Inside `PartitionedParquetWriter::flush_partition`, immediately after
`self.s3.upload(&s3_key, merged)` succeeds. `PartitionedParquetWriter`
gains a new field: `descriptor_sink: Option<Arc<dyn UploadSink>>`. Threaded
through `start_writer<S>()` and all 14 per-source `_start`/`_local_start`
wrapper function signatures (in each `src/forwarding/{syslog,ipfix,zeek,
suricata,sflow,wef,hec}_s3.rs`), constructed once in `main.rs` from
`config.iceberg` (if configured) and passed to every source alongside the
existing `source_stats: Arc<SourceHourlyStats>` parameter (the one prior
precedent in this codebase for threading a shared cross-cutting `Arc`
through every writer-construction call site).

Rejected: global/ambient state (e.g. a `OnceLock`) — inconsistent with
this codebase's demonstrated preference for explicit dependency injection
everywhere else.

Descriptor upload is `.await`ed **inline**, synchronously, right after the
Parquet upload — not spawned as a background task. Descriptors are
sub-KB JSON vs. the Parquet payload (often MBs) already uploaded
synchronously in the same call; a background task would add
lifecycle/error-visibility complexity for no measurable latency win at
this size.

**Failure handling**: best-effort. A descriptor upload failure is logged
(`tracing::warn!`) and increments a new `iceberg_descriptor_upload_errors{source=...}`
metric, but does NOT propagate into `flush_partition`'s return value —
a descriptor-sink outage never fails, retries, or triggers the existing
hard-cap/drop logic on the core Parquet-writing path. This matches the
codebase's existing pattern of independently logged-and-skipped
persistence-target failures (e.g. syslog's S3/local targets each fail
independently).

## Non-goals (explicit, deliberate — not oversights)

- **No `iceberg-rust` (or any Iceberg library) dependency added to
  logthing.** The whole point is that the external committer owns all
  real Iceberg machinery (manifests, snapshots, catalog commits).
- **No Iceberg field-ID tagging of Arrow schemas.** A separate,
  multi-file follow-up (touches every source's schema definitions);
  `column_stats` ships index-keyed in the meantime (see above).
- **No dual-write support for `[iceberg]`** (`.s3` + `.local`
  simultaneously) — explicit config-load error instead, see Config shape.
- **No new abstraction for "descriptor destination"** — reuses the
  existing `UploadSink` trait exactly as-is (plus the new
  `location_hint()` method, needed for every implementor regardless of
  this feature).

## Testing (per project-wide unit + integration + e2e mandate)

- **Unit** (`buffered_writer.rs`): descriptor built/uploaded on a
  successful flush when configured; NOT emitted when unconfigured (zero
  behavior change baseline); descriptor upload failure does not block or
  fail the overall flush; column-stats extraction correctness against a
  known `RecordBatch`/schema; descriptor-key derivation (`.parquet` →
  `.json` swap, prefix-empty vs. prefix-set cases).
- **Unit** (`iceberg_descriptor.rs`): struct → JSON serialization shape;
  schema-hash determinism (same schema → same hash; different schema →
  different hash).
- **Unit** (`config/mod.rs`): TOML deserialization of `[iceberg]`; an
  env-var-override regression test (mirroring the pattern already
  established in this project for other config sections); the new
  fail-fast validation path (both `.s3` and `.local` present →
  `Config::load()` returns `Err` naming both resolved values).
- **Integration**: one new test appended to **each of the 7 existing**
  `tests/{syslog,ipfix,zeek,suricata,sflow,wef,hec}_local_integration.rs`
  files (confirmed to exist for all 7 sources — verified via `ls tests/`),
  each exercising that source's real `_start`/`_local_start` wrapper
  function directly against a real `LocalDiskSink`-backed descriptor
  sink, asserting a descriptor JSON lands on disk alongside the Parquet
  file with content cross-referencing it. This specifically catches a
  source silently failing to forward the new `descriptor_sink` parameter
  — a per-file mechanical code review of the 14-signature threading
  change would not reliably catch that; a failing test for that specific
  source will.
- **E2E**: extend one existing docker-compose e2e config/verifier
  (mirroring the existing `wef-local-verifier` pattern) to enable
  `[iceberg]` against a real running server process end-to-end,
  confirming descriptors appear for at least one real source under the
  full startup wiring path through `main.rs` — the one tier that would
  catch a `main.rs`-level wiring mistake, since the per-source
  integration tests above construct each wrapper function directly and
  bypass `main.rs`.

## Review record

Three full reject/revise cycles (this skill's maximum) with a fresh,
independent reviewer subagent each round, full context passed inline:

- **Round 1** rejected: v1 field scope silently dropped column stats
  without weighing alternatives (undercutting the feature's core value);
  dual-write handling ("silently prefer S3") was self-described as an
  uncertain coin-flip resolved without justification; the 14-signature
  parameter-threading ripple was under-weighted as a footnote.
- **Round 2** rejected the revision: the fail-fast dual-write fix left an
  unmitigated new failure mode (config-layer provenance loss) unaddressed;
  the column-stats deferral was still asserted rather than genuinely
  weighed against a column-index-keyed middle ground; testing strategy
  was entirely absent from the decision log; and a new, real gap was
  found — the descriptor had no way to identify which bucket/directory a
  file lived in.
- **Round 3** rejected the further revision on two remaining concrete
  defects: the new `location_hint()` fix dropped the S3 `endpoint` (wrong
  for MinIO/non-AWS S3-compatible stores, which is this project's own
  demonstrated deployment target), and the testing plan incorrectly
  assumed `wef`/`hec` lacked existing integration-test scaffolding when
  both files in fact already exist.
- Per the skill's 3-round cap, this was surfaced to the user directly
  after round 3 rather than self-revised a fourth time. The user reviewed
  both remaining defects and approved applying both fixes and proceeding
  — reflected in this document's Config/`IcebergDescriptor`/Testing
  sections above (endpoint now included in `location_hint()`; all 7
  sources, not 5, committed to the integration-test tier).
