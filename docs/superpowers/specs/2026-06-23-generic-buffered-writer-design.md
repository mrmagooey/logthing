# Generic Buffered Parquet Writer — Design

**Date:** 2026-06-23
**Status:** Approved (design), pending implementation plan
**Branch:** `feat/generic-writer`
**Related:** project-health review M-1 (duplication) + M-2 (buffer-accounting divergence); deferred from the security-hardening effort.

## Goal

Replace the four near-duplicate S3 Parquet writers (`parquet_s3.rs` WEF, `syslog_s3.rs`, `ipfix_s3.rs`, `zeek_s3.rs`) with **one generic buffered-Parquet-writer** plus a thin per-source adapter, so the buffering / flush / cap / encode / upload / channel / graceful-shutdown machinery lives in exactly one place. Fixes-once instead of fixes-four, and converges the divergent buffer-accounting models (M-2).

## Locked decisions

| Topic | Decision |
|-------|----------|
| Adapter shape | Associated-type trait `ParquetSink`; generic `PartitionedParquetWriter<S: ParquetSink>` (monomorphized, no `dyn` on the hot path) |
| Scope | Migrate **all four** sources, WEF last as the riskiest increment |
| Metrics | **Unify** to `parquet_s3_*{source="…"}` (breaking rename of the per-source `*_s3_*` families) |
| Config | Shared `BufferedWriterConfig` reused by all sources; backward-compatible TOML keys |
| Flush accounting | Unified `FlushPolicy` (rows OR bytes OR age) — a deliberate convergence, **not byte-identical** to today's per-source single-trigger timing |

## Current state (what's being unified)

All four writers independently re-implement: a per-buffer `VecDeque<(RecordBatch, est_bytes)>` with row+byte counters; `drop_oldest_to_cap` (hard cap + drop metric, throttled warn); `flush_check_interval` timer; `spawn_blocking` Parquet encode → `S3Sink::upload`; a bounded mpsc channel + background `select!` task with `start_with_capacity → (Handler, JoinHandle)`, overflow drop metric, and flush-on-channel-close (graceful shutdown); and a date-partitioned key builder.

Divergences:

| Writer | Partitioning | Flush trigger | Schema | Notes |
|--------|--------------|---------------|--------|-------|
| `syslog_s3` | single buffer | rows (`max_buffer_rows`) | one fixed | |
| `ipfix_s3` | single buffer | bytes (`flush_threshold_bytes`), hard cap `max_buffer_rows*4` | one fixed | |
| `zeek_s3` | map `log_path → StreamBuffer` (+ `MAX_ZEEK_STREAMS` cap, `sanitize_log_path`) | bytes | per-partition (registry + envelope fallback) | |
| `parquet_s3` (WEF) | map `event_id → EventTypeBuffer` | est-bytes (`max_file_size_mb`) | one fixed, split per event-type | integrated with `Forwarder`/HTTP path + graceful-shutdown worker |

## Architecture

### The adapter trait (each source implements ~40–60 lines)

```rust
pub trait ParquetSink: Send + Sync + 'static {
    type Record: Send + 'static;

    /// Stable source label: "syslog" | "ipfix" | "zeek" | "wef".
    /// Used as the `source` metric label and the base S3 key prefix component.
    fn source(&self) -> &'static str;

    /// Partition segment for this record. `None` => a single shared buffer
    /// (syslog, ipfix). `Some(seg)` => one buffer per distinct seg
    /// (zeek: sanitized log_path; wef: `event_type=<id>`). The segment is used
    /// both as the buffer-map key and an S3 key path component.
    fn partition(&self, record: &Self::Record) -> Option<String>;

    /// Arrow schema for a partition. Constant for single-schema sources;
    /// a registry/fallback lookup for zeek.
    fn schema(&self, partition: Option<&str>) -> Arc<arrow_schema::Schema>;

    /// Convert one record into a single-row `RecordBatch` for its partition's
    /// schema. Best-effort total (never panic / never silently drop a field —
    /// mirrors zeek's mapping rule; type mismatches go to an `_extra`/raw column
    /// where the schema has one).
    fn to_record_batch(&self, record: &Self::Record, schema: &Arc<arrow_schema::Schema>)
        -> anyhow::Result<arrow_array::RecordBatch>;
}
```

This matches the existing model: each current writer already buffers `RecordBatch`es. The generic buffers per-partition `VecDeque<(RecordBatch, est_bytes)>` and, on flush, concatenates them (`arrow::compute::concat_batches`) for the partition's schema, encodes once, and uploads. The adapter owns only the columnar record→batch construction (reusing each source's existing mapping code); the generic owns all buffering/flush/cap/upload. (An adapter may batch multiple records per `RecordBatch` later as an optimization, but single-row batches preserve current behavior and are the baseline.)

### The generic writer + handler

```rust
pub struct PartitionedParquetWriter<S: ParquetSink> {
    sink: S,
    s3: Arc<S3Sink>,
    config: BufferedWriterConfig,
    buffers: HashMap<String, PartitionBuffer>, // keyed by partition segment ("" for None)
    // partition-count cap, last-flush timestamps, etc.
}

pub struct ParquetWriterHandle<S: ParquetSink> { tx: mpsc::Sender<S::Record> }

impl<S: ParquetSink> ParquetWriterHandle<S> {
    /// Spawn the background writer task; returns the handle + its JoinHandle
    /// (for graceful-shutdown await). Mirrors the existing
    /// `start_with_capacity` contract used across the current writers.
    pub fn start(sink: S, s3: Arc<S3Sink>, config: BufferedWriterConfig)
        -> (Self, tokio::task::JoinHandle<()>);
    pub fn try_send(&self, record: S::Record) -> Result<(), TrySendError<S::Record>>;
}
```

The generic owns: per-partition buffer creation (`schema()` → builders), `append`, row/byte accounting, `FlushPolicy` evaluation, `drop_oldest_to_cap` + `parquet_s3_buffer_dropped{source}`, the partition-count cap (`max_partitions`; overflow → a fixed overflow partition + `parquet_s3_partitions_capped{source}`, generalizing zeek's behavior), the `flush_check_interval` timer, `spawn_blocking` encode → `S3Sink::upload(build_key(...))`, the bounded channel + background `select!` loop, overflow `parquet_s3_dropped{source}`, and **flush-on-channel-close** for graceful shutdown.

### Unified flush policy (M-2 convergence)

```rust
pub struct FlushPolicy { pub max_rows: usize, pub max_bytes: usize, pub interval: Duration }
```
A partition flushes when `rows >= max_rows` **OR** `bytes >= max_bytes` **OR** `age >= interval`. Both counters are always tracked. Hard cap (drop-oldest) at `max_rows.saturating_mul(4)` rows, as today. This deliberately gives syslog a byte trigger and ipfix/zeek a row trigger; per-source defaults preserve each source's dominant behavior while unifying the model. **Consequence:** flush *timing* is no longer byte-identical to the current single-trigger writers — existing per-writer tests asserting exact single-trigger flush will be updated to the unified policy.

### Unified metrics (breaking rename)

`parquet_s3_records_written{source}`, `parquet_s3_uploads{source}`, `parquet_s3_upload_errors{source}`, `parquet_s3_dropped{source}` (channel overflow), `parquet_s3_buffer_dropped{source}` (hard-cap drop), `parquet_s3_partitions_capped{source}`. These replace `syslog_s3_*`, `ipfix_s3_*`, `zeek_s3_*`, and the WEF/`wef_*` counters. Docs must be updated to the new names; e2e verifiers assert S3 objects (not metric names) and are unaffected.

### Shared config

```rust
pub struct BufferedWriterConfig {
    #[serde(flatten)] pub connection: S3ConnectionConfig, // endpoint/bucket/region/keys (masked Debug)
    pub prefix: String,            // per-source default: "syslog"|"ipfix"|"zeek"|"wef"
    pub max_buffer_rows: usize,
    pub flush_threshold_bytes: usize,
    pub flush_interval_secs: u64,
    pub channel_capacity: usize,
    pub max_partitions: usize,      // generalizes MAX_ZEEK_STREAMS; bounds wef event-type cardinality too
}
```
Reused by `[syslog.s3]`/`[ipfix.s3]`/`[zeek.s3]` and the WEF parquet destination. **Backward-compatible**: existing TOML keys still deserialize (the field set is the superset already present per source); only the Rust struct is unified. Per-source defaults differ in `prefix` (and may differ in the threshold defaults to preserve dominant behavior). The masked `Debug` from `S3ConnectionConfig` is inherited.

### Key building

`{prefix}/[{partition}/]year={Y}/month={MM}/day={DD}/{uuid}.parquet` — partition segment present only when `partition()` returns `Some` (zeek `<log_path>`, wef `event_type=<id>`); absent for syslog/ipfix. Preserves each source's current S3 layout exactly.

## Per-source adapters (what each implements)

- **`IpfixSink`**: `source()="ipfix"`, `partition()=None`, `schema()`= the fixed `FlowRecord` schema, `append()`= the current FlowRecord→Arrow mapping. Config default prefix `"ipfix"`, byte-dominant thresholds.
- **`SyslogSink`**: `source()="syslog"`, `partition()=None`, fixed syslog schema, current SyslogMessage→Arrow mapping. Default prefix `"syslog"`, row-dominant defaults.
- **`ZeekSink`**: `source()="zeek"`, `partition()=Some(sanitize_log_path(_path))`, `schema()`= the existing typed-registry-or-envelope lookup, `append()`= the existing best-effort/total mapping (type-mismatch → `_extra`). Default prefix `"zeek"`, `max_partitions` from config.
- **`WefSink`**: `source()="wef"`, `partition()=Some(format!("event_type={id}"))`, fixed WEF schema, current WindowsEvent→Arrow mapping. The `Forwarder`/`create_parquet_s3_forwarder` wiring, `AppState.parquet_s3_sender`, and the graceful-shutdown worker are migrated so WEF flows through `ParquetWriterHandle` like the others (the generic's `(Handle, JoinHandle)` + flush-on-close replaces the bespoke WEF worker added during security hardening).

## Migration phases (sequential; each independently reviewable + mergeable on the branch)

1. **Generic core** — `ParquetSink` trait, `RowBuilders`, `PartitionedParquetWriter`, `ParquetWriterHandle`, `FlushPolicy`, `BufferedWriterConfig`, unified metrics, key builder, partition cap, shutdown/flush. Full unit tests. Nothing wired to a source yet.
2. **ipfix** → `IpfixSink` adapter; delete ipfix's bespoke writer machinery; ipfix tests updated to unified policy + metric labels; ipfix e2e green.
3. **syslog** → `SyslogSink`; same.
4. **zeek** → `ZeekSink` (multi-partition + registry + cap); same.
5. **WEF** → `WefSink`; migrate the forwarding-path + shutdown integration; WEF e2e + graceful-shutdown behavior re-verified.
6. **Cleanup** — remove all dead duplicated code, finalize the unified config struct + metric names, update docs (`README`, `*_IMPLEMENTATION.md`, metric names) and `logthing.toml` if needed.

## Error handling
Unchanged in behavior, unified in one place: bounded buffers + drop-on-overflow (counted), hard-cap drop-oldest (counted), flush-on-channel-close, S3 upload failure logged + retained-then-capped, encode off the runtime via `spawn_blocking`, panic-free on all inputs (the zeek best-effort/total mapping rule is the trait contract).

## Testing
- **Unit:** the generic gets thorough tests (single + multi partition; rows/bytes/age flush triggers; hard-cap drop; partition cap → overflow; channel overflow drop; flush-on-close; encode round-trip; key format). Each adapter gets schema + row-mapping tests.
- **Behavior-preservation gate:** each migrated source keeps its existing tests (updated only where they assert the old single-trigger flush or old metric names).
- **Integration/e2e:** the existing per-source MinIO e2e verifiers (wef/syslog/ipfix/zeek) must still pass — they assert S3 objects land with the right schema under the right prefix, which the migration preserves.
- Full `cargo test` (all targets) + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` green at every phase; final whole-branch review.

## Risks
- **WEF increment (top risk):** forwarding-path + graceful-shutdown integration; mitigated by doing it last on a proven generic and re-verifying its e2e + shutdown flush.
- **Flush-timing convergence:** intended (M-2) but changes flush cadence; covered by updating the per-writer tests to the unified policy.
- **Metric rename:** breaking; mitigated by being pre-release and updating docs in the cleanup phase.

## Files
- Create: `src/forwarding/buffered_writer.rs` (the generic + trait + `RowBuilders` + `BufferedWriterConfig` + key builder + metrics).
- Modify: `src/forwarding/{ipfix_s3,syslog_s3,zeek_s3,parquet_s3}.rs` (collapse to adapters), `src/forwarding/mod.rs`, `src/config/mod.rs` (unify config), `src/main.rs` + `src/server/mod.rs` (WEF wiring + shutdown), docs.
- Net: large reduction in `src/forwarding/` line count; future sources add a ~50-line adapter.
