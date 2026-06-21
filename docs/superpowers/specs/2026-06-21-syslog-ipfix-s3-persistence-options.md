# Options: Syslog + IPFIX S3/Parquet Persistence

**Date:** 2026-06-21
**Status:** Draft / Options analysis — not a final spec
**Context:** Extending the existing WEF → Parquet/S3 pipeline to also persist syslog messages and (future) IPFIX flow records.

---

## Ground truth: what the code actually does today

Before the options, a precise map of the current moving parts.

### The WEF pipeline

`src/server/mod.rs` wires everything at startup (around lines 147–184):

1. `create_parquet_s3_forwarder(&config.forwarding.destinations)` scans the `DestinationConfig` list for any entry whose `protocol == Http` and whose `url` starts with `s3://`. If found, it constructs a `ParquetS3Forwarder` (`src/forwarding/parquet_s3.rs`).
2. A `tokio::mpsc::channel::<Arc<WindowsEvent>>(10000)` is created. The sender half is stored as `AppState.parquet_s3_sender: Option<mpsc::Sender<Arc<WindowsEvent>>>`.
3. A dedicated worker task loops over `receiver.recv()` / a periodic flush timer, calling `s3_forwarder.forward((*event).clone())` and `s3_forwarder.flush_all()`.
4. In `process_single_event` (line 554), the handler calls `sender.try_send(event.clone())` — cheap because `event` is `Arc<WindowsEvent>`.

The `ParquetS3Forwarder` (`src/forwarding/parquet_s3.rs`) is hardwired to `WindowsEvent`:
- `BufferedEvent::from_windows_event(&WindowsEvent)` — the only entry point for data.
- `buffers: HashMap<u32, EventTypeBuffer>` keyed by `event_id` (the `ParsedEvent.event_id` field).
- `write_parquet_file` emits a fixed Arrow schema: `event_id: UInt32`, `timestamp: Utf8`, `source_host: Utf8`, `subscription_id: Utf8`, `event_data: Utf8` (the full event serialised as JSON).
- S3 key pattern: `event_type={event_id}/year=.../month=.../day=.../file.parquet`.

The `Forwarder` struct (`src/forwarding/mod.rs`) is a **separate, unrelated component** — it forwards WEF events over HTTP/TCP/UDP/syslog to downstream destinations. It is also `WindowsEvent`-typed (`Sender<Arc<WindowsEvent>>`), but this discussion focuses on the Parquet/S3 path, not the forwarding path.

### Syslog today

`SyslogListener` (`src/syslog/listener.rs`) receives UDP/TCP datagrams, parses them into `SyslogMessage` (`src/syslog/mod.rs`), and calls `SyslogHandler::handle_message`. The only handler is `DefaultSyslogHandler`, which logs via `info!` — **nothing reaches S3**. There is zero wiring between the syslog listener and `AppState`.

`SyslogMessage` has a rich parsed structure: `priority`, `severity`, `facility`, `timestamp: Option<DateTime<Utc>>`, `hostname`, `app_name`, `proc_id`, `msg_id`, `message: String`, `structured_data: Option<HashMap<String,HashMap<String,String>>>`, `protocol` (RFC3164 vs RFC5424).

### IPFIX

Does not yet exist. The prompt specifies it will follow the syslog pattern: a UDP listener + a handler trait producing decoded flow records. The key constraint is that IPFIX field schemas are **defined at runtime** by "template" packets — you don't know the column set until you receive a template from each exporter.

---

## The central tension

The Parquet/S3 pipeline is `WindowsEvent`-typed end-to-end. Getting syslog and IPFIX records into S3 requires either (a) generalising that pipeline to accept other types, (b) duplicating independent pipelines per source, (c) normalising everything into a common envelope, or (d) some hybrid. Each approach makes a different tradeoff between schema fidelity, query ergonomics, implementation effort, and risk to the working WEF path.

---

## Option A — Per-source independent pipelines (parallel duplication)

### Summary

Leave the WEF pipeline entirely untouched. Add a dedicated `SyslogParquetS3Forwarder` and (later) an `IpfixParquetS3Forwarder`, each with its own mpsc channel, own Parquet schema, own S3 prefix, and own worker task. Zero shared infrastructure between the three pipelines.

### How it works

**WEF path:** unchanged. `AppState.parquet_s3_sender: Option<mpsc::Sender<Arc<WindowsEvent>>>` stays as-is.

**Syslog path:**
- Add `AppState.syslog_s3_sender: Option<mpsc::Sender<SyslogMessage>>` (no `Arc` needed if `SyslogMessage` is `Clone`; it is, per `#[derive(Clone)]`).
- Create `SyslogParquetS3Forwarder` in `src/forwarding/parquet_s3_syslog.rs` mirroring the structure of `parquet_s3.rs` but operating on `SyslogMessage`.
- Schema: `timestamp: Utf8`, `hostname: Utf8` (nullable), `app_name: Utf8` (nullable), `proc_id: Utf8` (nullable), `facility: UInt8`, `severity: UInt8`, `message: Utf8`, `structured_data: Utf8` (JSON-serialised `HashMap`).
- S3 prefix: `source=syslog/severity={0-7}/year=.../month=.../day=.../`.
- Wire a `SyslogS3Handler` (implementing `SyslogHandler`) that sends to the channel; swap in this handler in place of `DefaultSyslogHandler` when the syslog S3 destination is configured.

**IPFIX path (future):** Same pattern — `IpfixParquetS3Forwarder` with its own channel and its own schema (see IPFIX dynamic-schema handling below).

**Config:** Extend `DestinationConfig` with a `source_type` discriminant (`wef`, `syslog`, `ipfix`) so `Server::new` knows which forwarder to build, or use separate toml sections (`[syslog_s3]`, `[ipfix_s3]`).

### IPFIX dynamic-schema handling

IPFIX is the hardest case in this option because each flow record can have a different set of fields. Two sub-approaches:

- **Fixed-plus-overflow schema:** Define a Parquet schema covering the 20-30 most common IPFIX Information Elements (flow start/end, src/dst IPv4/IPv6, src/dst port, protocol, octet/packet counts, flow direction, ToS). Extra fields go into a `extra_fields: Utf8` JSON column. This keeps the schema stable and most analytical queries fast, at the cost of making uncommon IEs awkward to query.
- **Fully flat schema per template:** Each unique IPFIX template produces its own S3 prefix and Parquet file. The Arrow schema is built dynamically at runtime from the decoded template. S3 key includes `template_id={id}`. This gives perfect column-per-field but means schema discovery tools must enumerate many prefixes.

Recommendation within this option: use fixed-plus-overflow for the first iteration.

### Effort and blast radius

- No changes to `src/forwarding/parquet_s3.rs`, `AppState.parquet_s3_sender`, or `process_single_event`.
- New files: `src/forwarding/parquet_s3_syslog.rs`, `src/forwarding/parquet_s3_ipfix.rs`.
- `src/server/mod.rs`: add two more optional sender fields to `AppState`; add two more initialisation blocks in `Server::new`; add `syslog_s3_sender.try_send(...)` in the syslog handler.
- `src/syslog/listener.rs`: add a new `SyslogS3Handler` impl or extend `DefaultSyslogHandler` to carry an optional sender.
- Risk to WEF path: near-zero — nothing in the working path changes.

### Pros

- Surgical: the WEF pipeline is untouched and cannot regress.
- Each source gets exactly the right Parquet schema — no lowest-common-denominator columns.
- Sources can have independent flush intervals, buffer sizes, and S3 bucket/prefix configs.
- Easily comprehensible: each source's pipeline is self-contained in one file.
- Incremental by nature: syslog can ship first; IPFIX added later with zero disruption.

### Cons

- **Significant code duplication.** `EventTypeBuffer`, `should_flush`, `write_parquet_file`, `upload_to_s3` all get copy-pasted three times. Any bug fix (e.g. a zstd compression parameter change) must be applied in three places.
- Three separate background worker tasks, three separate channel monitors in `AppState` — more operational complexity.
- `create_parquet_s3_forwarder` naming becomes misleading; needs a companion `create_syslog_s3_forwarder`, etc.
- Config selection logic (`source_type` discriminant or new toml sections) adds surface area.

### Reversibility / migration

Entirely additive. Syslog S3 can be enabled or disabled independently of WEF. Safe to ship behind a feature flag or behind the absence of a config key.

---

## Option B — Generic trait-based unified pipeline

### Summary

Introduce a `Persistable` trait (or similar) that every record type implements, and make `ParquetS3Forwarder` generic over `T: Persistable`. A single pipeline handles all sources; WEF, syslog, and IPFIX dispatch to their respective typed forwarder instances.

### How it works

Define a trait in `src/forwarding/mod.rs` or a new `src/forwarding/persistable.rs`:

```rust
pub trait Persistable: Send + 'static {
    fn partition_key(&self) -> String;          // e.g. "event_id=4624" or "severity=6"
    fn timestamp(&self) -> DateTime<Utc>;
    fn source_host(&self) -> &str;
    fn to_arrow_columns(batch: &[Self]) -> (Arc<Schema>, Vec<ArrayRef>);
    fn estimated_size(&self) -> usize;
}
```

`ParquetS3Forwarder<T: Persistable>` becomes generic; it calls `T::to_arrow_columns` to build the `RecordBatch`. Each source type (`WindowsEvent`, `SyslogMessage`, `IpfixFlow`) implements the trait with its own schema.

`AppState` holds one forwarder instance per source (still typed separately because the Arrow schema differs):
```rust
pub wef_s3_sender: Option<mpsc::Sender<Arc<WindowsEvent>>>,
pub syslog_s3_sender: Option<mpsc::Sender<SyslogMessage>>,
pub ipfix_s3_sender: Option<mpsc::Sender<IpfixFlow>>,
```

The `ParquetS3Forwarder<T>` struct is now shared code; only the trait implementations differ per type. Buffer management (`EventTypeBuffer`, `should_flush`, `flush_all`, `upload_to_s3`) is written once.

### IPFIX dynamic-schema handling

The `to_arrow_columns` implementation for `IpfixFlow` must deal with dynamic templates. Two approaches:
- **Encode IPFIX in the trait implementation:** `IpfixFlow::to_arrow_columns` selects a fixed schema of common IEs and JSON-encodes the rest. The trait method receives `&[IpfixFlow]` and can look at all records in the batch to determine which known columns are present.
- **Template-scoped forwarder instances:** Maintain a `HashMap<TemplateId, ParquetS3Forwarder<IpfixFlow>>` where each instance has a schema built from that template's IE set. This gives per-template Parquet files but requires managing multiple forwarder instances dynamically.

For the first iteration: fixed-common-IEs + JSON overflow, same as Option A.

### Effort and blast radius

- `src/forwarding/parquet_s3.rs`: refactor `ParquetS3Forwarder` to be generic over `T: Persistable`. The existing `BufferedEvent` is replaced by the trait's methods directly. This is a non-trivial refactor of the main forwarder file.
- `src/models/mod.rs`: implement `Persistable for WindowsEvent`. Must produce identical Arrow schema and S3 key pattern to today's hardcoded `write_parquet_file`, or accept a schema change (breaking for existing Parquet readers).
- `src/syslog/mod.rs`: implement `Persistable for SyslogMessage`.
- New: `src/ipfix/mod.rs` (when IPFIX arrives): implement `Persistable for IpfixFlow`.
- `src/server/mod.rs`: `AppState` gains per-source sender fields; `Server::new` creates one generic forwarder per source.
- Risk to WEF: **Medium.** The refactor touches `parquet_s3.rs` directly. The existing `BufferedEvent` intermediate type is eliminated; `WindowsEvent` must now satisfy `Persistable`. Tests in `parquet_s3.rs` must be rewritten. A schema mismatch during the refactor would silently change the Parquet column layout for existing WEF data.

### Pros

- Zero code duplication in buffer management, flush logic, and S3 upload — written once.
- New source types only require implementing the `Persistable` trait — a clean, bounded contract.
- Consistent operational behaviour: one flush strategy, one retry policy, one monitoring surface.
- Arrow/Parquet schema per source type (not a single flat schema) because each type's `to_arrow_columns` is independent.

### Cons

- `ParquetS3Forwarder<T>` becomes generic, which in Rust means monomorphised — the compiler generates a full copy per `T`. This is fine for three types but worth knowing.
- Refactoring `parquet_s3.rs` to generic while keeping the WEF path working requires careful test coverage to verify the column layout is preserved.
- `to_arrow_columns(batch: &[Self]) -> (Arc<Schema>, Vec<ArrayRef>)` requires the implementer to build Arrow arrays from scratch; this is non-trivial boilerplate per type.
- The trait is not object-safe (due to the batched slice signature), so you cannot hold `Box<dyn Persistable>` — each sender channel must be typed. This is fine architecturally but means `AppState` still has N sender fields for N source types, so the unification is in the implementation, not in the runtime dispatch.

### Reversibility / migration

The WEF path must be refactored in-place. A safe incremental path:
1. Introduce the trait without changing the forwarder (just add `impl Persistable for WindowsEvent`).
2. Port `ParquetS3Forwarder` to generic, with tests confirming identical column output.
3. Add `impl Persistable for SyslogMessage` and wire it.
4. Add IPFIX later.

Step 2 is the risky commit; it should be gated behind a good test that compares output schema byte-for-byte.

---

## Option C — Common envelope record ("LogRecord" normalisation)

### Summary

Define a single `LogRecord` enum or struct that all source types are normalised into before entering a single unified Parquet/S3 pipeline. Every record goes through one channel, one forwarder, one S3 bucket prefix, one Parquet schema.

### How it works

Define in `src/models/mod.rs`:

```rust
pub enum LogRecord {
    WindowsEvent(Arc<WindowsEvent>),
    Syslog(SyslogMessage),
    Ipfix(IpfixFlow),
}
```

Or alternatively a flat struct:

```rust
pub struct LogRecord {
    pub id: Uuid,
    pub received_at: DateTime<Utc>,
    pub source_host: String,
    pub source_type: &'static str,   // "wef", "syslog", "ipfix"
    pub timestamp: Option<DateTime<Utc>>,
    pub severity: Option<u8>,
    // common syslog/WEF fields...
    pub payload: serde_json::Value,  // the full source record, JSON-serialised
}
```

`AppState` gets a single `log_s3_sender: Option<mpsc::Sender<LogRecord>>`. One worker task, one `ParquetS3Forwarder<LogRecord>`. S3 key: `source_type={wef,syslog,ipfix}/year=.../month=.../day=.../`.

The Parquet schema is fixed and applies to all records:

| column | type | notes |
|---|---|---|
| `id` | Utf8 | UUID |
| `received_at` | Utf8 | ISO 8601 |
| `source_type` | Utf8 | "wef" / "syslog" / "ipfix" |
| `source_host` | Utf8 | |
| `timestamp` | Utf8 | nullable, event-native time |
| `severity` | UInt8 | nullable |
| `facility` | UInt8 | nullable, syslog only |
| `app_name` | Utf8 | nullable, syslog only |
| `event_id` | UInt32 | nullable, WEF only |
| `payload` | Utf8 | full source record as JSON |

### IPFIX dynamic-schema handling

This is where the envelope approach is most comfortable with dynamic schemas: IPFIX fields go entirely into the `payload` JSON column. Nothing about the Parquet schema changes when new IPFIX templates arrive. Querying specific IPFIX IEs requires JSON path operators (Athena: `json_extract`, DuckDB: `json_extract_string`) — slower than native columns, but works without schema migrations.

If higher query performance on IPFIX is needed later, dedicated columns for the most common IEs (src IP, dst IP, ports, byte count) can be promoted to top-level columns in a schema evolution step.

### Effort and blast radius

- `src/models/mod.rs`: add `LogRecord` enum/struct.
- `src/forwarding/parquet_s3.rs`: replace `BufferedEvent` with `LogRecord`; replace `from_windows_event` with conversion impls. Schema changes from five to ten+ columns — **this is a breaking Parquet schema change for existing WEF data** if the same S3 prefix is used.
- `src/server/mod.rs`: replace `parquet_s3_sender: Option<mpsc::Sender<Arc<WindowsEvent>>>` with `log_s3_sender: Option<mpsc::Sender<LogRecord>>`. Convert `Arc<WindowsEvent>` into `LogRecord` at the call site in `process_single_event`.
- `src/syslog/listener.rs`: add a `SyslogS3Handler` that converts `SyslogMessage → LogRecord` and sends.
- Risk to WEF: **High if the same S3 prefix is used, Medium if WEF moves to a new prefix.** The `AppState` field rename and the schema change both touch working code. The conversion (`Arc<WindowsEvent> → LogRecord`) is a clone step that didn't exist before. The S3 prefix change would require operators to update any existing Athena/Glue table definitions.

### Pros

- Single pipeline: one channel, one worker, one forwarder, one S3 configuration block.
- Adding a new source type is trivial: implement `From<NewType> for LogRecord` and send to the existing channel.
- Works naturally for cross-source analysis (e.g. correlate a Windows logon event with a DNS query) — all records land in the same prefix and can be queried together.
- IPFIX dynamic schema is a non-problem: everything goes to `payload`.

### Cons

- **Schema mismatch for analytic queries.** A query over "all syslog messages" must also scan WEF and IPFIX partitions (or filter on `source_type`). Column-level statistics in Parquet are weaker because most columns are nullable/absent for each source type.
- Columns like `event_id`, `facility`, `app_name` are meaningless for two of the three source types — a lot of nulls.
- The `payload: Utf8` column carries the full source record as JSON, so every WEF query now has to `json_extract` to get `event_id`, `provider`, etc. — **a step backward from today's schema**, where `event_id` is already a first-class UInt32 column.
- Mixing records from all sources in the same Parquet row group reduces compression efficiency (heterogeneous data is harder to compress than homogeneous).
- **Breaking change** to the existing WEF S3 schema unless the WEF source is isolated to its own sub-prefix (which partially negates the benefit of unification).
- A single shared channel is a potential single point of backpressure failure — a burst of IPFIX flows could starve WEF events.

### Reversibility / migration

- If the existing WEF S3 prefix is preserved and WEF data is written in the new `LogRecord` schema, existing Glue/Athena crawlers break.
- The safest migration: continue writing WEF to its existing schema on the old S3 path, and write the new `LogRecord` schema to a different prefix. But this means WEF is persisted twice, and the old path still needs to be maintained.
- A cleaner cut: version the S3 prefix (`schema_version=2/source_type=wef/...`) and update all query tooling at the same time. This is operationally viable but requires coordination.

---

## Option D — Hybrid: keep per-source Parquet writers, share infrastructure via trait (recommended)

### Summary

A hybrid of A and B: introduce a `S3Sink` trait that captures the buffer/flush/upload logic, implement it once, but keep separate sink instances per source type so schemas remain native. This avoids both the duplication of pure-A and the WEF-schema-breaking risk of C, while giving the code-reuse benefit of B without making the forwarder generically typed.

### How it works

Extract the reusable pieces from `src/forwarding/parquet_s3.rs` into a shared module:

```rust
// src/forwarding/s3_sink.rs
pub struct S3SinkConfig { /* bucket, endpoint, flush_interval, etc — same as ParquetS3Config today */ }

pub struct S3Sink {
    config: S3SinkConfig,
    s3_client: S3Client,
}

impl S3Sink {
    pub async fn upload_parquet(&self, local_path: &Path, s3_key: &str) -> Result<()> { ... }
}
```

Then each source type owns its own "buffer + writer" component that uses `S3Sink` for the upload:

```rust
// src/forwarding/wef_s3.rs
pub struct WefS3Writer { sink: S3Sink, buffers: HashMap<u32, EventTypeBuffer>, ... }
impl WefS3Writer {
    pub async fn accept(&mut self, event: &WindowsEvent) -> Result<()> { ... }
    pub async fn flush_all(&mut self) -> Result<()> { ... }
}

// src/forwarding/syslog_s3.rs
pub struct SyslogS3Writer { sink: S3Sink, buffer: Vec<SyslogMessage>, ... }
impl SyslogS3Writer {
    pub async fn accept(&mut self, msg: SyslogMessage) -> Result<()> { ... }
    pub async fn flush_all(&mut self) -> Result<()> { ... }
}
```

The S3 client creation, credential wiring, and `upload_parquet` live once in `S3Sink`. The buffer management and Arrow schema construction live per-source-type in their respective writer structs. A helper macro or a `BufferWriter<T>` generic struct (simpler than the full `Persistable` trait) can reduce the buffer-management boilerplate if desired.

`AppState` gains:
```rust
pub wef_s3_sender: Option<mpsc::Sender<Arc<WindowsEvent>>>,    // existing field, unchanged name
pub syslog_s3_sender: Option<mpsc::Sender<SyslogMessage>>,     // new
pub ipfix_s3_sender: Option<mpsc::Sender<IpfixFlow>>,          // future
```

Each source's worker task is spawned independently, as in Option A, but the upload code is shared.

### IPFIX dynamic-schema handling

`IpfixS3Writer` manages a `HashMap<TemplateId, IpfixTemplateBuffer>` where each buffer holds the decoded flows for one template. At flush time, it:
1. Looks up the Arrow schema for that template (built when the template packet was first received and stored in a `HashMap<TemplateId, Arc<Schema>>`).
2. Builds the `RecordBatch` with one column per IE in the template.
3. Uploads to `source=ipfix/template_id={id}/year=.../month=.../day=.../`.

For IEs not present in the common fixed set, every new template produces its own schema — this is the "fully dynamic" sub-approach, which is more honest than JSON-stuffing for flow data. If the template churn is low (most network exporters send only a handful of templates), this is operationally fine. If template IDs are unstable (some exporters re-negotiate templates after reconnect), the writer should deduplicate by canonical IE fingerprint rather than raw template ID.

Fallback for truly unknown/exotic IEs: include them in an `extra_data: Utf8` JSON column within the per-template schema.

### Effort and blast radius

- `src/forwarding/parquet_s3.rs`: extract S3 client creation and `upload_to_s3` into `S3Sink`. Rename `ParquetS3Forwarder` to `WefS3Writer` (or keep it and just add `S3Sink` as a shared building block alongside). The `BufferedEvent` type and WEF-specific buffer logic stays in `parquet_s3.rs`/`wef_s3.rs`.
- New files: `src/forwarding/s3_sink.rs`, `src/forwarding/syslog_s3.rs`, `src/forwarding/ipfix_s3.rs`.
- `src/server/mod.rs`: two new sender fields; two new initialisation blocks; syslog handler wiring. The existing `parquet_s3_sender` field and its worker task are unchanged.
- `src/syslog/listener.rs`: add a `SyslogS3Handler` impl.
- Risk to WEF: **Low.** The existing `parquet_s3.rs` path touches only to extract the S3 client + upload into `S3Sink`. The `BufferedEvent`, `EventTypeBuffer`, `write_parquet_file`, and the worker task in `server/mod.rs` are untouched. The only risk is the `S3Sink` extraction introducing a regression in `upload_to_s3` — which is caught by a test that roundtrips through MinIO or a mock S3.

### Pros

- S3 plumbing written once: credentials, `force_path_style`, `ByteStream::from_path`, error handling.
- Per-source schemas: WEF keeps its current column layout (no breaking change for existing Parquet consumers). Syslog gets native `severity`/`facility` columns. IPFIX gets per-template dynamic schemas.
- Blast radius of adding a new source type is exactly one new `*_s3.rs` file + a few lines in `server/mod.rs` + the handler wiring.
- WEF path risk is extremely low because its buffering code is not refactored.
- The `S3Sink` struct is independently testable against a MinIO or localstack instance.

### Cons

- Each source still has its own buffer management code — partial duplication remains. (`EventTypeBuffer` logic and `flush_all` loop is repeated per writer.)
- `AppState` grows with N sender fields as N sources are added.
- Config: need a way to express per-source S3 destinations. The current `DestinationConfig` has no `source_type` field. Adding one (or using separate config sections) is a small but necessary config change.
- Three separate worker tasks means three separate periodic flush timers. A burst that triggers many flushes across sources could generate S3 API spikes. (Mitigated by independent `max_file_size_mb` and `flush_interval_secs` per source.)

### Reversibility / migration

Entirely additive once the `S3Sink` extraction is done. The extraction itself is a pure refactor of the WEF upload path; it can be shipped as a standalone commit with no functional change before the syslog/IPFIX wiring is added.

---

## Comparison table

| Dimension | A (Parallel duplication) | B (Generic trait) | C (Envelope) | D (Hybrid — recommended) |
|---|---|---|---|---|
| Code duplication | High | Low | Low | Medium |
| WEF blast radius | None | Medium | High | Low |
| WEF schema preserved | Yes | Yes (if careful) | No | Yes |
| Syslog native schema | Yes | Yes | No (JSON payload) | Yes |
| IPFIX native columns | Yes (with effort) | Yes (with effort) | No (JSON payload) | Yes |
| IPFIX dynamic templates | Moderate | Moderate | Trivial | Best |
| First-ship complexity | Low | High | Medium | Medium |
| Config extensibility | New sections | New sections | Single section | New sections |
| Incremental shipping | Easy | Harder (WEF refactor first) | Hard (schema break) | Easy |
| Cross-source queries | Hard (separate prefixes) | Hard (separate prefixes) | Easy (one prefix) | Hard (separate prefixes) |

---

## Recommendation

**Implement Option D (hybrid: shared `S3Sink`, independent per-source writers).**

### Why

The core constraint is that the WEF → S3 path is working in production. Option C is the only path that genuinely simplifies the *schema* side, but it does so at the cost of degrading the WEF Parquet schema (WEF `event_id` goes from a native UInt32 column to a `json_extract` call) and requiring a breaking S3 schema migration. That is too much collateral damage.

Option A is the lowest-risk path and should be the fallback if the team is time-constrained, but it leaves ~200 lines of S3/upload logic duplicated across three files with no shared abstraction. The first time a MinIO credential rotation or a `ByteStream` API change needs fixing, it will need to be fixed in three places.

Option B is architecturally elegant but the `Persistable` trait approach requires refactoring the WEF forwarder before a single syslog byte can reach S3. In Rust, generic refactors tend to propagate type parameters upward, and there's real risk of breaking the working pipeline during the refactor.

Option D gets the main benefit of B (shared S3 plumbing, written once, tested once) while keeping per-source buffer code isolated. The WEF pipeline is touched only at the `upload_to_s3` / S3 client level — a clean extraction that can be verified by checking that existing tests still pass.

### Smallest sensible first increment

1. **Commit 1 (pure refactor, no new behaviour):** Extract `S3Client` creation and `upload_to_s3` from `ParquetS3Forwarder` into a new `src/forwarding/s3_sink.rs` — struct `S3Sink { config: S3SinkConfig, s3_client: S3Client }` with `pub async fn upload_parquet(&self, path: &Path, s3_key: &str) -> Result<()>`. Update `ParquetS3Forwarder` to hold an `S3Sink`. Confirm all existing tests pass; add a test for `S3Sink::upload_parquet` against a mock/localstack.

2. **Commit 2 (syslog S3 writer):** Add `src/forwarding/syslog_s3.rs` — `SyslogS3Writer` with a simple `Vec<SyslogMessage>` buffer, a fixed Parquet schema, and `sink: S3Sink`. Add a `SyslogS3Handler` in `src/syslog/listener.rs` that holds an `mpsc::Sender<SyslogMessage>`. Wire in `Server::new`: new `syslog_s3_sender` field, worker task, `SyslogS3Handler` (replacing `DefaultSyslogHandler` when configured).

3. **Commit 3 (config):** Add `source_type` to `DestinationConfig` (or add a `syslog_s3` config section), update `create_parquet_s3_forwarder` and add `create_syslog_s3_writer` so operators can configure syslog → S3 independently of WEF → S3.

4. **Later (IPFIX):** Add `src/forwarding/ipfix_s3.rs` with `IpfixS3Writer`. The key addition is a `HashMap<TemplateId, Arc<Schema>>` for per-template schema tracking. Ship once the IPFIX listener exists.

This sequence ensures WEF never regresses (Commit 1 is a pure refactor), syslog can be validated end-to-end independently (Commit 2), and IPFIX arrives without touching any of the above.
