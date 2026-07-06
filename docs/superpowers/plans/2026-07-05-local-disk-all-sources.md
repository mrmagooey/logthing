# Implementation Plan: Local-Disk Output Target — Extend to Remaining 6 Sources

## 0. Baseline verified against actual code (not the historical spec docs)

The design spec (`docs/superpowers/specs/2026-07-04-local-disk-output-target-design.md`) and plan (`docs/superpowers/plans/2026-07-04-local-disk-output-target.md`) describe the Zeek implementation, but the code has moved on since those docs were written: commit `266c67d` added a `source_stats: Arc<SourceHourlyStats>` parameter to every `*_start` function and `ParquetWriterHandle::start_with_stats`. Current reference shape, confirmed by reading `src/forwarding/zeek_s3.rs` (1080 lines):

- `build_zeek_handle()` (`src/forwarding/zeek_s3.rs:200-231`) — shared helper taking `(prefix, max_buffer_rows, flush_threshold_bytes, flush_interval_secs, channel_capacity, sink: Arc<dyn UploadSink>, source_stats: Arc<SourceHourlyStats>)`, called by both `zeek_start` (233-257) and `zeek_local_start` (259-277).
- `unused_s3_connection_placeholder()` (186-194) — fills `BufferedWriterConfig.connection` with empty strings since a local-only pipeline has no S3 connection; the field is dead once a pre-built sink is supplied.
- `MultiZeekHandler` (161-174) — `pub struct MultiZeekHandler(pub Vec<Arc<dyn ZeekHandler>>)`, fans out by cloning `ZeekRecord` (already `#[derive(Clone)]`) and calling `handle_record` on each.
- `main.rs:198-261` — builds `zeek_handlers: Vec<Arc<dyn ZeekHandler>>`, conditionally pushes S3 and/or local handlers, then `match zeek_handlers.len() { 0 => Default, 1 => single, _ => MultiZeekHandler }`.
- `tests/zeek_local_integration.rs` — real `LocalDiskSink` + real Parquet reader round-trip for both `conn` and `dns` partitions, checks for leftover `.tmp-` files.
- E2E: `62ed05a` added `[zeek.local]` to `tests/e2e/simulation-environment/config/logthing.toml`, a `zeek-local-data` named volume mounted into both `logthing` and a new `zeek-local-verifier` service.

**Gap found in the reference implementation** (worth fixing when this work lands, not blindly copying): `zeek-local-verifier` is defined in `docker-compose.yml` but is **never invoked** by `tests/e2e/simulation-environment/run.sh` (grep confirms zero references there, unlike `zeek-s3-verifier` which is `run --rm` on line 43). The Zeek e2e "local alongside s3" check currently does not actually run in the pipeline. Any per-source e2e replication should add the `run --rm <source>-local-verifier` line to `run.sh` — and this plan should also fix Zeek's own omission while touching that file.

## 1. Current state of each remaining source (read from actual files, not assumed)

None of the other 6 sources has a `build_xxx_handle` extraction yet — every `xxx_start` builds `BufferedWriterConfig`/`FlushPolicy` inline and calls `ParquetWriterHandle::start_with_stats` directly. So step 2 of the per-source pattern ("extract a shared helper first") is required for **all six**, not optional for some:

| Source | File | `*_start` fn (inline build, no helper) | Handler trait / call site |
|---|---|---|---|
| Suricata | `src/forwarding/suricata_s3.rs:129-156` | `suricata_start` | `SuricataHandler::handle_record` (`src/suricata/listener.rs:38-39`) — `Arc<dyn SuricataHandler>` in `main.rs:270-292` |
| IPFIX | `src/forwarding/ipfix_s3.rs:269-292` | `ipfix_start` | `IpfixHandler::handle_flows(Vec<FlowRecord>, …)` (`src/ipfix/listener.rs:28-29`) — `Arc<dyn IpfixHandler>` in `main.rs:158-180` |
| syslog | `src/forwarding/syslog_s3.rs:176-199` | `syslog_start` | `SyslogHandler::handle_message` (`src/syslog/listener.rs:50-51`) — wrapped in `PayloadDispatchingHandler<H>` (`src/syslog/listener.rs:120-124`), used in `main.rs:99-134` |
| structured syslog | `src/forwarding/structured_syslog_s3.rs:118-143` | `structured_syslog_start` | not a `Handler` trait at all — invoked directly from inside `PayloadDispatchingHandler::handle_message` (`src/syslog/listener.rs:127-135`) via `self.structured_handle` |
| sFlow | `src/forwarding/sflow_s3.rs:254-277` | `sflow_start` | `SflowHandler::handle_samples(Vec<SflowRecord>, …)` (`src/sflow/listener.rs:29-30`) — `Arc<dyn SflowHandler>` in `main.rs:315-337` |
| generic/HEC | `src/forwarding/generic_s3.rs:119-144` | `hec_start(cfg, s3, max_partitions, source_stats)` — note the extra explicit `max_partitions` param, not on `HecS3Config` | **not a `Handler` trait** — direct `Option<GenericS3Handler>` field on `IngestState` (`src/ingest/mod.rs:47-52`), used via `if let Some(ref handler) = ingest.generic_s3 { handler.try_send(...) }` at 4 call sites: `src/ingest/handlers.rs:94,136,176` and `src/server/mod.rs:2623` (OTLP path) |
| WEF | `src/forwarding/parquet_s3.rs:100-126` | `wef_start` | **not a `Handler` trait** — direct `Option<ParquetWriterHandle<WefSink>>` field on `AppState` (`src/server/mod.rs:50-54`), used at exactly one call site, `src/server/mod.rs:638-649` |

Two structurally different wiring shapes exist, not one:

- **Trait-object shape** (Zeek, Suricata, IPFIX, syslog, sFlow): `main.rs` builds `Arc<dyn XxxHandler>` and hands it to a listener. This is where `MultiXxxHandler` fan-out (Zeek's pattern) applies directly.
- **Concrete-handle-in-state shape** (WEF, HEC/generic): no `Handler` trait exists at all; the route handler holds an `Option<ParquetWriterHandle<ConcreteSink>>` (or two, for HEC vs OTLP-via-HEC) directly and calls `try_send` inline. **A `MultiXxxHandler` wrapper is the wrong shape here** — there's nothing polymorphic to wrap. The correct pattern is a second `Option<...Handler>` field (`parquet_local_sender` on `AppState`, `generic_local: Option<GenericS3Handler>` on `IngestState`) and calling `try_send` on both at each existing call site. This is *not* extra design work — it's less work than building a fan-out wrapper, since these two sources have only 1 and 4 call sites respectively.

Record-type `Clone` check (needed for any Multi-handler fan-out): `FlowRecord` (`src/ipfix/mod.rs:13`), `SflowRecord` (`src/sflow/mod.rs:24`), `SuricataRecord` (`src/suricata/mod.rs:6`), `SyslogMessage` (`src/syslog/mod.rs:49`) are **already** `#[derive(Clone)]` — no additional derive work needed anywhere, unlike Zeek where `ZeekRecord` needed the derive added.

## 2. Scope decision: structured syslog

**Recommendation: separate follow-on, not in this pass.** Reasoning:
- Structured syslog (`src/forwarding/structured_syslog_s3.rs`) is not reached through the `SyslogHandler` trait at all — it's invoked directly inside `PayloadDispatchingHandler::handle_message` (`src/syslog/listener.rs:127-135`) as a side-channel, gated by `syslog.parse_payloads`. Adding `.local` to it means wiring a *third* independent config/sink/handle path through `PayloadDispatchingHandler`.
- It shares `SyslogS3Config`'s shape today (reuses the type wholesale, per `structured_syslog_s3.rs:118` `cfg: &SyslogS3Config`) rather than having its own `StructuredSyslogS3Config`. A `.local` counterpart needs a naming/reuse decision that's cleaner to make once, in its own PR.
- It's genuinely a superset of the primary-syslog change (same config shape, same `PartitionedParquetWriter<StructuredSyslogSink>` machinery), so once the primary-syslog `.local` pattern is proven, structured syslog is a near-mechanical repeat.
- Primary syslog is by far the more commonly enabled path (`parse_payloads` defaults to `false`) — the value delivered by unblocking primary syslog local disk is higher per unit of effort than blocking on structured syslog too.

Do primary syslog `.local` in this pass; file structured syslog `.local` as an explicit one-line follow-on once primary syslog's pattern is merged.

## 3. Per-source plan

### 3.1 Suricata (recommended second, after Zeek pattern is proven — see §5)

**Why closest to Zeek:** multi-partition by `sanitize_event_type(event_type)` (`suricata_s3.rs:35-53`), directly mirroring Zeek's `sanitize_log_path`; `DEFAULT_MAX_SURICATA_PARTITIONS = 256` mirrors `DEFAULT_MAX_ZEEK_PARTITIONS`; only difference is a single envelope schema (no per-partition typed registry) vs Zeek's typed-schema registry — irrelevant to the local-disk plumbing.

1. **Config** — new `SuricataLocalConfig` in `src/config/mod.rs`, placed after `SuricataS3Config` (currently ends line 425), identical shape to `ZeekLocalConfig`: `directory: PathBuf`, `prefix`, `flush_threshold_bytes`, `flush_interval_secs`, `channel_capacity`, `max_buffer_rows` (reuse existing `default_suricata_*` functions). `SuricataConfig` gains `pub local: Option<SuricataLocalConfig>` (default `None`), mirroring `ZeekConfig.local`.
2. **`build_suricata_handle` extraction** — refactor `suricata_start` (129-156) into a private helper taking `(prefix, max_buffer_rows, flush_threshold_bytes, flush_interval_secs, channel_capacity, sink: Arc<dyn UploadSink>, source_stats)`, called by both `suricata_start` and new `suricata_local_start`.
3. **`MultiSuricataHandler`** — new struct in `suricata_s3.rs`, `pub struct MultiSuricataHandler(pub Vec<Arc<dyn SuricataHandler>>)` — line-for-line copy of `MultiZeekHandler`.
4. **`main.rs`** — replace `suricata_config_clone.suricata.s3.as_ref()` single-branch block (266-306) with the `Vec<Arc<dyn SuricataHandler>>` + match-on-length pattern from the Zeek block (202-248).
5. **Tests**: unit `suricata_local_start_wires_handler_and_join_handle`, `multi_suricata_handler_fans_out_to_every_inner_handler`, `multi_suricata_handler_survives_one_inner_handler_dropping`; config tests `suricata_local_absent_gives_none`, `suricata_local_config_deserializes_from_toml`, `suricata_s3_and_local_can_both_be_configured_simultaneously`; integration `tests/suricata_local_integration.rs` mirroring `tests/zeek_local_integration.rs`.
6. **E2E**: add `[suricata.local]` to `tests/e2e/simulation-environment/config/logthing.toml`, a `suricata-local-data` volume, `suricata-local-verifier/{Dockerfile,entrypoint.py}` adapted from `zeek-local-verifier/entrypoint.py`, **and** add the corresponding `run --rm suricata-local-verifier` line to `run.sh` (fixing the omission noted in §0 for both sources while here).
7. **Gotcha**: none beyond the mechanical repeat — multi-partition shape matches Zeek almost exactly, which is exactly why this is the right second source to validate the template generalizes.

### 3.2 IPFIX

1. **Config** — new `IpfixLocalConfig` mirroring `IpfixS3Config` (`config/mod.rs:614-634`), swap `connection` for `directory`. `IpfixConfig` (211-225) gains `pub local: Option<IpfixLocalConfig>`; update its `Default` impl (227-236).
2. **`build_ipfix_handle` extraction** from `ipfix_start` (269-292).
3. **Handler**: `IpfixHandler::handle_flows(&self, flows: Vec<FlowRecord>, source)` — `Vec<FlowRecord>` is `Clone` via `FlowRecord: Clone`, so `MultiIpfixHandler(pub Vec<Arc<dyn IpfixHandler>>)` clones the whole `Vec` once per destination, same pattern as Zeek.
4. **`main.rs`** — same `Vec<Arc<dyn IpfixHandler>>` restructuring of the block at 154-193.
5. **Tests**: unit `ipfix_local_start_wires_handler_and_join_handle`, `MultiIpfixHandler` fan-out + isolation tests; config tests mirroring `ipfix_s3_config_deserializes_from_toml`/`ipfix_s3_absent_means_no_persistence`; integration `tests/ipfix_local_integration.rs` (push a `Vec<FlowRecord>` batch, force flush, read back `flow_record_schema()` columns).
6. **E2E**: `ipfix-local-verifier` alongside existing `ipfix-generator`/`ipfix-s3-verifier`, plus the `run.sh` invocation line.
7. **Gotcha**: `IpfixSink` is single-partition (`partition()` returns `None`, `max_partitions: 1` hardcoded) — same as syslog, unlike Zeek/Suricata's multi-partition shape. No architectural difference for the local-disk plumbing, just simpler test fixtures.

### 3.3 syslog (primary; structured syslog explicitly deferred, §2)

1. **Config** — new `SyslogLocalConfig` mirroring `SyslogS3Config` (`config/mod.rs:579-596`): `directory`, `prefix` (default `"syslog"`), `max_buffer_rows`, `flush_interval_secs`, `channel_capacity` (**no `flush_threshold_bytes` field** — `SyslogS3Config` doesn't have one either; `syslog_start` hardcodes `flush_threshold_bytes: usize::MAX` since syslog uses row-count+age triggers only — `SyslogLocalConfig` should match this exactly). `SyslogConfig` (180-207) gains `pub local: Option<SyslogLocalConfig>`; update `Default for SyslogConfig` (725-737).
2. **`build_syslog_handle` extraction** from `syslog_start` (176-199).
3. **Handler fan-out is trickier than Zeek** because the primary syslog handler is always wrapped in `PayloadDispatchingHandler<H>` (a generic struct over `H: SyslogHandler`, `syslog/listener.rs:120-138`) which itself already needs to dispatch to `structured_handle` conditionally. Two viable approaches:
   - **(a) Recommended**: Build `MultiSyslogHandler(pub Vec<Arc<dyn SyslogHandler>>)` exactly like Zeek's, then wrap *that* in `PayloadDispatchingHandler` as its `inner` (i.e., `PayloadDispatchingHandler<MultiSyslogHandler>` when both s3+local resolve, `PayloadDispatchingHandler<SyslogS3Handler>` when one resolves) — this keeps `PayloadDispatchingHandler` completely unchanged, since it's generic over any `H: SyslogHandler`. Zero changes to `PayloadDispatchingHandler` itself, all new code isolated to `syslog_s3.rs` + the `main.rs` block.
   - (b) Special-case inside `PayloadDispatchingHandler` — rejected, adds a second dispatch axis to a struct that's already juggling parse_payloads/structured routing.
4. **`main.rs`** — the syslog block (67-149) is the most involved of the four trait-object sources because it already has 3 nested match arms. Restructure the `syslog_handler` construction (99-134) to build `Vec<Arc<dyn SyslogHandler>>` for s3+local first, collapse via the `match .len() { 0 => Default, 1 => single, _ => Arc::new(MultiSyslogHandler(...)) }` pattern, **then** wrap the result in `PayloadDispatchingHandler` exactly as today — i.e., the Multi-handler resolution happens *before* the `PayloadDispatchingHandler` wrap, not instead of it.
5. **Tests**: unit `syslog_local_start_wires_handler_and_join_handle`, `MultiSyslogHandler` fan-out/isolation, `PayloadDispatchingHandler<MultiSyslogHandler>` compiles and dispatches correctly; config tests; integration `tests/syslog_local_integration.rs` (schema mirrors the 11-column `syslog_schema()`).
6. **E2E**: `syslog-local-verifier`; check the existing docker-compose service name before assuming a specific `syslog-s3-verifier` name exists to copy.
7. **Gotcha**: single-partition (same as IPFIX), **and** the extra `PayloadDispatchingHandler` wrapping layer not present for any other source — this is the one place the Zeek template doesn't map over 1:1 structurally, even though the actual `.local` plumbing underneath is identical.

### 3.4 sFlow

1. **Config** — new `SflowLocalConfig` mirroring `SflowS3Config` (`config/mod.rs:693-707`). `SflowConfig` (656-669) gains `pub local: Option<SflowLocalConfig>`; update `Default for SflowConfig` (671-680).
2. **`build_sflow_handle` extraction** from `sflow_start` (254-277, uses `max_partitions: 2 // "flow" and "counter"` hardcoded).
3. **Handler**: `SflowHandler::handle_samples(&self, samples: Vec<SflowRecord>, source)` — `Vec<SflowRecord>` clonable via `SflowRecord: Clone`. `MultiSflowHandler(pub Vec<Arc<dyn SflowHandler>>)`, same shape as `MultiIpfixHandler`.
4. **`main.rs`** — restructure block at 311-350.
5. **Tests**: unit + config + integration (`tests/sflow_local_integration.rs`, must exercise **both** schemas — `FLOW_SCHEMA` and `COUNTER_SCHEMA`, since `SflowSink::schema()` branches on `partition` at `sflow_s3.rs:69-74`).
6. **E2E**: no `sflow-generator`/`sflow-s3-verifier` currently listed in `run.sh`'s invocation sequence even though `sflow_s3_integration.rs` exists as a Rust-level integration test — verify at implementation time whether sFlow has e2e simulation-environment coverage at all before assuming a `sflow-local-verifier` slots in next to an existing `sflow-s3-verifier`; it may need the sibling S3 e2e verifier built first, which would be out of scope for this specific plan.
7. **Gotcha**: fixed 2-partition cardinality (`"flow"`/`"counter"`) — smallest, most bounded partition space of any source; no overflow-bucket testing is meaningfully exercisable the way Zeek's 256-cap test is, so the integration test should just assert both partitions land correctly rather than porting Zeek's overflow-cap test.

### 3.5 generic/HEC

1. **Config** — new `HecLocalConfig` mirroring `HecS3Config` (`config/mod.rs:474-493`): `directory`, `prefix` (default `"hec"`), `flush_threshold_bytes`, `flush_interval_secs`, `channel_capacity`, `max_buffer_rows`. **No `max_sourcetype_partitions` field on `HecLocalConfig`** — that cardinality knob lives on the parent `HecConfig` (`max_sourcetype_partitions: usize`) and is passed as an explicit function argument to `hec_start(cfg, s3, max_partitions, source_stats)`, not read off `HecS3Config` itself. This confirms partitioning cardinality is orthogonal to the sink/destination and already lives one layer up — `hec_local_start` should take the same explicit `max_partitions: usize` parameter, sourced from the same `cfg.hec.max_sourcetype_partitions` at the call site, so both `.s3` and `.local` pipelines share one cardinality limit. `HecConfig` (512-527) gains `pub local: Option<HecLocalConfig>`.
2. **`build_hec_handle` extraction** from `hec_start` (119-144).
3. **No Handler trait exists for HEC** — `IngestState` (`ingest/mod.rs:47-52`) directly holds `pub generic_s3: Option<GenericS3Handler>`. The correct local-disk pattern here is **not** a `MultiGenericHandler` wrapper — add a sibling field `pub generic_local: Option<GenericS3Handler>` to `IngestState`, and at all 4 call sites (`ingest/handlers.rs:94,136,176`, `server/mod.rs:2623`) try both:
   ```rust
   if let Some(ref h) = ingest.generic_s3 { h.try_send(record.clone())...; }
   if let Some(ref h) = ingest.generic_local { h.try_send(record)...; }
   ```
   This is **less new code** than a fan-out wrapper would be, and keeps `IngestState`'s existing shape (a plain struct of `Option<Handler>` fields) consistent.
4. **`server/mod.rs` wiring** — extend the `IngestState`-building block (208-238) with a second `if let Some(local_cfg) = config.hec.local.as_ref() { ... }` branch building `generic_local` via `hec_local_start(local_cfg, sink, config.hec.max_sourcetype_partitions, source_stats.clone())`.
5. **Tests**: unit `hec_local_start_wires_handler_and_join_handle` (mirror `hec_start_wires_handler_and_join_handle`, `generic_s3.rs:358-391`); new test proving both `generic_s3` and `generic_local` receive a record when both configured; config tests. Integration `tests/hec_local_integration.rs` mirroring `tests/hec_s3_integration.rs`. **Compile-forced fix**: `IngestState` gains a new required struct field (`generic_local`), so every existing literal construction (grepped: 5 across `ingest/mod.rs`, `server/mod.rs`×3, `handlers.rs`) needs a `generic_local: None` added — small but touches every existing test file for this source.
6. **E2E**: `hec_e2e.rs` already exists as a Rust-level e2e test — verify whether HEC has simulation-environment docker-compose coverage before assuming a `hec-local-verifier` docker service is the right test surface; a Rust-level `tests/hec_local_integration.rs` plus extending `tests/hec_e2e.rs` may be sufficient and cheaper.
7. **Gotcha**: no surprise on partitioning (confirmed orthogonal). The actual gotcha is architectural: **no `Handler` trait to fan out through**, requiring the sibling-`Option`-field pattern instead of `MultiXxxHandler`.

### 3.6 WEF

**Scope recommendation: include it — it is not legacy.** Despite looking like a candidate for exclusion, reading the code shows the opposite: WEF (Windows Event Forwarding) is the **original, founding feature** of this server — `main.rs:21-22` literally logs `"Starting WEF Server with {} worker threads"` and `"Starting WEF Server v{}"`, the binary's own identity is "the WEF server." It was actively migrated to the generic buffered-writer architecture (`ba3a5c9 refactor(wef): migrate WEF→S3 to generic ParquetWriterHandle<WefSink>`), has a dedicated `tests/wef_s3_integration.rs`, extensive route-handler tests in `server/mod.rs`, and full Kerberos-auth support wired through it. There is no deprecation notice anywhere. **Excluding it from this pass would leave the actual primary product surface without the new capability** — include it.

1. **Config** — new `WefLocalConfig` mirroring `WefS3Config` (`config/mod.rs:429-449`), same empty-`prefix`-by-default nuance (`WefS3Config.prefix` defaults to `""` to preserve the legacy `event_type=<id>/year=…` layout — `WefLocalConfig` should default `prefix` to `""` too, for on-disk layout parity with the S3 layout). `WefConfig` (466-470) gains `pub local: Option<WefLocalConfig>`.
2. **`build_wef_handle` extraction** from `wef_start` (`parquet_s3.rs:100-126`).
3. **No `Handler` trait** (same shape as HEC) — `AppState.parquet_s3_sender: Option<ParquetWriterHandle<WefSink>>` (`server/mod.rs:50-54`) is used at exactly **one** call site (`server/mod.rs:638-649`). Add sibling field `parquet_local_sender: Option<ParquetWriterHandle<WefSink>>` to `AppState`, and at the single call site try both (clone `event` — already `Arc<WindowsEvent>`, so cloning is just an Arc-refcount bump):
   ```rust
   if let Some(ref sender) = state.parquet_s3_sender { sender.try_send(event.clone())...; }
   if let Some(ref sender) = state.parquet_local_sender { sender.try_send(event.clone())...; }
   ```
4. **`server/mod.rs::Server::new` wiring** — extend the block at 172-196 with a second `if let Some(wef_local_cfg) = config.wef.local.as_ref() { ... }` branch, producing a `wef_local_worker_handle`. This must also be threaded through shutdown — cleanest change is probably to have `Server` collect both WEF handles into one `Vec<JoinHandle<()>>` internally and expose a single `take_wef_worker_handles() -> Vec<...>` rather than adding parallel single-`Option` accessor methods.
5. **Tests**: unit `wef_local_start_spawns_and_exits_cleanly` (mirror `wef_start_spawns_and_exits_cleanly`, `parquet_s3.rs:266-303`); a test proving `AppState` with both senders set delivers to both; config tests. Integration `tests/wef_local_integration.rs` mirroring `tests/wef_s3_integration.rs`.
6. **E2E**: existing `wef-generator` service already runs (`run.sh:26`); no S3 verifier is explicitly named for WEF — worth double-checking exact e2e coverage for WEF before assuming a `wef-s3-verifier`/`wef-local-verifier` pair is the right shape; it may currently be verified only via a shared `s3-verifier`, in which case the local counterpart should extend that shared verifier rather than create a new per-source one.
7. **Gotcha**: `max_partitions: 0` (unbounded — "EventIDs are bounded in practice") — no overflow-bucket behavior exists for WEF at all, unlike Zeek/Suricata. Also the two-handle-threading-through-shutdown wrinkle above is WEF-specific bookkeeping not present in any trait-object source, since WEF's shutdown sequencing is manually wired in `main.rs` rather than going through the generic `writer_handles` vec.

## 4. Cross-cutting item: the `unused_s3_connection_placeholder()` duplication

Zeek's `zeek_s3.rs:186-194` defines a private `unused_s3_connection_placeholder()`. If each of the 6 remaining sources copies this verbatim into its own file, that's 6 duplicate private functions doing the same thing. Recommend hoisting this one function to `src/forwarding/buffered_writer.rs` (or `mod.rs`) as `pub(crate) fn unused_s3_connection_placeholder() -> S3ConnectionConfig` in a small preparatory commit before the first non-Zeek source lands — small enough to bundle into the Suricata PR (first one after Zeek) as a "also dedupe this helper" commit.

## 5. Sequencing recommendation

1. **Suricata first** (of the remaining 6). Structurally closest to Zeek — validates that the `build_xxx_handle` extraction + `MultiXxxHandler` fan-out + `main.rs` `Vec<Arc<dyn Handler>>` pattern generalizes to a second source with *zero* new architectural questions, before spending effort on sources that need something different (WEF/HEC's no-trait shape, syslog's `PayloadDispatchingHandler` decorator layer). Also a good point to hoist `unused_s3_connection_placeholder()` (§4).
2. **IPFIX and sFlow next**, in either order — both single/low-cardinality partition, same `Vec<Arc<dyn Handler>>` `main.rs` pattern as Suricata, no new wrinkles. Doing both back-to-back after Suricata means 3 of 4 trait-object sources are done with an identical, by-then-well-rehearsed diff shape.
3. **syslog** (primary only, §2) — do this after the above three, not before, because it's the one trait-object source with the extra `PayloadDispatchingHandler<H>` generic-decorator layer; better to have the base pattern fully proven on 3 "plain" sources first.
4. **HEC/generic and WEF last**, in either order — both are the no-`Handler`-trait, sibling-`Option`-field shape, architecturally distinct from the first four. Doing these last means the "does this really need a Multi-handler wrapper, or just two Option fields" design call is made once the team has full confidence in the trait-object pattern from having shipped it 4 times.
5. **Structured syslog** — explicit standalone follow-on after primary syslog ships (§2), not part of this 6-source sequence at all.

## 6. One PR per source, not one big PR

The repo's own history strongly supports this: Zeek's local-disk work landed as **9 separate commits** (`eda8525` UploadSink trait → `2c14527` S3Sink impl → `16105b3` generalize writer → `fa1f1aa` config → `cbcf89c` start+Multi → `8890f34` main.rs wiring → `4b6dc36` integration test → `62ed05a` e2e → plus doc commits), and every other source's *original* S3 support similarly landed as its own multi-commit sequence scoped to one source. Each source's `.local` support is independently shippable, independently testable, and touches a disjoint set of files with the sole shared-file exception being `config/mod.rs` and `main.rs`/`server/mod.rs`, which already accumulate one region per source without conflict. Recommend **6 independent PRs** (5 after deferring structured syslog, sequenced per §5), each following the same commit-granularity pattern Zeek used (trait/type change → config → start-fn+multi-handler → wiring → integration test → e2e → docs), not one combined PR.

## Critical Files for Implementation

- `src/forwarding/zeek_s3.rs` — the reference implementation every other source's diff should mirror line-for-line where the shape matches (`build_zeek_handle`, `MultiZeekHandler`, `zeek_local_start`)
- `src/config/mod.rs` — every new `XxxLocalConfig` struct and `Config`/`XxxConfig.local` field land here
- `src/main.rs` — wiring for the 4 remaining trait-object sources (suricata, ipfix, syslog, sflow)
- `src/server/mod.rs` — wiring for WEF and HEC/generic (the no-`Handler`-trait shape); `AppState`/`IngestState` field additions and the two `try_send` call sites
- `src/ingest/handlers.rs` and `src/ingest/mod.rs` — the 4 `ingest.generic_s3` call sites and `IngestState` struct that need a sibling `generic_local` field for HEC
- `tests/zeek_local_integration.rs` and `tests/e2e/simulation-environment/{docker-compose.yml,run.sh,zeek-local-verifier/}` — the template for each new `tests/xxx_local_integration.rs` and each new `xxx-local-verifier` e2e service (and the place to fix the pre-existing `run.sh` omission noted in §0)
