# S3 Persistence Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) tracking. These are refactors on WORKING, reviewed code — the existing test suite (321 passing) is the safety net; it must stay green at every step.

**Goal:** Resolve the non-blocking follow-ups from the IPFIX+S3 final whole-branch review: converge the two S3 writers, dedupe S3 config, fix module/test hygiene, and clear small nits.

**Architecture:** Two sequential phases on one branch (`feat/s3-followups`). Phase A reworks the forwarding writers + S3 config (high file overlap, done as one coherent unit). Phase B does crate-module + doc hygiene. Sequential because both touch `src/config/mod.rs` and `src/main.rs`.

**Tech Stack:** Rust 2024, tokio, arrow/parquet, aws-sdk-s3, `serde`, `metrics`.

## Global Constraints
- Rust 2024; 100-col; 4-space indent; `cargo fmt`; `cargo clippy -- -D warnings` must add NO new warnings (the repo has ~25 pre-existing; do not regress, and DO remove the ones this plan targets).
- `export PATH="$HOME/.cargo/bin:$PATH"` before any cargo command (cargo is not on the default PATH).
- Behavior-preserving for the WEF→S3 path and all three persistence flows: data still lands in S3 with the same schemas; only internals/config-shape change.
- Pre-1.0 (v0.1.0 just tagged), so config-key renames for coherence are acceptable, but every change must keep `serde(default)` backward-compat where a field is OPTIONAL (absent S3 config still = no persistence).
- Full suite (`cargo test`) green after every task; commit per task (conventional messages).

## Decisions (made for the judgment calls; flagged for the record)
- **D1 (item 7 — syslog S3 disables DNS parsing):** DOCUMENT only, do not change behavior. Enabling `[syslog.s3]` swaps to the S3 handler which does not run DNS-log extraction; this is acceptable and out of the original feature's scope. Add a note in README + a code comment. (Composing persistence + DNS parsing is a deliberate future feature, not a cleanup.)
- **D2 (item 2 — config coherence):** standardize the prefix field name to `prefix` on BOTH syslog and ipfix S3 config, default slash-free (`"syslog"` / `"ipfix"`), with each `build_*key` inserting the `/` separator. Add `channel_capacity` to syslog S3 config (default 4096) and wire it via `start_with_capacity`, matching ipfix.
- **D3 (item 3 — dedupe S3 fields):** introduce `S3ConnectionConfig { endpoint, bucket, region, access_key, secret_key }`, `#[serde(flatten)]`-embedded in `SyslogS3Config` and `IpfixS3Config` (keeps flat TOML). Add `S3Sink::from_connection(&S3ConnectionConfig)`; syslog/ipfix build via it, deleting the `to_parquet_s3_config()` phantom-field bridges. LEAVE the WEF `ParquetS3Config` + `S3Sink::from_config(&ParquetS3Config)` untouched (low blast radius).
- **D4 (item 1 — buffer accounting):** in `ipfix_s3.rs` replace the fragile parallel `buffer_bytes: VecDeque<usize>` with a single buffer whose elements carry their byte estimate (`VecDeque<(RecordBatch, usize)>` or a small struct), removing all two-deque sync risk. Keep the byte-based flush trigger. (Full syslog/ipfix convergence onto a shared generic writer is noted as a larger future option, not done here.)
- **D5 (item 4 — module double-compile):** make `src/lib.rs` the single module home (add `admin/middleware/parser/protocol/server/stats` as `pub mod` alongside the existing ones) and convert `src/main.rs` to a thin binary that `use`s the `logthing` crate instead of re-declaring modules — eliminating the lib+bin double compilation and double test-run.

---

## PHASE A — Forwarding writers + S3 config convergence

### Task A1: Single-deque byte accounting in IpfixS3Writer (item 1, D4)
**Files:** Modify `src/forwarding/ipfix_s3.rs`.
**Interfaces:** Produces: unchanged public `IpfixS3Writer`/`IpfixS3Handler` API; internal buffer becomes `VecDeque<(RecordBatch, usize)>` (or a named `BufferedBatch` struct). `buffered_bytes`/`buffer_row_count` scalars remain.
- [ ] Add/confirm a unit test driving push beyond the hard cap with an unreachable `S3Sink`, asserting `buffered_rows()` stays ≤ cap AND `buffered_bytes` is consistent with the remaining buffer (sum of element byte estimates). Run, see current behavior.
- [ ] Replace the parallel `buffer_bytes` deque: store `(batch, est_bytes)` per element; on `push_batch` push the pair; in `drop_oldest_to_cap` pop the pair and subtract its `est_bytes` (no `unwrap_or(0)` masking — the byte travels with the batch); on `flush` clear the single deque and zero the scalars.
- [ ] `cargo test forwarding::ipfix_s3 --quiet` green; `cargo clippy -- -D warnings` clean for the file; commit.

### Task A2: Shared S3ConnectionConfig + from_connection (item 3, D3)
**Files:** Modify `src/config/mod.rs`, `src/forwarding/s3_sink.rs`, `src/forwarding/syslog_s3.rs`, `src/forwarding/ipfix_s3.rs`, `src/main.rs`.
**Interfaces:** Produces: `pub struct S3ConnectionConfig { endpoint, bucket, region, access_key, secret_key }` (Debug/Clone/Deserialize/Serialize); `S3Sink::from_connection(cfg: &S3ConnectionConfig) -> anyhow::Result<S3Sink>`. `SyslogS3Config`/`IpfixS3Config` embed it via `#[serde(flatten)] connection: S3ConnectionConfig`.
- [ ] Config unit tests: a `[syslog.s3]`/`[ipfix.s3]` TOML block with flat `endpoint/bucket/region/...` keys still deserializes (flatten keeps it flat); absent block still => `None`. Run/see fail.
- [ ] Implement `S3ConnectionConfig`; add `S3Sink::from_connection` (move the client-construction body; have the existing `from_config(&ParquetS3Config)` delegate by building an `S3ConnectionConfig` from the ParquetS3Config fields, so WEF stays behavior-identical and the construction logic lives in one place).
- [ ] Flatten the connection struct into `SyslogS3Config`/`IpfixS3Config`; update their handlers to call `S3Sink::from_connection(&cfg.connection)`; delete `to_parquet_s3_config()`. Update `main.rs` call sites.
- [ ] Full `cargo test` green (incl. existing parquet_s3/WEF tests UNCHANGED); clippy clean; commit.

### Task A3: Prefix-name + channel-capacity coherence (item 2, D2)
**Files:** Modify `src/config/mod.rs`, `src/forwarding/syslog_s3.rs`, `src/forwarding/ipfix_s3.rs`, `src/main.rs`.
**Interfaces:** Produces: both configs expose `prefix: String` (default `"syslog"`/`"ipfix"`, slash-free) + `channel_capacity: usize`; both `build_*_key` insert `/` between prefix and the date partition.
- [ ] Tests: assert syslog key for default prefix is `syslog/year=.../...` (builder-inserted slash) and respects a custom slash-free prefix; assert a configured `channel_capacity` is honored by `SyslogS3Handler` (capacity=1 drops, large doesn't — mirror the ipfix wiring test). Run/see fail.
- [ ] Rename syslog `key_prefix`→`prefix` (slash-free default), update `build_key` to insert `/`; add `channel_capacity` to `SyslogS3Config` (default 4096) and call `SyslogS3Handler::start_with_capacity(cfg, sink, channel_capacity)` from `main.rs`; ensure ipfix `prefix` default is slash-free and its builder inserts `/` (already does — confirm).
- [ ] Full `cargo test` green; clippy clean; commit.

### Task A4: Small nits — dup upload log + unused constructor (items 5-log, 6)
**Files:** Modify `src/forwarding/parquet_s3.rs` (or `s3_sink.rs`), `src/ipfix/listener.rs`, `src/syslog/listener.rs`.
- [ ] Remove the duplicate upload `info!`: keep exactly one "Uploaded … to S3" line (keep the one in `S3Sink::upload`; drop the redundant one in `parquet_s3.rs::upload_to_s3`). Confirm via reading; no test asserts on log text.
- [ ] Resolve the unused `with_default_handler` constructors flagged by clippy: remove `IpfixListener::with_default_handler` and the pre-existing unused `SyslogListener::with_default_handler` (neither is called; `main.rs` constructs handlers directly). If removal breaks a test, wire the test to the real construction instead.
- [ ] `cargo clippy -- -D warnings` shows these two `with_default_handler` warnings GONE and no new ones; `cargo test` green; commit.

### Task A5: Document syslog-S3 / DNS-parsing interaction (item 7, D1)
**Files:** Modify `README.md`, `src/syslog/listener.rs` (doc comment on the S3 handler / `parse_dns`).
- [ ] Add a short note: when `[syslog.s3]` persistence is enabled, the S3 handler is used and DNS-log extraction (`parse_dns`) does not run; the two are currently mutually exclusive. No code-behavior change.
- [ ] `cargo test` green (docs only); commit.

---

## PHASE B — Crate-module + doc hygiene (after Phase A merged-in on the branch)

### Task B1: main.rs uses the `logthing` lib crate (item 4, D5)
**Files:** Modify `src/lib.rs`, `src/main.rs`.
**Interfaces:** `src/lib.rs` becomes the single declaration site for ALL modules main needs (`pub mod admin; middleware; parser; protocol; server; stats;` added to the existing `config/forwarding/ipfix/models/syslog`). `src/main.rs` removes its `mod …;` lines and `use logthing::{…}` instead.
- [ ] Before: run `cargo test --lib` and `cargo test --bin logthing` and note the duplicated test counts. 
- [ ] Add the missing `pub mod` lines to `lib.rs`; promote any module/item visibility main.rs needs (only as far as required). Convert `main.rs` to `use logthing::server::Server;` etc., dropping `mod` declarations.
- [ ] Verify the binary still builds and runs (`cargo build` + `cargo run -- --help` if a help path exists, else `cargo build`); `cargo test` passes and the SAME tests no longer run twice (lib test count unchanged, bin test count drops to only `main.rs`'s own tests if any). Commit.

### Task B2: Doctest + stale `wef_server::` examples (item 5-doctest)
**Files:** Modify `Cargo.toml` (`[lib] doctest`), doc comments in `src/forwarding/mod.rs`, `src/syslog/mod.rs`, `src/models/mod.rs`, `src/config/mod.rs` (any `wef_server::` in `///` examples).
- [ ] Grep for `wef_server::` in doc comments; rename each to `logthing::` so the examples reference the real crate name.
- [ ] Remove `doctest = false` from `Cargo.toml` `[lib]` so doc examples compile again; keep `no_run` where present (examples shouldn't execute network/FS). Run `cargo test --doc` — it must pass (examples compile). If any example can't be made to compile cleanly, mark that specific example ` ```no_run ` / ` ```ignore ` with a one-line reason rather than re-disabling all doctests.
- [ ] `cargo test` (incl. `--doc`) green; commit.

---

## Self-Review
- **Coverage:** items 1(A1), 2(A3), 3(A2), 4(B1), 5(A4+B2), 6(A4), 7(A5) — all mapped.
- **Placeholders:** none — each task has concrete files, contracts, and acceptance commands.
- **Type consistency:** `S3ConnectionConfig`/`from_connection` names used identically across A2 call sites; `prefix`/`channel_capacity` field names consistent across A3 and main.rs.
- **Risk:** A2 (touches WEF config path via delegation) and B1 (crate restructure) are the riskiest — both gated by the unchanged existing test suite; review both adversarially for behavior drift.
