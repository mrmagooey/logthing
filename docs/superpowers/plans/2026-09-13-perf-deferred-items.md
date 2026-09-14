# Deferred Perf Items Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close the items deferred by `2026-09-13-ingestion-perf-test-coverage.md`, fixing the two real defects first and adding measurement only where something is genuinely unmeasured.

**Architecture:** Four tiers, executable independently and in priority order. Tier 1 is production defects. Tier 2 is the only change here that could improve throughput rather than measure it — whether it does is the task's question, not its premise. Tier 3 closes the last real measurement gaps. Tier 4 is more load generators, and is the first thing to cut.

**Spec:** The "Explicitly deferred" table in `docs/superpowers/plans/2026-09-13-ingestion-perf-test-coverage.md`, plus residuals surfaced while executing it (recorded in `docs/performance/2026-09-13-multiformat-load-results.md`).

## Global Constraints

- **Build environment — mandatory.** `export CC=/usr/bin/gcc CXX=/usr/bin/g++` and `export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc`. `~/.local/bin/cc` is a zig-cc shim that breaks `ring`/`zstd-sys` with an opaque `UnknownOperatingSystem`.
- **Never work on `master`.** One branch per tier.
- Benches are external crates: only `pub` items from `logthing::` are reachable. `#[cfg(test)]` fixtures must be reproduced inline, with a header comment saying so.
- Every bench header states what it measures, what it deliberately does not, and `Run with: cargo bench --bench <name>`.
- **A new bench target needs its `[[bench]]` entry and its file in the same commit.** Cargo fails at manifest-parse time on a registered bench with no file, which breaks build/test for the whole package.
- `cargo bench` must not be run with criterion flags against lib/bin targets — `[lib] bench = false` and `[[bin]] bench = false` already handle this; do not remove them.
- Pre-push runs fmt → clippy `-D warnings` → test → `bench --no-run`. Run it manually, then push `--no-verify`.
- **Commit before mutation-testing.** Reverting a mutation with `git checkout` destroys uncommitted work; use a file copy.
- Stage explicit paths, never `git add -A <dir>` — untracked files get swept in.

## Findings that drive this plan

Verified 2026-09-13 at `master` `fdfe806`. Do not re-derive:

1. **`suricata_records_received` and `suricata_records_by_event_type` are dead in production** (`src/suricata/listener.rs:49-50`). They live in `DefaultSuricataHandler`, which `main.rs` installs only when zero forwarding destinations are configured. Identical to the zeek defect fixed in v0.18.0. Suricata is the last protocol with this shape.
2. **`scripts/run-with-profiling.sh` is provably rotted** — 9 references to `LOGTHING__FORWARDING__DESTINATIONS__0__*`, a config shape that no longer exists (`src/config/mod.rs` mentions "destinations" only in an unrelated doc comment).
3. **`SO_RCVBUF` is never set on any listener socket.** Phase 2 measured 13.5% IPFIX loss in the kernel receive queue at 5,000/s with `rmem_default` = 208 KiB. Measured on this host 2026-09-13: uid 1000, no `CAP_NET_ADMIN`, so a 4 MiB request clamps — but still yields an actual buffer of **425984 vs the 212992 default**, a 2x gain with no sysctl change. Whether that translates into less loss is Tier 2's question.
4. **Two parse paths are genuinely unmeasured**: `WefParser::parse_event` (`src/parser/mod.rs:201`, `pub`) and `map_otlp_request` (`src/server/otlp.rs:26`, `pub`). Both are `pub`, so both are benchable without extraction.
5. **`StructuredSyslogSink::to_record_batch`** (`src/forwarding/structured_syslog_s3.rs:137`) is the only sink with zero encode coverage.
6. **`loadgen` has 3 of 7 subcommands.** Suricata is the cheapest remaining — identical TCP NDJSON shape to `zeek-tcp`.
7. Encode dominates parse everywhere (criterion baseline): binary decode is 42-50x cheaper than encode. Do not open a decoder optimisation.

---

## Tier 1 — Real defects

Branch: `fix/suricata-dead-counters`.

### Task 1: Move suricata's ingest counters onto the listener parse path

**Files:** `src/suricata/listener.rs` (modify), `tests/suricata_received_metric_integration.rs` (create)

This is the same fix v0.18.0 applied to zeek. Read that commit first: `git show 75ebc39 -- src/zeek/listener.rs` shows the shape.

- [ ] **Step 1: Write the failing integration test**

Create `tests/suricata_received_metric_integration.rs`, modelled on `tests/zeek_received_metric_integration.rs` — copy its structure verbatim and adapt the names. It installs a real `PrometheusBuilder` recorder globally, so it must contain exactly ONE `#[tokio::test]`; say so in the file header.

It must: start a real `SuricataListener` with a **non-default** handler (suricata's equivalent of `MultiZeekHandler` — check `src/forwarding/suricata_s3.rs` for `suricata_local_start`), send 3 EVE JSON lines over a real TCP connection (2 `alert`, 1 `flow`), then assert on `handle.render()`:
- `suricata_records_received` == 3
- `suricata_records_by_event_type{event_type="alert"}` == 2 and `{event_type="flow"}` == 1

- [ ] **Step 2: Run it and confirm it FAILS**

`cargo test --test suricata_received_metric_integration` → must fail with the counters absent from the exposition. That failure is the bug.

- [ ] **Step 3: Move the counters**

In `src/suricata/listener.rs`, delete both `metrics::counter!` calls from `DefaultSuricataHandler::handle_record` and emit them in `handle_tcp_connection` immediately before `handler.handle_record(parsed.record, src).await`, next to the existing `suricata_missing_event_type` increment.

**Bound the label.** `event_type` is wire-supplied and unbounded, exactly like zeek's `_path`. Zeek solved this with `zeek::schema::metric_log_path`, mapping to the schema registry's `&'static str` keys or `"other"`. Suricata has one schema (`envelope_schema`) and therefore no registry to derive from, so the allowlist is written out explicitly:

```rust
/// Suricata's EVE `event_type` values, as a closed set. The wire value is
/// unbounded in length and charset, so it must never reach a Prometheus label
/// raw — see `zeek::schema::metric_log_path` for the same problem solved
/// against a registry.
///
/// Hand-maintained, and that is a real difference from zeek's version, which
/// self-updates when a schema is added. Adding a new EVE type here is a
/// deliberate act; until it is added it reports as "other".
const EVE_EVENT_TYPES: &[&str] = &[
    "alert", "anomaly", "drop", "dns", "http", "tls", "ssh", "smtp", "ftp",
    "smb", "dhcp", "krb5", "flow", "netflow", "fileinfo", "stats",
];

pub fn metric_event_type(event_type: &str) -> &'static str {
    EVE_EVENT_TYPES
        .iter()
        .find(|known| **known == event_type)
        .copied()
        .unwrap_or("other")
}
```

**Do NOT derive this list by grepping the codebase.** Only `alert`, `anomaly`, `dns`, `flow`, `stats` and `unknown` appear in `src/suricata/` and `tests/` today — `http`, `tls` and `ssh` appear nowhere, yet they are among the highest-volume types in real deployments. A grep-derived list would silently collapse them into `"other"` and destroy exactly the visibility this metric exists to give.

Unit-test it as `zeek::schema::metric_log_path` is tested: every listed type maps to itself, and hostile inputs (a 16 KiB string, an embedded NUL, empty) all map to `"other"`.

- [ ] **Step 4: Confirm the test now passes**, plus `cargo test --lib suricata::` and `cargo test --test suricata_local_integration`.

- [ ] **Step 4b: Add the unit-level test.** The zeek fix shipped at three levels and this must match — the standing project policy requires unit, integration and e2e for new behaviour. Add a suricata analogue of `received_counters_fire_with_a_non_default_handler` (`src/zeek/listener.rs:428`) to `src/suricata/listener.rs`'s test module: a `DebuggingRecorder` with `set_default_local_recorder`, driving `handle_tcp_connection` inline over a real socket with `CapturingHandler` (NOT `DefaultSuricataHandler` — that is the whole point), asserting `suricata_records_received` and the labelled `suricata_records_by_event_type`.

- [ ] **Step 4c: Add the e2e test.** Create `tests/suricata_received_metric_e2e.rs`, mirroring `tests/zeek_received_metric_e2e.rs`: a real `Server` with `metrics.enabled = true`, a real `SuricataListener` with a real forwarding handler, EVE JSON over a real TCP connection, then scrape the production `/metrics` HTTP endpoint. One `#[tokio::test]` per binary — `Server::run` calls `metrics::set_global_recorder`, which panics on a second call.

- [ ] **Step 4d: Prove all three guard the bug.** Revert the Step 3 move (counters back in `DefaultSuricataHandler`), confirm each of the three fails, restore. Commit before doing this — reverting a mutation with `git checkout` discards uncommitted work.

- [ ] **Step 5: Update `DefaultSuricataHandler`'s doc comment**, which will claim it "increments metrics" and no longer will.

- [ ] **Step 6: Commit.** Message must state that the counters were dead in any deployment with a forwarding destination configured, and that the label is bounded because `event_type` is attacker-influenceable.

### Task 2: Delete or repair `scripts/run-with-profiling.sh`

**Files:** `scripts/run-with-profiling.sh`

- [ ] **Step 1: Establish whether anything uses it.** `grep -rn "run-with-profiling" . --exclude-dir=target --exclude-dir=.git`. Check `.github/workflows/`, `docs/`, and other scripts.
- [ ] **Step 2: Decide and act.** If nothing references it, **delete it** — a script that cannot run is worse than no script, because it looks like a supported path. If something does reference it, port the 9 `LOGTHING__FORWARDING__DESTINATIONS__0__*` env vars to the current config shape (compare against `scripts/profile-syslog-udp.sh`, which works).
- [ ] **Step 3: Commit**, stating which branch you took and the evidence.

---

## Tier 2 — The only change here that could improve throughput

Branch: `perf/so-rcvbuf`.

### Task 3: Make the UDP receive buffer configurable and default it higher

**Files:** `src/config/mod.rs`, the three UDP listeners (`src/ipfix/listener.rs`, `src/sflow/listener.rs`, `src/syslog/listener.rs`), tests.

Phase 2 measured 13.5% IPFIX loss in the kernel queue at only 5,000/s. `rmem_default` was 208 KiB and `SO_RCVBUF` was never set. This is the highest-value change available.

- [ ] **Step 1: Confirm the current state.** `grep -rn "SO_RCVBUF\|set_recv_buffer" src/` — expect nothing. Confirm how each UDP socket is constructed (`UdpSocket::bind`).

- [ ] **Step 2: Write the failing test.** A test that binds a listener socket through the production path and asserts the receive buffer is larger than the OS default. Reading it back needs `socket2` (check whether it is already an indirect dependency before adding it) or a raw `getsockopt`. Note the kernel **doubles** the value you set, and silently clamps to `net.core.rmem_max` unless the process has `CAP_NET_ADMIN` — so assert "larger than default", not an exact value, and say why in a comment.

- [ ] **Step 3: Add config.** A `receive_buffer_bytes: Option<usize>` on the UDP listener configs, defaulting to something meaningfully above 208 KiB (4 MiB is a common choice). `None` means "leave the OS default alone".

- [ ] **Step 4: Apply it at bind time** in all three UDP listeners. **The clamp is the trap**: if `rmem_max` is lower than requested, the kernel silently gives you less. Log the requested and actual values at startup so an operator can see the clamp rather than wondering why drops persist. This logging is the deliverable as much as the setsockopt is.

- [ ] **Step 5: Verify it actually helps.** Re-run the Phase 2 IPFIX measurement (`docs/performance/2026-09-13-multiformat-load-results.md` §6 has the exact commands) before and after, at 5,000/s and 20,000/s. Record kernel loss both ways.

**The clamp behaviour here is already measured — do not re-derive it, and do not assume it means failure.** On this host (uid 1000, no `CAP_NET_ADMIN` in the effective set, `rmem_max` = `rmem_default` = 212992), requesting 4 MiB yields an actual `SO_RCVBUF` of **425984**: the kernel clamps the request to `rmem_max` and then doubles it for bookkeeping. So the buffer still **doubles** versus the 212992 default, unprivileged, with no sysctl change.

That means the expected outcome is a real but bounded improvement, not nothing. Report the measured kernel-loss delta whatever it is. **If loss does not improve despite the buffer doubling, say so plainly** — that would mean the loss is driven by recv-task scheduling rather than buffer depth, which is a more interesting finding than the one this task set out to confirm.

- [ ] **Step 6: Commit, and update the results doc** with the before/after, including a clamp caveat if one applied.

---

## Tier 3 — The last real measurement gaps

Branch: `perf/remaining-benches`. All three tasks are independent; dispatch concurrently, but **register all three `[[bench]]` entries and files in one prep commit first** so no two agents touch `Cargo.toml`.

### Task 4: WEF XML parse bench

**Files:** `benches/wef_parse_recv_path.rs` (create), `Cargo.toml`

`WefParser::parse_event(&self, event_id: u32, xml: &str) -> Option<ParsedEventData>` (`src/parser/mod.rs:201`) is `pub`. XML parsing is typically the most expensive parse in any ingest stack and this one has never been measured — it may well be the dearest parse path in the repo.

- [ ] Bench at least: a small Security event (4624 logon) and a large one with many `EventData` fields. Take real XML shapes from `tests/e2e/simulation-environment/` or the WEF tests.
- [ ] Include an event id with **no** registered parser, so the `has_parser` miss path is measured too — that is the common case for unmodelled events.
- [ ] Setup assertion: each fixture must return `Some` (except the deliberate miss), so a malformed fixture fails loudly rather than timing an early return.
- [ ] Compare against the committed encode figure (WEF encode is 6.32 µs). Report the parse:encode ratio.

### Task 5: OTLP protobuf mapping bench

**Files:** `benches/otlp_map_request.rs` (create), `Cargo.toml`

`map_otlp_request(req: ExportLogsServiceRequest, source_host: String) -> Vec<GenericRecord>` (`src/server/otlp.rs:26`) is `pub`. The existing `generic_hec_to_record_batch` bench covers the shared *writer* path; OTLP's own request mapping is unmeasured.

- [ ] Bench a single-record request and a realistic batch (100 log records in one request) — OTLP clients batch aggressively, so per-request cost at batch size 1 is not the operating point.
- [ ] `Throughput::Elements(n)` so criterion reports per-record.
- [ ] This may need the `otlp` feature flag — check `Cargo.toml` and gate the bench if so.

### Task 6: Structured-syslog encode bench

**Files:** `benches/structured_syslog_to_record_batch.rs` (create), `Cargo.toml`

`StructuredSyslogSink::to_record_batch` (`src/forwarding/structured_syslog_s3.rs:137`) is the only sink with zero encode coverage.

- [ ] Mirror `benches/syslog_message_to_record_batch.rs`'s call shape exactly.
- [ ] Bench at least two payload types that `syslog::payload::dispatch` recognises (CEF and one other — read `src/syslog/payload/mod.rs` for the list).
- [ ] Note in the header that all sink schemas gained a non-null `partition_time` column in v0.16.0, so figures are not comparable to anything pre-2026-09-06.

### Task 7: Extend the criterion baseline doc

**Files:** `docs/performance/2026-09-13-criterion-baseline-0.18.0.md` (modify)

- [ ] Add the three new figures to the existing tables, marked with their measurement date if it differs.
- [ ] Update the "Still not covered at this layer" list — after Tier 3 only syslog TCP and syslog HTTP remain, and both share their parse with syslog UDP, which is already covered. Say that plainly so nobody adds a redundant bench.
- [ ] Keep the hardware caveat at the top. If run on different hardware than the original, **add a second provenance block rather than overwriting the first.**

---

## Tier 4 — More load generators (cut this first if effort is short)

Branch: `perf/loadgen-suricata`.

### Task 8: `loadgen suricata-tcp`

**Files:** `tools/loadgen/src/suricata_tcp.rs` (create), `tools/loadgen/src/main.rs` (modify)

The cheapest remaining format: identical TCP NDJSON transport to `zeek-tcp`.

**On why this is included at all**, given the plan lists Tier 4 as first to cut: it exercises Task 1's fix against real sustained wire traffic, which the committed tests do not. That is incidental validation, **not** a substitute for Task 1's own three-level coverage — its smoke check is a manual one-off, not a CI-run regression test. If effort runs short, cut this and lose nothing that Task 1 Steps 1-4c do not already guard.

- [ ] **Read `tools/loadgen/src/zeek_tcp.rs` first and mirror it.** Same arg names, same one-held-connection, same abort-on-write-error (never reconnect — a silent reconnect hides the server-side backpressure the generator exists to measure), same inline `async {}` block for partial-count reporting, same `crate::pacing` use.
- [ ] `--event-type` (default `alert`) in place of zeek's `--log-path`.
- [ ] Test the wire format with **logthing's own parser**: `logthing::suricata::parse_line` must return `Ok` and the parsed `event_type` must match. This is the established convention — do not hand-roll a check.
- [ ] Smoke-test against a live server and confirm `suricata_records_received` matches the generator's count. **After Task 1 this counter works; before it, it would read zero** — so this task depends on Tier 1 Task 1 having landed.

**sFlow, HEC and OTLP generators remain deferred.** Three more subcommands is a lot of code for diminishing returns, and nothing currently blocks on them.

---

## Explicitly NOT in scope

| Item | Why |
|---|---|
| `tests/e2e/real-ad-environment/scripts/test_phase3_performance.py` | Needs a provisioned AD domain, four joined Windows hosts, and SSH credentials. Out of reach by construction, not by effort. |
| Re-dating the three 0.9.0-era `docs/performance/` docs | They state their own provenance honestly. Superseding them means re-running whole-system load on tuned hardware — a bigger exercise than this plan, and the 0.18.0 docs sit alongside them rather than replacing them. |
| `loadgen` sflow / hec / otlp subcommands | Diminishing returns; nothing blocks on them. |
| Multi-address fallback in `loadgen`'s UDP resolution | Reviewed and judged negligible for a dev/test tool whose targets are `127.0.0.1`, `localhost`, or a single-address compose service. |
| Any decoder optimisation | The baseline puts binary decode at 42-50x cheaper than encode. There is no case for it. |
