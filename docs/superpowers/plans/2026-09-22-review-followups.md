# Review follow-ups (2026-09-22) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the five follow-ups left by the review-fix branch: the Zeek overflow `log_path`, Zeek metric casing, `flush_all` counts, dead WEF error arms, and IPFIX variable-length fields.

**Architecture:** Four sequential tasks on `fix/review-2026-09-22`, each a root-cause fix in the shared function, with tests at every applicable level.

**Tech Stack:** Rust 2024, tokio, arrow/parquet 53, quick-xml 0.31, `metrics` 0.22.

**Spec:** `docs/superpowers/specs/2026-09-22-review-followups-design.md`

## Global Constraints

- Work ONLY in `/home/dev/projects/logthing-fix-review` on branch `fix/review-2026-09-22`. Never touch `master` or `/home/dev/projects/logthing`.
- Build env (both linker lines required): `source ~/.cargo/env; export CC=/usr/bin/gcc CXX=/usr/bin/g++ CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc CARGO_TARGET_DIR=/home/dev/projects/logthing/target`
- Run every cargo command in the FOREGROUND with timeout 600000 and let the call block. Never background a build and poll it. Check whether cargo is running only with `ps -eo comm | grep -c "^cargo$"`.
- Before committing: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and the task's tests plus `cargo test --lib`, all green.
- Every new metric needs a HELP 3-tuple in `src/metrics_descriptions.rs` (this plan adds none).
- Tests that install a global metrics recorder or spawn `Server::run` must be the ONLY `#[tokio::test]` in their file.
- AGENTS.md: 100-column lines, `///` docs on public items, conventional commits.
- Commit trailer, on every commit; use your own model name in Co-Authored-By:
  ```
  Co-Authored-By: <your model> <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Xsi6CGg4qvtb6NWh87KYGY
  ```
- Mutation-verify every regression test: revert the fix, confirm the test fails, restore. Report the evidence.
- Do not touch: `FlushIntervalRegistry`, `*_start`/`*_local_start` pairs, Kerberos ordering, the aggregate 2 s sleep.

## Review Focus

1. A Zeek overflow record whose path is unknown AND another whose path is typed must BOTH keep their real `log_path` (Task 1, `overflow_records_keep_their_real_log_path`).
2. `metric_log_path` must still bound hostile wire input to the fixed set (`"../Conn"`, `"Ｃonn"`, 1 KB of junk → `"other"`) (Task 1).
3. A varlen field declaring 255 + a 2-byte length larger than the remaining bytes must drop that record without panicking, keeping the records before it (Task 4).
4. A template made ONLY of varlen fields, each with value length 0, must decode one record per `N` bytes and terminate (Task 4).
5. NetFlow v9 flowsets whose template declares length 0xFFFF must behave exactly as before (no records, no panic) (Task 4).

---

### Task 1: Zeek overflow `log_path` + metric casing (spec A1, A2)

**Files:**
- Modify: `src/zeek/schema.rs` (`map_envelope` ~1712 → `pub(crate)`; new private `registry_lookup`; `metric_log_path` ~1781 and `get_schema_entry` ~1797 use it; tests)
- Modify: `src/forwarding/zeek_s3.rs` (`to_record_batch` else-branch ~109-120; tests)
- Modify: `tests/zeek_received_metric_e2e.rs` (add a `"Conn"` line + assertion; keep it a single test)
- Create: `tests/zeek_overflow_log_path_e2e.rs`

- [ ] **Step 1: Failing unit tests.** In `schema.rs` tests:

```rust
#[test]
fn metric_log_path_resolves_case_variants_and_bounds_hostile_input() {
    assert_eq!(metric_log_path("Conn"), "conn");
    assert_eq!(metric_log_path("DNS"), "dns");
    for hostile in ["../Conn", "Ｃonn", "", &"x".repeat(1024)] {
        assert_eq!(metric_log_path(hostile), "other", "{hostile:?}");
    }
}
```

In `zeek_s3.rs` tests:

```rust
#[test]
fn to_record_batch_on_envelope_schema_keeps_real_log_path_for_typed_record() {
    let rec = ZeekRecord {
        log_path: "dns".to_string(),
        fields: serde_json::json!({"_path": "dns", "ts": 1700000000.0}),
        received_at: chrono::Utc::now(),
    };
    let batch = ZeekSink.to_record_batch(&rec, &envelope_schema()).unwrap();
    let col = batch.column_by_name("log_path").unwrap()
        .as_any().downcast_ref::<arrow_array::StringArray>().unwrap();
    assert_eq!(col.value(0), "dns");
}
```

Run both with `cargo test --lib <name>`: expected FAIL (`"other"`; `"_overflow_nonexistent_"`).

- [ ] **Step 2: Implement.** In `schema.rs`:

```rust
/// The registry entry for `log_path`: exact match first, then the
/// `sanitize_log_path` key `ZeekSink` partitions by. The single lookup both
/// `get_schema_entry` and `metric_log_path` use, so the schema a record is
/// written with and the label it is counted under can never disagree.
fn registry_lookup(log_path: &str) -> Option<(&'static str, &'static Arc<SchemaEntry>)> {
    REGISTRY
        .get_key_value(log_path)
        .or_else(|| REGISTRY.get_key_value(sanitize_log_path(log_path).as_str()))
        .map(|(k, v)| (*k, v))
}
```

`metric_log_path` becomes `registry_lookup(log_path).map(|(name, _)| name).unwrap_or("other")`. In `get_schema_entry`, replace the two `REGISTRY.get` checks with `if let Some((_, entry)) = registry_lookup(log_path) { return entry.clone(); }`, keeping its doc comment accurate. (If `REGISTRY`'s `LazyLock` deref doesn't produce `&'static` references, return owned `Arc` clones instead: `Option<(&'static str, Arc<SchemaEntry>)>`.) Make `map_envelope` `pub(crate)`. In `zeek_s3.rs`'s else-branch:

```rust
} else {
    // The buffer holds the envelope schema (the `_overflow` partition)
    // but this record's own path is typed: map it as an envelope row
    // under its real `log_path`.
    crate::zeek::schema::map_envelope(&record.fields, &record.log_path, record.received_at)
        .map_err(|e| {
            anyhow::anyhow!("ZeekSink overflow mapper error for '{}': {e}", record.log_path)
        })
}
```

Run the unit tests: expected PASS. Mutation-check both.

- [ ] **Step 3: Integration.** In `zeek_s3.rs` tests, add `overflow_records_keep_their_real_log_path`: a `PartitionedParquetWriter<ZeekSink>` with `max_partitions = 1` (via `make_zeek_cfg`) over a `LocalDiskSink` tempdir. Push `conn`, then `dns` (typed) and `weird` (unknown); `flush_all` + `drain_pending_flushes`. Read the Parquet under `zeek/_overflow/` and assert its `log_path` column contains exactly `{"dns","weird"}`.

- [ ] **Step 4: E2E (A1).** `tests/zeek_overflow_log_path_e2e.rs`: a real `ZeekListener` over TCP with `zeek_local_start` → `MultiZeekHandler` (pattern: `tests/zeek_mixed_case_path_e2e.rs`). Find how the local writer's `max_partitions` is set (`zeek_local_start` / `ZeekLocalConfig` / the constant at zeek_s3.rs ~264). If it isn't configurable, send lines with 257 distinct `_path`s (`p0`..`p255`, then `dns`). Assert the `_overflow` Parquet's `log_path` column contains `"dns"` and never `"_overflow_nonexistent_"`.

- [ ] **Step 5: E2E (A2).** In `tests/zeek_received_metric_e2e.rs`, send one extra line with `"_path":"Conn"` and assert the scraped `zeek_records_by_path{log_path="conn"}` goes up by one for it (adjust the expected count). Check the listener's integration metric test (`tests/zeek_received_metric_integration.rs`) and add a `"Conn"` case there too.

- [ ] **Step 6: Verify and commit:** `fix(zeek): keep real log_path in overflow rows and resolve metric labels like schemas`.

---

### Task 2: `flush_all` resets row/byte counts (spec B)

**Files:** Modify `src/forwarding/buffered_writer.rs` (`flush_all` ~1125-1179; tests). Create `tests/flush_all_counts_integration.rs` only if the test can reach public API; otherwise put the integration test in-crate, named `*_integration_*`.

- [ ] **Step 1: Failing unit tests** (in-crate, with the existing `MockSink`/`RecordingSink`/`test_config` helpers):
  - `flush_all_success_zeroes_row_and_byte_counts`: push 3 records, `flush_all().await.unwrap()`, then for every remaining buffer `row_count == 0 && byte_count == 0`, and `total_buffered_rows() == 0`.
  - `flush_all_failure_restores_row_and_byte_counts`: with a failing upload sink (find the existing failing/unreachable sink helper), push 3, `flush_all()` returns `Err`, and `row_count == 3` with `byte_count` unchanged from before.
  Run: expected the first FAILS.

- [ ] **Step 2: Implement** inside the `taken` block, right after the `let byte_count = buf.byte_count;` line:

```rust
buf.row_count = 0;
buf.byte_count = 0;
```

The failure branch already restores both. Run: PASS; mutation-check.

- [ ] **Step 3: Integration:** real `LocalDiskSink` tempdir: push, `flush_all`, assert a Parquet file exists and `total_buffered_rows() == 0`.

- [ ] **Step 4: E2E:** not applicable. The only production caller runs `flush_all` on channel close and then `break`s, so no outer interface can observe the counts. Say this in the commit body.

- [ ] **Step 5: Commit:** `fix(forwarding): reset buffer counts after a successful flush_all`.

---

### Task 3: Remove dead WEF per-event error arms (spec C)

**Files:** Modify `src/protocol/mod.rs` (`parse_single_event` ~307; the `End`/`Empty` arms ~160-201).

- [ ] **Step 1:** Change the signature to `fn parse_single_event(&self, xml: &str, source_host: &str) -> WindowsEvent` (drop `Ok(..)`). In both call sites, replace the `match … { Ok(event) => events.push(event), Err(e) => { error!(…); events.push(raw) } }` with `events.push(self.parse_single_event(event_xml, &source_host));`. Update any tests that call `parse_single_event` directly. Remove imports that become unused.
- [ ] **Step 2:** `cargo test --lib protocol::` plus the three WEF test binaries (`wef_malformed_batch_integration`, `wef_malformed_batch_e2e`, `wef_local_integration`): all green and unchanged.
- [ ] **Step 3:** Integration/e2e: not applicable (no behaviour change; the existing WEF suites are the regression net). Say so in the commit body.
- [ ] **Step 4: Commit:** `refactor(wef): make parse_single_event infallible and drop dead error arms`.

---

### Task 4: IPFIX variable-length fields (spec D)

**Files:** Modify `src/ipfix/decoder.rs` (`parse_ipfix_data_set` ~700; callers ~560 (v10) and ~993 (v9); `FieldSpecifier.length` doc ~90; tests). Create `tests/ipfix_varlen_integration.rs`, `tests/ipfix_varlen_e2e.rs`.

**Interfaces:** `fn parse_ipfix_data_set(decoder, body, set_id, exporter, obs_domain_id, export_time, allow_varlen: bool)`. v10 passes `true`, v9 passes `false`.

- [ ] **Step 1: Failing unit tests** (build templates and data sets with the file's existing test byte-builders; read them first). Cover:
  - (a) template [srcIPv4(8) len 4, ie 96 len 0xFFFF]; data: 4 addr bytes, `0x03 "abc"` → 1 record, `src_addr` set, `extra["ie96"] == "616263"` (confirm IE 96 isn't in `ie_info`; if it is, pick an IE that isn't);
  - (b) the 3-byte form: `0xFF 0x01 0x2C` + 300 bytes → 1 record whose extra value is 600 hex chars;
  - (c) a zero-length value `0x00` → record present with `""`;
  - (d) two records back to back, then 1 padding byte (< min_record_len = 5) → exactly 2 records;
  - (e) the second record declares `0xFF 0xFF 0xFF` (65535) with only 10 bytes left → 1 record, no panic, no `Err` returned for the set;
  - (f) a template of ONLY two varlen fields, data `00 00 00 00` → 2 records;
  - (g) a v9 flowset with a 0xFFFF template field → 0 records, same as before (use the v9 path).
  Run: expected FAIL (0 records) for (a)-(f), PASS for (g).

- [ ] **Step 2: Implement.** Add the `allow_varlen` parameter and update both callers. After the template lookup:

```rust
/// RFC 7011 §7: a field length of 0xFFFF means variable-length encoding.
const VARLEN: u16 = 0xFFFF;

if allow_varlen && fields.iter().any(|f| f.length == VARLEN) {
    return Ok(parse_varlen_records(&fields, body, set_id, exporter, obs_domain_id, export_time));
}
// ...existing fixed-length loop, unchanged...
```

```rust
/// Decode a data set whose template has at least one variable-length field
/// (RFC 7011 §7): a 1-byte length, or 255 followed by a 2-byte length. A
/// record cut short partway ends the set (the rest is truncated data or
/// padding); records before it are kept.
fn parse_varlen_records(
    fields: &[FieldSpecifier],
    body: &[u8],
    set_id: u16,
    exporter: IpAddr,
    obs_domain_id: u32,
    export_time: DateTime<Utc>,
) -> Vec<FlowRecord> {
    // Padding (RFC 7011 §3.3.1) is shorter than any record, so stopping below
    // the minimum record size never decodes it. Every varlen field costs at
    // least its 1-byte length, so each record advances `pos`.
    let min_record_len: usize = fields
        .iter()
        .map(|f| if f.length == VARLEN { 1 } else { f.length as usize })
        .sum();
    let mut records = Vec::new();
    let mut pos = 0usize;
    'records: while body.len().saturating_sub(pos) >= min_record_len.max(1) {
        let mut rec = new_flow_record(obs_domain_id, set_id, exporter, export_time);
        let mut p = pos;
        for field in fields {
            let len = if field.length == VARLEN {
                let Ok(l) = read_bytes(body, p, 1) else { break 'records };
                p += 1;
                if l[0] < 255 {
                    l[0] as usize
                } else {
                    let Ok(l) = read_u16_be(body, p) else { break 'records };
                    p += 2;
                    l as usize
                }
            } else {
                field.length as usize
            };
            let Ok(raw) = read_bytes(body, p, len) else { break 'records };
            apply_field_to_record(&mut rec, field, raw);
            p += len;
        }
        pos = p;
        metrics::counter!("ipfix_flows_decoded").increment(1);
        records.push(rec);
    }
    records
}
```

Extract the `FlowRecord { .. }` literal from the fixed loop into `fn new_flow_record(obs_domain_id, template_id, exporter, export_time) -> FlowRecord` and use it in both loops, so neither duplicates the other. Update the `FieldSpecifier.length` doc to say 0xFFFF is handled for IPFIX. Run: PASS; mutation-check (e.g. remove the `allow_varlen` dispatch).

- [ ] **Step 3: Integration** `tests/ipfix_varlen_integration.rs`: a real `IpfixListener` on UDP with `ipfix_local_start` to a tempdir (pattern: `tests/ipfix_local_integration.rs`). Send a template set with a varlen field, then a data set with 2 records. Shut down and assert the Parquet has 2 rows and an `extra` value holding the hex.

- [ ] **Step 4: E2E** `tests/ipfix_varlen_e2e.rs` (single test): spawn the real binary with IPFIX enabled (pattern: `tests/listener_ip_whitelist_e2e.rs`: toml in a tempdir, `ChildGuard`, `wait_for_metrics`/`wait_for_udp`). Send the same template + data over UDP, then poll `/metrics` until `ipfix_flows_decoded` ≥ 2 (deadline 15 s). Mutation-check: with the dispatch removed, the counter stays 0.

- [ ] **Step 5: Verify and commit:** `feat(ipfix): decode variable-length fields (RFC 7011 §7)`. Also add a CHANGELOG `## [Unreleased]` entry for this task and Task 1 (see "After all tasks").

---

## After all tasks

Add to CHANGELOG `## [Unreleased]`: under Fixed, Zeek overflow rows' real `log_path`; `"Conn"`-style metric labels; `flush_all` counts. Under Added, IPFIX variable-length fields. Task 3 is internal (no entry). Run the full `cargo test` once at the tip. Hand the merge decision to the user.
