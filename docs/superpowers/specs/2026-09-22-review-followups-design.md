# Review follow-ups (2026-09-22) — design

These are the five follow-ups found while fixing the 2026-09-22 review bugs
(spec `2026-09-22-review-fixes-design.md`). Produced via auto-develop; the
independent coherence reviewer's verdict was "coherent". Work continues on
`fix/review-2026-09-22`, and the merge to master stays the user's decision.

Order: **A** (#1 + #3, Zeek) → **B** (#4) → **C** (#2) → **D** (#5).

## A1: Zeek overflow records get a placeholder `log_path` (#1)

**Bug.** A record routed to the `_overflow` partition (the envelope schema,
once `max_partitions` is reached) whose own path is typed (e.g. `dns`) is
rejected by `EnvelopeAccumulator::try_append`. It then reaches the
else-branch of `ZeekSink::to_record_batch`, which maps it via
`get_schema_entry("_overflow_nonexistent_")`. That entry's closure writes the
literal `"_overflow_nonexistent_"` into the envelope `log_path` column.

**Fix.** Make `map_envelope` in `src/zeek/schema.rs` `pub(crate)`, and in
the else-branch call `map_envelope(&record.fields, &record.log_path,
record.received_at)`. The accumulator is left unchanged (widening it would
only be a speed-up).

## A2: `metric_log_path("Conn")` labels `"other"` (#3)

**Bug.** `metric_log_path` does a raw `REGISTRY.get_key_value(log_path)`.
Since the earlier fix, `get_schema_entry` also tries
`sanitize_log_path(log_path)`, so `"Conn"` is written as conn but counted as
`other`.

**Fix.** Add one private lookup, `fn registry_lookup(log_path) ->
Option<(&'static str, &'static Arc<SchemaEntry>)>`: exact match first, then
the sanitized key. Both `get_schema_entry` and `metric_log_path` use it, so
the two can never disagree again.

## B: `flush_all` leaves stale row/byte counts (#4)

**Bug.** `flush_all` takes `buf.buffer` but never zeroes `row_count` /
`byte_count` on success; the failure path restores them.

**Fix.** Zero both at take time, as `try_flush_partition_async` already
does. The failure path keeps restoring them.

## C: dead WEF per-event error arms (#2)

**Finding.** `WefParser::parse_single_event` always returns `Ok`: when
`parse_event_data` fails it returns the event with no `.parsed`. The two
`Err(e) => error!("Failed to parse individual event")` arms are dead code,
and there is no log flood. Unparsed events are already counted downstream
(`parquet_s3_records_skipped{source="wef"}`, with a throttled warn).

**Fix.** Change it to `fn parse_single_event(..) -> WindowsEvent` and delete
both dead arms. No behaviour changes.

## D: IPFIX variable-length fields (#5)

**Bug.** `parse_ipfix_data_set` sums `FieldSpecifier.length` into
`record_len`. A template containing a variable-length field (length
`0xFFFF`, RFC 7011 §7) gets `record_len >= 65535`, so it decodes no records,
silently.

**Fix.**
- `parse_ipfix_data_set` gains `allow_varlen: bool`. The IPFIX (v10) caller
  passes `true`; the NetFlow v9 caller passes `false`, because RFC 3954 has
  no variable-length encoding and v9 keeps today's behaviour exactly.
- Templates with no `0xFFFF` field use the existing fixed-length loop,
  unchanged (it is a performance-sensitive path).
- Templates with a `0xFFFF` field, when `allow_varlen` is set, use a
  varlen loop:
  - `min_record_len` = sum of fixed lengths + 1 per varlen field. Iterate
    while `remaining >= min_record_len`, so trailing padding (RFC 7011
    §3.3.1, shorter than any record) is never decoded.
  - A varlen field has a 1-byte length L; if L == 255, a 2-byte big-endian
    length follows. Then come the value bytes.
  - If a record is cut short partway (any read fails), drop it and stop
    decoding that set. Records already decoded are kept.
  - Every record consumes at least 1 byte, so the loop always ends.
- Values go through the existing `apply_field_to_record`. Varlen IEs aren't
  in the known-IE table (which has no string type), so they land hex-encoded
  in `extra`, like every other unknown IE. String typing is a separate
  feature.
- Options-template data sets share this function, so they're covered too.

## Tests

| Item | Unit | Integration | E2E |
|---|---|---|---|
| A1 | `to_record_batch` on an envelope schema with a typed record keeps the real `log_path` | writer with `max_partitions = 1`: `conn` then `dns` → the overflow Parquet `log_path` column holds `"dns"` | real `ZeekListener` over TCP with a local sink, pushing past the partition cap (a local config field if one exists, else 257 distinct paths) → the overflow Parquet holds the real paths |
| A2 | `metric_log_path("Conn") == "conn"`, hostile inputs → `"other"` | listener-level metric test with `"Conn"` (pattern: `tests/zeek_received_metric_integration.rs`) | scrape a real `/metrics` after ingesting a `"Conn"` line → `zeek_records_by_path{log_path="conn"}` counts it (extend `tests/zeek_received_metric_e2e.rs`, keeping it one test per file) |
| B | after a successful `flush_all`, `row_count == byte_count == 0`; after a failed one, both are restored | `LocalDiskSink`: push, `flush_all`, `total_buffered_rows() == 0` | N/A: `flush_all` runs only at shutdown (the production call site `break`s right after), so no outer interface can observe the counts |
| C | existing `parse_events` tests stay green | N/A: no behaviour change | N/A: no behaviour change |
| D | varlen 1-byte length, 3-byte (255) length, a mixed fixed+varlen template, a zero-length varlen value, padding not decoded, a record cut short midway is dropped while earlier records are kept, v9 with 0xFFFF still yields nothing | real `IpfixListener` over UDP → `ipfix_local_start` → Parquet row whose `extra` holds the hex varlen value (pattern: `tests/ipfix_local_integration.rs`) | spawn the real binary with IPFIX enabled, send a varlen template + data over UDP, and check that `ipfix_flows_decoded` rises on `/metrics` (pattern: `tests/listener_ip_whitelist_e2e.rs`) |

Regression tests are mutation-verified: revert the fix and confirm the test fails.
