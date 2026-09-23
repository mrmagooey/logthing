# Log Aggregation

Aggregation counts records as they arrive, grouped by configured columns, and
writes the counted table to Parquet. A stream covered by a rule **stops
writing raw rows entirely** — that is the point: the noisy stream is reduced to
its summary.

```toml
[aggregate]
enabled = true
flush_interval_secs = 300   # window length; each row carries window_start/window_end
max_groups = 100000         # per rule, per window
channel_capacity = 4096     # bounded channel between the emit task and the Parquet writer (default: 4096)

[aggregate.local]           # and/or [aggregate.s3], same shape as other sources
directory = "/data/agg"
prefix = "aggregate"

[[aggregate.rules]]
name = "dns_by_query"       # unique; becomes the output partition
source = "zeek"             # zeek | suricata | syslog | ipfix | sflow
stream = "dns"              # optional; omitted = every record from that source
group_by = ["query", "id.orig_h"]

[[aggregate.rules]]
name = "flow_talkers"
source = "ipfix"
group_by = ["src_addr", "dst_addr", "dst_port"]
sum = ["octet_delta_count", "packet_delta_count"]
```

Output lands at `<prefix>/<rule>/year=/month=/day=/<uuid>.parquet` with one
column per `group_by` field, a `count`, one column per `sum`/`min`/`max`,
`window_start`/`window_end`, and `partition_time`.

Column names in the output schema:

| Config field | Output column |
| --- | --- |
| each `group_by` entry | used verbatim, e.g. `query`, `id.orig_h` |
| — | `count` (always present) |
| each `sum` field | `sum_<field>` |
| each `min` field | `min_<field>` |
| each `max` field | `max_<field>` |
| — | `window_start`, `window_end` (always present) |
| — | `partition_time` (always present, non-null; see below) |

For the `flow_talkers` rule above, the schema is: `src_addr, dst_addr,
dst_port, count, sum_octet_delta_count, sum_packet_delta_count, window_start,
window_end, partition_time`. A `group_by` entry can't be named `count`, and no two output
columns may collide (e.g. `group_by = ["sum_x"]` with `sum = ["x"]`) — both
are rejected at startup.

`partition_time` is materialised last and always equals `window_start` for
aggregate output (both were already non-null), but it is the column to
declare an Iceberg partition transform against — it is the one name every
sink's schema agrees on, so the same committer logic works unmodified
across all nine.

Notes:

- `stream` matches the Zeek `_path` (normalized to the stable stream name, so rotation
  suffixes are stripped; e.g., `conn.2026-08-14-16-08-44.log.gz` → `conn`), Suricata
  `event_type`, syslog `app_name`, sFlow `"flow"`/`"counter"`, or IPFIX `"flows"`.
- A record matching two rules is counted in both.
- Aggregates follow SQL semantics: missing and non-numeric values are skipped,
  the record is still counted, and a group with no numeric observations emits
  NULL rather than 0.
- Past `max_groups` distinct groups in a window, further keys fold into a
  single `_other` row so the window total stays exact.
- `flush_interval_secs` is the only window-length knob — there's no separate
  setting; it also drives the writer's flush age. Windows are bounded by
  arrival time, not event time: a record counts into whichever window is
  open when it *arrives*, and a late/out-of-order record is never re-bucketed
  into the window its own timestamp would suggest.
- Invalid rules (unknown or disabled source, empty `group_by`, duplicate name,
  no destination) are fatal at startup rather than silently inert.
- Aggregation doesn't disable a source's raw persistence — that's controlled
  independently by `[<source>.s3]`/`[<source>.local]`. To store *only* the
  aggregate output: leave a source's `s3`/`local` blocks unset (so raw rows
  have no destination), and omit `stream` in its rule so every record from
  that source is matched — otherwise unmatched records are silently dropped
  rather than persisted anywhere.
- Do not put `_path` in a Zeek rule's `group_by`: unlike the `stream` filter
  above, `group_by` reads the field straight off the raw JSON, which still
  holds the un-normalized value — a new group per rotation suffix.
- syslog's `protocol` is not an addressable field (falls through to the
  structured-data lookup and misses); `group_by = ["protocol"]` yields NULL.
