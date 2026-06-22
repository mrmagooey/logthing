# Zeek Ingestion Options Analysis

**Date:** 2026-06-22  
**Status:** Options / notes — NOT a final spec, NOT approved for implementation  
**Author:** Research pass (coordinator + web research)

---

## Background and scope

This document analyses how Zeek (the open-source network security monitor, formerly Bro)
output could be ingested into the `logthing` server. It covers:

1. Zeek's output formats and log-stream taxonomy.
2. The shipping/transport options Zeek provides or that are commonly paired with it.
3. How each transport maps onto logthing's existing ingestion patterns.
4. Parquet/S3 schema choices given Zeek's heterogeneous, schema-per-stream model.
5. Four concrete ingestion option sketches (A–D), each with effort/blast-radius
   and pros/cons.
6. A recommendation and smallest first increment.

Basis: source code in `src/syslog/`, `src/ipfix/`, `src/forwarding/`, `src/config/mod.rs`,
`src/main.rs`, and `docs/superpowers/specs/2026-06-21-ipfix-ingestion-and-s3-persistence-design.md`.

---

## Part 1: Zeek output formats

### 1.1 TSV / ASCII format (default)

Each log stream is a separate file. The file begins with a metadata preamble:

```
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path           conn
#open           2026-06-22-14-00-00
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto ...
#types  time  string  addr  port  addr  port  enum  ...
```

After the preamble each record is one tab-separated line. The `#fields` and
`#types` lines give a self-describing schema. Unset values are the literal `-`
string; set-typed values are comma-joined. Zeek types include `time` (Unix
epoch as a float), `addr`, `port`, `count`, `int`, `double`, `bool`, `string`,
`enum`, and container types `set[T]`, `vector[T]`.

TSV is the default and is what `zeekctl` archives.  Files are rotated
(default interval configurable via `Log::default_rotation_interval`; zeekctl
ships with an `archive-log` postprocessor that renames and optionally gzips).
The Zeek documentation gives no single canonical default rotation interval —
zeekctl commonly uses 1 hour, but this is site-configurable. Rotated files are
gzip-compressed by default when using zeekctl (`archive-log`).

### 1.2 JSON / NDJSON format

Enabled via `LogAscii::use_json=T` (command line or `local.zeek`), or by
loading `policy/tuning/json-logs`. Each log entry becomes one JSON object on
its own line (newline-delimited JSON, NDJSON). The metadata preamble
(`#separator` etc.) is absent. Fields map directly to JSON key/value pairs;
Zeek's `addr` and `port` types stringify naturally. Timestamps are ISO-8601
or float-epoch depending on version (float is default; ISO-8601 can be
configured with `LogAscii::json_timestamps`).

The `corelight/json-streaming-logs` package extends this: it injects two extra
fields into every record — `_path` (log stream name, e.g. `"conn"`) and
`_write_ts` (wall-clock time the line was written) — and writes unrotated,
uncompressed files with the prefix `json_streaming_*` specifically so that
log-shipper tools (Filebeat, Fluentd, etc.) can tail them with predictable
stable paths. This package does NOT write to a network socket; it is still
file-based.

**No built-in network/socket writer exists in Zeek.** Remote log export from
Zeek itself requires one of:

- The Kafka writer plugin (zeek-kafka, see §1.3).
- Zeek Broker (internal cluster protocol; not easily consumed externally, see §1.4).
- An external shipper reading local files.

### 1.3 zeek-kafka (SeisoLLC plugin)

Installs as a Zeek package (`zkg install zeek-kafka`). Implements a
`Log::Writer` plugin that publishes one Kafka message per log entry in JSON
format. Topic naming is configurable:

- All streams to a single topic (default topic name: `zeek`).
- Per-stream topics: set `topic_name` to `""` and configure per-stream
  `Log::Filter`s; each stream goes to a topic named after its `$path` value
  (e.g. `conn`, `dns`, `http`).

Messages have no Avro/schema-registry envelope — plain JSON strings. The
plugin supports SASL/Kerberos via librdkafka (`--enable-sasl`). Version 1.2.0
(July 2025). No minimum Zeek version stated in README; community threads
reference Zeek v3.x–v6.x compatibility.

**UNVERIFIED:** Whether zeek-kafka sends a full preamble/metadata object to
Kafka or just the data record. The README implies data records only; the `_path`
field analogue is the topic name or the optional `tag_json` wrapper.

### 1.4 Zeek Broker

Broker is Zeek's internal messaging library (pub/sub over CAF). It is used for
cluster communication — worker nodes ship log entries to logger nodes. It is
not a general external API: consuming Broker from outside Zeek requires linking
against the Broker C++ library or using the Python bindings, neither of which
is an obvious fit for a Tokio/Rust server. Broker is not considered further as
a realistic ingestion path for logthing.

### 1.5 External shippers (Filebeat, Fluentd, Logstash, Vector)

The dominant operational pattern today is:

```
Zeek writes JSON/NDJSON log files
  → Filebeat/Vector tails files
  → Ships to Elasticsearch, Logstash, Kafka, or an HTTP endpoint
```

The Elastic Filebeat `zeek` module has built-in support for all major Zeek log
streams (conn, dns, http, ssl, files, notice, weird, ssh, etc.) and expects
JSON input. Logit.io, Logz.io, Wazuh all document this path.

If logthing were to accept Zeek data via an HTTP endpoint, Vector or Filebeat
could be configured with an HTTP output (Vector's `http` sink; Filebeat's
`logstash` output pointed at logthing, or a direct HTTP output).

---

## Part 2: Zeek log-stream taxonomy and the schema heterogeneity problem

Zeek produces 30+ distinct log streams. The streams that matter most in practice:

| Stream | Key fields (selected) | Approx. field count |
|--------|-----------------------|---------------------|
| conn.log | ts, uid, id.{orig,resp}_{h,p}, proto, service, duration, orig/resp_{bytes,pkts,ip_bytes}, conn_state, history | ~20 |
| dns.log | ts, uid, id.*, proto, query, qclass, qtype, rcode, answers, TTLs | ~20 |
| http.log | ts, uid, id.*, method, host, uri, referrer, version, user_agent, status_code, resp_body_len | ~25 |
| ssl.log | ts, uid, id.*, version, cipher, curve, server_name, resumed, established, cert_chain_fuids | ~20 |
| x509.log | ts, id, certificate.{subject,issuer,not_valid_{before,after},key_alg,sig_alg,key_type,key_length}, basic_constraints | ~15 |
| files.log | ts, fuid, tx_hosts, rx_hosts, conn_uids, source, depth, mime_type, filename, duration, local_orig, is_orig, seen_bytes, total_bytes, missing_bytes, md5, sha1, sha256 | ~20 |
| smtp.log | ts, uid, id.*, helo, mailfrom, rcptto, date, from, to, reply_to, msg_id, subject, agent, user_agent, is_webmail | ~20 |
| ssh.log | ts, uid, id.*, version, auth_success, auth_attempts, direction, client, server, cipher_alg, mac_alg, kex_alg, host_key_alg, host_key | ~15 |
| notice.log | ts, uid, id.*, fuid, proto, note, msg, sub, src, dst, p, n, peer_descr, actions, suppress_for, dropped | ~20 |
| weird.log | ts, uid, id.*, name, addl, notice, peer | ~10 |
| files, pe, dhcp, ntp, smtp, ftp, rdp, kerberos, etc. | varied | ~10–30 each |

**Central tension:** Every log stream has a different schema. This is
structurally analogous to IPFIX's per-template variability, but worse: Zeek has
30+ fully typed, named schemas rather than IPFIX's ~50 IE variations within one
record model. Schema evolution is also common (fields added between Zeek
versions, custom scripts adding fields).

The IPFIX design precedent (one fixed common-fields schema + JSON `extra`
column for everything else) applies here. The three schema modeling options are
analyzed in Part 4.

---

## Part 3: Transport → logthing mapping

| Zeek transport | Where Zeek runs | logthing receives via | Closest existing analog |
|----------------|-----------------|-----------------------|-------------------------|
| File tail (JSON/NDJSON) | Same host as logthing, or NFS/shared FS | File tailer task in `src/zeek/tailer.rs` | No direct analog; new module type |
| Kafka (zeek-kafka) | Anywhere; Kafka broker as intermediary | Kafka consumer task | No analog; new Kafka consumer crate needed |
| Filebeat/Vector → HTTP POST | Zeek on separate host, shipper pushes to logthing | New HTTP endpoint in logthing's Axum router | Partial: WEF uses Axum for HTTP ingestion |
| JSON-in-syslog via rsyslog/syslog-ng | Zeek host uses rsyslog to forward | Existing `SyslogListener` | Direct reuse; no new module needed |

---

## Part 4: Parquet/S3 schema options for Zeek's heterogeneous streams

Given Zeek's 30+ log types, three schema approaches are possible:

### Option S1: One fixed common-envelope schema + JSON payload column (IPFIX pattern)

A single Arrow schema with universal fields drawn from what every record has, 
plus a `payload` JSON string column for the rest:

```
zeek_ts: Utf8 (ISO-8601 or epoch string)
zeek_uid: Utf8 (nullable; not all streams have uid)
log_path: Utf8 ("conn", "dns", "http", etc.)
id_orig_h: Utf8 (nullable)
id_orig_p: UInt16 (nullable)
id_resp_h: Utf8 (nullable)
id_resp_p: UInt16 (nullable)
payload: Utf8 (full JSON of remaining fields, always present)
ingest_time: Utf8 (logthing server wall-clock at receipt)
source_ip: Utf8 (sender IP address)
```

Pros: Single Arrow schema, single Parquet writer, single S3 prefix, simplest
implementation. All data is preserved. Mirrors IPFIX `extra` precedent exactly.

Cons: All stream-specific fields are buried in `payload`; SQL queries need
`json_extract`; Parquet's column-store benefits are lost for the payload blob.
Columnar predicate pushdown on e.g. `http.status_code` is impossible without
unpacking.

### Option S2: Per-log-type Arrow schemas + per-type S3 prefixes

A separate fixed schema per stream (conn, dns, http, ssl, …), each with all
known fields typed correctly. Each stream gets its own `ZeekXxxS3Writer` and
S3 prefix (e.g. `zeek/conn/`, `zeek/dns/`).

Pros: Full columnar pushdown on per-stream fields; ideal query performance;
clean S3 namespacing (easy to grant per-stream IAM policies).

Cons: 30+ schemas to maintain; any new Zeek version or custom script field
causes a schema mismatch. Requires a schema registry or version-detection
strategy. High initial implementation burden. Schema evolution via Parquet's
`schema_evolution` is possible but complicates readers. Custom Zeek scripts can
add fields at any site, making a canonical set impossible to define.

### Option S3: Hybrid — fixed schema for top 4–5 streams + envelope for the rest

Fixed, rich schemas for the highest-value streams (conn, dns, http, ssl) and
the common-envelope approach for everything else. Two Parquet writers: one
per typed stream, one catch-all.

Pros: Best query performance where it matters (conn + dns are the vast majority
of Zeek log volume); manageable schema maintenance scope.

Cons: Two parallel code paths; still needs schema version handling for the
typed streams; adds complexity proportional to the number of typed streams
covered.

**Recommendation for schema:** Start with Option S1 (envelope + payload) for
the first increment. This is directly precedented by the IPFIX `extra` column
and keeps blast radius minimal. Optionally layer per-stream typed schemas for
conn.log and dns.log as a follow-on once the ingestion plumbing is stable. The
`log_path` column means Parquet files are trivially partitionable per stream
later without a schema change (just add an S3 key component).

---

## Part 5: Four ingestion options (A–D)

---

### Option A: File tailer of Zeek JSON logs

**How it works end-to-end:**

Zeek is configured to write NDJSON logs locally (either `LogAscii::use_json=T`
or the `corelight/json-streaming-logs` package). logthing runs a background
Tokio task (`src/zeek/tailer.rs`) that inotify-watches (Linux) or polls a
configured directory, tails each active `*.log` file line-by-line, parses each
line as JSON, attaches a `log_path` derived from the filename (stripping the
`json_streaming_` prefix if present), and passes a `ZeekRecord` to a
`ZeekHandler` trait implementation.

**New module shape:**

```
src/zeek/
  mod.rs        — ZeekRecord { ts, uid, log_path, id_orig_h, id_orig_p,
                               id_resp_h, id_resp_p, payload: serde_json::Value,
                               ingest_time, source: String }
  tailer.rs     — ZeekTailerConfig { log_dir, glob_pattern, poll_interval_ms }
                  ZeekHandler trait (async fn handle_record(&self, r: ZeekRecord))
                  DefaultZeekHandler (log + metrics)
                  ZeekTailer::start() — inotify/polling loop over log_dir
src/forwarding/
  zeek_s3.rs    — ZeekS3Handler : ZeekHandler (same pattern as IpfixS3Handler)
                  ZeekS3WriterConfig, ZeekS3Writer
```

Config (TOML):
```toml
[zeek]
enabled = false
log_dir = "/opt/zeek/logs/current"
glob = "*.log"
poll_interval_ms = 500

[zeek.s3]
endpoint = "..."
bucket = "..."
region = "..."
prefix = "zeek"
```

**Parquet schema:** Option S1 (envelope + payload).

**Operational considerations:**

- Zeek and logthing MUST run on the same host, or Zeek's log directory must be
  network-mounted (NFS/CIFS). Co-location is the most common lab/SMB deployment
  pattern.
- Delivery reliability: at-least-once if the tailer tracks byte offsets per file
  (a simple offset map keyed by inode + filename). On restart, resume from last
  committed offset. On log rotation, the old file is renamed (not deleted
  immediately) so in-flight lines can still be drained. Implementation must
  handle inode reuse and gzip-rotated files (skip compressed archives or
  decompress them).
- Ordering: preserved within a stream file; across streams it is wall-clock
  order of tailer read, not Zeek event order.
- Backpressure: the tailer reads slower when the `ZeekHandler` channel is full;
  naturally bounded because it is single-threaded per file.
- No Kafka dependency. No network configuration on Zeek's side.

**Effort / blast radius:**

- New: `src/zeek/mod.rs`, `src/zeek/tailer.rs`, `src/forwarding/zeek_s3.rs`.
- Modify: `src/config/mod.rs` (add `[zeek]` section), `src/main.rs` (spawn
  tailer task), `src/forwarding/mod.rs`.
- No changes to existing sources (syslog, IPFIX, WEF).
- External dependency: `notify` or `inotify` crate for filesystem events, or
  pure polling with `tokio::fs`. The `notify` crate (4+ million downloads/week)
  is the idiomatic choice for Tokio projects.
- No new network listener port.

**Pros:**
- Zero Zeek-side configuration change (just set JSON output mode once).
- Extremely simple operational model for co-located deployments.
- Works with stock Zeek; no plugin installation.
- Lossless: file is the source of truth; tailer can resume after logthing restart.
- Low operational risk.

**Cons:**
- Requires co-location (or shared filesystem, which has its own complexity).
- File tailing is inherently polling or inotify-dependent — not pure push.
- Rotated/gzipped files need special handling.
- Does not scale to multi-Zeek-node deployments without a shared FS or
  per-node logthing sidecar.
- `notify` crate adds a dependency (though a lightweight one).

---

### Option B: Kafka consumer of zeek-kafka output

**How it works end-to-end:**

Zeek is configured with the `zeek-kafka` plugin (`zkg install zeek-kafka`).
The plugin publishes one JSON message per log entry to a Kafka broker (either
a single `zeek` topic or per-stream topics like `conn`, `dns`, `http`). logthing
runs a Kafka consumer task (`src/zeek/kafka_consumer.rs`) using the
`rdkafka` crate (Rust bindings for librdkafka). The consumer reads messages
from the configured topic(s), deserializes JSON, extracts `log_path` from the
topic name (or from a `_path` field if `tag_json = T` is set in the plugin),
and dispatches to a `ZeekHandler`.

**New module shape:**

```
src/zeek/
  mod.rs            — ZeekRecord (same as Option A)
  kafka_consumer.rs — ZeekKafkaConfig { brokers, topics, group_id, ... }
                      ZeekHandler trait (shared with Option A)
                      ZeekKafkaConsumer::start()
src/forwarding/
  zeek_s3.rs        — shared with Option A
```

Config (TOML):
```toml
[zeek.kafka]
enabled = false
brokers = ["kafka:9092"]
topics = ["conn", "dns", "http", "ssl", "files", "notice"]  # or ["zeek"] for single-topic
group_id = "logthing-zeek"
```

**Parquet schema:** Option S1 (envelope + payload). Topic name provides
`log_path`.

**Operational considerations:**

- Zeek and logthing can run on entirely separate hosts; Kafka is the decoupling
  layer.
- Delivery: Kafka's at-least-once semantics with consumer group offset commits.
  Commit offsets after successful S3 flush (not per-message) for true
  at-least-once with batching.
- Ordering: within a Kafka partition, messages are ordered. If zeek-kafka uses
  the Zeek UID as the partition key, related records for one connection land in
  order; otherwise partition assignment is round-robin.
- Backpressure: Kafka consumer poll rate naturally limits ingestion; bounded
  channel to `ZeekS3Writer` provides the same overflow/drop mechanism as IPFIX.
- Multi-Zeek-node: all nodes publish to the same Kafka topics; logthing sees
  a single unified stream. This is the primary architectural advantage.
- Kafka requires a running Kafka (or MSK/Confluent Cloud) cluster. Non-trivial
  ops dependency.
- `rdkafka` crate links librdkafka (C library) via cargo-build; adds
  significant build complexity (C toolchain required) and binary size. The
  `rdkafka` crate is well-maintained (tokio-rdkafka feature), but it is a
  substantially heavier dependency than anything currently in the project.

**Effort / blast radius:**

- New: `src/zeek/mod.rs`, `src/zeek/kafka_consumer.rs`, `src/forwarding/zeek_s3.rs`.
- Modify: `src/config/mod.rs`, `src/main.rs`, `src/forwarding/mod.rs`.
- `Cargo.toml`: add `rdkafka` with `cmake` feature. This changes the build
  environment requirements.
- No changes to existing sources.
- Side dependency: zeek-kafka must be installed and configured on the Zeek node.

**Pros:**
- Multi-node Zeek naturally handled (all nodes publish to same Kafka).
- Reliable delivery with replayability (Kafka retention).
- Decoupled: logthing can be restarted without losing data.
- Scales to high-throughput environments.
- Standard pattern in the Zeek/ELK ecosystem; operational runbooks exist.

**Cons:**
- Kafka infrastructure required (significant ops overhead for small deployments).
- `rdkafka`/librdkafka build dependency is a heavy addition; complicates CI and
  container builds.
- zeek-kafka plugin installation required on Zeek nodes.
- Kafka message ordering across topics is not guaranteed.
- Overkill for single-node deployments.

---

### Option C: NDJSON-over-TCP intake endpoint

**How it works end-to-end:**

Zeek writes NDJSON logs. An external shipper (Vector, Fluent Bit, or a minimal
shell script using `tail -F | nc`) reads the files and streams them over a TCP
connection to logthing. logthing adds a new TCP listener (`src/zeek/listener.rs`)
that accepts connections, reads newline-delimited JSON records, and dispatches
to a `ZeekHandler`. Each JSON object must contain a `_path` field (compatible
with `json-streaming-logs` package) or the stream type is derived from a
handshake header (a simpler approach is to require `_path` in every record,
since `json-streaming-logs` already provides this).

**New module shape:**

```
src/zeek/
  mod.rs       — ZeekRecord (same as above)
  listener.rs  — ZeekListenerConfig { tcp_port, bind_address, max_connections }
                 ZeekHandler trait
                 ZeekListener::start() — TcpListener loop (mirrors SyslogListener TCP)
```

Config (TOML):
```toml
[zeek]
enabled = false
tcp_port = 9001
bind_address = "0.0.0.0"
```

Shipper configuration example (Vector):
```yaml
[sources.zeek]
type = "file"
include = ["/opt/zeek/logs/current/json_streaming_*.log"]

[sinks.logthing]
type = "socket"
inputs = ["zeek"]
address = "logthing:9001"
mode = "tcp"
encoding.codec = "ndjson"
```

**Parquet schema:** Option S1 (envelope + payload, `log_path` from `_path` field).

**Operational considerations:**

- Zeek and logthing can be on separate hosts (shipper bridges them).
- TCP connection loss: the shipper (Vector, Fluent Bit) has built-in retry with
  an on-disk buffer, providing at-least-once delivery.
- Ordering: line order within a single TCP stream; across reconnects it depends
  on the shipper's buffer.
- Backpressure: TCP flow control propagates back to the shipper; the shipper
  buffers or slows reads.
- The TCP listener code is nearly identical to `SyslogListener::start_tcp_listener`;
  it replaces syslog parsing with JSON parsing (`serde_json::from_str`).
- This option requires deploying a shipper on the Zeek host; no existing
  shipper is needed if logthing is co-located (could also use Option A in
  that case).
- Multi-node: each Zeek node runs its own shipper and connects to logthing.
  logthing handles N concurrent TCP connections.

**Effort / blast radius:**

- New: `src/zeek/mod.rs`, `src/zeek/listener.rs`, `src/forwarding/zeek_s3.rs`.
- Modify: `src/config/mod.rs`, `src/main.rs`.
- No new external crates beyond `serde_json` (already used).
- TCP listener code is a near-copy of the syslog TCP listener, simplified
  (no syslog framing; just line-by-line JSON).
- Opens a new inbound TCP port on logthing.
- Very low blast radius on existing code.

**Pros:**
- No Kafka dependency.
- Zeek and logthing can be on different hosts (shipper in between).
- Standard NDJSON-over-TCP; many shippers support this natively.
- Leverages `corelight/json-streaming-logs`'s `_path` field directly.
- Code is structurally trivial — closest to an existing pattern (syslog TCP).
- Multi-node: add more shipper connections.
- The shipper provides buffering and retry between restarts.

**Cons:**
- Requires deploying an external shipper on each Zeek host (unless co-located).
- Shipper configuration is an external moving part not managed by logthing.
- TCP connection management: need per-connection read tasks, max-connection cap.
- If the shipper is not configured, no data flows (setup is split across two
  components).
- No built-in authentication on the TCP socket (can be addressed with TLS or
  IP allowlisting via logthing's existing `SecurityConfig::allowed_ips`).

---

### Option D: JSON-in-syslog via the existing SyslogListener

**How it works end-to-end:**

`rsyslog` or `syslog-ng` on the Zeek host can be configured to tail Zeek NDJSON
log files and forward each line wrapped in a syslog envelope (RFC 5424 or 3164)
to logthing's existing syslog listener on UDP/514 or TCP/601. logthing's
`SyslogHandler` receives the message; its `message` field contains the raw JSON.
A new `ZeekSyslogHandler` (or an extension of `DefaultSyslogHandler`) detects
when the `message` field is a valid JSON object containing `_path` (or where
`app_name` indicates Zeek), parses it, and routes it like the other options.
No new listener is needed.

**New module shape:**

```
src/syslog/
  zeek_syslog_handler.rs — ZeekSyslogHandler : SyslogHandler
                           detects JSON payload, extracts _path,
                           dispatches ZeekRecord to ZeekS3Handler
src/zeek/
  mod.rs                 — ZeekRecord
src/forwarding/
  zeek_s3.rs             — shared with other options
```

rsyslog config example on Zeek host:
```
module(load="imfile")
input(type="imfile"
      File="/opt/zeek/logs/current/json_streaming_*.log"
      Tag="zeek"
      Severity="informational"
      Facility="local0")
*.* action(type="omfwd" target="logthing" port="514" protocol="udp")
```

**Parquet schema:** Option S1 (same as above).

**Operational considerations:**

- Zero new logthing listener — uses the existing syslog port.
- Syslog UDP has a max message size of ~64KB (UDP datagram limit). Zeek records
  are typically well under 1KB, so this is not a practical limit in most cases.
  TCP syslog (601) has no inherent size limit.
- rsyslog/syslog-ng required on the Zeek host; these are standard on any
  Linux system that runs Zeek.
- Syslog framing adds ~50–100 bytes of overhead per record (PRI, hostname,
  timestamp, tag).
- The syslog timestamp and the Zeek `ts` field are both present; the Zeek `ts`
  is inside the JSON and is the authoritative one.
- The `ZeekSyslogHandler` must coexist with the existing `DefaultSyslogHandler`
  and `SyslogS3Handler` — the existing `SyslogListener` currently takes one
  `Arc<dyn SyslogHandler>`, so the handler must either be a multiplexing wrapper
  or the config must select among handlers.
- Multi-node: each Zeek node uses rsyslog to forward to logthing. Standard.
- Ordering: same as syslog (UDP is unordered; TCP is in-order per connection).
- Delivery: UDP = fire-and-forget; TCP = at-least-once with connection-level
  buffering.

**Effort / blast radius:**

- Smallest possible blast radius: one new handler struct in `src/syslog/`.
- No new listener, no new port, no new config section beyond a handler selector
  flag in `[syslog]`.
- Must not break existing syslog behavior — gated by the new handler being
  opted into explicitly.
- Shared `ZeekRecord` and `ZeekS3Writer` with other options.

**Pros:**
- Zero new infrastructure on logthing side (reuses existing syslog port and listener).
- rsyslog/syslog-ng are already present on any Linux Zeek host.
- Works over the network (Zeek remote from logthing).
- Smallest code addition.
- Config is additive (existing syslog configs continue to work).
- If you already have a syslog forwarding pipeline, Zeek records just join it.

**Cons:**
- Syslog is not the right semantic container for structured log records; the
  JSON is wrapped in a framing that strips its native meaning.
- The handler must detect "is this JSON from Zeek?" heuristically (check for
  valid JSON with `_path`, or check `app_name`). Fragile if other JSON-in-syslog
  arrives on the same port.
- UDP is lossy; TCP syslog is better but rsyslog configuration is non-obvious.
- Syslog record overhead is small but non-zero.
- The current `SyslogListener` handler is a single `Arc<dyn SyslogHandler>`,
  requiring a multiplexing wrapper to run both `SyslogS3Handler` and
  `ZeekSyslogHandler` simultaneously. This is a small but real code change.
- Limited extensibility: if Zeek-specific features are needed (e.g. per-stream
  S3 prefixes, schema evolution), the syslog framing becomes a barrier.

---

## Part 6: Summary comparison

| Criterion | A: File tailer | B: Kafka consumer | C: NDJSON-over-TCP | D: JSON-in-syslog |
|-----------|---------------|-------------------|-------------------|-------------------|
| New logthing modules | zeek/tailer.rs | zeek/kafka_consumer.rs | zeek/listener.rs | syslog/zeek_handler.rs |
| New listener port | None | None | Yes (TCP) | None |
| Zeek co-location required | Yes (or shared FS) | No | No | No |
| External dependency | notify crate | rdkafka + librdkafka | None (shipper optional) | rsyslog/syslog-ng |
| Zeek-side change | JSON output mode | zeek-kafka plugin | JSON output mode | JSON output mode + rsyslog config |
| At-least-once delivery | Yes (offset tracking) | Yes (Kafka offsets) | Yes (shipper buffer) | No (UDP) / Yes (TCP) |
| Multi-node Zeek | Needs shared FS | Native | Yes (N connections) | Yes (standard) |
| Blast radius on existing code | Low | Low | Low | Very low |
| Implementation effort | Medium | High | Low-Medium | Low |
| Ops complexity | Low | High (Kafka infra) | Medium (shipper) | Low |
| Query performance (Parquet) | S1 (envelope) | S1 | S1 | S1 |

---

## Part 7: Recommendation

**Build Option C (NDJSON-over-TCP) first, with Option A as the co-location
shortcut.**

**Rationale:**

Option C has the best balance of:
- Architectural fit (mirrors the syslog TCP listener almost exactly — it is
  essentially the syslog TCP listener with JSON parsing instead of syslog
  parsing),
- No new external crate dependencies,
- Network-transparent (Zeek and logthing can be on different hosts),
- Shipper-agnostic (Vector, Fluent Bit, Logstash, even `tail -F | nc` work),
- Clean new module in `src/zeek/` with a `ZeekHandler` trait that all future
  options share.

Option A (file tailer) is simpler for the co-located case and should be
built as a second phase, sharing the same `ZeekHandler` trait and
`ZeekS3Writer`. Its main addition is the inotify/polling loop.

Option D is the lowest-effort path if the operational environment already has
syslog forwarding infrastructure, but it is semantically awkward (JSON
wrapped in syslog) and becomes a liability if Zeek-specific features are
needed later. It is suitable as a stopgap but not as a designed-to-last path.

Option B (Kafka) is the right choice for large multi-node Zeek deployments but
carries disproportionate infrastructure and build complexity for a first
increment. It can be added later as a third transport behind the same
`ZeekHandler` trait.

**Smallest sensible first increment (Option C):**

1. `src/zeek/mod.rs` — `ZeekRecord` struct with the S1 envelope fields.
2. `src/zeek/listener.rs` — `ZeekListenerConfig`, `ZeekHandler` trait,
   `DefaultZeekHandler`, `ZeekListener` (TcpListener loop; JSON line parsing;
   extract `log_path` from `_path` field or fall back to `"unknown"`).
3. `src/forwarding/zeek_s3.rs` — `ZeekS3WriterConfig`, `ZeekS3Writer`,
   `ZeekS3Handler` (identical pattern to `IpfixS3Handler`; Arrow schema for
   ZeekRecord).
4. `src/config/mod.rs` — `[zeek]` and `[zeek.s3]` sections.
5. `src/main.rs` — conditional spawn when `config.zeek.enabled`.

No changes to syslog, IPFIX, or WEF modules. New TCP port (configurable,
default e.g. 9001). Zeek side: `LogAscii::use_json=T` + install
`json-streaming-logs` + configure Vector/Fluent Bit to ship to logthing:9001.

---

## Appendix: Unverified / flagged Zeek facts

- **Default rotation interval:** Zeek's `Log::default_rotation_interval`
  defaults to `0secs` (disabled) in the framework source, but zeekctl's
  `archive-log` script imposes rotation — the interval used by zeekctl was
  not definitively confirmed from documentation; community sources consistently
  cite 1 hour as the operational default.
- **zeek-kafka tag_json behavior:** Whether `tag_json=T` wraps the entire JSON
  object in `{ "conn": { ... } }` or just adds a `_path` field is inferred
  from the README description; not confirmed from live output.
- **zeek-kafka minimum Zeek version:** README does not state this; Zeek 4.x+
  is a reasonable assumption from community threads, but not verified.
- **JSON timestamp format:** Whether `LogAscii::use_json=T` produces float
  epoch or ISO-8601 timestamps depends on the `LogAscii::json_timestamps` 
  setting (default is `JSON::TS_EPOCH` = float). This affects how `ts` should
  be parsed in the ingestion code.
- **Broker external consumption:** Confirmed as impractical for Rust without
  linking against the C++ Broker library; no Rust Broker crate was found.
