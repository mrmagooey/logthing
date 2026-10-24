# Event filter (dropping unwanted events)

logthing can drop whole events that match a rule before they are stored. Rules are configured
with `[[filter.rules]]`, apply to all eight sources (WEF, syslog, Zeek, Suricata, IPFIX,
sFlow, HEC, OTLP), are off by default, and cost one branch per event when a source has no
rules. A dropped event is never enqueued, spooled, aggregated or written.

## Configuration

```toml
[[filter.rules]]
name   = "wef-wfp-noise"
source = "wef"
match  = { event_id = [5156, 5158] }

[[filter.rules]]
name   = "systemd-started"
source = "syslog"
match  = { app_name = "systemd", message = { regex = "^Started " } }

[[filter.rules]]
name   = "zeek-dns-wpad"
source = "zeek"
match  = { log_path = "dns", query = ["wpad", "isatap"] }

[[filter.rules]]
name   = "otlp-healthchecks"
source = "otlp"
match  = { "attributes.http.route" = "/healthz" }
```

| Key | Meaning |
|---|---|
| `name` | Unique, non-empty. It is the `rule` label on `events_filtered` and appears in startup errors. |
| `source` | One of `wef`, `syslog`, `zeek`, `suricata`, `ipfix`, `sflow`, `hec`, `otlp`. |
| `match` | Table of `field = condition`. Field names are listed [per source](#fields-per-source). |

## Conditions

| Form | Example | Matches when |
|---|---|---|
| Scalar (string, integer, float, boolean) | `app_name = "systemd"` | the field equals the value |
| Array of scalars | `event_id = [5156, 5158]` | the field equals any element |
| Table with `regex` | `message = { regex = "^Started " }` | the regex matches anywhere in the field |

- All conditions in one rule must match (AND). An event is dropped when any rule matches (OR
  across rules).
- **Comparison is on text.** Strings compare as-is and case-sensitively. Booleans compare as
  `true` / `false`. A number with no fractional part and an absolute value below 2^53 compares
  as an integer, so `event_id = 5156`, `event_id = "5156"` and `event_id = 5156.0` are the same
  rule and all match WEF event 5156. Other numbers compare as their shortest decimal text.
- **2^53 limit.** Numeric fields are carried as 64-bit floats, so integers above 2^53
  (u64 counters, WEF `keywords` and `event_record_id`) can compare imprecisely. Use a regex or a
  smaller field for those.
- **Regexes are unanchored.** `{ regex = "Started" }` matches any value containing `Started`;
  add `^` and `$` to anchor. They use the Rust `regex` syntax and the same 1 MiB compiled-size
  cap as redaction `mask_patterns`. A pattern that can match the empty string (`x*`, `^`, `.*`)
  is rejected at startup, because it would drop every event that carries the field.
- **A field the event lacks, or whose value is `null`, never matches.** A typo in a field name
  therefore keeps data rather than silently dropping it. Field names are not checked against a
  schema at startup.
- **Array- and object-valued fields never match** (for example Zeek `answers`). Only scalars
  are comparable, and arrays are not indexed.

## Fields per source

Names are the stored column or JSON key names. Where a value is free-form JSON it is addressed
by a path under the column that stores it. The path is looked up as one literal key first
(so keys that contain dots work, such as OTLP `http.route`), then as a dotted path through
nested objects; it is case-sensitive.

| Source | Field names | Free-form part |
|---|---|---|
| syslog | `priority`, `severity`, `facility`, `timestamp` (RFC 3339), `hostname`, `app_name`, `proc_id`, `msg_id`, `message`, `protocol` (exactly `Rfc3164`, `Rfc5424` or `Unknown`) | structured data as `<sdid>.<param>` |
| Zeek | `log_path` (the normalized stream name, e.g. `dns`, `conn`) and every other stored column by its Zeek JSON key; `id_orig_h`, `id_orig_p`, `id_resp_h`, `id_resp_p` and the dotted JSON names `id.orig_h` etc. both work | any key of the record |
| Suricata | any EVE key: `event_type`, `src_ip`, `dest_ip`, `dest_port`, `proto`, and nested keys as `alert.signature_id`, `dns.rrname` | any key of the EVE record |
| IPFIX | the stored typed columns: `observation_domain_id`, `template_id`, `protocol_version`, `exporter`, `export_time`, `src_addr`, `dst_addr`, `src_port`, `dst_port`, `ip_protocol`, `octet_delta_count`, `packet_delta_count`, `flow_start`, `flow_end`, `tcp_flags`, `input_interface`, `output_interface` | other information elements by name or `ie<id>` |
| sFlow | the stored typed columns: `exporter`, `received_at`, `src_addr`, `dst_addr`, `src_port`, `dst_port`, `ip_protocol`, `sampling_rate`, `input_ifindex`, `output_ifindex`, the `if_*` counters, and `sample_type` (`flow` or `counter`) | other elements by name |
| WEF | `source_host`, `subscription_id`, `computer`, `provider`, `channel`, `event_id`, `security_user_id`, `level`, `message`, `task`, `opcode`, `keywords`, `event_record_id`, `process_id`, `thread_id` | `data.<Name>` (EventData) |
| HEC | `sourcetype`, `host`, `source`, `index`; `fields` alone matches only when the event itself is a scalar | `fields.<path>`, `indexed_fields.<path>` |
| OTLP | `severity_number`, `severity_text`, `body`, `service_name`, `service_namespace`, `service_instance_id`, `host_name`, `peer_addr`, `trace_id`, `span_id`, `flags`, `event_name`, `scope_name`, `scope_version` | `attributes.<key>`, `resource_attributes.<key>` |

Notes:

- **Zeek:** use `log_path`. `_path` is not an alias; it resolves to the raw `_path` value in the
  JSON, which can carry a rotation suffix.
- **WEF:** `level` is the numeric Windows level: 1 Critical, 2 Error, 3 Warning,
  4 Information, 5 Verbose. An event whose XML could not be parsed has only `source_host` and
  `subscription_id`; every other field is missing and never matches.
- **HEC:** the raw route (`/services/collector/raw`) stores the text as `{"raw": "<text>"}`, so
  address it as `fields.raw`. Bare `fields` only matches when the event value is a scalar.
- **OTLP:** the body is matched as a whole text, so use a regex for a substring.
- **Timestamps** that are exposed compare as RFC 3339 text, so a regex is the practical way to
  match them: syslog `timestamp`, IPFIX `export_time`, `flow_start` and `flow_end`, and sFlow
  `received_at`. Zeek `ts` and Suricata `timestamp` are ordinary JSON keys of the record.
- **Not addressable:** `event_uuid` (HEC and OTLP assign it after filtering), HEC and OTLP
  `time`, OTLP `observed_time`, `partition_time`, and `received_at` on every source except
  sFlow.

## Where it runs

The filter runs as soon as a record is parsed, before anything that describes what is stored:

- HEC and OTLP: before [redaction](redaction.md), so rules match the raw values you would
  write. A dropped record is never stored, so nothing is leaked.
- All sources: before [aggregation](aggregation.md) and before
  [cardinality watches](configuration.md), so dropped events are neither counted nor observed.
- IPFIX and sFlow filter per flow or sample record; the rest of the datagram is kept.

A filtered event is **acknowledged**: the WEF bookmark advances, HEC answers success, OTLP does
not count it as rejected, and a request in which every record is filtered still succeeds.
Otherwise the sender would resend a dropped event forever. Filtered events are never spooled
or written (see [delivery-semantics.md](delivery-semantics.md)).

## Counters

`events_filtered{source,rule}` counts events dropped by each rule. Arrival counters keep
meaning "arrived", with two exceptions:

| Counted including filtered events | Counted excluding filtered events |
|---|---|
| `syslog_messages_received`, `zeek_records_received`, `zeek_records_by_path`, `suricata_records_received`, `suricata_records_by_event_type`, the IPFIX and sFlow decoder counters, WEF throughput statistics | `hec_events_received`, `otlp_logs_received` |

## Validation and restarts

Startup fails, naming the rule, for: an empty or duplicate `name`; an unknown `source`; a
`source` that is not enabled (WEF is always enabled; OTLP counts as disabled when not compiled
in); an empty `match`; an empty field name; an empty list; a regex that is invalid, too large or
can match the empty string; a condition that is not a scalar, a list of scalars or
`{ regex = "..." }`.

Like all configuration, rules are read at startup; a change needs a restart. `filter.rules` is
a list of tables, so it cannot be set through `LOGTHING__*` environment variables and must be
written in the config file (see [configuration.md](configuration.md)).
