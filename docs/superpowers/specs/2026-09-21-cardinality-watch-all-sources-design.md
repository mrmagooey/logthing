# Cardinality watch: all six ingest sources — design

Status: approved (auto-develop coherence review, round 3 of 3)
Date: 2026-09-21
Branch: `feat/field-cardinality-metric`

## Problem

`[[metrics.cardinality_watch]]` supports `source = "zeek" | "wef"`. The other
four ingest sources — suricata, syslog, ipfix, sflow — cannot be watched, even
though each already has an `AggFields` impl (written for the aggregation
feature) that `CardinalityWatcher::observe<R: AggFields>` would accept
unchanged.

Several of those sources carry better host-identity fields than zeek's
`id.orig_h`: syslog has `hostname`, ipfix and sflow have `exporter`.

## Scope

Grow `KNOWN_WATCH_SOURCES` from 2 to 6 and wire the four new sources. No
structural change to config, metric labels, the watcher, the cap, the window
semantics, or the hostile-input safety property — that is the payoff of the
existing list-and-`source` config shape.

## The load-bearing finding: the default code path is not the obvious one

`syslog`, `ipfix`, and `sflow` listeners each have a `recv_tasks` knob that
**defaults to 8**. Above 1, `start_with_shutdown` takes a `SO_REUSEPORT`
fan-out path that spawns N tasks running *separate free functions* —
`syslog_udp_recv_loop`, `ipfix_recv_loop`, `sflow_recv_loop` — each with its
own dispatch calls. The inline `recv_tasks <= 1` branch is **not** what ships.

Wiring only the inline branch would make all three sources observe zero records
at stock config: the gauge pins at 0, which this module's own docs call
indistinguishable from "ingestion is dead" — the exact misreading the feature
exists to prevent.

### Complete dispatch-site inventory (17)

| Source | Sites |
|---|---|
| suricata | `listener.rs:489` |
| syslog | `:369, :462, :658, :812, :865, :918` |
| ipfix | `:164, :216, :353, :412, :465` |
| sflow | `:155, :207, :333, :388, :441` |

`PayloadDispatchingHandler::handle_message` (`syslog/listener.rs:218`) is
deliberately **excluded**: it is a `SyslogHandler` trait impl invoked *by* those
dispatch sites, not a listener observation point. Observing there would repeat
the "metric inside a `Default*Handler` never fires" bug this repo has already
shipped once.

## Design

### Observation via a per-source helper

Each of the four listeners gains a small `observe_and_dispatch` helper that
observes the record (looping the batch for ipfix/sflow) and then calls the
handler. Every dispatch site — inline branch and fan-out loop alike — routes
through it.

At 17 sites the duplication *is* the failure mode. Every site must be touched
anyway to add the observe call, so routing them through one helper is the same
diff size and makes a missed site structurally impossible rather than merely
guarded. The helpers are per-source, not a cross-source abstraction — this repo
has previously tried and rejected generic multi-source unification
(`forwarding-start-pairs-are-load-bearing`), and zeek's listener already funnels
its entry points through one shared per-record function in exactly this shape.

### Stream validation: only where the set is a compile-time constant

`compile_watches` gains startup validation of `stream` for **ipfix** (must be
`"flows"`) and **sflow** (`"flow"` or `"counter"`) — the only two sources whose
`AggFields::stream()` returns a literal or a closed enum.

**Suricata is deliberately NOT validated.** `SuricataRecord::stream()` returns
the raw wire `event_type`, not the collapsed `metric_event_type` label.
`EVE_EVENT_TYPES` (`suricata/schema.rs`) is a hand-maintained *label* allowlist
whose own comment says adding a type is "a deliberate act; until it is added it
reports as `other`". Validating a configured stream against it would reject a
watch on a legitimate Suricata event type that simply has not been added yet.
zeek, wef, and syslog streams are open wire values and equally unvalidatable.

### One-shot never-matched warning

`CardinalityWatcher` gains a warning fired at the first window boundary at which
the watch has **never matched any record since process start**, naming both
causes: a misconfigured `stream`, or the source genuinely receiving nothing.
One-shot — it never repeats.

"Never matched since startup" is chosen over "no match in the last N windows"
because the latter is ambiguous with any quiet period at every value of N,
whereas a misconfigured stream never matches *ever*. Firing at the first
boundary is fast (one window); one-shot means it cannot become noise.

Known, accepted false positive: a source that legitimately receives nothing
during its first window warns once. And because watcher state is in-memory and
resets on restart, a genuinely-down source under a crash-loop or a restart
cadence near `cardinality_window_secs` re-arms the warning each restart. That is
inherited from the module's existing reset-on-restart property (which the
"field never found" warning already shares), not introduced here — document it,
do not engineer around it.

### Source-enabled validation, and the WEF exception

A watch naming a source that is disabled in config is fatal at startup,
following `aggregate::compile_rules`'s `source_enabled` precedent: otherwise it
produces a permanently-absent gauge that reads as an outage.

**Do not reuse `aggregate::source_enabled` verbatim.** It has no `"wef"` arm and
falls through to `_ => false`; `WefConfig` has no `enabled` field and `/wsman`
is mounted unconditionally. Reusing it would make every existing
`source = "wef"` watch fail startup — a regression against the shipped,
tested WEF feature. The cardinality check needs an explicit `"wef" => true`
with a comment recording that no WEF enable/disable toggle exists.

## Testing

- **Unit** — `compile_watches` accepts each of the six sources; rejects a
  disabled source; accepts `wef` with no enable toggle; rejects a bad ipfix or
  sflow `stream`; accepts an arbitrary suricata `stream` (regression guard for
  the deliberate non-validation above). One-shot warning fires once and only
  once.
- **Integration** — one per new source, and for the three fan-out-capable
  sources **each must exercise both `recv_tasks <= 1` and `recv_tasks > 1`**.
  The round-1 defect was the default path being unwired; a test that drives only
  the inline branch would not catch a repeat.
- **E2E** — one, for syslog watching `hostname`, **explicitly at default
  `recv_tasks`** so it drives the SO_REUSEPORT path.
  `tests/syslog_panic_resilience_e2e.rs` already uses the default deliberately
  and says why.
- **Guard** — a source-scanning test asserting no raw `handler.handle_*` call in
  these four listeners bypasses its helper. Same idiom as
  `describes_every_metric_emitted_in_src` (`src/metrics_descriptions.rs`), which
  already scans `src/` textually for undescribed metrics.

**Stated deviation:** one e2e rather than four. The HTTP-scrape path is shared
and already proven by two existing e2e tests; per-source risk sits in the helper
and the fan-out wiring, which integration covers at both `recv_tasks` values.
Each e2e is a separate compiled binary on a machine with limited disk.

## Documentation

`logthing.toml` gains a syslog `hostname` example and an ipfix `exporter`
example (single-record and batch cases), a comment listing all six valid
`source` values, and two notes:

- ipfix's `stream` is the mandatory constant `"flows"` — the dimension carries
  no information there.
- syslog traffic without `app_name` (RFC 3164-style) has an empty stream, and
  empty configured streams are rejected, so that traffic can never be watched.

The `ponytail:` comment in `cardinality.rs`'s module doc currently says "exactly
two supported sources" and names what a third would take. It becomes false the
moment this ships and must be updated to six.

## Rejected alternatives

| Option | Why rejected |
|---|---|
| Duplicate the observe call at all 17 sites | The duplication is the failure mode; a future site silently undercounts |
| Observe in the ipfix/sflow decoder | Decoder is also called from tests and benches with no watcher |
| Observe in handler impls | A metric inside a `Default*Handler` never fires in most deployments |
| Uniform "no match in N windows" warning for all six | Ambiguous with a quiet period at every N; drops free, precise startup validation where closed sets exist |
| Validate suricata's `stream` against `EVE_EVENT_TYPES` | That list is an incomplete-by-design label allowlist; would reject legitimate unlisted event types |
| Reuse `aggregate::source_enabled` | No `wef` arm, `_ => false` — breaks the shipped WEF watch |
