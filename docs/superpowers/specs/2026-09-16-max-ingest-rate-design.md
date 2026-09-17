# Max ingest rate per format — design

**Date:** 2026-09-16
**Status:** approved, pending implementation plan
**Base commit:** `152766d` (v0.19.1)

## 1. Problem

logthing has no maximum sustainable ingest rate for any of its seven wire
formats. Every perf document in `docs/performance/` says so explicitly, and
each one names a different reason the number is missing:

- `2026-09-13-multiformat-load-results.md` §4: *"No capacity number. The
  generator saturated before the server did for Zeek, and the kernel buffer
  saturated before the server did for IPFIX. Neither ceiling found is
  logthing's."*
- `2026-09-14-throughput-baseline-repeats.md`: *"Nothing below is a capacity
  number — every figure is loss at a fixed, reproduced offered rate."*

The working hypothesis going in is that `tools/loadgen` is the binding
constraint. **That hypothesis has never been measured**, and one of the two
data points offered for it does not support it:

> `2026-09-13-multiformat-load-results.md` §2 reports `zeek-tcp` achieving
> 15,283/s against a 20,000/s target and concludes *"the generator, not the
> server, is the limit above ~15k/s."* On TCP that inference is invalid. A
> server draining the socket too slowly produces exactly the same signature —
> the write blocks, the generator's achieved rate falls. Nothing in that run
> distinguishes the two.

The IPFIX data point is sound (UDP cannot backpressure, so 29,118/s unbounded
is a real generator ceiling), but it covers one format.

So the problem is two problems, and they must be solved in order:

1. **Attribution.** Make "the generator ran out" and "the server ran out"
   separately observable, per format.
2. **Capacity.** Raise the generator only where attribution says it binds,
   then ramp each format to a defined ceiling.

## 2. Decisions taken

| Decision | Choice | Rejected alternatives |
|---|---|---|
| Environment | Loopback on the existing KVM host, with generator and server `taskset`-pinned to disjoint core sets and per-side CPU recorded per run | Docker sim environment (adds container networking and more CPU contention); off-box sender (no hardware, no NIC/link-rate accounting in this repo) |
| Format scope | The 7 formats `tools/loadgen` already implements | Adding OTLP + WEF generators first (delays every measurement behind generator-writing); UDP only (leaves the HTTP paths, which are the most broken, unmeasured) |
| Ceiling metric | Highest offered rate whose **median total loss ≤ `LOSS_BUDGET`** (default 0.1%) over `RUNS` runs, with loss reported per drop site as well as totalled | First non-zero drop (the baseline doc shows 124/300,000 lost at random on this host — a zero-tolerance gate measures noise); knee of achieved-vs-offered (conflates generator and server saturation, i.e. reproduces the exact bug in §1) |

Pinning does not make this a clean-room capacity number. It makes the *loss
attribution* trustworthy, which is the part currently missing. All existing
host caveats carry forward verbatim into the results document.

## 3. What is already built and gets reused

`scripts/repeat-ipfix-loopback-loss.sh` (added 2026-09-14) already solves the
hard parts of a loss harness and has 20 validated runs behind it:

- restarts the server between every run, so `*_datagrams_received`,
  `*_socket_drops` and `parquet_s3_dropped` all start at zero — no delta
  bookkeeping;
- diffs `/proc/net/snmp`'s host-wide `RcvbufErrors` around each load burst,
  and cross-checks it against the listener's own `*_socket_drops`
  (reconciled exactly on all 20 runs in the baseline doc);
- swaps between a `trivial` handler shape (`Default*Handler`, no sink) and a
  `real` shape (a local Parquet sink in a temp dir, no external service);
- reports median / min / max across N repeats rather than one number.

This design **generalises that script** rather than writing a second harness.

Two defects in it get fixed as part of that work, both recorded from prior
sessions:

- `pkill -f "$BIN"` (startup and `EXIT` trap) matches the whole command line,
  so it kills any shell whose command text contains the binary path —
  symptom is a bare exit 144 with no output. Replace with a pidfile.
- its cleanup does `rm -f logthing.admin.toml`, which deletes a **tracked**
  file. Restore-from-backup only.

## 4. Phase 0 — attribution (no new generator code)

Two probes, neither of which requires changing `tools/loadgen`.

### 4.1 Multi-process scaling

Run 1, 2 and 4 `loadgen` processes concurrently at each one's unbounded rate
against the same server, same format, and compare aggregate achieved rate.

- Scales ~linearly → the per-process ceiling is not fundamental. The fix for
  "the generator is too slow" is *run more of them*, and Phase 1 is skipped
  entirely for that format.
- Flattens → the limit is downstream of the generator (server, kernel, or
  shared CPU), and the achieved-rate number was never a generator ceiling.

This runs first because it is the cheapest possible answer and can obsolete
all of Phase 1.

### 4.2 Receiver-free reference rate

For the three UDP formats, point the generator at an **unbound loopback
port**. The kernel discards at the socket layer, the `send` syscall costs what
it always costs, and no receiver exists to be the bottleneck. The achieved
rate is then a pure generator ceiling, at zero code cost.

For `zeek-tcp`, `suricata-tcp`, `hec-http` and `generic-http` a peer is
required, so the nearest equivalent is the harness's existing `trivial` shape
— a real listener with a `Default*Handler` and no sink configured. This is
weaker (the server still does socket and parse work) and is labelled as such
in the results.

**Phase 0 output:** a per-format table of *generator ceiling* vs *achieved
rate against a real sink*. Formats where those are equal are generator-bound
and go to Phase 1. Formats where achieved is already lower skip Phase 1 —
something else binds first.

## 5. Phase 1 — raise the generator, only where Phase 0 says it binds

Every subcommand today is one task on one socket, building each payload on the
hot path: `chrono::Utc::now()` + `json!` + `format!` + `to_string()` for the
NDJSON formats, `build_datagram()` for the binary ones. The HTTP subcommands
additionally send **one HTTP request per single event**, so `hec-http` and
`generic-http` currently measure `reqwest`'s request rate, not logthing's
ingest rate.

Fixes in strict ladder order, stopping at the first rung that clears the
server's observed rate:

1. **N processes** — no code, already proven or disproven in §4.1.
2. **Pre-rendered payload ring.** Build K payloads at startup (K = 1024),
   index `sent % K`, patch only the sequence/varying bytes in place. Removes
   the whole per-record serialisation cost. Roughly ten lines per generator.
3. **HTTP request batching.** `--events-per-request` for `hec-http` and
   `generic-http`; both endpoints already accept multi-event bodies. Largest
   single HTTP win available, and a more realistic shipper shape than one
   event per POST.
4. **`--workers N`** — N tasks, each with its own socket/connection, splitting
   the target rate. Only if 1–3 still fall short of the server.

Rung 2 must not change the wire bytes' validity: each generator's existing
"parses with logthing's own parser" unit test (e.g.
`conn_record_parses_with_logthings_own_parser` in `zeek_tcp.rs`) is extended
to cover payloads taken off the ring, and the existing "consecutive records
are distinct" test is what stops the ring from degenerating into one repeated
row.

## 6. Phase 2 — `scripts/max-ingest-rate.sh`

Generalises `repeat-ipfix-loopback-loss.sh`. New behaviour on top of §3's
inherited machinery:

### 6.1 Per-format map

`FORMAT` selects the generator subcommand, its port, the config template, and
the metric set to scrape:

| FORMAT | subcommand | port | received counter | kernel loss | writer loss |
|---|---|---|---|---|---|
| `syslog` | `syslog-udp` | 514 | `syslog_messages_received` | `syslog_socket_drops` | `parquet_s3_dropped{source="syslog"}` |
| `ipfix` | `ipfix-udp` | 4739 | `ipfix_datagrams_received` | `ipfix_socket_drops` | `…{source="ipfix"}` |
| `sflow` | `sflow-udp` | 6343 | `sflow_datagrams_received` | `sflow_socket_drops` | `…{source="sflow"}` |
| `zeek` | `zeek-tcp` | 47760 | `zeek_records_received` | n/a (TCP) | `…{source="zeek"}` |
| `suricata` | `suricata-tcp` | 47761 | `suricata_records_received` | n/a (TCP) | `…{source="suricata"}` |
| `hec` | `hec-http` | 5985 | `hec_events_received` | n/a | `…{source="hec"}` |

Sink `source` labels are the sinks' own `source()` values: `syslog`,
`structured_syslog`, `ipfix`, `sflow`, `zeek`, `suricata`, `hec`.
`loadgen syslog-udp --structured` routes to the `structured_syslog` sink
instead of `syslog`, so the syslog metric map is selected by that flag.
| `generic` | `generic-http` | 5985 | `hec_events_received` (shared — §6.4) | n/a | `…{source="hec"}` (shared — §6.4) |

All three UDP listeners already report `<protocol>_socket_drops` through
`SocketDropStats` (`src/net.rs:222`), so kernel loss is observable for every
UDP format, not just IPFIX. `parquet_s3_buffer_dropped` and
`parquet_s3_records_written` are scraped for every format as well.

### 6.2 CPU pinning and the generator-saturation guard

The host has 12 vCPUs. The harness pins the server to cores 4–11 and the
generator to cores 0–3 with `taskset`, and samples each side's CPU time from
`/proc/<pid>/stat` around the load burst. Both figures are reported per run.

### 6.3 Ramp and verdict

Coarse doubling from a per-format start rate until the first failing rate,
then bisect between last-pass and first-fail to a configurable resolution.
Not a linear sweep.

A rate **passes** iff, across `RUNS` runs of `DURATION` seconds each:

- median total loss ≤ `LOSS_BUDGET` (default 0.1%), where total loss is
  `offered − parquet-written`, **and**
- the generator achieved ≥ 99% of target rate in *every* run.

A run failing the second clause is reported `GENERATOR-LIMITED` and the ramp
stops with no ceiling claimed for that format. This clause is the entire
point of the design: it is what would have caught the Zeek TCP
misattribution in §1, and it is why Phase 0's reference rates matter.

`offered − parquet-written` is only meaningful once buffered rows have
actually been flushed, so each run ends with an explicit drain period (a
forced flush where the config allows one, otherwise a fixed wait) before
counters are scraped, and the harness rescrapes once and fails the run if
`parquet_s3_records_written` is still climbing. Counting rows still in flight
as loss is the failure mode `2026-09-13-multiformat-load-results.md` §2
already had to explain away by hand.

Loss is always reported **per drop site** (kernel / writer-channel / buffer
hard cap) in addition to the total. The baseline doc's finding that
`parquet_s3_dropped` reached 70–75% of delivered datagrams while kernel loss
was 3.6% is exactly the information a single aggregated percentage destroys.

### 6.4 `hec` and `generic` share every counter

`handle_ndjson` (`src/ingest/handlers.rs:219`) increments
`hec_events_received`, the same counter the two HEC routes use, and its
records land in the same `GenericSink`, whose `source()` is `"hec"`
(`src/forwarding/generic_s3.rs:163`). The two formats are therefore
indistinguishable in the metrics.

No production code changes for this. The harness runs exactly one format at a
time against a freshly restarted server, so the attribution is unambiguous by
construction — but the results document must state which generator produced
each `hec`-labelled row, and the harness must refuse to run `hec` and
`generic` concurrently.

## 7. Phase 3 — results document

`docs/performance/2026-09-16-max-ingest-rate.md`, following
`docs/performance/methodology-template.md`. Per format:

- max sustainable rate, with the loss breakdown at that rate and at the first
  failing rate;
- the Phase 0 generator ceiling alongside it, so the margin is visible;
- an explicit verdict: **kernel-limited / writer-limited / server-CPU-limited
  / generator-limited**;
- generator and server CPU at the ceiling;
- all existing host caveats carried forward verbatim.

## 8. Testing

| Level | What |
|---|---|
| Unit | Rust tests for the payload ring and HTTP batching in `tools/loadgen` — a payload taken off the ring still round-trips through logthing's own parser, and consecutive payloads remain distinct (extends the existing per-generator tests). `SELFTEST=1` mode in the harness feeds synthetic per-run values through the median / verdict / bisect logic and asserts the outcomes, including the `GENERATOR-LIMITED` path. |
| Integration | One short real harness run (1,000/s, 2 runs, 3 s, `real` shape) asserting it emits a verdict, that `*_socket_drops` reconciles with the `RcvbufErrors` delta, and that `logthing.toml` / `logthing.admin.toml` are byte-identical afterwards (regression for §3's tracked-file deletion). |
| E2E | The real per-format ramps that produce §7's document. |

## 9. Out of scope

- **OTLP and WEF generators.** OTLP has never been written; WEF has only the
  non-loadgen `tests/e2e/simulation-environment/wef-generator`. Add once the
  seven formats have numbers.
- **Off-box sender.** The only route to a defensible absolute capacity
  figure, and the right follow-up, but it needs hardware this design does not
  assume.
- **`sendmmsg` batching**, io_uring, or any other syscall-amortisation work in
  the generator. Rungs 1–4 of §5 are expected to be enough; revisit only with
  a Phase 0 number showing otherwise.
- **Optimising logthing itself.** This design measures ceilings. Acting on
  them is separate work, and `perf-per-record-cost-figure-is-wrong` is the
  standing warning about opening perf work on an unmeasured premise.
