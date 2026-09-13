# Criterion baseline — logthing 0.18.0

**The first criterion numbers committed to this repo.** The three existing
`docs/performance/` results docs are all end-to-end `loadgen`/profiling runs
pinned to crate version **0.9.0**, nine minor releases back; none of them
report criterion output.

---

## ⚠️ Read this before quoting any number below

**This run was taken on a virtual machine with no CPU frequency control.**
Treat these figures as **magnitudes, and as ratios between benches within this
same run**. Do not treat them as absolute constants, and do not compare them
against a run taken on different hardware.

- CPU: **QEMU Virtual CPU version 2.5+** under **KVM** — the model name is
  generic, so the real underlying silicon is unknown. 12 vCPUs. BogoMIPS
  5319.99.
- **No `cpufreq` interface exists** on this guest: there is no scaling
  governor to pin, no frequency to read, and no way to rule out contention
  from other tenants on the host during the run.
- Memory: 61 GiB. Kernel: `6.12.94+deb13-amd64`.

`docs/performance/2026-07-25-syslog-udp-cpu-profile.md:365-368` flags the
absence of recorded hardware as a known limitation of the earlier docs. This
section exists so that limitation is not repeated — the honest answer about
this machine is "a VM, and we cannot see more than that."

## Provenance

| | |
|---|---|
| Crate version | 0.18.0 |
| Git commit | `c613d5d` (branch `perf/recv-path-benches`) |
| Date | 2026-09-13 |
| Toolchain | `rustc 1.98.1 (48a229cea 2026-09-01)` |
| Command | `cargo bench -- --save-baseline v0.18.0` |
| Criterion settings | defaults — 100 samples, 3 s warm-up, 5 s measurement. No bench in this repo overrides them. |

All figures below are the **median** of criterion's 100-sample estimate.

---

## 1. Receive path — bytes off the wire → in-memory record

Before this release, this layer had **exactly one bench in the entire repo**
(syslog UDP). Four sources were added here.

| Source | Case | Median | Notes |
|---|---|---|---|
| **zeek** (TCP NDJSON) | `conn` | **2.86 µs** | new |
| | `dns` | 2.85 µs | new |
| | `http` | 3.20 µs | new — longest string values |
| | `conn` w/ rotated `_path` | 3.15 µs | new — exercises `normalize_log_path`'s split arm |
| | `from_utf8` + parse (`conn`) | 3.37 µs | new — full listener chain |
| **suricata** (TCP NDJSON) | `alert` | **4.89 µs** | new — nested `alert` + `flow` objects |
| | `flow` | 3.22 µs | new |
| | `dns` | 2.99 µs | new |
| | `from_utf8` + parse (`alert`) | 5.03 µs | new |
| **IPFIX** (UDP binary) | warm cache, data-only | **308 ns** | new — **the steady-state number** |
| | cold cache, template+data | 510 ns | new — template-refresh only |
| **sFlow** (UDP binary) | flow, raw packet header | **220 ns** | new |
| | flow, pre-parsed IPv4 | 214 ns | new |
| | counter sample | 230 ns | new |
| **syslog** (UDP) | RFC 3164 envelope | 5.46 µs | pre-existing |
| | `payload::dispatch`, all-miss | 1.22 µs | pre-existing |
| | `payload::dispatch`, CEF hit | 2.95 µs | pre-existing |
| | combined recv path | 8.03 µs | pre-existing |

### Still not covered at this layer

Listed so the gap stays visible rather than silently absent: **syslog TCP**,
**syslog HTTP** (`POST /syslog`), **HEC** (HTTP body → `GenericRecord`), **WEF**
(XML event parse), **OTLP** (protobuf request mapping). WEF and OTLP are the
two worth doing next — both are genuinely unmeasured parse work not shared
with any benched transport.

## 2. Encode path — record → Arrow `RecordBatch`

| Sink / schema | Median | Notes |
|---|---|---|
| zeek `conn` | **15.58 µs** | new |
| zeek `dns` | 16.28 µs | new |
| zeek `http` | 15.33 µs | new |
| zeek `ssl` | 14.98 µs | new |
| zeek `notice` | 14.13 µs | new |
| zeek `files` | 11.04 µs | new |
| zeek `envelope` (unmodelled stream) | **10.29 µs** | new — the fallback every unmodelled stream takes |
| zeek `conn`, per-record (amortization bench) | 17.57 µs | pre-existing |
| zeek `conn`, amortized batch of 10 | 43.03 µs (4.30 µs/record) | pre-existing |
| zeek `conn`, amortized batch of 100 | 391.90 µs (3.92 µs/record) | pre-existing |
| zeek `conn`, amortized batch of 1000 | 3.30 ms (3.30 µs/record) | pre-existing |
| IPFIX, 1-flow datagram | 15.44 µs | pre-existing |
| IPFIX, 10-flow datagram | 23.41 µs (2.34 µs/flow) | pre-existing |
| sFlow, flow sample | 9.34 µs | pre-existing |
| sFlow, counter sample | 10.52 µs | pre-existing |
| syslog | 8.83 µs | pre-existing |
| suricata envelope | 5.57 µs | pre-existing |
| WEF | 6.32 µs | pre-existing |
| generic/HEC | 4.13 µs | pre-existing |

**Structured syslog** (`StructuredSyslogSink::to_record_batch`) remains the one
sink with zero encode coverage.

---

## 3. What these numbers actually say

**Binary decode is ~42-50× cheaper than encode, and is not a bottleneck.**
This is the headline new result, and every pairing below is single-record
against single-record:

| | decode | encode | ratio |
|---|---|---|---|
| IPFIX (1 flow) | 308 ns | 15.44 µs | **50.1×** |
| sFlow flow sample | 220 ns | 9.34 µs | **42.5×** |
| sFlow counter sample | 230 ns | 10.52 µs | **45.7×** |

Both binary receive paths had never been measured before; neither deserves
optimisation attention.

Do **not** widen this to "30-70×". The 70× end is only reachable by dividing
the 10-flow IPFIX batch total (23.41 µs) by a *single*-flow decode (308 ns) —
a batch-against-single unit mismatch — and the 30× end only by using the
cold-cache decode (510 ns) that this same document says essentially no
production traffic pays. Both are the exact error §4 below warns about.

**Text parse is real but secondary.** Zeek parses a `conn` line in 2.86 µs and
encodes it in 15.58 µs — encode dominates roughly 5:1. Suricata's `alert` parse
(4.89 µs) is the dearest *pure* parse measured — the combined
`from_utf8 + parse` rows (5.03 µs suricata, 3.37 µs zeek) are higher by
construction since they include the UTF-8 validation step. That `alert` leads
tracks: it is the only fixture carrying nested `alert` and `flow` objects.

**The IPFIX template cache earns its keep.** A cold-cache decode costs 510 ns
against 308 ns warm — a 1.65× penalty. Since a real exporter re-sends templates
on a multi-minute interval and sends data sets continuously, essentially all
production traffic pays the 308 ns path. Quote that one.

**The unmodelled-stream fallback is the cheapest zeek encode, not the dearest.**
`envelope_unmodelled` at 10.29 µs beats every modelled schema (11.04-16.28 µs).
That is the opposite of the intuition that a generic fallback must be slower —
it carries the JSON through as one string rather than building a dozen typed
Arrow columns. Worth knowing before anyone "optimises" it.

### A prediction in the plan that was wrong

The plan for the sFlow bench asserted that `flow_raw_header` would be the most
expensive of the three cases, and that if it were not, "the Ethernet walk is not
running." **The prediction failed and the explanation was wrong.** Measured:
raw-header 220 ns, pre-parsed IPv4 214 ns, counter 230 ns — flat within ~7%,
with `counter` marginally dearest.

The walk *is* running: the pre-existing unit test
`decode_flow_sample_raw_header_extracts_5tuple` (`src/sflow/decoder.rs:832`)
asserts that this exact fixture yields src `192.168.1.10`, dst `10.0.0.2`,
ports 8080/80, protocol TCP — which is only reachable through
`parse_ethernet` → `parse_ipv4` → `parse_transport`. Walking ~54 bytes of
header is a handful of fixed-offset reads, genuinely negligible against the
fixed per-datagram cost (header parse, `Vec` allocation, building an
`SflowRecord` with 20+ `Option` fields). And `counter` is marginally dearest
because it populates 10 counter fields against the flow sample's ~7.

No bug. The bench is correct; the expectation written into the plan was not.

## 4. What these numbers do NOT say

**They do not justify optimising any parse path.** Per
`docs/performance/2026-07-25-syslog-udp-cpu-profile.md`, the whole-process cost
is ~94.6 µs/datagram, of which syslog recv parse (~6.1 µs) and writer encode
(~7.07 µs) together account for ~13 µs. **~85% remains unattributed** —
syscalls, futex contention, tokio scheduling, parquet encode, logging. Adding
four more parse measurements does not change that. Do not open a parser
optimisation off this document without new end-to-end evidence.

**Do not ratio these against the 94.6 µs/datagram figure.** That number is
whole-process CPU across all threads; these are single-threaded, single-record
costs. Subtracting or dividing one by the other is precisely the error that
`docs/superpowers/specs/2026-07-25-cpu-profiling-instrumentation-design.md`
was written to correct.

**The "~500 µs-1.3 ms per record" figure is wrong and retracted.** It appears in
`docs/superpowers/specs/2026-07-24-performance-improvements-plan.md` §2.1 and
`docs/superpowers/specs/2026-07-24-record-batch-amortization-benchmark-results.md`,
and was retracted in
`docs/superpowers/specs/2026-07-25-cpu-profiling-instrumentation-design.md:46-62`.
The real range for `to_record_batch` is **4.13-17.57 µs** across all sinks, as
measured above.

Against *these* numbers the old figure is **28-315× too high** (500 µs ÷
17.57 µs ≈ 28×; 1.3 ms ÷ 4.13 µs ≈ 315×). The "40-100×" wording used in the
retraction doc was derived against that document's own narrower figure set and
does not follow from the range restated here — if you need a multiplier, use
the one derived from the numbers you are actually quoting. Never cite the old
figure itself.

### One thing that was checked and needed no change

The plan expected the pre-existing bench headers to carry stale column counts
after the v0.16.0 `partition_time` addition. They do not — `grep -n
"column\|field count\|5-column\|schema has" benches/*.rs` matches nothing in
any of the seven `*_to_record_batch.rs` files or `syslog_parse_recv_path.rs`.
Those headers never stated column counts, so there was nothing to correct. The
comparability caveat below is recorded here instead.

### Comparability caveat

v0.16.0 (2026-09-06, BREAKING) added a non-null `partition_time` column to all
nine sink schemas, and syslog additionally gained `received_at` — after every
pre-existing bench was written. **No encode figure here is comparable to one
taken before 2026-09-06.** The visible effect: zeek `conn` per-record encode was
recorded at 13.14 µs previously and measures 17.57 µs in this run through the
same bench. Some of that is the extra column, some is this VM. Both reasons are
why this doc leads with the hardware disclosure.

## 5. Reproducing

```bash
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo bench -- --save-baseline v0.18.0
```

Takes ~15 minutes for 13 targets. Results land in `target/criterion/`, which is
gitignored; CI now uploads them as an artifact (`.github/workflows/performance.yml`).

Note `[lib] bench = false` and `[[bin]] bench = false` in `Cargo.toml`: without
them `cargo bench` treats the lib and bin test harnesses as bench targets and
forwards criterion's flags to them, where `--save-baseline` is unrecognised and
aborts the whole run with exit 101.
