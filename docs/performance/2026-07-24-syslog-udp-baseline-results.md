# `syslog-udp` baseline: local-disk `LocalDiskSink`, 2026-07-24

**Git commit this baseline was captured against:** `6bc8aa987a827de2e8133e9ea3945e70341ea677`
(branch `perf/performance-testing-infrastructure`; working tree clean at the time of capture
apart from the throwaway repo-root config swaps described in Step 3 below, which were reverted
before this doc was committed).

**Config used:** [`tools/loadgen/ci/logthing-baseline.toml`](../../tools/loadgen/ci/logthing-baseline.toml)
(local disk, not MinIO — per
`docs/superpowers/specs/2026-07-05-performance-testing-strategy-design.md` §6, this isolates the
ingestion/buffering-path from S3/network/Docker variables).

## Scope deviation from the design doc's 4-point sweep

The design doc §9 recommends a 10k/50k/100k/unbounded sweep. This run captures the plan's
3-point reduced sweep (10k/50k/unbounded) only. A 100k point was *not* added: the unbounded run
(§"Results" below) already saturates the syslog UDP path far harder than 50k does (achieved
~71.7k sends/sec, and — see the kernel-drop analysis below — most of the marginal load past
~28k/sec receive-side is shed by the OS socket buffer, not absorbed by `logthing`), so a 100k
point sits between 50k and unbounded and is very unlikely to reveal a distinct regime. This is
flagged per the brief as an explicit, reasoned scope reduction, not a silent drop.

## Buffer-policy values in effect (restated per the "never compare across differing
flush-threshold configs" rule)

These come from `[syslog.local]`'s defaults (`SyslogLocalConfig` in `src/config/mod.rs`), none of
which are overridden in `logthing-baseline.toml`:

| Field | Value | Source |
|---|---|---|
| `max_buffer_rows` | `10_000` | `default_syslog_s3_max_rows()` — syslog's own default, **not** the generic `BufferedWriterConfig` default of `100_000` |
| `flush_interval_secs` | `900` | `default_syslog_s3_flush_interval_secs()` |
| `channel_capacity` | `4_096` | `default_syslog_s3_channel_capacity()` |
| `flush_threshold_bytes` | *(not applicable — see caveat)* | — |

**Caveat found while verifying the above against source, not just the brief's text:** the brief
asked to restate `flush_threshold_bytes=128 MiB` as "the generic default, no syslog-specific
override." That's true of `BufferedWriterConfig`'s generic default
(`default_flush_threshold_bytes()` = 128 MiB), but it does **not** actually apply to syslog's
local sink: `syslog_local_start()` in `src/forwarding/syslog_s3.rs` hardcodes the byte-threshold
parameter to `usize::MAX` when constructing the writer ("syslog uses row-count + age triggers
only" per its own comment). So for this baseline, there is effectively **no** byte-size flush
trigger at all — only `max_buffer_rows` and `flush_interval_secs` can force a flush. Restated
here for the record since it affects how future comparisons against this baseline should be
read.

## Commands run

### Step 2 — build

```bash
export CARGO_TARGET_DIR=/home/dev/projects/logthing/target CC=/usr/bin/gcc CXX=/usr/bin/g++
cargo build --profile profiling
cargo build -p loadgen --release
```
Both completed successfully:
```
Finished `profiling` profile [optimized + debuginfo] target(s) in 9.76s
Finished `release` profile [optimized] target(s) in 2.43s
```
(both builds attached to a partially-warm shared `target/` dir; most of the wall-clock cost was
one-time dependency compilation, not `logthing`/`loadgen` themselves.)

### Step 3 — start `logthing` against the baseline config

Two repo-root config files needed to be handled, not just `logthing.toml` as the brief
anticipated — **finding beyond the brief's literal Step 3**: `logthing.admin.toml` is also
git-tracked at the repo root and is loaded by `Config::load()` with *higher* precedence than
`logthing.toml` (`config::File::from(Path::new(ADMIN_OVERRIDE_FILE))` is added as a source after
the `logthing.toml` source). Its checked-in contents set `bind_address = "127.0.0.1:9999"`,
`syslog.udp_port = 514`, `syslog.tcp_port = 601`, and `syslog.parse_payloads = false` — left in
place, it would have silently overridden the baseline config's ports/bind address/payload-parsing
setting. Both files were backed up (with an `md5sum` check that the backup was byte-identical to
the original) and `logthing.admin.toml` was removed for the duration of the run, then both were
restored afterward from the backup:

```bash
mkdir -p /tmp/logthing-baseline-config-backup
cp logthing.toml /tmp/logthing-baseline-config-backup/logthing.toml.orig
cp logthing.admin.toml /tmp/logthing-baseline-config-backup/logthing.admin.toml.orig
md5sum logthing.toml logthing.admin.toml /tmp/logthing-baseline-config-backup/*.orig   # confirmed identical
rm -f logthing.admin.toml
cp tools/loadgen/ci/logthing-baseline.toml ./logthing.toml

rm -rf /tmp/logthing-perf-local && mkdir -p /tmp/logthing-perf-local
/home/dev/projects/logthing/target/profiling/logthing > /tmp/logthing-baseline-stdout.log 2>&1 &
echo $! > /tmp/logthing-baseline.pid
sleep 2
curl -sf http://127.0.0.1:9090/metrics > /dev/null && echo UP
```
(Note: the brief's literal `./target/profiling/logthing` doesn't resolve here because
`CARGO_TARGET_DIR` points outside the worktree — the absolute path
`/home/dev/projects/logthing/target/profiling/logthing` was used instead; same binary.)

Server came up cleanly, logging confirmation of every port from the baseline config:
```
Syslog UDP listener started on 0.0.0.0:15514
Syslog TCP listener started on 0.0.0.0:15601
Starting WEF server on http://0.0.0.0:5985
Metrics server started on http://0.0.0.0:9090
```
`curl http://127.0.0.1:9090/metrics` returned `200 OK` (empty body — no metrics recorded yet,
expected before any traffic).

### Step 4 — sweep

For each rate point: snapshot `/metrics`, run `loadgen syslog-udp` for 60s, sleep 3s (drain), snapshot
`/metrics` again, snapshot `ps`. Exact commands (rate/port args vary per point):

```bash
curl -s http://127.0.0.1:9090/metrics > /tmp/metrics-before-<point>.txt

/home/dev/projects/logthing/target/release/loadgen syslog-udp \
    --host 127.0.0.1 --port 15514 \
    --target-rate <10000|50000|0> --duration-secs 60

sleep 3
curl -s http://127.0.0.1:9090/metrics > /tmp/metrics-after-<point>.txt
ps -o pid,rss,pcpu,etime -p "$(cat /tmp/logthing-baseline.pid)" > /tmp/resource-usage-<point>.txt
```

All three ran against the **same** `logthing` process, back-to-back, in the order 10k → 50k →
unbounded (not three independent fresh-process runs — see Limitations below for what that means
for the `ps` numbers).

### Step 5 — stop and restore

```bash
kill "$(cat /tmp/logthing-baseline.pid)"
cp /tmp/logthing-baseline-config-backup/logthing.toml.orig ./logthing.toml
cp /tmp/logthing-baseline-config-backup/logthing.admin.toml.orig ./logthing.admin.toml
```
Confirmed: process gone (`ps -p <pid>` → no such process), no orphaned
`target/profiling/logthing` process left (`pgrep -fa` → empty), and `git diff`/`git status` on the
two restored repo-root config files came back clean (byte-identical to their pre-run committed
state).

## Results

### Raw counters (from `/metrics`, `curl`'d before/after each run; counter absent = 0)

| Metric | after 10k | after 50k | after unbounded |
|---|---|---|---|
| `syslog_messages_received` | 593,676 | 2,254,556 | 3,469,209 |
| `syslog_parse_errors` | *(absent = 0)* | *(absent = 0)* | *(absent = 0)* |
| `syslog_oversized_lines` | *(absent = 0)* | *(absent = 0)* | *(absent = 0)* |
| `parquet_s3_records_written{source="syslog",target="local"}` | 590,000 | 1,538,624 | 2,540,075 |
| `parquet_s3_dropped{source="syslog",target="local"}` | *(absent = 0)* | 551,177 | 716,985 |
| `parquet_s3_buffer_dropped{source="syslog",target="local"}`* | *(absent = 0)* | 136,592 | 208,924 |

\* not one of the brief's named metrics, included because it appeared unprompted and is
plausibly relevant to interpreting the drop numbers; not otherwise analyzed in depth here.

### Per-run deltas, achieved send rate, and resource usage

| | 10k target | 50k target | unbounded (rate=0) |
|---|---|---|---|
| **loadgen achieved rate** | 9,999.8 rec/s | 49,999.9 rec/s | 71,677.5 rec/s |
| **datagrams sent** | 599,990 | 2,999,997 | 4,300,653 |
| **Δ `syslog_messages_received`** | +593,676 | +1,660,880 | +1,214,653 |
| **Δ `syslog_parse_errors`** | +0 | +0 | +0 |
| **Δ `syslog_oversized_lines`** | +0 | +0 | +0 |
| **Δ `parquet_s3_records_written`** | +590,000 | +948,624 | +1,001,451 |
| **Δ `parquet_s3_dropped`** | +0 | +551,177 | +165,808 |
| **Δ `parquet_s3_buffer_dropped`** | +0 | +136,592 | +72,332 |
| **app-level receive rate** (Δreceived / 60s) | ~9,895/s (98.9% of sent) | ~27,681/s (55.4% of sent) | ~20,244/s (28.2% of sent) |
| **`ps` RSS** (cumulative, same process) | 454,668 KB (~444 MiB) | 2,464,792 KB (~2.35 GiB) | 2,863,228 KB (~2.73 GiB) |
| **`ps` %CPU** (lifetime average, see caveat) | 61.8% | 118% | 109% |
| **`ps` ELAPSED** (since process start) | 01:43 | 03:14 | 05:20 |

## Honest read

**`syslog_parse_errors` and `syslog_oversized_lines` stayed at 0 across all three runs and all
~7.3M datagrams sent in total.** This is a clean, unambiguous result — every accepted datagram
was well-formed RFC3164 as `logthing`'s parser sees it, corroborating Task 9's unit test
(`raw_message_parses_as_rfc3164`) at real ingestion scale, not just in isolation.

**`parquet_s3_dropped` stays at exactly 0 at 10k/sec and jumps to hundreds of thousands at
50k/sec and beyond.** This is a real, clear regime change, not noise — 0 vs. 551,177 is not the
kind of gap that could be sampling jitter. It's consistent with the brief's hypothesis that
10k/sec sits below the `channel_capacity=4_096` bounded channel's absorption point (the writer
task drains faster than 4,096 messages ever accumulate) while 50k/sec does not.

**The gap between what `loadgen` sent and what `logthing` counted as `syslog_messages_received`
is real, large, and — this is the important finding beyond what the brief anticipated — almost
entirely explained by OS-level UDP receive-buffer drops, not by anything in `logthing`'s own
code path.** Evidence:
- `/proc/net/snmp`'s `Udp: RcvbufErrors` (system-wide, cumulative since boot) rose by exactly
  3,086,000 during the unbounded run — which is *exactly* the gap between datagrams sent
  (4,300,653) and `syslog_messages_received`'s delta (1,214,653) for that run
  (4,300,653 − 1,214,653 = 3,086,000).
- For the 10k and 50k runs I only captured a cumulative `RcvbufErrors` reading after both had
  run (1,345,431), not a clean per-run snapshot (methodology gap — see Limitations). But the
  arithmetic is still telling: the 10k run's sent-vs-received gap (599,990 − 593,676 = 6,314) plus
  the 50k run's sent-vs-received gap (2,999,997 − 1,660,880 = 1,339,117) sum to 1,345,431 — an
  exact match to the one cumulative reading I do have. That's consistent with essentially all of
  the loss at both rates being kernel-level, not app-level, though I did not independently confirm
  it per-run for 10k/50k the way I did for unbounded.
- This host's `net.core.rmem_max` / `net.core.rmem_default` are both `212992` bytes (~208 KiB) —
  the Linux stock default, not a value tuned for this test. `logthing`'s syslog UDP listener
  (`src/syslog/listener.rs`) binds with `UdpSocket::bind` and does not set `SO_RCVBUF` explicitly,
  so it inherits this default.

  **What this means for reading this baseline:** the throughput ceiling visible in these numbers
  is *this environment's default UDP socket buffer size*, not necessarily `logthing`'s own
  ingestion+parsing+buffering-path ceiling. A host with a larger `rmem_max` (or a version of
  `logthing` that explicitly sizes the socket buffer) could plausibly show a different — and
  possibly much less severe — receive-side ceiling at the same send rates. Anyone using this doc
  as a comparison baseline (e.g. Task 12's CI job) should check whether the CI runner has the same
  default before assuming a like-for-like comparison.

**Counterintuitive but real: the unbounded run delivered *less* absolute throughput to
`logthing` than the paced 50k run did** (~20,244 msgs/sec received vs. ~27,681 msgs/sec received),
despite `loadgen` itself sending faster unbounded (71,677.5/s vs 49,999.9/s). This isn't noise —
it's the direct consequence of the point above: flooding harder past the point the kernel socket
buffer can absorb doesn't get more data *to* `logthing`, it just means a larger fraction gets
shed by the OS before `logthing` ever sees it (71.9% of unbounded sends were never received vs.
44.6% of 50k sends). The "unbounded" data point in this sweep is therefore better read as
"characterizes what happens when the OS socket buffer is overwhelmed on this host" rather than
"characterizes `logthing`'s peak sustainable ingestion rate" — those turn out to be different
questions here, and conflating them would overstate what this run shows.

**One reconciliation gap I want to flag rather than paper over:** per-run, `Δrecords_written +
Δdropped` doesn't fully add up to `Δreceived` (e.g. 50k: 948,624 + 551,177 = 1,499,801 vs.
1,660,880 received — a 9.7% shortfall; unbounded: 1,001,451 + 165,808 = 1,167,259 vs. 1,214,653
received — a 3.9% shortfall). The most plausible explanation is records sitting in the writer's
own unflushed row buffer at the moment of the post-run snapshot (a partial buffer under
`max_buffer_rows=10,000` waiting on the next flush trigger, which given
`flush_interval_secs=900` won't fire on its own for a long time) — but I have not verified this
against the source beyond it being consistent with the buffering design, and a longer post-run
drain than the 3s used here might resolve more of it. I'm calling this a real but small
unaccounted remainder rather than asserting a specific cause.

## Limitations / methodology caveats

- **Sequential, not independent, runs.** All three rate points ran against the same `logthing`
  process, back-to-back, rather than a fresh process per point. The `ps` RSS/CPU/ELAPSED columns
  above are therefore cumulative process state at each point in time, not isolated per-run
  measurements — e.g. the 50k row's RSS includes memory retained from the 10k run. `%CPU` from
  `ps` is a lifetime average (CPU-seconds ÷ wall-clock-seconds since process start), not an
  instantaneous per-run rate; it should be read as directional (visibly higher during the
  50k/unbounded segments than the 10k segment) rather than as a precise per-run figure.
- **No pre-10k `/proc/net/snmp` baseline captured.** I captured `Udp: RcvbufErrors` only after
  the 50k run (as an ad-hoc investigation once the receive gap looked large) and again after the
  unbounded run — not before the 10k run started. The unbounded-run attribution above is exact
  (I have clean before/after for that one); the 10k/50k attribution is inferred from arithmetic
  consistency, not independently measured per-run.
- **3-second drain may be short for the loaded runs.** The reconciliation gap noted above suggests
  some records were still in-flight in the writer's buffer at snapshot time, especially for the
  50k run.
- **This is one machine, one run per rate point, no repeats.** No error bars, no statistical
  treatment — single-sample numbers. Where the signal is a 0-vs-hundreds-of-thousands jump
  (drops) or an exact arithmetic match (kernel-drop accounting), I'm treating that as real. Where
  numbers are within the same order of magnitude and could plausibly shift run-to-run (e.g. the
  precise reconciliation-gap percentages), I'm not treating small differences as meaningful.

## Files produced by this run (not committed — local artifacts only)

`/tmp/metrics-before-10k.txt`, `/tmp/metrics-after-10k.txt`, `/tmp/metrics-before-50k.txt`,
`/tmp/metrics-after-50k.txt`, `/tmp/metrics-before-unbounded.txt`,
`/tmp/metrics-after-unbounded.txt`, `/tmp/resource-usage-10k.txt`, `/tmp/resource-usage-50k.txt`,
`/tmp/resource-usage-unbounded.txt`, `/tmp/udp-snmp-before-unbounded.txt`,
`/tmp/udp-snmp-after-unbounded.txt`.
