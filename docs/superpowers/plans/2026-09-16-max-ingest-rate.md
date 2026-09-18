# Max Ingest Rate Per Format — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a defensible maximum sustainable ingest rate for each of logthing's seven wire formats, with every run's loss attributed to a named site and with generator-limited runs refused rather than reported as ceilings.

**Architecture:** Measure before optimising. Phase 0 establishes each generator's own ceiling with no new generator code (N concurrent processes, plus an unbound-port target for UDP). Phase 1 raises the generator only where Phase 0 proves it binds. Phase 2 replaces `scripts/repeat-ipfix-loopback-loss.sh` with a per-format ramp harness that inherits its validated loss machinery and adds CPU pinning, a drain-to-stable scrape, and a generator-saturation guard. Phase 3 runs the ramps and writes the results.

**Tech Stack:** Bash (harness, `taskset`, `/proc/net/snmp`, `/proc/<pid>/stat`, Prometheus text scrape via `curl`/`wget`), Rust 2024 (`tools/loadgen`, `clap`, `tokio`), `cargo test -p loadgen`.

**Spec:** `docs/superpowers/specs/2026-09-16-max-ingest-rate-design.md`

## Global Constraints

- Branch: `perf/max-ingest-rate`. Never commit to `master`.
- Build env for every `cargo` invocation in this repo:
  `export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc`
  Dropping the linker var silently links LLVM libunwind and the build breaks.
- Binaries under test are always release builds: `cargo build --release --bin logthing` and `cargo build --release -p loadgen`.
- **Never use `pkill -f` with the server binary path.** It matches whole command lines and kills the invoking shell (symptom: bare exit 144, no output). Use a pidfile.
- **Never `rm` `logthing.toml` or `logthing.admin.toml`.** Both are tracked. Back up, overwrite, restore from backup.
- Host is a 12-vCPU KVM guest with no `cpufreq`. Generator cores: `0-3`. Server cores: `4-11`. Every results table carries the host caveat verbatim from `docs/performance/2026-09-14-throughput-baseline-repeats.md`.
- Loss is always reported **per drop site** (kernel / writer-channel / buffer hard cap) in addition to any total. Never sum sites into a single headline number without also showing the breakdown.
- The seven formats and their fixed parameters:

  | FORMAT | subcommand | port | sink `source` label | kernel loss counter |
  |---|---|---|---|---|
  | `syslog` | `syslog-udp` | 514 | `syslog` | `syslog_socket_drops` |
  | `ipfix` | `ipfix-udp` | 4739 | `ipfix` | `ipfix_socket_drops` |
  | `sflow` | `sflow-udp` | 6343 | `sflow` | `sflow_socket_drops` |
  | `zeek` | `zeek-tcp` | 47760 | `zeek` | n/a (TCP) |
  | `suricata` | `suricata-tcp` | 47761 | `suricata` | n/a (TCP) |
  | `hec` | `hec-http` | 5985 | `hec` | n/a |
  | `generic` | `generic-http` | 5985 | `hec` | n/a |

- Received counters: `syslog_messages_received`, `ipfix_datagrams_received`, `sflow_datagrams_received`, `zeek_records_received`, `suricata_records_received`, `hec_events_received` (shared by `hec` **and** `generic`).
- `hec` and `generic` are indistinguishable in metrics (`src/ingest/handlers.rs:219`, `src/forwarding/generic_s3.rs:163`). The harness must run exactly one format at a time; results must name which generator produced each `hec`-labelled row.
- Every `loadgen` subcommand's final line matches
  `loadgen <sub>: sent <N> (flows|datagrams|records) in <S>s (achieved rate: <R> ...)`.
  One regex pair parses offered and achieved for all seven.

---

## File Structure

**Created:**

- `scripts/loadgen-ceiling.sh` — Phase 0 probe. Runs N concurrent `loadgen`
  processes for one format and reports per-process and aggregate achieved
  rate. Optional unbound-port target for UDP formats. Self-tests its own
  parsing/aggregation under `SELFTEST=1`.
- `scripts/max-ingest-rate.sh` — Phase 2 harness. Per-format config
  templating, server lifecycle via pidfile, CPU pinning, drain-to-stable
  scrape, per-site loss accounting, median/min/max over N runs, ramp+bisect,
  and the pass/fail verdict. Self-tests its pure logic under `SELFTEST=1`.
- `tests/harness_smoke.rs` — integration test driving `max-ingest-rate.sh`
  once at a low rate against a real server.
- `docs/performance/2026-09-16-generator-ceiling.md` — Phase 0 results.
- `docs/performance/2026-09-16-max-ingest-rate.md` — Phase 3 results.

**Modified:**

- `tools/loadgen/src/{syslog_udp,ipfix_udp,sflow_udp,zeek_tcp,suricata_tcp}.rs`
  — pre-rendered payload ring (Task 3), `--workers` (Task 5).
- `tools/loadgen/src/{hec_http,generic_http}.rs` — `--events-per-request`
  (Task 4), `--workers` (Task 5).

**Deleted:**

- `scripts/repeat-ipfix-loopback-loss.sh` — superseded by
  `max-ingest-rate.sh` in fixed-rate mode. Its `pkill -f "$BIN"` startup and
  EXIT trap, and its `rm -f logthing.admin.toml`, are the two defects the
  replacement exists to not inherit. `docs/performance/2026-09-14-throughput-baseline-repeats.md`
  gets a pointer to the equivalent new invocation so its numbers stay
  reproducible.

**Not created:** no shared shell library. Two scripts with a little duplicated
metric-scraping is smaller than two scripts plus a library, and the duplication
is ~15 lines.

---

## Task 1: Phase 0 probe script

**Files:**
- Create: `scripts/loadgen-ceiling.sh`
- Test: `SELFTEST=1 ./scripts/loadgen-ceiling.sh`

**Interfaces:**
- Consumes: nothing.
- Produces: `parse_sent()`, `parse_achieved()`, `sum_field()` shell functions,
  exercised by `SELFTEST=1`. Stdout is a TSV table with columns
  `procs`, `per_proc_rate`, `aggregate_rate`, `total_sent`.

- [ ] **Step 1: Write the failing self-test**

Create `scripts/loadgen-ceiling.sh` containing only the self-test block and
stubs, so the test runs and fails:

```bash
#!/bin/bash
# Phase 0 generator-ceiling probe. See
# docs/superpowers/specs/2026-09-16-max-ingest-rate-design.md §4.
set -u

parse_sent() { :; }
parse_achieved() { :; }
sum_field() { :; }

if [ "${SELFTEST:-0}" = "1" ]; then
    fail=0
    check() {
        if [ "$2" != "$3" ]; then
            echo "FAIL: $1: expected '$3', got '$2'"
            fail=1
        else
            echo "ok: $1"
        fi
    }

    IPFIX_OUT='loadgen ipfix-udp: sending to 127.0.0.1:4739 at target_rate=0 flows/s for 10s (template_interval=60s)
loadgen ipfix-udp: sent 291180 flows in 10.000s (achieved rate: 29118.0 flows/s)'
    ZEEK_OUT='loadgen zeek-tcp: sent 127960 records in 10.000s (achieved rate: 12796.0 rec/s)'
    SFLOW_OUT='loadgen sflow-udp: sent 90000 datagrams in 10.000s (achieved rate: 9000.0 rec/s); 0 send errors'

    check "parse_sent ipfix"   "$(parse_sent "$IPFIX_OUT")"   "291180"
    check "parse_sent zeek"    "$(parse_sent "$ZEEK_OUT")"    "127960"
    check "parse_sent sflow"   "$(parse_sent "$SFLOW_OUT")"   "90000"
    check "parse_achieved ipfix" "$(parse_achieved "$IPFIX_OUT")" "29118.0"
    check "parse_achieved zeek"  "$(parse_achieved "$ZEEK_OUT")"  "12796.0"
    check "parse_achieved sflow" "$(parse_achieved "$SFLOW_OUT")" "9000.0"
    check "sum_field three rates" "$(printf '%s\n' 100.5 200.25 9.25 | sum_field)" "310.00"
    check "sum_field empty"       "$(printf '' | sum_field)" "0.00"

    [ "$fail" -eq 0 ] && echo "SELFTEST PASS" || echo "SELFTEST FAIL"
    exit "$fail"
fi
```

- [ ] **Step 2: Run the self-test to verify it fails**

```bash
chmod +x scripts/loadgen-ceiling.sh
SELFTEST=1 ./scripts/loadgen-ceiling.sh
```

Expected: `SELFTEST FAIL`, with every `check` line reporting `expected 'X', got ''`.

- [ ] **Step 3: Implement the three parsers**

Replace the three stubs:

```bash
# Every loadgen subcommand ends with the same sentence shape:
#   "loadgen <sub>: sent <N> (flows|datagrams|records) in <S>s (achieved rate: <R> ...)"
# One pair of expressions therefore covers all seven formats. `tail -1` guards
# against a subcommand that prints the phrase more than once (hec-http and
# generic-http print "sent N before aborting" on an auth failure).
parse_sent() {
    printf '%s\n' "$1" | sed -n 's/.*sent \([0-9]\{1,\}\) \(flows\|datagrams\|records\) in .*/\1/p' | tail -1
}

parse_achieved() {
    printf '%s\n' "$1" | sed -n 's/.*achieved rate: \([0-9.]\{1,\}\).*/\1/p' | tail -1
}

# Sums a newline-separated list of decimals on stdin. Prints 0.00 for empty
# input rather than an empty string, so callers can always do arithmetic.
sum_field() {
    awk '{ s += $1 } END { printf "%.2f\n", s }'
}
```

- [ ] **Step 4: Run the self-test to verify it passes**

```bash
SELFTEST=1 ./scripts/loadgen-ceiling.sh
```

Expected: eight `ok:` lines and `SELFTEST PASS`, exit 0.

- [ ] **Step 5: Implement the probe body**

Insert above the `SELFTEST` block (so the self-test still short-circuits
before any of this runs):

```bash
REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOADGEN="$REPO/target/release/loadgen"
FORMAT="${FORMAT:-ipfix}"
PROCS="${PROCS:-1 2 4}"
DURATION="${DURATION:-10}"
# BLACKHOLE=1 targets a port this script binds itself and never reads. The
# kernel enqueues, the buffer fills, and it discards -- so the send syscall
# costs what it normally costs and no userspace receiver can be the
# bottleneck. The port must be BOUND: loadgen connect()s its UDP socket, so an
# unbound port returns ICMP port-unreachable as ECONNREFUSED and the generator
# aborts. UDP only: a TCP or HTTP generator needs a real peer.
BLACKHOLE="${BLACKHOLE:-0}"
BLACKHOLE_PORT="${BLACKHOLE_PORT:-39999}"
GEN_CPUS="${GEN_CPUS:-0-3}"

case "$FORMAT" in
    syslog)   SUB="syslog-udp";   PORT=514;   TRANSPORT=udp ;;
    ipfix)    SUB="ipfix-udp";    PORT=4739;  TRANSPORT=udp ;;
    sflow)    SUB="sflow-udp";    PORT=6343;  TRANSPORT=udp ;;
    zeek)     SUB="zeek-tcp";     PORT=47760; TRANSPORT=tcp ;;
    suricata) SUB="suricata-tcp"; PORT=47761; TRANSPORT=tcp ;;
    hec)      SUB="hec-http";     PORT=5985;  TRANSPORT=http ;;
    generic)  SUB="generic-http"; PORT=5985;  TRANSPORT=http ;;
    *) echo "FATAL: unknown FORMAT '$FORMAT'"; exit 1 ;;
esac

if [ "$BLACKHOLE" = "1" ]; then
    if [ "$TRANSPORT" != "udp" ]; then
        echo "FATAL: BLACKHOLE=1 needs a connectionless transport; $FORMAT is $TRANSPORT."
        echo "For $TRANSPORT, run against a real server in 'trivial' shape instead"
        echo "(scripts/max-ingest-rate.sh SHAPE=trivial) and label the number as such."
        exit 1
    fi
    # $4 is LocalAddress:Port in `ss -lun` data rows; $5 is the PEER address.
    if ss -lun 2>/dev/null | awk '{print $4}' | grep -q ":$BLACKHOLE_PORT\$"; then
        echo "FATAL: something is bound to UDP $BLACKHOLE_PORT; this probe must bind it itself."
        exit 1
    fi
    PORT="$BLACKHOLE_PORT"
fi

[ -x "$LOADGEN" ] || { echo "FATAL: $LOADGEN not found. cargo build --release -p loadgen"; exit 1; }

TMP="$(mktemp -d)" || exit 1
trap 'rm -rf "$TMP"' EXIT

echo "# format=$FORMAT sub=$SUB port=$PORT transport=$TRANSPORT blackhole=$BLACKHOLE duration=${DURATION}s gen_cpus=$GEN_CPUS"
printf 'procs\tper_proc_rates\taggregate_rate\ttotal_sent\n'

for n in $PROCS; do
    for i in $(seq 1 "$n"); do
        # --target-rate 0 is "unbounded" in every subcommand: send as fast as
        # the loop will go. That is the number we are after.
        taskset -c "$GEN_CPUS" "$LOADGEN" "$SUB" \
            --host 127.0.0.1 --port "$PORT" \
            --target-rate 0 --duration-secs "$DURATION" \
            > "$TMP/p$i.out" 2>&1 &
    done
    wait

    RATES=""
    SENTS=""
    for i in $(seq 1 "$n"); do
        OUT="$(cat "$TMP/p$i.out")"
        R="$(parse_achieved "$OUT")"
        S="$(parse_sent "$OUT")"
        if [ -z "$R" ] || [ -z "$S" ]; then
            echo "FATAL: process $i of $n produced no parseable result:"
            cat "$TMP/p$i.out"
            exit 1
        fi
        RATES="$RATES$R"$'\n'
        SENTS="$SENTS$S"$'\n'
    done

    AGG="$(printf '%s' "$RATES" | grep -v '^$' | sum_field)"
    TOT="$(printf '%s' "$SENTS" | grep -v '^$' | sum_field)"
    PER="$(printf '%s' "$RATES" | grep -v '^$' | tr '\n' ',' | sed 's/,$//')"
    printf '%s\t%s\t%s\t%s\n' "$n" "$PER" "$AGG" "$TOT"
done

echo "# Read this as: if aggregate_rate scales ~linearly with procs, the"
echo "# per-process ceiling is not fundamental -- run more processes rather"
echo "# than optimising the generator. If it flattens, the limit is downstream."
```

- [ ] **Step 6: Verify the probe runs end to end**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo build --release -p loadgen
FORMAT=ipfix BLACKHOLE=1 PROCS="1 2" DURATION=3 ./scripts/loadgen-ceiling.sh
```

Expected: a two-row TSV table with non-zero `aggregate_rate` in both rows and
no `FATAL`. Then confirm the guard fires:

```bash
FORMAT=zeek BLACKHOLE=1 DURATION=3 ./scripts/loadgen-ceiling.sh; echo "exit=$?"
```

Expected: the `BLACKHOLE=1 needs a connectionless transport` message, `exit=1`.

- [ ] **Step 7: Commit**

```bash
git add scripts/loadgen-ceiling.sh
git commit -m "perf: add Phase 0 generator-ceiling probe

Measures what tools/loadgen can emit, independent of any receiver: N
concurrent processes at unbounded rate, optionally aimed at an unbound UDP
port so the kernel discards and nothing downstream can bind first.

Until now 'the generator is the bottleneck' was an inference, and for TCP a
wrong one -- achieved-below-target is equally consistent with server
backpressure."
```

---

## Task 2: Run Phase 0 and publish the gate

**Files:**
- Create: `docs/performance/2026-09-16-generator-ceiling.md`

**Interfaces:**
- Consumes: `scripts/loadgen-ceiling.sh` from Task 1.
- Produces: the **Phase 1 gate** — a per-format `needs generator work: yes/no`
  column that Tasks 3, 4 and 5 read to decide whether they run at all.

- [ ] **Step 1: Build both release binaries**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo build --release --bin logthing && cargo build --release -p loadgen
```

- [ ] **Step 2: Run the blackhole probe for the three UDP formats**

```bash
for f in syslog ipfix sflow; do
  echo "=== $f ==="
  FORMAT=$f BLACKHOLE=1 PROCS="1 2 4" DURATION=15 ./scripts/loadgen-ceiling.sh
done
```

Record every row. The probe binds UDP 39999 itself and frees it on exit; its
guard aborts if something else already holds it. If a previous run leaked a
listener, free the port before starting — never with `pkill`.

- [ ] **Step 3: Run the multi-process probe for the four peer-requiring formats**

These need a listener, so start the server in `trivial` shape first (no sink
configured, so `Default*Handler` runs and the writer path is out of the
picture):

```bash
cp logthing.toml /tmp/logthing.toml.bak
cat > logthing.toml <<'CONF'
bind_address = "0.0.0.0:5985"
[tls]
enabled = false
[metrics]
enabled = true
port = 9090
[logging]
level = "error"
format = "pretty"
[syslog]
enabled = false
[zeek]
enabled = true
tcp_port = 47760
bind_address = "0.0.0.0"
[suricata]
enabled = true
tcp_port = 47761
bind_address = "0.0.0.0"
[hec]
enabled = true
token = ""
CONF
taskset -c 4-11 ./target/release/logthing > /tmp/ceiling-server.log 2>&1 &
echo $! > /tmp/ceiling-server.pid
sleep 3

for f in zeek suricata hec generic; do
  echo "=== $f ==="
  FORMAT=$f PROCS="1 2 4" DURATION=15 ./scripts/loadgen-ceiling.sh
done

kill "$(cat /tmp/ceiling-server.pid)"; sleep 1
kill -9 "$(cat /tmp/ceiling-server.pid)" 2>/dev/null
cp /tmp/logthing.toml.bak logthing.toml
```

Do **not** use `pkill`. Confirm afterwards that `git status` shows
`logthing.toml` unmodified.

- [ ] **Step 4: Write the results document**

Create `docs/performance/2026-09-16-generator-ceiling.md` with:

- the host caveat block copied verbatim from
  `docs/performance/2026-09-14-throughput-baseline-repeats.md`;
- provenance (crate version, commit, date, command lines);
- one table per format: `procs`, `per-process rate`, `aggregate rate`;
- for the four peer-requiring formats, an explicit note that the number is a
  *trivial-shape* figure, not a receiver-free one — the server still does
  socket and parse work, so it is an upper bound on the generator that may be
  depressed by the server;
- **the gate table**, one row per format:

  | format | generator ceiling (1 proc) | aggregate at 4 procs | scales? | highest achieved rate seen against a real sink | needs generator work? |

  `needs generator work? = yes` only when the 1-process ceiling is within
  ~20% of the best rate ever achieved against a real sink **and** the
  aggregate does not scale with process count. If it scales, the answer is
  "no — run N processes", and Tasks 3–5 are skipped for that format.
- an explicit statement of what this run overturns or confirms about
  `docs/performance/2026-09-13-multiformat-load-results.md` §2's claim that
  the generator limits Zeek above ~15k/s.

- [ ] **Step 5: Commit**

```bash
git add docs/performance/2026-09-16-generator-ceiling.md
git commit -m "perf: Phase 0 generator-ceiling results

First measurement of what tools/loadgen can emit independent of a receiver.
Gates whether any generator optimisation is worth doing, per format."
```

---

## Task 3: Pre-rendered payload ring

**Run this task only for formats the Task 2 gate marks `needs generator work: yes`.**
If the gate says no for all five socket formats, skip to Task 6 and record the
skip in the commit history.

**Files:**
- Modify: `tools/loadgen/src/zeek_tcp.rs`, `tools/loadgen/src/suricata_tcp.rs`,
  `tools/loadgen/src/syslog_udp.rs`, `tools/loadgen/src/ipfix_udp.rs`,
  `tools/loadgen/src/sflow_udp.rs`
- Test: the existing `#[cfg(test)] mod tests` in each of those files

**Interfaces:**
- Consumes: each file's existing `build_record(n, ...) -> String` /
  `build_data_datagram(seq, n) -> Vec<u8>` / `build_datagram(seq, n) -> Vec<u8>`.
  These stay, unchanged — the ring is built *from* them.
- Produces: `const RING_SIZE: u64 = 1024;` and `fn build_ring(...) -> Vec<Vec<u8>>`
  in each module, plus `fn patch_seq(buf: &mut [u8], seq: u32)` in the two
  binary-format modules. Nothing outside these modules consumes them.

- [ ] **Step 1: Write the failing tests (zeek, as the NDJSON exemplar)**

Add to `tools/loadgen/src/zeek_tcp.rs`'s test module:

```rust
/// The ring must not degenerate into one repeated row: the server has to see
/// varying values or the measurement is of a pathologically compressible
/// workload rather than a realistic one.
#[test]
fn ring_entries_are_distinct_and_newline_terminated() {
    let ring = build_ring("conn");
    assert_eq!(ring.len() as u64, RING_SIZE);
    for entry in &ring {
        assert_eq!(*entry.last().unwrap(), b'\n', "every ring entry must be newline-terminated");
    }
    let distinct: std::collections::HashSet<&Vec<u8>> = ring.iter().collect();
    assert_eq!(distinct.len(), ring.len(), "every ring entry must be distinct");
}

/// Same guarantee the pre-ring generator had: bytes off the ring parse with
/// logthing's own parser, so a wire-format drift breaks the test rather than
/// silently producing a run that measures parse failures.
#[test]
fn ring_entries_parse_with_logthings_own_parser() {
    let ring = build_ring("conn");
    for entry in [&ring[0], &ring[RING_SIZE as usize / 2], &ring[RING_SIZE as usize - 1]] {
        let line = std::str::from_utf8(entry).unwrap().trim_end_matches('\n');
        let parsed = logthing::zeek::parse_line(line, chrono::Utc::now())
            .expect("ring entry must parse with logthing's own parser");
        assert_eq!(parsed.record.log_path, "conn");
    }
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test -p loadgen zeek_tcp::tests::ring -- --nocapture
```

Expected: FAIL — `cannot find function 'build_ring'` / `cannot find value 'RING_SIZE'`.

- [ ] **Step 3: Implement the ring in `zeek_tcp.rs`**

```rust
/// Number of distinct pre-rendered payloads held in memory and cycled
/// through. Building each record on the hot path (`chrono::Utc::now()` +
/// `json!` + `format!` + `to_string()`) is the generator's dominant
/// per-record cost; rendering K once at startup removes it entirely.
///
/// ponytail: K=1024 is a fixed constant, not a flag. It is large enough that
/// the sink sees varying `uid`/`id.orig_p`/byte-count values rather than one
/// repeated row, and small enough (~250 KiB) to stay in cache. Make it a flag
/// only if a measurement shows the cycle length mattering.
const RING_SIZE: u64 = 1024;

/// Pre-render `RING_SIZE` newline-terminated records. Every entry carries the
/// `ts` it was built with, so a long run replays K startup timestamps rather
/// than advancing time. That is deliberate: partitioning is by day, runs last
/// seconds, and per-record `Utc::now()` is part of what this removes.
fn build_ring(log_path: &str) -> Vec<Vec<u8>> {
    (0..RING_SIZE)
        .map(|n| {
            let mut line = build_record(n, log_path).into_bytes();
            line.push(b'\n');
            line
        })
        .collect()
}
```

Then replace the `write_record` call sites. `run()` builds the ring once
before the send loops:

```rust
    let ring = build_ring(&args.log_path);
```

and `write_record` becomes a slice write:

```rust
async fn write_record(
    writer: &mut BufWriter<TcpStream>,
    ring: &[Vec<u8>],
    n: u64,
) -> anyhow::Result<()> {
    writer
        .write_all(&ring[(n % RING_SIZE) as usize])
        .await
        .context("write zeek record")?;
    Ok(())
}
```

Call sites change from `write_record(&mut writer, sent, &args.log_path).await?`
to `write_record(&mut writer, &ring, sent).await?`. Note this also halves the
number of `write_all` calls per record — the newline is now part of the entry.

- [ ] **Step 4: Run to verify they pass**

```bash
cargo test -p loadgen zeek_tcp -- --nocapture
```

Expected: PASS, including the three pre-existing tests
(`conn_record_parses_with_logthings_own_parser`,
`distinct_sequence_numbers_yield_distinct_uids`,
`unmodelled_stream_still_parses_with_its_own_log_path`), which must not have
been modified.

- [ ] **Step 5: Repeat for `suricata_tcp.rs` and `syslog_udp.rs`**

Same shape. `syslog_udp.rs` sends one datagram per record, so its ring entries
are **not** newline-terminated — drop that assertion and keep the distinctness
and parses-with-logthing's-own-parser ones, using
`logthing::syslog::SyslogMessage::parse` in place of `zeek::parse_line`.
`suricata_tcp.rs` keeps the newline, using `logthing::suricata::parse_line`.
Check each module's existing test imports for the exact parser path rather
than assuming.

- [ ] **Step 6: Write the failing tests for the binary formats**

IPFIX and sFlow carry an exporter sequence number that must keep advancing
across the whole run, so their ring entries are patched in place before each
send. Add to `tools/loadgen/src/ipfix_udp.rs`'s test module:

```rust
/// The sequence number lives at bytes 8..12 of the IPFIX v10 message header
/// (version 2 + length 2 + exportTime 4). If `build_data_datagram`'s header
/// layout ever changes, this test fails rather than the harness silently
/// replaying one sequence number for a whole run.
#[test]
fn patch_seq_sets_the_header_sequence_number() {
    let mut buf = build_data_datagram(1, 0);
    patch_seq(&mut buf, 0xDEAD_BEEF);
    assert_eq!(&buf[8..12], &0xDEAD_BEEFu32.to_be_bytes());
}

/// A patched ring entry must still decode through logthing's own decoder --
/// patching the wrong offset would corrupt the datagram, and a corrupt
/// datagram looks exactly like kernel loss in the totals.
#[test]
fn patched_ring_entry_still_decodes() {
    let mut dec = IpfixDecoder::new();
    decode_datagram(&mut dec, &build_template_datagram(1), exporter()).expect("template");
    let ring = build_ring();
    let mut buf = ring[7].clone();
    patch_seq(&mut buf, 12_345);
    let flows = decode_datagram(&mut dec, &buf, exporter()).expect("patched data datagram");
    assert_eq!(flows.len(), 1);
}
```

- [ ] **Step 7: Run to verify they fail**

```bash
cargo test -p loadgen ipfix_udp::tests::patch -- --nocapture
cargo test -p loadgen ipfix_udp::tests::patched -- --nocapture
```

Expected: FAIL — `cannot find function 'patch_seq'` / `build_ring`.

- [ ] **Step 8: Implement ring + seq patching for `ipfix_udp.rs`**

```rust
const RING_SIZE: u64 = 1024;

/// Byte offset of the sequence number in the IPFIX v10 message header:
/// version (2) + length (2) + exportTime (4). Asserted by
/// `patch_seq_sets_the_header_sequence_number`.
const SEQ_OFFSET: usize = 8;

fn build_ring() -> Vec<Vec<u8>> {
    // seq is patched per send, so the value baked in here is irrelevant.
    (0..RING_SIZE).map(|n| build_data_datagram(0, n)).collect()
}

fn patch_seq(buf: &mut [u8], seq: u32) {
    buf[SEQ_OFFSET..SEQ_OFFSET + 4].copy_from_slice(&seq.to_be_bytes());
}
```

In `run()`, build the ring once and keep one scratch buffer that is refilled
from the ring per send, so the ring itself stays immutable:

```rust
    let ring = build_ring();
    let mut scratch: Vec<u8> = ring[0].clone();
```

and each send site becomes:

```rust
    scratch.clear();
    scratch.extend_from_slice(&ring[(sent % RING_SIZE) as usize]);
    patch_seq(&mut scratch, seq);
    socket.send(&scratch).await.context("send ipfix data datagram")?;
```

Leave the template-datagram path alone: it fires once per
`--template-interval-secs`, never on the hot path.

- [ ] **Step 9: Implement the same for `sflow_udp.rs`**

sFlow v5's header is version (4) + agent_addr_type (4) + agent_addr (4) +
sub_agent_id (4), so `SEQ_OFFSET = 16`. Note in a comment that
`build_datagram` also writes `seq` into `uptime_ms` at offset 20 and into each
sample's own `sequence_number`; only the datagram-header field is patched, and
the others become fixed per ring slot. That is harmless — logthing's decoder
reads the header sequence number — but it must be stated, not discovered.
Mirror both tests, using `logthing::sflow::decoder::decode_datagram`.

- [ ] **Step 10: Run the whole loadgen suite**

```bash
cargo test -p loadgen
```

Expected: PASS, no test removed or weakened.

- [ ] **Step 11: Re-run the Phase 0 probe and confirm the ceiling moved**

```bash
cargo build --release -p loadgen
for f in ipfix sflow syslog; do
  echo "=== $f ==="; FORMAT=$f BLACKHOLE=1 PROCS="1" DURATION=15 ./scripts/loadgen-ceiling.sh
done
```

Expected: the 1-process aggregate rate is higher than Task 2 recorded for the
same format. **If it is not, stop and say so** — the ring was not the
bottleneck, and Tasks 4 and 5 should be re-justified against that evidence
rather than run on momentum.

- [ ] **Step 12: Commit**

```bash
git add tools/loadgen/src
git commit -m "perf(loadgen): pre-render payloads instead of building per record

Every subcommand built each payload on the hot path (Utc::now + json! +
format! + to_string, or build_datagram). Render 1024 once at startup and
cycle; IPFIX and sFlow patch the header sequence number per send so the
exporter sequence still advances.

Ring entries are asserted distinct and still round-trip through logthing's
own parsers, so this cannot silently degrade into replaying one row."
```

---

## Task 4: HTTP request batching

**Run this task only if the Task 2 gate marks `hec` or `generic` as
`needs generator work: yes`** — which it is expected to, because both send one
HTTP request per single event today and are therefore measuring `reqwest`.

**Files:**
- Modify: `tools/loadgen/src/hec_http.rs`, `tools/loadgen/src/generic_http.rs`
- Test: the `#[cfg(test)] mod tests` in both files

**Interfaces:**
- Consumes: `build_event_json(n) -> Value` (hec) and `build_record_json(n) -> Value`
  (generic), both already present and unchanged.
- Produces: `--events-per-request <N>` (default 1) on both subcommands, and
  `fn build_batch_body(start: u64, count: usize) -> String` in each module.
  Both handlers split the body on `\n` (`src/ingest/parse.rs:26` for HEC
  envelopes, `parse_ndjson_body` for `/ingest`), so a batch is literally
  newline-joined JSON objects.

- [ ] **Step 1: Write the failing tests (generic)**

Add to `tools/loadgen/src/generic_http.rs`'s test module:

```rust
/// A batch body must be exactly `count` newline-separated JSON objects, with
/// no trailing blank line beyond what the handler tolerates, and every record
/// distinct.
#[test]
fn batch_body_has_one_json_object_per_line() {
    let body = build_batch_body(100, 4);
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 4);
    let mut seqs = Vec::new();
    for line in lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("each line is valid JSON");
        seqs.push(v["seq"].as_u64().unwrap());
    }
    assert_eq!(seqs, vec![100, 101, 102, 103]);
}

/// Decisive test: the batch must come back out of logthing's own parser as
/// `count` records, not one. A body the server silently parses as a single
/// record would inflate the achieved rate by the batch factor.
#[test]
fn batch_body_parses_as_count_records_by_logthings_own_parser() {
    let body = build_batch_body(0, 8);
    let records = logthing::ingest::parse_ndjson_body(body.as_bytes(), "generic")
        .expect("batch body must parse");
    assert_eq!(records.len(), 8);
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test -p loadgen generic_http::tests::batch -- --nocapture
```

Expected: FAIL — `cannot find function 'build_batch_body'`.
`parse_ndjson_body` is already re-exported (`src/ingest/mod.rs:12`), so no
visibility change is needed — the only missing symbol is the one this task
adds.

- [ ] **Step 3: Implement batching in `generic_http.rs`**

Add the arg:

```rust
    /// Records per HTTP request. One request per record (the default) measures
    /// reqwest's request rate rather than logthing's ingest rate; real
    /// shippers batch. `/ingest` splits the body on newlines, so a batch is
    /// newline-joined JSON objects.
    #[arg(long, default_value_t = 1)]
    pub events_per_request: usize,
```

Add the builder:

```rust
fn build_batch_body(start: u64, count: usize) -> String {
    let mut body = String::with_capacity(count * 160);
    for i in 0..count as u64 {
        if i > 0 {
            body.push('\n');
        }
        body.push_str(&build_record_json(start + i).to_string());
    }
    body
}
```

In `spawn_request`, replace `build_record_json(n).to_string()` with
`build_batch_body(n, ctx.events_per_request)`, and — critically — count
accepted **records**, not requests:

```rust
            Ok(resp) if is_accepted(resp.status()) => {
                ctx.sent.fetch_add(ctx.events_per_request as u64, Ordering::Relaxed);
            }
```

In `run()`, the pacing loop must advance `n` by `events_per_request` per
request and issue `target_rate / events_per_request` requests per second.
Concretely, where the loop currently computes records-per-tick, divide by the
batch size and keep the fractional carry:

```rust
    let batch = args.events_per_request.max(1);
    let requests_per_tick_target =
        (args.target_rate as f64 / batch as f64) * per_tick_interval.as_secs_f64();
```

and each spawned request takes `n` then advances `n += batch as u64`.

- [ ] **Step 4: Run to verify they pass**

```bash
cargo test -p loadgen generic_http -- --nocapture
```

Expected: PASS, including the pre-existing in-process handler test.

- [ ] **Step 5: Repeat for `hec_http.rs`**

Identical shape, with two differences: the body is built from
`build_event_json(n, sourcetype)` (the `{"event": ...}` envelope — note it
takes the sourcetype as a second argument, so `build_batch_body` for this
module is `build_batch_body(start: u64, count: usize, sourcetype: &str)`), and
the round-trip test uses
`logthing::ingest::parse_hec_event_body(body.as_bytes(), "loadgen")`.
The request currently uses `.json(&body)`; switch it to `.body(batch_string)`,
since the batch is already-serialised text and `.json()` would re-encode it as
a single JSON string.

- [ ] **Step 6: Verify the achieved rate actually moved**

```bash
cargo build --release -p loadgen
# server from Task 2 Step 3 still in trivial shape, or restart it the same way
./target/release/loadgen generic-http --target-rate 0 --duration-secs 10 --events-per-request 1
./target/release/loadgen generic-http --target-rate 0 --duration-secs 10 --events-per-request 100
```

Expected: the second achieves a materially higher rec/s. Record both numbers —
they go in the Task 11 results document as the reason the HTTP ceilings are
quotable at all.

- [ ] **Step 7: Commit**

```bash
git add tools/loadgen/src/hec_http.rs tools/loadgen/src/generic_http.rs
git commit -m "perf(loadgen): batch events per HTTP request

hec-http and generic-http sent one request per single event, so both
measured reqwest's request rate, not logthing's ingest rate. --events-per-request
joins N records into one body; both handlers already split on newlines.

Accepted-record accounting multiplies by the batch size, so the achieved rate
stays a record rate and does not silently become a request rate."
```

---

## Task 5: `--workers N`

**Run this task only if Tasks 3 and 4 left a format whose generator ceiling is
still below the rate the server sustains.** If nothing is left, skip it and
record why. This is the last rung and the only one that adds a concurrency
model; do not run it speculatively.

**Files:**
- Modify: whichever of `tools/loadgen/src/*.rs` still needs it
- Test: the `#[cfg(test)] mod tests` in each modified file

**Interfaces:**
- Consumes: the ring/batch work from Tasks 3 and 4.
- Produces: `--workers <N>` (default 1) on the modified subcommands, and
  `fn split_rate(total: u64, workers: usize) -> Vec<u64>`.

- [ ] **Step 1: Write the failing test**

`split_rate` is the only part with a failure mode worth a test — an off-by-one
in the remainder silently offers less load than requested, which would be read
as a server ceiling. Add to the first module you modify:

```rust
/// The per-worker rates must sum to exactly the requested total: any
/// remainder lost to integer division is load the harness thinks it offered
/// and did not, i.e. a fake ceiling.
#[test]
fn split_rate_preserves_the_total() {
    assert_eq!(split_rate(10_000, 4), vec![2500, 2500, 2500, 2500]);
    assert_eq!(split_rate(10_001, 4), vec![2501, 2500, 2500, 2500]);
    assert_eq!(split_rate(3, 4), vec![1, 1, 1, 0]);
    assert_eq!(split_rate(0, 4).iter().sum::<u64>(), 0);
    for workers in 1..=8 {
        assert_eq!(split_rate(77_777, workers).iter().sum::<u64>(), 77_777);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test -p loadgen split_rate -- --nocapture
```

Expected: FAIL — `cannot find function 'split_rate'`.

- [ ] **Step 3: Implement**

```rust
/// Split a target rate across `workers`, giving the remainder to the first
/// workers one unit at a time so the per-worker rates sum to exactly `total`.
fn split_rate(total: u64, workers: usize) -> Vec<u64> {
    let w = workers.max(1) as u64;
    let base = total / w;
    let rem = total % w;
    (0..w).map(|i| base + if i < rem { 1 } else { 0 }).collect()
}
```

Then wrap the existing send loop in a per-worker `async` block, spawn one task
per worker onto a `JoinSet`, give each its own socket/connection and its own
slice of the ring index space (`worker_id * RING_SIZE / workers` as the
starting offset, so workers do not all send identical bytes at the same
instant), and sum their `sent` counts for the final report.

`--target-rate 0` (unbounded) passes 0 to every worker, which every send loop
already treats as unbounded.

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test -p loadgen
```

Expected: PASS, whole suite.

- [ ] **Step 5: Verify `--workers` beats `--workers 1`**

```bash
cargo build --release -p loadgen
FORMAT=<the format> BLACKHOLE=1 PROCS="1" DURATION=15 ./scripts/loadgen-ceiling.sh
./target/release/loadgen <sub> --target-rate 0 --duration-secs 15 --workers 4
```

Expected: `--workers 4` achieves a higher rate than the 1-process probe. If it
does not, revert this task rather than shipping an unused flag.

- [ ] **Step 6: Commit**

```bash
git add tools/loadgen/src
git commit -m "perf(loadgen): add --workers for per-process parallelism

Last rung, added only for the formats still generator-bound after
pre-rendering and HTTP batching. split_rate is tested to preserve the total
exactly -- a remainder lost to integer division would offer less load than
requested and read as a server ceiling."
```

---

## Task 6: Harness core — fixed rate, IPFIX only, superseding the old script

**Files:**
- Create: `scripts/max-ingest-rate.sh`
- Delete: `scripts/repeat-ipfix-loopback-loss.sh`
- Modify: `docs/performance/2026-09-14-throughput-baseline-repeats.md` (its
  "Reproduce" block, so its numbers stay reproducible under the new name)
- Test: `SELFTEST=1 ./scripts/max-ingest-rate.sh`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: shell functions `median_of`, `min_of`, `max_of`, `metric`,
  `metric_labeled`, `snmp_rcvbuf_errors`, `write_config`, `start_server`,
  `stop_server`, `parse_sent`, `parse_achieved`, and the env interface
  `FORMAT`, `SHAPE`, `RATE`, `DURATION`, `RUNS`, `METRICS_PORT`.
  Tasks 7–9 extend this file; nothing else sources it.

- [ ] **Step 1: Write the failing self-test**

Create `scripts/max-ingest-rate.sh` with the self-test block and stubs for the
pure functions:

```bash
#!/bin/bash
# Per-format maximum sustainable ingest rate. Supersedes
# scripts/repeat-ipfix-loopback-loss.sh -- same restart-per-run, zeroed-counter,
# RcvbufErrors-reconciling machinery, generalised across formats.
#
# Spec: docs/superpowers/specs/2026-09-16-max-ingest-rate-design.md
set -u

median_of() { :; }
min_of() { :; }
max_of() { :; }

if [ "${SELFTEST:-0}" = "1" ]; then
    fail=0
    check() {
        if [ "$2" != "$3" ]; then echo "FAIL: $1: expected '$3', got '$2'"; fail=1
        else echo "ok: $1"; fi
    }
    check "median odd"   "$(printf '%s\n' 3 1 2     | median_of)" "2"
    check "median even"  "$(printf '%s\n' 4 1 2 3   | median_of)" "2.5000"
    check "median one"   "$(printf '%s\n' 7         | median_of)" "7"
    check "median empty" "$(printf ''               | median_of)" "nan"
    check "min"          "$(printf '%s\n' 3 1 2     | min_of)"    "1"
    check "max"          "$(printf '%s\n' 3 1 2     | max_of)"    "3"
    check "median decimals" "$(printf '%s\n' 0.0413 0.0000 0.0000 0.0000 0.0000 | median_of)" "0.0000"
    [ "$fail" -eq 0 ] && echo "SELFTEST PASS" || echo "SELFTEST FAIL"
    exit "$fail"
fi
```

- [ ] **Step 2: Run to verify it fails**

```bash
chmod +x scripts/max-ingest-rate.sh
SELFTEST=1 ./scripts/max-ingest-rate.sh
```

Expected: `SELFTEST FAIL` with seven `expected 'X', got ''` lines.

- [ ] **Step 3: Implement the aggregation functions**

Ported verbatim from `scripts/repeat-ipfix-loopback-loss.sh` — they are
already correct and have 20 validated runs behind them:

```bash
median_of() { sort -n | awk '{a[NR]=$1} END {n=NR; if(n==0){print "nan"; exit} if(n%2==1) print a[(n+1)/2]; else printf "%.4f\n", (a[n/2]+a[n/2+1])/2}'; }
min_of() { sort -n | head -1; }
max_of() { sort -n | tail -1; }
```

- [ ] **Step 4: Run to verify it passes**

```bash
SELFTEST=1 ./scripts/max-ingest-rate.sh
```

Expected: seven `ok:` lines, `SELFTEST PASS`, exit 0.

- [ ] **Step 5: Port the run machinery, with the two defects fixed**

Insert above the self-test block. This is the old script's body with
`FORMAT=ipfix` hardcoded for now (Task 7 generalises it) and two changes:

```bash
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/target/release/logthing"
LOADGEN="$REPO/target/release/loadgen"
FORMAT="${FORMAT:-ipfix}"
SHAPE="${SHAPE:-real}"
RATE="${RATE:-20000}"
DURATION="${DURATION:-15}"
RUNS="${RUNS:-5}"
METRICS_PORT="${METRICS_PORT:-9090}"
RECONCILE_TOLERANCE=2

[ -x "$BIN" ]     || { echo "FATAL: $BIN missing. cargo build --release --bin logthing"; exit 1; }
[ -x "$LOADGEN" ] || { echo "FATAL: $LOADGEN missing. cargo build --release -p loadgen"; exit 1; }

fetch() {
    if command -v curl >/dev/null 2>&1; then curl -sf "$1"; else wget -qO- "$1"; fi
}
metric() {
    fetch "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null \
        | awk -v m="$1" '$0 ~ "^"m" " {print $2}'
}
metric_labeled() {
    fetch "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null \
        | awk -v m="^$1\\{" -v pat="$2" '$0 ~ m && $0 ~ pat {print $NF}'
}
snmp_rcvbuf_errors() {
    awk '/^Udp:/ { n++
        if (n == 1) { for (i = 1; i <= NF; i++) if ($i == "RcvbufErrors") col = i; next }
        if (n == 2) { print $col; exit } }' /proc/net/snmp
}
parse_sent()     { printf '%s\n' "$1" | sed -n 's/.*sent \([0-9]\{1,\}\) \(flows\|datagrams\|records\) in .*/\1/p' | tail -1; }
parse_achieved() { printf '%s\n' "$1" | sed -n 's/.*achieved rate: \([0-9.]\{1,\}\).*/\1/p' | tail -1; }

# DEFECT FIX 1 (vs repeat-ipfix-loopback-loss.sh): that script ran
# `pkill -f "$BIN"` at startup and in its EXIT trap. `pkill -f` matches whole
# command lines, so it killed any shell whose command text contained the
# binary path -- including the one that launched it. Symptom was a bare
# exit 144 with no output. A pidfile kills exactly the process we started.
PIDFILE="$(mktemp)" || exit 1

TMP_ROOT="$(mktemp -d)" || exit 1
LOCAL_DIR="$TMP_ROOT/parquet-local"
mkdir -p "$LOCAL_DIR"
cd "$REPO" || exit 1

# DEFECT FIX 2: the old script's cleanup did `rm -f logthing.admin.toml`,
# deleting a TRACKED file. Both configs are backed up and restored from the
# backup; nothing is ever removed.
CONFIG_BACKUP="$TMP_ROOT/logthing.toml.orig"
ADMIN_BACKUP="$TMP_ROOT/logthing.admin.toml.orig"
cp logthing.toml "$CONFIG_BACKUP" || exit 1
HAD_ADMIN=0
if [ -f logthing.admin.toml ]; then HAD_ADMIN=1; cp logthing.admin.toml "$ADMIN_BACKUP"; fi

SRV_PID=""
cleanup() {
    stop_server
    cp "$CONFIG_BACKUP" "$REPO/logthing.toml" 2>/dev/null
    if [ "$HAD_ADMIN" -eq 1 ]; then cp "$ADMIN_BACKUP" "$REPO/logthing.admin.toml" 2>/dev/null; fi
    rm -f "$PIDFILE"
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

write_config() {
    {
        echo 'bind_address = "0.0.0.0:5985"'
        echo '[tls]'; echo 'enabled = false'
        echo '[metrics]'; echo 'enabled = true'; echo "port = $METRICS_PORT"
        echo '[logging]'; echo 'level = "error"'; echo 'format = "pretty"'
        echo '[syslog]'; echo 'enabled = false'
        echo '[ipfix]'; echo 'enabled = true'
        echo "udp_port = 4739"; echo 'bind_address = "0.0.0.0"'
        if [ "$SHAPE" = "real" ]; then
            echo '[ipfix.local]'; echo "directory = \"$LOCAL_DIR\""
        fi
    } > "$REPO/logthing.toml"
}

start_server() {
    local run_id="$1"
    "$BIN" > "$TMP_ROOT/server-$run_id.log" 2>&1 &
    SRV_PID=$!
    echo "$SRV_PID" > "$PIDFILE"
    local up=0
    for _ in $(seq 1 30); do
        if fetch "http://127.0.0.1:$METRICS_PORT/metrics" >/dev/null 2>&1; then up=1; break; fi
        sleep 0.5
    done
    [ "$up" -eq 1 ] || { echo "FATAL: server did not start for run $run_id"; tail -30 "$TMP_ROOT/server-$run_id.log"; exit 1; }
    # /metrics answering proves the admin HTTP listener is up, not that the
    # UDP listener's bind has completed.
    sleep 1
}

stop_server() {
    [ -n "${SRV_PID:-}" ] || return 0
    kill "$SRV_PID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$SRV_PID" 2>/dev/null || break; sleep 0.5; done
    kill -0 "$SRV_PID" 2>/dev/null && kill -9 "$SRV_PID" 2>/dev/null
    wait "$SRV_PID" 2>/dev/null
    SRV_PID=""
}
```

Then the per-run loop, one-for-one with the old script's: `write_config`,
then for each of `RUNS` — `start_server`, read `snmp_rcvbuf_errors` before,
run the generator, `sleep 2`, scrape `ipfix_datagrams_received` /
`ipfix_socket_drops` / `parquet_s3_dropped{source="ipfix"}`, read
`snmp_rcvbuf_errors` after, `stop_server`, abort if socket drops and the
`RcvbufErrors` delta disagree by more than `RECONCILE_TOLERANCE`, then print
the TSV row. Finish with the median/min/max summary and the two "all zero"
notes. Copy that block from the old script before deleting it.

- [ ] **Step 6: Verify it reproduces the committed baseline**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo build --release --bin logthing && cargo build --release -p loadgen
FORMAT=ipfix SHAPE=trivial RATE=20000 DURATION=15 RUNS=5 ./scripts/max-ingest-rate.sh
FORMAT=ipfix SHAPE=real    RATE=20000 DURATION=15 RUNS=5 ./scripts/max-ingest-rate.sh
```

Expected, from `docs/performance/2026-09-14-throughput-baseline-repeats.md`:
trivial shape at/near 0% loss (median 0.0000%, max ~0.04%); real shape median
in the low single digits (that doc recorded median 3.63%, range 1.67–5.10%)
with `parquet_s3_dropped{source="ipfix"}` in the 200k range. Run-to-run spread
is large on this host, so **the acceptance criterion is "same order, same
shape, reconciliation never fires"**, not identical digits. If the
reconciliation check fires, stop — something is wrong with the port, a stale
process, or the scrape.

- [ ] **Step 7: Verify the two defect fixes**

```bash
git status --porcelain logthing.toml logthing.admin.toml
```

Expected: no output — both tracked files byte-identical after a full run. Then
confirm no `pkill` remains:

```bash
grep -n pkill scripts/max-ingest-rate.sh; echo "grep exit=$?"
```

Expected: no matches, `grep exit=1`.

- [ ] **Step 8: Delete the old script and repoint its doc**

```bash
git rm scripts/repeat-ipfix-loopback-loss.sh
```

In `docs/performance/2026-09-14-throughput-baseline-repeats.md`, replace the
four `./scripts/repeat-ipfix-loopback-loss.sh` invocations in its "Reproduce"
block with the `FORMAT=ipfix ... ./scripts/max-ingest-rate.sh` equivalents, and
add one line above them noting the script was renamed and generalised on
2026-09-16, and that the old one's `pkill -f` and `rm logthing.admin.toml`
behaviours are gone.

- [ ] **Step 9: Commit**

```bash
git add scripts/max-ingest-rate.sh docs/performance/2026-09-14-throughput-baseline-repeats.md
git commit -m "perf: replace the IPFIX loss harness with a per-format one

Same restart-per-run, zeroed-counter, RcvbufErrors-reconciling machinery,
reproduced against the committed 2026-09-14 baseline, minus two defects: the
pkill -f that killed the invoking shell, and the cleanup that rm'd a tracked
logthing.admin.toml."
```

---

## Task 7: Per-format map (all seven formats)

**Files:**
- Modify: `scripts/max-ingest-rate.sh`
- Test: `SELFTEST=1 ./scripts/max-ingest-rate.sh`

**Interfaces:**
- Consumes: Task 6's `write_config`, `start_server`, `metric`, `metric_labeled`.
- Produces: `resolve_format()` setting `SUB`, `PORT`, `TRANSPORT`,
  `RECV_METRIC`, `DROP_METRIC`, `SOURCE_LABEL`, `CONFIG_SECTION`; plus
  `scrape_losses()` printing a tab-separated
  `received kernel_drops writer_drops buffer_drops written`.

- [ ] **Step 1: Write the failing self-test**

Append to the `SELFTEST` block:

```bash
    check "resolve ipfix sub"     "$(FORMAT=ipfix    resolve_format && echo "$SUB")"          "ipfix-udp"
    check "resolve ipfix drop"    "$(FORMAT=ipfix    resolve_format && echo "$DROP_METRIC")"  "ipfix_socket_drops"
    check "resolve zeek drop"     "$(FORMAT=zeek     resolve_format && echo "$DROP_METRIC")"  ""
    check "resolve zeek recv"     "$(FORMAT=zeek     resolve_format && echo "$RECV_METRIC")"  "zeek_records_received"
    check "resolve generic label" "$(FORMAT=generic  resolve_format && echo "$SOURCE_LABEL")" "hec"
    check "resolve hec label"     "$(FORMAT=hec      resolve_format && echo "$SOURCE_LABEL")" "hec"
    check "resolve suricata port" "$(FORMAT=suricata resolve_format && echo "$PORT")"         "47761"
    check "resolve sflow recv"    "$(FORMAT=sflow    resolve_format && echo "$RECV_METRIC")"  "sflow_datagrams_received"
    check "resolve syslog struct" "$(FORMAT=syslog STRUCTURED=1 resolve_format && echo "$SOURCE_LABEL")" "structured_syslog"
    check "resolve syslog plain"  "$(FORMAT=syslog STRUCTURED=0 resolve_format && echo "$SOURCE_LABEL")" "syslog"
    check "resolve unknown rc"    "$(FORMAT=nope resolve_format >/dev/null 2>&1; echo $?)"    "1"
```

- [ ] **Step 2: Run to verify it fails**

```bash
SELFTEST=1 ./scripts/max-ingest-rate.sh
```

Expected: `SELFTEST FAIL`, eleven new failures (`resolve_format: command not found`).

- [ ] **Step 3: Implement `resolve_format`**

```bash
# Sink `source` labels below are the sinks' own source() values
# (src/forwarding/*_s3.rs). Note `generic` and `hec` share BOTH the received
# counter (src/ingest/handlers.rs:219) and the sink label
# (src/forwarding/generic_s3.rs:163) -- they are indistinguishable in the
# metrics, which is why this harness runs exactly one format per invocation.
resolve_format() {
    STRUCTURED="${STRUCTURED:-0}"
    case "${FORMAT:-}" in
        syslog)
            SUB="syslog-udp"; PORT=514; TRANSPORT=udp
            RECV_METRIC="syslog_messages_received"; DROP_METRIC="syslog_socket_drops"
            CONFIG_SECTION="syslog"
            if [ "$STRUCTURED" = "1" ]; then SOURCE_LABEL="structured_syslog"; else SOURCE_LABEL="syslog"; fi
            ;;
        ipfix)
            SUB="ipfix-udp"; PORT=4739; TRANSPORT=udp
            RECV_METRIC="ipfix_datagrams_received"; DROP_METRIC="ipfix_socket_drops"
            SOURCE_LABEL="ipfix"; CONFIG_SECTION="ipfix" ;;
        sflow)
            SUB="sflow-udp"; PORT=6343; TRANSPORT=udp
            RECV_METRIC="sflow_datagrams_received"; DROP_METRIC="sflow_socket_drops"
            SOURCE_LABEL="sflow"; CONFIG_SECTION="sflow" ;;
        zeek)
            SUB="zeek-tcp"; PORT=47760; TRANSPORT=tcp
            RECV_METRIC="zeek_records_received"; DROP_METRIC=""
            SOURCE_LABEL="zeek"; CONFIG_SECTION="zeek" ;;
        suricata)
            SUB="suricata-tcp"; PORT=47761; TRANSPORT=tcp
            RECV_METRIC="suricata_records_received"; DROP_METRIC=""
            SOURCE_LABEL="suricata"; CONFIG_SECTION="suricata" ;;
        hec)
            SUB="hec-http"; PORT=5985; TRANSPORT=http
            RECV_METRIC="hec_events_received"; DROP_METRIC=""
            SOURCE_LABEL="hec"; CONFIG_SECTION="hec" ;;
        generic)
            SUB="generic-http"; PORT=5985; TRANSPORT=http
            RECV_METRIC="hec_events_received"; DROP_METRIC=""
            SOURCE_LABEL="hec"; CONFIG_SECTION="hec" ;;
        *)
            echo "FATAL: unknown FORMAT '${FORMAT:-}' (want one of: syslog ipfix sflow zeek suricata hec generic)" >&2
            return 1 ;;
    esac
    return 0
}
```

`DROP_METRIC=""` for the four non-UDP formats is load-bearing: the kernel-loss
column and the `RcvbufErrors` reconciliation are both skipped when it is
empty, because TCP and HTTP cannot lose datagrams in a socket buffer.

- [ ] **Step 4: Run to verify it passes**

```bash
SELFTEST=1 ./scripts/max-ingest-rate.sh
```

Expected: all `ok:`, `SELFTEST PASS`.

- [ ] **Step 5: Generalise `write_config`**

Replace the hardcoded IPFIX body. Every listener section takes the same
`enabled`/port/`bind_address` shape, and every local sink is
`[<section>.local] directory = "..."` (`src/config/mod.rs`):

```bash
write_config() {
    {
        echo 'bind_address = "0.0.0.0:5985"'
        echo '[tls]'; echo 'enabled = false'
        echo '[metrics]'; echo 'enabled = true'; echo "port = $METRICS_PORT"
        echo '[logging]'; echo 'level = "error"'; echo 'format = "pretty"'
        # Every listener off by default, so an unrelated one can never bind a
        # port or consume CPU during another format's run.
        echo '[syslog]'; echo 'enabled = false'

        case "$TRANSPORT" in
            udp)
                if [ "$CONFIG_SECTION" = "syslog" ]; then
                    # [syslog] was already emitted above; rewrite it enabled.
                    :
                else
                    echo "[$CONFIG_SECTION]"; echo 'enabled = true'
                    echo "udp_port = $PORT"; echo 'bind_address = "0.0.0.0"'
                fi ;;
            tcp)
                echo "[$CONFIG_SECTION]"; echo 'enabled = true'
                echo "tcp_port = $PORT"; echo 'bind_address = "0.0.0.0"' ;;
            http)
                echo '[hec]'; echo 'enabled = true'; echo 'token = ""' ;;
        esac

        if [ "$SHAPE" = "real" ]; then
            echo "[$CONFIG_SECTION.local]"
            echo "directory = \"$LOCAL_DIR\""
        fi
    } > "$REPO/logthing.toml"
}
```

For `FORMAT=syslog`, emit the `[syslog]` section **once**, enabled, with
`udp_port = 514` — restructure the function so the always-off `[syslog]` line
is only written when the format under test is not syslog. Verify by running
`FORMAT=syslog SHAPE=real RUNS=1 DURATION=3 RATE=1000 ./scripts/max-ingest-rate.sh`
and confirming the server log has no duplicate-key or bind error.

Binding UDP 514 requires either root or `CAP_NET_BIND_SERVICE`. If the run
aborts on a permission error, override with `PORT` (add a `PORT` env override
to `resolve_format`) and say so in the results document — do not silently run
syslog on a different port than the table claims.

- [ ] **Step 6: Generalise the generator invocation and the scrape**

```bash
run_generator() {
    local rate="$1" secs="$2"
    local extra=""
    case "$FORMAT" in
        hec|generic) extra="--events-per-request ${EVENTS_PER_REQUEST:-1} --concurrency ${CONCURRENCY:-64}" ;;
        syslog)      [ "${STRUCTURED:-0}" = "1" ] && extra="--structured" ;;
    esac
    # shellcheck disable=SC2086
    "$LOADGEN" "$SUB" --host 127.0.0.1 --port "$PORT" \
        --target-rate "$rate" --duration-secs "$secs" $extra 2>&1
}

# Prints: received  kernel_drops  writer_drops  buffer_drops  written
scrape_losses() {
    local recv kd wd bd wr
    recv="$(metric "$RECV_METRIC")"; recv="${recv:-0}"
    if [ -n "$DROP_METRIC" ]; then kd="$(metric "$DROP_METRIC")"; kd="${kd:-0}"; else kd="n/a"; fi
    wd="$(metric_labeled parquet_s3_dropped "source=\"$SOURCE_LABEL\"")";        wd="${wd:-0}"
    bd="$(metric_labeled parquet_s3_buffer_dropped "source=\"$SOURCE_LABEL\"")"; bd="${bd:-0}"
    wr="$(metric_labeled parquet_s3_records_written "source=\"$SOURCE_LABEL\"")"; wr="${wr:-0}"
    printf '%s\t%s\t%s\t%s\t%s\n' "$recv" "$kd" "$wd" "$bd" "$wr"
}
```

Guard the `RcvbufErrors` reconciliation with `[ -n "$DROP_METRIC" ]` so it is
skipped for TCP and HTTP. Widen the TSV header to
`run  format  shape  offered  achieved  received  kernel_drops  writer_drops  buffer_drops  written  loss_pct`.

- [ ] **Step 7: Smoke each of the seven formats at a low rate**

```bash
for f in ipfix sflow zeek suricata hec generic syslog; do
  echo "=== $f ==="
  FORMAT=$f SHAPE=real RATE=1000 DURATION=5 RUNS=1 ./scripts/max-ingest-rate.sh || echo "FAILED: $f"
done
git status --porcelain logthing.toml logthing.admin.toml
```

Expected: seven tables, each with non-zero `received` and non-zero `written`,
no `FAILED:` line, and no output from `git status`. A format showing
`written = 0` means the local sink was not wired — fix the config emission
before continuing, because a zero there makes every loss figure meaningless.

- [ ] **Step 8: Commit**

```bash
git add scripts/max-ingest-rate.sh
git commit -m "perf(harness): support all seven formats

Per-format map of subcommand, port, transport, received counter, kernel-drop
counter and sink source label. Kernel-loss accounting and the RcvbufErrors
reconciliation are skipped for TCP/HTTP rather than reported as zero, since
those transports cannot lose datagrams in a socket buffer.

hec and generic share a received counter and a sink label, so the harness
runs exactly one format per invocation."
```

---

## Task 8: CPU pinning, drain-to-stable, and the generator-saturation guard

**Files:**
- Modify: `scripts/max-ingest-rate.sh`
- Test: `SELFTEST=1 ./scripts/max-ingest-rate.sh`

**Interfaces:**
- Consumes: Task 7's `run_generator`, `scrape_losses`.
- Produces: `classify_run(achieved, target, loss_pct, budget)` printing one of
  `PASS`, `FAIL-LOSS`, `GENERATOR-LIMITED`; `drain_until_stable(metric_name, label)`;
  and `cpu_ticks(pid)`.

- [ ] **Step 1: Write the failing self-test**

```bash
    # target 20000, 99% floor = 19800
    check "classify pass"        "$(classify_run 19999 20000 0.05 0.1)" "PASS"
    check "classify at floor"    "$(classify_run 19800 20000 0.05 0.1)" "PASS"
    check "classify loss fail"   "$(classify_run 19999 20000 0.50 0.1)" "FAIL-LOSS"
    check "classify gen limited" "$(classify_run 15283 20000 0.00 0.1)" "GENERATOR-LIMITED"
    # Generator saturation is checked FIRST: a run the generator could not
    # sustain says nothing about loss, in either direction.
    check "gen limit beats loss" "$(classify_run 15283 20000 9.90 0.1)" "GENERATOR-LIMITED"
    check "classify exact budget" "$(classify_run 20000 20000 0.10 0.1)" "PASS"
    check "unbounded target"     "$(classify_run 12796 0 0.00 0.1)"     "PASS"
```

- [ ] **Step 2: Run to verify it fails**

```bash
SELFTEST=1 ./scripts/max-ingest-rate.sh
```

Expected: seven new failures, `classify_run: command not found`.

- [ ] **Step 3: Implement `classify_run`**

```bash
# Fraction of target the generator must actually achieve for the run's loss
# figure to mean anything. docs/performance/2026-09-13-multiformat-load-results.md
# §2 read zeek achieving 15,283/s against a 20,000/s target as a generator
# ceiling; on TCP that signature is equally consistent with server
# backpressure. This harness refuses to call either one a ceiling.
ACHIEVED_FLOOR_PCT="${ACHIEVED_FLOOR_PCT:-99}"

classify_run() {
    local achieved="$1" target="$2" loss="$3" budget="$4"
    if [ "$target" != "0" ]; then
        local ok
        ok="$(awk -v a="$achieved" -v t="$target" -v f="$ACHIEVED_FLOOR_PCT" \
              'BEGIN { print (a >= t * f / 100) ? 1 : 0 }')"
        if [ "$ok" != "1" ]; then echo "GENERATOR-LIMITED"; return 0; fi
    fi
    if [ "$(awk -v l="$loss" -v b="$budget" 'BEGIN { print (l <= b) ? 1 : 0 }')" = "1" ]; then
        echo "PASS"
    else
        echo "FAIL-LOSS"
    fi
}
```

- [ ] **Step 4: Run to verify it passes**

```bash
SELFTEST=1 ./scripts/max-ingest-rate.sh
```

Expected: all `ok:`, `SELFTEST PASS`.

- [ ] **Step 5: Add CPU pinning**

```bash
GEN_CPUS="${GEN_CPUS:-0-3}"
SRV_CPUS="${SRV_CPUS:-4-11}"
```

Prefix the server launch in `start_server` with `taskset -c "$SRV_CPUS"` and
the generator launch in `run_generator` with `taskset -c "$GEN_CPUS"`. Sample
each side's CPU with:

```bash
# utime+stime in clock ticks from /proc/<pid>/stat (fields 14 and 15). Read
# before and after the load burst and diff; divide by `getconf CLK_TCK` and
# the wall-clock duration to get cores-used. A generator at ~4.0 cores on a
# 4-core cpuset IS the ceiling, and the run must be read as generator-limited
# regardless of what classify_run says about the rate.
cpu_ticks() {
    awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0
}
```

Report `gen_cores` and `srv_cores` as columns on every run row.

- [ ] **Step 6: Replace the fixed `sleep 2` with drain-to-stable**

The fixed sleep counts rows still in flight as loss —
`docs/performance/2026-09-13-multiformat-load-results.md` §2 had to explain
that away by hand. Poll instead:

```bash
# Poll parquet_s3_records_written until it stops climbing, so
# offered - written is real loss and not rows still in the buffer.
DRAIN_MAX_SECS="${DRAIN_MAX_SECS:-30}"
drain_until_stable() {
    local prev="" cur elapsed=0
    while [ "$elapsed" -lt "$DRAIN_MAX_SECS" ]; do
        sleep 2; elapsed=$((elapsed + 2))
        cur="$(metric_labeled parquet_s3_records_written "source=\"$SOURCE_LABEL\"")"
        cur="${cur:-0}"
        if [ "$cur" = "$prev" ]; then echo "$cur"; return 0; fi
        prev="$cur"
    done
    echo "WARN: parquet_s3_records_written still climbing after ${DRAIN_MAX_SECS}s; this run's written count is a lower bound" >&2
    echo "$prev"
}
```

Call it after the generator exits and before `scrape_losses`. In `trivial`
shape there is no writer, so skip it and keep a flat `sleep 2` — that shape
only needs the 1 s `/proc/net/udp` poll tick to land.

- [ ] **Step 7: Verify on a real run**

```bash
FORMAT=ipfix SHAPE=real RATE=20000 DURATION=15 RUNS=3 ./scripts/max-ingest-rate.sh
```

Expected: every row carries a verdict, `gen_cores` and `srv_cores`; at least
one row's drain loop exits before `DRAIN_MAX_SECS`. Then force the guard:

```bash
FORMAT=ipfix SHAPE=real RATE=5000000 DURATION=10 RUNS=1 ./scripts/max-ingest-rate.sh
```

Expected: verdict `GENERATOR-LIMITED` — no generator reaches 5M/s on this
host — and **no ceiling reported**.

- [ ] **Step 8: Commit**

```bash
git add scripts/max-ingest-rate.sh
git commit -m "perf(harness): pin CPUs, drain before scraping, guard on generator saturation

A run whose generator missed its target says nothing about the server, so it
is classified GENERATOR-LIMITED before loss is even considered. Written
counts are polled to stability instead of read after a fixed sleep, so rows
still in the buffer are not counted as loss."
```

---

## Task 9: Ramp and bisect

**Files:**
- Modify: `scripts/max-ingest-rate.sh`
- Test: `SELFTEST=1 ./scripts/max-ingest-rate.sh`

**Interfaces:**
- Consumes: Task 8's `classify_run`; Task 7's `run_generator`, `scrape_losses`.
- Produces: `measure_rate(rate)` printing `PASS`/`FAIL-LOSS`/`GENERATOR-LIMITED`
  for one rate across `RUNS` runs, and `ramp(start)` printing the final
  `CEILING <rate>` or `GENERATOR-LIMITED <rate>` line. `ramp` calls
  `measure_rate`, so the self-test overrides `measure_rate` with a table-driven
  stub and asserts the search sequence.

- [ ] **Step 1: Write the failing self-test**

```bash
    # Stub measure_rate with a known ceiling so the search itself is under
    # test, not the server. Records every rate tried, in order.
    TRIED=""
    measure_rate() {
        TRIED="$TRIED $1"
        if [ "$1" -le "$STUB_CEILING" ]; then echo "PASS"; else echo "FAIL-LOSS"; fi
    }

    STUB_CEILING=26000 TRIED="" BISECT_RESOLUTION=1000
    RESULT="$(STUB_CEILING=26000 BISECT_RESOLUTION=1000 ramp 5000)"
    # Trace: doubling 5000/10000/20000 PASS, 40000 FAIL; bisect 30000 FAIL,
    # 25000 PASS, 27500 FAIL, 26250 FAIL, 25625 PASS; 26250-25625=625 <= 1000
    # so the search stops and reports the last passing rate.
    check "ramp finds ceiling" "$RESULT" "CEILING 25625"

    # A ramp that never fails must not claim a ceiling -- it only proves the
    # server survived everything offered.
    STUB_CEILING=99999999
    RESULT="$(STUB_CEILING=99999999 BISECT_RESOLUTION=1000 RAMP_MAX=80000 ramp 5000)"
    check "ramp hits RAMP_MAX" "$RESULT" "NO-CEILING-FOUND 80000"

    # A GENERATOR-LIMITED verdict anywhere aborts the search rather than
    # being treated as a failing rate (which would report a fake ceiling).
    measure_rate() { TRIED="$TRIED $1"; [ "$1" -ge 20000 ] && echo "GENERATOR-LIMITED" || echo "PASS"; }
    RESULT="$(BISECT_RESOLUTION=1000 ramp 5000)"
    check "ramp aborts on gen limit" "$RESULT" "GENERATOR-LIMITED 20000"
```

- [ ] **Step 2: Run to verify it fails**

```bash
SELFTEST=1 ./scripts/max-ingest-rate.sh
```

Expected: three new failures, `ramp: command not found`.

- [ ] **Step 3: Implement `ramp`**

```bash
BISECT_RESOLUTION="${BISECT_RESOLUTION:-1000}"
RAMP_MAX="${RAMP_MAX:-500000}"

# Coarse doubling to the first failing rate, then bisect between the last
# passing and first failing rate down to BISECT_RESOLUTION. A linear sweep
# would spend most of its runs far below the answer.
ramp() {
    local rate="$1" last_pass=0 first_fail=0 verdict

    while [ "$rate" -le "$RAMP_MAX" ]; do
        verdict="$(measure_rate "$rate")"
        case "$verdict" in
            PASS)              last_pass="$rate" ;;
            GENERATOR-LIMITED) echo "GENERATOR-LIMITED $rate"; return 0 ;;
            *)                 first_fail="$rate"; break ;;
        esac
        rate=$((rate * 2))
    done

    if [ "$first_fail" -eq 0 ]; then
        echo "NO-CEILING-FOUND $last_pass"
        return 0
    fi

    while [ $((first_fail - last_pass)) -gt "$BISECT_RESOLUTION" ]; do
        local mid=$(( (last_pass + first_fail) / 2 ))
        verdict="$(measure_rate "$mid")"
        case "$verdict" in
            PASS)              last_pass="$mid" ;;
            GENERATOR-LIMITED) echo "GENERATOR-LIMITED $mid"; return 0 ;;
            *)                 first_fail="$mid" ;;
        esac
    done

    echo "CEILING $last_pass"
}
```

`NO-CEILING-FOUND` reports `last_pass` — the largest rate actually offered
and survived — not `RAMP_MAX`, which may never have been tried. It is
deliberately a different token from `CEILING`: "survived everything we could
offer" is not the same claim as "we found the limit", and the results document
must not render them the same way.

- [ ] **Step 4: Run to verify it passes**

```bash
SELFTEST=1 ./scripts/max-ingest-rate.sh
```

Expected: all `ok:`, `SELFTEST PASS`. The three expected values above were
derived by running `ramp` against each stub; if one disagrees, the
implementation diverged from the plan — fix the implementation, do not relax
the expectation.

- [ ] **Step 5: Implement `measure_rate` for real**

```bash
# Runs `RUNS` full runs at `rate` and returns one verdict for the rate.
# Any GENERATOR-LIMITED run poisons the whole rate: the remaining runs
# cannot rescue a figure the generator could not offer.
LOSS_BUDGET="${LOSS_BUDGET:-0.1}"
measure_rate() {
    local rate="$1" i losses="" achieveds="" verdict
    for i in $(seq 1 "$RUNS"); do
        run_one "$i" "$rate" || return 1       # prints the TSV row, sets RUN_LOSS/RUN_ACHIEVED
        verdict="$(classify_run "$RUN_ACHIEVED" "$rate" "$RUN_LOSS" "$LOSS_BUDGET")"
        if [ "$verdict" = "GENERATOR-LIMITED" ]; then echo "GENERATOR-LIMITED"; return 0; fi
        losses="$losses"$'\n'"$RUN_LOSS"
        achieveds="$achieveds"$'\n'"$RUN_ACHIEVED"
    done
    local med med_ach
    med="$(printf '%s' "$losses" | grep -v '^$' | median_of)"
    med_ach="$(printf '%s' "$achieveds" | grep -v '^$' | median_of)"
    echo "# rate=$rate median_loss=${med}% median_achieved=${med_ach}" >&2
    classify_run "$med_ach" "$rate" "$med" "$LOSS_BUDGET"
}
```

Refactor Task 6–8's per-run body into `run_one <run_id> <rate>`, which sets
`RUN_LOSS` (total loss percent: `(offered − written) / offered × 100`) and
`RUN_ACHIEVED`, prints the TSV row including the per-site breakdown, and
returns non-zero only on a hard failure (server would not start, reconciliation
disagreed).

- [ ] **Step 6: Add the ramp entry point**

```bash
# RATE set -> fixed-rate mode (reproduces the old repeat-ipfix harness).
# RATE unset -> ramp mode.
if [ -n "${RATE:-}" ]; then
    measure_rate "$RATE" >/dev/null
else
    ramp "${RAMP_START:-5000}"
fi
```

Make `RATE` unset by default rather than `20000`, and update the Task 6
reproduce commands (which pass `RATE=` explicitly) — they keep working.

- [ ] **Step 7: Verify a real ramp**

```bash
FORMAT=ipfix SHAPE=real RUNS=3 DURATION=15 RAMP_START=2000 BISECT_RESOLUTION=500 \
  ./scripts/max-ingest-rate.sh
```

Expected: a sequence of per-rate tables followed by one `CEILING <rate>` line,
with the ceiling below 20,000/s — `docs/performance/2026-09-14-throughput-baseline-repeats.md`
recorded 3.6% median kernel loss and 200k+ writer drops for IPFIX real shape
at 20,000/s, far outside a 0.1% budget. A ceiling at or above 20,000/s means
something is wrong with the loss accounting; stop and investigate.

- [ ] **Step 8: Commit**

```bash
git add scripts/max-ingest-rate.sh
git commit -m "perf(harness): ramp and bisect to a per-format ceiling

Coarse doubling to first failure then bisect, with a GENERATOR-LIMITED
verdict aborting the search instead of being treated as a failing rate --
which would report the generator's ceiling as the server's."
```

---

## Task 10: Integration test

**Files:**
- Create: `tests/max_ingest_rate_harness_integration.rs`
- Test: `cargo test --test max_ingest_rate_harness_integration`

**Interfaces:**
- Consumes: `scripts/max-ingest-rate.sh` as a black box.
- Produces: nothing other tasks consume.

Follows the existing precedent of `tests/docker_build_context_integration.rs`,
which likewise drives repo tooling from a Rust integration test.

- [ ] **Step 1: Write the failing test**

```rust
//! Integration coverage for `scripts/max-ingest-rate.sh`.
//!
//! The harness's pure logic is covered by its own `SELFTEST=1` mode; this
//! test covers the parts that only appear when it drives a real server:
//! that a run produces a verdict at all, and that it leaves the two TRACKED
//! config files untouched (the defect its predecessor shipped with).

use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The harness's own self-test must pass before any run is trusted.
#[test]
fn harness_selftest_passes() {
    let out = Command::new("bash")
        .arg("scripts/max-ingest-rate.sh")
        .env("SELFTEST", "1")
        .current_dir(repo_root())
        .output()
        .expect("run harness self-test");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("SELFTEST PASS"),
        "harness self-test failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// One short real run: a verdict is emitted, and both tracked config files
/// come back byte-identical. Requires release binaries; skips (rather than
/// fails) if they are absent, so `cargo test` on a fresh checkout is green.
#[test]
fn short_run_emits_a_verdict_and_restores_tracked_configs() {
    let root = repo_root();
    if !root.join("target/release/logthing").exists() || !root.join("target/release/loadgen").exists()
    {
        eprintln!("skipping: release binaries not built");
        return;
    }

    let before_main = std::fs::read(root.join("logthing.toml")).expect("read logthing.toml");
    let before_admin = std::fs::read(root.join("logthing.admin.toml")).ok();

    let out = Command::new("bash")
        .arg("scripts/max-ingest-rate.sh")
        .env("FORMAT", "ipfix")
        .env("SHAPE", "real")
        .env("RATE", "1000")
        .env("DURATION", "3")
        .env("RUNS", "2")
        .current_dir(&root)
        .output()
        .expect("run harness");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "harness exited {:?}:\n{stdout}", out.status.code());
    assert!(
        stdout.contains("PASS") || stdout.contains("FAIL-LOSS") || stdout.contains("GENERATOR-LIMITED"),
        "no verdict in harness output:\n{stdout}"
    );

    assert_eq!(
        before_main,
        std::fs::read(root.join("logthing.toml")).expect("logthing.toml still exists"),
        "harness must restore logthing.toml byte-for-byte"
    );
    assert_eq!(
        before_admin,
        std::fs::read(root.join("logthing.admin.toml")).ok(),
        "harness must restore logthing.admin.toml (it is tracked; the predecessor rm'd it)"
    );
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --test max_ingest_rate_harness_integration
```

Expected: FAIL if any harness behaviour is missing. If both pass immediately,
verify the test is real by temporarily breaking the harness (e.g. `exit 1`
before the summary), re-running to see a failure, then reverting.

- [ ] **Step 3: Make it pass**

Fix whatever the test exposes in `scripts/max-ingest-rate.sh`. These tests
assert behaviour the harness is already specified to have; no production code
changes.

- [ ] **Step 4: Run the full test suite**

```bash
cargo test --test max_ingest_rate_harness_integration
cargo test -p loadgen
```

Expected: PASS, both.

- [ ] **Step 5: Commit**

```bash
git add tests/max_ingest_rate_harness_integration.rs
git commit -m "test: integration coverage for the ingest-rate harness

Asserts a real short run emits a verdict and restores both tracked config
files byte-for-byte -- the specific defect the predecessor harness shipped."
```

---

## Task 11: Run the ramps and publish the results

**Files:**
- Create: `docs/performance/2026-09-16-max-ingest-rate.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: everything above.
- Produces: the deliverable.

- [ ] **Step 1: Rebuild both binaries from the final branch state**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo build --release --bin logthing && cargo build --release -p loadgen
git rev-parse --short HEAD    # record this in the results doc
```

- [ ] **Step 2: Ramp every format**

```bash
for f in ipfix sflow syslog zeek suricata hec generic; do
  echo "########## $f ##########"
  FORMAT=$f SHAPE=real RUNS=5 DURATION=15 RAMP_START=2000 \
    BISECT_RESOLUTION=500 LOSS_BUDGET=0.1 \
    ./scripts/max-ingest-rate.sh 2>&1 | tee "/tmp/ramp-$f.log"
done
```

This is long-running (roughly `runs × duration × rates-tried` per format).
Run formats one at a time; never two concurrently — they share the host's
CPUs and, for `hec`/`generic`, the same counters.

- [ ] **Step 3: Write the results document**

`docs/performance/2026-09-16-max-ingest-rate.md`, following
`docs/performance/methodology-template.md`:

- the host caveat block, verbatim, from
  `docs/performance/2026-09-14-throughput-baseline-repeats.md`;
- provenance: crate version, commit, date, exact command lines, `nproc`,
  `net.core.rmem_max`, the `GEN_CPUS`/`SRV_CPUS` split;
- **the headline table**, one row per format:

  | format | max sustainable rate | median total loss at that rate | kernel / writer / buffer split | generator ceiling (Task 2) | gen cores | srv cores | verdict |

  where verdict is one of **kernel-limited**, **writer-limited**,
  **server-CPU-limited**, **generator-limited**;
- per format, the first failing rate and its loss breakdown — the ceiling is
  only interpretable next to what failure looked like;
- an explicit note that `hec` and `generic` share `hec_events_received` and
  `source="hec"`, naming which generator produced each row;
- for `syslog`, whether it ran on port 514 or an override;
- **what this does NOT establish**: it is a loopback figure on a shared-CPU
  KVM guest, not a deployment capacity number, and an off-box sender is the
  next step.

- [ ] **Step 4: Correct the record in the older doc**

Add a dated correction note to
`docs/performance/2026-09-13-multiformat-load-results.md` §2, in the same
style as the two `⚠️ Corrected 2026-09-14` notes already there, stating what
Task 2 and Task 11 found about its "the generator, not the server, is the
limit above ~15k/s" claim — confirming or overturning it with the measured
numbers.

- [ ] **Step 5: Update the changelog**

Add an `Added` entry for `scripts/max-ingest-rate.sh` and
`scripts/loadgen-ceiling.sh`, a `Changed` entry for the loadgen generator
work actually done, and a `Removed` entry for
`scripts/repeat-ipfix-loopback-loss.sh` naming its replacement.

- [ ] **Step 6: Verify the working tree is clean**

```bash
git status --porcelain
cargo test -p loadgen && cargo test --test max_ingest_rate_harness_integration
```

Expected: only the intended files listed; both test commands pass.

- [ ] **Step 7: Commit**

```bash
git add docs/performance CHANGELOG.md
git commit -m "perf: per-format maximum sustainable ingest rates

First capacity numbers for all seven wire formats. Every figure carries a
per-site loss breakdown and a verdict naming what bound it; runs the
generator could not sustain are reported as such rather than as ceilings."
```

---

## Notes for the executor

- **Tasks 3, 4 and 5 are conditional on Task 2's gate.** Skipping one because
  the measurement says it is unnecessary is the correct outcome, not a
  shortfall. Record the skip and the number that justified it.
- **Two-stage review applies per task**: spec-compliance first, then code
  quality, by separate reviewers. Neither is skipped, and the implementer's
  own check substitutes for neither.
- **Never run two formats concurrently.** They share the host CPUs, and
  `hec`/`generic` share every counter.
- **After any harness run, check `git status`.** A dirty `logthing.toml` or a
  missing `logthing.admin.toml` means the restore path broke.
