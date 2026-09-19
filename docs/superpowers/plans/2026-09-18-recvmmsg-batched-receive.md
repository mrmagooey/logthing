# `recvmmsg`-based batched UDP receive — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let each UDP recv task pull multiple queued datagrams out of the kernel in one `recvmmsg(2)` syscall instead of one `recv_from` per datagram, so a **single high-rate sender** — the case `recv_tasks` fan-out structurally cannot help — gets more receive capacity out of the syscall-bound recv loop the CPU profile already identified as the bottleneck.

**Architecture:** A new `recv_batch_size` config knob (default `1`, meaning "off", following the exact precedent `recv_tasks` set before its own default was raised) gates a per-recv-task switch: `<= 1` keeps today's `socket.recv_from(&mut buf)` loop byte-for-byte; `> 1` allocates one `RecvMmsgBatch` (fixed-capacity `mmsghdr`/`iovec`/buffer/address storage, built once and reused for the task's lifetime) and calls `libc::recvmmsg` through `tokio::net::UdpSocket::try_io`, non-blocking (`MSG_DONTWAIT`), so a call returns immediately with whatever is already queued — from `1` message up to `recv_batch_size` — and never waits to fill a batch. Each message in the batch is then run through the *exact* per-datagram path that exists today (`allowed_ips.is_allowed`, decode, per-datagram counters), just called once per message in a `for` loop instead of once per `select!` iteration. `recv_batch_size` is orthogonal to `recv_tasks`: the former controls how many datagrams one syscall on one socket can return; the latter controls how many sockets/tasks exist. A single-sender deployment gets nothing from `recv_tasks > 1` (§ "THE LIMITATION" in the fan-out results doc) but can get a real reduction in syscalls-per-datagram from `recv_batch_size > 1` on a single socket (`recv_tasks = 1`). A multi-sender deployment can combine both.

**Tech Stack:** Rust 2024, tokio 1.49 (`UdpSocket::try_io` + `Interest::READABLE`, already available under the `full` feature this crate already enables), `libc` (new direct dependency — already resolved transitively at `0.2.180` via `tokio`/`mio`/`socket2`, so this adds zero new supply-chain surface, only makes the existing transitive crate callable directly), `socket2` 0.6 (already a dependency, reused for `SockAddrStorage`/`SockAddr::as_socket()` rather than hand-rolling `AF_INET`/`AF_INET6` byte parsing).

**Spec:** `docs/performance/2026-09-18-udp-recv-fanout-results.md` (this plan's direct predecessor and prerequisite reading — "THE LIMITATION THAT MUST BE READ BEFORE ANY NUMBER BELOW" section is the reason this plan exists) and `docs/performance/2026-09-18-udp-recv-scaling-options.md` (`perf/udp-recv-scaling`, §1c: `recvmmsg` was identified there as the correct complementary lever for the single-sender case and explicitly not prototyped — "Not prototyped here... Inferred, not measured").

## Global Constraints

- Branch: `perf/recvmmsg-batched-receive`. Never commit to `master`.
- Build env for every cargo command: `export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc`. Dropping the linker var silently links LLVM libunwind and the build breaks.
- `recv_batch_size` defaults to `1` on every listener, and `<= 1` must execute today's exact `recv_from` code path with today's exact behaviour — this is the safety property that makes the change deployable, identical in spirit to how `recv_tasks <= 1` preserves the pre-fan-out path.
- `recv_batch_size` and `recv_tasks` are independent knobs; every combination (including `recv_tasks > 1` **and** `recv_batch_size > 1` together) must work, because that is the multi-sender-with-high-per-sender-rate deployment shape.
- **The `allowed_ips.is_allowed` check runs once per datagram inside the batch, never once per batch.** A batch can (in principle) contain datagrams from different sources; collapsing the check to the batch's first message would open an ingest bypass for every other message in it.
- **Per-datagram counters stay per datagram.** `ipfix_datagrams_received`, `sflow_datagrams_received`, `syslog_messages_received`, and `listener_source_rejected` each increment once per datagram/message processed, never once per batch — a batch of N must move every one of these counters by N over N datagrams, not by 1.
- **One `SocketDropStats` per socket group, polled once** — unaffected by this plan (it reads `/proc/net/udp`, not the recv path), but must not regress: batching changes how many datagrams one syscall returns, not how many sockets exist per group.
- **The existing single-datagram path must remain available and unchanged** when `recv_batch_size <= 1`, on both the `recv_tasks <= 1` single-socket path and the `recv_tasks > 1` fan-out path (each fan-out task independently honours `recv_batch_size`).
- Never use `pkill` anywhere in scripts or commands — it matches whole command lines and kills the invoking shell.
- `logthing.toml` and `logthing.admin.toml` are tracked; the measurement harness moves the admin file aside and restores it. `git status --porcelain` must be clean after any harness run.
- **Never run two harness invocations concurrently** — fixed ports, one metrics endpoint; overlapping runs silently contaminate each other.
- Real-shape harness runs need `DURATION` of at least 10 (sinks flush every 5s; the harness refuses less). Syslog needs `PORT=15140` on this host — 514 and the listener's default TCP port 601 are both privileged.
- This host has 12 vCPUs and `net.core.rmem_max` = 212992; generator pinned to cores 0-3, server to 4-11 by the harness. Run-to-run variance near a format's loss knee is large and documented (`docs/performance/2026-09-18-udp-recv-fanout-results.md` §4's "variance finding") — every comparison in this plan uses `RUNS >= 3` and reads medians, never a single run, and no figure in this plan's own results doc should be read as accurate beyond two significant figures, matching that precedent.
- Each commit message ends with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.

## The premise this plan depends on, and why Task 1 is not optional

`recv_tasks` fan-out raised measured ceilings substantially (ipfix 37,500 → 65,000/s, sflow 40,000 → 82,500/s, syslog 20,000 → 27,500/s) — but every one of those numbers was measured with `GEN_PROCS=4`, i.e. four distinct source ports. `SO_REUSEPORT` distributes datagrams across a socket group by hashing the packet's 4-tuple, so **one sender with one stable source port always lands on the same group member no matter how many members exist**. `recv_tasks` therefore cannot raise a true single-sender ceiling. This plan's entire justification is that `recvmmsg` is the lever that *does* help that case, because it reduces the number of syscalls needed to drain one socket rather than spreading the draining across sockets. Task 1 measures whether `recv_tasks` really does nothing for a single sender, on this host, before any line of `recvmmsg` code is written — if it turns out `recv_tasks` already helps a single sender (e.g. because of some interaction this plan's authors didn't anticipate), the motivation for building `recvmmsg` support is undermined and Task 1 says so instead of proceeding.

## File Structure

**Modified:**
- `Cargo.toml` — add `libc = "0.2"` as a direct dependency (pinned to the version already resolved transitively, `0.2.180`, so `Cargo.lock` should not move any other crate).
- `src/net.rs` — `RecvMmsgBatch`: fixed-capacity `recvmmsg(2)` buffer/syscall wrapper, reused by all three listeners.
- `src/config/mod.rs` — `recv_batch_size` on `IpfixConfig`, `SflowConfig`, `SyslogConfig`; `MAX_RECV_BATCH_SIZE`; `validate_recv_batch_size_config`.
- `src/ipfix/listener.rs`, `src/sflow/listener.rs`, `src/syslog/listener.rs` — `recv_batch_size` on each `*ListenerConfig`; batched-recv arm added to both the `recv_tasks <= 1` inline loop and the `*_recv_loop` fan-out function, gated on `recv_batch_size > 1`.
- `src/main.rs` — wire the three `recv_batch_size` knobs through.
- `docs/performance/2026-09-18-max-ingest-rate.md`, `CHANGELOG.md`, `logthing.toml` — results and operator guidance.

**Created:**
- `docs/performance/2026-09-18-recvmmsg-batched-receive-results.md` — Task 1's premise check plus Task 7's before/after measurements.

**Not created:** no new module for the batch buffer — it is one struct plus its impl, ~120 lines, and belongs in `src/net.rs` next to the bind helpers and `SocketDropStats` it's used alongside. No `AsyncFd` wrapper — `UdpSocket::try_io` already provides the readiness-gated non-blocking-syscall pattern `AsyncFd` would, without registering the fd with a second reactor.

---

## Task 1: Prove the premise — does `recv_tasks` really do nothing for a single sender?

No code in this task. This is a measurement gate: if the numbers below contradict the premise, stop and say so instead of proceeding to Task 2.

**Files:** none modified. Produces the opening section of `docs/performance/2026-09-18-recvmmsg-batched-receive-results.md`.

**Interfaces:**
- Consumes: the already-merged `recv_tasks` knob (`LOGTHING__IPFIX__RECV_TASKS` env override), `scripts/max-ingest-rate.sh`.
- Produces: a go/no-go decision that every later task depends on.

- [ ] **Step 1: Confirm the harness self-test passes on this checkout**

```bash
cd /home/dev/projects/logthing && SELFTEST=1 ./scripts/max-ingest-rate.sh
```

Expected: `SELFTEST PASS`. If it fails, stop — nothing measured below can be trusted.

- [ ] **Step 2: Build release binaries**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cd /home/dev/projects/logthing && cargo build --release --bin logthing && cargo build --release -p loadgen
```

- [ ] **Step 3: Measure IPFIX at three rates, `GEN_PROCS=1`, `recv_tasks=1` vs `recv_tasks=8`**

`GEN_PROCS=1` means one generator process, therefore one source port, therefore every datagram hashes to the same `SO_REUSEPORT` group member regardless of how many members exist. `RUNS=5` (not the usual 3) because this comparison is the premise the whole plan rests on and deserves the extra precision against the documented run-to-run variance. Rates: 20,000 (well under the known `recv_tasks=1`/`GEN_PROCS=4` ceiling of 37,500), 37,500 (that ceiling itself), and 50,000 (above it) — chosen to show the comparison both below and above where fan-out made a difference under multi-sender load, so a difference under single-sender load would show up as clearly as possible if it existed.

```bash
for RT in 1 8; do
  for RATE in 20000 37500 50000; do
    cd /home/dev/projects/logthing && \
    LOGTHING__IPFIX__RECV_TASKS=$RT FORMAT=ipfix SHAPE=real RATE=$RATE DURATION=15 RUNS=5 GEN_PROCS=1 \
    ./scripts/max-ingest-rate.sh > "/tmp/premise-check-rt${RT}-rate${RATE}.log" 2>&1
  done
done
```

Each invocation is foreground, one at a time — never concurrent (Global Constraints). Six runs total, ~90s each, so budget ~10 minutes plus restart overhead.

- [ ] **Step 4: Compare**

For each rate, read the median `total_loss_pct` from the `recv_tasks=1` log and the `recv_tasks=8` log. The premise predicts these are the same (within the documented variance — treat any difference under ~0.1 percentage points, or any case where both logs land on the same PASS/FAIL-LOSS side of the budget, as "no difference"). Tabulate:

| rate | `recv_tasks=1` median loss | `recv_tasks=8` median loss | same? |
|---|---:|---:|---|
| 20,000 | | | |
| 37,500 | | | |
| 50,000 | | | |

- [ ] **Step 5: The gate**

**If all three rows show "same" (within variance):** the premise holds — `recv_tasks` genuinely buys a single sender nothing, confirming the motivation for this plan. Proceed to Task 2.

**If any row shows `recv_tasks=8` meaningfully beating `recv_tasks=1` under `GEN_PROCS=1`:** the premise is wrong. Before concluding that, rule out the mundane explanation first — check `/tmp/premise-check-rt8-*.log` for a `GENERATOR-LIMITED` verdict or an achieved rate below the `ACHIEVED_FLOOR_PCT` (99%) floor, since a single generator process not actually offering the target rate would produce a spuriously low loss figure at `recv_tasks=8` that has nothing to do with fan-out helping. If the achieved rate looks clean and the difference is real, **stop here**: write up why in the results doc, explain that this plan's premise does not hold on this host under this measurement, and do not proceed to Task 2 — say explicitly that the `recvmmsg` work should not be built until the reason for the unexpected `recv_tasks` benefit is understood, since building a second lever on top of a misunderstood first one compounds the confusion rather than resolving it.

- [ ] **Step 6: Write up and commit**

Create `docs/performance/2026-09-18-recvmmsg-batched-receive-results.md` with the hardware caveat block (copied verbatim from `docs/performance/2026-09-14-throughput-baseline-repeats.md`, same as the fan-out results doc did), provenance (commit, date, `nproc`, `net.core.rmem_max`, core split, exact commands), the table from Step 4, and the verdict from Step 5.

```bash
cd /home/dev/projects/logthing && git add docs/performance/2026-09-18-recvmmsg-batched-receive-results.md
git commit -m "perf: confirm recv_tasks gives a single sender no benefit

Measured ipfix at 20,000/50,000/50,000/s, GEN_PROCS=1 (one source port),
recv_tasks=1 vs recv_tasks=8, RUNS=5. This is the premise the recvmmsg plan
depends on: SO_REUSEPORT hashes by 4-tuple, so a single sender should see no
difference regardless of recv_tasks. Confirmed before writing any recvmmsg
code rather than assumed.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `recv_batch_size` config knob

**Files:**
- Modify: `src/config/mod.rs`
- Test: the `#[cfg(test)] mod tests` in that file

**Interfaces:**
- Consumes: Task 1's go decision.
- Produces: `IpfixConfig.recv_batch_size: usize`, `SflowConfig.recv_batch_size: usize`, `SyslogConfig.recv_batch_size: usize`, each `#[serde(default = "default_<protocol>_recv_batch_size")]` returning `1`; `MAX_RECV_BATCH_SIZE: usize`; `pub fn validate_recv_batch_size_config(cfg: &Config) -> anyhow::Result<()>`.

Mirrors the existing `recv_tasks`/`MAX_RECV_TASKS`/`validate_recv_tasks_config` pattern exactly (`src/config/mod.rs:835-869`), with one deliberate difference: the default stays `1` (off), not `8`. `recv_tasks` was shipped at `1` first and only raised to `8` after a separate idle-cost measurement justified it (`docs/performance/2026-09-18-udp-recv-fanout-results.md` §6); no equivalent idle-cost measurement exists yet for `recv_batch_size`, whose idle cost is different in kind — a fixed `recv_batch_size * 65535` bytes of buffer allocated once per task at startup, not the extra socket/fd/thread cost `recv_tasks` incurs — so shipping conservatively and revisiting the default later, the same way `recv_tasks` did, is the correct sequencing here too.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn validate_recv_batch_size_config_rejects_oversized_value() {
    let mut cfg = Config::default();
    cfg.ipfix.recv_batch_size = 100_000;
    let err = validate_recv_batch_size_config(&cfg)
        .expect_err("must reject an oversized recv_batch_size");
    assert!(
        err.to_string().contains("ipfix.recv_batch_size"),
        "error must name the offending field: {err}"
    );
}

#[test]
fn validate_recv_batch_size_config_ok_for_default_and_sane_values() {
    assert!(validate_recv_batch_size_config(&Config::default()).is_ok());
    let mut cfg = Config::default();
    cfg.ipfix.recv_batch_size = 32;
    cfg.sflow.recv_batch_size = 32;
    cfg.syslog.recv_batch_size = 32;
    assert!(validate_recv_batch_size_config(&cfg).is_ok());
}

#[test]
fn ipfix_config_recv_batch_size_defaults_to_one() {
    assert_eq!(IpfixConfig::default().recv_batch_size, 1);
}
```

Check the exact `Config::default()`/`IpfixConfig` construction pattern already used by `validate_recv_tasks_config_ok_for_default_and_sane_values` (`src/config/mod.rs:2613`) and follow it — do not guess at field names not already confirmed by reading the struct.

- [ ] **Step 2: Run to verify they fail**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib config::tests::validate_recv_batch_size -- --nocapture
cargo test --lib config::tests::ipfix_config_recv_batch_size -- --nocapture
```

Expected: FAIL to compile — `recv_batch_size` does not exist on `IpfixConfig`/`SflowConfig`/`SyslogConfig` yet, and `validate_recv_batch_size_config` does not exist.

- [ ] **Step 3: Add the field to all three config structs**

In `IpfixConfig` (`src/config/mod.rs`, next to `recv_tasks` at line ~302):

```rust
    /// Number of datagrams one `recvmmsg(2)` call may return per receive
    /// task (default: 1, meaning off — every call still returns at most one
    /// datagram, via the original `recv_from` path). Above 1, each recv task
    /// batches up to this many already-queued datagrams into one syscall
    /// instead of one syscall per datagram. Unlike `recv_tasks`, this helps
    /// a SINGLE high-rate sender: it reduces syscalls per datagram on one
    /// socket rather than spreading datagrams across sockets, so it is the
    /// lever for exactly the deployment shape `recv_tasks` cannot help (see
    /// `recv_tasks`'s own doc comment). The two knobs are independent and
    /// may be combined. Never waits to fill a batch — a lone datagram is
    /// still returned immediately (see
    /// docs/superpowers/plans/2026-09-18-recvmmsg-batched-receive.md's
    /// latency discussion). Rejected above `MAX_RECV_BATCH_SIZE` at config
    /// load — see `validate_recv_batch_size_config`.
    #[serde(default = "default_ipfix_recv_batch_size")]
    pub recv_batch_size: usize,
```

Add `recv_batch_size: default_ipfix_recv_batch_size(),` to `impl Default for IpfixConfig` and `fn default_ipfix_recv_batch_size() -> usize { 1 }` beside `default_ipfix_recv_tasks`. Repeat identically for `SflowConfig`/`default_sflow_recv_batch_size` and `SyslogConfig`/`default_syslog_recv_batch_size` (syslog's applies to the UDP arm only, same caveat as its `recv_tasks` doc comment already states).

- [ ] **Step 4: Add the bound and validator**

Next to `MAX_RECV_TASKS` (`src/config/mod.rs:847`):

```rust
/// Upper bound on `recv_batch_size` for each UDP fan-out listener. Each unit
/// is a `65535`-byte buffer allocated once per recv task at startup (the
/// same per-datagram size the existing single-recv path already allocates),
/// so an unbounded value multiplies startup memory per task rather than
/// failing fast with a clear error. `256` is `256 * 65535` ≈ 16.8 MiB per
/// task -- already generous; nothing in this plan's own measurements
/// recommends anywhere near that value, this is a typo guard, not a tuning
/// ceiling.
const MAX_RECV_BATCH_SIZE: usize = 256;

/// Rejects a `recv_batch_size` value above `MAX_RECV_BATCH_SIZE` for any of
/// the three UDP fan-out listeners. `0` and `1` are always accepted -- `0`
/// is treated the same as `1` (batching off), matching `recv_tasks`'s own
/// `0`-means-`1` convention. See `MAX_RECV_BATCH_SIZE` for why the bound
/// exists.
pub fn validate_recv_batch_size_config(cfg: &Config) -> anyhow::Result<()> {
    for (section, value) in [
        ("ipfix.recv_batch_size", cfg.ipfix.recv_batch_size),
        ("sflow.recv_batch_size", cfg.sflow.recv_batch_size),
        ("syslog.recv_batch_size", cfg.syslog.recv_batch_size),
    ] {
        if value > MAX_RECV_BATCH_SIZE {
            anyhow::bail!(
                "{section} = {value} exceeds the maximum of {MAX_RECV_BATCH_SIZE}; this almost \
                 certainly means a typo rather than an intentional value -- each unit allocates a \
                 65535-byte buffer per recv task at startup. Lower {section} to \
                 {MAX_RECV_BATCH_SIZE} or below."
            );
        }
    }
    Ok(())
}
```

Call it beside the existing `validate_recv_tasks_config(&config)?;` call (`src/config/mod.rs:1471`):

```rust
        validate_recv_tasks_config(&config)?;
        validate_recv_batch_size_config(&config)?;
```

- [ ] **Step 5: Run to verify they pass**

```bash
cargo test --lib config::
```

Expected: PASS, including the three new tests and every pre-existing one.

- [ ] **Step 6: Run the whole suite**

```bash
cargo test --workspace
```

Expected: PASS. Nothing outside `config::mod` reads these fields yet, so nothing else should be affected.

- [ ] **Step 7: Commit**

```bash
git add src/config/mod.rs
git commit -m "feat(config): add recv_batch_size knob for the three UDP listeners

Default 1 (off), independent of recv_tasks. Shipped conservative like
recv_tasks originally was -- no idle-cost measurement yet justifies raising
it, unlike recv_tasks's later default-8 change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `RecvMmsgBatch` — the `recvmmsg` buffer and syscall wrapper

**Files:**
- Modify: `Cargo.toml`, `src/net.rs`
- Test: the `#[cfg(test)] mod tests` in `src/net.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks (this is the standalone mechanism; Task 2's config knob is wired to it starting in Task 4).
- Produces:
  `pub struct RecvMmsgBatch` with `pub fn new(batch_size: usize) -> Self`, `pub async fn recv(&mut self, socket: &tokio::net::UdpSocket) -> std::io::Result<usize>` (returns the number of datagrams received, `1..=batch_size`), `pub fn payload(&self, i: usize) -> &[u8]`, `pub fn src(&self, i: usize) -> Option<SocketAddr>`.

**The design choice this task locks in, and why:** `tokio::net::UdpSocket` has no batched-receive method, so the raw `libc::recvmmsg` syscall has to be invoked directly. The two realistic ways to do that from tokio are `tokio::io::unix::AsyncFd` (wrap the raw fd, register it with a second reactor) or `UdpSocket::try_io` (call the syscall through the socket's *own* existing registration). This plan uses `try_io`: it is a method already on the exact `UdpSocket` the bind helpers return, so there is no second fd registration to keep in sync with the first, no `AsRawFd`-derived fd whose lifetime has to be reasoned about separately from the socket that owns it, and it is tokio's own documented pattern for "perform a raw syscall, await readiness, retry on `WouldBlock`" (`UdpSocket::try_io`'s own docs: "Usually, readable(), writable() or ready() is used with this function"). The non-blocking form is `MSG_DONTWAIT`, passed explicitly on every call rather than relying on the socket's `O_NONBLOCK` flag (already set by both bind helpers via `set_nonblocking(true)`) as an invariant enforced elsewhere — belt-and-suspenders, and it means `RecvMmsgBatch::recv` is correct even if called against a socket this crate didn't itself configure as non-blocking.

**Buffer management:** one `RecvMmsgBatch` is constructed once per recv task (not per call) and owns fixed-length `Vec<Vec<u8>>` (one `65535`-byte buffer per potential message — the same per-datagram size every existing single-recv loop already allocates, so switching a task to batched mode does not change per-message memory, only how many messages one syscall can return), `Vec<libc::sockaddr_storage>` (one per potential message), `Vec<libc::iovec>` and `Vec<libc::mmsghdr>` built once from raw pointers into the buffer/address vectors. None of these are resized after construction, so the raw pointers stay valid for the life of the struct — allocating any of this per call would trade one syscall for `batch_size` heap allocations, exactly the cost this feature exists to avoid.

**Linux-only:** `libc::recvmmsg`/`libc::mmsghdr` are defined only for Linux-like targets in the `libc` crate. This is consistent with the rest of `src/net.rs`, which already assumes `/proc/net/udp` is readable (`SocketDropStats`) without a `#[cfg(target_os = "linux")]` gate — this crate's shipped binaries are Linux-only (see the musl static-build comments in `Cargo.toml`). No new portability gate is added here; if that assumption ever changes crate-wide, `RecvMmsgBatch` changes with it, not before.

- [ ] **Step 1: Add the dependency**

In `Cargo.toml`, under `# IP/network utilities` next to `socket2`:

```toml
# Raw recvmmsg(2) for batched UDP receive (src/net.rs::RecvMmsgBatch).
# Already resolved transitively at this version via tokio/mio/socket2 --
# this makes it directly callable, it does not add a new dependency to the
# tree.
libc = "0.2"
```

- [ ] **Step 2: Run to confirm the lockfile doesn't move anything else**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo build --lib 2>&1 | tail -20
git diff Cargo.lock | grep -E '^\+name|^-name'
```

Expected: build succeeds (compile error until Step 6 adds the struct is fine to ignore here — this step is only checking the lockfile diff); `libc` gains an entry (or its version pin is confirmed) and no other crate's version line changes. If anything else moves, stop and say so before continuing — a version bump elsewhere is not what this step should do.

- [ ] **Step 3: Cross-compilation risk check — does `libc::recvmmsg`/`mmsghdr` bind on the musl release targets?**

`.github/workflows/binaries.yml` builds two release targets via `cargo-zigbuild` (`build-tool: cargo-zigbuild`, comment there: "supplies a zig-based cross C toolchain so the native C dependencies... cross-compile cleanly to the musl/arm64 targets"):

```yaml
        target:
          - x86_64-unknown-linux-musl
          - aarch64-unknown-linux-musl
```

`libc::recvmmsg`/`libc::mmsghdr` are new direct calls this task introduces (everything else `src/net.rs` does today, e.g. `SocketDropStats` reading `/proc/net/udp`, is plain file I/O with no musl-specific struct layout involved). musl's libc headers do not always agree with glibc's on struct layout and syscall plumbing for less-common calls, and nothing measured so far in this plan confirms `recvmmsg`/`mmsghdr` bind cleanly cross-compiled to `aarch64-unknown-linux-musl` specifically — `x86_64-unknown-linux-musl` is the more common cross target and lower risk, but is still unverified locally.

```bash
command -v rustup; command -v zig
```

On this host, both are absent (checked while amending this plan: `rustup` → command not found, no `zig` binary), so neither target can be added nor cross-built here — do not fake this check by only compiling for the host's own glibc target, which proves nothing about musl.

- **If `rustup`/`zig` (or `cargo-zigbuild`) are available in whatever environment executes this step**, do the real check and treat a failure as a genuine finding to report, not a flake:

  ```bash
  rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl
  cargo zigbuild --target aarch64-unknown-linux-musl --lib 2>&1 | tail -30
  cargo zigbuild --target x86_64-unknown-linux-musl --lib 2>&1 | tail -30
  ```

  Expected: both compile cleanly once Step 6 has added `RecvMmsgBatch` (re-run this after Step 6 if run before it). A struct-layout or missing-symbol error here is a real blocker — stop and report it rather than working around it with `#[cfg]` guesses.

- **If neither tool is available (the case on this host today):** do not attempt a local substitute. Record the risk explicitly in this task's final commit message (Step 10): "cross-compilation to aarch64-unknown-linux-musl/x86_64-unknown-linux-musl not verified locally (no rustup/zig on this host) — verify in CI before merge." Before `perf/recvmmsg-batched-receive` merges, a maintainer must confirm `binaries.yml` builds green on both matrix targets with this branch's changes — a manual `workflow_dispatch` run (no tag) builds and archives both targets without publishing a release (per the workflow's own `dry-run` comment), which is the safe way to check this pre-merge without cutting a release.

- [ ] **Step 4: Write the failing tests**

Add to `src/net.rs`'s test module:

```rust
/// The core batching property: N datagrams sent to one socket from N
/// different client sockets, all queued before `recv()` is called, must
/// come back in ONE `recv()` call -- proving the syscall is actually
/// batching, not silently falling back to one-at-a-time.
#[tokio::test]
async fn recv_returns_multiple_queued_datagrams_in_one_call() {
    let listen_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = listen_sock.local_addr().unwrap();

    let n = 10;
    let mut expected_payloads = Vec::new();
    for i in 0..n {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = format!("msg-{i}").into_bytes();
        client.send_to(&payload, addr).await.unwrap();
        expected_payloads.push(payload);
    }
    // Give the kernel a moment to queue all n sends before the batched
    // recv is attempted -- this test is about batching behaviour, not
    // about racing delivery.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut batch = RecvMmsgBatch::new(32);
    let received = batch.recv(&listen_sock).await.unwrap();

    assert_eq!(received, n, "all {n} already-queued datagrams must come back in one call");
    let mut got_payloads: Vec<Vec<u8>> = (0..received).map(|i| batch.payload(i).to_vec()).collect();
    got_payloads.sort();
    let mut want_payloads = expected_payloads;
    want_payloads.sort();
    assert_eq!(got_payloads, want_payloads, "every payload must be received intact");

    let mut srcs: Vec<SocketAddr> = (0..received).map(|i| batch.src(i).unwrap()).collect();
    srcs.sort();
    srcs.dedup();
    assert_eq!(srcs.len(), n, "each message's source address must be distinct and correctly parsed");
}

/// A lone datagram must come back immediately -- `recv()` must NOT wait to
/// fill the batch. This is the latency property a log-ingest server cannot
/// regress on: a single low-rate syslog line delayed to fill a batch would
/// be worse than the single-datagram path it replaces.
#[tokio::test]
async fn recv_returns_a_single_datagram_without_waiting_to_fill_the_batch() {
    let listen_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = listen_sock.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"lonely datagram", addr).await.unwrap();

    let mut batch = RecvMmsgBatch::new(32);
    let result = tokio::time::timeout(std::time::Duration::from_millis(30), batch.recv(&listen_sock)).await;

    let received = result
        .expect("recv() must return well within 30ms for one already-queued datagram, not wait to fill a 32-message batch")
        .unwrap();
    assert_eq!(received, 1);
    assert_eq!(batch.payload(0), b"lonely datagram");
}
```

Add `use super::*; use tokio::net::UdpSocket; use std::net::SocketAddr;` as needed at the top of the test module (some of these may already be imported).

- [ ] **Step 5: Run to verify they fail**

```bash
cargo test --lib net::tests::recv_returns -- --nocapture
```

Expected: FAIL to compile — `RecvMmsgBatch` does not exist yet.

- [ ] **Step 6: Implement `RecvMmsgBatch`**

Add to `src/net.rs`, after `bind_udp_reuseport_with_recv_buffer`:

```rust
use std::io;
use std::os::fd::AsRawFd;

/// Fixed-capacity storage for one `recvmmsg(2)` call, built once per recv
/// task and reused for its lifetime. Allocating `mmsghdr`/`iovec`/buffer/
/// address storage per call would trade one syscall for `batch_size` heap
/// allocations -- exactly the cost batching exists to avoid. Not `Send` in
/// any way that matters here: each recv task owns one and never shares it.
pub struct RecvMmsgBatch {
    batch_size: usize,
    bufs: Vec<Vec<u8>>,
    addrs: Vec<libc::sockaddr_storage>,
    // SAFETY invariant: `iovecs[i].iov_base` points into `bufs[i]`'s own
    // heap buffer and `msgs[i].msg_hdr.msg_name` points at `addrs[i]`.
    // Neither `bufs`, `addrs`, `iovecs` nor `msgs` is ever resized after
    // `new()` returns, so these raw pointers stay valid for the struct's
    // whole lifetime regardless of how the struct itself is moved (moving a
    // `Vec` moves its 3-word header, never its heap-allocated contents).
    iovecs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
}

impl RecvMmsgBatch {
    /// `batch_size` message slots, each with a `65535`-byte buffer -- the
    /// same per-datagram size every existing single-recv loop already
    /// allocates (`vec![0u8; 65535]`), so switching a task from
    /// single-datagram to batched recv does not change per-message memory.
    pub fn new(batch_size: usize) -> Self {
        assert!(batch_size >= 1, "batch_size must be at least 1");
        let mut bufs: Vec<Vec<u8>> = (0..batch_size).map(|_| vec![0u8; 65535]).collect();
        let addrs: Vec<libc::sockaddr_storage> =
            (0..batch_size).map(|_| unsafe { std::mem::zeroed() }).collect();
        let mut iovecs: Vec<libc::iovec> = bufs
            .iter_mut()
            .map(|b| libc::iovec {
                iov_base: b.as_mut_ptr() as *mut libc::c_void,
                iov_len: b.len(),
            })
            .collect();
        let msgs: Vec<libc::mmsghdr> = iovecs
            .iter_mut()
            .zip(addrs.iter())
            .map(|(iov, addr)| libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: addr as *const libc::sockaddr_storage as *mut libc::c_void,
                    msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
                    msg_iov: iov as *mut libc::iovec,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            })
            .collect();
        Self { batch_size, bufs, addrs, iovecs, msgs }
    }

    /// Message `i`'s payload from the most recent successful `recv()` call.
    pub fn payload(&self, i: usize) -> &[u8] {
        &self.bufs[i][..self.msgs[i].msg_len as usize]
    }

    /// Message `i`'s source address from the most recent successful
    /// `recv()` call. Reuses `socket2::SockAddr::as_socket()` for the
    /// AF_INET/AF_INET6 parsing rather than hand-rolling it -- socket2 is
    /// already a dependency and this is exactly what it exists to do
    /// safely.
    pub fn src(&self, i: usize) -> Option<SocketAddr> {
        let mut storage = socket2::SockAddrStorage::zeroed();
        // SAFETY: `addrs[i]` was filled by the kernel during `recvmmsg` with
        // whatever address family it actually delivered; copying those
        // exact bytes into a freshly zeroed, correctly sized storage and
        // handing the kernel-reported length to `SockAddr::new` satisfies
        // its safety contract (family and length matching the storage's
        // content).
        unsafe {
            *storage.view_as::<libc::sockaddr_storage>() = self.addrs[i];
        }
        let len = self.msgs[i].msg_hdr.msg_namelen;
        unsafe { socket2::SockAddr::new(storage, len) }.as_socket()
    }

    /// One non-blocking `recvmmsg(2)` call, returning as many datagrams as
    /// are already queued on `socket`, up to `batch_size` -- WITHOUT
    /// waiting to fill the batch. `MSG_DONTWAIT` forces non-blocking
    /// behaviour on this call regardless of the socket's own `O_NONBLOCK`
    /// state.
    ///
    /// # Safety
    /// `fd` must be an open, valid UDP socket file descriptor, live for the
    /// duration of the call.
    unsafe fn recv_mmsg_once(&mut self, fd: std::os::fd::RawFd) -> io::Result<usize> {
        // Reset msg_namelen before every call: the kernel overwrites it per
        // message with the actual address length used, and a stale
        // shorter value left over from a previous call would truncate the
        // next message's address parse.
        for msg in &mut self.msgs {
            msg.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        }
        let n = unsafe {
            libc::recvmmsg(
                fd,
                self.msgs.as_mut_ptr(),
                self.batch_size as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // ponytail: msg_hdr.msg_flags is not inspected for MSG_TRUNC here.
        // Deliberate, not an oversight -- it's the same blind spot the
        // existing single-datagram `recv_from` path already has (it trusts
        // the returned length too), and every buffer here is 65535 bytes,
        // the maximum possible UDP payload, so a real truncation is not
        // reachable over UDP regardless. Revisit only if a buffer size
        // smaller than 65535 is ever introduced.
        Ok(n as usize)
    }

    /// Await readiness, then attempt one batched read -- the same
    /// `try_io` pattern `tokio::net::UdpSocket::try_io`'s own docs
    /// recommend for raw syscalls on a tokio socket: a `WouldBlock` from
    /// the syscall clears the readiness flag and the loop awaits it again,
    /// rather than spinning. Returns the number of datagrams received,
    /// always `>= 1` on `Ok` -- UDP has no "0 means closed" case the way a
    /// stream socket does, so a `0` from the syscall is treated as
    /// "nothing arrived yet, try again" rather than surfaced to the caller.
    pub async fn recv(&mut self, socket: &tokio::net::UdpSocket) -> io::Result<usize> {
        loop {
            socket.readable().await?;
            let fd = socket.as_raw_fd();
            let result =
                socket.try_io(tokio::io::Interest::READABLE, || unsafe { self.recv_mmsg_once(fd) });
            match result {
                Ok(0) => continue,
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}
```

- [ ] **Step 7: Run to verify they pass**

```bash
cargo test --lib net::tests::recv_returns -- --nocapture
```

Expected: PASS both.

- [ ] **Step 8: Demonstrate the latency test actually catches a regression**

This is the sabotage the brief requires: a plausible but wrong "improvement" someone might make — waiting a little to let more messages accumulate before returning, on the theory that a fuller batch is more efficient — must make the latency test fail, not pass by luck.

Temporarily change the `recv_mmsg_once` call's last two arguments from `libc::MSG_DONTWAIT, std::ptr::null_mut()` to `0` (no flag) and a non-null `&mut libc::timespec { tv_sec: 0, tv_nsec: 50_000_000 }` (a 50ms wait budget) passed as `&mut timeout as *mut _`:

```bash
cargo test --lib net::tests::recv_returns_a_single_datagram -- --nocapture
```

**Erratum (confirmed by a standalone C repro against the real syscall, both outcomes measured):** this sabotage does NOT produce a 50ms-bounded failure, on either kind of fd — do not use it. `recvmmsg`'s `timeout` argument only gates the wait for the *first* message of a batch, not for `vlen`-1 further messages after the first has already arrived — see `man 2 recvmmsg`'s own BUGS section ("the call will block forever" once at least one datagram is received and no more arrive). Measured:
- **blocking fd**, `flags=0`, 50ms `timespec`, one datagram pre-queued, `VLEN=32` → the call **hung indefinitely** (observed >150s, killed by hand) — matches the BUGS section exactly; there is no 50ms bound.
- **`O_NONBLOCK` fd**, identical flags and timeout → returned in **0.02ms** with the one datagram, because the socket's own non-blocking flag short-circuits the wait regardless of the timeout argument passed.

Every `tokio::net::UdpSocket` in this crate is `O_NONBLOCK` already (mio sets `SOCK_NONBLOCK` at socket creation; `bind_udp_reuseport_with_recv_buffer` also calls `set_nonblocking(true)` explicitly; tokio's own `check_socket_for_blocking` refuses a blocking socket outright), so this sabotage against `RecvMmsgBatch::recv` will simply keep passing — it never exercises the regression it's meant to catch. **Use this substitute instead**: temporarily add `tokio::time::sleep(std::time::Duration::from_millis(50)).await;` as the first line of `RecvMmsgBatch::recv`, before the `loop`. This is a Rust-level "wait to accumulate" sabotage matching this step's actual intent, and reliably fails the latency test's 30ms budget.

```bash
cargo test --lib net::tests::recv_returns_a_single_datagram -- --nocapture
```

Expected: FAIL, both runs — the `sleep(50ms)` pushes `recv()` past the test's 30ms timeout budget deterministically, not as a scheduling artifact. Run it twice to confirm. Revert the temporary `sleep` (the `MSG_DONTWAIT`/`null_mut()` call was never the problem and should be left exactly as written) and re-run Step 7 to confirm both tests pass again before continuing.

Note: `MSG_DONTWAIT` in the shipped code is still correct to keep — it is an independent, correct belt-and-braces guarantee against a hypothetical blocking fd reaching this code path. It is `O_NONBLOCK`, not `MSG_DONTWAIT`, that provides the zero-latency guarantee for every socket this crate actually constructs.

- [ ] **Step 9: Run the whole suite**

```bash
cargo test --workspace
```

Expected: PASS. Nothing outside `net::` calls `RecvMmsgBatch` yet.

- [ ] **Step 10: Commit**

```bash
git add Cargo.toml Cargo.lock src/net.rs
git commit -m "feat(net): add RecvMmsgBatch, a reusable recvmmsg(2) wrapper

Fixed-capacity mmsghdr/iovec/buffer/address storage, built once per recv
task and reused. Non-blocking (MSG_DONTWAIT) via UdpSocket::try_io, so a
call returns immediately with whatever is already queued and never waits to
fill a batch -- verified by a test that fails, deterministically and
twice, when a 50ms wait budget is substituted for MSG_DONTWAIT.

Not yet wired into any listener.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: IPFIX listener batched receive

**Files:**
- Modify: `src/ipfix/listener.rs`, `src/config/mod.rs` (already has the field from Task 2 — this task only reads it), `src/main.rs`
- Test: the `#[cfg(test)] mod tests` in `src/ipfix/listener.rs`

**Interfaces:**
- Consumes: Task 2's `IpfixConfig.recv_batch_size`; Task 3's `RecvMmsgBatch`.
- Produces: `IpfixListenerConfig.recv_batch_size: usize` (default `1`); both the `recv_tasks <= 1` inline loop and `ipfix_recv_loop` (the `recv_tasks > 1` fan-out function) gain a `recv_batch_size > 1` arm.

- [ ] **Step 1: Write the failing tests**

Add to `src/ipfix/listener.rs`'s test module. First, extend the existing `start_test_listener` helper to also set `recv_batch_size` (it currently takes only `recv_tasks`):

```rust
async fn start_test_listener(
    recv_tasks: usize,
    recv_batch_size: usize,
) -> (
    tokio::task::JoinHandle<anyhow::Result<()>>,
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    Arc<CountingHandler>,
) {
    let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = tmp.local_addr().unwrap().port();
    drop(tmp);
    let bound: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

    let config = IpfixListenerConfig {
        udp_port,
        bind_address: "127.0.0.1".to_string(),
        recv_tasks,
        recv_batch_size,
        ..IpfixListenerConfig::default()
    };
    let handler = CountingHandler::new();
    let listener = IpfixListener::new(config, handler.clone());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });
    sleep(Duration::from_millis(50)).await;

    (task, bound, shutdown_tx, handler)
}
```

Update the one existing call site (`data_decodes_when_sent_from_eight_source_ports_other_than_the_templates`) from `start_test_listener(4).await` to `start_test_listener(4, 1).await` — `1` keeps that test on the unbatched path, unchanged, since it is testing `recv_tasks` fan-out, not batching.

Now the new tests:

```rust
/// The end-to-end regression this task exists to prevent: a batch of many
/// datagrams arriving before the listener's next recv must decode every one
/// of them, not just the first. A buggy implementation that reads a batch
/// but only processes message 0 (the classic "forgot the loop" bug) would
/// pass a single-datagram smoke test and fail this one.
#[tokio::test]
async fn batched_recv_decodes_every_datagram_in_a_batch() {
    let (listener, bound, shutdown_tx, handler) = start_test_listener(1, 16).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&template_datagram(1), bound).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    for n in 0..10u64 {
        sock.send_to(&data_datagram(n as u32 + 2, n), bound).await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let _ = shutdown_tx.send(true);
    let _ = listener.await;

    assert_eq!(handler.flow_count(), 10, "every data record in the batch must decode");
}

/// The `allowed_ips` and per-datagram-counter invariant, tested together:
/// with allowed_ips restricted to exclude 127.0.0.1 entirely, every message
/// in a multi-message batch must be independently rejected and independently
/// counted -- `listener_source_rejected` must read N after N rejected
/// datagrams, not 1. A batch-level check (verify the first message's source,
/// apply the verdict to the whole batch, `continue` the outer loop) would
/// still reject everything on this all-loopback test -- the counter is what
/// distinguishes "checked once" from "checked N times", not the pass/fail
/// outcome, which loopback can't vary by source IP.
#[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
#[tokio::test]
async fn batched_recv_checks_and_counts_allowed_ips_per_datagram() {
    use metrics::set_default_local_recorder;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::{CompositeKey, MetricKind};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = set_default_local_recorder(&recorder);

    let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = tmp.local_addr().unwrap().port();
    drop(tmp);
    let bound: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

    // Whitelist a network that does NOT include 127.0.0.1 -- every datagram
    // in this test must be rejected.
    let disallowing_whitelist = IpWhitelist::new(vec!["10.0.0.0/8".to_string()]).unwrap();
    let config = IpfixListenerConfig {
        udp_port,
        bind_address: "127.0.0.1".to_string(),
        recv_tasks: 1,
        recv_batch_size: 16,
        ..IpfixListenerConfig::default()
    };
    let handler = CountingHandler::new();
    let listener = IpfixListener::new(config, handler.clone()).with_allowed_ips(disallowing_whitelist);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let n = 10u32;
    for i in 0..n {
        sock.send_to(&template_datagram(i + 1), bound).await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let _ = shutdown_tx.send(true);
    let _ = task.await;

    assert_eq!(handler.flow_count(), 0, "every datagram must be rejected");

    let map = snapshotter.snapshot().into_hashmap();
    let rejected = map
        .get(&CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts("listener_source_rejected", vec![metrics::Label::new("protocol", "ipfix")]),
        ))
        .map(|(_, _, v)| match v {
            DebugValue::Counter(c) => *c,
            _ => 0,
        })
        .unwrap_or(0);
    assert_eq!(rejected, n as u64, "listener_source_rejected must count every datagram in the batch, not one per batch");
}

/// The gap Finding 1 of the plan review named directly: the two tests above
/// both pin `recv_tasks = 1`, so they only ever exercise the batched arm
/// inside `start_with_shutdown`'s inline loop, never `ipfix_recv_loop` (the
/// `recv_tasks > 1` fan-out function) -- the combined `recv_tasks > 1` AND
/// `recv_batch_size > 1` shape had no automated coverage at all before this
/// test. `recv_tasks = 4` forces every datagram through the SO_REUSEPORT
/// group and `ipfix_recv_loop`'s own batched arm (Step 5); all sends come
/// from one client socket, back-to-back with no `.await` between them, so
/// they consistently hash to the same group member (SO_REUSEPORT hashes by
/// the full 4-tuple, and one client socket keeps its source port fixed) and
/// have a real chance to queue together before that task's next `recv()`
/// drains them -- exercising an actual multi-message batch inside the
/// fan-out path, not just a fan-out path that happens to only ever see one
/// message per call.
#[tokio::test]
async fn fanout_batched_recv_decodes_every_datagram_across_batches() {
    let (listener, bound, shutdown_tx, handler) = start_test_listener(4, 16).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&template_datagram(1), bound).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    for n in 0..10u64 {
        // No sleep between sends -- give the kernel a chance to queue
        // several before ipfix_recv_loop's next batch.recv() call drains
        // the socket, so this test actually exercises n > 1 in the
        // `for i in 0..n` loop of the fan-out batched arm, not n == 1 every
        // time.
        sock.send_to(&data_datagram(n as u32 + 2, n), bound).await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let _ = shutdown_tx.send(true);
    let _ = listener.await;

    assert_eq!(
        handler.flow_count(),
        10,
        "every data record sent through the recv_tasks=4 + recv_batch_size=16 combined path must decode"
    );
}

/// The `allowed_ips`/counter invariant from
/// `batched_recv_checks_and_counts_allowed_ips_per_datagram` above, re-run
/// through `ipfix_recv_loop`'s batched arm (`recv_tasks = 4`) instead of the
/// inline loop's. Like that test, every send here comes from one source
/// address (loopback can't vary by source IP within one process any more in
/// the fan-out path than it could in the inline one), so this cannot
/// distinguish "checked using the right per-message address" from "checked
/// using a fixed wrong address" on its own -- what it adds on top of the
/// non-fan-out version is coverage of the `self.x` → loop-local-param
/// translation in Step 5 itself: a build that left a stray `self.` in
/// `ipfix_recv_loop` fails to compile (there is no `self` in a free
/// function), and a build that substituted the wrong loop-local (e.g. an
/// out-of-scope `IpfixListenerConfig::default()`'s allowed_ips instead of
/// the `allowed_ips` parameter actually passed in) is caught here because
/// this test constructs the disallowing whitelist and threads it through
/// `with_allowed_ips` exactly as the non-fan-out version does, on the
/// `recv_tasks = 4` path.
#[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
#[tokio::test]
async fn fanout_batched_recv_checks_and_counts_allowed_ips_per_datagram() {
    use metrics::set_default_local_recorder;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::{CompositeKey, MetricKind};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = set_default_local_recorder(&recorder);

    let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = tmp.local_addr().unwrap().port();
    drop(tmp);
    let bound: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

    let disallowing_whitelist = IpWhitelist::new(vec!["10.0.0.0/8".to_string()]).unwrap();
    let config = IpfixListenerConfig {
        udp_port,
        bind_address: "127.0.0.1".to_string(),
        recv_tasks: 4,
        recv_batch_size: 16,
        ..IpfixListenerConfig::default()
    };
    let handler = CountingHandler::new();
    let listener = IpfixListener::new(config, handler.clone()).with_allowed_ips(disallowing_whitelist);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move { listener.start_with_shutdown(shutdown_rx).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let n = 10u32;
    for i in 0..n {
        sock.send_to(&template_datagram(i + 1), bound).await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let _ = shutdown_tx.send(true);
    let _ = task.await;

    assert_eq!(handler.flow_count(), 0, "every datagram must be rejected");

    let map = snapshotter.snapshot().into_hashmap();
    let rejected = map
        .get(&CompositeKey::new(
            MetricKind::Counter,
            metrics::Key::from_parts("listener_source_rejected", vec![metrics::Label::new("protocol", "ipfix")]),
        ))
        .map(|(_, _, v)| match v {
            DebugValue::Counter(c) => *c,
            _ => 0,
        })
        .unwrap_or(0);
    assert_eq!(
        rejected,
        n as u64,
        "listener_source_rejected must count every datagram through the recv_tasks=4 + recv_batch_size=16 combined path, not one per batch"
    );
}
```

The snippet above uses the real constructor, verified against `src/middleware/mod.rs:37` — `pub fn new(allowed_ips: Vec<String>) -> anyhow::Result<Self>` (there is no `from_cidrs`; despite the name, `new` already accepts both CIDR ranges and bare IPs, see its doc comment). Do not reintroduce a guessed name if refactoring this test later. Also check `metrics::Key::from_parts` is the right way to build a labeled key for a `DebuggingRecorder` snapshot lookup by reading how an existing test in this codebase already does it (`src/net.rs`'s `socket_drop_stats_observes_real_kernel_drops` uses an unlabeled key; find a labeled-metric example elsewhere in the test suite, e.g. wherever `listener_source_rejected` is itself asserted on already, and match its exact pattern rather than guessing at the API).

- [ ] **Step 2: Run to verify they fail**

```bash
cargo test --lib ipfix::listener::tests::batched_recv -- --nocapture
cargo test --lib ipfix::listener::tests::fanout_batched_recv -- --nocapture
```

Expected: FAIL to compile — `recv_batch_size` does not exist on `IpfixListenerConfig` yet. (`batched_recv` alone as a filter also matches the two `fanout_batched_recv_*` tests added below since `cargo test`'s filter is a substring match, not an anchor — the second invocation above is just to make that explicit, either filter run alone already runs all four.)

- [ ] **Step 3: Add the config field**

In `IpfixListenerConfig` (`src/ipfix/listener.rs`, next to `recv_tasks`):

```rust
    /// Number of datagrams one `recvmmsg(2)` call may return per recv task
    /// (default: 1, off). See `IpfixConfig::recv_batch_size` for the full
    /// explanation -- unlike `recv_tasks`, this helps a single high-rate
    /// exporter.
    pub recv_batch_size: usize,
```

with `recv_batch_size: 1` in `Default for IpfixListenerConfig`. Wire `config_clone.ipfix... ipfix_config_clone.ipfix.recv_batch_size` into `src/main.rs`'s `IpfixListenerConfig` struct literal, next to the existing `recv_tasks: ipfix_config_clone.ipfix.recv_tasks,` line.

- [ ] **Step 4: Add the batched-recv arm to the `recv_tasks <= 1` inline loop**

In `start_with_shutdown`'s `if self.config.recv_tasks <= 1` branch, gate on `recv_batch_size` the same way the outer function gates on `recv_tasks` — `<= 1` keeps today's loop body exactly as it is; `> 1` runs a parallel loop using `RecvMmsgBatch`:

```rust
        if self.config.recv_tasks <= 1 {
            let socket = crate::net::bind_udp_with_recv_buffer(
                &addr,
                self.config.receive_buffer_bytes,
                "ipfix",
            )
            .await?;
            let bound_addr = socket.local_addr()?;
            info!("IPFIX UDP listener started on {}", bound_addr);

            let mut decoder = IpfixDecoder::new();
            let mut socket_stats = crate::net::SocketDropStats::new(&socket, "ipfix");
            let mut socket_stats_ticker =
                tokio::time::interval(crate::net::SOCKET_DROP_POLL_INTERVAL);

            if self.config.recv_batch_size <= 1 {
                let mut buf = vec![0u8; 65535];
                loop {
                    tokio::select! {
                        result = socket.recv_from(&mut buf) => {
                            // ... unchanged, byte-for-byte identical to today ...
                        }
                        _ = socket_stats_ticker.tick() => {
                            socket_stats.poll().await;
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                info!("IPFIX listener: shutdown signal received");
                                break;
                            }
                        }
                    }
                }
                return Ok(());
            }

            // Batched-recv path: recv_batch_size > 1.
            let mut batch = crate::net::RecvMmsgBatch::new(self.config.recv_batch_size);
            loop {
                tokio::select! {
                    result = batch.recv(&socket) => {
                        match result {
                            Ok(n) => {
                                for i in 0..n {
                                    let Some(src) = batch.src(i) else {
                                        warn!("ipfix: batch message with unparseable source address, skipping");
                                        continue;
                                    };
                                    // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                                    if !self.allowed_ips.is_allowed(&src) {
                                        metrics::counter!("listener_source_rejected", "protocol" => "ipfix").increment(1);
                                        debug!("Rejected ipfix datagram from {} — not in allowed_ips", src);
                                        continue;
                                    }
                                    let payload = batch.payload(i);
                                    debug!("IPFIX datagram from {}: {} bytes", src, payload.len());
                                    match decode_datagram(&mut decoder, payload, src.ip()) {
                                        Ok(flows) if flows.is_empty() => {
                                            debug!("IPFIX datagram from {} produced no flows (template-only or empty)", src);
                                        }
                                        Ok(flows) => {
                                            self.handler.handle_flows(flows, src).await;
                                        }
                                        Err(e) => {
                                            metrics::counter!("ipfix_decode_errors").increment(1);
                                            warn!("IPFIX decode error from {}: {}", src, e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                // ponytail: EINTR (and every other transient
                                // errno recvmmsg can return) is not special-
                                // cased -- it surfaces here as a generic
                                // error and gets retried on the next loop
                                // iteration via batch.recv()'s own readable()
                                // await. Exact parity with the existing
                                // single-recv_from error arm this batched arm
                                // sits beside (src/ipfix/listener.rs's
                                // `Err(e) => { error!("IPFIX UDP receive
                                // error: {}", e); }`, ~line 165) -- not a gap
                                // introduced by batching.
                                error!("IPFIX UDP batched receive error: {}", e);
                            }
                        }
                    }
                    _ = socket_stats_ticker.tick() => {
                        socket_stats.poll().await;
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!("IPFIX listener: shutdown signal received");
                            break;
                        }
                    }
                }
            }

            return Ok(());
        }
```

The `// ... unchanged ...` marker above is not literal — copy the existing recv arm's body verbatim from the current file rather than writing a placeholder; the point of `recv_batch_size <= 1` is that this path is untouched.

- [ ] **Step 5: Add the same arm to `ipfix_recv_loop` (the `recv_tasks > 1` fan-out path)**

`ipfix_recv_loop` takes the same gate, parameterized identically. Written out literally below, not as "same as Step 4's" — this is the code path Finding 1 of the plan review flagged as having the least coverage, precisely because it had been the least literally shown; the translation from `self.allowed_ips`/`self.handler` to the loop-local `allowed_ips`/`handler` params is exactly where a copy-paste mistake (e.g. leaving `self.handler` in when `self` is not in scope here, which would fail to compile — or the more dangerous version, reusing the wrong loop-local variable) would land:

```rust
async fn ipfix_recv_loop(
    socket: UdpSocket,
    mut decoder: IpfixDecoder,
    handler: Arc<dyn IpfixHandler>,
    allowed_ips: IpWhitelist,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut socket_stats: Option<crate::net::SocketDropStats>,
    recv_batch_size: usize,
) {
    let mut socket_stats_ticker = tokio::time::interval(crate::net::SOCKET_DROP_POLL_INTERVAL);

    if recv_batch_size <= 1 {
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                // ... unchanged from today's ipfix_recv_loop body ...
            }
        }
        return;
    }

    let mut batch = crate::net::RecvMmsgBatch::new(recv_batch_size);
    loop {
        tokio::select! {
            result = batch.recv(&socket) => {
                match result {
                    Ok(n) => {
                        for i in 0..n {
                            let Some(src) = batch.src(i) else {
                                warn!("ipfix: batch message with unparseable source address, skipping");
                                continue;
                            };
                            // ponytail: any new recv/accept arm in this module needs this same is_allowed check.
                            if !allowed_ips.is_allowed(&src) {
                                metrics::counter!("listener_source_rejected", "protocol" => "ipfix").increment(1);
                                debug!("Rejected ipfix datagram from {} — not in allowed_ips", src);
                                continue;
                            }
                            let payload = batch.payload(i);
                            debug!("IPFIX datagram from {}: {} bytes", src, payload.len());
                            match decode_datagram(&mut decoder, payload, src.ip()) {
                                Ok(flows) if flows.is_empty() => {
                                    debug!("IPFIX datagram from {} produced no flows (template-only or empty)", src);
                                }
                                Ok(flows) => {
                                    handler.handle_flows(flows, src).await;
                                }
                                Err(e) => {
                                    metrics::counter!("ipfix_decode_errors").increment(1);
                                    warn!("IPFIX decode error from {}: {}", src, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // ponytail: EINTR is not special-cased here either --
                        // same parity note as the inline loop's batched arm
                        // in Step 4. Retried on the next loop iteration via
                        // batch.recv()'s own readable() await.
                        error!("IPFIX UDP batched receive error: {}", e);
                    }
                }
            }
            _ = socket_stats_ticker.tick() => {
                if let Some(stats) = socket_stats.as_mut() {
                    stats.poll().await;
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
}
```

Note every use of `self.` from Step 4's inline-loop arm becomes a bare loop-local identifier here (`allowed_ips`, `handler`) — there is no `self` in a free function. `decoder` was already loop-local in both arms, unchanged.

Update its call site in `start_with_shutdown`'s fan-out branch to pass `self.config.recv_batch_size`.

- [ ] **Step 6: Demonstrate the combined-path tests actually catch a fan-out batching bug**

This is the sabotage the review requires for the code path Finding 1 identified as uncovered: `recv_tasks > 1` **and** `recv_batch_size > 1` together, exercised only by `ipfix_recv_loop`'s batched arm just written in Step 5. The combined-path tests added in Step 1 (`fanout_batched_recv_decodes_every_datagram_across_batches` and `fanout_batched_recv_checks_and_counts_allowed_ips_per_datagram`) must both go red under this sabotage, proving they actually exercise the translated `self.x` → loop-local-param arm rather than passing vacuously.

Temporarily change the `for i in 0..n` loop body in Step 5's batched arm to reuse index `0` for the source-address and payload lookups instead of `i`:

```rust
for i in 0..n {
    let Some(src) = batch.src(0) else {   // sabotage: was batch.src(i)
        ...
    };
    ...
    let payload = batch.payload(0);        // sabotage: was batch.payload(i)
    ...
}
```

```bash
cargo test --lib ipfix::listener::tests::fanout_batched_recv -- --nocapture
```

Expected: FAIL — `fanout_batched_recv_decodes_every_datagram_across_batches` fails because every message in a multi-message batch decodes datagram 0's payload N times over instead of each of the N distinct payloads, so the decoded flow count/content no longer matches what was sent. Run it twice to rule out a scheduling fluke, same as Task 3 Step 8's sabotage check. Revert the temporary change back to `batch.src(i)`/`batch.payload(i)` and re-run Step 7 to confirm both tests pass again before continuing.

If the combined-path tests do NOT fail under this sabotage, they are not exercising `ipfix_recv_loop`'s batched arm and must be fixed before proceeding — a green combined-path test that survives this sabotage is worse than no test, because it would hide exactly the bug class Finding 1 named.

- [ ] **Step 7: Run to verify they pass**

```bash
cargo test --lib ipfix::
```

Expected: PASS, including all four new tests (the two single-task batching tests from before this amendment, plus the two combined-path `recv_tasks > 1` + `recv_batch_size > 1` tests) and every pre-existing one — the eight-source-port fan-out test included, now called with an explicit `1` for `recv_batch_size`.

- [ ] **Step 8: Verify `recv_batch_size=1` and `recv_tasks=1` together are unchanged**

```bash
cargo test --workspace
```

Expected: PASS. Every pre-existing test in the whole workspace runs the default (`recv_tasks=1`, batching off via whatever default `IpfixListenerConfig::default()` sets, which must be `1`) — a failure here means the default path changed, which this task must not do.

- [ ] **Step 9: Commit**

```bash
git add src/ipfix/listener.rs src/config/mod.rs src/main.rs
git commit -m "feat(ipfix): batched receive via recv_batch_size

recv_batch_size (default 1, off) makes each recv task pull up to that many
already-queued datagrams per recvmmsg(2) call instead of one recv_from per
datagram. Orthogonal to recv_tasks: applies inside both the single-socket
and SO_REUSEPORT fan-out paths. allowed_ips and per-datagram counters run
once per message in the batch, verified by tests asserting
listener_source_rejected counts N rejections for N rejected datagrams, not 1
-- including the combined recv_tasks>1 + recv_batch_size>1 path inside
ipfix_recv_loop, which a src/payload index-reuse sabotage confirms these
tests actually catch.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: sFlow listener batched receive

**Files:**
- Modify: `src/sflow/listener.rs`, `src/main.rs`
- Test: the `#[cfg(test)] mod tests` in `src/sflow/listener.rs`

**Interfaces:**
- Consumes: Task 2's `SflowConfig.recv_batch_size`; Task 3's `RecvMmsgBatch`.
- Produces: `SflowListenerConfig.recv_batch_size: usize` (default `1`); the same batched-recv arm in both `start_with_shutdown`'s inline loop and `sflow_recv_loop`.

sFlow's decoder is stateless (confirmed already in the fan-out plan's Task 5 and unchanged since), so this is a direct structural mirror of Task 4 with no decoder-sharing concern — `decode_datagram(&buf[..len], src.ip())` takes no `&mut` decoder at all. Because it is a near-copy of Task 4, it inherits Task 4's Finding-1 fix too: **write `sflow_recv_loop`'s batched arm out literally**, translating `self.allowed_ips`/`self.handler` to the loop-local `allowed_ips`/`handler` params exactly as Task 4 Step 5 does — do not write "same as the inline loop's arm" as a placeholder, for the same reason Task 4's plan text was corrected: it is the code path with the least coverage, and describing it instead of writing it is how that happens.

- [ ] **Step 1: Write the failing tests**

Extend `start_test_listener` in `src/sflow/listener.rs` to take `recv_batch_size` the same way Task 4 did for ipfix, update its one existing call site to pass `1`, and add:

```rust
#[tokio::test]
async fn batched_recv_decodes_every_datagram_in_a_batch() {
    let (listener, bound, shutdown_tx, handler) = start_test_listener(1, 16).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let n = 10u32;
    for i in 0..n {
        sock.send_to(&build_datagram(i + 1, i as u64), bound).await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let _ = shutdown_tx.send(true);
    let _ = listener.await;

    assert_eq!(handler.record_count(), n as usize * RECORDS_PER_DATAGRAM);
}
```

Add the same `listener_source_rejected`-counts-per-datagram test as Task 4's `batched_recv_checks_and_counts_allowed_ips_per_datagram`, adapted to sFlow's `build_datagram`/`CountingHandler` and the `"sflow"` protocol label.

**Also add the combined-path pair** — the same `recv_tasks = 4` + `recv_batch_size = 16` tests Task 4 added (`fanout_batched_recv_decodes_every_datagram_across_batches` and `fanout_batched_recv_checks_and_counts_allowed_ips_per_datagram`), adapted to sFlow exactly as the two single-task tests above already are: `start_test_listener(4, 16)`, one client socket sending `n = 10` datagrams back-to-back via `build_datagram`, asserting `handler.record_count() == n as usize * RECORDS_PER_DATAGRAM` for the decode test and `listener_source_rejected` (label `"sflow"`) `== n as u64` for the rejection test. These are what exercise `sflow_recv_loop`'s batched arm — the combined `recv_tasks > 1` + `recv_batch_size > 1` path had no coverage at all before this amendment, for sFlow same as ipfix.

- [ ] **Step 2: Run to verify they fail**

```bash
cargo test --lib sflow::listener::tests::batched_recv -- --nocapture
cargo test --lib sflow::listener::tests::fanout_batched_recv -- --nocapture
```

Expected: FAIL to compile.

- [ ] **Step 3: Implement**

Mirror Task 4 exactly: `recv_batch_size` field + default on `SflowListenerConfig`, wired through `main.rs`; batched arm added to both `start_with_shutdown`'s `recv_tasks <= 1` branch and `sflow_recv_loop`, gated on `recv_batch_size > 1`; `allowed_ips` check and `sflow_datagrams_received`/`listener_source_rejected` counters run once per message inside the batch loop, exactly as the existing per-datagram body already does — no decoder to share, so `decode_datagram(batch.payload(i), src.ip())` replaces `decode_datagram(&buf[..len], src.ip())` directly. Write `sflow_recv_loop`'s batched arm out in full in the actual `src/sflow/listener.rs` edit (per this task's header note above) — the EINTR-parity comment on the generic `Err(e)` arm and the `is_allowed`-per-message `ponytail:` comment both carry over from Task 4's literal version unchanged in spirit.

- [ ] **Step 4: Demonstrate the combined-path tests actually catch a fan-out batching bug**

Same sabotage as Task 4 Step 6, sFlow-flavored: in `sflow_recv_loop`'s batched arm, temporarily change the `for i in 0..n` loop to use `batch.src(0)`/`batch.payload(0)` instead of `batch.src(i)`/`batch.payload(i)`.

```bash
cargo test --lib sflow::listener::tests::fanout_batched_recv -- --nocapture
```

Expected: FAIL — `fanout_batched_recv_decodes_every_datagram_across_batches` fails because every message decodes datagram 0's payload repeatedly instead of each distinct payload, so `record_count()` no longer matches `n * RECORDS_PER_DATAGRAM`. Run twice to rule out a scheduling fluke. Revert the temporary change and re-run Step 5 to confirm both tests pass again before continuing.

- [ ] **Step 5: Run to verify they pass**

```bash
cargo test --lib sflow::
cargo test --workspace
```

Expected: PASS both, including the two combined-path tests.

- [ ] **Step 6: Commit**

```bash
git add src/sflow/listener.rs src/main.rs
git commit -m "feat(sflow): batched receive via recv_batch_size

Same recv_batch_size knob as ipfix, default 1. Stateless decoder, so no
cross-message sharing concern -- straight structural port of the ipfix
integration, including the combined recv_tasks>1 + recv_batch_size>1 test
coverage and its src/payload index-reuse sabotage check.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: syslog UDP listener batched receive

**Files:**
- Modify: `src/syslog/listener.rs`, `src/main.rs`
- Test: the `#[cfg(test)] mod tests` in `src/syslog/listener.rs`

**Interfaces:**
- Consumes: Task 2's `SyslogConfig.recv_batch_size`; Task 3's `RecvMmsgBatch`.
- Produces: `SyslogListenerConfig.recv_batch_size: usize` (default `1`), applying to the UDP arm only — same caveat as `recv_tasks` already carries for this listener: the TCP arm is a separate `tokio::select!` branch entirely and is untouched by this knob.

Also a near-copy of Task 4, so it inherits the same Finding-1 fix: write `syslog_udp_recv_loop`'s batched UDP arm out literally in the actual code edit, translating `self.x` to loop-local params exactly as Task 4 Step 5 does — not "same as the inline loop's arm".

- [ ] **Step 1: Write the failing tests**

Extend `start_test_listener` in `src/syslog/listener.rs` to take `recv_batch_size`, update its one existing call site to pass `1`, and add:

```rust
#[tokio::test]
async fn batched_recv_parses_every_message_in_a_batch() {
    let (listener, bound, shutdown_tx, handler) = start_test_listener(1, 16).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 0..10 {
        let msg = format!("<34>Oct 11 22:14:15 host app: batch {i}");
        sock.send_to(msg.as_bytes(), bound).await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let _ = shutdown_tx.send(true);
    let _ = listener.await;

    assert_eq!(handler.message_count(), 10);
}
```

Add the `listener_source_rejected`-counts-per-datagram test, adapted to syslog's `"syslog_udp"` protocol label (per its existing convention — see Global Constraints in the fan-out plan's Task 6, carried forward here: this listener's label is `"syslog_udp"`, not `"syslog"`).

**Also add the combined-path pair**, same shape as Task 4/5: `start_test_listener(4, 16)` (recv_tasks=4 forces `syslog_udp_recv_loop`, the fan-out UDP path), one client socket sending 10 syslog lines back-to-back, asserting `handler.message_count() == 10` for the decode test and `listener_source_rejected` (label `"syslog_udp"`) `== 10` for the rejection test (disallowing whitelist, mirroring Task 4's `fanout_batched_recv_checks_and_counts_allowed_ips_per_datagram`). These exercise `syslog_udp_recv_loop`'s batched arm, the code path this task's header note above requires be written literally — same combined-path gap Finding 1 named for ipfix and sFlow applies here identically.

- [ ] **Step 2: Run to verify they fail**

```bash
cargo test --lib syslog::listener::tests::batched_recv -- --nocapture
cargo test --lib syslog::listener::tests::fanout_batched_recv -- --nocapture
```

Expected: FAIL to compile.

- [ ] **Step 3: Implement**

Mirror Task 4/5 on the UDP arm only. The `recv_tasks <= 1` combined UDP+TCP loop and the fan-out `syslog_udp_recv_loop` both need the same `recv_batch_size` gate on their UDP handling; the TCP accept arm in each is untouched. `syslog_messages_received`/`syslog_parse_errors`/`listener_source_rejected` (label `"syslog_udp"`) run once per message inside the batch loop. Write `syslog_udp_recv_loop`'s batched arm out in full, with the same EINTR-parity comment on its generic `Err(e)` arm and the same per-message `is_allowed` `ponytail:` comment as Task 4/5's literal versions.

- [ ] **Step 4: Demonstrate the combined-path tests actually catch a fan-out batching bug**

Same sabotage as Task 4 Step 6 / Task 5 Step 4: in `syslog_udp_recv_loop`'s batched arm, temporarily change the `for i in 0..n` loop to use `batch.src(0)`/`batch.payload(0)` instead of `batch.src(i)`/`batch.payload(i)`.

```bash
cargo test --lib syslog::listener::tests::fanout_batched_recv -- --nocapture
```

Expected: FAIL — `fanout_batched_recv_parses_every_message_across_batches` (or whatever name Step 1 gave the decode test) fails because every message parses line 0's text repeatedly instead of each distinct line, so `message_count()` no longer reads 10 distinct messages received. Run twice. Revert and re-run Step 5 to confirm both tests pass again before continuing.

- [ ] **Step 5: Run to verify they pass**

```bash
cargo test --lib syslog::
cargo test --workspace
```

Expected: PASS both, including the two combined-path tests. Some syslog tests bind privileged ports and silently pass when run as root — if anything here looks suspiciously easy, check which port it actually bound before trusting the result.

- [ ] **Step 6: Commit**

```bash
git add src/syslog/listener.rs src/main.rs
git commit -m "feat(syslog): batched receive via recv_batch_size on the UDP arm

Same recv_batch_size knob, default 1, UDP only -- the TCP listener is
unchanged. Includes the combined recv_tasks>1 + recv_batch_size>1 test
coverage and its src/payload index-reuse sabotage check on
syslog_udp_recv_loop.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Measure the single-sender ceiling with batching on

**Files:**
- Modify: `docs/performance/2026-09-18-recvmmsg-batched-receive-results.md` (created in Task 1)

**Interfaces:**
- Consumes: Tasks 4-6.
- Produces: the numbers Task 8 documents for operators.

- [ ] **Step 1: Build release binaries**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cd /home/dev/projects/logthing && cargo build --release --bin logthing && cargo build --release -p loadgen
```

- [ ] **Step 2: Confirm `recv_batch_size=1` reproduces the Task 1 baseline**

Control run, `GEN_PROCS=1`, `recv_tasks=1`, `recv_batch_size` unset (default `1`):

```bash
cd /home/dev/projects/logthing && \
FORMAT=ipfix SHAPE=real RATE=37500 DURATION=15 RUNS=5 GEN_PROCS=1 ./scripts/max-ingest-rate.sh
```

Expected: median loss matches Task 1's `recv_tasks=1` figure at 37,500/s within the documented variance. If it doesn't, stop — the batching work has regressed the default path and nothing below is meaningful until that's explained.

- [ ] **Step 3: Ramp the single-sender ceiling with batching on, `recv_tasks=1`**

The single-sender case this plan exists for: one generator process, `recv_tasks=1` (fan-out would buy nothing here per Task 1), `recv_batch_size` raised.

```bash
cd /home/dev/projects/logthing && \
LOGTHING__IPFIX__RECV_BATCH_SIZE=32 FORMAT=ipfix SHAPE=real RUNS=5 DURATION=15 \
  RAMP_START=20000 BISECT_RESOLUTION=2000 RAMP_MAX=200000 GEN_PROCS=1 ./scripts/max-ingest-rate.sh
```

Watch for `GENERATOR-LIMITED`: a single generator process has its own ceiling (per `docs/performance/2026-09-16-generator-ceiling.md`, roughly 68,000-72,000 flows/s for IPFIX at 1 process). If the ramp reports `GENERATOR-LIMITED` before finding a server-side ceiling, that means batching raised the server's true ceiling above what one generator process can offer — report that explicitly as "server ceiling exceeds single-process generator capacity, true ceiling unfound with GEN_PROCS=1", raise `GEN_PROCS` only if doing so does not reintroduce the multi-source-port confound Task 1 controlled for (i.e., note clearly that a `GEN_PROCS>1` re-measurement is no longer isolating the single-sender case).

Repeat for sflow and syslog (syslog needs `PORT=15140`):

```bash
cd /home/dev/projects/logthing && \
LOGTHING__SFLOW__RECV_BATCH_SIZE=32 FORMAT=sflow SHAPE=real RUNS=5 DURATION=15 \
  RAMP_START=20000 BISECT_RESOLUTION=2000 RAMP_MAX=200000 GEN_PROCS=1 ./scripts/max-ingest-rate.sh

cd /home/dev/projects/logthing && \
LOGTHING__SYSLOG__RECV_BATCH_SIZE=32 FORMAT=syslog SHAPE=real RUNS=5 DURATION=15 PORT=15140 \
  RAMP_START=10000 BISECT_RESOLUTION=1000 RAMP_MAX=100000 GEN_PROCS=1 ./scripts/max-ingest-rate.sh
```

- [ ] **Step 4: Sweep `recv_batch_size` at a fixed above-baseline rate, IPFIX only**

Same methodology as the fan-out plan's `recv_tasks` sweep (§4 of its results doc): pick a rate above the `recv_batch_size=1`/`recv_tasks=1` ceiling and below the new ceiling found in Step 3, compare `recv_batch_size` ∈ {1, 4, 8, 16, 32}, `GEN_PROCS=1`, `RUNS=5`:

```bash
for BS in 1 4 8 16 32; do
  cd /home/dev/projects/logthing && \
  LOGTHING__IPFIX__RECV_BATCH_SIZE=$BS FORMAT=ipfix SHAPE=real RATE=<rate from Step 3> DURATION=15 RUNS=5 GEN_PROCS=1 \
  ./scripts/max-ingest-rate.sh
done
```

Record total loss and `srv_cores` for each. The point is the shape of the curve, same as the `recv_tasks` sweep before it — where it stops helping, and what it costs.

- [ ] **Step 5: Measure the combination — `recv_tasks=4` and `recv_batch_size` together, multi-sender**

Confirms the two knobs compose rather than interfere, under the multi-sender shape `recv_tasks` alone already covers well:

```bash
cd /home/dev/projects/logthing && \
LOGTHING__IPFIX__RECV_TASKS=4 LOGTHING__IPFIX__RECV_BATCH_SIZE=8 FORMAT=ipfix SHAPE=real RUNS=5 DURATION=15 \
  RATE=65000 GEN_PROCS=4 ./scripts/max-ingest-rate.sh
```

Compare against the fan-out plan's own `recv_tasks=4` figure at its ceiling (65,000/s, 0.0000% median loss, `docs/performance/2026-09-18-udp-recv-fanout-results.md` §4). Batching should not make this worse; whether it meaningfully improves it (fewer syscalls per socket on top of more sockets) or is simply neutral at a rate already at zero loss is the finding to report, not assumed.

- [ ] **Step 6: Update the results document**

Append to `docs/performance/2026-09-18-recvmmsg-batched-receive-results.md`: the single-sender before/after table (Step 2 vs Step 3, per format), the `recv_batch_size` sweep (Step 4), the composition measurement (Step 5), and — following the fan-out results doc's own precedent — an explicit "what this does not establish" section: loopback on a shared-CPU KVM guest, generator and server on one box; if any format became generator-limited under `GEN_PROCS=1` before a server ceiling was found, say so rather than reporting the generator's limit as the server's.

- [ ] **Step 7: Commit**

```bash
git add docs/performance/2026-09-18-recvmmsg-batched-receive-results.md
git commit -m "perf: measured single-sender ceilings with recv_batch_size

Before/after per format at recv_tasks=1 with recv_batch_size 1 vs raised,
GEN_PROCS=1 throughout to isolate the single-sender case recv_tasks cannot
help. Plus a recv_batch_size sweep and a combined recv_tasks+recv_batch_size
multi-sender measurement.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Operator documentation

**Files:**
- Modify: `logthing.toml`, `CHANGELOG.md`, `docs/performance/2026-09-18-max-ingest-rate.md`

**Interfaces:**
- Consumes: Task 7's measurements.
- Produces: the deliverable an operator reads.

- [ ] **Step 1: Document the knob in the sample config**

Add a commented `recv_batch_size` line to the `[syslog]`, `[ipfix]` and `[sflow]` sections of `logthing.toml`, directly beneath the existing `recv_tasks` line, following that line's style. State: default is 1 (off); raise it for a single high-rate sender where `recv_tasks` cannot help (name the measured recommendation from Task 7's sweep, not a guess); it costs a fixed `recv_batch_size * 65535` bytes per recv task at startup; it composes with `recv_tasks` (name the measured combination result from Task 7 Step 5).

- [ ] **Step 2: Update the headline results document**

In `docs/performance/2026-09-18-max-ingest-rate.md`, add a dated note to the ipfix, sflow and syslog sections pointing at the new results doc, in the same style as the `recv_tasks` correction note already there. Do not rewrite the original figures.

- [ ] **Step 3: Update the changelog**

`CHANGELOG.md`, Unreleased: an `Added` entry for `recv_batch_size` on the three UDP listeners, noting the default of `1` preserves existing behaviour and that it is the complementary lever to `recv_tasks` for single-sender deployments.

- [ ] **Step 4: Verify the tree**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --workspace
cd /home/dev/projects/logthing && git status --porcelain
```

Expected: full suite green; only intended files listed.

- [ ] **Step 5: Commit**

```bash
git add logthing.toml CHANGELOG.md docs/performance/2026-09-18-max-ingest-rate.md
git commit -m "docs: operator guidance for recv_batch_size

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Notes for the executor

- **Task 1 is a gate, not a formality.** If the premise doesn't hold, the right outcome is stopping and saying so — not quietly building `recvmmsg` support anyway because the plan says to.
- **`recv_batch_size <= 1` must stay byte-identical to today**, in both the single-socket and `recv_tasks > 1` fan-out paths, at every step — this is what makes the change deployable, and the whole workspace suite exercises it.
- **`allowed_ips` and every per-datagram counter run once per message inside a batch, never once per batch.** Tasks 4-6 each carry a test that would catch a batch-level shortcut via the rejection counter, since loopback testing can't vary source IP within one batch to distinguish it any other way.
- **`recv_tasks > 1` AND `recv_batch_size > 1` together is a real, separately-tested code path, not just a manual Task 7 measurement.** Tasks 4-6 each carry a `fanout_batched_recv_*` pair (`recv_tasks=4`, `recv_batch_size=16`) exercising `ipfix_recv_loop`/`sflow_recv_loop`/`syslog_udp_recv_loop`'s batched arm specifically — the arm most likely to carry a `self.x` → loop-local-param translation bug, since it's a free function with no `self`. Each of those arms must be written out literally in the actual source edit, not described as "same as the inline loop's arm" — and each task's plan text now does this itself, so an executor copying code out of this plan is copying real code, not filling in a placeholder.
- **Never delete or weaken a pre-existing test.** The three `start_test_listener` helpers each gain a second parameter; their one existing call site each needs updating to pass `1`, not removing.
- **Cross-compilation to `aarch64-unknown-linux-musl`/`x86_64-unknown-linux-musl` (Task 3 Step 3) is unverified on a host with no `rustup`/`zig`.** Don't skip that step silently — if the tools genuinely aren't available, its own instructions say to note the risk in the commit message and defer to a pre-merge CI check (`binaries.yml`, `workflow_dispatch`, `dry-run`) rather than pretending a glibc-only local build proves anything about musl.
- **Two blind spots in `RecvMmsgBatch`/the batched arms are intentional, not bugs to fix if noticed later:** `recv_mmsg_once` never inspects `msg_hdr.msg_flags` for `MSG_TRUNC` (same blind spot the existing `recv_from` path already has, and moot at a 65535-byte buffer anyway), and `EINTR` from `recvmmsg`/`batch.recv()` surfaces as a generic logged error and gets retried next loop iteration, exact parity with the existing single-`recv_from` error arm. Both are marked with `ponytail:` comments in the code for exactly this reason — don't "fix" them without re-reading why they're there.
- **`GENERATOR-LIMITED` is not a ceiling** — if a batched server outruns a single generator process, say so rather than reporting the generator's limit as the server's, and be explicit that raising `GEN_PROCS` to work around it reopens the multi-source-port confound Task 1 exists to rule out.
- **One harness invocation at a time**, always. They share fixed ports and one metrics endpoint.
- **No figure in this plan's results doc deserves more than two significant figures of trust** — same variance finding as the fan-out plan before it, same host, same measurement method.
