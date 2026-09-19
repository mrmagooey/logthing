# UDP Receive Fan-Out Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let each UDP listener drain its socket from N tasks instead of one, turning idle cores into receive capacity, without the correctness risk the prototype carried.

**Architecture:** `SO_REUSEPORT` puts N sockets on one port, each with its own recv task, behind a `recv_tasks` config knob defaulting to 1 (today's behaviour). IPFIX's template cache moves behind an `Arc<RwLock<_>>` shared by every task, so a datagram decodes correctly on whichever task receives it — correctness stops depending on how the kernel steers packets. sFlow and syslog decoders are already stateless and need no equivalent argument.

**Tech Stack:** Rust 2024, tokio, `socket2` (already a dependency — check `Cargo.toml` before adding anything), `metrics`.

**Spec:** `docs/performance/2026-09-18-udp-recv-scaling-options.md` (on branch `perf/udp-recv-scaling`, commit `68ea1d6`). Read it before Task 1; §2.1 explains the risk this plan's shared cache eliminates, and §3 has the measurement that motivates the work.

**Prototype to port from, not merge:** branch `perf/udp-recv-scaling` (`68ea1d6`) holds a working IPFIX-only prototype marked `// ponytail: PROTOTYPE`. Its `bind_udp_reuseport_with_recv_buffer` and `parse_proc_net_udp` changes are directly reusable. Its per-task-decoder design is NOT — this plan replaces it with a shared cache.

## Global Constraints

- Branch: `perf/udp-recv-fanout`. Never commit to `master`.
- Build env for every cargo command: `export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc`. Dropping the linker var silently links LLVM libunwind and the build breaks.
- `recv_tasks` defaults to `1` on every listener, and `1` must execute today's code path with today's behaviour. This is the safety property that makes the change deployable.
- **Never use `pkill`** — it matches whole command lines and kills the invoking shell (symptom: bare exit 144, no output). Stop processes by pid.
- `logthing.toml` and `logthing.admin.toml` are TRACKED. The measurement harness moves the admin file aside and restores it. `git status --porcelain` must be clean after any harness run.
- **Never run two harness invocations concurrently** — fixed ports, one metrics endpoint; overlapping runs silently contaminate each other.
- Real-shape harness runs need `DURATION` of at least 10 (sinks flush every 5s; the harness refuses less). Syslog needs `PORT=15140` on this host — 514 and the listener's default TCP port 601 are both privileged.
- Each commit message ends with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.

**Prerequisite:** branch `fix/harness-drop-aggregation` (`89dd749`) must be merged to `master` before Task 7. It fixes `scripts/max-ingest-rate.sh` to sum drops across every socket on a port; without it the harness reads one socket of N, disagrees with the in-process counter, and aborts every fanned-out run. This was hit empirically at 100,000/s, not hypothesised.

## Measured baseline this plan must beat

From `docs/performance/2026-09-18-max-ingest-rate.md`, all real-shape, 3 runs/rate, 0.1% total-loss budget:

| format | ceiling today | loss site | server CPU at ceiling |
|---|---|---|---|
| syslog | 20,000/s | kernel socket buffer | ~1.1 of 8 cores |
| ipfix | 37,500/s | kernel socket buffer | ~0.9 of 8 cores |
| sflow | 40,000/s | kernel socket buffer | ~1.2 of 8 cores |

`writer_drops` and `buffer_drops` are `0` in every row at every rate — all loss is in the kernel, and seven of eight cores sit idle.

---

## File Structure

**Modified:**
- `src/ipfix/decoder.rs` — `IpfixDecoder.cache` becomes a shared, lock-protected `TemplateCache`; accessor methods replace direct field access. The decode paths and the capacity bound keep their current semantics.
- `src/net.rs` — add `bind_udp_reuseport_with_recv_buffer`; `parse_proc_net_udp` sums every matching line instead of returning the first.
- `src/ipfix/listener.rs`, `src/sflow/listener.rs`, `src/syslog/listener.rs` — N-socket fan-out path, gated on `recv_tasks`.
- `src/config/mod.rs` — `recv_tasks` on `IpfixConfig`, `SflowConfig`, `SyslogConfig`.
- `src/main.rs` — wire the three knobs through.
- `docs/performance/2026-09-18-max-ingest-rate.md`, `CHANGELOG.md`, `logthing.toml` — results and operator guidance.
- `scripts/max-ingest-rate.sh` — Task 7 needs a way to set `recv_tasks` in the config the harness generates. Small addition to `write_config`, not a redesign.

**Created:**
- `docs/performance/2026-09-18-udp-recv-fanout-results.md` — before/after measurements.

**Not created:** no new module for the shared cache. It is ~40 lines and belongs with the decoder that owns it. No eBPF steering program — the shared cache makes kernel steering irrelevant to correctness, which is why that option was dropped.

---

## Task 1: Shared template cache in the IPFIX decoder

No fan-out yet. This task alone must leave behaviour bit-identical, so it can be reviewed on correctness rather than on performance.

**Files:**
- Modify: `src/ipfix/decoder.rs`
- Test: the existing `#[cfg(test)] mod tests` in that file

**Interfaces:**
- Consumes: nothing.
- Produces: `IpfixDecoder` becomes `Clone` (a cheap `Arc` clone sharing one cache). New accessors, replacing direct `.cache` field access:
  `cache_get(&self, key: &TemplateKey) -> Option<Vec<FieldSpecifier>>`,
  `cache_len(&self) -> usize`, `cache_contains_key(&self, key: &TemplateKey) -> bool`,
  `cache_is_empty(&self) -> bool`, and the existing
  `try_insert_template(&self, key: TemplateKey, fields: Vec<FieldSpecifier>)` (note: `&self`, not `&mut self`).
  `decode_datagram`'s signature is unchanged — it keeps taking `&mut IpfixDecoder`, so no call site outside this file moves.

- [ ] **Step 1: Write the failing test**

Add to `src/ipfix/decoder.rs`'s test module:

```rust
/// The decisive property this plan turns on: two decoder handles share one
/// template cache, so a template learned through one is visible through the
/// other. This is what lets any recv task decode any datagram, and it is
/// what removes the dependence on the kernel steering an exporter's packets
/// to a fixed socket.
#[test]
fn cloned_decoders_share_one_template_cache() {
    let a = IpfixDecoder::new();
    let b = a.clone();
    let key: TemplateKey = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 0, 256);
    let fields = vec![FieldSpecifier { ie_id: 8, length: 4, enterprise_number: None }];

    a.try_insert_template(key, fields.clone());

    assert_eq!(
        b.cache_get(&key).map(|f| f.len()),
        Some(1),
        "a template inserted through one handle must be visible through the other"
    );
    assert_eq!(a.cache_len(), b.cache_len(), "both handles see one cache");
}

/// The capacity bound must be enforced across ALL handles, not per handle —
/// otherwise N recv tasks would each admit MAX_CACHED_TEMPLATES entries and
/// the flood protection would be N times weaker than documented.
#[test]
fn template_capacity_bound_is_shared_across_handles() {
    let a = IpfixDecoder::new();
    let b = a.clone();
    let exporter = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    for i in 0..MAX_CACHED_TEMPLATES {
        a.try_insert_template((exporter, 0, i as u16), vec![]);
    }
    assert_eq!(a.cache_len(), MAX_CACHED_TEMPLATES);

    b.try_insert_template((exporter, 1, 9999), vec![]);
    assert_eq!(
        b.cache_len(),
        MAX_CACHED_TEMPLATES,
        "inserting through a second handle must not exceed the shared bound"
    );
    assert!(!b.cache_contains_key(&(exporter, 1, 9999)));
}
```

Check the exact field names of `FieldSpecifier` in this file before writing the literal above — if it has more fields, fill them in rather than guessing.

- [ ] **Step 2: Run to verify it fails**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib ipfix::decoder::tests::cloned_decoders_share -- --nocapture
```

Expected: FAIL to compile — `IpfixDecoder` does not implement `Clone`, and `cache_get`/`cache_len` do not exist.

- [ ] **Step 3: Implement the shared cache**

Replace the struct and its insert method:

```rust
/// The template map plus the one-shot warning flag, together under a single
/// lock. They are one unit of state: the flag describes whether we have
/// already warned about *this* map being full, so splitting them would let
/// the warning and the capacity check disagree.
#[derive(Debug, Default)]
pub(crate) struct TemplateCache {
    map: HashMap<TemplateKey, Vec<FieldSpecifier>>,
    limit_warned: bool,
}

/// Decoder handle. Cloning yields another handle onto the SAME template
/// cache, which is what lets N recv tasks decode each other's exporters'
/// data. Read-mostly: a template is written once per exporter re-send
/// interval and read once per data set, so an `RwLock` read is the common
/// path and it is cheap against a syscall-bound receive loop.
#[derive(Debug, Clone, Default)]
pub struct IpfixDecoder {
    cache: Arc<RwLock<TemplateCache>>,
}

impl IpfixDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn cache_get(&self, key: &TemplateKey) -> Option<Vec<FieldSpecifier>> {
        self.cache.read().expect("template cache lock poisoned").map.get(key).cloned()
    }

    pub(crate) fn cache_len(&self) -> usize {
        self.cache.read().expect("template cache lock poisoned").map.len()
    }

    pub(crate) fn cache_contains_key(&self, key: &TemplateKey) -> bool {
        self.cache.read().expect("template cache lock poisoned").map.contains_key(key)
    }

    pub(crate) fn cache_is_empty(&self) -> bool {
        self.cache.read().expect("template cache lock poisoned").map.is_empty()
    }

    /// Insert `fields` for `key`, enforcing the capacity bound.
    ///
    /// - If `key` already exists the entry is updated unconditionally.
    /// - If `key` is new and the cache is at `MAX_CACHED_TEMPLATES` capacity,
    ///   the insert is refused, `ipfix_templates_dropped` is incremented, and a
    ///   warning is logged (at most once until capacity drops below the limit).
    pub(crate) fn try_insert_template(&self, key: TemplateKey, fields: Vec<FieldSpecifier>) {
        let mut guard = self.cache.write().expect("template cache lock poisoned");
        if !guard.map.contains_key(&key) && guard.map.len() >= MAX_CACHED_TEMPLATES {
            metrics::counter!("ipfix_templates_dropped").increment(1);
            if !guard.limit_warned {
                tracing::warn!(
                    "ipfix: template cache full ({MAX_CACHED_TEMPLATES} entries); \
                     new template from exporter {} (domain {}, id {}) dropped. \
                     Possible template flood — check for spoofed UDP sources.",
                    key.0,
                    key.1,
                    key.2,
                );
                guard.limit_warned = true;
            }
            return;
        }
        if guard.map.len() < MAX_CACHED_TEMPLATES {
            guard.limit_warned = false;
        }
        guard.map.insert(key, fields);
    }
}
```

Add `use std::sync::{Arc, RwLock};` at the top. Delete the old `impl Default for IpfixDecoder` if the derive now covers it.

- [ ] **Step 4: Update the read path and every direct `.cache` use**

The read path at roughly `src/ipfix/decoder.rs:588` currently does `decoder.cache.get(&key)` and clones on hit. Replace with:

```rust
    let fields = match decoder.cache_get(&key) {
        Some(f) => f,
        None => {
            metrics::counter!("ipfix_templates_missing").increment(1);
            tracing::debug!(
                "ipfix: no cached template for key ({exporter}, {obs_domain_id}, {set_id}) — skipping data set"
            );
            return Ok(Vec::new());
        }
```

Note this removes a `.clone()` — `cache_get` already returns an owned `Vec`, so the value is cloned once under the read lock rather than twice.

There are 6 non-test and 21 test uses of `.cache` in this file. Convert every one to the accessors: `dec.cache.insert(k, v)` → `dec.try_insert_template(k, v)`, `dec.cache.get(&k)` → `dec.cache_get(&k)`, `dec.cache.len()` → `dec.cache_len()`, `dec.cache.contains_key(&k)` → `dec.cache_contains_key(&k)`, `dec.cache.is_empty()` → `dec.cache_is_empty()`. Tests that asserted on `dec.template_limit_warned` directly must now assert on observable behaviour instead — the flag is private state behind the lock; assert that a further insert is refused rather than reading the flag.

Several tests declare `let mut dec = ...`; with `&self` methods the `mut` becomes unnecessary and will warn. Drop it where the compiler says so.

- [ ] **Step 5: Run the full decoder suite**

```bash
cargo test --lib ipfix::decoder
```

Expected: PASS, including the two new tests and every pre-existing one. **No pre-existing test may be deleted or weakened to make this compile** — if one cannot be expressed through the accessors, say so rather than removing it.

- [ ] **Step 6: Run the whole suite to catch outside callers**

```bash
cargo test --workspace
```

Expected: PASS. `decode_datagram`'s signature is unchanged, so listeners and benches should not need edits. If something does, it was reaching into `.cache` from outside — report it.

- [ ] **Step 7: Commit**

```bash
git add src/ipfix/decoder.rs
git commit -m "refactor(ipfix): share the template cache behind a lock

Cloning an IpfixDecoder now yields another handle onto the same cache, so a
template learned by one holder is visible to all. Behaviour for a single
holder is unchanged; this is the groundwork that lets N recv tasks decode
each other's exporters without depending on how the kernel steers packets.

The capacity bound and its one-shot warning move under the same lock, so N
holders cannot each admit MAX_CACHED_TEMPLATES entries.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Sum socket drops across every socket on a port

**Files:**
- Modify: `src/net.rs`
- Test: the `#[cfg(test)] mod tests` in that file

**Interfaces:**
- Consumes: nothing.
- Produces: `parse_proc_net_udp(contents: &str, needle: &str) -> Option<ProcNetUdpEntry>` — takes the file's TEXT rather than reading the file, so it is testable against fixtures, and sums `rx_queue`/`drops` across every matching line instead of returning the first.

`SocketDropStats` polls `/proc/net/udp` for the line matching its socket's `local_address:port`. With `SO_REUSEPORT` there are N lines for one address:port, differing only by inode. Returning the first silently under-reports the other N-1 sockets' drops — and because the measurement harness cross-checks this counter against `/proc/net/udp` and aborts on disagreement, under-reporting makes the format unmeasurable rather than merely mismeasured.

This is a real bug fix independent of fan-out: it was latent the moment any protocol got a second socket on one port.

- [ ] **Step 1: Write the failing tests**

```rust
/// Two sockets on the same address:port — the shape SO_REUSEPORT produces.
/// Differing inodes, same local_address. Both lines must be counted.
const FIXTURE_PROC_NET_UDP_REUSEPORT: &str = "\
  sl  local_address rem_address   st tx_queue:rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:1F49 00000000:0000 07 00000000:00000100 00:00000000 00000000     0        0 12345 2 0000000000000000 11
  101: 00000000:1F49 00000000:0000 07 00000000:00000200 00:00000000 00000000     0        0 12346 2 0000000000000000 31
";

#[test]
fn parse_proc_net_udp_sums_all_matching_lines() {
    let entry = parse_proc_net_udp(FIXTURE_PROC_NET_UDP_REUSEPORT, "00000000:1F49")
        .expect("both reuseport lines must parse");
    assert_eq!(entry.drops, 42, "drops must be summed across both sockets, not taken from the first");
    assert_eq!(entry.rx_queue, 0x300, "rx_queue must be summed too");
}

/// The single-socket case — every deployment today — must be untouched by
/// the summing change.
#[test]
fn parse_proc_net_udp_single_match_unaffected_by_summing() {
    let entry = parse_proc_net_udp(FIXTURE_PROC_NET_UDP, "00000000:1F49")
        .expect("port 0x1F49 line must parse");
    assert_eq!(entry.rx_queue, 0x100);
}

#[test]
fn parse_proc_net_udp_returns_none_when_no_line_matches() {
    assert!(parse_proc_net_udp(FIXTURE_PROC_NET_UDP_REUSEPORT, "00000000:DEAD").is_none());
}
```

`FIXTURE_PROC_NET_UDP` already exists in this file — reuse it, do not redefine it. Check its existing `drops` value and make the second assertion match reality rather than the number written above.

- [ ] **Step 2: Run to verify they fail**

```bash
cargo test --lib net::tests::parse_proc_net_udp -- --nocapture
```

Expected: the summing test fails (reports the first line's drops only); the none-case may already pass.

- [ ] **Step 3: Implement**

Port the implementation verbatim from the prototype — it is already written and correct:

```bash
git show perf/udp-recv-scaling:src/net.rs | sed -n '165,205p'
```

It accumulates into a `ProcNetUdpEntry { rx_queue: 0, drops: 0 }`, tracks a `matched` flag, `continue`s past malformed lines, and returns `None` when nothing matched. Keep the field-count and hex-parsing guards exactly as they are — `/proc/net/udp` lines vary across kernel versions and the guards are what stop a format change becoming a panic.

Update the caller that currently passes a file path so it reads the file and passes the contents.

- [ ] **Step 4: Run to verify they pass**

```bash
cargo test --lib net::
```

Expected: PASS, including the pre-existing `socket_drop_stats_observes_real_kernel_drops` test, which floods an unread socket and asserts the counter moves.

- [ ] **Step 5: Commit**

```bash
git add src/net.rs
git commit -m "fix(net): sum socket drops across every socket sharing a port

parse_proc_net_udp returned the first matching /proc/net/udp line. With one
socket per port that is correct; with SO_REUSEPORT it silently reports one
socket of N. Now sums, and takes the file contents so it is testable against
fixtures rather than only against the live kernel.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `SO_REUSEPORT` bind helper

**Files:**
- Modify: `src/net.rs`
- Test: the `#[cfg(test)] mod tests` in that file

**Interfaces:**
- Consumes: nothing.
- Produces: `pub async fn bind_udp_reuseport_with_recv_buffer(addr: &SocketAddr, requested: Option<usize>, protocol: &str) -> std::io::Result<UdpSocket>`.

- [ ] **Step 1: Write the failing test**

```rust
/// Two sockets must be able to share one address:port under SO_REUSEPORT —
/// without it the second bind fails with EADDRINUSE. Port 0 lets the kernel
/// pick, then the second binds explicitly to whatever it chose.
#[tokio::test]
async fn reuseport_allows_two_sockets_on_one_port() {
    let first = bind_udp_reuseport_with_recv_buffer(
        &"127.0.0.1:0".parse().unwrap(), None, "test_proto",
    )
    .await
    .expect("first reuseport bind");
    let addr = first.local_addr().expect("local addr");

    let second = bind_udp_reuseport_with_recv_buffer(&addr, None, "test_proto")
        .await
        .expect("second bind on the same port must succeed under SO_REUSEPORT");

    assert_eq!(first.local_addr().unwrap(), second.local_addr().unwrap());
}

/// A plain bind must still refuse to share a port — proving the test above
/// demonstrates SO_REUSEPORT rather than some ambient permissiveness.
#[tokio::test]
async fn plain_bind_still_refuses_a_shared_port() {
    let first = bind_udp_with_recv_buffer(&"127.0.0.1:0".parse().unwrap(), None, "test_proto")
        .await
        .expect("first plain bind");
    let addr = first.local_addr().expect("local addr");

    assert!(
        bind_udp_with_recv_buffer(&addr, None, "test_proto").await.is_err(),
        "a second plain bind on the same port must fail"
    );
}
```

- [ ] **Step 2: Run to verify they fail**

```bash
cargo test --lib net::tests::reuseport -- --nocapture
cargo test --lib net::tests::plain_bind -- --nocapture
```

Expected: the first fails to compile (function missing); the second should already pass and exists to keep the first honest.

- [ ] **Step 3: Implement**

Port verbatim from the prototype:

```bash
git show perf/udp-recv-scaling:src/net.rs | sed -n '54,92p'
```

It mirrors `bind_udp_with_recv_buffer` exactly, adding `sock.set_reuse_port(true)?`, and keeps the `SO_RCVBUF` readback that warns when the kernel clamps the request — which it does on this host, where `net.core.rmem_max` is 212992 against a 4 MiB request. `socket2` is already a dependency; confirm in `Cargo.toml` before adding anything.

- [ ] **Step 4: Run to verify they pass**

```bash
cargo test --lib net::
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/net.rs
git commit -m "feat(net): add a SO_REUSEPORT UDP bind helper

Lets N sockets share one port so N tasks can drain it. Same SO_RCVBUF
handling and clamp warning as the existing bind helper.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: IPFIX listener fan-out

**Files:**
- Modify: `src/ipfix/listener.rs`, `src/config/mod.rs`, `src/main.rs`
- Test: the `#[cfg(test)] mod tests` in `src/ipfix/listener.rs`

**Interfaces:**
- Consumes: Task 1's `IpfixDecoder: Clone` sharing one cache; Task 2's summed `parse_proc_net_udp`; Task 3's `bind_udp_reuseport_with_recv_buffer`.
- Produces: `IpfixListenerConfig.recv_tasks: usize` (default 1) and `IpfixConfig.recv_tasks: usize` (`#[serde(default = "default_ipfix_recv_tasks")]`, returning 1).

**The design point that makes this safe.** The prototype gave each recv task its own decoder, so correctness depended on the kernel always steering an exporter's template and data datagrams to the same socket — true while its source port is stable, false if it rotates (NAT rebinding, multi-socket senders), and the failure is silent data loss. With Task 1's shared cache that dependence is gone: any task can decode any exporter's data because they all read one cache. Clone the decoder handle per task; do not construct one per task.

- [ ] **Step 1: Write the failing test**

```rust
/// The decisive test for this plan. Templates arrive from one source port
/// and data from a DIFFERENT one, so under SO_REUSEPORT they hash to
/// different sockets and are received by different tasks. With a shared
/// template cache every data set still decodes. With the prototype's
/// per-task decoders this test fails — which is exactly the silent
/// data-loss path it exists to close.
#[tokio::test]
async fn data_decodes_when_template_and_data_arrive_on_different_sockets() {
    let (listener, bound, shutdown_tx, handler) = start_test_listener(4).await;

    // Separate client sockets => different source ports => different
    // SO_REUSEPORT group members.
    let template_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let data_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_ne!(
        template_sock.local_addr().unwrap().port(),
        data_sock.local_addr().unwrap().port(),
        "the two client sockets must differ, or this test proves nothing"
    );

    template_sock.send_to(&template_datagram(1), bound).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    for n in 0..50u64 {
        data_sock.send_to(&data_datagram(n as u32 + 2, n), bound).await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let _ = shutdown_tx.send(true);
    let _ = listener.await;

    assert_eq!(
        handler.flow_count(), 50,
        "every data record must decode even though its template arrived on another socket"
    );
}
```

Build `start_test_listener(recv_tasks)`, `template_datagram(seq)`, `data_datagram(seq, n)` and the counting handler from whatever this module's existing tests already use — read them first and reuse their helpers rather than inventing parallel ones. `tools/loadgen/src/ipfix_udp.rs` has known-good `build_template_datagram` / `build_data_datagram` byte layouts if you need a reference for the wire format.

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --lib ipfix::listener::tests::data_decodes_when_template -- --nocapture
```

Expected: FAIL to compile until `recv_tasks` exists. Once it compiles but before the shared cache is wired in, it should fail on the flow count — if it passes immediately, the two client sockets probably hashed to the same group member; assert on that explicitly rather than accepting a lucky pass.

- [ ] **Step 3: Add the config knob**

In `src/ipfix/listener.rs`, add to `IpfixListenerConfig`:

```rust
    /// Number of `SO_REUSEPORT` sockets, each drained by its own task. `1`
    /// (the default) uses a single plain socket and is byte-for-byte today's
    /// behaviour. Above 1, the kernel fans datagrams across the group; all
    /// tasks share one template cache, so any task can decode any exporter.
    pub recv_tasks: usize,
```

with `recv_tasks: 1` in its `Default`. In `src/config/mod.rs`, add to `IpfixConfig`:

```rust
    /// Number of UDP receive tasks (default: 1). Raise to spread socket
    /// draining across cores when the kernel is dropping datagrams while CPU
    /// sits idle. See docs/performance/2026-09-18-udp-recv-fanout-results.md.
    #[serde(default = "default_ipfix_recv_tasks")]
    pub recv_tasks: usize,
```

and `fn default_ipfix_recv_tasks() -> usize { 1 }`, following the `default_udp_receive_buffer_bytes` pattern beside it. Wire it through `src/main.rs`.

- [ ] **Step 4: Implement the fan-out**

In `start_with_shutdown`, keep the existing single-socket path verbatim for `recv_tasks <= 1` — that is the safety property. For `recv_tasks > 1`, bind N sockets with `bind_udp_reuseport_with_recv_buffer`, spawn one task per socket running the existing recv loop, and clone the decoder handle into each:

```rust
        let decoder = IpfixDecoder::new();
        // One handle per task, all sharing one template cache (see
        // IpfixDecoder's docs) — so an exporter's data decodes on whichever
        // task receives it, whatever the kernel's steering does.
        for _ in 0..self.config.recv_tasks {
            let socket = crate::net::bind_udp_reuseport_with_recv_buffer(
                &addr, self.config.receive_buffer_bytes, "ipfix",
            ).await?;
            let decoder = decoder.clone();
            // ... spawn the same recv loop the single-socket path runs
        }
```

Two things to get right:
- **The `allowed_ips` check.** The existing loop has a `// ponytail:` comment stating that any new recv arm needs the same `is_allowed` check. Each spawned task must keep it — dropping it in one path would open an ingest bypass.
- **`SocketDropStats`.** Construct exactly ONE, not one per task. All N sockets share an address:port, so each would read the same summed total from Task 2 and `metrics::counter!` would multiply-count. Pick the first socket for its `local_addr` and poll once.

Shutdown must still stop every task; join them all before returning.

- [ ] **Step 5: Run to verify it passes**

```bash
cargo test --lib ipfix::
```

Expected: PASS, including the new test and every existing listener test.

- [ ] **Step 6: Verify `recv_tasks=1` is unchanged**

```bash
cargo test --workspace
```

Expected: PASS. Every pre-existing test runs the default path, so a failure here means the default changed — which is the one thing this task must not do.

- [ ] **Step 7: Commit**

```bash
git add src/ipfix/listener.rs src/config/mod.rs src/main.rs
git commit -m "feat(ipfix): optional SO_REUSEPORT receive fan-out

recv_tasks (default 1) binds N sockets sharing the port, each drained by its
own task, all sharing one template cache. Correctness does not depend on the
kernel steering an exporter to a fixed socket: the regression test sends a
template and its data from different source ports and still decodes every
record.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: sFlow listener fan-out

**Files:**
- Modify: `src/sflow/listener.rs`, `src/config/mod.rs`, `src/main.rs`
- Test: the `#[cfg(test)] mod tests` in `src/sflow/listener.rs`

**Interfaces:**
- Consumes: Task 3's bind helper; Task 4's config pattern.
- Produces: `SflowListenerConfig.recv_tasks` and `SflowConfig.recv_tasks` (default 1).

`src/sflow/decoder.rs` states in its module docs that the decoder is stateless — sFlow v5 carries all context inline. Verify that claim by reading it before you start; if it holds, this task needs no cache-sharing argument at all and is a straight port of Task 4's structure.

- [ ] **Step 1: Write the failing test**

```rust
/// Datagrams from several source ports must all be handled when fanned out.
/// sFlow's decoder is stateless, so the only risk is a lost or misrouted
/// datagram, not a decode failure.
#[tokio::test]
async fn fanned_out_listener_receives_from_several_source_ports() {
    let (listener, bound, shutdown_tx, handler) = start_test_listener(4).await;

    for i in 0..4u32 {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for n in 0..10u64 {
            sock.send_to(&build_datagram(i * 10 + n as u32 + 1, n), bound).await.unwrap();
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let _ = shutdown_tx.send(true);
    let _ = listener.await;

    assert_eq!(handler.record_count(), 40 * RECORDS_PER_DATAGRAM);
}
```

Reuse this module's existing test helpers and its datagram builder; `tools/loadgen/src/sflow_udp.rs` has a known-good byte layout. Set `RECORDS_PER_DATAGRAM` from what the builder actually emits — read it, do not assume 1.

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --lib sflow::listener::tests::fanned_out -- --nocapture
```

Expected: FAIL to compile — `recv_tasks` does not exist on this listener yet.

- [ ] **Step 3: Implement**

Mirror Task 4: `recv_tasks` on both config structs defaulting to 1, `recv_tasks <= 1` keeps today's exact path, `> 1` binds N `SO_REUSEPORT` sockets each with its own task. One `SocketDropStats` for the group, not N. Keep the `allowed_ips` check in every recv arm. No decoder sharing is needed — construct whatever the existing loop constructs, per task.

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test --lib sflow::
cargo test --workspace
```

Expected: PASS both.

- [ ] **Step 5: Commit**

```bash
git add src/sflow/listener.rs src/config/mod.rs src/main.rs
git commit -m "feat(sflow): optional SO_REUSEPORT receive fan-out

Same recv_tasks knob as IPFIX, default 1. sFlow's decoder is stateless, so
fan-out needs no cross-task cache.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: syslog UDP listener fan-out

**Files:**
- Modify: `src/syslog/listener.rs`, `src/config/mod.rs`, `src/main.rs`
- Test: the `#[cfg(test)] mod tests` in `src/syslog/listener.rs`

**Interfaces:**
- Consumes: Task 3's bind helper; Task 4's config pattern.
- Produces: `SyslogConfig.recv_tasks` (default 1), applying to the UDP arm only.

Two things specific to this listener:
- It binds **both** a UDP and a TCP port in the same `run()`. `recv_tasks` applies to the UDP socket only; the TCP listener is untouched. Say so in the config doc comment, or an operator will reasonably expect it to affect both.
- Its `SocketDropStats` is registered under the protocol label `"syslog_udp"` (not `"syslog"`), yielding `syslog_udp_socket_drops`. Keep that label exactly — tooling depends on it, and the naming inconsistency with `ipfix`/`sflow` is recorded as a separate follow-up, not something to fix here.

- [ ] **Step 1: Write the failing test**

```rust
/// Messages from several source ports must all arrive when fanned out.
/// Syslog UDP parses each datagram independently — no cross-datagram state.
#[tokio::test]
async fn fanned_out_udp_receives_from_several_source_ports() {
    let (listener, bound, shutdown_tx, handler) = start_test_listener(4).await;

    for i in 0..4 {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for n in 0..10 {
            let msg = format!("<34>Oct 11 22:14:15 host app: fanout {i}-{n}");
            sock.send_to(msg.as_bytes(), bound).await.unwrap();
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let _ = shutdown_tx.send(true);
    let _ = listener.await;

    assert_eq!(handler.message_count(), 40);
}
```

Reuse this module's existing test helpers. Confirm the message format parses with `logthing::syslog::SyslogMessage::parse` before relying on it — this module's own tests show the accepted RFC 3164 shape.

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --lib syslog::listener::tests::fanned_out -- --nocapture
```

Expected: FAIL to compile.

- [ ] **Step 3: Implement**

Mirror Task 4, on the UDP arm only. `recv_tasks <= 1` keeps today's exact path. Keep the `"syslog_udp"` drop-stats label and one `SocketDropStats` for the group. Keep the `allowed_ips` check in every recv arm.

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test --lib syslog::
cargo test --workspace
```

Expected: PASS both. Note some syslog tests bind privileged ports and silently pass when run as root — if anything here looks suspiciously easy, check which port it bound.

- [ ] **Step 5: Commit**

```bash
git add src/syslog/listener.rs src/config/mod.rs src/main.rs
git commit -m "feat(syslog): optional SO_REUSEPORT receive fan-out on the UDP arm

Same recv_tasks knob, default 1, UDP only — the TCP listener is unchanged.
Syslog parses each datagram independently, so fan-out needs no shared state.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Measure the new ceilings

**Files:**
- Create: `docs/performance/2026-09-18-udp-recv-fanout-results.md`

**Interfaces:**
- Consumes: Tasks 4-6.
- Produces: the before/after numbers Task 8 documents.

**Prerequisite:** `fix/harness-drop-aggregation` (`89dd749`) must be merged to `master` and present on this branch. Without it the harness reads one socket of N, disagrees with the in-process counter, and aborts every fanned-out run with a reconciliation FATAL. Confirm before starting:

```bash
cd /home/dev/projects/logthing && SELFTEST=1 ./scripts/max-ingest-rate.sh
```

Expected: 35 checks, `SELFTEST PASS`. If it reports 32, the fix is not present — stop and say so.

- [ ] **Step 1: Build the release binaries**

```bash
export PATH="$HOME/.cargo/bin:$PATH" CC=/usr/bin/gcc CXX=/usr/bin/g++ \
       CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo build --release --bin logthing && cargo build --release -p loadgen
```

- [ ] **Step 2: Confirm `recv_tasks=1` reproduces the committed ceilings**

This is the control. Run each format at the rate the committed results doc reports as its ceiling, with `recv_tasks` unset:

```bash
cd /home/dev/projects/logthing && FORMAT=ipfix  SHAPE=real RATE=37500 DURATION=15 RUNS=3 GEN_PROCS=4 ./scripts/max-ingest-rate.sh
cd /home/dev/projects/logthing && FORMAT=sflow  SHAPE=real RATE=40000 DURATION=15 RUNS=3 GEN_PROCS=4 ./scripts/max-ingest-rate.sh
cd /home/dev/projects/logthing && FORMAT=syslog SHAPE=real RATE=20000 DURATION=15 RUNS=3 GEN_PROCS=4 PORT=15140 ./scripts/max-ingest-rate.sh
```

Expected: all three PASS, matching the committed ceilings. **If any fails, stop** — the fan-out work has regressed the default path, and no comparison below is meaningful until that is explained.

These take about 90 seconds each, foreground, one at a time. Never two at once.

- [ ] **Step 3: Measure the fanned-out ceilings**

Set `recv_tasks` in the harness's generated config. The harness writes `logthing.toml` itself, so add `RECV_TASKS` support to its `write_config` (emitting `recv_tasks = N` under the listener's section when set), or set it via the `LOGTHING__<SECTION>__RECV_TASKS` environment variable if the config layer supports it — check `src/config/mod.rs` for how env overrides are wired before choosing. Say which you used.

Then ramp each format with `recv_tasks=4`, omitting `RATE` to search:

```bash
cd /home/dev/projects/logthing && FORMAT=ipfix SHAPE=real RUNS=3 DURATION=15 RAMP_START=20000 BISECT_RESOLUTION=2000 RAMP_MAX=400000 GEN_PROCS=4 <recv_tasks=4> ./scripts/max-ingest-rate.sh
```

**A full ramp takes 10+ minutes and will not survive a turn boundary.** Do not background it and end your turn — ask the coordinator to run it, or run it foreground if your harness allows a long enough call. Report per-rate medians and the final verdict line.

Watch for `GENERATOR-LIMITED`. At 4 generator processes the generator tops out near 58,000/s for some formats, so a fanned-out server may outrun it — that verdict means the measurement hit the generator's ceiling, not the server's, and must NOT be reported as a ceiling. If it fires, raise `GEN_PROCS` and say what you raised it to.

- [ ] **Step 4: Sweep `recv_tasks` to find the useful setting**

At a fixed rate above the `recv_tasks=1` ceiling, compare 1, 2, 4 and 8 for one format (IPFIX is enough):

```bash
cd /home/dev/projects/logthing && FORMAT=ipfix SHAPE=real RATE=60000 DURATION=15 RUNS=3 GEN_PROCS=4 <recv_tasks=N> ./scripts/max-ingest-rate.sh
```

Record total loss and `srv_cores` for each. The point is the shape of the curve — where it stops helping, and what it costs in CPU — not a single number. If 8 is worse than 4, say so; that is the operator guidance Task 8 needs.

- [ ] **Step 5: Write the results document**

`docs/performance/2026-09-18-udp-recv-fanout-results.md`, following `docs/performance/methodology-template.md`:

- the host caveat block, copied verbatim from `docs/performance/2026-09-14-throughput-baseline-repeats.md`;
- provenance: commit, date, `nproc`, `net.core.rmem_max`, the core split, exact commands;
- a before/after table per format: ceiling at `recv_tasks=1` vs `recv_tasks=4`, with per-drop-site loss and `srv_cores` at each;
- the `recv_tasks` sweep from Step 4;
- syslog's port 15140, and the `--events-per-request` and `GEN_PROCS` settings used, so the numbers are reproducible;
- **what this does not establish**: loopback on a shared-CPU KVM guest, generator and server on one box. If a format becomes generator-limited after fan-out, say the ceiling is unfound rather than reporting the generator's limit.

- [ ] **Step 6: Commit**

```bash
git add docs/performance/2026-09-18-udp-recv-fanout-results.md
git commit -m "perf: measured UDP receive fan-out ceilings

Before/after per format at recv_tasks=1 and 4, plus a sweep showing where
additional recv tasks stop helping.

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

Add a commented `recv_tasks` line to the `[syslog]`, `[ipfix]` and `[sflow]` sections of `logthing.toml`, following the style of the existing commented options there. State: the default is 1; raise it when the kernel is dropping datagrams while CPU sits idle (`<protocol>_socket_drops` climbing while the process uses roughly one core); it costs one task and one socket each; and name the setting Task 7 found stopped helping. Do not recommend "all your cores" — recommend the number Step 4 measured.

- [ ] **Step 2: Update the headline results document**

In `docs/performance/2026-09-18-max-ingest-rate.md`, add a dated note to each of the syslog, ipfix and sflow sections pointing at the fan-out results and giving the new ceiling, in the same style as the correction notes already in that file. Do not rewrite the original figures — they remain correct for `recv_tasks=1`, which is still the default.

- [ ] **Step 3: Update the changelog**

`CHANGELOG.md`, Unreleased: an `Added` entry for `recv_tasks` on the three UDP listeners (noting the default of 1 preserves existing behaviour), and a `Fixed` entry for `parse_proc_net_udp` summing across sockets sharing a port.

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
git commit -m "docs: operator guidance for recv_tasks

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Notes for the executor

- **`recv_tasks=1` must stay byte-identical to today** at every step. It is what makes this deployable, and the whole workspace suite exercises it — a failure there is never "just a test to update".
- **Never delete or weaken a pre-existing test** to make a refactor compile. Task 1 converts 21 test sites to accessors; if one cannot be expressed that way, report it rather than dropping it.
- **`GENERATOR-LIMITED` is not a ceiling.** If the fanned-out server outruns the load generator, raise `GEN_PROCS` and say so; never report the generator's limit as the server's.
- **One harness invocation at a time**, always. They share fixed ports and one metrics endpoint.
- The prototype branch `perf/udp-recv-scaling` is a reference, not a merge source. Its per-task-decoder design is deliberately replaced here.
