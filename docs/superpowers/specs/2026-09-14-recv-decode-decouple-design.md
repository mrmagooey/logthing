# Decoupling `recv_from` from decode+dispatch — design

**Status:** approved by independent coherence review (round 2), 2026-09-14.
Implements Tier 1 of `docs/superpowers/plans/2026-09-14-throughput-improvements.md`.

## Problem

`src/ipfix/listener.rs`'s receive loop serialises, on one task: `recv_from` →
allowed-IPs check → `decode_datagram` → `handler.handle_flows(...).await`.

Measured (`docs/performance/2026-09-14-ipfix-recv-path-cpu-profile.md`):
**5.47% datagram loss while using 0.51 of 12 cores** — ~11.5 cores idle while
the kernel discards datagrams for want of a consumer. Loss is confirmed to
occur in the receive socket buffer (`ipfix_socket_drops` reconciles exactly
with `/proc/net/snmp` `RcvbufErrors` across five runs).

Not the cause, each ruled out by measurement: buffer size, decode cost
(308 ns, 3.84% of self-time), the sender, the network.

## Design

Split each of the two recv loops into a producer and a consumer.

**Producer** (stays on the listener task): `recv_from` → allowed-IPs check →
copy the datagram out of the shared buffer → `try_send` into a bounded
channel → loop. The socket-stats ticker and shutdown arms stay here.

**Consumer** (one spawned task, owns the `IpfixDecoder`): `recv()` →
`decode_datagram` → `handler.handle_flows(...).await`.

## Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Raw bytes cross the channel, not decoded flows | Sending decoded flows leaves decode on the recv task, decoupling nothing |
| D2 | `Vec::from(&buf[..len])` per datagram; no pool initially | A ~1500-byte copy is ~100 ns against a 54 µs budget. A pool up front optimises an unmeasured cost. **Reversible — and the acceptance gate is built to catch it being wrong** |
| D3 | `RECV_QUEUE_CAPACITY = 4096` | Fixed by the plan; not a config knob, per its no-knob-nobody-sets constraint |
| D4 | `try_send`, drop on full, count | `send().await` reintroduces the coupling being removed; unbounded trades a bounded drop for unbounded memory. Matches `buffered_writer`'s precedent |
| D5 | Exactly one consumer | The IPFIX template cache is per-`IpfixDecoder`. Multiple consumers is the Tier 4 coherency hazard — a template arriving on one worker is absent from another's cache, silently dropping data sets |
| D6 | IPFIX only | It has the measured loss and the reproduction. sFlow/syslog are Tier 3, separately measured |
| D7 | `listener_recv_queue_dropped{protocol="ipfix"}`, **no log line** | Matches the `listener_source_rejected{protocol}` convention used by six listeners, so Tier 3 reuses one metric. `drop_log.rs` records per-drop logging costing ~21% of throughput at 50k/s |
| D8 | Acceptance under **both** handler shapes | See below — this is the decision that makes the gate real |
| D9 | Task 0.1 harness lands first, as Tier 1's first commit | The gate needs a before-baseline that does not yet exist; the plan permits this sequencing |

## The acceptance gate, and why it is shaped this way

An earlier draft measured only `DefaultIpfixHandler`. Coherence review found
that gate **could not fail**: D2's added per-datagram allocation is only
dangerous in the Run B shape (real handler, allocator 39.44% of self-time),
and the `parquet_s3_dropped` guard against relocating the drop downstream is
never emitted by `DefaultIpfixHandler` at all.

Acceptance therefore requires, N≥5 runs each, before and after:

1. **Trivial-handler shape** (`DefaultIpfixHandler`) — median kernel loss down
   ≥50% relative, before/after ranges non-overlapping.
2. **Real-handler shape** (`[ipfix.local]`, local disk, no external service) —
   the same bar, **and** `parquet_s3_dropped{source="ipfix"}` not up >10%
   relative.

**Tier 1 passes only if both clear the bar.** This lets the gate return three
distinct verdicts rather than one: helped both, helped the trivial shape while
the allocation hurt the real one (blocked), or no measurable difference
(reported inconclusive — not rounded up).

That last outcome is a live possibility and must not be spun. With one
consumer the producer sheds ~15.7% of Run A's self-time while
`recvfrom`+`epoll_wait` (44.56%) stay exactly where they are. Whether that
raises the sustained-receive ceiling is genuinely unknown — the profile doc
lists this and `SO_REUSEPORT` fan-out as two co-equal untested hypotheses.
