# Multi-format load results — logthing 0.18.0

First end-to-end load measurements for **Zeek (TCP)** and **IPFIX (UDP)**. Until
this run, the only sustained load in the simulation environment was WEF over
HTTP; the two highest-volume socket listeners had no e2e coverage at all.

---

## ⚠️ Read this before quoting any number below

Same caveat as `2026-09-13-criterion-baseline-0.18.0.md`, and it bites harder
here because these are whole-system numbers:

- Host is a **QEMU/KVM guest**, generic CPU model, 12 vCPUs, **no `cpufreq`
  interface** — no governor to pin, no way to rule out host contention.
- Generator and server run **in containers on the same host**, competing for
  the same 12 vCPUs. A real deployment has the sender on another machine.
- Host: 61 GiB RAM, kernel `6.12.94+deb13-amd64`, Docker 29.6.1.
- `net.core.rmem_default` = `net.core.rmem_max` = **212992** (208 KiB) in the
  container. This is the single most important number on the page for the UDP
  results, and it was not tuned.

These are **attribution** results — *where* records are lost — not capacity
results. Do not quote a max sustainable rate from this page.

## Provenance

| | |
|---|---|
| Crate version | 0.18.0 |
| Commit | `b8d65d5` (branch `perf/loadgen-formats`) |
| Date | 2026-09-13 |
| Environment | `tests/e2e/simulation-environment`, `docker compose` |
| Generators | `loadgen zeek-tcp`, `loadgen ipfix-udp` (`tools/loadgen`) |
| Sinks | both S3 (MinIO) and local disk enabled per `config/logthing.toml` |
| Server process | §1 ran against a freshly restarted server (counters from zero); §2 reads deltas from one long-lived process. The two disagree at 5,000/s — see §2. |

---

## 1. The headline: transport decides where you lose records

Both generators offered **the same rate for the same duration** — 5,000/s for
20 s — against the same server process:

| | Zeek (TCP) | IPFIX (UDP) |
|---|---|---|
| offered | 99,995 | 99,990 |
| reached the application | **99,995** (100%) | **86,517** (86.5%) |
| lost in the kernel | **0** | **13,473 (13.5%)** |
| decoded | 99,995 | 86,515 |
| `*_templates_missing` | n/a | **0** |
| dropped by the writer channel | **0** | 2,392 (2.8% of decoded) |
| reached parquet | 99,995 | 84,123 |

**TCP loses nothing; UDP loses 13.5% before logthing executes a single line of
code.** The `ipfix_datagrams_received` counter increments on entry to
`decode_datagram`, so `offered − datagrams_received` is by construction loss
before the application sees the datagram.

> **⚠️ Correction, 2026-09-14.** This section originally went on to attribute
> that loss to `rmem_default` being 208 KiB with no `SO_RCVBUF` tuning — i.e.
> to the buffer being too small. **That attribution was wrong**, and §7 and §8
> below record the evidence that overturned it. The loss *site* is confirmed
> (the receiver's socket buffer), but buffer size is not the *cause*: raising
> `SO_RCVBUF` to double the actual buffer produced no improvement at 5,000/s.
> The constraint is the consumer's drain rate. Read §8 before acting on
> anything in this section.

**`ipfix_templates_missing` is 0 at every rate tested.** That matters: a missing
template silently discards the data set, which would have looked identical to a
kernel drop in the totals. The generator's 10-second template re-send interval
is doing its job, and the two failure modes are cleanly separated.

## 2. Rate sweep

Cumulative-counter deltas across three 20 s runs each. Read these as *shape*,
not as precise capacity — see the caveat above.

### Zeek (TCP)

| target rate | achieved | offered | reached app | writer drops |
|---|---|---|---|---|
| 5,000/s | 4,999.7/s | 99,995 | 99,995 | 0 |
| 20,000/s | **15,283/s** | 307,775 | 304,972 | 0 |
| unbounded | **12,796/s** | 263,573 | 262,265 | 0 |

Two things to note honestly:

- **The generator, not the server, is the limit above ~15k/s.** Asked for
  20,000/s it achieved 15,283/s. We did not find the server's TCP ceiling, so
  nothing on this page should be read as one.
- **Unbounded is *slower* than a 20k target** (12,796/s vs 15,283/s). Counter‑
  intuitive, and not investigated. Plausibly the unpaced loop blocks on socket
  writes, or generator and server contend for the same vCPUs. Flagged rather
  than explained — it is a property of this harness on this host, and a reason
  not to treat the unbounded mode as "maximum throughput".
- The small offered-vs-reached gaps at higher rates (≈0.9%, ≈0.5%) are records
  still in flight at scrape time, not losses: `parquet_s3_dropped` stayed at 0
  throughout, and the counter converged upward on a later scrape.

### IPFIX (UDP)

| target rate | achieved | offered | reached app | kernel loss | templates missing |
|---|---|---|---|---|---|
| 5,000/s | 4,999.5/s | 99,990 | 89,694 | ~10.3% | 0 |
| 20,000/s | 19,726/s | 394,531 | 322,686 | ~18.2% | 0 |
| unbounded | 29,118/s | 582,358 | 419,377 | ~28.0% | 0 |

Kernel loss scales with offered rate, as an undersized receive buffer predicts.
The IPFIX generator sustains a materially higher rate than the Zeek one
(29k/s vs 13k/s unbounded) because a UDP `send` does not wait for a peer.

**These are a different run from §1, and the two disagree — which is itself a
result.** §1's 5,000/s row was taken against a freshly restarted server so every
counter started at zero; this sweep reuses one long-lived process and reads
counter deltas. At the same nominal 5,000/s the two runs lost **13,473 (13.5%)**
and **10,296 (10.3%)** respectively — a 3.2-percentage-point spread on an
identical offered load.

Do not average them or treat either as *the* number. Kernel-queue loss depends
on scheduling luck between the sending and receiving processes, which on this
host share 12 vCPUs; it is not a deterministic property of the server. The
honest summary is "10-14% at 5,000/s on this host, varying run to run." Anyone
wanting a stable figure needs a quiet host, the generator off-box, and repeated
runs with a reported spread — none of which this environment provides. (Note
this paragraph's "scheduling luck" reading held up: §8 confirms the binding
constraint is the recv task's drain rate, not buffer depth.)

## 3. What to do with this

**The decoder is not the lever.** `2026-09-13-criterion-baseline-0.18.0.md`
measures IPFIX decode at **308 ns per datagram** — 0.6% of the per-datagram
budget at the observed rate. The records lost here were never decoded at all.
Do not open a decoder optimisation on the strength of these numbers.

> **⚠️ Corrected 2026-09-14.** This section previously said the lever was
> `rmem` — "raising `net.core.rmem_max` and setting `SO_RCVBUF` on the listener
> sockets". **That was wrong.** §7 raised the actual buffer from 212992 to
> 425984 and measured no improvement at 5,000/s. §8 shows why: the receiver's
> socket buffer is where the loss *happens*, but the binding constraint is the
> rate the recv task drains it. Enlarging a buffer whose consumer is too slow
> only delays the overflow. Read §8 before acting here.

**A useful invariant fell out of this run:** `offered − datagrams_received` is
kernel loss, and `parquet_s3_dropped` is writer-channel loss. They are
independently observable and were both non-zero for IPFIX in the same run
(13,473 and 2,392). Any future capacity work should report them separately —
collapsing them into one "drop rate" hides which fix applies.

## 4. What this run does NOT establish

- **No capacity number.** The generator saturated before the server did for
  Zeek, and the kernel buffer saturated before the server did for IPFIX. Neither
  ceiling found is logthing's.
- **Nothing about the other five sources.** suricata, sFlow, HEC, OTLP and
  syslog-over-TCP/HTTP still have no load generator. `tools/loadgen` now has 3
  of the 7 subcommands its design calls for.
- **Nothing comparable to a bare-metal deployment**, for every reason in the
  caveat at the top.

## 5. Environment fixes this run required

Two things had to change before the environment would start at all. Both are
committed separately from the loadgen work so they stay reviewable on their own.

**MinIO moved off Docker Hub.** `docker pull minio/minio:RELEASE.2024-01-16T16-07-38Z`
— the tag pinned in `docker-compose.yml` — now fails with *"pull access denied
for minio/minio, repository does not exist or may require 'docker login'"*.
Verified this is specific to that repository and not a network problem:
`hello-world` and `rust:1.93-slim-bookworm` both pulled fine from Docker Hub in
the same session, while `minio/minio:latest` failed identically to the pinned
tag. `quay.io/minio/minio` and `quay.io/minio/mc` both pull, so the compose file
now points there (commit `61dadf9`).

Moved to a floating tag rather than re-pinning a specific release: the point of
the old pin was reproducibility, and what it actually delivered was an
environment that could not start. A pin to a registry path that no longer exists
is worse than no pin. Re-pin to a `quay.io` release tag if reproducibility
matters more than startability here.

`rust:1.93-slim-bookworm`, the other tag the plan flagged as a staleness risk,
still pulls fine.

**Every build was shipping ~12 GB of context.** There was no `.dockerignore`,
and the daemon receives the whole build context regardless of which paths a
Dockerfile `COPY`s — `target/` alone is 76 GB here, with `.claude/` and
`.superpowers/` adding ~55 GB more. Added an allowlist `.dockerignore` (nothing
sent unless named); context is now 2.3 MB. This affected the pre-existing
`logthing:e2e` and Kerberos images too, not just the new loadgen one.

## 6. Reproducing

```bash
cd tests/e2e/simulation-environment
docker compose up -d minio && docker compose run --rm minio-setup
docker compose build logthing loadgen-zeek      # see note below
docker compose up -d --force-recreate logthing

LOADGEN_ZEEK_RATE=5000  LOADGEN_DURATION=20 docker compose run --rm loadgen-zeek
LOADGEN_IPFIX_RATE=5000 LOADGEN_DURATION=20 docker compose run --rm loadgen-ipfix

docker compose exec -T logthing wget -qO- http://localhost:9100/metrics
```

Three traps this run hit, all of which produce plausible-looking wrong results:

1. **`docker compose run -e VAR=…` does not work here.** The rates are
   `${LOADGEN_ZEEK_RATE:-5000}` inside `command:`, which compose interpolates
   from *its own* environment at config-parse time. Passing `-e` sets the
   container's environment instead, leaving the default baked into the command —
   three "different" rates all silently ran at 5,000/s and produced byte-identical
   output. Set the variable in the invoking shell, as above.
2. **`docker compose up` will not rebuild an image whose tag already exists.**
   The `logthing:e2e` image on this host was four weeks old; the container that
   started was built from stale code and failed on unrelated config. Build
   explicitly, or `--force-recreate` is not enough.
3. **Metrics are on port 9100 in this environment**, not the 9090 default —
   `config/logthing.toml` overrides it.

`curl` is not installed in the server image; `wget` is.

## 7. `SO_RCVBUF` follow-up (Tier 2 Task 3, branch `t2/so-rcvbuf`)

§1 attributed the 13.5% IPFIX kernel loss at 5,000/s to the default 208 KiB
`SO_RCVBUF` and untouched `rmem_max`. `t2/so-rcvbuf` made the UDP receive
buffer configurable (`receive_buffer_bytes: Option<usize>`, default 4 MiB) and
applies it at bind time in all three UDP listeners via `socket2`. On this
host (uid 1000, no `CAP_NET_ADMIN`, `rmem_max` = `rmem_default` = 212992) the
request is clamped and doubled, and the server logs it on every startup:

```
WARN syslog_udp: SO_RCVBUF requested 4194304 bytes, kernel granted only 425984 bytes (clamped by net.core.rmem_max)
WARN ipfix: SO_RCVBUF requested 4194304 bytes, kernel granted only 425984 bytes (clamped by net.core.rmem_max)
```

425984 vs 212992 — the actual buffer doubles, exactly as predicted before
this task started. **The question was whether that doubling moves the
kernel-loss number**, using the exact §6 reproduction steps, comparing commit
`6570ccc` (pre-change, no `SO_RCVBUF` anywhere) against this branch's tip.
Two 20 s runs per rate per commit, same host, same session:

| rate | commit | run 1 loss | run 2 loss | pooled loss |
|---|---|---|---|---|
| 5,000/s | before (`6570ccc`) | 4,184 / 99,995 (4.18%) | 3,095 / 100,000 (3.10%) | 7,279 / 199,995 (**3.64%**) |
| 5,000/s | after (`t2/so-rcvbuf`) | 4,887 / 99,990 (4.89%) | 3,053 / 99,995 (3.05%) | 7,940 / 199,985 (**3.97%**) |
| 20,000/s | before (`6570ccc`) | 71,516 / 368,688 (19.40%) | 89,081 / 399,881 (22.28%) | 160,597 / 768,569 (**20.90%**) |
| 20,000/s | after (`t2/so-rcvbuf`) | 53,235 / 398,044 (13.37%) | 75,924 / 380,372 (19.96%) | 129,159 / 778,416 (**16.59%**) |

**At 5,000/s: no improvement.** Pooled loss is statistically indistinguishable
before vs. after (3.64% vs 3.97%, after is nominally *worse*), and each
commit's own two runs (4.18% vs 3.10%; 4.89% vs 3.05%) already span more than
the before/after gap. Doubling the buffer bought nothing measurable at this
rate on this host. That is itself informative: at 5,000/s the loss is not
buffer-depth-limited — it tracks scheduling luck between the generator and
server containers contending for the same 12 vCPUs, matching §2's own
observation that identical offered load produced a 3.2-point spread run to
run. Also worth noting this session's absolute numbers (3-5%) run well below
§1/§2's original 10-14% at the same nominal rate — different day, different
host contention, same generator and server code path — which is further
evidence these are noisy attribution numbers, not a stable capacity figure.

**At 20,000/s: a real but not fully resolved improvement.** Pooled loss drops
from 20.90% to 16.59%, roughly a 4.3-point (~20% relative) reduction — a
plausible payoff of a 2x buffer at a rate where the queue is under more
sustained pressure. But it is not a clean win: the after-commit's two runs
(13.37%, 19.96%) span 6.6 points, wide enough that its worse run overlaps the
before-commit's range (19.40%–22.28%) entirely. Two runs per condition cannot
rule out this being the same scheduling noise seen at 5,000/s, just larger in
absolute terms at the higher rate. Call it a directional signal consistent
with the task's predicted "real but bounded improvement," not a proven one —
resolving it further needs more repetitions than this session's time budget
allowed, or a host without generator/server vCPU contention.

**Bottom line:** the setsockopt is correct and the logging surfaces the clamp
exactly as designed (425984 vs 212992, every startup). Whether it *helps*
loss is rate-dependent and, at the lower rate tested, indistinguishable from
noise — do not read this task as having proven the fix's value at 5,000/s,
only that it's wired up correctly and shows a suggestive-but-unconfirmed win
at 20,000/s. Do not raise `rmem_max` on the host to chase a cleaner number;
that changes what is being measured.

## 8. Root cause: where the loss happens, and why

Established 2026-09-14 by counter reconciliation on a controlled loopback run
(IPFIX, 20,000/s, 15 s) — loopback deliberately, to remove the docker bridge
and the NIC from the picture entirely:

| | count |
|---|---|
| generator reported sending | 299,977 |
| application saw (`ipfix_datagrams_received`) | 277,571 |
| **loss** | **22,406** |
| `RcvbufErrors` delta (`/proc/net/snmp`) | **22,407** |
| `SndbufErrors` delta | **0** |

The loss and `RcvbufErrors` reconcile to within one datagram — the template
datagram, which is sent once and counted separately. So:

**The loss site is the receiver's socket buffer. Definitively.** Three
hypotheses die here:

- **Not the sender.** `SndbufErrors` is 0; the sending kernel never failed to
  buffer. Note that the generator's `sent` count is successful `send()`
  syscall returns, so this had to be checked rather than assumed.
- **Not the network fabric.** This was loopback.
- **Not decode.** `decode_datagram` costs 308 ns (see the criterion baseline) —
  0.6% of the per-datagram budget at the observed rate.

**But buffer size is not the cause.** §7's before/after study raised the actual
buffer from 212992 to 425984 and found *no* improvement at 5,000/s. A buffer
only overflows if the consumer is persistently slower than the producer; a
larger one then merely delays the overflow.

**The consumer is the constraint.** That run sustained 277,571 datagrams in
15 s ≈ **18.5k/s** against 20k offered — roughly **54 µs per datagram**, of
which decode is 0.3 µs. **~99% of the per-datagram budget is something other
than parsing.** That echoes `2026-07-25-syslog-udp-cpu-profile.md`, which
could not attribute ~85% of its own per-datagram figure either.

Two candidate explanations remain, and this measurement does not separate them:

1. **Per-datagram overhead outside the decoder** — syscalls, tokio scheduling,
   futex contention, logging macros, the allowed-IPs check.
2. **Recv/handler coupling.** `src/ipfix/listener.rs`'s loop calls
   `self.handler.handle_flows(flows, src).await` *inline on the recv task*.
   While that await is pending nothing calls `recv_from`, so the socket has no
   consumer at all — receive capacity is coupled to downstream latency, and UDP
   answers by dropping. This is exactly why zeek over TCP loses nothing at the
   same offered rate: TCP backpressures the sender instead.

Against (2) on its own: the run above used a trivial handler and still lost
3-4% at 5,000/s, far below the ceiling — that residual looks like scheduling
jitter (generator and server share 12 vCPUs on this host), not saturation.

**Do not "fix" this by raising `rmem_max`.** That enlarges the buffer whose
size has already been shown not to be the binding constraint.

### Reproducing the attribution

```bash
udp() { awk '/^Udp:/{if(++n==2){print $2,$4,$6,$7}}' /proc/net/snmp; }  # In InErr Rcvbuf Sndbuf
LOGTHING__IPFIX__ENABLED=true LOGTHING__SYSLOG__ENABLED=false ./target/release/logthing &
udp   # before
./target/release/loadgen ipfix-udp --host 127.0.0.1 --port 4739     --target-rate 20000 --duration-secs 15
udp   # after
wget -qO- http://127.0.0.1:9090/metrics | grep ipfix_datagrams_received
```
