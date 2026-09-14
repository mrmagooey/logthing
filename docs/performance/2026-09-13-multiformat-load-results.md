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
| Server process | restarted immediately before the run, so all counters start at zero |

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
`decode_datagram`, so `offered − datagrams_received` is by construction loss in
the kernel receive queue, not in the application. With `rmem_default` at 208 KiB
and no `SO_RCVBUF` tuning, that is the expected result, and it is consistent
with `docs/performance/2026-07-25-syslog-udp-cpu-profile.md`'s conclusion that
the bottleneck sits upstream of the writer.

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
| 5,000/s | 4,999.5/s | 99,990 | 89,694 | ~10% | 0 |
| 20,000/s | 19,726/s | 394,531 | 322,686 | ~18% | 0 |
| unbounded | 29,118/s | 582,358 | 419,377 | ~28% | 0 |

Kernel loss scales with offered rate, as an undersized receive buffer predicts.
The IPFIX generator sustains a materially higher rate than the Zeek one
(29k/s vs 13k/s unbounded) because a UDP `send` does not wait for a peer.

## 3. What to do with this

**The actionable finding is `rmem`, not code.** Before anyone optimises the
IPFIX or sFlow decode path on the strength of these numbers, note that
`2026-09-13-criterion-baseline-0.18.0.md` measures that decode at **308 ns per
datagram** — roughly 0.3% of a 100 µs/datagram budget at 10k/s. The records lost
here were never decoded at all. Raising `net.core.rmem_max` and setting
`SO_RCVBUF` on the listener sockets is the lever; the decoder is not.

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

## 5. Reproducing

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
