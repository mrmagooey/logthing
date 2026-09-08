# SIGTERM graceful shutdown

**Date:** 2026-09-07
**Branch:** `fix/sigterm-graceful-shutdown` (cut from `master` @ `4393dd5`)

## Problem

`src/main.rs:738-743` is the entire signal surface of the binary:

```rust
let shutdown_signal = async {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install Ctrl+C handler");
    info!("Shutdown signal received");
};
```

`tokio::signal::ctrl_c()` handles SIGINT only. Nothing anywhere in `src/`
references SIGTERM. `src/server/mod.rs:390` carries a comment claiming graceful
shutdown is wired "so the axum server stops on SIGTERM", but no code ever fires
that path on SIGTERM.

`Dockerfile:60` is `CMD ["logthing"]` — exec form, no shell, no init — so the
process runs as PID 1. The kernel special-cases PID 1: a signal whose
disposition is still `SIG_DFL` is discarded rather than taking its default
action. `kill -TERM 1` inside the container is therefore a no-op.

Everything after the `tokio::select!` at `src/main.rs:745` — `shutdown_tx.send(true)`,
the listener drain, and the writer-flush deadline at `src/main.rs:844` — is
reachable *only* through the `ctrl_c` arm. So under Kubernetes: SIGTERM is
discarded, the pod hangs for the full `terminationGracePeriodSeconds`, then
SIGKILL lands and no buffered writer is ever flushed. Whatever the last periodic
flush did not cover is lost.

Outside a container the process is not PID 1, so SIGTERM instead terminates it
immediately — also skipping the flush. PID 1 converts instant data loss into a
30-second hang followed by the same data loss.

## Fix

Add one function to `src/shutdown.rs` (an existing "shutdown utilities" module):

```rust
/// Resolves when the process receives SIGTERM or SIGINT.
pub async fn wait_for_shutdown_signal() {
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler");
    tokio::select! {
        r = tokio::signal::ctrl_c() => r.expect("Failed to install Ctrl+C handler"),
        // ponytail: recv() -> None (signal driver torn down) is treated as a
        // shutdown request. Worst case that starts a graceful shutdown one
        // process-teardown early, which loses nothing.
        _ = sigterm.recv() => {}
    }
}
```

`src/main.rs:738-743` collapses to calling it, keeping its existing
`info!("Shutdown signal received")` log. The module doc at `src/shutdown.rs:1`
(currently "Shutdown utilities: deadline-bounded handle awaiting.") is updated
to cover both functions.

Nothing else moves. The downstream `shutdown_tx.send(true)` → listener drain →
writer flush sequence is already correct and is not touched.

## Decisions

| # | Question | Chosen | Why |
|---|---|---|---|
| 1 | Where does the logic live? | `src/shutdown.rs`, not inline in `main.rs` | `main.rs` is a binary — nothing in `tests/` can reach it, so inline is untestable at unit level. `src/shutdown.rs` already exists for exactly this. |
| 2 | How to catch SIGTERM? | `tokio::signal::unix` | `tokio` is already `features = ["full"]`, which includes `signal`. A new dependency for six lines is not warranted. |
| 3 | Which signals? | SIGTERM + SIGINT only | SIGTERM is the bug; SIGINT preserves today's Ctrl+C. SIGHUP conventionally means *reload* — treating it as shutdown would be an unrequested behaviour change. |
| 4 | `#[cfg(unix)]` gating? | No | Repo is Linux-only: musl release targets (`.github/workflows/binaries.yml:41-42`), glibc `debian:bookworm-slim` runtime image (`Dockerfile:32`), all CI on ubuntu, and zero `cfg(unix)`/`cfg(windows)`/`cfg(target_os` anywhere in `src/`. tokio's unix signal path works on either libc. |
| 5 | Registration failure? | `.expect()` panic | Matches the existing `.expect("Failed to install Ctrl+C handler")`. Registration fails only for SIGKILL/SIGSTOP-class nonsense; failing fast at startup beats a daemon that silently cannot be stopped. |
| 6 | How do tests send signals? | `kill(1)` via `std::process::Command` | No new dev-dependency; the e2e test already spawns processes. |
| 7 | Change `Dockerfile`/`docker-compose`? | No | A handler-equipped PID 1 receives SIGTERM normally. An init shim would treat the symptom and leave the binary still unable to stop itself. |

## Testing

### Unit — `src/shutdown.rs`, existing `#[cfg(test)] mod tests`

Poll the future once, *then* signal:

```rust
let mut fut = Box::pin(wait_for_shutdown_signal());
tokio::select! {
    _ = &mut fut => panic!("resolved before any signal was sent"),
    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
}
kill_self(sig);
tokio::time::timeout(Duration::from_secs(5), fut).await.expect("...");
```

This is race-free, verified against vendored tokio 1.49.0 source:
`tokio::signal::unix::signal(kind)` (`unix.rs:419`) is a *synchronous* fn that
registers the OS disposition at call time, and `tokio::signal::ctrl_c()`
(`unix.rs:524-526`) calls that same synchronous `signal(SignalKind::interrupt())`
in its body, which runs on first poll. `select!` must poll every branch. So one
poll installs both dispositions before any `kill` can be sent — the signal can
neither hit default disposition nor be missed. The first `select!` arm doubles as
an assertion that the future does not resolve spuriously.

Both signals go in **one** test, sequentially. `cargo test` runs a binary's tests
as parallel threads and signal delivery is process-wide, so two concurrent tests
each holding a live receiver would observe each other's kills. This must remain
the only test in the `--lib` binary that touches process signals.

### Integration — not applicable, deliberately

This change is one leaf function plus one call site inside a binary. An
integration test decomposes into two halves that are each already covered:

- signal → future resolves: covered directly by the unit test above.
- watch-channel flip → a real listener's `start_with_shutdown` returns: covered
  by `tests/ipfix_env_var_bind_integration.rs:83-88`, which asserts
  `result.is_ok(), "listener did not exit after shutdown signal"`.
  (Note: `tests/listener_ip_whitelist_integration.rs:125` also flips the channel
  but writes `let _ = timeout(...)`, discarding the result — it uses shutdown as
  teardown and asserts nothing about it, so it does *not* support this claim.)

The only new element between those halves is a single `watch::Sender::send(true)`
call — plain API use with no distinct failure mode. The genuine multi-component
wiring is `main.rs`'s own `tokio::select!` plus `shutdown_tx.send(true)`, which
lives inside the binary and is reachable only by running it — which is what the
e2e test does. Extracting that glue into the library purely to make it
integration-testable would be a refactor of working code beyond the reported
bug, and is deliberately not done.

### E2E — new file in `tests/`

Follows the existing pattern in `tests/listener_ip_whitelist_e2e.rs`: generated
`logthing.toml` in a tempdir, child spawned via `env!("CARGO_BIN_EXE_logthing")`
with `current_dir` set to it, a `ChildGuard` that kills and reaps on drop,
readiness polling rather than fixed sleeps.

Config enables the syslog UDP listener and `[syslog.local]` with
`max_buffer_rows = 100000` and `flush_interval_secs = 3600`, so the shutdown
drain is the only thing that can produce output inside the test window. Verified:
`flush_check_interval()` (`src/forwarding/s3_sink.rs:137-139`) is
`flush_interval.max(1s)`, so the age ticker in `ParquetWriterHandle::start_with_stats`
(`src/forwarding/buffered_writer.rs:1748,1816`) fires once an hour, and the row
threshold is unreachable by a small payload. The only remaining path is the
channel-close `None` arm (`buffered_writer.rs:1774-1802`) which runs
`drain_pending_flushes()` then `flush_all()`.

Send syslog datagrams, poll until ingestion is confirmed, then `kill -TERM` the
child and assert:

1. The child exits **without being signal-terminated** — check
   `std::os::unix::process::ExitStatusExt::signal().is_none()` (equivalently, a
   normal exit code), not merely that `wait()` returned. Budget 45s, chosen to
   clear the binary's internal 10s writer-flush deadline (`src/main.rs:844`) with
   margin.
2. A Parquet file containing the records exists on disk.

**What this test does and does not reproduce.** It does *not* reproduce the PID-1
signal-discard semantics: under `cargo test` the binary is an ordinary child
process, not init, so against the unfixed binary SIGTERM takes its default action
and kills it immediately rather than being discarded. Reproducing the PID-1 case
would require running the child as an actual init process and is out of scope.
What the test proves is the thing that actually matters — **SIGTERM now drives
the same graceful path SIGINT already did** — because a *handled* signal is never
subject to the PID-1 special case.

The discriminator is therefore assertion (1) plus (2) together: unfixed → killed
by signal, no Parquet file; fixed → clean exit, Parquet file present. Assertion
(1) alone would be vacuous, since the unfixed binary also "exits within 45s".
