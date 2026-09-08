# SIGTERM Graceful Shutdown Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `logthing` run its existing graceful-shutdown sequence on SIGTERM, not just SIGINT, so Kubernetes/Docker pod termination flushes buffered records instead of losing them.

**Architecture:** Add one `pub async fn wait_for_shutdown_signal()` to the existing `src/shutdown.rs` utility module that resolves on either SIGTERM or SIGINT, and call it from `src/main.rs` in place of the current bare `tokio::signal::ctrl_c()`. Everything downstream of the signal — `shutdown_tx.send(true)`, listener drain, writer flush — is already correct and is not touched.

**Tech Stack:** Rust, tokio (already `features = ["full"]`, which includes `signal`), parquet/arrow for the e2e assertion. **No new dependencies, including no new dev-dependencies.**

**Spec:** `docs/superpowers/specs/2026-09-07-sigterm-graceful-shutdown-design.md`

## Global Constraints

- **No new dependencies or dev-dependencies.** `tokio` already has `signal` via `features = ["full"]`. Send signals from tests with `kill(1)` via `std::process::Command`.
- **No `#[cfg(unix)]` gating.** This repo is Linux-only and has zero `cfg(unix)`/`cfg(windows)`/`cfg(target_os` in `src/`. Do not add the first one.
- **Catch SIGTERM and SIGINT only.** Not SIGHUP (conventionally means reload), not SIGQUIT.
- **Do not modify `Dockerfile` or `docker-compose.yml`.** A handler-equipped PID 1 receives SIGTERM normally.
- **Do not refactor `main.rs`'s shutdown sequence** beyond replacing the signal future itself. The drain/flush logic below it is working code and out of scope.
- **Build environment — required, the build fails confusingly without it:**
  ```bash
  source ~/.cargo/env
  export CC=/usr/bin/gcc CXX=/usr/bin/g++
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
  ```
  Both the `CC` line and the `..._LINKER` line are required. `~/.local/bin/cc` is a `zig cc` shim that shadows `/usr/bin` on PATH and dies with `UnknownOperatingSystem`; omitting the linker line silently links LLVM libunwind instead of `libgcc_s`.
- **Run all builds and tests in the FOREGROUND.** Never use `run_in_background` and wait for a notification — subagents do not receive those and will hang forever. Let the `Bash` call block for its full duration; a clean first compile takes ~6 minutes.

---

### Task 1: SIGTERM-aware shutdown signal + unit test

**Files:**
- Modify: `src/shutdown.rs` (module doc at line 1; add function; add test to the existing `#[cfg(test)] mod tests`)
- Modify: `src/main.rs:738-743`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `pub async fn logthing::shutdown::wait_for_shutdown_signal()` — takes no arguments, returns `()`, resolves when the process receives SIGTERM or SIGINT. Task 2 relies on the behaviour, not the symbol.

- [ ] **Step 1: Write the failing test**

Add to the existing `#[cfg(test)] mod tests` at the bottom of `src/shutdown.rs`. The `use super::*;` and `use std::time::Duration;` imports are already present in that module.

```rust
    /// Send `sig` to our own process via `kill(1)`. Avoids a `libc`/`nix`
    /// dev-dependency for what is one subprocess call.
    fn kill_self(sig: &str) {
        let pid = std::process::id().to_string();
        let status = std::process::Command::new("kill")
            .args([format!("-{sig}").as_str(), pid.as_str()])
            .status()
            .expect("failed to run kill(1)");
        assert!(status.success(), "kill -{sig} {pid} failed");
    }

    /// Both signals are exercised in ONE test, sequentially, and this must
    /// remain the only test in the `--lib` binary that touches process
    /// signals: `cargo test` runs a binary's tests as parallel threads and
    /// signal delivery is process-wide, so two concurrent tests each holding
    /// a live receiver would observe each other's kills.
    ///
    /// Polling the future once *before* signalling is what makes this
    /// race-free. `tokio::signal::unix::signal()` is a synchronous fn that
    /// installs the OS disposition at call time, and `tokio::signal::ctrl_c()`
    /// calls that same synchronous registration inside its body on first
    /// poll; `select!` must poll every branch. So after the first `select!`
    /// below returns via its sleep arm, both dispositions are installed and
    /// both receivers are live — the signal can neither hit default
    /// disposition (which would kill the test binary) nor be missed.
    ///
    /// Note: tokio's SIGINT/SIGTERM disposition override outlives the
    /// receivers, so for the rest of this test binary's life Ctrl+C no longer
    /// default-terminates it. That is inherent to exercising real signal
    /// handling in-process.
    #[tokio::test]
    async fn resolves_on_sigterm_and_on_sigint() {
        for sig in ["TERM", "INT"] {
            let mut fut = Box::pin(wait_for_shutdown_signal());

            // Poll once so registration actually happens, and assert the
            // future does not resolve with nothing pending.
            tokio::select! {
                _ = &mut fut => panic!("{sig}: resolved before any signal was sent"),
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }

            kill_self(sig);

            tokio::time::timeout(Duration::from_secs(5), fut)
                .await
                .unwrap_or_else(|_| {
                    panic!("{sig} did not resolve the shutdown future within 5s")
                });
        }
    }
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
source ~/.cargo/env
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --lib shutdown::tests::resolves_on_sigterm_and_on_sigint
```

Expected: compile error, `cannot find function 'wait_for_shutdown_signal' in this scope`.

- [ ] **Step 3: Write the minimal implementation**

Add to `src/shutdown.rs`, above the `#[cfg(test)]` module:

```rust
/// Resolves when the process receives SIGTERM or SIGINT.
///
/// SIGTERM is what Kubernetes and `docker stop` send. Handling it matters
/// twice over in a container: the binary runs as PID 1 (`CMD ["logthing"]`),
/// and the kernel discards signals at PID 1 whose disposition is still
/// `SIG_DFL` rather than applying the default terminate action — so without
/// this an unhandled SIGTERM is a no-op until the grace period expires and
/// SIGKILL lands, skipping every buffered-writer flush.
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

Update the module doc on `src/shutdown.rs:1` from:

```rust
//! Shutdown utilities: deadline-bounded handle awaiting.
```

to:

```rust
//! Shutdown utilities: signal handling and deadline-bounded handle awaiting.
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test --lib shutdown::tests::resolves_on_sigterm_and_on_sigint
```

Expected: PASS. If the test binary dies with "signal: 15 (SIGTERM)" instead of reporting a pass, the registration ordering is wrong — do not "fix" this by adding a longer sleep, re-check that the future is polled before `kill_self`.

- [ ] **Step 5: Wire it into `main.rs`**

Replace `src/main.rs:738-743`, which currently reads:

```rust
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        info!("Shutdown signal received");
    };
```

with:

```rust
    let shutdown_signal = async {
        logthing::shutdown::wait_for_shutdown_signal().await;
        info!("Shutdown signal received");
    };
```

`src/main.rs:3` already has `use logthing::shutdown::await_handles_with_deadline;` — either extend that import or use the fully-qualified path as shown. Do not change anything else in this function.

- [ ] **Step 6: Verify the whole crate still builds and the suite is green**

```bash
cargo build
cargo test --lib
```

Expected: build succeeds, `--lib` tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/shutdown.rs src/main.rs
git commit -m "fix: handle SIGTERM, not just SIGINT, for graceful shutdown

As PID 1 under Docker/Kubernetes the kernel discards SIGTERM when no
handler is installed, so the drain-and-flush sequence never ran and
records buffered since the last periodic flush were lost on every pod
termination.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UquMzVB7CCkD2EzadzNMA5"
```

---

### Task 2: End-to-end test — SIGTERM flushes buffered records

**Files:**
- Create: `tests/sigterm_graceful_shutdown_e2e.rs`

**Interfaces:**
- Consumes: the behaviour from Task 1 (`main.rs` shuts down gracefully on SIGTERM). Task 1 must be complete and committed first — this test fails without it.
- Produces: nothing consumed by later tasks.

**What this test proves, and what it does not.** Under `cargo test` the binary is an ordinary child process, **not PID 1**, so this does not reproduce the kernel's PID-1 signal-discard behaviour — against the unfixed binary SIGTERM takes its default action and kills the child immediately rather than being discarded. Reproducing the PID-1 case would require running the child as an actual init process and is out of scope. What it does prove is the thing that matters: **SIGTERM now drives the same graceful path SIGINT already did**, because a *handled* signal is never subject to the PID-1 special case.

The discriminator is the two assertions **together**: unfixed → child killed by signal, no Parquet file; fixed → clean exit status, Parquet file present. The exit assertion must check that the process was not signal-terminated — merely checking that `wait()` returned inside the deadline is vacuous, since the unfixed binary also exits promptly (by dying).

- [ ] **Step 1: Write the failing test**

Create `tests/sigterm_graceful_shutdown_e2e.rs`. This follows the established pattern in `tests/listener_ip_whitelist_e2e.rs` (generated config in a tempdir, `current_dir` set to it, `ChildGuard`, readiness polling, stdout/stderr to files rather than pipes to avoid a full-buffer deadlock).

```rust
//! End-to-end test: a real `logthing` process flushes its buffered records
//! to disk when it receives SIGTERM.
//!
//! Before the fix, `main.rs` installed only `tokio::signal::ctrl_c()`
//! (SIGINT), so SIGTERM never reached the graceful-shutdown sequence and
//! every record buffered since the last periodic flush was lost on pod
//! termination.
//!
//! The config below sets `max_buffer_rows = 100000` and
//! `flush_interval_secs = 3600`, so neither the row threshold nor the age
//! ticker can fire inside the test window — the shutdown drain
//! (`buffered_writer.rs`'s channel-close arm, which runs
//! `drain_pending_flushes()` then `flush_all()`) is the only path that can
//! produce a Parquet file here.
//!
//! NOTE: the child is an ordinary process, not PID 1, so this does not
//! reproduce the kernel's PID-1 signal-discard behaviour. Against the
//! unfixed binary SIGTERM simply kills the child outright. That is why the
//! exit assertion checks the process was *not* signal-terminated rather than
//! merely that it exited.

use std::fs::File;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::sleep;

const READY_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Must clear the binary's own 10s writer-flush deadline
/// (`await_handles_with_deadline` in `src/main.rs`) with margin.
const EXIT_TIMEOUT: Duration = Duration::from_secs(45);

const MESSAGE_COUNT: usize = 25;

/// Kills and reaps the child on drop — including during a panicking
/// assertion — so a failing test never leaves an orphaned daemon.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn walk_all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_all_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

async fn wait_for_metrics(url: &str, deadline: Instant) {
    loop {
        if let Ok(resp) = reqwest::get(url).await
            && resp.status().is_success()
        {
            return;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for metrics endpoint {url}");
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Poll until the child owns the UDP port. UDP has no handshake, so this
/// probes by trying to bind the same address: once our bind fails with
/// `AddrInUse`, the child has claimed it.
async fn wait_for_udp(port: u16, deadline: Instant) {
    let addr = format!("127.0.0.1:{port}");
    loop {
        match UdpSocket::bind(&addr).await {
            Ok(sock) => drop(sock),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return,
            Err(e) => panic!("unexpected error probing UDP {port}: {e}"),
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for syslog UDP {port} to be bound");
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Poll the metrics endpoint until `syslog_messages_received` reaches
/// `want`, so the test never signals the child before its records are
/// actually in the writer's buffer.
async fn wait_for_received(url: &str, want: u64, deadline: Instant) {
    let mut last = 0;
    loop {
        if let Ok(resp) = reqwest::get(url).await
            && let Ok(body) = resp.text().await
        {
            last = logthing::profiling::parse_counter(&body, "syslog_messages_received")
                .unwrap_or(0);
            if last >= want {
                return;
            }
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for syslog_messages_received >= {want}, last saw {last}");
        }
        sleep(POLL_INTERVAL).await;
    }
}

#[tokio::test]
async fn sigterm_flushes_buffered_records_to_disk() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp.path().join("syslog-out");

    // Allocate both ports together so they cannot collide with each other.
    let (http_port, metrics_port, syslog_udp_port) = {
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let metrics = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        (
            http.local_addr().unwrap().port(),
            metrics.local_addr().unwrap().port(),
            udp.local_addr().unwrap().port(),
        )
    };

    let toml = format!(
        r#"
bind_address = "127.0.0.1:{http_port}"

[tls]
enabled = false

[metrics]
enabled = true
port = {metrics_port}

[syslog]
enabled = true
udp_port = {syslog_udp_port}

[syslog.local]
directory = "{out_dir}"
prefix = "syslog"
max_buffer_rows = 100000
flush_interval_secs = 3600
"#,
        out_dir = out_dir.display(),
    );
    std::fs::write(tmp.path().join("logthing.toml"), toml).expect("write logthing.toml");

    // Redirect child output to files: a piped child can deadlock the parent
    // if its output buffer fills and nobody drains it.
    let stdout_log = File::create(tmp.path().join("stdout.log")).unwrap();
    let stderr_log = File::create(tmp.path().join("stderr.log")).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_logthing"))
        .current_dir(tmp.path())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log))
        .spawn()
        .expect("spawn logthing binary");
    let pid = child.id();
    let mut guard = ChildGuard(child);

    let deadline = Instant::now() + READY_TIMEOUT;
    let metrics_url = format!("http://127.0.0.1:{metrics_port}/metrics");
    wait_for_metrics(&metrics_url, deadline).await;
    wait_for_udp(syslog_udp_port, deadline).await;

    // Send the records.
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 0..MESSAGE_COUNT {
        let msg = format!("<134>Jan 15 10:30:45 host-e2e sigterm-test: record {i}\n");
        probe
            .send_to(msg.as_bytes(), ("127.0.0.1", syslog_udp_port))
            .await
            .expect("send syslog datagram");
    }
    wait_for_received(&metrics_url, MESSAGE_COUNT as u64, deadline).await;

    // Nothing may have been written yet — only the shutdown drain can flush.
    let mut before = Vec::new();
    walk_all_files(&out_dir, &mut before);
    assert!(
        before.iter().all(|p| p.extension().is_none_or(|e| e != "parquet")),
        "a Parquet file existed before shutdown, so this test cannot \
         attribute the post-shutdown file to the drain: {before:?}"
    );

    // --- The actual trigger under test ---
    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("run kill(1)");
    assert!(status.success(), "kill -TERM {pid} failed");

    // Poll for exit rather than blocking, so we can bound the wait.
    let exit_deadline = Instant::now() + EXIT_TIMEOUT;
    let exit_status = loop {
        match guard.0.try_wait().expect("try_wait") {
            Some(status) => break status,
            None => {
                if Instant::now() > exit_deadline {
                    panic!(
                        "child {pid} did not exit within {EXIT_TIMEOUT:?} of SIGTERM \
                         — the signal was ignored"
                    );
                }
                sleep(POLL_INTERVAL).await;
            }
        }
    };

    // Assertion 1: exited on its own, NOT killed by the signal. Checking only
    // that it exited would be vacuous — the unfixed binary also exits
    // promptly, by dying.
    assert!(
        exit_status.signal().is_none(),
        "child was terminated by signal {:?} instead of shutting down \
         gracefully — SIGTERM reached default disposition, meaning no handler \
         was installed",
        exit_status.signal()
    );
    assert!(
        exit_status.success(),
        "child exited uncleanly: {exit_status:?}"
    );

    // Assertion 2: the drain actually wrote the records.
    let mut after = Vec::new();
    walk_all_files(&out_dir, &mut after);
    let parquet: Vec<_> = after
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
        .collect();
    assert!(
        !parquet.is_empty(),
        "no Parquet file under {} after SIGTERM — the shutdown drain never ran, \
         so the buffered records were lost. Files present: {after:?}",
        out_dir.display()
    );

    let mut rows = 0usize;
    for path in &parquet {
        let file = File::open(path).expect("open parquet");
        let reader =
            parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file)
                .expect("parquet reader")
                .build()
                .expect("build reader");
        for batch in reader {
            rows += batch.expect("read batch").num_rows();
        }
    }
    assert_eq!(
        rows, MESSAGE_COUNT,
        "expected all {MESSAGE_COUNT} buffered records to be flushed by the \
         shutdown drain, found {rows}"
    );
}
```

- [ ] **Step 2: Run the test to verify it passes against the fixed binary**

```bash
source ~/.cargo/env
export CC=/usr/bin/gcc CXX=/usr/bin/g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/gcc
cargo test --test sigterm_graceful_shutdown_e2e -- --nocapture
```

Expected: PASS.

If it fails on the `syslog.local` config (e.g. a TOML key mismatch), read the real field names off `SyslogLocalConfig` in `src/config/mod.rs` and the `[syslog.local]` wiring in `src/main.rs` and correct the generated config — do not weaken the assertions to make it pass.

- [ ] **Step 3: Prove the test actually catches the bug**

A test that passes on the fixed binary but would also have passed on the broken one is worthless. Verify the discriminator by temporarily reverting the fix:

```bash
git stash push -- src/shutdown.rs src/main.rs   # if Task 1 is uncommitted; otherwise:
# git checkout HEAD~1 -- src/main.rs
cargo test --test sigterm_graceful_shutdown_e2e 2>&1 | tail -30
```

Expected: FAIL, on the `exit_status.signal().is_none()` assertion (child killed by signal 15) or on the missing-Parquet assertion. Then restore:

```bash
git stash pop        # or: git checkout HEAD -- src/main.rs
cargo test --test sigterm_graceful_shutdown_e2e
```

Expected: PASS again. **Record both observed outputs in your final report** — this step is the evidence that the test is real.

- [ ] **Step 4: Run the full suite for regressions**

```bash
cargo test
```

Expected: no new failures versus the branch point. Note any pre-existing failures explicitly rather than attributing them to this change.

- [ ] **Step 5: Commit**

```bash
git add tests/sigterm_graceful_shutdown_e2e.rs
git commit -m "test: e2e proof that SIGTERM flushes buffered records

Configures the syslog local sink so neither the row threshold nor the
age ticker can fire in the test window, making the shutdown drain the
only path that can produce a Parquet file. Asserts the child was not
signal-terminated, which is what distinguishes the fixed binary from
the broken one.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UquMzVB7CCkD2EzadzNMA5"
```
