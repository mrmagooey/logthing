//! Shutdown utilities: signal handling and deadline-bounded handle awaiting.

use std::time::Duration;
use tokio::task::JoinHandle;

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

/// Await a list of `JoinHandle<()>` tasks, respecting a shared wall-clock
/// deadline.
///
/// Each handle is awaited in order against the *remaining* time left before
/// `deadline` expires.  As soon as the deadline fires any un-awaited handles
/// are left to run in the background (the caller is responsible for aborting
/// them beforehand if that is required).
///
/// Returns the number of handles that completed (returned or panicked) before
/// the deadline.  Handles that were still running when the deadline fired are
/// *not* counted.
///
/// # Example
/// ```no_run
/// use logthing::shutdown::await_handles_with_deadline;
/// use std::time::Duration;
/// use tokio::task;
///
/// # #[tokio::main]
/// # async fn main() {
/// let handles: Vec<task::JoinHandle<()>> = (0..3)
///     .map(|_| tokio::spawn(async {}))
///     .collect();
/// let completed = await_handles_with_deadline(handles, Duration::from_secs(10)).await;
/// assert_eq!(completed, 3);
/// # }
/// ```
pub async fn await_handles_with_deadline(
    handles: Vec<JoinHandle<()>>,
    deadline: Duration,
) -> usize {
    let mut completed = 0usize;
    let sleep = tokio::time::sleep(deadline);
    tokio::pin!(sleep);

    for handle in handles {
        tokio::select! {
            _ = handle => {
                completed += 1;
            }
            _ = &mut sleep => {
                // Deadline expired — stop waiting.
                return completed;
            }
        }
    }

    completed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// All handles complete quickly — function returns the full count well
    /// within the deadline.
    #[tokio::test]
    async fn all_handles_complete_before_deadline() {
        let handles: Vec<JoinHandle<()>> = (0..4)
            .map(|_| tokio::spawn(async { /* completes instantly */ }))
            .collect();

        let start = Instant::now();
        let completed = await_handles_with_deadline(handles, Duration::from_secs(5)).await;
        let elapsed = start.elapsed();

        assert_eq!(completed, 4, "all 4 handles should be counted as completed");
        assert!(
            elapsed < Duration::from_secs(1),
            "should finish well before the 5 s deadline; took {elapsed:?}"
        );
    }

    /// A handle that sleeps past a short deadline is not counted, and the
    /// function itself returns within roughly the deadline (not blocked forever).
    #[tokio::test]
    async fn hung_handle_is_not_counted_and_function_returns_on_time() {
        // One fast handle, one slow handle that outlasts the deadline.
        let fast = tokio::spawn(async { /* completes instantly */ });
        let slow = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let deadline = Duration::from_millis(200);
        let start = Instant::now();
        let completed = await_handles_with_deadline(vec![fast, slow], deadline).await;
        let elapsed = start.elapsed();

        // Only the fast handle should be counted.
        assert_eq!(
            completed, 1,
            "only the fast handle should complete before the deadline"
        );

        // The function must return promptly after the deadline fires.
        assert!(
            elapsed < Duration::from_millis(600),
            "function should return within ~deadline (200 ms); took {elapsed:?}"
        );
    }

    /// No handles at all — returns 0 immediately.
    #[tokio::test]
    async fn empty_handles_returns_zero() {
        let completed = await_handles_with_deadline(vec![], Duration::from_secs(5)).await;
        assert_eq!(completed, 0);
    }

    /// When ALL handles finish quickly the deadline is NOT consumed — the
    /// function exits as soon as the last handle completes, well before the
    /// deadline wall time.
    #[tokio::test]
    async fn returns_immediately_when_all_done_without_waiting_for_deadline() {
        let handles: Vec<JoinHandle<()>> = (0..2).map(|_| tokio::spawn(async {})).collect();

        let start = Instant::now();
        let completed = await_handles_with_deadline(handles, Duration::from_secs(10)).await;
        let elapsed = start.elapsed();

        assert_eq!(completed, 2);
        assert!(
            elapsed < Duration::from_secs(1),
            "should not wait the full 10 s; took {elapsed:?}"
        );
    }

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
}
