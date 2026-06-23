//! Shutdown utilities: deadline-bounded handle awaiting.

use std::time::Duration;
use tokio::task::JoinHandle;

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
}
