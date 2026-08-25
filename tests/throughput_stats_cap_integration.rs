//! Integration coverage for the `ThroughputStats` event-type cap.
//!
//! The unit tests in `src/stats/mod.rs` pin the capping logic against a
//! single-threaded caller. The gap this file closes: `ThroughputStats` wraps
//! a real `DashMap` shared behind `Arc` across many concurrent tasks (the
//! same shape `AppState.throughput` has in production, where every request
//! handler holds a clone), and the cap check
//! (`contains_key`-then-`len`-then-`entry`) is explicitly racy under
//! concurrency. This drives many real tokio tasks at a shared
//! `ThroughputStats` handle with keys that exceed the cap, and confirms the
//! map stays *bounded* (not unbounded growth to one row per distinct key)
//! even though the race can let it overshoot the exact cap slightly.

use logthing::stats::ThroughputStats;
use std::sync::Arc;

/// Mirror of `stats::MAX_EVENT_TYPES` (private to that module). Kept in sync
/// by the assertions below, which would fail loudly if the real cap ever
/// diverged from this value in a way that changed the bounded-growth shape.
const MAX_EVENT_TYPES: usize = 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cap_holds_under_concurrent_distinct_keys() {
    let stats = Arc::new(ThroughputStats::new());

    // Comfortably over the cap, spread across many concurrent tasks so the
    // racy contains_key/len/entry check actually gets exercised concurrently
    // rather than serialized by a single caller.
    const TASKS: usize = 64;
    const KEYS_PER_TASK: usize = 32; // 64 * 32 = 2048 distinct keys, 2x the cap.

    let mut joins = Vec::with_capacity(TASKS);
    for task_id in 0..TASKS {
        let stats = stats.clone();
        joins.push(tokio::spawn(async move {
            for k in 0..KEYS_PER_TASK {
                stats.record_event(format!("task-{task_id}-key-{k}")).await;
            }
        }));
    }
    for j in joins {
        j.await.expect("task panicked");
    }

    let snapshot = stats.snapshot().await;

    // Bounded, not unbounded: without the cap this would be exactly 2048
    // rows (one per distinct key). The racy check is bounded by thread
    // count, so allow slack up to TASKS entries past the cap, but the
    // dominant behavior must be collapsing into _other.
    assert!(
        snapshot.len() <= MAX_EVENT_TYPES + TASKS,
        "map grew to {} rows, expected at most {} (cap {} + race slack bounded by {} tasks)",
        snapshot.len(),
        MAX_EVENT_TYPES + TASKS,
        MAX_EVENT_TYPES,
        TASKS
    );
    assert!(
        snapshot.len() < TASKS * KEYS_PER_TASK,
        "the cap must have collapsed at least some of the 2048 distinct keys, got {} rows",
        snapshot.len()
    );

    let other_total: u64 = snapshot
        .iter()
        .filter(|row| row.event_type == "_other")
        .map(|row| row.total_events)
        .sum();
    assert!(
        other_total > 0,
        "expected the _other bucket to have absorbed overflowing keys"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_stays_bounded_when_one_key_dominates_at_the_cap() {
    let stats = ThroughputStats::new();

    for i in 0..MAX_EVENT_TYPES {
        stats.record_event(format!("known-type-{i}")).await;
    }
    assert_eq!(stats.snapshot().await.len(), MAX_EVENT_TYPES);

    // A flood of never-seen keys after the cap must all land in "_other",
    // not grow the map further.
    for i in 0..5_000 {
        stats.record_event(format!("flood-{i}")).await;
    }

    let snapshot = stats.snapshot().await;
    assert_eq!(
        snapshot.len(),
        MAX_EVENT_TYPES + 1,
        "5,000 overflowing keys must still collapse to exactly one _other row"
    );
    let other = snapshot
        .iter()
        .find(|row| row.event_type == "_other")
        .expect("expected _other row");
    assert_eq!(other.total_events, 5_000);
}
