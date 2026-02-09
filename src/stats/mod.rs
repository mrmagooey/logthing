use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Arc;

const RETENTION_MINUTES: i64 = 60;

#[derive(Clone)]
pub struct ThroughputStats {
    inner: Arc<DashMap<String, EventStats>>,
}

impl Default for ThroughputStats {
    fn default() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }
}

impl ThroughputStats {
    /// Create a new throughput statistics tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an event occurrence for tracking throughput statistics.
    ///
    /// Events are aggregated by type and tracked in 1-minute buckets.
    /// Uses DashMap for lock-free concurrent access.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wef_server::stats::ThroughputStats;
    ///
    /// let stats = ThroughputStats::new();
    ///
    /// // Record some events
    /// stats.record_event("Microsoft-Windows-Security-Auditing:4624".to_string()).await;
    /// stats.record_event("Microsoft-Windows-Security-Auditing:4624".to_string()).await;
    /// stats.record_event("Microsoft-Windows-Security-Auditing:4625".to_string()).await;
    /// ```
    pub async fn record_event(&self, event_type: String) {
        let minute = current_minute();
        // Use DashMap for lock-free concurrent updates
        self.inner
            .entry(event_type)
            .or_default()
            .value_mut()
            .record(minute);
    }

    /// Get a snapshot of current throughput statistics.
    ///
    /// Returns per-event-type statistics including total events, events in the
    /// last minute, and events in the last 5 minutes.
    /// Uses DashMap for lock-free concurrent reads.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wef_server::stats::ThroughputStats;
    ///
    /// let stats = ThroughputStats::new();
    ///
    /// // Record events and get snapshot
    /// stats.record_event("Microsoft-Windows-Security-Auditing:4624".to_string()).await;
    ///
    /// let snapshot = stats.snapshot().await;
    /// for row in snapshot {
    ///     println!(
    ///         "{}: {} total, {} last minute",
    ///         row.event_type, row.total_events, row.last_minute
    ///     );
    /// }
    /// ```
    pub async fn snapshot(&self) -> Vec<ThroughputSnapshot> {
        let minute = current_minute();
        // Use DashMap's concurrent iterator for lock-free reads
        let mut rows: Vec<ThroughputSnapshot> = self
            .inner
            .iter()
            .map(|entry| {
                let event_type = entry.key().clone();
                let stats = entry.value();
                stats.to_snapshot(event_type, minute)
            })
            .collect();

        rows.sort_by(|a, b| b.last_minute.cmp(&a.last_minute));
        rows
    }
}

#[derive(Default)]
struct EventStats {
    total: u64,
    buckets: VecDeque<MinuteBucket>,
}

impl EventStats {
    fn record(&mut self, minute: i64) {
        self.total += 1;
        match self.buckets.back_mut() {
            Some(bucket) if bucket.minute == minute => bucket.count += 1,
            _ => self.buckets.push_back(MinuteBucket { minute, count: 1 }),
        }
        self.retain_recent(minute);
    }

    fn retain_recent(&mut self, minute: i64) {
        while let Some(front) = self.buckets.front() {
            if front.minute < minute - RETENTION_MINUTES {
                self.buckets.pop_front();
            } else {
                break;
            }
        }
    }

    fn to_snapshot(&self, event_type: String, minute: i64) -> ThroughputSnapshot {
        let last_minute = self.sum_for_window(1, minute);
        let last_five_minutes = self.sum_for_window(5, minute);
        ThroughputSnapshot {
            event_type,
            total_events: self.total,
            last_minute,
            last_five_minutes,
            average_per_second_last_minute: if last_minute == 0 {
                0.0
            } else {
                last_minute as f64 / 60.0
            },
        }
    }

    fn sum_for_window(&self, window_minutes: i64, minute: i64) -> u64 {
        if window_minutes <= 0 {
            return 0;
        }
        let start = minute - window_minutes + 1;
        self.buckets
            .iter()
            .filter(|bucket| bucket.minute >= start)
            .map(|bucket| bucket.count)
            .sum()
    }
}

#[derive(Serialize, Clone)]
pub struct ThroughputSnapshot {
    pub event_type: String,
    pub total_events: u64,
    pub last_minute: u64,
    pub last_five_minutes: u64,
    pub average_per_second_last_minute: f64,
}

struct MinuteBucket {
    minute: i64,
    count: u64,
}

fn current_minute() -> i64 {
    let now: DateTime<Utc> = Utc::now();
    now.timestamp() / 60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_counts_per_event_type() {
        let stats = ThroughputStats::new();

        stats.record_event("type-a".into()).await;
        stats.record_event("type-b".into()).await;
        stats.record_event("type-a".into()).await;

        let snapshot = stats.snapshot().await;
        let mut map = std::collections::HashMap::new();
        for row in snapshot {
            map.insert(row.event_type.clone(), row);
        }

        assert_eq!(map.get("type-a").unwrap().total_events, 2);
        assert_eq!(map.get("type-b").unwrap().total_events, 1);
        assert!(map.get("type-a").unwrap().average_per_second_last_minute > 0.0);
    }
}
