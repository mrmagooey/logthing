use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

const RETENTION_MINUTES: i64 = 60;

#[derive(Clone, Default)]
pub struct ThroughputStats {
    inner: Arc<RwLock<HashMap<String, EventStats>>>,
}

impl ThroughputStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn record_event(&self, event_type: String) {
        let minute = current_minute();
        let mut guard = self.inner.write().await;
        let stats = guard.entry(event_type).or_insert_with(EventStats::default);
        stats.record(minute);
    }

    pub async fn snapshot(&self) -> Vec<ThroughputSnapshot> {
        let guard = self.inner.read().await;
        let minute = current_minute();
        let mut rows = guard
            .iter()
            .map(|(event_type, stats)| stats.to_snapshot(event_type.clone(), minute))
            .collect::<Vec<_>>();

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
