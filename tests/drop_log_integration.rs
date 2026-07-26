//! Integration coverage for per-drop log throttling.
//!
//! The unit tests in `drop_log.rs` pin the policy; this pins the property the
//! change exists for: a burst of drops must produce ONE log line, not one per
//! drop, while still reporting an accurate running total.

use std::sync::{Arc, Mutex};

use logthing::forwarding::drop_log::{
    DROP_LOG_INTERVAL_NANOS, DropKind, DropLogThrottles, DropSite,
};
use tracing::subscriber;
use tracing_subscriber::layer::SubscriberExt;

/// Collects formatted event messages so we can count emitted lines.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

impl<S> tracing_subscriber::Layer<S> for Capture
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct V(String);
        impl tracing::field::Visit for V {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={:?} ", f.name(), v));
            }
        }
        let mut v = V(String::new());
        event.record(&mut v);
        self.0.lock().unwrap().push(v.0);
    }
}

#[test]
fn burst_of_drops_emits_one_line_with_a_correct_total() {
    let cap = Capture::default();
    let sub = tracing_subscriber::registry().with(cap.clone());
    let _g = subscriber::set_default(sub);

    let throttles = DropLogThrottles::new();
    // 10,000 drops inside one interval, exactly as an overload burst produces.
    for _ in 0..10_000 {
        if let Some(dropped_total) = throttles.check_at(DropSite::Syslog, DropKind::Full, 0) {
            tracing::warn!(dropped_total, "Syslog S3 channel full; dropped message");
        }
    }

    let lines = cap.0.lock().unwrap();
    assert_eq!(
        lines.len(),
        1,
        "10,000 drops must emit exactly one line, got {}",
        lines.len()
    );
    assert!(
        lines[0].contains("dropped_total=1"),
        "first line reports the total at emission time, got: {}",
        lines[0]
    );
}

#[test]
fn a_second_line_after_the_interval_reports_the_accumulated_total() {
    let cap = Capture::default();
    let sub = tracing_subscriber::registry().with(cap.clone());
    let _g = subscriber::set_default(sub);

    let throttles = DropLogThrottles::new();
    for _ in 0..5_000 {
        if let Some(dropped_total) = throttles.check_at(DropSite::Syslog, DropKind::Full, 0) {
            tracing::warn!(dropped_total, "Syslog S3 channel full; dropped message");
        }
    }
    // One more drop, past the window.
    if let Some(dropped_total) =
        throttles.check_at(DropSite::Syslog, DropKind::Full, DROP_LOG_INTERVAL_NANOS)
    {
        tracing::warn!(dropped_total, "Syslog S3 channel full; dropped message");
    }

    let lines = cap.0.lock().unwrap();
    assert_eq!(lines.len(), 2, "expected one line per interval");
    assert!(
        lines[1].contains("dropped_total=5001"),
        "the second line must report every drop since start, got: {}",
        lines[1]
    );
}
