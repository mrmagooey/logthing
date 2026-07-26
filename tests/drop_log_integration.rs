//! Integration coverage for per-drop log throttling.
//!
//! The unit tests in `drop_log.rs` pin the policy; the first two tests below
//! pin the property the change exists for: a burst of drops must produce ONE
//! log line, not one per drop, while still reporting an accurate running
//! total. Those two tests call `DropLogThrottles::check_at` directly and
//! re-emit the log line inline, so they exercise the throttle against
//! itself, not against a real call site.
//!
//! The third test below closes that gap: it drives a real
//! `GenericS3Handler` (`ParquetWriterHandle<GenericSink>`, the same type
//! `IngestState.generic_s3` holds in production) through `try_send` /
//! `drop_log_due`, the same API real call sites use, and asserts that HEC
//! and OTLP — which share that one handle in production — both get to log
//! their own first occurrence rather than muting each other.

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
        // Trailing space distinguishes an exact match from a prefix hit like
        // `dropped_total=15001` (this formatter always appends a trailing
        // space after each field — see `Capture::on_event` above).
        lines[0].contains("dropped_total=1 "),
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
        // Trailing space (see the first test's assertion above) tightens
        // this to an exact field match, not a prefix hit like
        // `dropped_total=50011`.
        lines[1].contains("dropped_total=5001 "),
        "the second line must report every drop since start, got: {}",
        lines[1]
    );
}

/// A real production call site: `GenericS3Handler`, the same
/// `ParquetWriterHandle<GenericSink>` that `IngestState.generic_s3` holds,
/// which both the HEC/NDJSON ingest routes (`ingest/handlers.rs`) and the
/// OTLP ingest route (`server/mod.rs`) send through.
///
/// This does not drive the full HTTP handlers end-to-end — standing up the
/// axum router, HEC auth tokens, and request bodies for both routes is
/// machinery orthogonal to what this throttle needs covered. Per the review
/// note allowing a direct-handle substitute when driving the full handlers
/// is impractical, this instead constructs the same `GenericS3Handler` type
/// production code builds (mirroring the construction `generic_s3.rs`'s own
/// tests use), fills its channel with real `try_send` calls until one
/// returns `Full`, and then calls `drop_log_due` with both `DropSite::Hec`
/// and `DropSite::Otlp` against that one real, shared handle — the exact
/// shape of the production hazard (an OTLP burst muting HEC's line, or vice
/// versa) that keying by `DropSite` rather than by handle exists to prevent.
#[tokio::test(flavor = "current_thread")]
async fn hec_and_otlp_share_a_real_handle_without_muting_each_other() {
    use logthing::config::S3ConnectionConfig;
    use logthing::forwarding::buffered_writer::{
        BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetWriterHandle,
    };
    use logthing::forwarding::generic_s3::GenericSink;
    use logthing::forwarding::s3_sink::S3Sink;
    use logthing::ingest::GenericRecord;
    use tokio::sync::mpsc::error::TrySendError;

    let connection = S3ConnectionConfig {
        endpoint: "http://127.0.0.1:1".to_string(),
        bucket: "test-bucket".to_string(),
        region: "us-east-1".to_string(),
        access_key: "AKIATEST".to_string(),
        secret_key: "SECRETTEST".to_string(),
    };
    // `from_connection` only validates config shape; it never dials the
    // endpoint, so an unreachable address (127.0.0.1:1) is fine — nothing in
    // this test triggers an actual upload.
    let s3 = Arc::new(
        S3Sink::from_connection(&connection)
            .await
            .expect("from_connection only validates config shape, doesn't connect"),
    );

    let cfg = BufferedWriterConfig {
        connection,
        prefix: "hec".to_string(),
        max_buffer_rows: usize::MAX,
        flush_threshold_bytes: usize::MAX,
        flush_interval_secs: 3600,
        channel_capacity: 4,
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
        interval: LiveInterval::new(std::time::Duration::from_secs(3600)),
    };

    let (handle, _join) = ParquetWriterHandle::start(GenericSink, s3, cfg, policy);

    fn record() -> GenericRecord {
        GenericRecord {
            sourcetype: "access_log".to_string(),
            host: Some("host1".to_string()),
            time: Some(chrono::Utc::now()),
            fields: serde_json::json!({"action": "login"}),
            received_at: chrono::Utc::now(),
        }
    }

    // Flood the channel with a tight synchronous loop — no `.await` between
    // sends — so the spawned background writer task never gets a chance to
    // run and drain it on this current-thread runtime, making the channel
    // reliably fill to `channel_capacity` and the next `try_send` return
    // `Full`.
    let mut saw_full = false;
    for _ in 0..64 {
        if let Err(TrySendError::Full(_)) = handle.try_send(record()) {
            saw_full = true;
            break;
        }
    }
    assert!(
        saw_full,
        "expected try_send to return Full after flooding a channel_capacity=4 handle"
    );

    // Both DropSite::Hec and DropSite::Otlp keyed against the SAME handle —
    // exactly the production scenario. Each must log on its own first
    // occurrence; neither may mute the other.
    assert_eq!(
        handle.drop_log_due(DropSite::Hec, DropKind::Full),
        Some(1),
        "HEC's first drop on the shared handle must log"
    );
    assert_eq!(
        handle.drop_log_due(DropSite::Otlp, DropKind::Full),
        Some(1),
        "OTLP's first drop on the SAME shared handle must also log — an OTLP burst must not mute \
         HEC's first-occurrence line, or vice versa"
    );
}
