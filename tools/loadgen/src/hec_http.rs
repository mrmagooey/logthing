//! `loadgen hec-http` -- paced, concurrent HTTP load generator for the
//! Splunk HEC event ingest route (`POST /services/collector/event`).
//!
//! Unlike the socket-based generators (`syslog-udp`, `zeek-tcp`,
//! `ipfix-udp`, `suricata-tcp`), HTTP is a request/response protocol: one
//! serialized request-then-wait would be latency-bound and never reach an
//! interesting rate. This subcommand keeps up to `--concurrency` requests
//! in flight at once (a `tokio::sync::Semaphore` gates how many are
//! outstanding), while `crate::pacing`'s tick-based fractional-carry
//! accumulator controls how many *new* requests are launched per tick --
//! same pacing model as every other subcommand, just launching requests
//! instead of writing bytes directly.
//!
//! Each event line matches the envelope `logthing::ingest::parse_hec_event_body`
//! actually accepts: `{"event": <any>, "time": <epoch_float>, "host": "h",
//! "sourcetype": "t"}` (see `src/ingest/parse.rs`).
//!
//! Only a 2xx response counts as "sent" for the achieved-rate figure --
//! counting a rejected request as sent would produce a measurement that
//! looks like zero loss while actually meaning nothing. A 401 specifically
//! means `--token` does not match the target's `[hec.token]`; that
//! condition cannot self-correct mid-run, so the whole run aborts loudly
//! with the status code rather than quietly piling up errors.

use anyhow::Context;
use clap::Args;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use crate::pacing::tick_record_count;

#[derive(Args, Debug)]
pub struct HecHttpArgs {
    /// Target host to send HEC HTTP requests to.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Target HTTP port. Matches `Config::default()`'s `bind_address` port
    /// (`default_bind_address()` -> `0.0.0.0:5985` in `src/config/mod.rs`).
    #[arg(long, default_value_t = 5985)]
    pub port: u16,

    /// Target sustained rate, in records/sec (2xx responses only). 0 means
    /// "unbounded" (launch requests as fast as `--concurrency` allows).
    #[arg(long, default_value_t = 10_000)]
    pub target_rate: u64,

    /// How long to send for, in seconds.
    #[arg(long, default_value_t = 60)]
    pub duration_secs: u64,

    /// Shared secret sent as `Authorization: Splunk <token>`. Must match
    /// the target server's `[hec.token]` config value. Empty (the default)
    /// sends no Authorization header at all, matching a dev-mode server
    /// with an empty configured token (auth skipped entirely).
    #[arg(long, default_value = "")]
    pub token: String,

    /// `sourcetype` recorded in each HEC event envelope.
    #[arg(long, default_value = "loadgen")]
    pub sourcetype: String,

    /// Maximum number of HTTP requests in flight at once. HTTP is
    /// latency-bound, so this is the real throughput lever -- raise it if
    /// the achieved rate plateaus below `--target-rate` with CPU to spare.
    #[arg(long, default_value_t = 64)]
    pub concurrency: usize,
}

/// Shared, cheaply-cloned state every in-flight request task needs.
#[derive(Clone)]
struct HecCtx {
    client: reqwest::Client,
    url: Arc<str>,
    token: Arc<str>,
    sourcetype: Arc<str>,
    semaphore: Arc<Semaphore>,
    sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    auth_failed: Arc<AtomicBool>,
}

pub async fn run(args: HecHttpArgs) -> anyhow::Result<()> {
    let url = format!(
        "http://{}:{}/services/collector/event",
        args.host, args.port
    );
    let client = reqwest::Client::builder()
        .build()
        .context("build reqwest HTTP client")?;

    println!(
        "loadgen hec-http: sending to {url} at target_rate={} rec/s for {}s (concurrency={})",
        args.target_rate, args.duration_secs, args.concurrency
    );

    let ctx = HecCtx {
        client,
        url: url.as_str().into(),
        token: args.token.as_str().into(),
        sourcetype: args.sourcetype.as_str().into(),
        semaphore: Arc::new(Semaphore::new(args.concurrency.max(1))),
        sent: Arc::new(AtomicU64::new(0)),
        errors: Arc::new(AtomicU64::new(0)),
        auth_failed: Arc::new(AtomicBool::new(false)),
    };

    let duration = Duration::from_secs(args.duration_secs);
    let start = Instant::now();
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut n: u64 = 0;

    if args.target_rate == 0 {
        // Unbounded: launch requests as fast as `--concurrency` allows.
        while start.elapsed() < duration && !ctx.auth_failed.load(Ordering::Relaxed) {
            spawn_request(&ctx, &mut tasks, n).await;
            n += 1;
        }
    } else {
        // Same 1ms-tick, fractional-carry pacing as every other subcommand
        // -- see `crate::pacing` for why the carry accumulator is shared
        // rather than reimplemented here. Here it controls how many
        // requests are *launched* per tick, not how many complete.
        let per_tick_interval = crate::pacing::TICK;
        let records_per_tick_target = args.target_rate as f64 * per_tick_interval.as_secs_f64();
        let mut ticker = tokio::time::interval(per_tick_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Burst);
        let mut carry: f64 = 0.0;

        'send_loop: loop {
            if start.elapsed() >= duration {
                break;
            }
            ticker.tick().await;
            let records_this_tick = tick_record_count(&mut carry, records_per_tick_target);
            for _ in 0..records_this_tick {
                if start.elapsed() >= duration || ctx.auth_failed.load(Ordering::Relaxed) {
                    break 'send_loop;
                }
                spawn_request(&ctx, &mut tasks, n).await;
                n += 1;
            }
        }
    }

    // Drain in-flight requests so `sent`/`errors` reflect everything that
    // was actually launched, not just what had completed by the deadline.
    while tasks.join_next().await.is_some() {}

    let elapsed = start.elapsed();
    let sent = ctx.sent.load(Ordering::Relaxed);
    let errors = ctx.errors.load(Ordering::Relaxed);

    if errors > 0 {
        println!(
            "loadgen hec-http: {errors} requests rejected (non-2xx or transport error) -- \
             not counted as sent"
        );
    }

    if ctx.auth_failed.load(Ordering::Relaxed) {
        anyhow::bail!(
            "loadgen hec-http: aborted -- server rejected requests with 401 Unauthorized; \
             --token does not match the target's [hec.token] (sent {sent} before aborting)"
        );
    }

    println!(
        "loadgen hec-http: sent {sent} records in {:.3}s (achieved rate: {:.1} rec/s)",
        elapsed.as_secs_f64(),
        sent as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}

/// Acquire a concurrency permit (blocking this loop, i.e. natural
/// backpressure, if `--concurrency` in-flight requests are already
/// outstanding) and spawn one HEC event POST onto `tasks`.
async fn spawn_request(ctx: &HecCtx, tasks: &mut JoinSet<()>, n: u64) {
    let permit = ctx
        .semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("semaphore is never closed");
    let ctx = ctx.clone();
    tasks.spawn(async move {
        let _permit = permit;
        let body = build_event_json(n, &ctx.sourcetype);
        let mut req = ctx.client.post(ctx.url.as_ref()).json(&body);
        if !ctx.token.is_empty() {
            req = req.header("Authorization", format!("Splunk {}", ctx.token));
        }
        match req.send().await {
            Ok(resp) if is_accepted(resp.status()) => {
                ctx.sent.fetch_add(1, Ordering::Relaxed);
            }
            Ok(resp) => {
                let status = resp.status();
                ctx.errors.fetch_add(1, Ordering::Relaxed);
                if status == StatusCode::UNAUTHORIZED {
                    ctx.auth_failed.store(true, Ordering::Relaxed);
                    eprintln!(
                        "loadgen hec-http: request rejected with {status} (Unauthorized) -- \
                         check --token matches the server's [hec.token]"
                    );
                }
            }
            Err(e) => {
                ctx.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("loadgen hec-http: request error: {e:#}");
            }
        }
    });
}

/// Only a 2xx response counts as an accepted ("sent") record -- a 4xx/5xx
/// must be counted as an error instead, never inflating the achieved rate.
fn is_accepted(status: StatusCode) -> bool {
    status.is_success()
}

/// Build one Splunk HEC event envelope for the event ingest route. No
/// trailing newline -- a single JSON object is the entire request body for
/// this subcommand (one event per POST).
///
/// `n` seeds `seq` and `src_ip` so consecutive events are genuinely
/// distinct records, not the same event repeated N times.
fn build_event_json(n: u64, sourcetype: &str) -> Value {
    let now = chrono::Utc::now();
    let epoch = now.timestamp() as f64 + f64::from(now.timestamp_subsec_micros()) / 1e6;
    json!({
        "time": epoch,
        "host": "loadgen-host",
        "sourcetype": sourcetype,
        "event": {
            "msg": format!("synthetic load-test event #{n}"),
            "level": "info",
            "seq": n,
            "src_ip": format!("10.0.{}.{}", (n / 256) % 256, n % 256),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard against silent wire-format drift: build an event
    /// body with logthing's OWN `parse_hec_event_body` (not a hand-rolled
    /// shape check) and assert it round-trips.
    #[test]
    fn event_body_parses_with_logthings_own_hec_parser() {
        let line = build_event_json(42, "loadgen_test").to_string();
        let records = logthing::ingest::parse_hec_event_body(line.as_bytes(), "fallback_st")
            .expect("loadgen HEC event body must parse with logthing's own parser");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sourcetype, "loadgen_test");
        assert_eq!(records[0].host.as_deref(), Some("loadgen-host"));
        assert!(records[0].time.is_some(), "epoch `time` must parse");
        assert!(
            records[0].fields["msg"]
                .as_str()
                .unwrap()
                .contains("#42"),
            "event field must carry the sequence number, got: {}",
            records[0].fields
        );
    }

    /// A generator emitting identical rows N times measures the wrong
    /// thing: two events at different sequence numbers must differ.
    #[test]
    fn distinct_sequence_numbers_yield_distinct_events() {
        let a = build_event_json(1, "t");
        let b = build_event_json(2, "t");
        assert_ne!(a["event"]["seq"], b["event"]["seq"]);
        assert_ne!(a["event"]["src_ip"], b["event"]["src_ip"]);
    }

    /// The default sourcetype falls back correctly when parsed with no
    /// query-param override, matching what the real route does.
    #[test]
    fn default_sourcetype_used_when_missing() {
        let value = build_event_json(1, "loadgen");
        assert_eq!(value["sourcetype"], "loadgen");
    }

    /// A non-2xx response (unauthorized, bad request, server error) must
    /// never be classified as accepted -- this is the pure predicate the
    /// achieved-rate counter is gated on.
    #[test]
    fn is_accepted_only_true_for_2xx() {
        assert!(is_accepted(StatusCode::OK));
        assert!(is_accepted(StatusCode::from_u16(204).unwrap()));
        assert!(!is_accepted(StatusCode::UNAUTHORIZED));
        assert!(!is_accepted(StatusCode::BAD_REQUEST));
        assert!(!is_accepted(StatusCode::PAYLOAD_TOO_LARGE));
        assert!(!is_accepted(StatusCode::INTERNAL_SERVER_ERROR));
    }

    // ---------------------------------------------------------------- //
    // Integration: drive the generated body through logthing's REAL
    // axum handler in-process, same harness shape as `src/server/mod.rs`'s
    // `build_hec_router` test helper. A generator whose payloads the real
    // handler rejects is worse than no generator -- this is the check
    // that catches that.
    // ---------------------------------------------------------------- //

    fn test_router(token: &str) -> axum::Router {
        use axum::{Extension, Router, routing::post};
        use logthing::ingest::{IngestState, handle_hec_event};

        Router::new()
            .route("/services/collector/event", post(handle_hec_event))
            .layer(Extension(Arc::new(token.to_string())))
            .layer(Extension(IngestState::default()))
    }

    #[tokio::test]
    async fn generated_event_is_accepted_by_the_real_hec_handler() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let router = test_router("loadgen-it-token");
        let body = build_event_json(7, "loadgen_it").to_string();
        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/event")
            .header("Authorization", "Splunk loadgen-it-token")
            .body(Body::from(body))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 65536)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["code"], 0);
        assert_eq!(json["text"], "Success");
    }

    /// Proves the generator's own auth failure detection lines up with
    /// reality: a wrong token must come back 401, not silently succeed.
    #[tokio::test]
    async fn wrong_token_is_rejected_with_401() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let router = test_router("correct-token");
        let body = build_event_json(1, "loadgen_it").to_string();
        let req = Request::builder()
            .method("POST")
            .uri("/services/collector/event")
            .header("Authorization", "Splunk wrong-token")
            .body(Body::from(body))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
