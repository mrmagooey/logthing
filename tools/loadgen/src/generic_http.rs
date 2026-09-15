//! `loadgen generic-http` -- paced, concurrent HTTP load generator for the
//! generic NDJSON ingest route (`POST /ingest`).
//!
//! Same request/response-is-latency-bound problem as `hec-http` (see that
//! module's doc comment for the full rationale): this keeps up to
//! `--concurrency` requests in flight via a `tokio::sync::Semaphore`, paced
//! by `crate::pacing`'s tick-based fractional-carry accumulator.
//!
//! `/ingest` (`logthing::ingest::handle_ndjson`) accepts a body of one or
//! more newline-delimited JSON objects, stored verbatim as `fields` --
//! there is no envelope wrapper like HEC's `{"event": ...}` (see
//! `src/ingest/parse.rs`'s `parse_ndjson_body`). `sourcetype` comes from the
//! `?sourcetype=` query parameter rather than a body key.
//!
//! It shares HEC's auth model exactly: `/ingest` is registered on the same
//! `hec.enabled`-gated router with the same `Authorization: Splunk <token>`
//! check, so `--token` must match the same `[hec.token]` config value.
//!
//! Only a 2xx response counts as "sent"; a 401 aborts the whole run loudly
//! (see `hec_http`'s doc comment for why that one status is special-cased
//! rather than just tallied as an error).

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
pub struct GenericHttpArgs {
    /// Target host to send generic ingest HTTP requests to.
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
    /// the target server's `[hec.token]` config value (`/ingest` shares
    /// HEC's auth gate). Empty (the default) sends no Authorization header,
    /// matching a dev-mode server with an empty configured token.
    #[arg(long, default_value = "")]
    pub token: String,

    /// `sourcetype` passed as the `?sourcetype=` query parameter.
    #[arg(long, default_value = "loadgen")]
    pub sourcetype: String,

    /// Maximum number of HTTP requests in flight at once.
    #[arg(long, default_value_t = 64)]
    pub concurrency: usize,
}

/// Shared, cheaply-cloned state every in-flight request task needs.
#[derive(Clone)]
struct GenericCtx {
    client: reqwest::Client,
    url: Arc<str>,
    token: Arc<str>,
    semaphore: Arc<Semaphore>,
    sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    auth_failed: Arc<AtomicBool>,
}

pub async fn run(args: GenericHttpArgs) -> anyhow::Result<()> {
    let url = format!(
        "http://{}:{}/ingest?sourcetype={}",
        args.host, args.port, args.sourcetype
    );
    let client = reqwest::Client::builder()
        .build()
        .context("build reqwest HTTP client")?;

    println!(
        "loadgen generic-http: sending to {url} at target_rate={} rec/s for {}s (concurrency={})",
        args.target_rate, args.duration_secs, args.concurrency
    );

    let ctx = GenericCtx {
        client,
        url: url.as_str().into(),
        token: args.token.as_str().into(),
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
        // Same 1ms-tick, fractional-carry pacing as every other subcommand.
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
            "loadgen generic-http: {errors} requests rejected (non-2xx or transport error) -- \
             not counted as sent"
        );
    }

    if ctx.auth_failed.load(Ordering::Relaxed) {
        anyhow::bail!(
            "loadgen generic-http: aborted -- server rejected requests with 401 Unauthorized; \
             --token does not match the target's [hec.token] (sent {sent} before aborting)"
        );
    }

    println!(
        "loadgen generic-http: sent {sent} records in {:.3}s (achieved rate: {:.1} rec/s)",
        elapsed.as_secs_f64(),
        sent as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}

/// Acquire a concurrency permit (blocking this loop, i.e. natural
/// backpressure, if `--concurrency` in-flight requests are already
/// outstanding) and spawn one NDJSON POST onto `tasks`.
async fn spawn_request(ctx: &GenericCtx, tasks: &mut JoinSet<()>, n: u64) {
    let permit = ctx
        .semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("semaphore is never closed");
    let ctx = ctx.clone();
    tasks.spawn(async move {
        let _permit = permit;
        let body = build_record_json(n).to_string();
        let mut req = ctx.client.post(ctx.url.as_ref()).body(body);
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
                        "loadgen generic-http: request rejected with {status} (Unauthorized) -- \
                         check --token matches the server's [hec.token]"
                    );
                }
            }
            Err(e) => {
                ctx.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("loadgen generic-http: request error: {e:#}");
            }
        }
    });
}

/// Only a 2xx response counts as an accepted ("sent") record -- a 4xx/5xx
/// must be counted as an error instead, never inflating the achieved rate.
fn is_accepted(status: StatusCode) -> bool {
    status.is_success()
}

/// Build one NDJSON record for `/ingest`. No envelope wrapper -- the whole
/// object becomes `GenericRecord::fields` verbatim.
///
/// `n` seeds `seq` and `src_ip` so consecutive records are genuinely
/// distinct rows, not the same row repeated N times.
fn build_record_json(n: u64) -> Value {
    json!({
        "host": "loadgen-host",
        "msg": format!("synthetic load-test record #{n}"),
        "seq": n,
        "src_ip": format!("10.0.{}.{}", (n / 256) % 256, n % 256),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard against silent wire-format drift: build a record
    /// with logthing's OWN `parse_ndjson_body` (not a hand-rolled shape
    /// check) and assert it round-trips.
    #[test]
    fn record_body_parses_with_logthings_own_ndjson_parser() {
        let line = build_record_json(42).to_string();
        let records = logthing::ingest::parse_ndjson_body(line.as_bytes(), "fallback_st")
            .expect("loadgen NDJSON body must parse with logthing's own parser");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sourcetype, "fallback_st");
        assert!(
            records[0].fields["msg"]
                .as_str()
                .unwrap()
                .contains("#42"),
            "record must carry the sequence number, got: {}",
            records[0].fields
        );
    }

    /// A generator emitting identical rows N times measures the wrong
    /// thing: two records at different sequence numbers must differ.
    #[test]
    fn distinct_sequence_numbers_yield_distinct_records() {
        let a = build_record_json(1);
        let b = build_record_json(2);
        assert_ne!(a["seq"], b["seq"]);
        assert_ne!(a["src_ip"], b["src_ip"]);
    }

    /// A non-2xx response must never be classified as accepted -- the pure
    /// predicate the achieved-rate counter is gated on.
    #[test]
    fn is_accepted_only_true_for_2xx() {
        assert!(is_accepted(StatusCode::OK));
        assert!(!is_accepted(StatusCode::UNAUTHORIZED));
        assert!(!is_accepted(StatusCode::BAD_REQUEST));
        assert!(!is_accepted(StatusCode::INTERNAL_SERVER_ERROR));
    }

    // ---------------------------------------------------------------- //
    // Integration: drive the generated body through logthing's REAL axum
    // handler in-process, same harness shape as `src/server/mod.rs`'s
    // `build_hec_router` test helper.
    // ---------------------------------------------------------------- //

    fn test_router(token: &str) -> axum::Router {
        use axum::{Extension, Router, routing::post};
        use logthing::ingest::{IngestState, handle_ndjson};

        Router::new()
            .route("/ingest", post(handle_ndjson))
            .layer(Extension(Arc::new(token.to_string())))
            .layer(Extension(IngestState::default()))
    }

    #[tokio::test]
    async fn generated_record_is_accepted_by_the_real_ingest_handler() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let router = test_router("loadgen-it-token");
        let body = build_record_json(7).to_string();
        let req = Request::builder()
            .method("POST")
            .uri("/ingest?sourcetype=loadgen_it")
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
    }

    /// Proves the generator's own auth failure detection lines up with
    /// reality: a wrong token must come back 401, not silently succeed.
    #[tokio::test]
    async fn wrong_token_is_rejected_with_401() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let router = test_router("correct-token");
        let body = build_record_json(1).to_string();
        let req = Request::builder()
            .method("POST")
            .uri("/ingest?sourcetype=loadgen_it")
            .header("Authorization", "Splunk wrong-token")
            .body(Body::from(body))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
