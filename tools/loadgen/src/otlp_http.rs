//! `loadgen otlp-http` -- paced, concurrent OTLP/HTTP protobuf log load generator for
//! `POST /v1/logs`. Same pacing/concurrency model as `hec-http`; the differences are the
//! protobuf body, optional gzip (`Content-Encoding: gzip`), a bearer token, and
//! `--services` distinct `service.name` values (each is a path partition and its own write
//! buffer server-side, capped by `[otlp] max_service_partitions`, default 64, then `_overflow`).
//!
//! A 503 answer is backpressure, not failure: see `crate::backpressure`.

use anyhow::Context;
use clap::Args;
use flate2::{Compression, write::GzEncoder};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value as AnyVal};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::Message;
use reqwest::StatusCode;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use crate::backpressure::{Backpressure, RETRY_GRACE, SendOutcome, send_with_retry};
use crate::pacing::tick_record_count;

/// Arguments for `loadgen otlp-http`.
#[derive(Args, Debug)]
pub struct OtlpHttpArgs {
    /// Target host.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    /// Target HTTP port (`bind_address` default 5985).
    #[arg(long, default_value_t = 5985)]
    pub port: u16,
    /// Target sustained rate in records/sec (2xx only). 0 = unbounded.
    #[arg(long, default_value_t = 10_000)]
    pub target_rate: u64,
    /// How long to send for, in seconds.
    #[arg(long, default_value_t = 60)]
    pub duration_secs: u64,
    /// Sent as `Authorization: Bearer <token>`; must match `[otlp] bearer_token`. Empty = no header.
    #[arg(long, default_value = "")]
    pub token: String,
    /// Maximum HTTP requests in flight.
    #[arg(long, default_value_t = 64)]
    pub concurrency: usize,
    /// Log records per ExportLogsServiceRequest.
    #[arg(long, default_value_t = 1)]
    pub events_per_request: usize,
    /// Distinct `service.name` values to cycle through (one per request).
    #[arg(long, default_value_t = 1)]
    pub services: u64,
    /// gzip-compress request bodies (`Content-Encoding: gzip`).
    #[arg(long)]
    pub gzip: bool,
    /// Add PII-shaped attributes/body text (see `pii.rs`) so redaction rules have work to do.
    #[arg(long)]
    pub pii_fields: bool,
    /// Retries of a 503-answered request before it is abandoned.
    #[arg(long, default_value_t = 5)]
    pub max_retries: u32,
}

/// Shared, cheaply-cloned state every in-flight request task needs.
#[derive(Clone)]
struct OtlpCtx {
    client: reqwest::Client,
    url: Arc<str>,
    token: Arc<str>,
    semaphore: Arc<Semaphore>,
    sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    auth_failed: Arc<AtomicBool>,
    bp: Arc<Backpressure>,
    events_per_request: usize,
    services: u64,
    gzip: bool,
    pii: bool,
    max_retries: u32,
    /// Run end plus [`RETRY_GRACE`]: 503 retries stop after this.
    deadline: Instant,
}

/// Run the generator until `--duration-secs` elapses, then drain and print the summary lines.
pub async fn run(args: OtlpHttpArgs) -> anyhow::Result<()> {
    let url = format!("http://{}:{}/v1/logs", args.host, args.port);
    let client = reqwest::Client::builder()
        .build()
        .context("build reqwest HTTP client")?;

    println!(
        "loadgen otlp-http: sending to {url} at target_rate={} rec/s for {}s (concurrency={}, \
         services={}, gzip={})",
        args.target_rate, args.duration_secs, args.concurrency, args.services, args.gzip
    );

    let ctx = OtlpCtx {
        client,
        url: url.as_str().into(),
        token: args.token.as_str().into(),
        semaphore: Arc::new(Semaphore::new(args.concurrency.max(1))),
        sent: Arc::new(AtomicU64::new(0)),
        errors: Arc::new(AtomicU64::new(0)),
        auth_failed: Arc::new(AtomicBool::new(false)),
        bp: Arc::new(Backpressure::default()),
        events_per_request: args.events_per_request.max(1),
        services: args.services,
        gzip: args.gzip,
        pii: args.pii_fields,
        max_retries: args.max_retries,
        deadline: Instant::now() + Duration::from_secs(args.duration_secs) + RETRY_GRACE,
    };
    let batch = ctx.events_per_request as u64;

    let duration = Duration::from_secs(args.duration_secs);
    let start = Instant::now();
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut n: u64 = 0;

    if args.target_rate == 0 {
        // Unbounded: launch requests as fast as `--concurrency` allows.
        while start.elapsed() < duration && !ctx.auth_failed.load(Ordering::Relaxed) {
            spawn_request(&ctx, &mut tasks, n).await;
            n += batch;
        }
    } else {
        // Same 1ms-tick, fractional-carry pacing as every other subcommand, scaled down by
        // the batch size so `--target-rate` stays a records/sec figure.
        let tick = crate::pacing::TICK;
        let requests_per_tick_target =
            (args.target_rate as f64 / batch as f64) * tick.as_secs_f64();
        let mut ticker = tokio::time::interval(tick);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Burst);
        let mut carry: f64 = 0.0;

        'send_loop: loop {
            if start.elapsed() >= duration {
                break;
            }
            ticker.tick().await;
            let requests_this_tick = tick_record_count(&mut carry, requests_per_tick_target);
            for _ in 0..requests_this_tick {
                if start.elapsed() >= duration || ctx.auth_failed.load(Ordering::Relaxed) {
                    break 'send_loop;
                }
                spawn_request(&ctx, &mut tasks, n).await;
                n += batch;
            }
        }
    }

    // Drain in-flight requests so the counters reflect everything that was launched.
    while tasks.join_next().await.is_some() {}

    let elapsed = start.elapsed();
    let sent = ctx.sent.load(Ordering::Relaxed);
    let errors = ctx.errors.load(Ordering::Relaxed);

    if errors > 0 {
        println!(
            "loadgen otlp-http: {errors} requests rejected (non-2xx or transport error) -- \
             not counted as sent"
        );
    }
    println!("{}", ctx.bp.summary("otlp-http", args.max_retries));

    if ctx.auth_failed.load(Ordering::Relaxed) {
        anyhow::bail!(
            "loadgen otlp-http: aborted -- server rejected requests with 401 Unauthorized; \
             --token does not match the target's [otlp] bearer_token (sent {sent} before aborting)"
        );
    }

    println!(
        "loadgen otlp-http: sent {sent} records in {:.3}s (achieved rate: {:.1} rec/s)",
        elapsed.as_secs_f64(),
        sent as f64 / elapsed.as_secs_f64()
    );
    Ok(())
}

/// Acquire a concurrency permit (natural backpressure when `--concurrency` requests are
/// outstanding) and spawn one OTLP export onto `tasks`.
async fn spawn_request(ctx: &OtlpCtx, tasks: &mut JoinSet<()>, n: u64) {
    let permit = ctx
        .semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("semaphore is never closed");
    let ctx = ctx.clone();
    tasks.spawn(async move {
        let _permit = permit;
        // Encode (and compress) ONCE; retries resend identical bytes.
        let proto = build_request(n, ctx.events_per_request, ctx.services, ctx.pii).encode_to_vec();
        let body = if ctx.gzip {
            match gzip(&proto) {
                Ok(b) => b,
                Err(e) => {
                    ctx.errors.fetch_add(1, Ordering::Relaxed);
                    eprintln!("loadgen otlp-http: gzip failed: {e:#}");
                    return;
                }
            }
        } else {
            proto
        };
        let build = || {
            let mut req = ctx
                .client
                .post(ctx.url.as_ref())
                .header("Content-Type", "application/x-protobuf")
                .body(body.clone());
            if ctx.gzip {
                req = req.header("Content-Encoding", "gzip");
            }
            if !ctx.token.is_empty() {
                req = req.bearer_auth(ctx.token.as_ref());
            }
            req
        };
        match send_with_retry(build, &ctx.bp, ctx.max_retries, ctx.deadline).await {
            SendOutcome::Accepted => {
                ctx.sent
                    .fetch_add(ctx.events_per_request as u64, Ordering::Relaxed);
            }
            SendOutcome::Rejected(status) => {
                ctx.errors.fetch_add(1, Ordering::Relaxed);
                if status == StatusCode::UNAUTHORIZED {
                    ctx.auth_failed.store(true, Ordering::Relaxed);
                    eprintln!(
                        "loadgen otlp-http: request rejected with {status} (Unauthorized) -- \
                         check --token matches the server's [otlp] bearer_token"
                    );
                } else {
                    eprintln!("loadgen otlp-http: request rejected with {status}");
                }
            }
            SendOutcome::Abandoned => {
                ctx.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("loadgen otlp-http: request abandoned (503 after all retries)");
            }
            SendOutcome::TransportError(e) => {
                ctx.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("loadgen otlp-http: request error: {e:#}");
            }
        }
    });
}

/// gzip at the fast level, as common shippers do (cheap on the client, still ~10x on logs).
pub(crate) fn gzip(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(bytes).context("gzip write")?;
    enc.finish().context("gzip finish")
}

fn str_kv(key: &str, value: String) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(AnyVal::StringValue(value)),
        }),
        ..Default::default()
    }
}

/// Build one export request of `count` records starting at sequence `start`. All records in
/// a request share one resource whose `service.name` is `loadgen-svc-{k}`, `k` cycling over
/// `services` values per request (`start / count`).
pub(crate) fn build_request(
    start: u64,
    count: usize,
    services: u64,
    pii: bool,
) -> ExportLogsServiceRequest {
    let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0).max(0) as u64;
    let svc = (start / count.max(1) as u64) % services.max(1);
    let log_records = (0..count as u64)
        .map(|i| {
            let seq = start + i;
            let mut body = format!("synthetic load-test log #{seq}");
            let mut attributes = vec![
                KeyValue {
                    key: "seq".to_string(),
                    value: Some(AnyValue {
                        value: Some(AnyVal::IntValue(seq as i64)),
                    }),
                    ..Default::default()
                },
                str_kv(
                    "src_ip",
                    format!("10.0.{}.{}", (seq / 256) % 256, seq % 256),
                ),
            ];
            if pii {
                let p = crate::pii::pii_fields(seq);
                let get = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
                attributes.push(str_kv("password", get(&p["password"])));
                attributes.push(str_kv(
                    "headers.authorization",
                    get(&p["headers"]["authorization"]),
                ));
                attributes.push(str_kv("user.email", get(&p["user"]["email"])));
                body.push(' ');
                body.push_str(&get(&p["note"]));
            }
            let mut trace_id = vec![0u8; 8];
            trace_id.extend_from_slice(&seq.to_be_bytes());
            LogRecord {
                time_unix_nano: now,
                observed_time_unix_nano: now,
                severity_number: 9,
                severity_text: "INFO".to_string(),
                body: Some(AnyValue {
                    value: Some(AnyVal::StringValue(body)),
                }),
                attributes,
                trace_id,
                span_id: seq.to_be_bytes().to_vec(),
                ..Default::default()
            }
        })
        .collect();
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![str_kv("service.name", format!("loadgen-svc-{svc}"))],
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                log_records,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_name_of(r: &ExportLogsServiceRequest) -> String {
        let attrs = &r.resource_logs[0].resource.as_ref().unwrap().attributes;
        let kv = attrs.iter().find(|kv| kv.key == "service.name").unwrap();
        match kv.value.as_ref().unwrap().value.as_ref().unwrap() {
            AnyVal::StringValue(s) => s.clone(),
            other => panic!("service.name must be a string, got {other:?}"),
        }
    }

    #[test]
    fn request_has_one_resource_per_request_and_count_records() {
        let req = build_request(0, 8, 1, false);
        assert_eq!(req.resource_logs.len(), 1);
        let n: usize = req.resource_logs[0]
            .scope_logs
            .iter()
            .map(|s| s.log_records.len())
            .sum();
        assert_eq!(n, 8);
    }

    #[test]
    fn service_name_cycles_through_exactly_services_values() {
        let names: std::collections::BTreeSet<String> = (0..20u64)
            .map(|i| service_name_of(&build_request(i * 4, 4, 5, false)))
            .collect();
        assert_eq!(names.len(), 5);
        assert!(names.iter().all(|n| n.starts_with("loadgen-svc-")));
    }

    #[test]
    fn services_zero_is_treated_as_one() {
        let a = service_name_of(&build_request(0, 1, 0, false));
        let b = service_name_of(&build_request(100, 1, 0, false));
        assert_eq!(a, b);
    }

    #[test]
    fn gzip_body_round_trips_to_the_same_protobuf() {
        use std::io::Read;
        let req = build_request(0, 3, 1, true);
        let plain = req.encode_to_vec();
        let gz = gzip(&plain).unwrap();
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&gz[..])
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(ExportLogsServiceRequest::decode(&out[..]).unwrap(), req);
        assert!(
            gz.len() < plain.len(),
            "gzip must actually compress synthetic logs"
        );
    }

    #[test]
    fn records_map_through_logthings_own_mapper() {
        let req = build_request(0, 6, 1, true);
        let recs = logthing::server::otlp::map_otlp_request(req, "127.0.0.1:1".into());
        assert_eq!(recs.len(), 6);
        for r in &recs {
            assert_eq!(r.service_name.as_deref(), Some("loadgen-svc-0"));
            assert_eq!(r.severity_number, Some(9));
            assert_eq!(r.severity_text.as_deref(), Some("INFO"));
            assert!(
                r.body
                    .as_deref()
                    .unwrap()
                    .contains("synthetic load-test log #")
            );
            assert!(r.trace_id.is_some() && r.span_id.is_some());
            assert_eq!(
                r.attributes["user.email"].as_str().map(|s| s.contains('@')),
                Some(true)
            );
        }
    }

    #[test]
    fn distinct_sequence_numbers_yield_distinct_bodies() {
        let a = build_request(1, 1, 1, false).encode_to_vec();
        let b = build_request(2, 1, 1, false).encode_to_vec();
        assert_ne!(a, b);
    }

    // ------------------------------------------------------------------ //
    // Integration: drive generated bodies through logthing's REAL handler
    // in-process. `handle_otlp_logs` extracts `ConnectInfo<SocketAddr>`, which
    // `oneshot` cannot supply, so `MockConnectInfo` stands in for the peer.
    // `post_gzip` is the same wrapper `create_router` mounts `/v1/logs` with.
    // ------------------------------------------------------------------ //

    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
    use axum::{Extension, Router};
    use logthing::config::{Config, OtlpConfig};
    use logthing::ingest::IngestState;
    use logthing::ingest::decompress::post_gzip;
    use logthing::server::{AppState, handle_otlp_logs};
    use logthing::stats::ThroughputStats;
    use logthing::wef::bookmarks::BookmarkStore;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    fn app_state(token: &str) -> Arc<AppState> {
        let config = Config {
            otlp: OtlpConfig {
                enabled: true,
                bearer_token: Some(token.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        Arc::new(AppState {
            config: Arc::new(tokio::sync::RwLock::new(config)),
            throughput: Arc::new(ThroughputStats::new()),
            wef_cardinality_watchers: Vec::new(),
            wef: None,
            bookmarks: Arc::new(BookmarkStore::new(16)),
            event_parser: None,
            parquet_s3_sender: None,
            parquet_local_sender: None,
        })
    }

    fn router(token: &str, ingest: IngestState) -> Router {
        Router::new()
            .route("/v1/logs", post_gzip(handle_otlp_logs))
            .layer(Extension(ingest))
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4317))))
            .with_state(app_state(token))
    }

    async fn post(router: Router, body: Vec<u8>, gz: bool, bearer: &str) -> u16 {
        let mut b = Request::builder()
            .method("POST")
            .uri("/v1/logs")
            .header("Content-Type", "application/x-protobuf")
            .header("Authorization", format!("Bearer {bearer}"));
        if gz {
            b = b.header("Content-Encoding", "gzip");
        }
        router
            .oneshot(b.body(Body::from(body)).unwrap())
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    #[tokio::test]
    async fn generated_gzip_protobuf_is_accepted_by_the_real_otlp_handler() {
        let body = gzip(&build_request(0, 10, 3, true).encode_to_vec()).unwrap();
        let r = router("it-token", IngestState::default());
        assert_eq!(post(r, body, true, "it-token").await, 200);
    }

    #[tokio::test]
    async fn generated_plain_protobuf_is_accepted_by_the_real_otlp_handler() {
        let body = build_request(0, 10, 3, false).encode_to_vec();
        let r = router("it-token", IngestState::default());
        assert_eq!(post(r, body, false, "it-token").await, 200);
    }

    #[tokio::test]
    async fn wrong_bearer_token_is_rejected_with_401() {
        let body = build_request(0, 1, 1, false).encode_to_vec();
        let r = router("it-token", IngestState::default());
        assert_eq!(post(r, body, false, "nope").await, 401);
    }

    /// `--services` above `[otlp] max_service_partitions`: the extra services must not be
    /// dropped or error -- they land in the `_overflow` partition of the real sink.
    #[tokio::test]
    async fn services_above_partition_cap_land_in_overflow_partition() {
        use logthing::config::OtlpLocalConfig;
        use logthing::forwarding::local_sink::LocalDiskSink;
        use logthing::forwarding::otlp_s3::otlp_local_start;

        const CAP: usize = 3;
        const SERVICES: u64 = 6;
        let tmp = tempfile::tempdir().unwrap();
        let sink = Arc::new(LocalDiskSink::new(tmp.path().to_path_buf()).await.unwrap());
        let cfg = OtlpLocalConfig {
            directory: tmp.path().to_path_buf(),
            prefix: "otlp".to_string(),
            flush_threshold_bytes: 1,
            flush_interval_secs: 1,
            channel_capacity: 256,
            max_buffer_rows: 100_000,
        };
        let (handler, _join) = otlp_local_start(
            &cfg,
            sink,
            CAP,
            Arc::new(logthing::stats::SourceHourlyStats::new()),
            None,
        );
        let ingest = IngestState {
            otlp_local: Some(handler),
            ..Default::default()
        };
        // One single-record request per service, sequentially, so partition
        // assignment order is deterministic: services 0..CAP get their own, the rest overflow.
        for i in 0..SERVICES {
            let body = build_request(i, 1, SERVICES, false).encode_to_vec();
            assert_eq!(
                post(router("it-token", ingest.clone()), body, false, "it-token").await,
                200
            );
        }

        let root = tmp.path().join("otlp");
        let partitions = |_: ()| -> std::collections::BTreeSet<String> {
            let mut set = std::collections::BTreeSet::new();
            let mut stack = vec![root.clone()];
            while let Some(d) = stack.pop() {
                let Ok(rd) = std::fs::read_dir(&d) else {
                    continue;
                };
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if p.extension().is_some_and(|x| x == "parquet") {
                        let rel = p.strip_prefix(&root).unwrap();
                        set.insert(
                            rel.components()
                                .next()
                                .unwrap()
                                .as_os_str()
                                .to_string_lossy()
                                .into(),
                        );
                    }
                }
            }
            set
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while partitions(()).len() < CAP + 1 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let got = partitions(());
        assert!(got.contains("_overflow"), "partitions: {got:?}");
        assert_eq!(
            got.len(),
            CAP + 1,
            "CAP named partitions + _overflow: {got:?}"
        );
    }
}
