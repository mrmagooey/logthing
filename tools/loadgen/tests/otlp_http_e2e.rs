//! End-to-end: the compiled `loadgen` binary against real sockets.
//!
//! The crate is a binary, so these tests drive `env!("CARGO_BIN_EXE_loadgen")` as a child
//! process. Server side is either logthing's REAL `handle_otlp_logs` behind `post_gzip` (as
//! `create_router` mounts it) or a tiny axum stub that answers scripted statuses.

use axum::extract::connect_info::MockConnectInfo;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Extension, Router};
use logthing::config::{Config, OtlpConfig};
use logthing::ingest::IngestState;
use logthing::ingest::decompress::post_gzip;
use logthing::server::{AppState, handle_otlp_logs};
use logthing::stats::ThroughputStats;
use logthing::wef::bookmarks::BookmarkStore;
use std::io::Read;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Run loadgen with `args`, panicking if it does not exit within `limit`. Returns (success, stdout, stderr).
fn run_loadgen(args: Vec<String>, limit: Duration) -> (bool, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_loadgen"))
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn loadgen");
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("loadgen did not exit within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    (status.success(), out, err)
}

async fn run_async(args: &[&str], limit: Duration) -> (bool, String, String) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || run_loadgen(args, limit))
        .await
        .unwrap()
}

/// `sent N records` parsed from the summary line.
fn sent_records(out: &str) -> u64 {
    let line = out
        .lines()
        .find(|l| l.contains(": sent "))
        .unwrap_or_else(|| panic!("no 'sent' line in:\n{out}"));
    line.split("sent ")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

/// Number after `backpressure: ` on the backpressure line (503 count) and the abandoned count.
fn backpressure_counts(out: &str) -> (u64, u64) {
    let line = out
        .lines()
        .find(|l| l.contains("backpressure: "))
        .unwrap_or_else(|| panic!("no backpressure line in:\n{out}"));
    let throttled: u64 = line
        .split("backpressure: ")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let abandoned: u64 = line
        .split(" 503 responses, ")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    (throttled, abandoned)
}

async fn serve(app: Router) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap()
    });
    port
}

/// Stub answering `first_n` requests with 503 (`retry-after: 0`) and the rest with 200;
/// returns (port, 200-counter).
async fn stub(first_n: usize) -> (u16, Arc<AtomicUsize>) {
    let seen = Arc::new(AtomicUsize::new(0));
    let oks = Arc::new(AtomicUsize::new(0));
    let (s2, o2) = (seen.clone(), oks.clone());
    let app = Router::new().fallback(move || {
        let i = s2.fetch_add(1, Ordering::SeqCst);
        let o2 = o2.clone();
        async move {
            if i < first_n {
                (StatusCode::SERVICE_UNAVAILABLE, [("retry-after", "0")], "").into_response()
            } else {
                o2.fetch_add(1, Ordering::SeqCst);
                (StatusCode::OK, "{}").into_response()
            }
        }
    });
    (serve(app).await, oks)
}

#[tokio::test(flavor = "multi_thread")]
async fn otlp_http_gzip_run_against_real_logthing_router_succeeds() {
    let config = Config {
        otlp: OtlpConfig {
            enabled: true,
            bearer_token: Some("e2e-token".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let state = Arc::new(AppState {
        config: Arc::new(tokio::sync::RwLock::new(config)),
        throughput: Arc::new(ThroughputStats::new()),
        wef_cardinality_watchers: Vec::new(),
        wef: None,
        bookmarks: Arc::new(BookmarkStore::new(16)),
        event_parser: None,
        parquet_s3_sender: None,
        parquet_local_sender: None,
    });
    let app = Router::new()
        .route("/v1/logs", post_gzip(handle_otlp_logs))
        .layer(Extension(IngestState::default()))
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))))
        .with_state(state);
    let port = serve(app).await.to_string();

    let (ok, out, err) = run_async(
        &[
            "otlp-http",
            "--port",
            &port,
            "--token",
            "e2e-token",
            "--gzip",
            "--pii-fields",
            "--services",
            "3",
            "--events-per-request",
            "10",
            "--target-rate",
            "200",
            "--duration-secs",
            "2",
        ],
        Duration::from_secs(30),
    )
    .await;
    assert!(ok, "loadgen failed:\nstdout:\n{out}\nstderr:\n{err}");
    assert!(
        out.contains("backpressure: 0 503 responses, 0 requests abandoned"),
        "stdout:\n{out}\nstderr:\n{err}"
    );
    let n = sent_records(&out);
    assert!(
        n > 0 && n.is_multiple_of(10),
        "sent {n}\nstdout:\n{out}\nstderr:\n{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hec_http_503_is_retried_and_counted_separately_from_errors() {
    let (port, oks) = stub(5).await;
    let port = port.to_string();
    let (ok, out, err) = run_async(
        &[
            "hec-http",
            "--port",
            &port,
            "--events-per-request",
            "5",
            "--target-rate",
            "100",
            "--duration-secs",
            "2",
            "--max-retries",
            "5",
        ],
        Duration::from_secs(30),
    )
    .await;
    assert!(ok, "loadgen failed:\nstdout:\n{out}\nstderr:\n{err}");
    assert!(
        out.contains("backpressure: 5 503 responses, 0 requests abandoned"),
        "stdout:\n{out}\nstderr:\n{err}"
    );
    let n = sent_records(&out);
    assert!(oks.load(Ordering::SeqCst) > 0);
    assert_eq!(n, 5 * oks.load(Ordering::SeqCst) as u64, "{out}\n{err}");
    assert!(!out.contains("requests rejected"), "{out}\n{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn permanent_503_run_finishes_and_reports_abandoned() {
    // The stub 503s forever; wire it as a route that never answers 2xx.
    let app = Router::new().route(
        "/v1/logs",
        post(|| async { (StatusCode::SERVICE_UNAVAILABLE, [("retry-after", "0")], "") }),
    );
    let port = serve(app).await.to_string();
    let (ok, out, err) = run_async(
        &[
            "otlp-http",
            "--port",
            &port,
            "--max-retries",
            "1",
            "--target-rate",
            "20",
            "--duration-secs",
            "1",
        ],
        Duration::from_secs(20),
    )
    .await;
    assert!(ok, "loadgen failed:\nstdout:\n{out}\nstderr:\n{err}");
    let (throttled, abandoned) = backpressure_counts(&out);
    assert!(abandoned > 0, "{out}\n{err}");
    assert_eq!(
        throttled,
        abandoned * 2,
        "1 try + 1 retry per abandoned request: {out}\n{err}"
    );
    assert_eq!(sent_records(&out), 0, "{out}\n{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn permanent_503_with_huge_retry_budget_stops_at_run_deadline() {
    // 1 s run + 2 s grace: with Retry-After: 1 and a million allowed retries, only the
    // run-level cutoff can end this in time.
    let app = Router::new().route(
        "/v1/logs",
        post(|| async { (StatusCode::SERVICE_UNAVAILABLE, [("retry-after", "1")], "") }),
    );
    let port = serve(app).await.to_string();
    let started = Instant::now();
    let (ok, out, err) = run_async(
        &[
            "otlp-http",
            "--port",
            &port,
            "--max-retries",
            "1000000",
            "--target-rate",
            "5",
            "--duration-secs",
            "1",
        ],
        Duration::from_secs(20),
    )
    .await;
    assert!(ok, "loadgen failed:\nstdout:\n{out}\nstderr:\n{err}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "run took {:?}\n{out}\n{err}",
        started.elapsed()
    );
    let (throttled, abandoned) = backpressure_counts(&out);
    assert!(abandoned > 0 && throttled > abandoned, "{out}\n{err}");
}
