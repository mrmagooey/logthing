//! Throughput benchmark quantifying the improvement from the buffered-writer
//! flush-decoupling fix (see `src/forwarding/buffered_writer.rs`): flushes
//! (Arrow/Parquet encode + upload) now run as spawned background tasks
//! (a `tokio::task::JoinSet`) instead of blocking the writer's channel-drain
//! loop inline.
//!
//! This is a standalone example binary (not a `#[test]`) because it measures
//! real wall-clock throughput under a real, sustained TCP load -- something
//! that belongs in a benchmark, not the test suite. Run it with:
//!
//! ```text
//! cargo run --release --example flush_decoupling_benchmark -- \
//!     mode=realistic duration_secs=30 target_rate=4000 upload_delay_ms=150
//! ```
//!
//! ## Design
//!
//! Wires a REAL Zeek TCP ingest pipeline -- real `ZeekListener` (accepts a
//! real TCP connection, parses real NDJSON), real `ZeekSink` (the actual
//! "conn"-schema Arrow mapping cost logthing pays in production), a real
//! `ParquetWriterHandle<ZeekSink>` (the code under test), and a custom
//! `UploadSink` that sleeps `upload_delay_ms` instead of doing a real S3 PUT
//! (matching this repo's own performance-testing-strategy design doc's
//! rationale: measuring the ingestion/buffering path's own throughput
//! deliberately decouples it from real storage-backend variability, a
//! separate, already-tested concern).
//!
//! A real TCP client drives sustained load for `duration_secs`, paced to
//! `target_rate` records/sec, then the harness waits a fixed drain period and
//! reads real Prometheus counters (`parquet_s3_records_written`,
//! `parquet_s3_dropped`, `parquet_s3_buffer_dropped`) via a REAL global
//! `metrics_exporter_prometheus` recorder -- not the thread-local
//! `DebuggingRecorder` used in this repo's own tests, which has a documented
//! cross-thread visibility gap (see `tests/buffered_writer_flush_decoupling_integration.rs`'s
//! doc comment): a `multi_thread` runtime can schedule a spawned task's
//! metric calls onto a different OS thread than the one holding a
//! thread-local recorder guard, silently hiding them from a snapshot. The
//! real global recorder has no such gap -- it aggregates across every OS
//! thread in the process.
//!
//! ## Modes
//!
//! - `realistic`: production-default thresholds (100k row buffer cap, 100 MiB
//!   flush-bytes threshold, 256-record channel capacity) -- "does the fix
//!   matter under normal settings".
//! - `stress`: `max_buffer_rows=50`, `flush_threshold_bytes=usize::MAX` (only
//!   the row threshold matters), `channel_capacity` unchanged -- forces
//!   frequent flushing to isolate and quantify the maximum benefit the
//!   decoupling provides.

use logthing::forwarding::buffered_writer::{
    BufferedWriterConfig, FlushPolicy, LiveInterval, ParquetWriterHandle, UploadSink,
};
use logthing::forwarding::zeek_s3::ZeekSink;
use logthing::stats::SourceHourlyStats;
use logthing::zeek::listener::{ZeekHandler, ZeekListener, ZeekListenerConfig};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Config / flag parsing
// ---------------------------------------------------------------------------

const USAGE: &str = "\
flush_decoupling_benchmark -- measures logthing's Zeek ingest throughput

USAGE:
    cargo run --release --example flush_decoupling_benchmark -- [KEY=VALUE ...]

FLAGS (all optional, key=value form):
    mode=<realistic|stress>       default: realistic
    duration_secs=<u64>           default: 30
    target_rate=<u64>             records/sec to send, default: 4000
    upload_delay_ms=<u64>         simulated S3 PUT latency, default: 150
    max_buffer_rows=<usize>       default: 100000 (overridden to 50 in stress mode)
    channel_capacity=<usize>      default: 256
    flush_threshold_bytes=<usize> default: 104857600 (100 MiB; overridden to
                                  usize::MAX in stress mode)

EXAMPLE:
    cargo run --release --example flush_decoupling_benchmark -- \\
        mode=stress duration_secs=30 target_rate=8000 upload_delay_ms=150
";

#[derive(Debug, Clone)]
struct BenchConfig {
    mode: String,
    duration_secs: u64,
    target_rate: u64,
    upload_delay_ms: u64,
    max_buffer_rows: usize,
    channel_capacity: usize,
    flush_threshold_bytes: usize,
}

impl BenchConfig {
    fn from_args() -> Self {
        let mut mode = "realistic".to_string();
        let mut duration_secs: u64 = 30;
        let mut target_rate: u64 = 4000;
        let mut upload_delay_ms: u64 = 150;
        let mut max_buffer_rows: usize = 100_000;
        let mut channel_capacity: usize = 256;
        let mut flush_threshold_bytes: usize = 104_857_600;

        for arg in std::env::args().skip(1) {
            if arg == "-h" || arg == "--help" {
                print!("{USAGE}");
                std::process::exit(0);
            }
            let Some((key, value)) = arg.split_once('=') else {
                eprintln!("Ignoring unrecognized argument: {arg}");
                continue;
            };
            match key {
                "mode" => mode = value.to_string(),
                "duration_secs" => duration_secs = value.parse().expect("duration_secs: u64"),
                "target_rate" => target_rate = value.parse().expect("target_rate: u64"),
                "upload_delay_ms" => upload_delay_ms = value.parse().expect("upload_delay_ms: u64"),
                "max_buffer_rows" => {
                    max_buffer_rows = value.parse().expect("max_buffer_rows: usize")
                }
                "channel_capacity" => {
                    channel_capacity = value.parse().expect("channel_capacity: usize")
                }
                "flush_threshold_bytes" => {
                    flush_threshold_bytes = value.parse().expect("flush_threshold_bytes: usize")
                }
                other => eprintln!("Ignoring unrecognized flag: {other}"),
            }
        }

        let mut cfg = Self {
            mode,
            duration_secs,
            target_rate,
            upload_delay_ms,
            max_buffer_rows,
            channel_capacity,
            flush_threshold_bytes,
        };

        match cfg.mode.as_str() {
            "realistic" => {}
            "stress" => {
                cfg.max_buffer_rows = 50;
                cfg.flush_threshold_bytes = usize::MAX;
                // channel_capacity left as-is (256 default, or whatever was passed).
            }
            other => {
                eprintln!("Unknown mode '{other}', expected 'realistic' or 'stress'.\n");
                print!("{USAGE}");
                std::process::exit(1);
            }
        }

        cfg
    }
}

// ---------------------------------------------------------------------------
// UploadSink -- simulated S3 PUT latency, no real network/disk I/O
// ---------------------------------------------------------------------------

struct DelayUploadSink {
    delay: Duration,
}

#[async_trait::async_trait]
impl UploadSink for DelayUploadSink {
    async fn upload(&self, _key: &str, _body: Vec<u8>) -> anyhow::Result<()> {
        tokio::time::sleep(self.delay).await;
        Ok(())
    }
    fn target_label(&self) -> &'static str {
        "bench"
    }
    fn location_hint(&self) -> String {
        "bench://simulated".to_string()
    }
}

// ---------------------------------------------------------------------------
// Metrics helpers -- real global Prometheus recorder, parsed as text
// ---------------------------------------------------------------------------

/// Finds the sample line for `metric{labels}` in Prometheus exposition text
/// and parses its trailing numeric value. Returns 0 if the metric hasn't
/// been emitted yet (counters don't appear in the render until first
/// incremented).
fn parse_counter(rendered: &str, metric_with_labels: &str) -> f64 {
    for line in rendered.lines() {
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with(metric_with_labels)
            && let Some(value_str) = line.rsplit(' ').next()
            && let Ok(v) = value_str.parse::<f64>()
        {
            return v;
        }
    }
    0.0
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = BenchConfig::from_args();

    // Install the REAL global Prometheus recorder -- matches production's
    // start_metrics_server (src/server/mod.rs) exactly, not the
    // thread-local DebuggingRecorder used in this repo's own test code.
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    metrics::set_global_recorder(recorder).expect("failed to install global Prometheus recorder");

    println!("=== flush_decoupling_benchmark ===");
    println!("{cfg:#?}");

    let writer_cfg = BufferedWriterConfig {
        connection: logthing::config::S3ConnectionConfig {
            endpoint: String::new(),
            bucket: String::new(),
            region: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
        },
        prefix: "zeek".to_string(),
        max_buffer_rows: cfg.max_buffer_rows,
        flush_threshold_bytes: cfg.flush_threshold_bytes,
        flush_interval_secs: 3600,
        channel_capacity: cfg.channel_capacity,
        max_partitions: 8,
    };
    let policy = FlushPolicy {
        max_rows: cfg.max_buffer_rows,
        max_bytes: cfg.flush_threshold_bytes,
        interval: LiveInterval::new(Duration::from_secs(3600)),
    };
    let upload_sink: Arc<dyn UploadSink> = Arc::new(DelayUploadSink {
        delay: Duration::from_millis(cfg.upload_delay_ms),
    });

    let (handler, _writer_join_handle) = ParquetWriterHandle::<ZeekSink>::start_with_stats(
        ZeekSink,
        upload_sink,
        writer_cfg,
        policy,
        Arc::new(SourceHourlyStats::new()),
        None,
    );
    let handler: Arc<dyn ZeekHandler> = Arc::new(handler);

    // Reserve an ephemeral port (bind-then-drop -- ZeekListener::start()
    // binds internally and doesn't report back which port it chose; same
    // pattern as tests/zeek_flush_decoupling_e2e.rs).
    let port = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        probe.local_addr()?.port()
    };
    let listener_cfg = ZeekListenerConfig {
        tcp_port: port,
        bind_address: "127.0.0.1".to_string(),
    };
    let zeek_listener = ZeekListener::new(listener_cfg, handler.clone());
    tokio::spawn(async move {
        let _ = zeek_listener.start().await;
    });

    let mut stream = loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };
    // Disable Nagle's algorithm -- we want each NDJSON line to actually hit
    // the wire promptly at the paced interval, not get batched by the OS.
    stream.set_nodelay(true).ok();

    let records_sent = Arc::new(AtomicU64::new(0));
    let target_rate = cfg.target_rate.max(1);
    let duration = Duration::from_secs(cfg.duration_secs);

    println!(
        "\nSending sustained load: target_rate={} records/sec for {} secs...",
        target_rate, cfg.duration_secs
    );

    let start = Instant::now();
    // Pace sends with a ticker at the target interarrival time. Batch
    // multiple lines per tick when the target rate is high enough that a
    // per-record ticker would exceed practical timer resolution (~1ms on
    // most platforms) -- report the ACTUAL achieved rate rather than
    // chasing unrealistic per-record timer precision.
    let per_tick_interval = Duration::from_micros(1000); // 1ms ticks
    let mut records_per_tick =
        (target_rate as f64 * per_tick_interval.as_secs_f64()).round() as u64;
    if records_per_tick < 1 {
        records_per_tick = 1;
    }
    let mut ticker = tokio::time::interval(per_tick_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);

    let mut n: u64 = 0;
    'send_loop: loop {
        if start.elapsed() >= duration {
            break;
        }
        ticker.tick().await;
        for _ in 0..records_per_tick {
            if start.elapsed() >= duration {
                break 'send_loop;
            }
            let line = format!("{{\"_path\":\"conn\",\"uid\":\"C{n}\"}}\n");
            if stream.write_all(line.as_bytes()).await.is_err() {
                eprintln!("TCP write failed at record {n}; stopping send loop early");
                break 'send_loop;
            }
            n += 1;
            records_sent.store(n, Ordering::Relaxed);
        }
    }
    stream.flush().await.ok();
    let elapsed = start.elapsed();
    let sent = records_sent.load(Ordering::Relaxed);

    println!(
        "Send loop finished: {} records sent in {:.3}s (achieved rate: {:.1} rec/s)",
        sent,
        elapsed.as_secs_f64(),
        sent as f64 / elapsed.as_secs_f64()
    );

    // Fixed drain period so in-flight buffered records / in-flight flushes
    // get a chance to complete before we snapshot metrics.
    println!("Draining for 2s...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Drop our TCP client and let the writer's channel close naturally at
    // process exit -- we don't need a clean shutdown for this measurement,
    // we only need the metrics snapshot after the drain period.
    drop(stream);

    let rendered = metrics_handle.render();

    let written = parse_counter(
        &rendered,
        r#"parquet_s3_records_written{source="zeek",target="bench"}"#,
    );
    let dropped = parse_counter(
        &rendered,
        r#"parquet_s3_dropped{source="zeek",target="bench"}"#,
    );
    let buffer_dropped = parse_counter(
        &rendered,
        r#"parquet_s3_buffer_dropped{source="zeek",target="bench"}"#,
    );

    let achieved_send_rate = sent as f64 / elapsed.as_secs_f64();
    let effective_accept_rate = (sent as f64 - dropped) / elapsed.as_secs_f64();
    let drop_pct = if sent > 0 {
        100.0 * dropped / sent as f64
    } else {
        0.0
    };

    println!("\n=== RESULTS ===");
    println!("mode:                        {}", cfg.mode);
    println!(
        "params:                      duration_secs={} target_rate={} upload_delay_ms={} \
max_buffer_rows={} channel_capacity={} flush_threshold_bytes={}",
        cfg.duration_secs,
        cfg.target_rate,
        cfg.upload_delay_ms,
        cfg.max_buffer_rows,
        cfg.channel_capacity,
        cfg.flush_threshold_bytes
    );
    println!("records sent:                {sent}");
    println!("records written (durable):   {written}");
    println!("records dropped (channel):   {dropped}");
    println!("records buffer_dropped(cap): {buffer_dropped}");
    println!("wall-clock elapsed:          {:.3}s", elapsed.as_secs_f64());
    println!("achieved send rate:          {achieved_send_rate:.1} rec/s");
    println!("effective accept rate:       {effective_accept_rate:.1} rec/s");
    println!("drop percentage:             {drop_pct:.3}%");
    println!("================\n");

    Ok(())
}
