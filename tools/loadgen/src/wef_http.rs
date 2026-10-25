//! `loadgen wef-http` -- paced, concurrent HTTP load generator for the Windows Event
//! Forwarding delivery route (`POST /wsman/subscriptions/<uuid>`).
//!
//! A real Windows client first sends an `Enumerate` to `/wsman`; the response carries the
//! `NotifyTo` delivery address, and every later `Events` batch is posted there. This mode
//! does the same: one Enumerate up front (its failure aborts the run, since without it the
//! delivery route is not even mounted), then up to `--concurrency` `Events` requests in
//! flight, each holding `--events-per-request` Security 4624 events with a bookmark.
//!
//! Bodies are UTF-16LE with a BOM and `Content-Type: application/soap+xml;charset=UTF-16`,
//! as Windows sends them, so the server's decode path is exercised.
//!
//! This is plain unauthenticated HTTP: the target must run with
//! `wef.allow_unauthenticated = true`. Kerberos/TLS cost is therefore NOT in the profile.
//!
//! Only a 2xx response counts as "sent". Pacing, semaphore and 503 backpressure handling
//! match `hec-http` (`--target-rate` is events/s).

use anyhow::Context;
use clap::Args;
use reqwest::StatusCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use crate::backpressure::{Backpressure, RETRY_GRACE, SendOutcome, send_with_retry};
use crate::pacing::tick_record_count;

/// Command-line arguments of `loadgen wef-http`.
#[derive(Args, Debug)]
pub struct WefHttpArgs {
    /// Target host to send WEF HTTP requests to.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Target HTTP port (the server's `bind_address` port).
    #[arg(long, default_value_t = 5985)]
    pub port: u16,

    /// Target sustained rate, in events/sec (2xx responses only). 0 means "unbounded".
    #[arg(long, default_value_t = 10_000)]
    pub target_rate: u64,

    /// How long to send for, in seconds.
    #[arg(long, default_value_t = 60)]
    pub duration_secs: u64,

    /// Events per `Events` request (one delivery batch).
    #[arg(long, default_value_t = 50)]
    pub events_per_request: usize,

    /// Maximum number of HTTP requests in flight at once.
    #[arg(long, default_value_t = 16)]
    pub concurrency: usize,

    /// Retries of a 503-answered request (backpressure) before it is abandoned.
    #[arg(long, default_value_t = 5)]
    pub max_retries: u32,

    /// `MachineID` header value sent with every request (the client identity).
    #[arg(long, default_value = "loadgen.example.com")]
    pub machine_id: String,
}

/// Shared, cheaply-cloned state every in-flight request task needs.
#[derive(Clone)]
struct WefCtx {
    client: reqwest::Client,
    url: Arc<str>,
    machine_id: Arc<str>,
    sub_uuid: Arc<str>,
    semaphore: Arc<Semaphore>,
    sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    events_per_request: usize,
    bp: Arc<Backpressure>,
    max_retries: u32,
    /// Run end plus [`RETRY_GRACE`]: 503 retries stop after this.
    deadline: Instant,
}

/// Run the generator; errors when Enumerate fails or every request failed.
pub async fn run(args: WefHttpArgs) -> anyhow::Result<()> {
    let base = format!("http://{}:{}", args.host, args.port);
    let client = reqwest::Client::builder()
        .build()
        .context("build reqwest HTTP client")?;
    let delivery_path = enumerate(&client, &base, &args.machine_id).await?;
    let url = format!("{base}{delivery_path}");
    let sub_uuid = delivery_path
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string();

    println!(
        "loadgen wef-http: sending to {url} at target_rate={} rec/s for {}s (concurrency={})",
        args.target_rate, args.duration_secs, args.concurrency
    );

    let ctx = WefCtx {
        client,
        url: url.as_str().into(),
        machine_id: args.machine_id.as_str().into(),
        sub_uuid: sub_uuid.as_str().into(),
        semaphore: Arc::new(Semaphore::new(args.concurrency.max(1))),
        sent: Arc::new(AtomicU64::new(0)),
        errors: Arc::new(AtomicU64::new(0)),
        events_per_request: args.events_per_request.max(1),
        bp: Arc::new(Backpressure::default()),
        deadline: Instant::now() + Duration::from_secs(args.duration_secs) + RETRY_GRACE,
        max_retries: args.max_retries,
    };
    let batch = ctx.events_per_request as u64;

    let duration = Duration::from_secs(args.duration_secs);
    let start = Instant::now();
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut n: u64 = 0;

    if args.target_rate == 0 {
        while start.elapsed() < duration {
            spawn_request(&ctx, &mut tasks, n).await;
            n += batch;
        }
    } else {
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
            for _ in 0..tick_record_count(&mut carry, requests_per_tick_target) {
                if start.elapsed() >= duration {
                    break 'send_loop;
                }
                spawn_request(&ctx, &mut tasks, n).await;
                n += batch;
            }
        }
    }

    while tasks.join_next().await.is_some() {}

    let elapsed = start.elapsed();
    let sent = ctx.sent.load(Ordering::Relaxed);
    let errors = ctx.errors.load(Ordering::Relaxed);

    if errors > 0 {
        println!(
            "loadgen wef-http: {errors} requests rejected (non-2xx or transport error) -- \
             not counted as sent"
        );
    }

    println!("{}", ctx.bp.summary("wef-http", args.max_retries));
    println!(
        "loadgen wef-http: sent {sent} records in {:.3}s (achieved rate: {:.1} rec/s)",
        elapsed.as_secs_f64(),
        sent as f64 / elapsed.as_secs_f64()
    );

    if sent == 0 && errors > 0 {
        anyhow::bail!("loadgen wef-http: every request failed ({errors} errors, 0 events sent)");
    }
    Ok(())
}

/// POST the Enumerate and return the path of the `NotifyTo` delivery address.
async fn enumerate(
    client: &reqwest::Client,
    base: &str,
    machine_id: &str,
) -> anyhow::Result<String> {
    let hint =
        "the target needs wef.allow_unauthenticated = true and a [[wef.subscriptions]] entry";
    let resp = client
        .post(format!("{base}/wsman"))
        .header("Content-Type", CONTENT_TYPE)
        .body(enumerate_body(machine_id))
        .send()
        .await
        .with_context(|| format!("WEF Enumerate to {base}/wsman failed to send; {hint}"))?;
    let status = resp.status();
    if status != StatusCode::OK {
        anyhow::bail!("WEF Enumerate failed (status {status}); {hint}");
    }
    let bytes = resp.bytes().await.context("read Enumerate response")?;
    notify_path(&decode_utf16(&bytes)).ok_or_else(|| {
        anyhow::anyhow!("WEF Enumerate failed (status {status}); no NotifyTo address; {hint}")
    })
}

/// Acquire a concurrency permit and spawn one `Events` POST onto `tasks`.
async fn spawn_request(ctx: &WefCtx, tasks: &mut JoinSet<()>, n: u64) {
    let permit = ctx
        .semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("semaphore is never closed");
    let ctx = ctx.clone();
    tasks.spawn(async move {
        let _permit = permit;
        let body = events_body(n, &ctx.machine_id, &ctx.sub_uuid, ctx.events_per_request);
        let build = || {
            ctx.client
                .post(ctx.url.as_ref())
                .header("Content-Type", CONTENT_TYPE)
                .body(body.clone())
        };
        match send_with_retry(build, &ctx.bp, ctx.max_retries, ctx.deadline).await {
            SendOutcome::Accepted => {
                ctx.sent
                    .fetch_add(ctx.events_per_request as u64, Ordering::Relaxed);
            }
            SendOutcome::Rejected(status) => {
                ctx.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("loadgen wef-http: request rejected with {status}");
            }
            SendOutcome::Abandoned => {
                ctx.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("loadgen wef-http: request abandoned (503 after all retries)");
            }
            SendOutcome::TransportError(e) => {
                ctx.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("loadgen wef-http: request error: {e:#}");
            }
        }
    });
}

const CONTENT_TYPE: &str = "application/soap+xml;charset=UTF-16";

// The envelope builders below duplicate the shape of `tests/common/mod.rs` in the root
// crate: loadgen cannot use that crate's test helpers.
const ENV_OPEN: &str = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" \
    xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
    xmlns:n=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\" \
    xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" \
    xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd\" \
    xmlns:b=\"http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd\">";

/// The Security 4624 fixture the root crate's tests use (`common::wef_fixture`).
const EVENT_4624: &str = include_str!("../../../tests/fixtures/wef/events/security_4624.xml");

/// UTF-16LE with a leading BOM, the encoding Windows clients send.
fn utf16(s: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    out.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
    out
}

/// Decode a UTF-16LE (BOM optional) response body, lossily.
fn decode_utf16(bytes: &[u8]) -> String {
    let body = bytes.strip_prefix(&[0xFF, 0xFE][..]).unwrap_or(bytes);
    let units: Vec<u16> = body
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

/// A unique `uuid:`-prefixed message id for request number `seq`.
fn message_id(seq: u64) -> String {
    format!("uuid:00000000-0000-4000-8000-{seq:012x}")
}

/// Subscription-manager `Enumerate` request, UTF-16LE encoded.
fn enumerate_body(machine_id: &str) -> Vec<u8> {
    let xml = format!(
        "{ENV_OPEN}<s:Header><a:To>http://logthing.example.com:5985/wsman/SubscriptionManager/WEC\
         </a:To><w:ResourceURI s:mustUnderstand=\"true\">\
         http://schemas.microsoft.com/wbem/wsman/1/SubscriptionManager/Subscription\
         </w:ResourceURI><m:MachineID \
         xmlns:m=\"http://schemas.microsoft.com/wbem/wsman/1/machineid\" \
         s:mustUnderstand=\"false\">{machine_id}</m:MachineID><a:ReplyTo><a:Address \
         s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous\
         </a:Address></a:ReplyTo><a:Action s:mustUnderstand=\"true\">\
         http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action>\
         <w:MaxEnvelopeSize s:mustUnderstand=\"true\">512000</w:MaxEnvelopeSize>\
         <a:MessageID>{mid}</a:MessageID><w:OperationTimeout>PT60.000S</w:OperationTimeout>\
         </s:Header><s:Body><n:Enumerate><w:OptimizeEnumeration/><w:MaxElements>32000\
         </w:MaxElements></n:Enumerate></s:Body></s:Envelope>",
        mid = message_id(0)
    );
    utf16(&xml)
}

/// One 4624 event with the given `EventRecordID` and a varying `TargetUserName`.
fn event_xml(record_id: u64) -> String {
    EVENT_4624
        .replace(
            "<EventRecordID>227443</EventRecordID>",
            &format!("<EventRecordID>{record_id}</EventRecordID>"),
        )
        .replace(
            "<Data Name=\"TargetUserName\">WIN-WFBHIBE5GXZ$</Data>",
            &format!(
                "<Data Name=\"TargetUserName\">user{}</Data>",
                record_id % 1000
            ),
        )
}

/// A delivery `Events` request carrying `n` events with record ids `seq..seq+n` and a
/// bookmark at the last one, UTF-16LE encoded.
fn events_body(seq: u64, machine_id: &str, sub_uuid: &str, n: usize) -> Vec<u8> {
    let bookmark_record_id = seq + n as u64;
    let events: String = (0..n as u64)
        .map(|i| {
            format!(
                "<w:Event Action=\"http://schemas.dmtf.org/wbem/wsman/1/wsman/Event\">\
                 <![CDATA[{}]]></w:Event>",
                event_xml(seq + i)
            )
        })
        .collect();
    let xml = format!(
        "{ENV_OPEN}<s:Header><a:To>http://logthing.example.com:5985/wsman/subscriptions/\
         {sub_uuid}/1\
         </a:To><m:MachineID xmlns:m=\"http://schemas.microsoft.com/wbem/wsman/1/machineid\" \
         s:mustUnderstand=\"false\">{machine_id}</m:MachineID><a:ReplyTo><a:Address \
         s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous\
         </a:Address></a:ReplyTo><a:Action s:mustUnderstand=\"true\">\
         http://schemas.dmtf.org/wbem/wsman/1/wsman/Events</a:Action>\
         <a:MessageID>{mid}</a:MessageID><p:OperationID s:mustUnderstand=\"false\">\
         uuid:3E4F5061-7283-4940-A5B6-C7D8E9F0A1B2</p:OperationID>\
         <p:SequenceId s:mustUnderstand=\"false\">1</p:SequenceId>\
         <w:OperationTimeout>PT60.000S</w:OperationTimeout>\
         <e:Identifier xmlns:e=\"http://schemas.xmlsoap.org/ws/2004/08/eventing\" \
         s:mustUnderstand=\"true\">{sub_uuid}</e:Identifier>\
         <w:Bookmark><BookmarkList><Bookmark Channel=\"Security\" \
         RecordId=\"{bookmark_record_id}\" IsCurrent=\"true\"/></BookmarkList></w:Bookmark>\
         <w:AckRequested/></s:Header><s:Body><w:Events>{events}</w:Events></s:Body></s:Envelope>",
        mid = message_id(seq)
    );
    utf16(&xml)
}

/// Path of the first `NotifyTo` `a:Address` in an `EnumerateResponse`, if any.
fn notify_path(enumerate_response: &str) -> Option<String> {
    let after = enumerate_response.split("<e:NotifyTo>").nth(1)?;
    let addr = after
        .split("<a:Address>")
        .nth(1)?
        .split("</a:Address>")
        .next()?;
    Some(reqwest::Url::parse(addr.trim()).ok()?.path().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(n: usize, seq: u64) -> String {
        decode_utf16(&events_body(
            seq,
            "m",
            "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0",
            n,
        ))
    }

    #[test]
    fn events_body_is_utf16le_with_bom() {
        for n in [1usize, 50] {
            let body = events_body(0, "m", "sub", n);
            assert_eq!(&body[..2], &[0xFF, 0xFE]);
            let text = decode_utf16(&body);
            assert!(text.contains("<w:Events>"));
            assert_eq!(text.matches("<w:Event ").count(), n);
        }
    }

    #[test]
    fn message_ids_are_unique_per_request() {
        let id = |s: u64| {
            let t = decoded(1, s);
            t.split("<a:MessageID>")
                .nth(1)
                .unwrap()
                .split('<')
                .next()
                .unwrap()
                .to_string()
        };
        assert_ne!(id(0), id(50));
        assert!(id(0).starts_with("uuid:"));
    }

    #[test]
    fn bookmark_record_id_increases() {
        let rid = |s: u64| {
            let t = decoded(5, s);
            t.split("RecordId=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        };
        assert!(rid(5) > rid(0));
    }

    #[test]
    fn event_record_ids_vary_across_batches() {
        let ids = |s: u64| -> Vec<String> {
            decoded(3, s)
                .split("<EventRecordID>")
                .skip(1)
                .map(|p| p.split('<').next().unwrap().to_string())
                .collect()
        };
        let (a, b) = (ids(0), ids(3));
        assert_eq!(a.len(), 3);
        assert!(a.iter().all(|x| !b.contains(x)), "{a:?} vs {b:?}");
        assert_eq!(a.iter().collect::<std::collections::HashSet<_>>().len(), 3);
        assert!(
            !decoded(1, 7).contains("227443"),
            "template id must be replaced"
        );
        assert!(
            !decoded(1, 7).contains("WIN-WFBHIBE5GXZ$"),
            "user must be replaced"
        );
    }

    #[test]
    fn notify_to_is_extracted_from_enumerate_response() {
        // Shape of the server's EnumerateResponse (src/wef/subscription.rs: the Subscribe
        // item's `e:NotifyTo` holds the reference properties with the delivery address).
        let resp = "<s:Body><e:NotifyTo><a:Address>http://logthing.example.com:5985/wsman/\
                    subscriptions/0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0</a:Address>\
                    <a:ReferenceProperties/></e:NotifyTo></s:Body>";
        assert_eq!(
            notify_path(resp).as_deref(),
            Some("/wsman/subscriptions/0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0")
        );
        assert_eq!(notify_path("<s:Body/>"), None);
    }

    // Integration: drive the generator against an in-process logthing `Server`.

    use logthing::config::{Config, MetricsConfig, TlsConfig, WefConfig, WefLocalConfig};
    use logthing::forwarding::flush_registry::FlushIntervalRegistry;
    use logthing::middleware::IpWhitelist;
    use logthing::server::Server;
    use logthing::stats::{SourceHourlyStats, ThroughputStats};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use tokio::sync::RwLock;

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn config(port: u16, dir: &std::path::Path, with_subscription: bool) -> Config {
        let subscriptions = if with_subscription {
            vec![
                serde_json::from_value(serde_json::json!({
                    "name": "security",
                    "uuid": "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0",
                    "channels": ["Security"],
                }))
                .unwrap(),
            ]
        } else {
            Vec::new()
        };
        Config {
            bind_address: format!("127.0.0.1:{port}").parse().unwrap(),
            tls: TlsConfig {
                enabled: false,
                ..TlsConfig::default()
            },
            metrics: MetricsConfig {
                enabled: false,
                ..MetricsConfig::default()
            },
            wef: WefConfig {
                collector_url: Some(format!("http://127.0.0.1:{port}")),
                allow_unauthenticated: true,
                subscriptions,
                local: Some(WefLocalConfig {
                    directory: dir.to_path_buf(),
                    prefix: String::new(),
                    flush_threshold_bytes: usize::MAX,
                    flush_interval_secs: 1,
                    channel_capacity: 4096,
                    max_buffer_rows: 100_000,
                }),
                ..WefConfig::default()
            },
            ..Config::default()
        }
    }

    fn parquet_rows(dir: &std::path::Path) -> i64 {
        let mut total = 0;
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "parquet") {
                    let b =
                        ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(p).unwrap())
                            .unwrap();
                    total += b.metadata().file_metadata().num_rows();
                }
            }
        }
        total
    }

    /// Start a server, run `body(port)`, shut down and flush; returns body's result.
    async fn with_server<T, F, Fut>(with_sub: bool, dir: &std::path::Path, body: F) -> T
    where
        F: FnOnce(u16) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let port = free_port();
        let cfg = config(port, dir, with_sub);
        let shared = Arc::new(RwLock::new(cfg.clone()));
        let mut server = Server::new(
            cfg,
            shared,
            Arc::new(ThroughputStats::new()),
            Arc::new(SourceHourlyStats::new()),
            FlushIntervalRegistry::new(),
            IpWhitelist::empty(),
            Vec::new(),
        )
        .await
        .expect("Server::new");
        let workers = server.take_wef_worker_handles();
        let (shutdown, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(server.run(rx));
        let client = reqwest::Client::new();
        let health = format!("http://127.0.0.1:{port}/health");
        let mut ready = false;
        for _ in 0..100 {
            if client
                .get(&health)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(ready, "server never became healthy");
        let out = body(port).await;
        shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("server joins")
            .expect("server task")
            .expect("server run");
        for h in workers {
            tokio::time::timeout(Duration::from_secs(10), h)
                .await
                .expect("worker joins")
                .expect("worker task");
        }
        out
    }

    fn args(port: u16, rate: u64, secs: u64, epr: usize) -> WefHttpArgs {
        WefHttpArgs {
            host: "127.0.0.1".into(),
            port,
            target_rate: rate,
            duration_secs: secs,
            events_per_request: epr,
            concurrency: 16,
            max_retries: 5,
            machine_id: "loadgen.example.com".into(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_lands_events_in_parquet() {
        let dir = tempfile::tempdir().unwrap();
        let res = with_server(true, dir.path(), |port| run(args(port, 200, 2, 10))).await;
        res.expect("run");
        let rows = parquet_rows(dir.path());
        assert!(rows >= 300, "expected >= 300 rows, got {rows}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn events_without_subscription_fail_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let res = with_server(false, dir.path(), |port| run(args(port, 100, 1, 5))).await;
        let msg = format!("{:#}", res.expect_err("must fail"));
        assert!(msg.contains("wef.allow_unauthenticated"), "{msg}");
        assert!(msg.contains("[[wef.subscriptions]]"), "{msg}");
    }
}
