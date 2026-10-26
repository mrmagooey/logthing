//! Criterion micro-benchmark + deterministic allocation counts for the syslog persistence
//! wrapper chain `PayloadDispatchingHandler -> MultiSyslogHandler -> no-op targets`, i.e. what
//! `main.rs` wires whenever any syslog persistence target is configured.
//!
//! Evidence legs, in order of weight:
//! 1. (c) allocation counts: a counting `#[global_allocator]` (one relaxed load per allocation
//!    while disabled) counts allocations and bytes across `ALLOC_N` calls per case and prints
//!    `ALLOC_COUNT ...` lines before criterion starts. Deterministic, noise-free.
//! 2. (a) criterion time per call, with the input message cloned in the (untimed) setup.
//!
//! The case `overhead_*` (zero targets, `parse_payloads=false`) isolates the harness's own
//! `block_on` cost so it can be subtracted when reading the other rows.
//!
//! Run with: `cargo bench --bench syslog_payload_dispatch`

use async_trait::async_trait;
use criterion::{BatchSize, Criterion, Throughput};
use logthing::forwarding::structured_syslog_s3::StructuredS3Handler;
use logthing::forwarding::syslog_s3::MultiSyslogHandler;
use logthing::syslog::SyslogMessage;
use logthing::syslog::listener::{PayloadDispatchingHandler, SyslogHandler};
use logthing::syslog::payload::StructuredSyslogRecord;
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Calls per case in the counting leg.
const ALLOC_N: usize = 2_000;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

fn note(size: usize) {
    if COUNTING.load(Ordering::Relaxed) {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size as u64, Ordering::Relaxed);
    }
}

/// Forwards to `System`; counts allocation events only while `COUNTING` is set.
struct CountingAlloc;

// SAFETY: every method forwards to `System` unchanged; the only addition is relaxed atomic
// counter updates, which neither allocate nor recurse.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

const TIMESTAMP: &str = "Jan 15 10:30:45";
const HOSTNAME: &str = "loadgen-host";
const PRI: u16 = 134;

fn plain_message() -> SyslogMessage {
    let raw =
        format!("<{PRI}>{TIMESTAMP} {HOSTNAME} loadgen[4242]: synthetic load-test message #1");
    SyslogMessage::parse(&raw).expect("plain message must parse")
}

fn cef_message() -> SyslogMessage {
    let raw = format!(
        "<{PRI}>{TIMESTAMP} {HOSTNAME} loadgen: CEF:0|Loadgen|SyntheticFirewall|1.0|100|\
         Synthetic Blocked Connection|5|src=10.0.0.1 dst=10.1.0.1 spt=1024 dpt=443 cnt=1"
    );
    SyslogMessage::parse(&raw).expect("cef message must parse")
}

/// Persistence target stand-in: takes the message and drops it.
struct NoopTarget;

#[async_trait]
impl SyslogHandler for NoopTarget {
    async fn handle_message(&self, message: SyslogMessage, _source: SocketAddr) {
        black_box(message);
    }
}

struct Rig {
    handler: PayloadDispatchingHandler<MultiSyslogHandler>,
    rx: tokio::sync::mpsc::Receiver<StructuredSyslogRecord>,
}

/// Real `MultiSyslogHandler` around `targets` no-op targets, wrapped in the real
/// `PayloadDispatchingHandler`, with a structured handle backed by a drained channel.
fn rig(targets: usize, parse_payloads: bool) -> Rig {
    let (tx, rx) = tokio::sync::mpsc::channel(1024);
    let structured = Arc::new(StructuredS3Handler::for_test(tx, "syslog", "structured"));
    let inner = Arc::new(MultiSyslogHandler(
        (0..targets)
            .map(|_| Arc::new(NoopTarget) as Arc<dyn SyslogHandler>)
            .collect(),
    ));
    Rig {
        handler: PayloadDispatchingHandler {
            inner,
            parse_payloads,
            structured_handle: Some(structured),
        },
        rx,
    }
}

fn source() -> SocketAddr {
    "127.0.0.1:5514".parse().unwrap()
}

fn run_one(rt: &tokio::runtime::Runtime, rig: &mut Rig, msg: SyslogMessage) {
    rt.block_on(rig.handler.handle_message(msg, source()));
    while rig.rx.try_recv().is_ok() {}
}

/// `(case id, shape, targets, parse_payloads)` for every measured case.
fn cases() -> Vec<(String, &'static str, usize, bool)> {
    let mut out = vec![(
        "overhead_targets0_parsefalse_plain".to_string(),
        "plain",
        0,
        false,
    )];
    for shape in ["plain", "cef"] {
        for targets in [1usize, 2] {
            for parse in [true, false] {
                out.push((
                    format!("{shape}_targets{targets}_parse{parse}"),
                    shape,
                    targets,
                    parse,
                ));
            }
        }
    }
    out
}

fn message_for(shape: &str) -> SyslogMessage {
    if shape == "cef" {
        cef_message()
    } else {
        plain_message()
    }
}

/// Leg (c): deterministic allocation counts per call.
fn print_alloc_counts(rt: &tokio::runtime::Runtime) {
    for (id, shape, targets, parse) in cases() {
        let template = message_for(shape);
        let mut rig = rig(targets, parse);
        // Warm lazily-initialised statics (regexes, metric handles) outside the window.
        run_one(rt, &mut rig, template.clone());
        // Pre-clone inputs so only the handler's own allocations are counted.
        let inputs: Vec<SyslogMessage> = (0..ALLOC_N).map(|_| template.clone()).collect();
        ALLOCS.store(0, Ordering::Relaxed);
        BYTES.store(0, Ordering::Relaxed);
        COUNTING.store(true, Ordering::Relaxed);
        for m in inputs {
            run_one(rt, &mut rig, m);
        }
        COUNTING.store(false, Ordering::Relaxed);
        println!(
            "ALLOC_COUNT case={id} allocs_per_record={:.2} bytes_per_record={:.1}",
            ALLOCS.load(Ordering::Relaxed) as f64 / ALLOC_N as f64,
            BYTES.load(Ordering::Relaxed) as f64 / ALLOC_N as f64,
        );
    }
}

/// Leg (a): criterion time per call.
fn bench_cases(c: &mut Criterion, rt: &tokio::runtime::Runtime) {
    let mut group = c.benchmark_group("syslog_payload_dispatch");
    group.throughput(Throughput::Elements(1));
    for (id, shape, targets, parse) in cases() {
        let template = message_for(shape);
        let mut rig = rig(targets, parse);
        group.bench_function(&id, |b| {
            b.iter_batched(
                || template.clone(),
                |m| run_one(rt, &mut rig, m),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    print_alloc_counts(&rt);
    let mut c = Criterion::default().configure_from_args();
    bench_cases(&mut c, &rt);
    c.final_summary();
}
