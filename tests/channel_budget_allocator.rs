//! Validates the channel-budget **estimator**, not the constants it feeds.
//!
//! `channel_budget.rs`'s own tests compare each `*_BYTES` constant against
//! `json_heap_bytes`, so they only ever prove the constant agrees with the
//! estimator — if the estimator is wrong, everything downstream is wrong and
//! every test still passes. (It was: before this test existed, `json_heap_bytes`
//! ignored `BTreeMap` node allocation and undercounted real heap by 2.4-3.1x,
//! so the "100 MiB" budget was really ~250 MiB.)
//!
//! This measures what the process actually allocates, with a counting global
//! allocator, and fails if the estimator drifts from it. It lives in its own
//! integration-test binary precisely because `#[global_allocator]` is
//! process-wide and must not perturb any other test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Net live bytes allocated by *this* thread. Thread-local rather than
    /// global so concurrently-running tests and the harness's own threads
    /// cannot pollute a measurement. Const-initialised and `Drop`-free, so
    /// touching it from inside the allocator cannot recurse or allocate.
    static LIVE: Cell<isize> = const { Cell::new(0) };
}

fn bump(delta: isize) {
    let _ = LIVE.try_with(|live| live.set(live.get() + delta));
}

struct CountingAlloc;

// SAFETY: every method forwards to `System` unchanged; the only addition is a
// non-allocating thread-local counter update.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump(layout.size() as isize);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump(layout.size() as isize);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        bump(-(layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump(new_size as isize - layout.size() as isize);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// Heap bytes that `build` allocates and does **not** free — i.e. the real
/// footprint of the value it returns.
fn live_heap_of<T>(build: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.with(Cell::get);
    let value = build();
    let after = LIVE.with(Cell::get);
    (value, (after - before).max(0) as usize)
}

/// Real allocation must be within 10% of the estimate, in either direction.
///
/// Not exact-equality: `btreemap_node_bytes` assumes packed nodes, and std's
/// node layout is an implementation detail that may shift. Not looser than
/// 10% either — the whole point is to catch the class of error that made this
/// test necessary, which was 144-211% off.
fn assert_within_10pct(real: usize, estimated: usize, what: &str) {
    let low = real * 9 / 10;
    let high = real * 11 / 10;
    assert!(
        estimated >= low && estimated <= high,
        "{what}: json_heap_bytes estimated {estimated} bytes but the allocator \
         saw {real} bytes ({:.2}x) -- expected {low}..={high}. Fix the \
         estimator, then re-derive every *_BYTES constant in \
         src/forwarding/channel_budget.rs from the new measurements.",
        real as f64 / estimated.max(1) as f64
    );
}

/// Flat object, one nesting level: the Zeek `conn` fixture from
/// `channel_budget.rs`'s `measured_zeek_record_bytes_matches_constant`.
/// Duplicated rather than shared because that fixture lives in a `#[cfg(test)]`
/// module the integration-test binary cannot see.
#[test]
fn json_heap_bytes_matches_real_allocation_for_a_zeek_conn_record() {
    let (fields, real) = live_heap_of(|| {
        serde_json::json!({
            "_path": "conn", "ts": 1717171717.123456, "uid": "CHhAvVGS1DHFjwGM9",
            "id.orig_h": "192.168.7.102", "id.orig_p": 33764,
            "id.resp_h": "93.184.216.34", "id.resp_p": 443,
            "proto": "tcp", "service": "ssl", "duration": 0.253,
            "orig_bytes": 1420, "resp_bytes": 5320, "conn_state": "SF",
            "local_orig": true, "local_resp": false, "missed_bytes": 0,
            "history": "ShADadFf", "orig_pkts": 12, "orig_ip_bytes": 1948,
            "resp_pkts": 14, "resp_ip_bytes": 5892
        })
    });
    let estimated = logthing::forwarding::channel_budget::json_heap_bytes(&fields);
    assert_within_10pct(real, estimated, "zeek conn fields");
}

/// Nested objects, where the old estimator was furthest off: every sub-object
/// costs a whole BTreeMap node of its own.
#[test]
fn json_heap_bytes_matches_real_allocation_for_a_nested_suricata_alert() {
    let (fields, real) = live_heap_of(|| {
        serde_json::json!({
            "timestamp": "2026-08-07T12:34:56.789012+0000",
            "flow_id": 1921394888273746i64,
            "in_iface": "eth0",
            "event_type": "alert",
            "src_ip": "192.168.7.102",
            "src_port": 45231,
            "dest_ip": "93.184.216.34",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2024897,
                "rev": 2,
                "signature": "ET MALWARE Suspicious User-Agent (curl)",
                "category": "A Network Trojan was detected",
                "severity": 1
            },
            "http": {
                "hostname": "example.com",
                "url": "/download/payload.bin",
                "http_user_agent": "curl/7.68.0",
                "http_method": "GET",
                "protocol": "HTTP/1.1",
                "status": 200,
                "length": 1024
            },
            "app_proto": "http",
            "flow": {
                "pkts_toserver": 6,
                "pkts_toclient": 8,
                "bytes_toserver": 512,
                "bytes_toclient": 4096,
                "start": "2026-08-07T12:34:55.123456+0000"
            }
        })
    });
    let estimated = logthing::forwarding::channel_budget::json_heap_bytes(&fields);
    assert_within_10pct(real, estimated, "suricata alert fields");
}

/// A small object of scalars — the shape IPFIX `extra` and HEC payloads take.
/// Five integer IEs own no string bytes at all, so this is almost pure node
/// overhead: the case the old estimator got most wrong (3.11x).
#[test]
fn json_heap_bytes_matches_real_allocation_for_a_small_scalar_object() {
    let (extra, real) = live_heap_of(|| {
        serde_json::json!({
            "ipClassOfService": 0,
            "minimumTTL": 64,
            "maximumTTL": 64,
            "flowEndReason": 3,
            "biflowDirection": 1
        })
    });
    let estimated = logthing::forwarding::channel_budget::json_heap_bytes(&extra);
    assert_within_10pct(real, estimated, "ipfix extra");
}

/// Guards the measurement rig itself: if `live_heap_of` silently returned 0
/// (TLS not wired up, allocator not installed), every assertion above would
/// pass vacuously for an estimator that also returned 0.
#[test]
fn the_counting_allocator_actually_counts() {
    let (v, real) = live_heap_of(|| vec![0u8; 4096]);
    assert_eq!(v.len(), 4096);
    assert!(real >= 4096, "counting allocator saw only {real} bytes");
}
