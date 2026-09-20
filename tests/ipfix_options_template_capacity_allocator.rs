//! Regression test for the IPFIX options-template capacity-amplification bug.
//!
//! `parse_ipfix_options_template_set` (src/ipfix/decoder.rs) used to allocate
//! `Vec::with_capacity(field_count)` for the wire-declared `field_count`
//! *before* checking it against the remaining body, then `break` out of the
//! field loop on truncation and cache the over-capacity `Vec` anyway. A single
//! 65,526-byte datagram of maximally-truncated Options Template Sets
//! (field_count = 0xFFFF, 6-byte bodies) measured 4.80 GiB retained via a
//! counting allocator -- a ~78,630x amplification that aborts the process via
//! `handle_alloc_error` well before that.
//!
//! This lives in its own integration-test binary because `#[global_allocator]`
//! is process-wide and must not perturb any other test. Modeled directly on
//! `tests/channel_budget_allocator.rs`'s `live_heap_of` rig.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr};

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

/// Heap bytes that `build` allocates and does **not** free -- i.e. what it
/// permanently retains, measured across the whole call.
fn live_heap_of<T>(build: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.with(Cell::get);
    let value = build();
    let after = LIVE.with(Cell::get);
    (value, (after - before).max(0) as usize)
}

/// Builds one hostile IPFIX v10 datagram: a run of maximally-truncated
/// Options Template Sets. Each set is 10 bytes on the wire (4-byte set
/// header + 6-byte body: template_id, field_count=0xFFFF, scope_field_count),
/// so the field-specifier loop always breaks on its first iteration (the
/// body has 0 bytes left for a 4-byte field specifier).
fn build_hostile_options_template_datagram(num_sets: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    let total_len = 16 + num_sets as usize * 10;
    buf.extend_from_slice(&10u16.to_be_bytes()); // version = 10 (IPFIX)
    buf.extend_from_slice(&(total_len as u16).to_be_bytes()); // message length
    buf.extend_from_slice(&0u32.to_be_bytes()); // export time
    buf.extend_from_slice(&0u32.to_be_bytes()); // sequence number
    buf.extend_from_slice(&0u32.to_be_bytes()); // observation domain id

    for i in 0..num_sets {
        buf.extend_from_slice(&3u16.to_be_bytes()); // set id = 3 (Options Template Set)
        buf.extend_from_slice(&10u16.to_be_bytes()); // set length = 10
        buf.extend_from_slice(&(256u16 + i).to_be_bytes()); // template_id, distinct, >= 256
        buf.extend_from_slice(&0xFFFFu16.to_be_bytes()); // field_count (attacker-controlled)
        buf.extend_from_slice(&1u16.to_be_bytes()); // scope_field_count
    }
    buf
}

/// The datagram from the bug report: 65,526 bytes, 6,551 hostile Options
/// Template Sets. Before the fix this retained ~4.80 GiB; the fix must keep
/// it under a few MB.
#[test]
fn hostile_options_template_flood_does_not_amplify_retained_memory() {
    use logthing::ipfix::decoder::{IpfixDecoder, decode_ipfix};

    let num_sets: u16 = 6_551;
    let datagram = build_hostile_options_template_datagram(num_sets);
    assert_eq!(
        datagram.len(),
        65_526,
        "datagram size should match the bug report"
    );

    let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let (result, retained) = live_heap_of(|| {
        let mut decoder = IpfixDecoder::new();
        let decode_result = decode_ipfix(&mut decoder, &datagram, exporter);
        // Keep the decoder (and therefore its template cache) alive for the
        // whole measurement window -- what matters is what the process
        // retains after decoding, not just during. `cache_len` is
        // `pub(crate)`, so it is not reachable from this external
        // integration-test crate; the retained-byte bound below is the
        // observable proxy for "did every template actually get cached".
        (decode_result, decoder)
    });
    let (decode_result, _decoder) = result;

    assert!(
        decode_result.is_ok(),
        "decode should succeed: {decode_result:?}"
    );

    const MAX_RETAINED_BYTES: usize = 4 * 1024 * 1024; // a few MB, not gigabytes
    assert!(
        retained < MAX_RETAINED_BYTES,
        "hostile datagram retained {retained} bytes ({:.2} MiB) -- amplification \
         {:.0}x over the {} byte datagram; expected under {MAX_RETAINED_BYTES} bytes",
        retained as f64 / (1024.0 * 1024.0),
        retained as f64 / datagram.len() as f64,
        datagram.len(),
    );
}

/// Guards the measurement rig itself: if `live_heap_of` silently returned 0
/// (TLS not wired up, allocator not installed), the assertion above would
/// pass vacuously no matter what the decoder actually retained.
#[test]
fn the_counting_allocator_actually_counts() {
    let (v, real) = live_heap_of(|| vec![0u8; 4096]);
    assert_eq!(v.len(), 4096);
    assert!(real >= 4096, "counting allocator saw only {real} bytes");
}
