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
    /// High-water mark of `LIVE` since the last reset in `live_heap_of`.
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn bump(delta: isize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + delta;
        live.set(now);
        let _ = PEAK.try_with(|peak| {
            if now > peak.get() {
                peak.set(now);
            }
        });
    });
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

/// Heap that `build` allocates and does **not** free (retained), and the
/// high-water mark above the starting level while it ran (peak).
fn live_heap_of<T>(build: impl FnOnce() -> T) -> (T, usize, usize) {
    let before = LIVE.with(Cell::get);
    PEAK.with(|p| p.set(before));
    let value = build();
    let after = LIVE.with(Cell::get);
    let peak = PEAK.with(Cell::get);
    (
        value,
        (after - before).max(0) as usize,
        (peak - before).max(0) as usize,
    )
}

fn datagram_header(total_len: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&10u16.to_be_bytes()); // version = 10 (IPFIX)
    buf.extend_from_slice(&(total_len as u16).to_be_bytes()); // message length
    buf.extend_from_slice(&0u32.to_be_bytes()); // export time
    buf.extend_from_slice(&0u32.to_be_bytes()); // sequence number
    buf.extend_from_slice(&0u32.to_be_bytes()); // observation domain id
    buf
}

/// One hostile IPFIX v10 datagram: a single maximally-truncated Options
/// Template Set (4-byte set header + 6-byte body: template_id,
/// field_count=0xFFFF, scope_field_count). The body has no room for even one
/// field specifier, so the decoder must reject it -- and must not have
/// reserved `field_count` entries up front to do so.
fn build_hostile_truncated_options_template() -> Vec<u8> {
    let mut buf = datagram_header(16 + 10);
    buf.extend_from_slice(&3u16.to_be_bytes()); // set id = 3 (Options Template Set)
    buf.extend_from_slice(&10u16.to_be_bytes()); // set length = 10
    buf.extend_from_slice(&256u16.to_be_bytes()); // template_id
    buf.extend_from_slice(&0xFFFFu16.to_be_bytes()); // field_count (attacker-controlled)
    buf.extend_from_slice(&1u16.to_be_bytes()); // scope_field_count
    buf
}

/// A datagram of `num_sets` well-formed minimal Options Template Sets, each
/// 14 bytes (4 set header + 6 record header + one 4-byte field specifier)
/// with a distinct template id, so every set is a real cache insert.
fn build_wellformed_options_template_flood(num_sets: u16) -> Vec<u8> {
    let mut buf = datagram_header(16 + num_sets as usize * 14);
    for i in 0..num_sets {
        buf.extend_from_slice(&3u16.to_be_bytes());
        buf.extend_from_slice(&14u16.to_be_bytes());
        buf.extend_from_slice(&(256u16 + i).to_be_bytes()); // distinct template_id
        buf.extend_from_slice(&1u16.to_be_bytes()); // field_count
        buf.extend_from_slice(&1u16.to_be_bytes()); // scope_field_count
        buf.extend_from_slice(&1u16.to_be_bytes()); // ie 1
        buf.extend_from_slice(&4u16.to_be_bytes()); // length 4
    }
    buf
}

/// The old bug reserved `Vec::with_capacity(field_count)` for the
/// wire-declared (attacker-controlled) count before checking it against the
/// body: ~786 KB for one 10-byte set, ~4.80 GiB across a 65 KB datagram of
/// them. The truncated template is now rejected, so nothing is retained --
/// the reservation shows up only as peak heap, which the clamp must keep tiny.
#[test]
fn hostile_truncated_options_template_does_not_reserve_declared_capacity() {
    use logthing::ipfix::decoder::{DecodeError, IpfixDecoder, decode_ipfix};

    let datagram = build_hostile_truncated_options_template();
    let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let (result, retained, peak) = live_heap_of(|| {
        let mut decoder = IpfixDecoder::new();
        let r = decode_ipfix(&mut decoder, &datagram, exporter);
        (r, decoder)
    });
    let (decode_result, _decoder) = result;

    assert!(
        matches!(decode_result, Err(DecodeError::Truncated { .. })),
        "decode should report Truncated: {decode_result:?}"
    );
    const MAX_PEAK_BYTES: usize = 64 * 1024;
    assert!(
        peak < MAX_PEAK_BYTES,
        "peak heap {peak} bytes for a 26-byte datagram -- declared field_count was \
         reserved; expected under {MAX_PEAK_BYTES} bytes"
    );
    assert!(retained < MAX_PEAK_BYTES, "retained {retained} bytes");
}

/// A full-size datagram of well-formed minimal options templates: thousands
/// of real cache inserts, each of which must stay small.
#[test]
fn wellformed_options_template_flood_stays_within_memory_bound() {
    use logthing::ipfix::decoder::{IpfixDecoder, decode_ipfix};

    let num_sets: u16 = 4_679; // 16 + 4679 * 14 = 65,522 bytes
    let datagram = build_wellformed_options_template_flood(num_sets);
    let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let (result, retained, _peak) = live_heap_of(|| {
        let mut decoder = IpfixDecoder::new();
        let r = decode_ipfix(&mut decoder, &datagram, exporter);
        (r, decoder)
    });
    let (decode_result, decoder) = result;
    assert!(
        decode_result.is_ok(),
        "flood must decode: {decode_result:?}"
    );
    // Proves the sets were real cache inserts, not skipped: each entry costs
    // at least a map slot plus its field vector.
    assert!(
        retained >= num_sets as usize * 32,
        "only {retained} bytes retained for {num_sets} templates"
    );
    drop(decoder);

    const MAX_RETAINED_BYTES: usize = 4 * 1024 * 1024;
    assert!(
        retained < MAX_RETAINED_BYTES,
        "flood retained {retained} bytes ({:.0}x the {} byte datagram); \
         expected under {MAX_RETAINED_BYTES}",
        retained as f64 / datagram.len() as f64,
        datagram.len(),
    );
}

/// Guards the measurement rig itself: if `live_heap_of` silently returned 0
/// (TLS not wired up, allocator not installed), the assertion above would
/// pass vacuously no matter what the decoder actually retained.
#[test]
fn the_counting_allocator_actually_counts() {
    let (v, real, _) = live_heap_of(|| vec![0u8; 4096]);
    assert_eq!(v.len(), 4096);
    assert!(real >= 4096, "counting allocator saw only {real} bytes");
}
