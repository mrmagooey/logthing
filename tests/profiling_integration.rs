//! Integration coverage for the `pprof` sampler.
//!
//! Only compiled with `--features pprof`; see the `build-pprof` CI job.

#![cfg(feature = "pprof")]

use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Distinctly named so it can be found in the flamegraph's symbol text.
#[inline(never)]
fn logthing_profiling_test_burner(iterations: u64) -> u64 {
    let mut acc = 0u64;
    for i in 0..iterations {
        acc = acc.wrapping_add(black_box(i).wrapping_mul(2_654_435_761));
    }
    acc
}

/// The sampler's first `ProfilerGuardBuilder::build()` call in this process
/// pays a one-time `backtrace::Backtrace::new()` warm-up cost that scales with
/// the size of the binary's debug info. In this workspace's unoptimized debug
/// test binary that warm-up has been observed to take several real seconds —
/// far more than the 2-second profiling window itself. A fixed sleep sized
/// only for the profiling window would therefore be racy (and would also
/// leave the burner idle by the time sampling actually starts, which would
/// fail the cross-thread assertion below for a reason that has nothing to do
/// with cross-thread sampling). So the burner runs continuously until the
/// sampler's artifacts are confirmed on disk, and this loop polls for them
/// with a generous timeout instead of guessing a fixed delay.
const ARTIFACT_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const ARTIFACT_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sampler_attributes_cpu_burned_on_a_different_thread() {
    let dir = tempfile::tempdir().expect("tempdir");

    // SAFETY: single-threaded setup before any profiling task is spawned.
    unsafe {
        std::env::set_var("LOGTHING_PROFILE_SECS", "2");
        std::env::set_var("LOGTHING_PROFILE_HZ", "99");
        std::env::set_var("LOGTHING_PROFILE_DIR", dir.path());
        std::env::remove_var("LOGTHING_PROFILE_DELAY_SECS");
    }

    // The guard is built by the spawned sampler task. The burner runs on a
    // *different* OS thread entirely, which is the property under test.
    logthing::profiling::maybe_start(Some(Box::new(|| Some(0))));

    let keep_burning = Arc::new(AtomicBool::new(true));
    let burner_flag = Arc::clone(&keep_burning);
    let burner = std::thread::spawn(move || {
        let mut acc = 0u64;
        while burner_flag.load(Ordering::Relaxed) {
            acc = acc.wrapping_add(logthing_profiling_test_burner(200_000));
        }
        acc
    });

    let metadata_path = dir.path().join("profile-metadata.json");
    let deadline = Instant::now() + ARTIFACT_WAIT_TIMEOUT;
    while !metadata_path.exists() {
        assert!(
            Instant::now() < deadline,
            "profiling artifacts did not appear within {ARTIFACT_WAIT_TIMEOUT:?}"
        );
        tokio::time::sleep(ARTIFACT_POLL_INTERVAL).await;
    }

    keep_burning.store(false, Ordering::Relaxed);
    let _ = burner.join();

    let svg = std::fs::read_to_string(dir.path().join("flamegraph.svg")).expect("flamegraph.svg");
    let meta_raw = std::fs::read_to_string(&metadata_path).expect("metadata");
    let pb = std::fs::metadata(dir.path().join("profile.pb")).expect("profile.pb");

    assert!(!svg.is_empty(), "flamegraph.svg is empty");
    assert!(pb.len() > 0, "profile.pb is empty");
    assert!(
        svg.contains("logthing_profiling_test_burner"),
        "flamegraph does not attribute samples to the burner running on another \
         thread — cross-thread SIGPROF sampling may be broken on this platform"
    );

    let meta: serde_json::Value = serde_json::from_str(&meta_raw).expect("metadata parses");
    assert!(
        meta["sample_count"].as_u64().unwrap() > 0,
        "no samples collected"
    );
}
