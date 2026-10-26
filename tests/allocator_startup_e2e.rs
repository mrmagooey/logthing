//! End-to-end: the real `logthing` binary reports which global allocator it was built with.
//!
//! The same test covers both builds: a default gnu build must log `allocator=system`, a
//! `--features jemalloc` build (or any musl build) must log `allocator=jemalloc`. This is the
//! gnu-host proxy for the musl release artifact; the musl evidence itself is the zigbuild gate and
//! symbol check (scripts/check-jemalloc-symbols.sh) plus the perf runs, which need a cross build
//! and cannot run under `cargo test`.

mod common;

use common::Proc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_logthing");

const TOML: &str = r#"
bind_address = "127.0.0.1:{HTTP}"

[tls]
enabled = false

[metrics]
enabled = false

[syslog]
enabled = false

[hec]
enabled = true
token = "e2e-token"

[hec.local]
directory = "{DIR}/hec"
"#;

#[tokio::test]
async fn test_startup_logs_allocator_matching_build() {
    let (expected, other) = if cfg!(any(feature = "jemalloc", target_env = "musl")) {
        ("allocator=jemalloc", "allocator=system")
    } else {
        ("allocator=system", "allocator=jemalloc")
    };

    let mut proc = Proc::spawn_healthy(BIN, TOML, &[]).await;
    assert!(
        common::wait_until(Duration::from_secs(10), || proc.logs().contains(expected)).await,
        "startup log never contained `{expected}`:\n{}",
        proc.logs()
    );
    assert!(
        !proc.logs().contains(other),
        "startup log unexpectedly contained `{other}`:\n{}",
        proc.logs()
    );
    let status = proc.terminate(Duration::from_secs(30));
    assert!(status.success(), "graceful shutdown failed: {status}");
}
