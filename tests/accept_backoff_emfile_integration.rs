//! Integration test: a persistent TCP accept error (EMFILE, induced here by
//! exhausting this process's own file descriptors) must not spin the accept
//! loop at 100% CPU. `AcceptBackoff` (`src/net.rs`) is supposed to pause for
//! `ACCEPT_ERROR_BACKOFF` after any accept error that isn't a per-connection
//! one, bounding how often `listener_accept_errors` can grow during a
//! sustained EMFILE window to roughly one per second. Without that pause,
//! `TcpListener::accept()` returns the same EMFILE immediately on every
//! re-poll (the socket stays readable), so the counter grows by thousands in
//! the same window instead — see the mutation check in this test's
//! surrounding task report for the measured before/after numbers.
//!
//! Run on a current-thread runtime deliberately: this test lowers the
//! process-wide `RLIMIT_NOFILE` soft limit down to a handful of descriptors,
//! and a multi-thread runtime's extra worker threads each hold their own
//! fds (epoll instances, wakers, ...) that would compete for that same tiny
//! budget and make the induced EMFILE nondeterministic.
//!
//! `metrics::set_global_recorder` can only be called once per process, and
//! cargo runs every `#[tokio::test]` in a test binary in the same process,
//! so this file intentionally contains exactly ONE `#[tokio::test]`.

use logthing::net::AcceptBackoff;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::{CompositeKey, MetricKind};
use std::fs::File;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream as TokioTcpStream};
use tokio::time::{Duration, sleep, timeout};

#[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
fn read_accept_errors(snapshotter: &metrics_util::debugging::Snapshotter) -> u64 {
    let map = snapshotter.snapshot().into_hashmap();
    map.get(&CompositeKey::new(
        MetricKind::Counter,
        metrics::Key::from_parts(
            "listener_accept_errors",
            vec![metrics::Label::new("protocol", "test")],
        ),
    ))
    .map(|(_, _, v)| match v {
        DebugValue::Counter(c) => *c,
        _ => 0,
    })
    .unwrap_or(0)
}

#[tokio::test(flavor = "current_thread")]
async fn accept_backoff_bounds_accept_errors_under_fd_exhaustion() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::set_global_recorder(recorder).expect("install DebuggingRecorder");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Drives `AcceptBackoff::accept` in a loop, exactly as every production
    // accept site does, holding every accepted stream alive in a Vec so it
    // keeps its fd (an immediately-dropped stream would just free the fd
    // straight back, undermining the fd-exhaustion setup below).
    let accepted_count = Arc::new(AtomicUsize::new(0));
    let held_streams: Arc<Mutex<Vec<TokioTcpStream>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let accepted_count = accepted_count.clone();
        let held_streams = held_streams.clone();
        tokio::spawn(async move {
            let mut backoff = AcceptBackoff::new("test");
            loop {
                if let Ok((stream, _src)) = backoff.accept(&listener).await {
                    held_streams.lock().unwrap().push(stream);
                    accepted_count.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }

    // Lower the soft fd limit to just above what's already open: enough
    // headroom for the runtime/harness's own fds (stdio, the listener
    // socket, tokio's epoll/eventfd instances, the process's other already-
    // open descriptors) but tight enough that a handful of /dev/null opens
    // exhausts the rest.
    let already_open = std::fs::read_dir("/proc/self/fd").unwrap().count();
    let new_limit = (already_open + 8) as libc::rlim_t;
    let rlimit = libc::rlimit {
        rlim_cur: new_limit,
        rlim_max: new_limit,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlimit) };
    assert_eq!(
        rc,
        0,
        "setrlimit(RLIMIT_NOFILE) failed: {}",
        std::io::Error::last_os_error()
    );

    // Exhaust every remaining fd with /dev/null opens until EMFILE.
    let mut nulls = Vec::new();
    loop {
        match File::open("/dev/null") {
            Ok(f) => nulls.push(f),
            Err(e) => {
                assert_eq!(
                    e.raw_os_error(),
                    Some(libc::EMFILE),
                    "expected /dev/null opens to fail with EMFILE once the process is at its \
                     lowered fd limit, got: {e}"
                );
                break;
            }
        }
    }

    // Free exactly one fd for the client connect below to consume. The
    // kernel completes the TCP handshake into its own accept backlog
    // regardless of whether *this* process has a free fd to `accept()` it
    // with, so it is the server's `accept()` call -- not the client's
    // `connect()` -- that is left to hit EMFILE once the client's socket
    // has used up that one freed fd.
    nulls.pop();
    // A blocking `std::net::TcpStream::connect` (not tokio's async connect):
    // it completes the handshake synchronously on this call, so there is no
    // await point here that could hand control to the spawned accept task
    // before the fd accounting above has settled.
    let _client = std::net::TcpStream::connect(addr).expect("client connect");

    // Give the accept loop time to observe the EMFILE repeatedly. Without
    // the backoff this window sees thousands of `accept()` calls (a busy
    // spin); with it, at most a handful (roughly one per
    // `ACCEPT_ERROR_BACKOFF` = 1s).
    sleep(Duration::from_millis(2500)).await;

    let errors = read_accept_errors(&snapshotter);
    assert!(
        (1..=4).contains(&errors),
        "expected listener_accept_errors{{protocol=\"test\"}} in 1..=4 after 2.5s of induced \
         EMFILE with AcceptBackoff pausing the accept loop, got {errors} (an unbounded/very \
         large count here means the accept loop is spinning instead of backing off)"
    );

    // --- Recovery: freeing the exhausted fds must let the listener accept
    // again -- both the connection already parked in the kernel backlog
    // (the `client` above, kept open so the server's `accept()` sees a live
    // connection rather than a peer that already hung up) and a brand-new
    // one.
    drop(nulls);

    let before = accepted_count.load(Ordering::SeqCst);
    let recovered = timeout(Duration::from_secs(3), async {
        loop {
            if accepted_count.load(Ordering::SeqCst) > before {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "listener did not resume accepting within 3s after file descriptors were freed"
    );

    // A fresh connection must also succeed now, proving the listener is
    // genuinely back to normal operation and not just draining one stale
    // backlog entry.
    let before = accepted_count.load(Ordering::SeqCst);
    let _fresh = std::net::TcpStream::connect(addr).expect("fresh client connect after recovery");
    let recovered_fresh = timeout(Duration::from_secs(3), async {
        loop {
            if accepted_count.load(Ordering::SeqCst) > before {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        recovered_fresh.is_ok(),
        "listener did not accept a fresh connection within 3s after recovery"
    );
}
