//! Shared UDP socket setup for the ipfix, sflow and syslog listeners.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{info, warn};

/// Bind a UDP socket at `addr`, optionally requesting a larger `SO_RCVBUF`.
///
/// `requested = None` leaves the OS default alone — a deliberate opt-out,
/// since a larger receive buffer is kernel memory held per socket for the
/// life of the process.
///
/// The kernel rarely grants exactly what's requested: an unprivileged caller
/// (no `CAP_NET_ADMIN`) has the request silently clamped to
/// `net.core.rmem_max`, and whatever survives the clamp is then doubled for
/// bookkeeping. Both the requested and the actual (post-clamp, post-double)
/// values are logged at startup so an operator can see the clamp happening
/// instead of wondering why kernel-queue drops persist after "fixing" the
/// buffer.
pub async fn bind_udp_with_recv_buffer(
    addr: &SocketAddr,
    requested: Option<usize>,
    protocol: &str,
) -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr).await?;
    // `0` is the operator-facing opt-out, not just `None`. TOML has no way to
    // express `None`: omitting the key runs the serde default (4 MiB) and
    // setting it yields `Some(n)`, so without this an operator has no
    // reachable way to decline the larger buffer at all — which is exactly
    // what the field's own docs promise they can do.
    if let Some(requested) = requested.filter(|n| *n > 0) {
        let sock_ref = socket2::SockRef::from(&socket);
        if let Err(e) = sock_ref.set_recv_buffer_size(requested) {
            warn!("{protocol}: failed to set SO_RCVBUF to {requested} bytes: {e}");
        } else {
            match sock_ref.recv_buffer_size() {
                Ok(actual) if actual < requested => warn!(
                    "{protocol}: SO_RCVBUF requested {requested} bytes, kernel granted only \
                     {actual} bytes (clamped by net.core.rmem_max)"
                ),
                Ok(actual) => info!(
                    "{protocol}: SO_RCVBUF requested {requested} bytes, kernel granted {actual} bytes"
                ),
                Err(e) => warn!("{protocol}: SO_RCVBUF set but readback failed: {e}"),
            }
        }
    }
    Ok(socket)
}

// ---------------------------------------------------------------------------
// Socket-level drop counter / rx-queue gauge (Task 0.0)
// ---------------------------------------------------------------------------
//
// `<proto>_datagrams_received` (per-listener) counts what arrived; nothing
// counted what the kernel discarded before it ever reached this process.
// Every prior loss figure was reconstructed by hand-diffing the process-wide
// `/proc/net/snmp`. This reads the *specific* line for our own socket out of
// `/proc/net/udp` (or `/proc/net/udp6` for a `[::]`-bound socket) instead.

/// How often a listener should poll `/proc/net/udp{,6}` for its own socket's
/// drop counter and rx-queue depth.
///
/// Matches `CHANNEL_GAUGE_INTERVAL` in `src/forwarding/buffered_writer.rs`:
/// one read per second per listener, zero per-datagram cost. This must only
/// ever be driven from a timer tick in a `select!` loop, never from the recv
/// arm — `src/forwarding/drop_log.rs` found that per-drop *logging* on the
/// recv path cost ~21% of throughput at 50k/s; a per-datagram `/proc` read
/// would be the same mistake in different packaging.
pub const SOCKET_DROP_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// One socket's `rx_queue` / `drops` reading, parsed from its `/proc/net/udp{,6}` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcNetUdpEntry {
    rx_queue: u64,
    drops: u64,
}

/// Format an IPv4 address the way the kernel writes it into `/proc/net/udp`'s
/// `local_address` field: each octet-quad reinterpreted as a little-endian
/// `u32` and printed as 8 uppercase hex digits (e.g. `127.0.0.1` -> `0100007F`).
fn ipv4_hex(ip: Ipv4Addr) -> String {
    format!("{:08X}", u32::from_le_bytes(ip.octets()))
}

/// Same idea as [`ipv4_hex`], applied per 4-byte word across all 16 bytes of
/// an IPv6 address, for `/proc/net/udp6`'s `local_address` field.
fn ipv6_hex(ip: Ipv6Addr) -> String {
    let octets = ip.octets();
    octets
        .chunks_exact(4)
        .map(|chunk| {
            let word: [u8; 4] = chunk.try_into().expect("chunks_exact(4)");
            format!("{:08X}", u32::from_le_bytes(word))
        })
        .collect()
}

/// The exact `local_address` field text (`<addr-hex>:<port-hex>`) the kernel
/// would print for `addr` in `/proc/net/udp` (v4) or `/proc/net/udp6` (v6),
/// plus which of the two files to read.
fn proc_net_udp_needle(addr: SocketAddr) -> (String, &'static str) {
    match addr {
        SocketAddr::V4(a) => (
            format!("{}:{:04X}", ipv4_hex(*a.ip()), a.port()),
            "/proc/net/udp",
        ),
        SocketAddr::V6(a) => (
            format!("{}:{:04X}", ipv6_hex(*a.ip()), a.port()),
            "/proc/net/udp6",
        ),
    }
}

/// Find the line in a `/proc/net/udp{,6}`-formatted file whose `local_address`
/// field exactly matches `needle`, and extract its `rx_queue`/`drops` columns.
///
/// Matching the full `local_address` (address *and* port), not just the port,
/// is deliberate: two sockets can share a port bound to different addresses,
/// and reading another socket's line would be a silent wrong answer.
fn parse_proc_net_udp(contents: &str, needle: &str) -> Option<ProcNetUdpEntry> {
    contents.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // sl local_address rem_address st tx_queue:rx_queue tr tm->when
        // retrnsmt uid timeout inode ref pointer drops -- 13 fields, drops last.
        if fields.len() < 13 {
            return None;
        }
        if !fields[1].eq_ignore_ascii_case(needle) {
            return None;
        }
        let rx_hex = fields[4].split_once(':')?.1;
        let rx_queue = u64::from_str_radix(rx_hex, 16).ok()?;
        let drops = fields.last()?.parse::<u64>().ok()?;
        Some(ProcNetUdpEntry { rx_queue, drops })
    })
}

/// Polls a single UDP listener socket's own `/proc/net/udp{,6}` line once per
/// call and reports `<protocol>_socket_drops` (counter, delta since the last
/// poll) and `<protocol>_socket_rx_queue_bytes` (gauge).
///
/// Callers must drive [`Self::poll`] from a `SOCKET_DROP_POLL_INTERVAL` timer
/// tick inside their existing `select!` loop -- never from the recv arm (see
/// `SOCKET_DROP_POLL_INTERVAL`'s docs).
pub struct SocketDropStats {
    protocol: &'static str,
    proc_path: &'static str,
    needle: String,
    prev_drops: Option<u64>,
    /// Set once `/proc/net/udp{,6}` proves unreadable (unusual container,
    /// non-Linux host); `poll()` becomes a no-op rather than warning every
    /// second or ever failing the listener.
    disabled: bool,
}

impl SocketDropStats {
    /// Build a tracker for `socket`'s own local address. Never fails: if the
    /// local address can't be read, the tracker starts disabled.
    pub fn new(socket: &UdpSocket, protocol: &'static str) -> Self {
        match socket.local_addr() {
            Ok(addr) => {
                let (needle, proc_path) = proc_net_udp_needle(addr);
                Self {
                    protocol,
                    proc_path,
                    needle,
                    prev_drops: None,
                    disabled: false,
                }
            }
            Err(e) => {
                warn!(
                    "{protocol}: could not read local_addr for socket-drop metrics, disabling: {e}"
                );
                Self {
                    protocol,
                    proc_path: "",
                    needle: String::new(),
                    prev_drops: None,
                    disabled: true,
                }
            }
        }
    }

    /// Read `/proc/net/udp{,6}` once and update this socket's metrics.
    ///
    /// `drops` is an absolute, monotonic-per-socket kernel counter;
    /// `metrics::counter!` wants a delta. If the reading goes backwards (the
    /// socket rebound, or the counter otherwise reset) this emits 0 rather
    /// than a bogus huge delta.
    pub async fn poll(&mut self) {
        if self.disabled {
            return;
        }
        let contents = match tokio::fs::read_to_string(self.proc_path).await {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "{}: {} unreadable, disabling socket-drop metrics: {e}",
                    self.protocol, self.proc_path
                );
                self.disabled = true;
                return;
            }
        };
        let Some(entry) = parse_proc_net_udp(&contents, &self.needle) else {
            // Transient miss (e.g. read raced a rebind) -- keep polling.
            return;
        };
        metrics::gauge!(format!("{}_socket_rx_queue_bytes", self.protocol))
            .set(entry.rx_queue as f64);
        let delta = match self.prev_drops {
            Some(prev) if entry.drops >= prev => entry.drops - prev,
            Some(_) => 0, // counter went backwards: rebind/reset, not a real drop burst.
            None => 0,    // first reading: no baseline to diff against yet.
        };
        self.prev_drops = Some(entry.drops);
        // Always increment (even by 0) so the counter registers and appears
        // on /metrics from the very first poll, rather than only once a real
        // drop occurs.
        metrics::counter!(format!("{}_socket_drops", self.protocol)).increment(delta);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recv_buffer_size(socket: &UdpSocket) -> usize {
        socket2::SockRef::from(socket).recv_buffer_size().unwrap()
    }

    /// `receive_buffer_bytes = 0` is the only opt-out an operator can actually
    /// write: TOML cannot express `None`, so omitting the key runs the serde
    /// default and any value yields `Some(n)`. Guards the gap between what the
    /// field's docs promise and what a config file can express.
    #[tokio::test]
    async fn zero_is_treated_as_opt_out_like_none() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let untouched = bind_udp_with_recv_buffer(&addr, None, "test")
            .await
            .unwrap();
        let zero = bind_udp_with_recv_buffer(&addr, Some(0), "test")
            .await
            .unwrap();
        assert_eq!(
            recv_buffer_size(&zero),
            recv_buffer_size(&untouched),
            "0 must leave the OS default alone, exactly as None does"
        );
    }

    /// The kernel doubles whatever `SO_RCVBUF` value survives the clamp, and
    /// an unprivileged caller gets silently clamped to `net.core.rmem_max` —
    /// so this asserts "larger than the OS default", never an exact byte
    /// count. Do NOT tighten this into an exact-value assertion: the real
    /// number is host- and privilege-dependent and would flake the moment it
    /// runs somewhere with a different `rmem_max`.
    #[tokio::test]
    async fn requesting_a_larger_buffer_beats_the_os_default() {
        let baseline = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let default_size = recv_buffer_size(&baseline);

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let tuned = bind_udp_with_recv_buffer(&addr, Some(4 * 1024 * 1024), "test")
            .await
            .unwrap();

        assert!(
            recv_buffer_size(&tuned) > default_size,
            "expected tuned buffer ({}) to exceed the OS default ({default_size})",
            recv_buffer_size(&tuned)
        );
    }

    /// `None` must be a true no-op — it must not even touch `SO_RCVBUF`.
    #[tokio::test]
    async fn none_leaves_the_os_default_alone() {
        let baseline = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let default_size = recv_buffer_size(&baseline);

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let untouched = bind_udp_with_recv_buffer(&addr, None, "test")
            .await
            .unwrap();

        assert_eq!(recv_buffer_size(&untouched), default_size);
    }

    /// Known-good encoding check: 127.0.0.1 is the textbook `/proc/net/udp`
    /// example (octets reversed into a little-endian `u32`).
    #[test]
    fn ipv4_hex_matches_known_proc_net_udp_encoding() {
        assert_eq!(ipv4_hex(Ipv4Addr::new(127, 0, 0, 1)), "0100007F");
        assert_eq!(ipv4_hex(Ipv4Addr::new(0, 0, 0, 0)), "00000000");
    }

    /// `::1` is the commonly-cited `/proc/net/tcp6`/`/proc/net/udp6` example:
    /// each 32-bit word of the address is independently byte-reversed, same
    /// as the IPv4 case, but word order is preserved.
    #[test]
    fn ipv6_hex_matches_known_proc_net_udp6_encoding() {
        assert_eq!(
            ipv6_hex(Ipv6Addr::LOCALHOST),
            "00000000000000000000000001000000"
        );
        assert_eq!(
            ipv6_hex(Ipv6Addr::UNSPECIFIED),
            "00000000000000000000000000000000"
        );
    }

    /// Real-format `/proc/net/udp` fixture: two sockets, one on port 0x1F49
    /// (8009) and a *different* socket on port 0x1F4A (8010). Parsing for
    /// the first port must return only the first line's columns -- proves
    /// the match is on the real socket, not just "first line" or "any line".
    const FIXTURE_PROC_NET_UDP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  51: 00000000:1F49 00000000:0000 07 00000000:00000100 00:00000000 00000000     0        0 7655 2 0000000000000000 42
  52: 00000000:1F4A 00000000:0000 07 00000000:00000200 00:00000000 00000000     0        0 7656 2 0000000000000000 99
";

    #[test]
    fn parse_proc_net_udp_extracts_rx_queue_and_drops_for_matching_port() {
        let entry = parse_proc_net_udp(FIXTURE_PROC_NET_UDP, "00000000:1F49")
            .expect("port 0x1F49 line must parse");
        assert_eq!(entry.rx_queue, 0x100);
        assert_eq!(entry.drops, 42);
    }

    /// Guards the silent-wrong-socket failure mode: a query for a *different*
    /// port present elsewhere in the file must not be satisfied by the wrong
    /// line's (very different) drops/rx_queue values.
    #[test]
    fn parse_proc_net_udp_does_not_match_a_different_port() {
        let entry = parse_proc_net_udp(FIXTURE_PROC_NET_UDP, "00000000:1F4A")
            .expect("port 0x1F4A line must parse");
        assert_eq!(entry.rx_queue, 0x200);
        assert_eq!(entry.drops, 99);
        assert_ne!(
            entry.drops, 42,
            "must not have matched the 0x1F49 socket's line"
        );
    }

    #[test]
    fn parse_proc_net_udp_returns_none_for_absent_port() {
        assert!(parse_proc_net_udp(FIXTURE_PROC_NET_UDP, "00000000:FFFF").is_none());
    }

    /// Integration: bind a real UDP socket, flood it without ever reading,
    /// and assert `SocketDropStats::poll` observes a non-zero drop delta.
    /// This is the test that proves the metric measures what its name
    /// claims, not just that the parser works on a fixture.
    ///
    /// A `DebuggingRecorder` installed as the thread-local default lets this
    /// assert on the exact metric emitted, mirroring
    /// `received_counters_fire_with_a_non_default_handler` in
    /// `src/zeek/listener.rs`.
    #[tokio::test]
    async fn socket_drop_stats_observes_real_kernel_drops() {
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        // A tiny SO_RCVBUF makes the kernel start dropping after only a few
        // datagrams, without needing tens of thousands of sends.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket2::SockRef::from(&socket)
            .set_recv_buffer_size(4096)
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let mut stats = SocketDropStats::new(&socket, "test_proto");
        // Establish the zero baseline before any traffic, exactly as the
        // real listeners do (their first tick lands well within a second of
        // bind, before meaningful traffic). Without this, the flood below
        // would land entirely inside the *first* reading and get reported
        // as a 0 delta by design (see `poll`'s `None => 0` baseline case).
        stats.poll().await;

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Flood without ever reading `socket` so the kernel queue fills and
        // starts discarding. 5000 x ~1200-byte datagrams into a 4 KiB (doubled
        // to ~8-9 KiB by the kernel) buffer comfortably overflows it.
        let payload = vec![0u8; 1200];
        for _ in 0..5000 {
            let _ = sender.send_to(&payload, addr).await;
        }
        // Loopback delivery into the receive queue happens via a softirq,
        // not synchronously inside `send_to`; give it a moment to catch up
        // before reading `/proc/net/udp`, same as the real listeners would
        // naturally see given a 1s poll interval.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        stats.poll().await;

        let map = snapshotter.snapshot().into_hashmap();
        let drops = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("test_proto_socket_drops"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);

        assert!(
            drops > 0,
            "expected test_proto_socket_drops > 0 after flooding an unread socket"
        );
    }
}
