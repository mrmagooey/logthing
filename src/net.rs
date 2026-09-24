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

/// Bind a UDP socket at `addr` with `SO_REUSEPORT` set, so multiple sockets
/// can share the same `addr`. The kernel fans datagrams out across the
/// group by a hash of the packet's 4-tuple, so a given sender lands on the
/// same socket for the life of the group. Same `SO_RCVBUF` handling as
/// `bind_udp_with_recv_buffer`.
pub async fn bind_udp_reuseport_with_recv_buffer(
    addr: &SocketAddr,
    requested: Option<usize>,
    protocol: &str,
) -> std::io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&(*addr).into())?;
    if let Some(requested) = requested.filter(|n| *n > 0) {
        if let Err(e) = sock.set_recv_buffer_size(requested) {
            warn!("{protocol}: failed to set SO_RCVBUF to {requested} bytes: {e}");
        } else {
            match sock.recv_buffer_size() {
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
    UdpSocket::from_std(sock.into())
}

use std::io;
use std::os::fd::AsRawFd;

/// Fixed-capacity storage for one `recvmmsg(2)` call, built once per recv
/// task and reused for its lifetime. Allocating `mmsghdr`/`iovec`/buffer/
/// address storage per call would trade one syscall for `batch_size` heap
/// allocations -- exactly the cost batching exists to avoid. Not auto-`Send`
/// (see the field comment on `iovecs`/`msgs` below and the `unsafe impl
/// Send` just after this struct) -- each recv task owns one and never
/// shares it.
pub struct RecvMmsgBatch {
    batch_size: usize,
    bufs: Vec<Vec<u8>>,
    addrs: Vec<libc::sockaddr_storage>,
    // SAFETY invariant: `iovecs[i].iov_base` points into `bufs[i]`'s own
    // heap buffer and `msgs[i].msg_hdr.msg_name` points at `addrs[i]`.
    // Neither `bufs`, `addrs`, `iovecs` nor `msgs` is ever resized after
    // `new()` returns, so these raw pointers stay valid for the struct's
    // whole lifetime regardless of how the struct itself is moved (moving a
    // `Vec` moves its 3-word header, never its heap-allocated contents).
    //
    // This is also the invariant the `unsafe impl Send` just below depends
    // on -- if a future change ever resizes any of these four fields after
    // construction, or introduces a field that borrows from outside the
    // struct (rather than from `bufs`/`addrs` it owns), that impl becomes
    // unsound and must be revisited together with this comment.
    // Never read from Rust -- `msgs[i]` holds the raw pointer into this
    // storage that the kernel actually reads/writes via `recvmmsg`. The
    // field's only job is to keep that allocation alive for the struct's
    // lifetime; deleting it (or letting it drop early) turns every `msgs`
    // pointer into a dangling one -- a use-after-free the next time
    // `recvmmsg` writes through it. Do not remove.
    #[allow(dead_code)]
    iovecs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
}

// SAFETY: `RecvMmsgBatch` is not auto-`Send` because `iovecs`/`msgs` hold
// raw pointers (`*mut c_void`/`*mut iovec`). Those pointers reference only
// this struct's own `bufs`/`addrs` heap allocations -- never another
// instance's, and never anything external -- and per the field-invariant
// comment above, neither `bufs`, `addrs`, `iovecs` nor `msgs` is ever
// resized after `new()` returns. Moving the whole struct (its four `Vec`
// headers, 3 words apiece) therefore leaves every pointed-to heap byte in
// place and every raw pointer still valid, a thread boundary included.
// Every construction site holds a single owned local, never wrapped in
// `Arc` or cloned; `recv()` takes `&mut self` and `src()`/`payload()` are
// only ever called sequentially by the task that owns it -- so this is
// *exclusive-ownership* Send, not concurrent access, and no `Sync` impl
// exists or is needed. Required because `RecvMmsgBatch::recv()` is
// `.await`ed while the struct is held live inside two `tokio::spawn`-ed
// futures in `src/ipfix/listener.rs` (`start_with_shutdown`'s inline
// `recv_batch_size > 1` arm and `ipfix_recv_loop`'s) -- without this,
// the compiler infers `!Send` for both and they fail to compile with
// "future cannot be sent between threads safely".
unsafe impl Send for RecvMmsgBatch {}

impl RecvMmsgBatch {
    /// `batch_size` message slots, each with a `65535`-byte buffer -- the
    /// same per-datagram size every existing single-recv loop already
    /// allocates (`vec![0u8; 65535]`), so switching a task from
    /// single-datagram to batched recv does not change per-message memory.
    pub fn new(batch_size: usize) -> Self {
        assert!(batch_size >= 1, "batch_size must be at least 1");
        let mut bufs: Vec<Vec<u8>> = (0..batch_size).map(|_| vec![0u8; 65535]).collect();
        let addrs: Vec<libc::sockaddr_storage> = (0..batch_size)
            .map(|_| unsafe { std::mem::zeroed() })
            .collect();
        let mut iovecs: Vec<libc::iovec> = bufs
            .iter_mut()
            .map(|b| libc::iovec {
                iov_base: b.as_mut_ptr() as *mut libc::c_void,
                iov_len: b.len(),
            })
            .collect();
        // `msghdr` is zeroed and then filled field-by-field rather than built
        // with a struct literal: musl's `msghdr` carries private padding
        // fields around `msg_iovlen`/`msg_controllen`, so a literal is a hard
        // compile error there ("cannot construct `msghdr` with struct literal
        // syntax due to private fields") even though it compiles on glibc.
        // The widths of those two fields also differ between the two libcs
        // (`size_t` vs `c_int`/`socklen_t`), so the assignments below are left
        // to integer inference instead of naming a type. Zeroing first is what
        // the padding wants anyway.
        let msgs: Vec<libc::mmsghdr> = iovecs
            .iter_mut()
            .zip(addrs.iter())
            .map(|(iov, addr)| {
                let mut msg_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
                msg_hdr.msg_name = addr as *const libc::sockaddr_storage as *mut libc::c_void;
                msg_hdr.msg_namelen =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                msg_hdr.msg_iov = iov as *mut libc::iovec;
                msg_hdr.msg_iovlen = 1;
                msg_hdr.msg_control = std::ptr::null_mut();
                msg_hdr.msg_controllen = 0;
                msg_hdr.msg_flags = 0;
                libc::mmsghdr {
                    msg_hdr,
                    msg_len: 0,
                }
            })
            .collect();
        Self {
            batch_size,
            bufs,
            addrs,
            iovecs,
            msgs,
        }
    }

    /// Message `i`'s payload from the most recent successful `recv()` call.
    pub fn payload(&self, i: usize) -> &[u8] {
        &self.bufs[i][..self.msgs[i].msg_len as usize]
    }

    /// Message `i`'s source address from the most recent successful
    /// `recv()` call. Reuses `socket2::SockAddr::as_socket()` for the
    /// AF_INET/AF_INET6 parsing rather than hand-rolling it -- socket2 is
    /// already a dependency and this is exactly what it exists to do
    /// safely.
    pub fn src(&self, i: usize) -> Option<SocketAddr> {
        let mut storage = socket2::SockAddrStorage::zeroed();
        // SAFETY: `addrs[i]` was filled by the kernel during `recvmmsg` with
        // whatever address family it actually delivered; copying those
        // exact bytes into a freshly zeroed, correctly sized storage and
        // handing the kernel-reported length to `SockAddr::new` satisfies
        // its safety contract (family and length matching the storage's
        // content).
        unsafe {
            *storage.view_as::<libc::sockaddr_storage>() = self.addrs[i];
        }
        let len = self.msgs[i].msg_hdr.msg_namelen;
        unsafe { socket2::SockAddr::new(storage, len) }.as_socket()
    }

    /// One non-blocking `recvmmsg(2)` call, returning as many datagrams as
    /// are already queued on `socket`, up to `batch_size` -- WITHOUT
    /// waiting to fill the batch. `MSG_DONTWAIT` forces non-blocking
    /// behaviour on this call regardless of the socket's own `O_NONBLOCK`
    /// state.
    ///
    /// # Safety
    /// `fd` must be an open, valid UDP socket file descriptor, live for the
    /// duration of the call.
    unsafe fn recv_mmsg_once(&mut self, fd: std::os::fd::RawFd) -> io::Result<usize> {
        // Reset msg_namelen before every call: the kernel overwrites it per
        // message with the actual address length used, and a stale
        // shorter value left over from a previous call would truncate the
        // next message's address parse.
        for msg in &mut self.msgs {
            msg.msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        }
        // The zero-latency guarantee (a lone queued datagram returns
        // immediately, never waits to fill the batch) actually comes from
        // `fd` already being O_NONBLOCK -- every UdpSocket this crate binds
        // is (mio sets SOCK_NONBLOCK at creation; bind_udp_reuseport_with_
        // recv_buffer also calls set_nonblocking(true) explicitly; tokio's
        // own check_socket_for_blocking refuses a blocking socket outright).
        // MSG_DONTWAIT is still correct to pass -- it's an independent,
        // correct belt-and-braces guarantee if this fn is ever reached with
        // a blocking fd -- but do not remove it as "redundant" with
        // O_NONBLOCK, and do not add a `timeout` here believing it bounds
        // the wait: measured against the real syscall, flags=0 with a
        // populated timespec either returns instantly (O_NONBLOCK fd, same
        // as now) or hangs forever (blocking fd, per recvmmsg(2)'s own BUGS
        // section) -- there is no bounded-wait behaviour to rely on either
        // way.
        // `MSG_DONTWAIT as _`, not a plain `MSG_DONTWAIT`: `recvmmsg`'s
        // `flags` parameter is `c_int` on glibc but `c_uint` on musl, while
        // `MSG_DONTWAIT` is `c_int` everywhere. Naming either type concretely
        // compiles on one libc and breaks the other -- the musl release
        // binaries built by `.github/workflows/binaries.yml` failed exactly
        // this way while the gnu test suite stayed green. Inference picks the
        // right width per target; both are the same ABI.
        let n = unsafe {
            libc::recvmmsg(
                fd,
                self.msgs.as_mut_ptr(),
                self.batch_size as libc::c_uint,
                libc::MSG_DONTWAIT as _,
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // ponytail: msg_hdr.msg_flags is not inspected for MSG_TRUNC here.
        // Deliberate, not an oversight -- it's the same blind spot the
        // existing single-datagram `recv_from` path already has (it trusts
        // the returned length too), and every buffer here is 65535 bytes,
        // the maximum possible UDP payload, so a real truncation is not
        // reachable over UDP regardless. Revisit only if a buffer size
        // smaller than 65535 is ever introduced.
        Ok(n as usize)
    }

    /// Await readiness, then attempt one batched read -- the same
    /// `try_io` pattern `tokio::net::UdpSocket::try_io`'s own docs
    /// recommend for raw syscalls on a tokio socket: a `WouldBlock` from
    /// the syscall clears the readiness flag and the loop awaits it again,
    /// rather than spinning. Returns the number of datagrams received,
    /// always `>= 1` on `Ok` -- UDP has no "0 means closed" case the way a
    /// stream socket does, so a `0` from the syscall is treated as
    /// "nothing arrived yet, try again" rather than surfaced to the caller.
    pub async fn recv(&mut self, socket: &tokio::net::UdpSocket) -> io::Result<usize> {
        loop {
            socket.readable().await?;
            let fd = socket.as_raw_fd();
            let result = socket.try_io(tokio::io::Interest::READABLE, || unsafe {
                self.recv_mmsg_once(fd)
            });
            match result {
                Ok(0) => continue,
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Socket-level drop counter / rx-queue gauge
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
    let (words, _remainder) = octets.as_chunks::<4>();
    words
        .iter()
        .map(|word| format!("{:08X}", u32::from_le_bytes(*word)))
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

/// Find every line in a `/proc/net/udp{,6}`-formatted file whose `local_address`
/// field exactly matches `needle`, and sum their `rx_queue`/`drops` columns.
///
/// Matching the full `local_address` (address *and* port), not just the port,
/// is deliberate: two sockets can share a port bound to different addresses,
/// and reading another socket's line would be a silent wrong answer.
///
/// Summing rather than taking the first match matters once a port has more
/// than one socket on it: today that's one socket per address:port for
/// every caller. But `SO_REUSEPORT` lets N sockets share one
/// `local_address:port`, each with its own kernel rx_queue/drops line and
/// distinct inode -- taking only the first would silently under-report
/// N-1 sockets' worth of drops.
fn parse_proc_net_udp(contents: &str, needle: &str) -> Option<ProcNetUdpEntry> {
    let mut total = ProcNetUdpEntry {
        rx_queue: 0,
        drops: 0,
    };
    let mut matched = false;
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // sl local_address rem_address st tx_queue:rx_queue tr tm->when
        // retrnsmt uid timeout inode ref pointer drops -- 13 fields, drops last.
        if fields.len() < 13 {
            continue;
        }
        if !fields[1].eq_ignore_ascii_case(needle) {
            continue;
        }
        let Some(rx_hex) = fields[4].split_once(':').map(|(_, h)| h) else {
            continue;
        };
        let Ok(rx_queue) = u64::from_str_radix(rx_hex, 16) else {
            continue;
        };
        let Some(drops) = fields.last().and_then(|s| s.parse::<u64>().ok()) else {
            continue;
        };
        total.rx_queue += rx_queue;
        total.drops += drops;
        matched = true;
    }
    matched.then_some(total)
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

// ---------------------------------------------------------------------------
// TCP accept backoff
// ---------------------------------------------------------------------------
//
// Errors like EMFILE leave a `TcpListener` readable, so a naive
// `loop { listener.accept().await }` re-polls the same error immediately: a
// 100% CPU spin with a log line per iteration. A plain `sleep` in the `Err`
// arm would fix the standalone-loop sites, but four of the eight accept
// sites put the accept inside a `tokio::select!` alongside other arms
// (syslog's UDP receive, the shutdown signal) -- sleeping there would block
// those other arms too. Instead the pause lives inside `AcceptBackoff`'s own
// `accept` future, which `select!` is free to drop and re-poll without
// losing the pause (see the cancel-safety doc comment below).

/// Pause before the next `accept` after a non-per-connection accept error.
pub const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_secs(1);

/// `TcpListener::accept` wrapper that stops a listener spinning on a
/// persistent accept error.
///
/// Errors like EMFILE leave the listener readable, so re-polling `accept()`
/// returns the same error at once: a 100% CPU loop with a log line per spin.
/// After such an error the next `accept` first waits out
/// [`ACCEPT_ERROR_BACKOFF`]. Per-connection errors (refused/aborted/reset)
/// don't pause, matching `axum::serve`.
///
/// Cancel-safe: the pause is cleared only after its sleep completes, so a
/// `select!` that drops this future mid-pause resumes the same pause on the
/// next call, while the other arms (UDP receive, shutdown) stay live.
#[derive(Debug)]
pub struct AcceptBackoff {
    protocol: &'static str,
    paused_until: Option<tokio::time::Instant>,
}

impl AcceptBackoff {
    /// `protocol` labels `listener_accept_errors`; use the same value as the
    /// site's `listener_source_rejected` label.
    pub fn new(protocol: &'static str) -> Self {
        Self {
            protocol,
            paused_until: None,
        }
    }

    /// Accept one connection, honouring any pending pause first.
    pub async fn accept(
        &mut self,
        listener: &tokio::net::TcpListener,
    ) -> io::Result<(tokio::net::TcpStream, SocketAddr)> {
        if let Some(until) = self.paused_until {
            tokio::time::sleep_until(until).await;
            self.paused_until = None;
        }
        let result = listener.accept().await;
        if let Err(e) = &result {
            metrics::counter!("listener_accept_errors", "protocol" => self.protocol).increment(1);
            if !is_connection_error(e) {
                self.paused_until = Some(tokio::time::Instant::now() + ACCEPT_ERROR_BACKOFF);
            }
        }
        result
    }
}

/// Per-connection errors (a peer that reset/aborted/refused before or during
/// the handshake) don't indicate a stuck listener and get no pause -- same
/// policy as `axum::serve`/hyper. Anything else (EMFILE, ENFILE, ...) does.
fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_connection_error_matches_per_connection_kinds_only() {
        use std::io::{Error, ErrorKind};
        for k in [
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
        ] {
            assert!(is_connection_error(&Error::from(k)));
        }
        assert!(!is_connection_error(&Error::from_raw_os_error(
            libc::EMFILE
        )));
        assert!(!is_connection_error(&Error::from_raw_os_error(
            libc::ENFILE
        )));
    }

    #[tokio::test(start_paused = true)]
    async fn accept_backoff_pause_survives_cancellation() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut b = AcceptBackoff::new("test");
        b.paused_until = Some(tokio::time::Instant::now() + ACCEPT_ERROR_BACKOFF);
        // Cancelled mid-pause (as a select! would): pause must persist.
        let r = tokio::time::timeout(Duration::from_millis(500), b.accept(&l)).await;
        assert!(r.is_err(), "accept must still be paused");
        assert!(
            b.paused_until.is_some(),
            "a dropped future must not clear the pause"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn accept_backoff_pause_does_not_block_other_select_arms() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut b = AcceptBackoff::new("test");
        b.paused_until = Some(tokio::time::Instant::now() + ACCEPT_ERROR_BACKOFF);
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        tx.send(true).unwrap();
        let start = tokio::time::Instant::now();
        tokio::select! {
            _ = b.accept(&l) => panic!("accept must not win while paused"),
            _ = rx.changed() => {}
        }
        assert!(start.elapsed() < Duration::from_millis(100));
    }

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

    /// Two sockets must be able to share one address:port under SO_REUSEPORT —
    /// without it the second bind fails with EADDRINUSE. Port 0 lets the kernel
    /// pick, then the second binds explicitly to whatever it chose.
    #[tokio::test]
    async fn reuseport_allows_two_sockets_on_one_port() {
        let first = bind_udp_reuseport_with_recv_buffer(
            &"127.0.0.1:0".parse().unwrap(),
            None,
            "test_proto",
        )
        .await
        .expect("first reuseport bind");
        let addr = first.local_addr().expect("local addr");

        let second = bind_udp_reuseport_with_recv_buffer(&addr, None, "test_proto")
            .await
            .expect("second bind on the same port must succeed under SO_REUSEPORT");

        assert_eq!(first.local_addr().unwrap(), second.local_addr().unwrap());
    }

    /// A plain bind must still refuse to share a port — proving the test above
    /// demonstrates SO_REUSEPORT rather than some ambient permissiveness.
    #[tokio::test]
    async fn plain_bind_still_refuses_a_shared_port() {
        let first = bind_udp_with_recv_buffer(&"127.0.0.1:0".parse().unwrap(), None, "test_proto")
            .await
            .expect("first plain bind");
        let addr = first.local_addr().expect("local addr");

        assert!(
            bind_udp_with_recv_buffer(&addr, None, "test_proto")
                .await
                .is_err(),
            "a second plain bind on the same port must fail"
        );
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

    /// Two sockets on the same address:port -- the shape SO_REUSEPORT produces.
    /// Differing inodes, same local_address. Both lines must be counted.
    const FIXTURE_PROC_NET_UDP_REUSEPORT: &str = "\
  sl  local_address rem_address   st tx_queue:rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:1F49 00000000:0000 07 00000000:00000100 00:00000000 00000000     0        0 12345 2 0000000000000000 11
  101: 00000000:1F49 00000000:0000 07 00000000:00000200 00:00000000 00000000     0        0 12346 2 0000000000000000 31
";

    #[test]
    fn parse_proc_net_udp_sums_all_matching_lines() {
        let entry = parse_proc_net_udp(FIXTURE_PROC_NET_UDP_REUSEPORT, "00000000:1F49")
            .expect("both reuseport lines must parse");
        assert_eq!(
            entry.drops, 42,
            "drops must be summed across both sockets, not taken from the first"
        );
        assert_eq!(entry.rx_queue, 0x300, "rx_queue must be summed too");
    }

    /// The single-socket case -- every deployment today -- must be untouched by
    /// the summing change.
    #[test]
    fn parse_proc_net_udp_single_match_unaffected_by_summing() {
        let entry = parse_proc_net_udp(FIXTURE_PROC_NET_UDP, "00000000:1F49")
            .expect("port 0x1F49 line must parse");
        assert_eq!(entry.rx_queue, 0x100);
    }

    #[test]
    fn parse_proc_net_udp_returns_none_when_no_line_matches() {
        assert!(parse_proc_net_udp(FIXTURE_PROC_NET_UDP_REUSEPORT, "00000000:DEAD").is_none());
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
    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
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

    /// The core batching property: N datagrams sent to one socket from N
    /// different client sockets, all queued before `recv()` is called, must
    /// come back in ONE `recv()` call -- proving the syscall is actually
    /// batching, not silently falling back to one-at-a-time.
    #[tokio::test]
    async fn recv_returns_multiple_queued_datagrams_in_one_call() {
        let listen_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = listen_sock.local_addr().unwrap();

        let n = 10;
        let mut expected_payloads = Vec::new();
        for i in 0..n {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let payload = format!("msg-{i}").into_bytes();
            client.send_to(&payload, addr).await.unwrap();
            expected_payloads.push(payload);
        }
        // Give the kernel a moment to queue all n sends before the batched
        // recv is attempted -- this test is about batching behaviour, not
        // about racing delivery.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut batch = RecvMmsgBatch::new(32);
        let received = batch.recv(&listen_sock).await.unwrap();

        assert_eq!(
            received, n,
            "all {n} already-queued datagrams must come back in one call"
        );
        let mut got_payloads: Vec<Vec<u8>> =
            (0..received).map(|i| batch.payload(i).to_vec()).collect();
        got_payloads.sort();
        let mut want_payloads = expected_payloads;
        want_payloads.sort();
        assert_eq!(
            got_payloads, want_payloads,
            "every payload must be received intact"
        );

        let mut srcs: Vec<SocketAddr> = (0..received).map(|i| batch.src(i).unwrap()).collect();
        srcs.sort();
        srcs.dedup();
        assert_eq!(
            srcs.len(),
            n,
            "each message's source address must be distinct and correctly parsed"
        );
    }

    /// A lone datagram must come back immediately -- `recv()` must NOT wait to
    /// fill the batch. This is the latency property a log-ingest server cannot
    /// regress on: a single low-rate syslog line delayed to fill a batch would
    /// be worse than the single-datagram path it replaces.
    #[tokio::test]
    async fn recv_returns_a_single_datagram_without_waiting_to_fill_the_batch() {
        let listen_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = listen_sock.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"lonely datagram", addr).await.unwrap();

        let mut batch = RecvMmsgBatch::new(32);
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(30),
            batch.recv(&listen_sock),
        )
        .await;

        let received = result
            .expect("recv() must return well within 30ms for one already-queued datagram, not wait to fill a 32-message batch")
            .unwrap();
        assert_eq!(received, 1);
        assert_eq!(batch.payload(0), b"lonely datagram");
    }
}
