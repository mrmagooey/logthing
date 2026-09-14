//! Shared UDP socket setup for the ipfix, sflow and syslog listeners.

use std::net::SocketAddr;
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
}
