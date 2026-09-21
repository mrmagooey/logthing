use axum::{
    extract::{ConnectInfo, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tracing::{debug, warn};

/// IP allowlist consulted by the main HTTP router's middleware AND by every
/// wire-protocol listener (syslog, ipfix, zeek, suricata, sflow) — each
/// holds its own `Clone` of the SAME underlying `Arc<RwLock<Vec<IpNet>>>`,
/// built once from `security.allowed_ips` at startup. Changing
/// `security.allowed_ips` requires a restart to take effect.
///
/// Uses a `std::sync::RwLock` (not `tokio::sync::RwLock`): `is_allowed` is a
/// synchronous, non-blocking, in-memory check called on a hot path (once per
/// HTTP request and once per UDP datagram across five listeners), so it must
/// stay a plain function, not an `async fn` requiring an `.await` at every
/// call site.
#[derive(Clone)]
pub struct IpWhitelist {
    allowed_networks: Arc<RwLock<Vec<IpNet>>>,
}

/// Parse a list of IP-address-or-CIDR strings into `IpNet`s.
///
/// Shared by `IpWhitelist::new` and by admin config validation
/// (`validate_config_invariants`), so a bad `allowed_ips` entry is rejected
/// identically wherever it's parsed.
pub fn parse_allowed_ips(allowed_ips: &[String]) -> anyhow::Result<Vec<IpNet>> {
    let mut networks = Vec::new();

    for ip_str in allowed_ips {
        match ip_str.parse::<IpNet>() {
            Ok(network) => networks.push(network),
            Err(_) => {
                // Try parsing as single IP and convert to /32 or /128
                if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                    networks.push(IpNet::from(ip));
                } else {
                    return Err(anyhow::anyhow!("Invalid IP or CIDR: {}", ip_str));
                }
            }
        }
    }

    Ok(networks)
}

impl IpWhitelist {
    /// Create a new IP whitelist from a list of IP addresses or CIDR ranges.
    ///
    /// Supports both single IP addresses (e.g., "192.168.1.1") and CIDR notation
    /// (e.g., "10.0.0.0/24").
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use logthing::middleware::IpWhitelist;
    ///
    /// // Whitelist with CIDR range and single IP
    /// let allowed = vec![
    ///     "10.0.0.0/24".to_string(),
    ///     "192.168.1.100".to_string(),
    /// ];
    /// let whitelist = IpWhitelist::new(allowed).unwrap();
    ///
    /// // Test if an address is allowed
    /// let addr: std::net::SocketAddr = "10.0.0.50:8080".parse().unwrap();
    /// assert!(whitelist.is_allowed(&addr));
    /// ```
    pub fn new(allowed_ips: Vec<String>) -> anyhow::Result<Self> {
        let networks = parse_allowed_ips(&allowed_ips)?;
        Ok(Self {
            allowed_networks: Arc::new(RwLock::new(networks)),
        })
    }

    /// Create an empty whitelist that allows all connections.
    pub fn empty() -> Self {
        Self {
            allowed_networks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Check if the given socket address is allowed.
    ///
    /// Returns true if the address is in the whitelist, or if the whitelist is empty.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use logthing::middleware::IpWhitelist;
    /// use std::net::SocketAddr;
    ///
    /// let whitelist = IpWhitelist::new(vec!["127.0.0.1".to_string()]).unwrap();
    ///
    /// let allowed_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    /// let blocked_addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
    ///
    /// assert!(whitelist.is_allowed(&allowed_addr));
    /// assert!(!whitelist.is_allowed(&blocked_addr));
    /// ```
    pub fn is_allowed(&self, addr: &SocketAddr) -> bool {
        let networks = self.allowed_networks.read().unwrap();
        // If no whitelist configured, allow all
        if networks.is_empty() {
            return true;
        }

        let ip = addr.ip();
        networks.iter().any(|net| net.contains(&ip))
    }
}

pub async fn ip_whitelist_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    whitelist: axum::Extension<IpWhitelist>,
    request: Request,
    next: Next,
) -> Response {
    if whitelist.is_allowed(&addr) {
        debug!("Connection allowed from {}", addr);
        next.run(request).await
    } else {
        warn!("Connection rejected from {} - not in whitelist", addr);
        (axum::http::StatusCode::FORBIDDEN, "Forbidden").into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_whitelist_from_ips_and_cidrs() {
        let whitelist = IpWhitelist::new(vec!["10.0.0.0/24".into(), "192.168.1.10".into()])
            .expect("valid whitelist");

        let addr_in_range: SocketAddr = "10.0.0.5:8080".parse().unwrap();
        let addr_ip: SocketAddr = "192.168.1.10:1234".parse().unwrap();
        let addr_outside: SocketAddr = "203.0.113.1:9999".parse().unwrap();

        assert!(whitelist.is_allowed(&addr_in_range));
        assert!(whitelist.is_allowed(&addr_ip));
        assert!(!whitelist.is_allowed(&addr_outside));
    }

    #[test]
    fn empty_whitelist_allows_all() {
        let whitelist = IpWhitelist::empty();
        let addr: SocketAddr = "192.0.2.1:80".parse().unwrap();
        assert!(whitelist.is_allowed(&addr));
    }
}
