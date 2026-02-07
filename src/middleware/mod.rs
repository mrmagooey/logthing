use axum::{
    extract::{ConnectInfo, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use std::net::SocketAddr;
use tracing::{debug, warn};

#[derive(Clone)]
pub struct IpWhitelist {
    allowed_networks: Vec<IpNet>,
}

impl IpWhitelist {
    pub fn new(allowed_ips: Vec<String>) -> anyhow::Result<Self> {
        let mut networks = Vec::new();

        for ip_str in allowed_ips {
            match ip_str.parse::<IpNet>() {
                Ok(network) => networks.push(network),
                Err(_) => {
                    // Try parsing as single IP and convert to /32 or /128
                    if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                        let net = IpNet::from(ip);
                        networks.push(net);
                    } else {
                        return Err(anyhow::anyhow!("Invalid IP or CIDR: {}", ip_str));
                    }
                }
            }
        }

        Ok(Self {
            allowed_networks: networks,
        })
    }

    pub fn empty() -> Self {
        Self {
            allowed_networks: Vec::new(),
        }
    }

    pub fn is_allowed(&self, addr: &SocketAddr) -> bool {
        // If no whitelist configured, allow all
        if self.allowed_networks.is_empty() {
            return true;
        }

        let ip = addr.ip();
        self.allowed_networks.iter().any(|net| net.contains(&ip))
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
