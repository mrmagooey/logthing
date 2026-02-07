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