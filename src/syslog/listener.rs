//! Syslog listener for receiving syslog messages via UDP and TCP

use crate::syslog::{SyslogMessage, dns::DnsLogEntry};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, error, info, warn};
use std::sync::Arc;

/// Configuration for syslog listener
#[derive(Debug, Clone)]
pub struct SyslogListenerConfig {
    pub udp_port: u16,
    pub tcp_port: u16,
    pub bind_address: String,
    pub parse_dns_logs: bool,
}

impl Default for SyslogListenerConfig {
    fn default() -> Self {
        Self {
            udp_port: 514,
            tcp_port: 601,
            bind_address: "0.0.0.0".to_string(),
            parse_dns_logs: true,
        }
    }
}

/// Syslog message handler trait
#[async_trait::async_trait]
pub trait SyslogHandler: Send + Sync {
    async fn handle_message(&self, message: SyslogMessage, source: SocketAddr);
}

/// Default handler that logs messages
pub struct DefaultSyslogHandler {
    parse_dns_logs: bool,
}

impl DefaultSyslogHandler {
    pub fn new(parse_dns_logs: bool) -> Self {
        Self { parse_dns_logs }
    }
}

#[async_trait::async_trait]
impl SyslogHandler for DefaultSyslogHandler {
    async fn handle_message(&self, message: SyslogMessage, source: SocketAddr) {
        info!(
            "[{}] {} {} - {}: {}",
            source,
            message.facility_str(),
            message.severity_str(),
            message.app_name.as_deref().unwrap_or("unknown"),
            message.message
        );
        
        if self.parse_dns_logs {
            if let Some(dns_entry) = DnsLogEntry::from_syslog(&message) {
                info!(
                    "DNS Query: {} asked for {} ({}) -> {:?}",
                    dns_entry.client_ip,
                    dns_entry.query_name,
                    dns_entry.query_type,
                    dns_entry.response_ips
                );
            }
        }
    }
}

/// Syslog listener that can receive messages via UDP and TCP
pub struct SyslogListener {
    config: SyslogListenerConfig,
    handler: Arc<dyn SyslogHandler>,
}

impl SyslogListener {
    pub fn new(config: SyslogListenerConfig, handler: Arc<dyn SyslogHandler>) -> Self {
        Self { config, handler }
    }
    
    pub fn with_default_handler(config: SyslogListenerConfig) -> Self {
        let parse_dns_logs = config.parse_dns_logs;
        Self::new(config, Arc::new(DefaultSyslogHandler::new(parse_dns_logs)))
    }
    
    /// Start both UDP and TCP listeners
    pub async fn start(&self) -> anyhow::Result<()> {
        let udp_listener = self.start_udp_listener();
        let tcp_listener = self.start_tcp_listener();
        
        tokio::select! {
            result = udp_listener => {
                if let Err(e) = result {
                    error!("UDP listener error: {}", e);
                }
            }
            result = tcp_listener => {
                if let Err(e) = result {
                    error!("TCP listener error: {}", e);
                }
            }
        }
        
        Ok(())
    }
    
    /// Start UDP syslog listener
    async fn start_udp_listener(&self) -> anyhow::Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.config.bind_address, self.config.udp_port)
            .parse()?;
        
        let socket = UdpSocket::bind(&addr).await?;
        info!("Syslog UDP listener started on {}", addr);
        
        let mut buf = vec![0u8; 65535];
        
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let msg = String::from_utf8_lossy(&buf[..len]);
                    debug!("Received UDP syslog message from {}: {} bytes", src, len);
                    
                    if let Some(syslog_msg) = SyslogMessage::parse(&msg) {
                        self.handler.handle_message(syslog_msg, src).await;
                    } else {
                        warn!("Failed to parse syslog message from {}: {}", src, &msg[..100.min(msg.len())]);
                    }
                }
                Err(e) => {
                    error!("UDP receive error: {}", e);
                }
            }
        }
    }
    
    /// Start TCP syslog listener (RFC 6587 octet counting or newline framing)
    async fn start_tcp_listener(&self) -> anyhow::Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.config.bind_address, self.config.tcp_port)
            .parse()?;
        
        let listener = TcpListener::bind(&addr).await?;
        info!("Syslog TCP listener started on {}", addr);
        
        loop {
            match listener.accept().await {
                Ok((stream, src)) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_tcp_connection(stream, src, handler).await {
                            error!("TCP connection error from {}: {}", src, e);
                        }
                    });
                }
                Err(e) => {
                    error!("TCP accept error: {}", e);
                }
            }
        }
    }
    
    /// Handle a TCP connection for syslog
    async fn handle_tcp_connection(
        stream: TcpStream,
        src: SocketAddr,
        handler: Arc<dyn SyslogHandler>,
    ) -> anyhow::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // Connection closed
                    debug!("TCP connection from {} closed", src);
                    break;
                }
                Ok(_) => {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        debug!("Received TCP syslog message from {}: {} bytes", src, trimmed.len());
                        
                        if let Some(syslog_msg) = SyslogMessage::parse(trimmed) {
                            handler.handle_message(syslog_msg, src).await;
                        } else {
                            warn!("Failed to parse TCP syslog message from {}: {}", src, &trimmed[..100.min(trimmed.len())]);
                        }
                    }
                }
                Err(e) => {
                    error!("TCP read error from {}: {}", src, e);
                    break;
                }
            }
        }
        
        Ok(())
    }
}

/// Example DNS syslog records for testing
pub mod examples {
    /// BIND/named DNS query log examples
    pub const BIND_DNS_QUERIES: &[&str] = &[
        // Standard A record query
        "<134>Jan 15 10:30:45 dns-server named[1234]: client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)",
        
        // AAAA record query
        "<134>Jan 15 10:30:46 dns-server named[1234]: client 192.168.1.100#12346: query: example.com IN AAAA + (2606:2800:220:1:248:1893:25c8:1946)",
        
        // MX record query
        "<134>Jan 15 10:30:47 dns-server named[1234]: client 192.168.1.101#12347: query: gmail.com IN MX + (172.217.0.5)",
        
        // NXDOMAIN response
        "<134>Jan 15 10:30:48 dns-server named[1234]: client 192.168.1.102#12348: query: nonexistent.example.com IN A - (NXDOMAIN)",
        
        // CNAME chain
        "<134>Jan 15 10:30:49 dns-server named[1234]: client 192.168.1.103#12349: query: www.example.com IN CNAME + (example.com)",
        
        // TXT record (SPF)
        "<134>Jan 15 10:30:50 dns-server named[1234]: client 192.168.1.104#12350: query: example.com IN TXT + (\"v=spf1 include:_spf.google.com ~all\")",
        
        // PTR record (reverse DNS)
        "<134>Jan 15 10:30:51 dns-server named[1234]: client 192.168.1.105#12351: query: 34.216.184.93.in-addr.arpa IN PTR + (example.com)",
        
        // NS record query
        "<134>Jan 15 10:30:52 dns-server named[1234]: client 192.168.1.106#12352: query: example.com IN NS + (a.iana-servers.net)",
        
        // SOA record query
        "<134>Jan 15 10:30:53 dns-server named[1234]: client 192.168.1.107#12353: query: example.com IN SOA + (ns.icann.org)",
        
        // DNSSEC related
        "<134>Jan 15 10:30:54 dns-server named[1234]: client 192.168.1.108#12354: query: example.com IN DNSKEY + (256 3 8 ...)",
    ];
    
    /// Unbound DNS query log examples
    pub const UNBOUND_DNS_QUERIES: &[&str] = &[
        "<134>Jan 15 10:31:00 dns-server unbound[5678]: info: 192.168.1.100 example.com. A IN",
        "<134>Jan 15 10:31:01 dns-server unbound[5678]: info: 192.168.1.101 google.com. AAAA IN",
        "<134>Jan 15 10:31:02 dns-server unbound[5678]: info: 192.168.1.102 github.com. A IN",
    ];
    
    /// PowerDNS query log examples
    pub const POWERDNS_QUERIES: &[&str] = &[
        "<134>Jan 15 10:32:00 dns-server pdns[9012]: Remote 192.168.1.100 wants 'example.com|A', do = 0, bufsize = 512",
        "<134>Jan 15 10:32:01 dns-server pdns[9012]: Remote 192.168.1.101 wants 'google.com|AAAA', do = 1, bufsize = 1232",
        "<134>Jan 15 10:32:02 dns-server pdns[9012]: Remote 192.168.1.102 wants 'api.github.com|A', do = 0, bufsize = 512",
    ];
    
    /// RFC 5424 formatted syslog with structured data
    pub const RFC5424_DNS_LOGS: &[&str] = &[
        r#"<165>1 2024-01-15T10:33:45.000Z dns-server named 1234 - [dns@12345 query="example.com" type="A" client="192.168.1.100" response="93.184.216.34"] DNS query processed"#,
        r#"<165>1 2024-01-15T10:33:46.000Z dns-server named 1234 - [dns@12345 query="google.com" type="AAAA" client="192.168.1.101" response="2607:f8b0:4004:c06::8a"] DNS query processed"#,
    ];
    
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_udp_listener() {
        let config = SyslogListenerConfig {
            udp_port: 1514, // Use non-privileged port for testing
            tcp_port: 1601,
            ..Default::default()
        };
        
        let listener = SyslogListener::with_default_handler(config);
        
        // Start listener in background
        let listener_handle = tokio::spawn(async move {
            listener.start().await.ok();
        });
        
        // Give listener time to start
        sleep(Duration::from_millis(100)).await;
        
        // Send test message
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let test_msg = examples::BIND_DNS_QUERIES[0];
        socket.send_to(test_msg.as_bytes(), "127.0.0.1:1514").await.unwrap();
        
        // Give time to process
        sleep(Duration::from_millis(100)).await;
        
        listener_handle.abort();
    }
}
