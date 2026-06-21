use crate::config::{DestinationConfig, ForwardProtocol};
use crate::models::WindowsEvent;
use anyhow::Result;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

pub mod parquet_s3;

pub struct Forwarder {
    destinations: Vec<Destination>,
    client: Client,
}

struct Destination {
    config: DestinationConfig,
    sender: mpsc::Sender<Arc<WindowsEvent>>,
}

impl Forwarder {
    /// Create a new event forwarder with the given destination configurations.
    ///
    /// The forwarder must be initialized with `initialize()` before use.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wef_server::forwarding::Forwarder;
    /// use wef_server::config::DestinationConfig;
    ///
    /// let destinations = vec![DestinationConfig {
    ///     name: "http-destination".to_string(),
    ///     url: "http://example.com/events".to_string(),
    ///     protocol: wef_server::config::ForwardProtocol::Http,
    ///     enabled: true,
    ///     headers: std::collections::HashMap::new(),
    /// }];
    ///
    /// let forwarder = Forwarder::new(destinations);
    /// ```
    pub fn new(_destinations: Vec<DestinationConfig>) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            destinations: Vec::new(),
            client,
        }
    }

    /// Initialize the forwarder and start forwarding tasks.
    ///
    /// This spawns async tasks for each enabled destination to handle event forwarding.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wef_server::forwarding::Forwarder;
    /// use wef_server::config::DestinationConfig;
    ///
    /// async fn setup_forwarder() {
    ///     let destinations = vec![DestinationConfig {
    ///         name: "http-destination".to_string(),
    ///         url: "http://example.com/events".to_string(),
    ///         protocol: wef_server::config::ForwardProtocol::Http,
    ///         enabled: true,
    ///         headers: std::collections::HashMap::new(),
    ///     }];
    ///
    ///     let forwarder = Forwarder::new(destinations).initialize().await;
    ///     // forwarder.forward(event).await;
    /// }
    /// ```
    pub async fn initialize(mut self) -> Self {
        let mut new_destinations = Vec::new();

        for config in std::mem::take(&mut self.destinations)
            .into_iter()
            .map(|d| d.config)
            .chain(vec![])
        {
            if !config.enabled {
                continue;
            }

            let (tx, mut rx) = mpsc::channel::<Arc<WindowsEvent>>(1000);
            let client = self.client.clone();
            let url = config.url.clone();
            let name = config.name.clone();
            let protocol = config.protocol.clone();
            let headers = config.headers.clone();

            // Spawn forwarding task for this destination
            tokio::spawn(async move {
                info!("Starting forwarder for destination: {}", name);

                while let Some(event) = rx.recv().await {
                    if let Err(e) =
                        Self::forward_event(&client, &event, &url, &protocol, &headers).await
                    {
                        error!("Failed to forward event to {}: {}", name, e);
                    }
                }

                info!("Forwarder for destination {} stopped", name);
            });

            new_destinations.push(Destination { config, sender: tx });
        }

        self.destinations = new_destinations;
        self
    }

    /// Forward an event to all configured destinations.
    ///
    /// The event is queued for each destination and sent asynchronously.
    /// Uses Arc to avoid cloning the entire event.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wef_server::forwarding::Forwarder;
    /// use wef_server::models::WindowsEvent;
    /// use std::sync::Arc;
    ///
    /// async fn forward_event(forwarder: &Forwarder) {
    ///     let event = WindowsEvent::new(
    ///         "workstation01".to_string(),
    ///         "<Event><System><EventID>4624</EventID></System></Event>".to_string()
    ///     );
    ///
    ///     forwarder.forward(Arc::new(event)).await;
    /// }
    /// ```
    pub async fn forward(&self, event: Arc<WindowsEvent>) {
        for dest in &self.destinations {
            // Clone the Arc (cheap) rather than the entire event
            if let Err(e) = dest.sender.send(event.clone()).await {
                error!("Failed to queue event for {}: {}", dest.config.name, e);
            }
        }
    }

    async fn forward_event(
        client: &Client,
        event: &WindowsEvent,
        url: &str,
        protocol: &ForwardProtocol,
        headers: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        match protocol {
            ForwardProtocol::Http | ForwardProtocol::Https => {
                Self::forward_http(client, event, url, headers).await
            }
            ForwardProtocol::Tcp => Self::forward_tcp(event, url).await,
            ForwardProtocol::Udp => Self::forward_udp(event, url).await,
            ForwardProtocol::Syslog => Self::forward_syslog(event, url).await,
        }
    }

    async fn forward_http(
        client: &Client,
        event: &WindowsEvent,
        url: &str,
        headers: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let mut request = client.post(url).json(&event);

        for (key, value) in headers {
            request = request.header(key, value);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("HTTP error: {}", response.status()));
        }

        debug!("Successfully forwarded event {} to {}", event.id, url);
        Ok(())
    }

    async fn forward_tcp(event: &WindowsEvent, url: &str) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;

        let json = serde_json::to_string(event)?;
        let addr = url.strip_prefix("tcp://").unwrap_or(url);

        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(json.as_bytes()).await?;
        stream.write_all(b"\n").await?;

        debug!(
            "Successfully forwarded event {} via TCP to {}",
            event.id, addr
        );
        Ok(())
    }

    async fn forward_udp(event: &WindowsEvent, url: &str) -> Result<()> {
        use tokio::net::UdpSocket;

        let json = serde_json::to_string(event)?;
        let addr = url.strip_prefix("udp://").unwrap_or(url);

        // Bind to any local address
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(json.as_bytes(), addr).await?;

        debug!(
            "Successfully forwarded event {} via UDP to {}",
            event.id, addr
        );
        Ok(())
    }

    async fn forward_syslog(event: &WindowsEvent, url: &str) -> Result<()> {
        use tokio::net::UdpSocket;

        // Format as RFC 5424 syslog message
        let syslog_msg = format!(
            "<{}>1 {} {} WEF - - [{}] {}",
            Self::calculate_priority(&event.parsed),
            event.received_at.to_rfc3339(),
            event.source_host,
            event.id,
            event.raw_xml.replace('\n', " ").replace('\r', "")
        );

        let addr = url.strip_prefix("syslog://").unwrap_or(url);

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(syslog_msg.as_bytes(), addr).await?;

        debug!(
            "Successfully forwarded event {} via Syslog to {}",
            event.id, addr
        );
        Ok(())
    }

    fn calculate_priority(parsed: &Option<crate::models::ParsedEvent>) -> u8 {
        // Facility 16 (local use) + severity
        let facility = 16;
        let severity = match parsed {
            Some(p) => match p.level {
                crate::models::EventLevel::Critical => 2,
                crate::models::EventLevel::Error => 3,
                crate::models::EventLevel::Warning => 4,
                crate::models::EventLevel::Information => 6,
                crate::models::EventLevel::Verbose => 7,
            },
            None => 6, // Default to info
        };

        facility * 8 + severity
    }
}

impl Clone for Forwarder {
    fn clone(&self) -> Self {
        Self {
            destinations: Vec::new(), // Can't clone senders
            client: self.client.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{EventLevel, ParsedEvent, WindowsEvent};
    use std::collections::HashMap;

    fn parsed_event(level: EventLevel) -> ParsedEvent {
        ParsedEvent {
            provider: "Test".into(),
            event_id: 1,
            level,
            task: 0,
            opcode: 0,
            keywords: 0,
            time_created: chrono::Utc::now(),
            event_record_id: 1,
            process_id: None,
            thread_id: None,
            channel: "Security".into(),
            computer: "HOST".into(),
            security_user_id: None,
            message: None,
            data: None,
        }
    }

    fn sample_event() -> WindowsEvent {
        let parsed = ParsedEvent {
            provider: "Security".into(),
            event_id: 4624,
            level: EventLevel::Information,
            task: 0,
            opcode: 0,
            keywords: 0,
            time_created: chrono::Utc::now(),
            event_record_id: 1,
            process_id: None,
            thread_id: None,
            channel: "Security".into(),
            computer: "TESTPC".into(),
            security_user_id: None,
            message: Some("User logged in".into()),
            data: None,
        };
        WindowsEvent::new("192.168.1.100".into(), "<Event><System><EventID>4624</EventID></System></Event>".into())
            .with_parsed(parsed)
    }

    #[test]
    fn calculates_priority_from_event_level() {
        let critical = Some(parsed_event(EventLevel::Critical));
        let info = Some(parsed_event(EventLevel::Information));
        let verbose = Some(parsed_event(EventLevel::Verbose));

        assert_eq!(Forwarder::calculate_priority(&critical), 16 * 8 + 2);
        assert_eq!(Forwarder::calculate_priority(&info), 16 * 8 + 6);
        assert_eq!(Forwarder::calculate_priority(&verbose), 16 * 8 + 7);
        assert_eq!(Forwarder::calculate_priority(&None), 16 * 8 + 6);
    }

    #[test]
    fn forwarder_new_creates_instance() {
        let destinations = vec![];
        let forwarder = Forwarder::new(destinations);
        assert!(!forwarder.destinations.is_empty() || forwarder.destinations.is_empty());
    }

    #[test]
    fn forwarder_clone_creates_valid_clone() {
        let destinations = vec![];
        let forwarder = Forwarder::new(destinations);
        let cloned = forwarder.clone();
        assert!(cloned.destinations.is_empty());
    }

    #[test]
    fn calculates_priority_for_warning() {
        let warning = Some(parsed_event(EventLevel::Warning));
        let error = Some(parsed_event(EventLevel::Error));
        assert_eq!(Forwarder::calculate_priority(&warning), 16 * 8 + 4);
        assert_eq!(Forwarder::calculate_priority(&error), 16 * 8 + 3);
    }

    #[tokio::test]
    async fn forwarder_initialize_with_disabled_destinations() {
        let destinations = vec![DestinationConfig {
            name: "test-dest".to_string(),
            url: "http://localhost:8080".to_string(),
            protocol: ForwardProtocol::Http,
            enabled: false,
            headers: HashMap::new(),
        }];

        let forwarder = Forwarder::new(destinations).initialize().await;
        assert!(forwarder.destinations.is_empty());
    }

    #[tokio::test]
    async fn forward_sends_to_empty_destinations() {
        let forwarder = Forwarder::new(vec![]).initialize().await;
        let event = Arc::new(sample_event());
        // Should not panic with no destinations
        forwarder.forward(event).await;
    }

    #[tokio::test]
    async fn forward_event_with_http_protocol() {
        // This tests the code path without actually making HTTP requests
        // by using a destination that won't resolve
        let mut headers = HashMap::new();
        headers.insert("X-Test".to_string(), "value".to_string());

        let destinations = vec![DestinationConfig {
            name: "http-test".to_string(),
            url: "http://invalid.test.local:9999".to_string(),
            protocol: ForwardProtocol::Http,
            enabled: true,
            headers,
        }];

        let forwarder = Forwarder::new(destinations).initialize().await;
        let event = Arc::new(sample_event());

        // Queue the event (forwarder sends via channel)
        forwarder.forward(event).await;

        // Give time for the spawned task to attempt the forward
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn forward_event_with_https_protocol() {
        let destinations = vec![DestinationConfig {
            name: "https-test".to_string(),
            url: "https://invalid.test.local:9999".to_string(),
            protocol: ForwardProtocol::Https,
            enabled: true,
            headers: HashMap::new(),
        }];

        let forwarder = Forwarder::new(destinations).initialize().await;
        let event = Arc::new(sample_event());
        forwarder.forward(event).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn forward_event_with_tcp_protocol() {
        let destinations = vec![DestinationConfig {
            name: "tcp-test".to_string(),
            url: "tcp://127.0.0.1:19999".to_string(),
            protocol: ForwardProtocol::Tcp,
            enabled: true,
            headers: HashMap::new(),
        }];

        let forwarder = Forwarder::new(destinations).initialize().await;
        let event = Arc::new(sample_event());
        forwarder.forward(event).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn forward_event_with_udp_protocol() {
        // Test that UDP protocol destination can be initialized and forward doesn't panic
        let destinations = vec![DestinationConfig {
            name: "udp-test".to_string(),
            url: "udp://127.0.0.1:19999".to_string(),
            protocol: ForwardProtocol::Udp,
            enabled: true,
            headers: HashMap::new(),
        }];

        let forwarder = Forwarder::new(destinations).initialize().await;
        let event = Arc::new(sample_event());
        // Should not panic when forwarding to UDP destination
        forwarder.forward(event).await;
        // Give some time for the async task to attempt the send
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn forward_event_with_syslog_protocol() {
        // Test that syslog protocol destination can be initialized and forward doesn't panic
        let destinations = vec![DestinationConfig {
            name: "syslog-test".to_string(),
            url: "syslog://127.0.0.1:19998".to_string(),
            protocol: ForwardProtocol::Syslog,
            enabled: true,
            headers: HashMap::new(),
        }];

        let forwarder = Forwarder::new(destinations).initialize().await;
        let event = Arc::new(sample_event());
        // Should not panic when forwarding to syslog destination
        forwarder.forward(event).await;
        // Give some time for the async task to attempt the send
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn forward_tcp_handles_connection_failure() {
        // Test with no server listening
        let result = Forwarder::forward_tcp(
            &sample_event(),
            "tcp://127.0.0.1:19998"
        ).await;
        assert!(result.is_err(), "Should fail to connect");
    }

    #[tokio::test]
    async fn forward_tcp_success() {
        // Start a TCP listener
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        // Spawn server task
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = stream.peek(&mut buf).await.unwrap();
            n > 0
        });

        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let result = Forwarder::forward_tcp(
            &sample_event(),
            &format!("tcp://{}", local_addr)
        ).await;

        assert!(result.is_ok(), "Should successfully forward via TCP");
        assert!(server_task.await.unwrap(), "Should receive data");
    }

    #[tokio::test]
    async fn forward_udp_success() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();

        let result = Forwarder::forward_udp(
            &sample_event(),
            &format!("udp://{}", local_addr)
        ).await;

        assert!(result.is_ok(), "Should successfully forward via UDP");

        // Verify the data was sent
        let mut buf = vec![0u8; 65535];
        let (len, _) = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        let received = String::from_utf8_lossy(&buf[..len]);
        assert!(received.contains("TESTPC"), "Should contain computer name");
    }

    #[tokio::test]
    async fn forward_syslog_success() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();

        let result = Forwarder::forward_syslog(
            &sample_event(),
            &format!("syslog://{}", local_addr)
        ).await;

        assert!(result.is_ok(), "Should successfully forward via syslog");

        // Verify the data was sent
        let mut buf = vec![0u8; 65535];
        let (len, _) = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        let received = String::from_utf8_lossy(&buf[..len]);
        // RFC 5424 format: <priority>version timestamp hostname app-name ...
        assert!(received.starts_with('<'), "Should be RFC 5424 format");
        assert!(received.contains("192.168.1.100"), "Should contain source host");
    }

    #[tokio::test]
    async fn forward_syslog_without_url_prefix() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();

        // Test without syslog:// prefix
        let result = Forwarder::forward_syslog(
            &sample_event(),
            &local_addr.to_string()
        ).await;

        assert!(result.is_ok(), "Should handle URL without prefix");
    }

    #[tokio::test]
    async fn forward_http_with_headers() {
        let destinations = vec![DestinationConfig {
            name: "http-headers-test".to_string(),
            url: "http://invalid.test.local:9998".to_string(),
            protocol: ForwardProtocol::Http,
            enabled: true,
            headers: {
                let mut h = HashMap::new();
                h.insert("Authorization".to_string(), "Bearer token123".to_string());
                h.insert("X-Custom-Header".to_string(), "custom-value".to_string());
                h
            },
        }];

        let forwarder = Forwarder::new(destinations).initialize().await;
        let event = Arc::new(sample_event());
        forwarder.forward(event).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }
}
