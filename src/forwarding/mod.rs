use crate::config::{DestinationConfig, ForwardProtocol};
use crate::models::WindowsEvent;
use anyhow::Result;
use reqwest::Client;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

pub mod parquet_s3;

pub struct Forwarder {
    destinations: Vec<Destination>,
    client: Client,
}

struct Destination {
    config: DestinationConfig,
    sender: mpsc::Sender<WindowsEvent>,
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

            let (tx, mut rx) = mpsc::channel::<WindowsEvent>(1000);
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wef_server::forwarding::Forwarder;
    /// use wef_server::models::WindowsEvent;
    ///
    /// async fn forward_event(forwarder: &Forwarder) {
    ///     let event = WindowsEvent::new(
    ///         "workstation01".to_string(),
    ///         "<Event><System><EventID>4624</EventID></System></Event>".to_string()
    ///     );
    ///
    ///     forwarder.forward(event).await;
    /// }
    /// ```
    pub async fn forward(&self, event: WindowsEvent) {
        for dest in &self.destinations {
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
    use crate::models::{EventLevel, ParsedEvent};

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
}
