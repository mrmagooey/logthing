use crate::models::{EventLevel, Heartbeat, ParsedEvent, SubscriptionRequest, WindowsEvent};
use anyhow::Result;
use chrono::{DateTime, Utc};
use quick_xml::Reader;
use quick_xml::events::Event as XmlEvent;
use tracing::{debug, error};

#[derive(Debug)]
pub enum WefMessage {
    Subscription(SubscriptionRequest),
    Events(Vec<WindowsEvent>),
    Heartbeat(Heartbeat),
    Unknown(String),
}

pub struct WefParser;

impl WefParser {
    /// Create a new WEF protocol parser.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wef_server::protocol::WefParser;
    ///
    /// let parser = WefParser::new();
    /// ```
    pub fn new() -> Self {
        Self
    }

    /// Parse a WEF protocol message.
    ///
    /// Automatically detects message type (Subscription, Events, or Heartbeat)
    /// and parses accordingly.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wef_server::protocol::WefParser;
    ///
    /// let parser = WefParser::new();
    ///
    /// // Parse a subscription request
    /// let subscription_xml = r#"<Subscribe><SubscriptionId>test-sub</SubscriptionId></Subscribe>"#;
    /// match parser.parse_message(subscription_xml, "workstation01".to_string()) {
    ///     Ok(msg) => println!("Parsed message: {:?}", msg),
    ///     Err(e) => eprintln!("Parse error: {}", e),
    /// }
    /// ```
    pub fn parse_message(&self, body: &str, source_host: String) -> Result<WefMessage> {
        debug!("Parsing WEF message from {}", source_host);

        // Check if it's a subscription request
        if body.contains("Subscribe") {
            return self.parse_subscription(body, source_host);
        }

        // Check if it's events
        if body.contains("Events") || body.contains("EventID") {
            return self.parse_events(body, source_host);
        }

        // Check if it's a heartbeat
        if body.contains("Heartbeat") {
            return self.parse_heartbeat(body, source_host);
        }

        Ok(WefMessage::Unknown(body.to_string()))
    }

    fn parse_subscription(&self, body: &str, source_host: String) -> Result<WefMessage> {
        debug!("Parsing subscription request");

        // Extract subscription ID
        let subscription_id = Self::extract_xml_value(body, "SubscriptionId")
            .unwrap_or_else(|| format!("sub_{}", uuid::Uuid::new_v4()));

        // Extract query
        let query = Self::extract_xml_value(body, "Query").unwrap_or_default();

        let request = SubscriptionRequest {
            subscription_id,
            source_host,
            query,
            heartbeat_interval: Self::extract_xml_value(body, "HeartbeatInterval")
                .and_then(|s| s.parse().ok()),
        };

        Ok(WefMessage::Subscription(request))
    }

    fn parse_events(&self, body: &str, source_host: String) -> Result<WefMessage> {
        debug!("Parsing events batch");

        let mut events = Vec::new();
        let mut reader = Reader::from_str(body);
        reader.trim_text(true);

        let mut buf = Vec::new();
        let mut current_event_xml = String::new();
        let mut in_event = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(XmlEvent::Start(e)) => {
                    if e.name().as_ref() == b"Event" {
                        in_event = true;
                        current_event_xml.clear();
                        current_event_xml.push_str("<Event>");
                    } else if in_event {
                        current_event_xml
                            .push_str(&format!("<{}>", String::from_utf8_lossy(e.name().as_ref())));
                    }
                }
                Ok(XmlEvent::End(e)) => {
                    if e.name().as_ref() == b"Event" && in_event {
                        current_event_xml.push_str("</Event>");
                        in_event = false;

                        // Parse this individual event
                        match self.parse_single_event(&current_event_xml, &source_host) {
                            Ok(event) => events.push(event),
                            Err(e) => {
                                error!("Failed to parse individual event: {}", e);
                                // Still add raw event
                                events.push(WindowsEvent::new(
                                    source_host.clone(),
                                    current_event_xml.clone(),
                                ));
                            }
                        }
                    } else if in_event {
                        current_event_xml.push_str(&format!(
                            "</{}>",
                            String::from_utf8_lossy(e.name().as_ref())
                        ));
                    }
                }
                Ok(XmlEvent::Text(e)) => {
                    if in_event {
                        current_event_xml.push_str(&e.unescape()?);
                    }
                }
                Ok(XmlEvent::Empty(e)) => {
                    if in_event {
                        let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                        current_event_xml.push_str(&format!("<{} />", name));
                    }
                }
                Ok(XmlEvent::Eof) => break,
                Err(e) => {
                    error!("XML parsing error: {}", e);
                    break;
                }
                _ => {}
            }
            buf.clear();
        }

        debug!("Parsed {} events from batch", events.len());
        Ok(WefMessage::Events(events))
    }

    fn parse_single_event(&self, xml: &str, source_host: &str) -> Result<WindowsEvent> {
        let mut event = WindowsEvent::new(source_host.to_string(), xml.to_string());

        // Try to parse the event XML into structured data
        if let Ok(parsed) = self.parse_event_data(xml) {
            event = event.with_parsed(parsed);
        }

        Ok(event)
    }

    fn parse_event_data(&self, xml: &str) -> Result<ParsedEvent> {
        let provider = Self::extract_xml_value(xml, "Provider").unwrap_or_default();

        let event_id = Self::extract_xml_value(xml, "EventID")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let level = Self::extract_xml_value(xml, "Level")
            .and_then(|s| s.parse().ok())
            .map(|l: u8| match l {
                1 => EventLevel::Critical,
                2 => EventLevel::Error,
                3 => EventLevel::Warning,
                4 => EventLevel::Information,
                _ => EventLevel::Verbose,
            })
            .unwrap_or_default();

        let time_created = Self::extract_xml_value(xml, "TimeCreated")
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let computer = Self::extract_xml_value(xml, "Computer").unwrap_or_default();

        let message = Self::extract_xml_value(xml, "Message")
            .or_else(|| Self::extract_xml_value(xml, "Data"));

        Ok(ParsedEvent {
            provider,
            event_id,
            level,
            task: 0,
            opcode: 0,
            keywords: 0,
            time_created,
            event_record_id: 0,
            process_id: None,
            thread_id: None,
            channel: String::new(),
            computer,
            security_user_id: None,
            message,
            data: None,
        })
    }

    fn parse_heartbeat(&self, body: &str, source_host: String) -> Result<WefMessage> {
        let subscription_id = Self::extract_xml_value(body, "SubscriptionId").unwrap_or_default();

        Ok(WefMessage::Heartbeat(Heartbeat {
            subscription_id,
            source_host,
            timestamp: Utc::now(),
        }))
    }

    fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
        let start_tag = format!("<{}>", tag);
        let end_tag = format!("</{}>", tag);

        if let Some(start) = xml.find(&start_tag) {
            let content_start = start + start_tag.len();
            if let Some(end) = xml[content_start..].find(&end_tag) {
                return Some(xml[content_start..content_start + end].to_string());
            }
        }

        // Try with attributes (e.g., <Provider Name="...">)
        let attr_pattern = format!(r#"{}="([^"]*)""#, tag);
        if let Some(start) = xml.find(&attr_pattern) {
            let value_start = start + tag.len() + 2; // +2 for ="
            if let Some(end) = xml[value_start..].find('"') {
                return Some(xml[value_start..value_start + end].to_string());
            }
        }

        None
    }
}

pub fn create_subscription_response(subscription_id: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
            <s:Header>
                <SubscriptionId xmlns="http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog">{}</SubscriptionId>
            </s:Header>
            <s:Body>
                <SubscribeResponse xmlns="http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog"/>
            </s:Body>
        </s:Envelope>"#,
        subscription_id
    )
}

pub fn create_heartbeat_response() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
        <s:Body>
            <HeartbeatResponse xmlns="http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog"/>
        </s:Body>
    </s:Envelope>"#
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subscription_request() {
        let parser = WefParser::new();
        let xml = r#"
        <Envelope>
          <Body>
            <Subscribe>
              <SubscriptionId>TestSubscription</SubscriptionId>
              <Query>*</Query>
            </Subscribe>
          </Body>
        </Envelope>
        "#;

        match parser
            .parse_message(xml, "source-host".into())
            .expect("parse succeeds")
        {
            WefMessage::Subscription(sub) => {
                assert_eq!(sub.subscription_id, "TestSubscription");
                assert_eq!(sub.source_host, "source-host");
                assert_eq!(sub.query, "*");
            }
            other => panic!("unexpected message: {:?}", other),
        }
    }

    #[test]
    fn parses_event_batch() {
        let parser = WefParser::new();
        let xml = r#"
        <Envelope>
          <Body>
            <Events>
              <Event>
                <System>
                  <Provider>Security</Provider>
                  <EventID>4624</EventID>
                  <Level>4</Level>
                  <TimeCreated>2024-01-01T00:00:00Z</TimeCreated>
                  <Computer>host</Computer>
                </System>
                <EventData>
                  <Data Name="TargetUserName">alice</Data>
                </EventData>
              </Event>
            </Events>
          </Body>
        </Envelope>
        "#;

        match parser
            .parse_message(xml, "collector".into())
            .expect("parse succeeds")
        {
            WefMessage::Events(events) => {
                assert_eq!(events.len(), 1);
                let event = &events[0];
                assert_eq!(event.source_host, "collector");
                let parsed = event.parsed.as_ref().expect("parsed event");
                assert_eq!(parsed.event_id, 4624);
                assert_eq!(parsed.computer, "host");
                assert_eq!(parsed.provider, "Security");
            }
            other => panic!("expected events but got {:?}", other),
        }
    }

    #[test]
    fn parses_heartbeat() {
        let parser = WefParser::new();
        let xml = r#"
        <Heartbeat>
          <SubscriptionId>hb-123</SubscriptionId>
        </Heartbeat>
        "#;

        match parser
            .parse_message(xml, "hb-source".into())
            .expect("parse succeeds")
        {
            WefMessage::Heartbeat(hb) => {
                assert_eq!(hb.subscription_id, "hb-123");
                assert_eq!(hb.source_host, "hb-source");
            }
            other => panic!("expected heartbeat but got {:?}", other),
        }
    }
}
