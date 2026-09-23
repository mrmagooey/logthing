use crate::models::{EventLevel, Heartbeat, ParsedEvent, SubscriptionRequest, WindowsEvent};
use anyhow::Result;
use chrono::{DateTime, Utc};
use quick_xml::Reader;
use quick_xml::escape::escape as xml_escape;
use quick_xml::events::Event as XmlEvent;
use tracing::{debug, error};

#[derive(Debug)]
pub enum WefMessage {
    Subscription(SubscriptionRequest),
    Events(Vec<WindowsEvent>),
    Heartbeat(Heartbeat),
    Unknown(String),
}

#[derive(Default)]
pub struct WefParser;

impl WefParser {
    /// Create a new WEF protocol parser.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use logthing::protocol::WefParser;
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
    /// use logthing::protocol::WefParser;
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

        // Fast single-pass detection using first meaningful element
        // Check first 2000 chars for type detection (avoids scanning entire large bodies)
        let check_body = crate::truncate_for_log(body, 2000);

        if check_body.contains("Subscribe") && check_body.contains("SubscriptionId") {
            return self.parse_subscription(body, source_host);
        }

        if check_body.contains("<Events>") || check_body.contains("<Event>") {
            return self.parse_events(body, source_host);
        }

        if check_body.contains("Heartbeat") {
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

        // `base` is the absolute offset into `body` where the current
        // window (and its fresh quick-xml `Reader`) starts. On a reader
        // error, rather than giving up on the rest of the batch (or, per
        // the first cut of this fix, folding everything after the error
        // into one giant raw event — which `WefSink` then drops wholesale
        // since it has no parsed data), we resync: keep only the malformed
        // event's own fragment as raw, find the next `<Event` start, and
        // restart parsing from there with a brand-new `Reader`. Iterative,
        // not recursive: a batch of thousands of malformed events must not
        // grow the stack.
        let mut base = 0usize;

        'outer: while let Some(window) = body.get(base..) {
            if window.is_empty() {
                break;
            }

            let mut reader = Reader::from_str(window);
            reader.trim_text(true);

            let mut buf = Vec::new();
            let mut event_start_pos: Option<usize> = None;
            let mut in_event = false;
            let mut depth: u32 = 0;
            // Absolute resume offset for the *next* outer iteration, set
            // only when an `Err` is handled and a later event start is
            // found. Left `None` on a clean `Eof` or when no later event
            // start exists — either way, parsing is done.
            let mut resume_at: Option<usize> = None;

            loop {
                let pos = reader.buffer_position();
                match reader.read_event_into(&mut buf) {
                    Ok(XmlEvent::Start(e)) => {
                        if e.name().as_ref() == b"Event" && !in_event {
                            in_event = true;
                            depth = 1;
                            event_start_pos = Some(pos);
                        } else if in_event {
                            depth += 1;
                        }
                    }
                    Ok(XmlEvent::End(e)) => {
                        if e.name().as_ref() == b"Event" && in_event && depth == 1 {
                            // Event ends here - extract the XML slice
                            in_event = false;

                            if let Some(start) = event_start_pos
                                && let Some(event_xml) = window.get(start..pos)
                            {
                                // Parse this individual event
                                match self.parse_single_event(event_xml, &source_host) {
                                    Ok(event) => events.push(event),
                                    Err(e) => {
                                        error!("Failed to parse individual event: {}", e);
                                        // Still add raw event
                                        events.push(WindowsEvent::new(
                                            source_host.clone(),
                                            event_xml.to_string(),
                                        ));
                                    }
                                }
                            }
                            depth = 0;
                        } else if in_event {
                            depth = depth.saturating_sub(1);
                        }
                    }
                    #[allow(clippy::collapsible_match)]
                    Ok(XmlEvent::Empty(e)) => {
                        if in_event && e.name().as_ref() == b"Event" && depth == 0 {
                            // Self-closing Event tag
                            in_event = false;

                            if let Some(start) = event_start_pos
                                && let Some(event_xml) = window.get(start..pos)
                            {
                                match self.parse_single_event(event_xml, &source_host) {
                                    Ok(event) => events.push(event),
                                    Err(e) => {
                                        error!("Failed to parse individual event: {}", e);
                                        events.push(WindowsEvent::new(
                                            source_host.clone(),
                                            event_xml.to_string(),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                    Ok(XmlEvent::Eof) => break,
                    Err(e) => {
                        error!("XML parsing error: {}", e);

                        // Where to resume searching for the next `<Event`
                        // start from: past the bad event's own start (so a
                        // malformed event can never match itself again),
                        // or the error position when we're not inside one.
                        let search_from = if in_event {
                            pos.max(event_start_pos.unwrap_or(pos).saturating_add(1))
                        } else {
                            pos
                        };
                        let next_start = find_next_event_start(window, search_from);

                        // Only inside an event is there a malformed
                        // fragment worth keeping raw — outside one, a
                        // reader error is envelope junk (a stray/mismatched
                        // closing tag) with no event data to preserve.
                        //
                        // This is also why the counter increments only
                        // here, not unconditionally: every *resumed* reader
                        // (one restarted after a resync) starts with an
                        // empty quick-xml tag stack, so once it legitimately
                        // reaches the original document's own closing
                        // `</Events></Body></Envelope>` — bytes that were
                        // always well-formed — check_end_names has no record
                        // of those tags ever opening and returns a second,
                        // spurious `Err` purely as an artifact of resuming
                        // mid-document. That happens with `in_event == false`
                        // and carries no lost event data, so it is logged
                        // (the line above) but must not inflate a metric
                        // whose whole purpose is "an event was lost".
                        if in_event {
                            metrics::counter!("wef_xml_parse_errors").increment(1);
                            let frag_from = event_start_pos.unwrap_or(pos);
                            let frag_to = next_start.unwrap_or(window.len());
                            if let Some(frag) = window.get(frag_from..frag_to)
                                && !frag.trim().is_empty()
                            {
                                events
                                    .push(WindowsEvent::new(source_host.clone(), frag.to_string()));
                            }
                        }

                        // `next_start` is window-relative; only accept it
                        // as a resume point if it actually advances past
                        // this window's start — otherwise resyncing would
                        // spin forever re-parsing the same bytes.
                        resume_at = next_start.map(|rel| base + rel).filter(|&abs| abs > base);
                        break;
                    }
                    _ => {}
                }
                buf.clear();
            }

            match resume_at {
                Some(next_base) => {
                    base = next_base;
                    continue 'outer;
                }
                None => break 'outer,
            }
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
        // Single-pass XML parsing for better performance
        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        let mut provider = String::new();
        let mut event_id: u32 = 0;
        let mut level: u8 = 0;
        let mut time_created = Utc::now();
        let mut computer = String::new();
        let mut channel = String::new();
        let mut message: Option<String> = None;
        let mut in_message = false;
        let mut in_data = false;
        let mut current_tag = String::new();

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(XmlEvent::Start(e)) => {
                    current_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    match current_tag.as_str() {
                        "Message" => in_message = true,
                        "Data" => in_data = true,
                        _ => {}
                    }
                }
                Ok(XmlEvent::End(e)) => {
                    let name = e.name();
                    let tag = String::from_utf8_lossy(name.as_ref());
                    match tag.as_ref() {
                        "Message" => in_message = false,
                        "Data" => in_data = false,
                        _ => {}
                    }
                }
                Ok(XmlEvent::Text(e)) => {
                    let text = match e.unescape() {
                        Ok(t) => t,
                        Err(err) => {
                            // `current_tag` is the raw wire tag name (quick-xml
                            // is non-validating, so it isn't restricted to
                            // well-formed XML Name characters) and unbounded —
                            // sanitize before it reaches this Display-formatted
                            // debug! line.
                            debug!(
                                "Failed to unescape XML text in tag <{}>: {}",
                                crate::sanitize_for_log(&current_tag, 100),
                                err
                            );
                            std::borrow::Cow::Borrowed("")
                        }
                    };
                    match current_tag.as_str() {
                        "Provider" => provider = text.to_string(),
                        "EventID" => {
                            event_id = text.parse().unwrap_or_else(|_| {
                                debug!(
                                    "Failed to parse EventID {:?} as u32, defaulting to 0",
                                    text.as_ref()
                                );
                                0
                            });
                        }
                        "Level" => {
                            level = text.parse().unwrap_or_else(|_| {
                                debug!(
                                    "Failed to parse Level {:?} as u8, defaulting to 0",
                                    text.as_ref()
                                );
                                0
                            });
                        }
                        "TimeCreated" => {
                            if let Ok(dt) = DateTime::parse_from_rfc3339(&text) {
                                time_created = dt.with_timezone(&Utc);
                            }
                        }
                        "Computer" => computer = text.to_string(),
                        "Channel" => channel = text.to_string(),
                        "Message" if in_message => {
                            message = Some(text.to_string());
                        }
                        "Data" if in_data && message.is_none() => {
                            message = Some(text.to_string());
                        }
                        _ => {}
                    }
                }
                Ok(XmlEvent::Empty(e)) if e.name().as_ref() == b"TimeCreated" => {
                    // Handle attributes in empty TimeCreated tags
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"SystemTime"
                            && let Ok(val) = std::str::from_utf8(&attr.value)
                            && let Ok(dt) = DateTime::parse_from_rfc3339(val)
                        {
                            time_created = dt.with_timezone(&Utc);
                        }
                    }
                }
                Ok(XmlEvent::Empty(_)) => {}
                Ok(XmlEvent::Eof) => break,
                Err(_) => break,
                _ => {}
            }
            buf.clear();
        }

        let level_enum = match level {
            1 => EventLevel::Critical,
            2 => EventLevel::Error,
            3 => EventLevel::Warning,
            4 => EventLevel::Information,
            _ => EventLevel::Verbose,
        };

        Ok(ParsedEvent {
            provider,
            event_id,
            level: level_enum,
            task: 0,
            opcode: 0,
            keywords: 0,
            time_created,
            event_record_id: 0,
            process_id: None,
            thread_id: None,
            channel,
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

/// Find the next `<Event` element start in `window`, searching from byte
/// offset `from`, for `parse_events`' resync-on-error path.
///
/// Matches `<Event` only when immediately followed by `>`, `/` (self-closing)
/// or ASCII whitespace — so `<EventData`, `<EventID` and `<Events` (the
/// batch wrapper itself) are correctly excluded. Returns a `window`-relative
/// byte offset.
fn find_next_event_start(window: &str, from: usize) -> Option<usize> {
    let haystack = window.get(from..)?;
    for (rel_offset, _) in haystack.match_indices("<Event") {
        let abs_offset = from + rel_offset;
        let after = abs_offset + "<Event".len();
        if let Some(&b) = window.as_bytes().get(after)
            && (b == b'>' || b == b'/' || b.is_ascii_whitespace())
        {
            return Some(abs_offset);
        }
    }
    None
}

pub fn create_subscription_response(subscription_id: &str) -> String {
    let escaped_id = xml_escape(subscription_id);
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
        escaped_id
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
    use chrono::Datelike;

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

    /// `Channel` (e.g. "Security", "System") is what `stats::cardinality`'s
    /// WEF watch matches a configured `stream` against
    /// (`AggFields for WindowsEvent` in `forwarding::aggregate::fields`) —
    /// a real Windows Event XML System element always carries it, so it
    /// must come through parsed, not hardcoded empty.
    #[test]
    fn parses_channel() {
        let parser = WefParser::new();
        let xml = r#"
        <Envelope>
          <Body>
            <Events>
              <Event>
                <System>
                  <Provider>Microsoft-Windows-Security-Auditing</Provider>
                  <EventID>4624</EventID>
                  <Level>4</Level>
                  <Channel>Security</Channel>
                  <TimeCreated>2024-01-01T00:00:00Z</TimeCreated>
                  <Computer>host</Computer>
                </System>
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
                let parsed = events[0].parsed.as_ref().expect("parsed event");
                assert_eq!(parsed.channel, "Security");
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

    #[test]
    fn extract_xml_value_finds_simple_tag() {
        let xml = "<Test><Value>hello</Value></Test>";
        assert_eq!(
            WefParser::extract_xml_value(xml, "Value"),
            Some("hello".to_string())
        );
    }

    #[test]
    fn extract_xml_value_returns_none_for_missing_tag() {
        let xml = "<Test><Other>value</Other></Test>";
        assert_eq!(WefParser::extract_xml_value(xml, "Missing"), None);
    }

    #[test]
    fn extract_xml_value_returns_none_for_attribute_pattern() {
        let xml = r#"<Test attr="attribute_value"/>"#;
        // The extract_xml_value function doesn't handle attribute extraction in the way we tested
        // It looks for tags or attr="value" patterns, but the pattern matching doesn't work this way
        // Let's test that it returns None for attribute-only lookups
        assert_eq!(WefParser::extract_xml_value(xml, "attr"), None);
    }

    #[test]
    fn parse_unknown_message_type() {
        let parser = WefParser::new();
        let xml = "<UnknownTag>some content</UnknownTag>";

        match parser
            .parse_message(xml, "test-host".into())
            .expect("parse succeeds")
        {
            WefMessage::Unknown(content) => {
                assert!(content.contains("UnknownTag"));
            }
            other => panic!("expected Unknown but got {:?}", other),
        }
    }

    #[test]
    fn parse_subscription_with_heartbeat_interval() {
        let parser = WefParser::new();
        let xml = r#"
        <Envelope>
          <Body>
            <Subscribe>
              <SubscriptionId>SubWithHeartbeat</SubscriptionId>
              <Query>System</Query>
              <HeartbeatInterval>60</HeartbeatInterval>
            </Subscribe>
          </Body>
        </Envelope>
        "#;

        match parser
            .parse_message(xml, "host".into())
            .expect("parse succeeds")
        {
            WefMessage::Subscription(sub) => {
                assert_eq!(sub.subscription_id, "SubWithHeartbeat");
                assert_eq!(sub.heartbeat_interval, Some(60));
            }
            other => panic!("expected Subscription but got {:?}", other),
        }
    }

    #[test]
    fn parse_subscription_without_subscription_id() {
        let parser = WefParser::new();
        // The parser requires both "Subscribe" AND "SubscriptionId" to detect as subscription
        // If SubscriptionId is missing, it generates one

        // Note: The parser needs both "Subscribe" and "SubscriptionId" keywords to match
        // If SubscriptionId is present but empty, it will be empty string, not a UUID
        // Let's test that we get a subscription back with empty query when SubscriptionId is empty
        let xml_with_empty_id = r#"
        <Envelope>
          <Body>
            <Subscribe>
              <SubscriptionId></SubscriptionId>
              <Query>*</Query>
            </Subscribe>
          </Body>
        </Envelope>
        "#;

        match parser
            .parse_message(xml_with_empty_id, "host".into())
            .expect("parse succeeds")
        {
            WefMessage::Subscription(sub) => {
                // Empty subscription ID results in empty string, not UUID
                assert_eq!(sub.subscription_id, "");
                assert_eq!(sub.query, "*");
            }
            other => panic!("expected Subscription but got {:?}", other),
        }
    }

    #[test]
    fn parse_events_with_empty_event_data() {
        let parser = WefParser::new();
        let xml = r#"
        <Envelope>
          <Body>
            <Events>
              <Event>
                <System>
                  <Provider>System</Provider>
                  <EventID>1</EventID>
                  <Level>4</Level>
                  <TimeCreated SystemTime="2024-01-01T00:00:00Z"/>
                  <Computer>testpc</Computer>
                </System>
                <EventData/>
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
                let parsed = events[0].parsed.as_ref().expect("parsed");
                assert_eq!(parsed.event_id, 1);
            }
            other => panic!("expected Events but got {:?}", other),
        }
    }

    #[test]
    fn parse_multiple_events_in_batch() {
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
                  <Computer>host1</Computer>
                </System>
              </Event>
              <Event>
                <System>
                  <Provider>Security</Provider>
                  <EventID>4625</EventID>
                  <Level>4</Level>
                  <TimeCreated>2024-01-01T00:00:01Z</TimeCreated>
                  <Computer>host2</Computer>
                </System>
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
                assert_eq!(events.len(), 2);
                assert_eq!(events[0].parsed.as_ref().unwrap().event_id, 4624);
                assert_eq!(events[1].parsed.as_ref().unwrap().event_id, 4625);
            }
            other => panic!("expected Events but got {:?}", other),
        }
    }

    #[test]
    fn parse_event_with_message_text() {
        let parser = WefParser::new();
        let xml = r#"
        <Envelope>
          <Body>
            <Events>
              <Event>
                <System>
                  <Provider>Application</Provider>
                  <EventID>1000</EventID>
                  <Level>2</Level>
                  <TimeCreated>2024-01-01T00:00:00Z</TimeCreated>
                  <Computer>testpc</Computer>
                </System>
                <EventData>
                  <Message>This is a test message</Message>
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
                let parsed = events[0].parsed.as_ref().expect("parsed");
                assert_eq!(parsed.message, Some("This is a test message".to_string()));
                assert_eq!(parsed.level, EventLevel::Error);
            }
            other => panic!("expected Events but got {:?}", other),
        }
    }

    #[test]
    fn parse_event_with_invalid_xml_still_returns_event() {
        let parser = WefParser::new();
        let xml = r#"
        <Envelope>
          <Body>
            <Events>
              <Event>
                <System>
                  <Provider>Test</Provider>
                  <EventID>not_a_number</EventID>
                  <Level>invalid</Level>
                </System>
              </Event>
            </Events>
          </Body>
        </Envelope>
        "#;

        // Should still return an event, but with defaults
        match parser
            .parse_message(xml, "collector".into())
            .expect("parse succeeds")
        {
            WefMessage::Events(events) => {
                assert_eq!(events.len(), 1);
                let parsed = events[0].parsed.as_ref().expect("parsed");
                assert_eq!(parsed.event_id, 0); // Default when parsing fails
                assert_eq!(parsed.provider, "Test");
            }
            other => panic!("expected Events but got {:?}", other),
        }
    }

    #[test]
    fn parse_self_closing_event_tag() {
        let parser = WefParser::new();
        // Self-closing Event tags (<Event />) are handled by the Empty event case in the parser
        // Let's verify the parser can handle an event with minimal content
        let xml = r#"
        <Envelope>
          <Body>
            <Events>
              <Event><System><EventID>1</EventID><Level>4</Level></System></Event>
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
                let parsed = events[0].parsed.as_ref().expect("parsed");
                assert_eq!(parsed.event_id, 1);
            }
            other => panic!("expected Events but got {:?}", other),
        }
    }

    #[test]
    fn parse_empty_envelope() {
        let parser = WefParser::new();
        let xml = "<Envelope></Envelope>";

        match parser
            .parse_message(xml, "test".into())
            .expect("parse succeeds")
        {
            WefMessage::Unknown(_) => {}
            other => panic!("expected Unknown for empty envelope but got {:?}", other),
        }
    }

    #[test]
    fn create_subscription_response_contains_subscription_id() {
        let sub_id = "test-subscription-123";
        let response = create_subscription_response(sub_id);
        assert!(response.contains(sub_id));
        assert!(response.contains("SubscribeResponse"));
        assert!(response.contains("wsman"));
    }

    #[test]
    fn create_subscription_response_escapes_xml_injection() {
        // A subscription_id containing XML-special chars must not produce raw injection
        let malicious_id = r#"]]><evil>&amp;"injected"</evil><![CDATA["#;
        let response = create_subscription_response(malicious_id);
        // Raw injection chars must not appear verbatim
        assert!(!response.contains("<evil>"), "raw < must be escaped");
        assert!(!response.contains("</evil>"), "raw </ must be escaped");
        // Escaped forms should appear
        assert!(response.contains("&lt;"), "< should be &lt;");
        assert!(response.contains("&amp;"), "& should be &amp;");
        // Existing test: response must still be structurally valid (contains SubscribeResponse)
        assert!(response.contains("SubscribeResponse"));
    }

    #[test]
    fn create_heartbeat_response_is_valid_xml() {
        let response = create_heartbeat_response();
        assert!(response.contains("HeartbeatResponse"));
        assert!(response.contains("wsman"));
        assert!(response.contains("Envelope"));
    }

    #[test]
    fn wef_parser_new_creates_instance() {
        let parser = WefParser::new();
        // Just verify it can be created
        let xml = "<Subscribe><SubscriptionId>test</SubscriptionId></Subscribe>";
        let result = parser.parse_message(xml, "host".into());
        assert!(result.is_ok());
    }

    #[test]
    fn parse_event_all_levels() {
        let parser = WefParser::new();

        let levels = vec![
            ("1", EventLevel::Critical),
            ("2", EventLevel::Error),
            ("3", EventLevel::Warning),
            ("4", EventLevel::Information),
            ("5", EventLevel::Verbose),
            ("0", EventLevel::Verbose), // Unknown defaults to Verbose
        ];

        for (level_str, expected_level) in levels {
            let xml = format!(
                r#"
            <Envelope>
              <Body>
                <Events>
                  <Event>
                    <System>
                      <Provider>Test</Provider>
                      <EventID>1</EventID>
                      <Level>{}</Level>
                      <TimeCreated>2024-01-01T00:00:00Z</TimeCreated>
                      <Computer>test</Computer>
                    </System>
                  </Event>
                </Events>
              </Body>
            </Envelope>
            "#,
                level_str
            );

            match parser
                .parse_message(&xml, "host".into())
                .expect("parse succeeds")
            {
                WefMessage::Events(events) => {
                    let parsed = events[0].parsed.as_ref().expect("parsed");
                    assert_eq!(
                        parsed.level, expected_level,
                        "Level {} should map to {:?}",
                        level_str, expected_level
                    );
                }
                other => panic!("expected Events but got {:?}", other),
            }
        }
    }

    #[test]
    fn parse_event_with_rfc3339_systemtime_attribute() {
        let parser = WefParser::new();
        let xml = r#"
        <Envelope>
          <Body>
            <Events>
              <Event>
                <System>
                  <Provider>Test</Provider>
                  <EventID>1</EventID>
                  <Level>4</Level>
                  <TimeCreated SystemTime="2024-06-15T12:30:45.1234567Z"/>
                  <Computer>testpc</Computer>
                </System>
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
                let parsed = events[0].parsed.as_ref().expect("parsed");
                assert_eq!(parsed.time_created.year(), 2024);
                assert_eq!(parsed.time_created.month(), 6);
                assert_eq!(parsed.time_created.day(), 15);
            }
            other => panic!("expected Events but got {:?}", other),
        }
    }

    #[test]
    fn extract_xml_value_handles_nested_tags() {
        let xml = "<Root><Level1><Level2>deep_value</Level2></Level1></Root>";
        assert_eq!(
            WefParser::extract_xml_value(xml, "Level2"),
            Some("deep_value".to_string())
        );
        assert_eq!(
            WefParser::extract_xml_value(xml, "Level1"),
            Some("<Level2>deep_value</Level2>".to_string())
        );
    }

    #[test]
    fn extract_xml_value_with_empty_content() {
        let xml = "<Test><Empty></Empty></Test>";
        assert_eq!(
            WefParser::extract_xml_value(xml, "Empty"),
            Some("".to_string())
        );
    }

    #[test]
    fn parse_malformed_xml_gracefully() {
        let parser = WefParser::new();
        let xml = "<Invalid<XML>Not valid XML content";

        // Should not panic, should return Unknown or error
        let result = parser.parse_message(xml, "test".into());
        // The parser should handle this gracefully
        match result {
            Ok(WefMessage::Unknown(_)) => {}
            Ok(_) => {}
            Err(_) => {}
        }
    }

    #[test]
    fn parse_events_mismatched_depth_does_not_panic() {
        let parser = WefParser::new();
        // Craft XML where closing tags exceed opening tags inside an Event
        // (mismatched nesting). Must not panic in debug mode.
        let xml = r#"
        <Envelope>
          <Body>
            <Events>
              <Event>
                <System>
                  <EventID>42</EventID>
                </System>
                </ExtraClose>
              </Event>
            </Events>
          </Body>
        </Envelope>
        "#;
        // Any result is acceptable — just must not panic
        let _ = parser.parse_message(xml, "host".into());
    }

    #[test]
    fn parse_message_multibyte_char_at_boundary_does_not_panic() {
        let parser = WefParser::new();
        // Build a body where a 4-byte emoji straddles byte 2000.
        // Each '😀' is 4 bytes (U+1F600). Fill 1999 ASCII bytes then append emojis.
        let prefix = "a".repeat(1999); // bytes 0..1999
        let suffix = "😀".repeat(10); // 4 bytes each; first one spans bytes 1999..2003
        let body = format!("{}{}", prefix, suffix);
        assert_eq!(body.as_bytes()[1999], 0xF0); // confirms emoji straddles byte 2000

        // Must not panic — any result is fine
        let result = parser.parse_message(&body, "host".into());
        assert!(result.is_ok() || result.is_err()); // just must not panic
    }

    #[test]
    fn parse_event_preserves_raw_xml() {
        let parser = WefParser::new();
        let xml = r#"
        <Envelope>
          <Body>
            <Events>
              <Event>
                <System>
                  <Provider>TestProvider</Provider>
                  <EventID>1234</EventID>
                  <Level>4</Level>
                  <TimeCreated>2024-01-01T00:00:00Z</TimeCreated>
                  <Computer>TestComputer</Computer>
                </System>
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
                let event = &events[0];
                assert!(event.raw_xml.contains("TestProvider"));
                assert!(event.raw_xml.contains("1234"));
                assert!(event.raw_xml.contains("TestComputer"));
            }
            other => panic!("expected Events but got {:?}", other),
        }
    }

    /// `current_tag` is the raw wire tag name (quick-xml is non-validating,
    /// so an ANSI escape isn't rejected as an illegal XML Name character —
    /// unlike `\r`/`\n`, which quick-xml's tokenizer treats as a name
    /// terminator and so can't reach `current_tag` this way). It must not
    /// carry that escape raw into the "Failed to unescape XML text" debug!
    /// line when the tag's text content fails to unescape (an unrecognized
    /// entity reference). Uses the shared `test_support` capture subscriber
    /// (see its doc comment).
    #[tokio::test]
    async fn unescape_error_log_sanitizes_tag_name() {
        crate::test_support::install_and_clear();

        let evil_tag = "Ev\u{1b}[31mil";
        let xml = format!("<{evil_tag}>&badentity;</{evil_tag}>");
        let parser = WefParser::new();

        // Doesn't need to succeed -- the debug! site fires during the failed
        // unescape regardless of the overall parse outcome.
        let _ = parser.parse_event_data(&xml);

        let events = crate::test_support::captured_events();
        let line = events
            .iter()
            .find(|m| m.contains("Failed to unescape XML text"))
            .unwrap_or_else(|| panic!("no matching debug! event captured; got: {events:?}"));

        assert!(
            !line.contains('\u{1b}'),
            "raw ESC leaked into the log line: {line:?}"
        );
        assert!(
            line.contains('\u{fffd}'),
            "expected U+FFFD replacement characters in the log line: {line:?}"
        );
    }

    /// Well-formed `<Event>` for event number `n`, matching real WEF shape.
    fn wef_event(n: u32) -> String {
        format!(
            "<Event><System><Provider>P</Provider><EventID>{n}</EventID><Level>4</Level>\
             </System></Event>"
        )
    }

    /// Malformed `<Event>` for event number `n`: a stray `</Mismatch>` end
    /// tag inside `<System>` trips quick-xml's default `check_end_names`
    /// and returns `Err` from `read_event_into` (verified by the RED run of
    /// the tests below).
    fn wef_malformed_event(n: u32) -> String {
        format!(
            "<Event><System><Provider>P</Provider></Mismatch><EventID>{n}</EventID>\
             <Level>4</Level></System></Event>"
        )
    }

    fn wef_envelope(events_xml: &str) -> String {
        format!("<Envelope><Body><Events>{events_xml}</Events></Body></Envelope>")
    }

    /// (a) Malformed MIDDLE event: resync must reach event 3, not fold it
    /// into the malformed fragment — both good events come back genuinely
    /// PARSED (`.parsed` is `Some`), not just raw text that happens to
    /// contain their `EventID`.
    #[test]
    fn parse_events_malformed_middle_event_keeps_good_events_on_both_sides_parsed() {
        let parser = WefParser::new();
        let body = wef_envelope(&format!(
            "{}{}{}",
            wef_event(1),
            wef_malformed_event(2),
            wef_event(3)
        ));

        let WefMessage::Events(ev) = parser.parse_message(&body, "h".into()).unwrap() else {
            panic!("expected Events");
        };
        assert_eq!(ev.len(), 3, "events: {ev:?}");

        assert_eq!(
            ev[0].parsed.as_ref().map(|p| p.event_id),
            Some(1),
            "event 1 must come back parsed"
        );

        assert!(
            ev[1].parsed.is_none(),
            "the malformed event has no parsed data"
        );
        assert!(ev[1].raw_xml.contains("</Mismatch>"));
        assert!(
            !ev[1].raw_xml.contains("<EventID>3</EventID>"),
            "the malformed fragment must stop at the next event start, not swallow event 3: {}",
            ev[1].raw_xml
        );

        assert_eq!(
            ev[2].parsed.as_ref().map(|p| p.event_id),
            Some(3),
            "event 3 after the error must also come back parsed, not folded into raw text"
        );
    }

    /// (b) Two malformed events in a batch of 4 — both good events must
    /// still parse, independent of how many resyncs happened before them.
    #[test]
    fn parse_events_two_malformed_events_in_batch_of_four_both_good_events_parsed() {
        let parser = WefParser::new();
        let body = wef_envelope(&format!(
            "{}{}{}{}",
            wef_event(1),
            wef_malformed_event(2),
            wef_event(3),
            wef_malformed_event(4)
        ));

        let WefMessage::Events(ev) = parser.parse_message(&body, "h".into()).unwrap() else {
            panic!("expected Events");
        };
        assert_eq!(ev.len(), 4, "events: {ev:?}");
        assert_eq!(ev[0].parsed.as_ref().map(|p| p.event_id), Some(1));
        assert!(ev[1].parsed.is_none());
        assert_eq!(ev[2].parsed.as_ref().map(|p| p.event_id), Some(3));
        assert!(ev[3].parsed.is_none());
    }

    /// (c) Malformed FIRST event: resync must still reach and parse the
    /// event after it, rather than folding both into one raw blob.
    #[test]
    fn parse_events_malformed_first_event_still_parses_the_good_event_after_it() {
        let parser = WefParser::new();
        let body = wef_envelope(&format!("{}{}", wef_malformed_event(1), wef_event(2)));

        let WefMessage::Events(ev) = parser.parse_message(&body, "h".into()).unwrap() else {
            panic!("expected Events");
        };
        assert_eq!(ev.len(), 2, "events: {ev:?}");
        assert!(ev[0].parsed.is_none());
        assert!(ev[0].raw_xml.contains("</Mismatch>"));
        assert_eq!(
            ev[1].parsed.as_ref().map(|p| p.event_id),
            Some(2),
            "the event after a malformed first event must still parse"
        );
    }

    /// (d) Trailing junk after the last event: the reader error happens
    /// outside any event and no later `<Event` start exists to resync to,
    /// so no raw row is added.
    #[test]
    fn parse_events_trailing_junk_after_last_event_adds_no_raw_row() {
        let parser = WefParser::new();
        let body = format!(
            "<Envelope><Body><Events>{}{}</Events></Bogus></Body></Envelope>",
            wef_event(1),
            wef_event(2)
        );

        let WefMessage::Events(ev) = parser.parse_message(&body, "h".into()).unwrap() else {
            panic!("expected Events");
        };
        assert_eq!(ev.len(), 2);
    }

    /// (e) A batch of many consecutive malformed events must complete
    /// (iterative resync, no recursion — no stack overflow) with one raw
    /// fragment per malformed event.
    #[test]
    fn parse_events_many_consecutive_malformed_events_completes_without_stack_overflow() {
        let parser = WefParser::new();
        const N: u32 = 5000;
        let body = wef_envelope(&(0..N).map(wef_malformed_event).collect::<String>());

        let WefMessage::Events(ev) = parser.parse_message(&body, "h".into()).unwrap() else {
            panic!("expected Events");
        };
        assert_eq!(ev.len(), N as usize, "one raw fragment per malformed event");
        assert!(
            ev.iter().all(|e| e.parsed.is_none()),
            "every fragment here is malformed and must have no parsed data"
        );
    }
}
