//! Namespace-aware WS-Management SOAP envelope parsing and response building.
//!
//! Windows clients choose their own namespace prefixes, so elements are matched on
//! (namespace URI, local name) and never on the prefix.

use std::borrow::Cow;

use anyhow::{Context, anyhow, bail};
use quick_xml::NsReader;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;

use super::encoding::encode_utf16le_bom;

/// Action URI of a WS-Enumeration `Enumerate` request.
pub const ACTION_ENUMERATE: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate";
/// Action URI of an `EnumerateResponse`.
pub const ACTION_ENUMERATE_RESPONSE: &str =
    "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse";
/// Action URI of a WS-Eventing `Subscribe`.
pub const ACTION_SUBSCRIBE: &str = "http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe";
/// Action URI of a client heartbeat.
pub const ACTION_HEARTBEAT: &str = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Heartbeat";
/// Action URI of an event delivery.
pub const ACTION_EVENTS: &str = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Events";
/// Action URI of an acknowledgement.
pub const ACTION_ACK: &str = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Ack";
/// Action URI of a `SubscriptionEnd` notification.
pub const ACTION_SUBSCRIPTION_END: &str =
    "http://schemas.xmlsoap.org/ws/2004/08/eventing/SubscriptionEnd";
/// Action URI of a Microsoft `End` message.
pub const ACTION_END: &str = "http://schemas.microsoft.com/wbem/wsman/1/wsman/End";
/// The WS-Addressing anonymous reply address.
pub const ADDRESS_ANONYMOUS: &str =
    "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";

const NS_SOAP: &str = "http://www.w3.org/2003/05/soap-envelope";
const NS_ADDRESSING: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
const NS_WSMAN: &str = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd";
const NS_MS_WSMAN: &str = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd";
const NS_ENUMERATION: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration";
const NS_EVENTING: &str = "http://schemas.xmlsoap.org/ws/2004/08/eventing";
const NS_MACHINEID: &str = "http://schemas.microsoft.com/wbem/wsman/1/machineid";

/// The request kinds a WEF client sends that this server distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WefAction {
    /// Subscription enumeration.
    Enumerate,
    /// Empty keep-alive delivery.
    Heartbeat,
    /// Event delivery.
    Events,
    /// Source-side subscription termination.
    SubscriptionEnd,
    /// Connection end notification.
    End,
    /// Anything else (including a wrong-namespace Action element).
    Unknown,
}

/// The parts of a SOAP request envelope the server cares about.
#[derive(Debug)]
pub struct SoapRequest {
    /// Classified action.
    pub action: WefAction,
    /// Raw (trimmed) action URI; empty when no addressing `Action` element was found.
    pub action_uri: String,
    /// `a:MessageID`, verbatim.
    pub message_id: Option<String>,
    /// `a:ReplyTo/a:Address`.
    pub reply_to: Option<String>,
    /// `m:MachineID`, trimmed.
    pub machine_id: Option<String>,
    /// Header `e:Identifier`, trimmed.
    pub identifier: Option<String>,
    /// `p:OperationID`.
    pub operation_id: Option<String>,
    /// Inner XML of `w:Bookmark`, verbatim from the source.
    pub bookmark: Option<String>,
    /// Text/CDATA content of each `w:Event`, in order (Events action only).
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Action,
    MessageId,
    Address,
    MachineId,
    Identifier,
    OperationId,
}

#[derive(Debug)]
struct Capture {
    field: Option<Field>,
    depth: usize,
    text: String,
    nested: bool,
}

fn classify(uri: &str) -> WefAction {
    match uri {
        ACTION_ENUMERATE => WefAction::Enumerate,
        ACTION_HEARTBEAT => WefAction::Heartbeat,
        ACTION_EVENTS => WefAction::Events,
        ACTION_SUBSCRIPTION_END => WefAction::SubscriptionEnd,
        ACTION_END => WefAction::End,
        _ => WefAction::Unknown,
    }
}

/// Parses a SOAP envelope, matching on (namespace URI, local name), never on prefixes.
///
/// Errors when the document is malformed or its root is not a SOAP 1.2 `Envelope`.
pub fn parse(xml: &str) -> anyhow::Result<SoapRequest> {
    let mut reader = NsReader::from_str(xml);
    let mut req = SoapRequest {
        action: WefAction::Unknown,
        action_uri: String::new(),
        message_id: None,
        reply_to: None,
        machine_id: None,
        identifier: None,
        operation_id: None,
        bookmark: None,
        events: Vec::new(),
    };
    let mut depth = 0usize;
    let mut seen_root = false;
    let mut header_depth: Option<usize> = None;
    let mut body_depth: Option<usize> = None;
    let mut reply_to_depth: Option<usize> = None;
    let mut events_depth: Option<usize> = None;
    let mut capture: Option<Capture> = None;
    let mut bookmark: Option<(usize, usize)> = None; // (element depth, inner start offset)

    loop {
        let pos_before = reader.buffer_position();
        let (ns, ev) = reader.read_resolved_event().context("malformed SOAP XML")?;
        let uri: Option<String> = match &ns {
            ResolveResult::Bound(n) => Some(String::from_utf8_lossy(n.as_ref()).into_owned()),
            _ => None,
        };
        match ev {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let is_empty = matches!(ev, Event::Empty(_));
                let local = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                let key = (uri.as_deref().unwrap_or(""), local.as_str());
                if !seen_root {
                    if key != (NS_SOAP, "Envelope") {
                        bail!("not a SOAP envelope");
                    }
                    seen_root = true;
                }
                if let Some(c) = capture.as_mut() {
                    c.nested = true;
                }
                let child_depth = depth + 1;
                if bookmark.is_none() && capture.is_none() {
                    let in_header = header_depth.is_some();
                    match key {
                        (NS_SOAP, "Header") if depth == 1 && !is_empty => {
                            header_depth = Some(child_depth)
                        }
                        (NS_SOAP, "Body") if depth == 1 && !is_empty => {
                            body_depth = Some(child_depth)
                        }
                        (NS_ADDRESSING, "ReplyTo") if in_header && !is_empty => {
                            reply_to_depth = Some(child_depth)
                        }
                        (NS_WSMAN, "Events") if body_depth.is_some() && !is_empty => {
                            events_depth = Some(child_depth)
                        }
                        (NS_WSMAN, "Bookmark") if in_header => {
                            if !is_empty {
                                bookmark = Some((child_depth, reader.buffer_position()));
                            } else {
                                req.bookmark = Some(String::new());
                            }
                        }
                        (NS_WSMAN, "Event") if events_depth.is_some() && !is_empty => {
                            capture = Some(Capture {
                                field: None,
                                depth: child_depth,
                                text: String::new(),
                                nested: false,
                            });
                        }
                        _ if in_header && !is_empty => {
                            let field = match key {
                                (NS_ADDRESSING, "Action") => Some(Field::Action),
                                (NS_ADDRESSING, "MessageID") => Some(Field::MessageId),
                                (NS_ADDRESSING, "Address") if reply_to_depth.is_some() => {
                                    Some(Field::Address)
                                }
                                (NS_MACHINEID, "MachineID") => Some(Field::MachineId),
                                (NS_EVENTING, "Identifier") => Some(Field::Identifier),
                                (NS_MS_WSMAN, "OperationID") => Some(Field::OperationId),
                                _ => None,
                            };
                            if let Some(f) = field {
                                capture = Some(Capture {
                                    field: Some(f),
                                    depth: child_depth,
                                    text: String::new(),
                                    nested: false,
                                });
                            }
                        }
                        _ => {}
                    }
                }
                if !is_empty {
                    depth = child_depth;
                }
            }
            Event::Text(ref t) => {
                if let Some(c) = capture.as_mut() {
                    c.text
                        .push_str(&t.unescape().context("bad text in SOAP XML")?);
                }
            }
            Event::CData(ref t) => {
                if let Some(c) = capture.as_mut() {
                    c.text.push_str(&String::from_utf8_lossy(t.as_ref()));
                }
            }
            Event::End(_) => {
                if let Some((bd, start)) = bookmark
                    && bd == depth
                {
                    req.bookmark = Some(xml[start..pos_before].to_string());
                    bookmark = None;
                }
                if capture.as_ref().is_some_and(|c| c.depth == depth) {
                    let c = capture.take().expect("checked above");
                    let trimmed = c.text.trim().to_string();
                    match c.field {
                        None => {
                            if !c.nested {
                                req.events.push(c.text);
                            }
                        }
                        Some(Field::Action) => req.action_uri = trimmed,
                        // MessageID is kept untrimmed (only blank ones drop out) so RelatesTo
                        // echoes the client's exact bytes.
                        Some(Field::MessageId) => {
                            req.message_id = (!trimmed.is_empty()).then_some(c.text)
                        }
                        Some(Field::Address) => {
                            req.reply_to = (!trimmed.is_empty()).then_some(trimmed)
                        }
                        Some(Field::MachineId) => req.machine_id = Some(trimmed),
                        Some(Field::Identifier) => {
                            req.identifier.get_or_insert(trimmed);
                        }
                        Some(Field::OperationId) => req.operation_id = Some(trimmed),
                    }
                }
                if header_depth == Some(depth) {
                    header_depth = None;
                }
                if body_depth == Some(depth) {
                    body_depth = None;
                }
                if reply_to_depth == Some(depth) {
                    reply_to_depth = None;
                }
                if events_depth == Some(depth) {
                    events_depth = None;
                }
                depth = depth.saturating_sub(1);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !seen_root {
        bail!("not a SOAP envelope");
    }
    if depth != 0 {
        bail!("truncated SOAP envelope");
    }
    req.action = classify(&req.action_uri);
    if req.action != WefAction::Events {
        req.events.clear();
    }
    Ok(req)
}

/// Escapes `&`, `<`, `>`, `"` and `'` for use in XML text or attribute values.
pub(crate) fn xml_escape(s: &str) -> Cow<'_, str> {
    if !s.contains(['&', '<', '>', '"', '\'']) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// Returns a fresh message id: `uuid:` followed by an uppercase hyphenated v4 UUID.
pub fn new_message_id() -> String {
    format!(
        "uuid:{}",
        uuid::Uuid::new_v4().hyphenated().to_string().to_uppercase()
    )
}

fn envelope(
    req: &SoapRequest,
    action: &str,
    extra_ns: &str,
    body: &str,
) -> anyhow::Result<Vec<u8>> {
    let relates_to = req
        .message_id
        .as_deref()
        .ok_or_else(|| anyhow!("request has no MessageID to relate the response to"))?;
    let operation_id = req.operation_id.as_deref().map_or_else(String::new, |o| {
        format!(
            "<p:OperationID s:mustUnderstand=\"false\">{}</p:OperationID>",
            xml_escape(o)
        )
    });
    let to = req.reply_to.as_deref().unwrap_or(ADDRESS_ANONYMOUS);
    let xml = format!(
        "<s:Envelope xml:lang=\"en-US\" xmlns:s=\"{NS_SOAP}\" xmlns:a=\"{NS_ADDRESSING}\" \
         xmlns:w=\"{NS_WSMAN}\" xmlns:p=\"{NS_MS_WSMAN}\"{extra_ns}>\
         <s:Header><a:Action>{action}</a:Action><a:MessageID>{mid}</a:MessageID>\
         {operation_id}<p:SequenceId>1</p:SequenceId><a:To>{to}</a:To>\
         <a:RelatesTo>{relates}</a:RelatesTo></s:Header>\
         <s:Body>{body}</s:Body></s:Envelope>",
        mid = new_message_id(),
        to = xml_escape(to),
        relates = xml_escape(relates_to),
    );
    Ok(encode_utf16le_bom(&xml))
}

/// Builds an Ack response (UTF-16LE with BOM, no XML declaration) for `req`.
///
/// Errors when the request carried no `MessageID`.
pub fn build_ack(req: &SoapRequest) -> anyhow::Result<Vec<u8>> {
    envelope(req, ACTION_ACK, "", "")
}

/// Builds an `EnumerateResponse` wrapping already-rendered subscription item strings.
///
/// Items are inserted verbatim (they may declare their own namespaces).
pub fn build_enumerate_response(req: &SoapRequest, items: &[String]) -> anyhow::Result<Vec<u8>> {
    let body = format!(
        "<n:EnumerateResponse><n:EnumerationContext></n:EnumerationContext>\
         <w:Items>{}</w:Items><w:EndOfSequence/></n:EnumerateResponse>",
        items.concat()
    );
    envelope(
        req,
        ACTION_ENUMERATE_RESPONSE,
        &format!(" xmlns:n=\"{NS_ENUMERATION}\""),
        &body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wef::encoding::decode_body;

    const ENUMERATE: &str = include_str!("../../tests/fixtures/wef/golden/enumerate.xml");
    const HEARTBEAT: &str = include_str!("../../tests/fixtures/wef/golden/heartbeat.xml");
    const EVENTS: &str = include_str!("../../tests/fixtures/wef/golden/events.xml");
    const SUB_END: &str = include_str!("../../tests/fixtures/wef/golden/subscription_end.xml");
    const END: &str = include_str!("../../tests/fixtures/wef/golden/end.xml");

    fn req_with(message_id: Option<&str>) -> SoapRequest {
        SoapRequest {
            action: WefAction::Events,
            action_uri: ACTION_EVENTS.into(),
            message_id: message_id.map(String::from),
            reply_to: None,
            machine_id: None,
            identifier: None,
            operation_id: None,
            bookmark: None,
            events: vec![],
        }
    }

    const MINI_NS: &str = "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" \
         xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"";

    #[test]
    fn test_parse_truncated_envelope_errors() {
        let xml = format!("<s:Envelope {MINI_NS}><s:Header><a:MessageID>uuid:1</a:MessageID>");
        assert!(parse(&xml).is_err());
    }

    #[test]
    fn test_parse_empty_reply_to_address_is_none() {
        let xml = format!(
            "<s:Envelope {MINI_NS}><s:Header><a:MessageID>uuid:1</a:MessageID>\
             <a:ReplyTo><a:Address></a:Address></a:ReplyTo></s:Header><s:Body/></s:Envelope>"
        );
        let req = parse(&xml).unwrap();
        assert_eq!(req.reply_to, None);
        let ack = decode(&build_ack(&req).unwrap());
        assert!(ack.contains(ADDRESS_ANONYMOUS));
    }

    #[test]
    fn test_parse_empty_message_id_is_none_and_ack_errors() {
        let xml = format!(
            "<s:Envelope {MINI_NS}><s:Header><a:MessageID>  </a:MessageID></s:Header>\
             <s:Body/></s:Envelope>"
        );
        let req = parse(&xml).unwrap();
        assert_eq!(req.message_id, None);
        assert!(build_ack(&req).is_err());
    }

    fn decode(bytes: &[u8]) -> String {
        decode_body(bytes).unwrap()
    }

    /// Collects (namespace, local name, direct text) for every element.
    fn elements(xml: &str) -> Vec<(String, String, String)> {
        let mut r = NsReader::from_str(xml);
        let mut out: Vec<(String, String, String)> = Vec::new();
        let mut stack: Vec<usize> = Vec::new();
        loop {
            let (ns, ev) = r.read_resolved_event().unwrap();
            let start = |ns: &ResolveResult, e: &quick_xml::events::BytesStart| {
                let u = match ns {
                    ResolveResult::Bound(n) => String::from_utf8_lossy(n.as_ref()).into_owned(),
                    _ => String::new(),
                };
                (
                    u,
                    String::from_utf8_lossy(e.local_name().as_ref()).into_owned(),
                    String::new(),
                )
            };
            match ev {
                Event::Start(e) => {
                    out.push(start(&ns, &e));
                    stack.push(out.len() - 1);
                }
                Event::Empty(e) => out.push(start(&ns, &e)),
                Event::Text(t) => {
                    if let Some(&i) = stack.last() {
                        out[i].2.push_str(&t.unescape().unwrap());
                    }
                }
                Event::End(_) => {
                    stack.pop();
                }
                Event::Eof => break,
                _ => {}
            }
        }
        out
    }

    fn text_of(els: &[(String, String, String)], ns: &str, local: &str) -> Option<String> {
        els.iter()
            .find(|e| e.0 == ns && e.1 == local)
            .map(|e| e.2.clone())
    }

    #[test]
    fn test_parse_enumerate_golden() {
        let r = parse(ENUMERATE).unwrap();
        assert_eq!(r.action, WefAction::Enumerate);
        assert_eq!(r.action_uri, ACTION_ENUMERATE);
        assert_eq!(
            r.message_id.as_deref(),
            Some("uuid:6F2C1A8E-3B4D-4E5F-8A9B-0C1D2E3F4A5B")
        );
        assert_eq!(r.reply_to.as_deref(), Some(ADDRESS_ANONYMOUS));
        assert_eq!(r.machine_id.as_deref(), Some("win10.example.com"));
        assert_eq!(
            r.operation_id.as_deref(),
            Some("uuid:8A1B2C3D-4E5F-4607-8192-A3B4C5D6E7F8")
        );
        assert!(r.events.is_empty());
        assert!(r.bookmark.is_none());
    }

    #[test]
    fn test_parse_trims_machine_id_and_identifier() {
        let r = parse(HEARTBEAT).unwrap();
        assert_eq!(r.machine_id.as_deref(), Some("win10.example.com"));
        assert_eq!(
            r.identifier.as_deref(),
            Some("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0")
        );
    }

    #[test]
    fn test_parse_heartbeat_golden() {
        let r = parse(HEARTBEAT).unwrap();
        assert_eq!(r.action, WefAction::Heartbeat);
        assert!(r.events.is_empty());
    }

    #[test]
    fn test_parse_events_golden_extracts_two_cdata_events_and_bookmark() {
        let r = parse(EVENTS).unwrap();
        assert_eq!(r.action, WefAction::Events);
        assert_eq!(r.events.len(), 2);
        assert!(r.events[0].starts_with("<Event xmlns="));
        assert!(r.events[0].contains("<EventID>4624</EventID>"));
        assert!(r.events[1].contains("<EventID Qualifiers='16384'>7045</EventID>"));
        let b = r.bookmark.unwrap();
        assert!(b.contains("<BookmarkList>"));
        assert!(b.contains("RecordId=\"1042\""));
        assert!(b.starts_with("<BookmarkList>") && b.ends_with("</BookmarkList>"));
    }

    #[test]
    fn test_parse_subscription_end_golden() {
        let r = parse(SUB_END).unwrap();
        assert_eq!(r.action, WefAction::SubscriptionEnd);
        assert_eq!(r.machine_id.as_deref(), Some("win10.example.com"));
        assert!(
            r.identifier.is_none(),
            "body Identifier is not a header field"
        );
        assert!(r.reply_to.is_none());
    }

    #[test]
    fn test_parse_end_golden() {
        let r = parse(END).unwrap();
        assert_eq!(r.action, WefAction::End);
        assert_eq!(r.action_uri, ACTION_END);
    }

    #[test]
    fn test_parse_matches_namespace_not_prefix() {
        let renamed = EVENTS
            .replace("xmlns:s=", "xmlns:x=")
            .replace("<s:", "<x:")
            .replace("</s:", "</x:")
            .replace(" s:mustUnderstand", " x:mustUnderstand")
            .replace("xmlns:w=", "xmlns:y=")
            .replace("<w:", "<y:")
            .replace("</w:", "</y:");
        let a = parse(EVENTS).unwrap();
        let b = parse(&renamed).unwrap();
        assert_eq!(b.action, a.action);
        assert_eq!(b.message_id, a.message_id);
        assert_eq!(b.machine_id, a.machine_id);
        assert_eq!(b.bookmark, a.bookmark);
        assert_eq!(b.events, a.events);
        assert_eq!(b.events.len(), 2);
    }

    #[test]
    fn test_parse_wrong_namespace_action_element_is_unknown() {
        let x = ENUMERATE.replace(
            "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"",
            "xmlns:a=\"http://example.com/other\"",
        );
        let r = parse(&x).unwrap();
        assert_eq!(r.action, WefAction::Unknown);
        assert_eq!(r.action_uri, "");
    }

    #[test]
    fn test_parse_non_soap_errors() {
        assert!(parse("<html><body/></html>").is_err());
        assert!(parse("").is_err());
        assert!(parse("<s:Envelope").is_err());
        assert!(parse("<Envelope xmlns=\"urn:other\"/>").is_err());
    }

    #[test]
    fn test_parse_unknown_action_is_unknown() {
        let x = ENUMERATE.replace(ACTION_ENUMERATE, "http://example.com/Nope");
        let r = parse(&x).unwrap();
        assert_eq!(r.action, WefAction::Unknown);
        assert_eq!(r.action_uri, "http://example.com/Nope");
    }

    #[test]
    fn test_parse_events_non_cdata_escaped_text() {
        let x = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" \
                 xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
                 xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\">\
                 <s:Header><a:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/Events</a:Action>\
                 </s:Header><s:Body><w:Events><w:Event>&lt;Event a=&apos;1&apos;&gt;&amp;amp;\
                 &lt;/Event&gt;</w:Event></w:Events></s:Body></s:Envelope>";
        let r = parse(x).unwrap();
        assert_eq!(r.events, vec!["<Event a='1'>&amp;</Event>".to_string()]);
    }

    #[test]
    fn test_parse_events_nested_element_event_skipped() {
        let x = EVENTS.replacen(
            "<w:Event Action=\"http://schemas.dmtf.org/wbem/wsman/1/wsman/Event\">",
            "<w:Event><Nested>x</Nested></w:Event><w:Event Action=\"a\">ok</w:Event>\
             <w:Event Action=\"http://schemas.dmtf.org/wbem/wsman/1/wsman/Event\">",
            1,
        );
        let r = parse(&x).unwrap();
        assert_eq!(r.events.len(), 3);
        assert_eq!(r.events[0], "ok");
        assert!(r.events[1].starts_with("<Event"));
    }

    #[test]
    fn test_build_ack_relates_to_echoes_message_id_exactly() {
        for id in [
            "uuid:abcdef00-1111-2222-3333-444455556666",
            "uuid:ABCDEF00-1111",
        ] {
            let out = decode(&build_ack(&req_with(Some(id))).unwrap());
            let els = elements(&out);
            assert_eq!(
                text_of(&els, NS_ADDRESSING, "RelatesTo").as_deref(),
                Some(id)
            );
        }
    }

    #[test]
    fn test_build_ack_is_utf16le_bom_without_xml_decl() {
        let bytes = build_ack(&req_with(Some("uuid:1"))).unwrap();
        assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
        let s = decode(&bytes);
        assert!(!s.contains("<?xml"));
        assert!(s.starts_with("<s:Envelope xml:lang=\"en-US\""));
        let els = elements(&s);
        assert_eq!(
            text_of(&els, NS_ADDRESSING, "Action").as_deref(),
            Some(ACTION_ACK)
        );
        assert_eq!(
            text_of(&els, NS_MS_WSMAN, "SequenceId").as_deref(),
            Some("1")
        );
        assert_eq!(
            text_of(&els, NS_ADDRESSING, "To").as_deref(),
            Some(ADDRESS_ANONYMOUS)
        );
        let mid = text_of(&els, NS_ADDRESSING, "MessageID").unwrap();
        assert!(mid.starts_with("uuid:"));
    }

    #[test]
    fn test_build_ack_body_empty() {
        let s = decode(&build_ack(&req_with(Some("uuid:1"))).unwrap());
        assert!(s.contains("<s:Body></s:Body>"));
    }

    #[test]
    fn test_build_ack_echoes_operation_id() {
        let mut r = req_with(Some("uuid:1"));
        r.operation_id = Some("uuid:OP-1".into());
        r.reply_to = Some("http://reply.example/x".into());
        let els = elements(&decode(&build_ack(&r).unwrap()));
        assert_eq!(
            text_of(&els, NS_MS_WSMAN, "OperationID").as_deref(),
            Some("uuid:OP-1")
        );
        assert_eq!(
            text_of(&els, NS_ADDRESSING, "To").as_deref(),
            Some("http://reply.example/x")
        );
        let none = decode(&build_ack(&req_with(Some("uuid:1"))).unwrap());
        assert!(!none.contains("OperationID"));
    }

    #[test]
    fn test_build_ack_without_message_id_errors() {
        assert!(build_ack(&req_with(None)).is_err());
        assert!(build_enumerate_response(&req_with(None), &[]).is_err());
    }

    #[test]
    fn test_new_message_id_format() {
        let id = new_message_id();
        assert!(id.starts_with("uuid:"));
        let u = &id[5..];
        assert_eq!(u.len(), 36);
        assert_eq!(u, u.to_uppercase());
        assert_ne!(id, new_message_id());
    }

    #[test]
    fn test_build_enumerate_response_contains_items_and_end_of_sequence() {
        let items = vec![
            "<m:Subscription xmlns:m=\"urn:x\"><m:Id>1</m:Id></m:Subscription>".to_string(),
            "<m:Subscription xmlns:m=\"urn:x\"><m:Id>2</m:Id></m:Subscription>".to_string(),
        ];
        let s = decode(&build_enumerate_response(&req_with(Some("uuid:9")), &items).unwrap());
        assert!(s.contains(&format!("xmlns:n=\"{NS_ENUMERATION}\"")));
        assert!(s.contains(&items.concat()));
        assert!(s.contains("<w:EndOfSequence/>"));
        let els = elements(&s);
        assert_eq!(
            text_of(&els, NS_ADDRESSING, "Action").as_deref(),
            Some(ACTION_ENUMERATE_RESPONSE)
        );
        assert!(
            els.iter()
                .any(|e| e.0 == NS_ENUMERATION && e.1 == "EnumerationContext")
        );
        assert_eq!(els.iter().filter(|e| e.1 == "Subscription").count(), 2);
        assert_eq!(
            text_of(&els, NS_ADDRESSING, "RelatesTo").as_deref(),
            Some("uuid:9")
        );
    }

    #[test]
    fn test_builders_escape_xml_in_reply_to() {
        let mut r = req_with(Some("uuid:<1>&"));
        r.reply_to = Some("http://h/?a=1&b=<2>".into());
        let s = decode(&build_ack(&r).unwrap());
        assert!(s.contains("http://h/?a=1&amp;b=&lt;2&gt;"));
        assert!(s.contains("uuid:&lt;1&gt;&amp;"));
        let els = elements(&s);
        assert_eq!(
            text_of(&els, NS_ADDRESSING, "To").as_deref(),
            Some("http://h/?a=1&b=<2>")
        );
    }

    #[test]
    fn test_xml_escape_borrows_when_clean() {
        assert!(matches!(xml_escape("plain"), Cow::Borrowed(_)));
        assert_eq!(xml_escape("a'\"b"), "a&apos;&quot;b");
    }
}
