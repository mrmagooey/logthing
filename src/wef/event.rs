//! Extraction of structured fields from Windows event XML.
//!
//! Each WEF `<Event>` payload (a CDATA section in the SOAP body) is parsed with
//! local-name matching, so the event namespace prefix or default namespace never matters.

use std::borrow::Cow;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event as XmlEvent};
use serde_json::{Map, Value};
use tracing::{debug, error};

use crate::models::{EventLevel, ParsedEvent, WindowsEvent};

fn is_illegal_xml_char(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}' | '\u{FFFE}' | '\u{FFFF}')
}

/// Replace characters that are illegal in XML 1.0 (U+0000-U+0008, U+000B, U+000C,
/// U+000E-U+001F, U+FFFE, U+FFFF) with the literal text `\u{XXXX}`.
///
/// Windows happily puts such characters in event data (for example raw control bytes in
/// command lines); a strict XML parser would reject the whole event. Tab, LF and CR are
/// kept. Borrows the input when it is already clean.
pub fn sanitize_xml_chars(s: &str) -> Cow<'_, str> {
    if !s.chars().any(is_illegal_xml_char) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if is_illegal_xml_char(c) {
            out.push_str(&format!("\\u{{{:04X}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

fn local(name: &[u8]) -> String {
    let n = name.rsplit(|b| *b == b':').next().unwrap_or(name);
    String::from_utf8_lossy(n).into_owned()
}

fn attr(e: &BytesStart<'_>, key: &str) -> Option<String> {
    e.attributes().flatten().find_map(|a| {
        (local(a.key.as_ref()) == key)
            .then(|| a.unescape_value().ok().map(|v| v.into_owned()))
            .flatten()
    })
}

fn num<T: std::str::FromStr + Default>(field: &str, text: &str) -> T {
    text.trim().parse().unwrap_or_else(|_| {
        debug!(
            "Unparsable {field} {:?}, defaulting",
            crate::sanitize_for_log(text, 64)
        );
        T::default()
    })
}

#[derive(Default)]
struct Builder {
    p: Option<ParsedEvent>,
    rendered: Option<String>,
    first_data: Option<String>,
    data: Map<String, Value>,
    cur_data_key: Option<String>,
    unnamed: usize,
}

impl Builder {
    fn start(&mut self, path: &[String], e: &BytesStart<'_>) {
        let name = path.last().map(String::as_str).unwrap_or("");
        let in_system = path.iter().any(|s| s == "System");
        let p = self.p.get_or_insert_with(blank);
        match name {
            "Provider" if in_system => p.provider = attr(e, "Name").unwrap_or_default(),
            "TimeCreated" if in_system => {
                if let Some(t) =
                    attr(e, "SystemTime").and_then(|v| DateTime::parse_from_rfc3339(&v).ok())
                {
                    p.time_created = t.with_timezone(&Utc);
                }
            }
            "Execution" if in_system => {
                p.process_id = attr(e, "ProcessID").and_then(|v| v.trim().parse().ok());
                p.thread_id = attr(e, "ThreadID").and_then(|v| v.trim().parse().ok());
            }
            "Security" if in_system => p.security_user_id = attr(e, "UserID"),
            "Data" if parent(path) == "EventData" => {
                let key = attr(e, "Name").unwrap_or_else(|| {
                    self.unnamed += 1;
                    if self.unnamed == 1 {
                        "Data".into()
                    } else {
                        format!("Data{}", self.unnamed - 1)
                    }
                });
                self.data
                    .entry(key.clone())
                    .or_insert_with(|| Value::String(String::new()));
                self.cur_data_key = Some(key);
            }
            _ => {}
        }
    }

    fn text(&mut self, path: &[String], text: &str) {
        let name = path.last().map(String::as_str).unwrap_or("");
        let in_system = path.iter().any(|s| s == "System");
        let p = self.p.get_or_insert_with(blank);
        match name {
            "EventID" if in_system => p.event_id = num("EventID", text),
            "Level" if in_system => {
                p.level = match num::<u8>("Level", text) {
                    1 => EventLevel::Critical,
                    2 => EventLevel::Error,
                    3 => EventLevel::Warning,
                    5 => EventLevel::Verbose,
                    _ => EventLevel::Information,
                }
            }
            "Task" if in_system => p.task = num("Task", text),
            "Opcode" if in_system => p.opcode = num("Opcode", text),
            "Keywords" if in_system => {
                let t = text.trim();
                let h = t
                    .strip_prefix("0x")
                    .or_else(|| t.strip_prefix("0X"))
                    .unwrap_or(t);
                p.keywords = u64::from_str_radix(h, 16).unwrap_or(0);
            }
            "EventRecordID" if in_system => p.event_record_id = num("EventRecordID", text),
            "Channel" if in_system => p.channel = text.to_string(),
            "Computer" if in_system => p.computer = text.to_string(),
            "Message" if parent(path) == "RenderingInfo" => {
                self.rendered.get_or_insert_with(|| text.to_string());
            }
            "Data" if parent(path) == "EventData" => {
                if let Some(k) = &self.cur_data_key {
                    self.data.insert(k.clone(), Value::String(text.to_string()));
                }
                if !text.is_empty() {
                    self.first_data.get_or_insert_with(|| text.to_string());
                }
            }
            _ if path.iter().any(|s| s == "UserData") && name != "UserData" => {
                self.data
                    .insert(name.to_string(), Value::String(text.to_string()));
            }
            _ => {}
        }
    }
}

fn parent(path: &[String]) -> &str {
    path.len()
        .checked_sub(2)
        .map(|i| path[i].as_str())
        .unwrap_or("")
}

fn blank() -> ParsedEvent {
    ParsedEvent {
        provider: String::new(),
        event_id: 0,
        level: EventLevel::Information,
        task: 0,
        opcode: 0,
        keywords: 0,
        time_created: Utc::now(),
        event_record_id: 0,
        process_id: None,
        thread_id: None,
        channel: String::new(),
        computer: String::new(),
        security_user_id: None,
        message: None,
        data: None,
    }
}

/// Parse one event XML string (a WEF CDATA payload) into a [`ParsedEvent`].
///
/// Elements are matched by local name. `Level` 0 and 4 (and any unknown value) map to
/// `Information`; unparsable numeric fields, including a `Keywords` value that is not
/// `0x`-prefixed hex, default to 0; a missing or unparsable `TimeCreated` defaults to now.
/// `message` is the `RenderingInfo/Message` text when present, else the first non-empty
/// `EventData/Data` text. `data` maps `EventData/Data@Name` (unnamed ones become `Data`,
/// `Data1`, ...) or `UserData` leaf element names to their text.
///
/// # Errors
/// Fails on malformed XML (reader error or unclosed elements) or when there is no
/// `<Event>` root element.
pub fn parse_event(xml: &str) -> Result<ParsedEvent> {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);
    let mut b = Builder::default();
    let mut path: Vec<String> = Vec::new();
    let mut saw_event = false;
    loop {
        match reader.read_event().context("malformed event XML")? {
            XmlEvent::Start(e) => {
                path.push(local(e.name().as_ref()));
                saw_event |= path.len() == 1 && path[0] == "Event";
                b.start(&path, &e);
            }
            XmlEvent::Empty(e) => {
                path.push(local(e.name().as_ref()));
                b.start(&path, &e);
                path.pop();
            }
            XmlEvent::End(_) => {
                path.pop();
            }
            XmlEvent::Text(t) => {
                let t = t.unescape().context("bad XML text")?;
                b.text(&path, &t);
            }
            XmlEvent::CData(c) => b.text(&path, &String::from_utf8_lossy(&c)),
            XmlEvent::Eof => break,
            _ => {}
        }
    }
    if !path.is_empty() {
        bail!(
            "unclosed element <{}> at end of event",
            path.last().unwrap()
        );
    }
    if !saw_event {
        bail!("no <Event> root element");
    }
    let mut p = b.p.unwrap_or_else(blank);
    p.message = b.rendered.or(b.first_data);
    if !b.data.is_empty() {
        p.data = Some(Value::Object(b.data));
    }
    Ok(p)
}

/// Sanitise and parse each payload into a [`WindowsEvent`].
///
/// A payload that fails to parse is skipped, increments the `wef_xml_parse_errors` counter,
/// and is reported in a single bounded `error!` line per call (the message embeds wire
/// bytes). `raw_xml` is the sanitised payload and `subscription_id` is `subscription_name`.
pub fn extract_events(
    payloads: &[String],
    source_host: &str,
    subscription_name: &str,
) -> Vec<WindowsEvent> {
    let mut out = Vec::with_capacity(payloads.len());
    let mut failed: u32 = 0;
    let mut first_err = String::new();
    for payload in payloads {
        let xml = sanitize_xml_chars(payload);
        match parse_event(&xml) {
            Ok(parsed) => {
                let mut ev = WindowsEvent::new(source_host.to_string(), xml.into_owned())
                    .with_parsed(parsed);
                ev.subscription_id = Some(subscription_name.to_string());
                out.push(ev);
            }
            Err(e) => {
                metrics::counter!("wef_xml_parse_errors").increment(1);
                if failed == 0 {
                    first_err = format!("{e:#}");
                }
                failed += 1;
            }
        }
    }
    if failed > 0 {
        error!(
            "XML parsing failed for {failed} event(s) in this WEF batch; first error: {}",
            crate::sanitize_for_log(&first_err, 200)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wef::soap;

    fn golden(i: usize) -> String {
        let xml = include_str!("../../tests/fixtures/wef/golden/events.xml");
        soap::parse(xml).unwrap().events[i].clone()
    }

    #[test]
    fn test_parse_event_security_4624_all_system_fields() {
        let p = parse_event(&golden(0)).unwrap();
        assert_eq!(p.provider, "Microsoft-Windows-Security-Auditing");
        assert_eq!(p.event_id, 4624);
        assert_eq!(p.task, 12544);
        assert_eq!(p.keywords, 0x8020000000000000);
        assert_eq!(p.event_record_id, 1041);
        assert_eq!(p.process_id, Some(636));
        assert_eq!(p.thread_id, Some(700));
        assert_eq!(p.channel, "Security");
        assert!(!p.computer.is_empty());
        assert_eq!(p.time_created.timestamp_subsec_nanos() % 100, 0);
        assert!(p.time_created.timestamp() > 0);
        assert!(p.data.unwrap()["TargetUserName"].is_string());
    }

    #[test]
    fn test_parse_event_rendering_info_message_preferred() {
        let p = parse_event(&golden(1)).unwrap();
        assert_eq!(p.event_id, 7045);
        assert!(p.message.unwrap().contains("service"));
    }

    #[test]
    fn test_parse_event_level_zero_is_information() {
        let p = parse_event(&golden(0)).unwrap();
        assert_eq!(p.level, EventLevel::Information);
        let x = "<Event><System><Level>2</Level></System></Event>";
        assert_eq!(parse_event(x).unwrap().level, EventLevel::Error);
    }

    #[test]
    fn test_parse_event_userdata_flattened() {
        let x = "<Event xmlns='u'><System><EventID>1102</EventID></System><UserData>\
                 <LogCleared xmlns='x'><SubjectUserName>bob</SubjectUserName>\
                 <SubjectLogonId>0x1</SubjectLogonId></LogCleared></UserData></Event>";
        let p = parse_event(x).unwrap();
        let d = p.data.unwrap();
        assert_eq!(d["SubjectUserName"], "bob");
        assert_eq!(d["SubjectLogonId"], "0x1");
    }

    #[test]
    fn test_parse_event_missing_optional_fields_defaults() {
        let p = parse_event("<Event><System><EventID>5</EventID></System></Event>").unwrap();
        assert_eq!(p.process_id, None);
        assert_eq!(p.thread_id, None);
        assert_eq!(p.security_user_id, None);
        assert_eq!(p.message, None);
        assert!(p.data.is_none());
    }

    #[test]
    fn test_parse_event_invalid_keywords_is_zero() {
        let x = "<Event><System><Keywords>bogus</Keywords></System></Event>";
        assert_eq!(parse_event(x).unwrap().keywords, 0);
    }

    #[test]
    fn test_parse_event_first_data_is_message_without_rendering_info() {
        let x = "<Event><System/><EventData><Data>hello</Data><Data>b</Data></EventData></Event>";
        let p = parse_event(x).unwrap();
        assert_eq!(p.message.as_deref(), Some("hello"));
        assert_eq!(p.data.unwrap()["Data1"], "b");
    }

    #[test]
    fn test_sanitize_xml_chars_replaces_controls_keeps_tab_lf_cr() {
        assert!(matches!(sanitize_xml_chars("a\tb\nc\r"), Cow::Borrowed(_)));
        assert_eq!(
            sanitize_xml_chars("a\u{4}b\u{FFFF}"),
            "a\\u{0004}b\\u{FFFF}"
        );
    }

    #[test]
    fn test_extract_events_sanitizes_illegal_xml_chars() {
        let x = "<Event><System><EventID>1</EventID></System>\
                 <EventData><Data Name=\"a\">x\u{4}y</Data></EventData></Event>";
        let evs = extract_events(&[x.to_string()], "h", "s");
        assert_eq!(evs.len(), 1);
        assert!(!evs[0].raw_xml.contains('\u{4}'));
        assert_eq!(
            evs[0].parsed.as_ref().unwrap().data.as_ref().unwrap()["a"],
            "x\\u{0004}y"
        );
    }

    #[test]
    #[allow(clippy::mutable_key_type)] // CompositeKey's AtomicBool is never hashed
    fn test_extract_events_skips_malformed_keeps_rest() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        let good = golden(0);
        let bad = good[..good.len() / 2].to_string();
        let payloads = [good.clone(), bad, golden(1)];
        let recorder = DebuggingRecorder::new();
        let snap = recorder.snapshotter();
        let evs = metrics::with_local_recorder(&recorder, || extract_events(&payloads, "h", "s"));
        assert_eq!(evs.len(), 2);
        let n: u64 = snap
            .snapshot()
            .into_hashmap()
            .into_iter()
            .filter(|(k, _)| k.key().name() == "wef_xml_parse_errors")
            .map(|(_, (_, _, v))| match v {
                DebugValue::Counter(c) => c,
                _ => 0,
            })
            .sum();
        assert_eq!(n, 1);
    }

    #[test]
    fn test_extract_events_sets_subscription_id() {
        let evs = extract_events(&[golden(0)], "host1", "sub-a");
        assert_eq!(evs[0].subscription_id.as_deref(), Some("sub-a"));
        assert_eq!(evs[0].source_host, "host1");
    }

    macro_rules! fixture_test {
        ($name:ident, $file:literal, $id:expr) => {
            #[test]
            fn $name() {
                let xml = include_str!(concat!("../../tests/fixtures/wef/events/", $file, ".xml"));
                let p = parse_event(&sanitize_xml_chars(xml)).unwrap();
                assert!(!p.provider.is_empty());
                assert_eq!(p.event_id, $id);
                assert!(!p.channel.is_empty());
                assert!(!p.computer.is_empty());
                assert!(p.event_record_id > 0);
            }
        };
    }

    fixture_test!(test_fixture_security_4624_parses, "security_4624", 4624);
    fixture_test!(test_fixture_security_4625_parses, "security_4625", 4625);
    fixture_test!(test_fixture_security_4672_parses, "security_4672", 4672);
    fixture_test!(test_fixture_security_4688_parses, "security_4688", 4688);
    fixture_test!(test_fixture_security_4768_parses, "security_4768", 4768);
    fixture_test!(test_fixture_security_4769_parses, "security_4769", 4769);
    fixture_test!(test_fixture_sysmon_1_parses, "sysmon_1", 1);
    fixture_test!(test_fixture_sysmon_3_parses, "sysmon_3", 3);
    fixture_test!(test_fixture_system_7045_parses, "system_7045", 7045);
    fixture_test!(test_fixture_rendered_7045_parses, "rendered_7045", 7045);
    fixture_test!(
        test_fixture_synth_illegal_char_parses,
        "synth_illegal_char",
        4624
    );

    #[test]
    fn test_fixture_rendered_7045_message_from_rendering_info() {
        let xml = include_str!("../../tests/fixtures/wef/events/rendered_7045.xml");
        let p = parse_event(xml).unwrap();
        assert_eq!(
            p.message.as_deref(),
            Some("A service was installed in the system.")
        );
    }

    #[test]
    fn test_fixture_synth_illegal_char_needs_sanitising() {
        let xml = include_str!("../../tests/fixtures/wef/events/synth_illegal_char.xml");
        assert!(matches!(sanitize_xml_chars(xml), Cow::Owned(_)));
    }
}
