//! Integration: shipped fixtures run through the WEF event extraction path and the shipped
//! generic event parsers (hex integers, XML entities, tags carrying attributes).

mod common;

use logthing::parser::GenericEventParser;
use logthing::wef::event::extract_events;

fn shipped_parser() -> GenericEventParser {
    GenericEventParser::from_file(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/event_parsers"),
    )
    .expect("shipped parsers load")
}

#[test]
fn test_wef_ingest_hex_pid_fixture_is_parsed_by_shipped_parser() {
    let events = extract_events(&[common::wef_fixture("security_4689_hex_pid")], "h", "sub");
    assert_eq!(events.len(), 1);
    let id = events[0].parsed.as_ref().unwrap().event_id;
    assert_eq!(id, 4689);

    let got = shipped_parser()
        .parse_event(id, &events[0].raw_xml)
        .expect("4689 with hex PID must parse");
    assert_eq!(got.fields["ProcessId"], serde_json::json!(420));
    assert_eq!(got.fields["ProcessName"], "C:\\Windows\\System32\\AT&T.exe");
    assert_eq!(
        got.formatted_message.as_deref(),
        Some("C:\\Windows\\System32\\AT&T.exe (PID 420) terminated")
    );
}

#[test]
fn test_wef_ingest_system_7045_fixture_event_id_tag_with_attributes() {
    let events = extract_events(&[common::wef_fixture("system_7045")], "h", "sub");
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    assert!(ev.raw_xml.contains("<EventID Qualifiers=\"16384\">7045"));

    let mut file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(
        &mut file,
        b"event_parsers:\n  7045:\n    name: \"svc\"\n    description: \"d\"\n    fields:\n      \
          - name: \"EventID\"\n        source: system\n        xpath: \"EventID\"\n        \
          required: true\n        type: integer\n",
    )
    .unwrap();
    let parser = GenericEventParser::from_file(file.path()).unwrap();
    let got = parser.parse_event(7045, &ev.raw_xml).expect("must parse");
    assert_eq!(got.fields["EventID"], serde_json::json!(7045));
}
