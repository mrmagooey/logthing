//! Criterion micro-benchmarks: the WEF (Windows Event Forwarding) XML parse
//! cost of `GenericEventParser::parse_event`, exactly as
//! `src/server/mod.rs:947` runs it — once per event, after the SOAP envelope
//! has already been split into individual `<Event>` XML fragments by
//! `protocol::parse_events`. This is the field-extraction layer: a per-field
//! `str::find` scan through the event XML (`extract_from_event_data` /
//! `extract_from_system`), not a real XML parser (no quick-xml, no DOM).
//!
//! Deliberately NOT measured: SOAP envelope parsing (`protocol::parse_events`,
//! upstream of this), the HTTP/WS-Man transport layer, and
//! `WefSink::to_record_batch` (covered by `wef_to_record_batch.rs`). This is
//! the config-driven per-event-id extraction only.
//!
//! `GenericEventParser` is constructed once, outside every timed closure, by
//! loading the real production config directory `config/event_parsers/` —
//! loading YAML is setup, not the thing under test.
//!
//! Three fixtures, chosen from what already exists in this repo rather than
//! invented:
//!   - `logon_4624`: the canonical high-volume Security event (successful
//!     logon), 5 configured fields. Field names, xpaths and output-format
//!     template are copied verbatim from `config/event_parsers/4624_successful_logon.yaml`.
//!   - `failed_logon_4625`: the largest configured event in this repo by
//!     field count (6, vs. 5 for 4624) — see `config/event_parsers/4625_failed_logon.yaml`.
//!     No shipped parser config in this repo defines more than 6 fields, so
//!     this is genuinely the "many fields" case available, not an
//!     artificially inflated one.
//!   - `no_parser_9999`: an event id with no registered parser at all (9999,
//!     the same sentinel `src/parser/tests.rs` uses for "unknown event id").
//!     `parse_event`'s first line is `self.config.parsers.get(&event_id)?`,
//!     so this measures the miss path: one hash lookup and an early return,
//!     with none of the field-extraction loop ever running. This is the
//!     common case for the many WEF event ids nobody has written a parser
//!     for yet.
//!
//! The `<Event>` XML shape (attributes, element nesting, `Data Name="..."`
//! encoding) mirrors `tests/e2e/simulation-environment/wef-generator/entrypoint.py`'s
//! `build_event_xml`, which is what this repo's own WEF load generator sends
//! over the wire in the simulation e2e environment.
//!
//! Run with: `cargo bench --bench wef_parse_recv_path`

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::parser::GenericEventParser;
use std::hint::black_box;

/// 4624 (Successful Logon): 5 configured fields, matching
/// `config/event_parsers/4624_successful_logon.yaml` exactly.
const LOGON_4624_XML: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing">Microsoft-Windows-Security-Auditing</Provider>
    <EventID>4624</EventID>
    <Level>0</Level>
    <Task>12544</Task>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-13T12:00:00.000000Z">2026-09-13T12:00:00.000000Z</TimeCreated>
    <EventRecordID>4624001</EventRecordID>
    <Channel>Security</Channel>
    <Computer>TEST-HOST</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">192.0.2.10</Data>
    <Data Name="IpPort">49732</Data>
  </EventData>
</Event>"#;

/// 4625 (Failed Logon): 6 configured fields, the largest field count of any
/// parser shipped in `config/event_parsers/` today — see that directory's
/// header comment in this file for why this is the real "many fields" case
/// rather than a synthetic one.
const FAILED_LOGON_4625_XML: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing">Microsoft-Windows-Security-Auditing</Provider>
    <EventID>4625</EventID>
    <Level>0</Level>
    <Task>12544</Task>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-13T12:00:01.000000Z">2026-09-13T12:00:01.000000Z</TimeCreated>
    <EventRecordID>4625001</EventRecordID>
    <Channel>Security</Channel>
    <Computer>TEST-HOST</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC000006A</Data>
    <Data Name="IpAddress">192.0.2.11</Data>
  </EventData>
</Event>"#;

/// No parser is registered for event id 9999 in `config/event_parsers/` —
/// the same sentinel id `src/parser/tests.rs` uses for "unknown event id".
/// The XML body is irrelevant to the outcome (the hash-map miss on
/// `event_id` happens before any field is ever looked at), but it is kept
/// well-formed and 4624-shaped so the fixture cannot be mistaken for a
/// malformed-input test.
const NO_PARSER_9999_XML: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing">Microsoft-Windows-Security-Auditing</Provider>
    <EventID>9999</EventID>
    <Level>0</Level>
    <Task>12544</Task>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-13T12:00:02.000000Z">2026-09-13T12:00:02.000000Z</TimeCreated>
    <EventRecordID>9999001</EventRecordID>
    <Channel>Security</Channel>
    <Computer>TEST-HOST</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">192.0.2.10</Data>
    <Data Name="IpPort">49732</Data>
  </EventData>
</Event>"#;

fn bench_parse_event(c: &mut Criterion) {
    // Setup, not the thing under test: load the real production parser
    // config once, outside every timed closure.
    let parser = GenericEventParser::from_file(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/event_parsers"),
    )
    .expect("config/event_parsers must load for this bench to mean anything");

    let mut group = c.benchmark_group("wef_parse_recv_path");
    group.throughput(Throughput::Elements(1));

    // Fail loudly at setup rather than silently timing an early return: a
    // typo in a fixture above, or a parser config change that drops a
    // required field, would otherwise look like a suspiciously fast parse.
    assert!(
        parser.parse_event(4624, LOGON_4624_XML).is_some(),
        "logon_4624 fixture must parse; check the XML literal against config/event_parsers/4624_successful_logon.yaml"
    );
    assert!(
        parser.parse_event(4625, FAILED_LOGON_4625_XML).is_some(),
        "failed_logon_4625 fixture must parse; check the XML literal against config/event_parsers/4625_failed_logon.yaml"
    );
    assert!(
        parser.parse_event(9999, NO_PARSER_9999_XML).is_none(),
        "no_parser_9999 fixture must NOT parse; event id 9999 must stay unregistered in config/event_parsers/ for this to measure the miss path"
    );

    for (name, event_id, xml) in [
        ("logon_4624", 4624u32, LOGON_4624_XML),
        ("failed_logon_4625", 4625u32, FAILED_LOGON_4625_XML),
        ("no_parser_9999", 9999u32, NO_PARSER_9999_XML),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| black_box(parser.parse_event(black_box(event_id), black_box(xml))))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_parse_event);
criterion_main!(benches);
