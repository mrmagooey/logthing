//! Fuzz entry points: one function per ingest path, each replaying the
//! production receive path (decode -> parse -> Arrow mapping) on raw bytes.
//!
//! Shared by the libFuzzer shims in `fuzz/fuzz_targets/` (nightly) and by
//! `tests/fuzz_corpus_replay_integration.rs` (stable), so a committed crash
//! input replays through exactly the code the fuzzer found it with.
//!
//! Each function returns how many records the input produced. Tests assert
//! seeds return > 0; a harness that rejects everything fuzzes nothing.
//! Mapping `Err`s are ignored on purpose: production counts and skips them.
//! Only panics, aborts, OOM and hangs are findings.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Utc};

use crate::forwarding::buffered_writer::ParquetSink;
use crate::forwarding::generic_s3::GenericSink;
use crate::forwarding::ipfix_s3::IpfixSink;
use crate::forwarding::parquet_s3::WefSink;
use crate::forwarding::sflow_s3::SflowSink;
use crate::forwarding::structured_syslog_s3::StructuredSyslogSink;
use crate::forwarding::suricata_s3::SuricataSink;
use crate::forwarding::syslog_s3::SyslogSink;
use crate::forwarding::zeek_s3::ZeekSink;
use crate::ipfix::decoder::{IpfixDecoder, MAX_CACHED_TEMPLATES};
use crate::parser::GenericEventParser;
use crate::protocol::{WefMessage, WefParser};
use crate::syslog::SyslogMessage;
use crate::syslog::payload::{self, StructuredSyslogRecord};

const EXPORTER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

/// Fixed receipt time so replays are deterministic.
fn fixed_now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_758_000_000, 0).expect("valid timestamp")
}

/// Run `rec` through the same mapping steps `PartitionedParquetWriter::push`
/// does, minus buffering and upload.
fn map_record<S: ParquetSink>(sink: &S, rec: &S::Record) {
    let partition = sink.partition(rec).filter(|p| !p.is_empty());
    let schema = sink.schema(partition.as_deref());
    let _ = sink.day_and_batch(rec, &schema, fixed_now());
    // Redundant for sinks using the default `day_and_batch`, but the ones that
    // override it skip building a batch there, so call it directly too.
    let _ = sink.to_record_batch(rec, &schema);
    if let Some(mut acc) = sink.new_batch(&schema)
        && let Ok(true) = acc.try_append(rec, fixed_now())
    {
        let _ = acc.finish();
    }
}

/// Split `data` into datagrams, each prefixed by its big-endian u16 length.
/// A final datagram shorter than its prefix claims is yielded as-is.
fn length_prefixed(mut data: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        let (len, rest) = data.split_first_chunk::<2>()?;
        let (dgram, rest) = rest.split_at(usize::from(u16::from_be_bytes(*len)).min(rest.len()));
        data = rest;
        Some(dgram)
    })
}

/// IPFIX / NetFlow v5 / v9: a sequence of datagrams from one exporter, all
/// sharing one template cache, as the UDP listener does.
pub fn ipfix(data: &[u8]) -> usize {
    let mut decoder = IpfixDecoder::new();
    let mut n = 0;
    for dgram in length_prefixed(data) {
        if let Ok(flows) = crate::ipfix::decoder::decode_datagram(&mut decoder, dgram, EXPORTER)
            && !flows.is_empty()
        {
            n += flows.len();
            map_record(&IpfixSink, &flows);
        }
        assert!(decoder.cache_len() <= MAX_CACHED_TEMPLATES);
    }
    n
}

/// sFlow v5: one datagram.
pub fn sflow(data: &[u8]) -> usize {
    let Ok(records) = crate::sflow::decoder::decode_datagram(data, EXPORTER) else {
        return 0;
    };
    for rec in &records {
        map_record(&SflowSink, rec);
    }
    records.len()
}

/// Syslog UDP path: lossy UTF-8, envelope parse, payload dispatch, and both
/// the raw and structured Arrow mappings.
pub fn syslog(data: &[u8]) -> usize {
    let text = String::from_utf8_lossy(data);
    let Some(msg) = SyslogMessage::parse(&text) else {
        return 0;
    };
    map_record(&SyslogSink, &msg);
    let p = payload::dispatch(&msg);
    let _ = p.to_json();
    if let Some(rec) = StructuredSyslogRecord::from_syslog_and_payload(&msg, &p) {
        map_record(&StructuredSyslogSink, &rec);
    }
    1
}

// ponytail: loads the repo's shipped parser configs; fine for fuzz/tests only.
fn event_parser() -> &'static GenericEventParser {
    static PARSER: OnceLock<GenericEventParser> = OnceLock::new();
    PARSER.get_or_init(|| {
        GenericEventParser::from_file(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/event_parsers"),
        )
        .expect("config/event_parsers must load")
    })
}

/// Sorted so a committed input's selector byte maps to the same parser on
/// every run (`supported_events` iterates a HashMap).
fn sorted_event_ids() -> &'static [u32] {
    static IDS: OnceLock<Vec<u32>> = OnceLock::new();
    IDS.get_or_init(|| {
        let mut ids = event_parser().supported_events();
        ids.sort_unstable();
        ids
    })
}

/// Generic WEF event parser: byte 0 picks the configured parser, the rest is
/// the event XML.
pub fn wef_event(data: &[u8]) -> usize {
    let Some((&pick, xml)) = data.split_first() else {
        return 0;
    };
    let ids = sorted_event_ids();
    let id = ids[usize::from(pick) % ids.len()];
    usize::from(
        event_parser()
            .parse_event(id, &String::from_utf8_lossy(xml))
            .is_some(),
    )
}

/// WEF HTTP body: envelope split, per-event generic parse, and WEF mapping.
pub fn wef_envelope(data: &[u8]) -> usize {
    let body = String::from_utf8_lossy(data);
    let Ok(WefMessage::Events(events)) = WefParser.parse_message(&body, "192.0.2.1".into()) else {
        return 0;
    };
    let n = events.len();
    for event in events {
        if let Some(parsed) = &event.parsed {
            let _ = event_parser().parse_event(parsed.event_id, &event.raw_xml);
        }
        map_record(&WefSink, &Arc::new(event));
    }
    n
}

/// NDJSON listener framing: `\n`-split, trailing `\r` stripped, empty lines
/// skipped, non-UTF-8 lines dropped (the listeners count and skip them).
fn ndjson_lines(data: &[u8]) -> impl Iterator<Item = &str> {
    data.split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.is_empty())
        .filter_map(|l| std::str::from_utf8(l).ok())
}

/// Zeek TCP NDJSON path: parse + Arrow mapping, one call per line.
pub fn zeek(data: &[u8]) -> usize {
    ndjson_lines(data)
        .filter_map(|l| crate::zeek::parse_line(l, fixed_now()).ok())
        .map(|p| map_record(&ZeekSink, &p.record))
        .count()
}

/// Suricata EVE NDJSON path: parse + Arrow mapping, one call per line.
pub fn suricata(data: &[u8]) -> usize {
    ndjson_lines(data)
        .filter_map(|l| crate::suricata::parse_line(l, fixed_now()).ok())
        .map(|p| map_record(&SuricataSink, &p.record))
        .count()
}

/// HEC / NDJSON HTTP bodies: byte 0 picks the route.
pub fn hec(data: &[u8]) -> usize {
    use crate::ingest::parse::{parse_hec_event_body, parse_hec_raw_body, parse_ndjson_body};
    let Some((&route, body)) = data.split_first() else {
        return 0;
    };
    let records = match route % 3 {
        0 => parse_hec_event_body(body, "fuzz"),
        1 => parse_hec_raw_body(body, "fuzz").map(|r| vec![r]),
        _ => parse_ndjson_body(body, "fuzz"),
    };
    let Ok(records) = records else {
        return 0;
    };
    for rec in &records {
        map_record(&GenericSink, rec);
    }
    records.len()
}

/// OTLP /v1/logs body: byte 0 picks protobuf (even) or JSON (odd).
#[cfg(feature = "otlp")]
pub fn otlp(data: &[u8]) -> usize {
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use prost::Message;
    let Some((&ct, body)) = data.split_first() else {
        return 0;
    };
    let req = if ct % 2 == 0 {
        ExportLogsServiceRequest::decode(body).ok()
    } else {
        serde_json::from_slice::<ExportLogsServiceRequest>(body).ok()
    };
    let Some(req) = req else {
        return 0;
    };
    let records = crate::server::otlp::map_otlp_request(req, "192.0.2.1".to_string());
    for rec in &records {
        map_record(&GenericSink, rec);
    }
    records.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeds(target: &str) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/seeds")
            .join(target);
        let mut out: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .map(|e| e.unwrap().path())
            .map(|p| {
                let bytes = std::fs::read(&p).unwrap();
                (p, bytes)
            })
            .collect();
        assert!(!out.is_empty(), "no seeds in {}", dir.display());
        out.sort();
        out
    }

    #[test]
    fn test_length_prefixed_splits_and_truncates() {
        let data = [0, 2, b'a', b'b', 0, 5, b'c'];
        let parts: Vec<&[u8]> = length_prefixed(&data).collect();
        assert_eq!(parts, vec![&b"ab"[..], &b"c"[..]]);
        assert_eq!(length_prefixed(&[7]).count(), 0);
    }

    #[test]
    fn test_ipfix_every_seed_produces_flows() {
        for (path, bytes) in seeds("ipfix") {
            assert!(ipfix(&bytes) > 0, "{} produced no flows", path.display());
        }
    }

    #[test]
    fn test_ipfix_data_only_after_template_uses_cache() {
        // Two datagrams, template in the first: the second only decodes if the
        // decoder state survives across datagrams within one input.
        let (_, both) = seeds("ipfix")
            .into_iter()
            .find(|(p, _)| p.ends_with("v10_template_then_data_only.bin"))
            .unwrap();
        assert_eq!(ipfix(&both), 2);
    }

    #[test]
    fn test_sflow_every_seed_produces_records() {
        for (path, bytes) in seeds("sflow") {
            assert!(sflow(&bytes) > 0, "{} produced no records", path.display());
        }
    }

    #[test]
    fn test_binary_targets_empty_and_garbage_input_return_zero() {
        for f in [ipfix, sflow] {
            assert_eq!(f(&[]), 0);
            assert_eq!(f(&[0xff; 64]), 0);
        }
    }

    #[test]
    fn test_syslog_every_seed_parses() {
        for (path, bytes) in seeds("syslog") {
            assert!(syslog(&bytes) > 0, "{} did not parse", path.display());
        }
    }

    #[test]
    fn test_syslog_seeds_cover_every_payload_parser() {
        use crate::syslog::{SyslogMessage, payload};
        let mut kinds: Vec<&str> = seeds("syslog")
            .iter()
            .filter_map(|(_, b)| SyslogMessage::parse(&String::from_utf8_lossy(b)))
            .filter_map(|m| payload::dispatch(&m).payload_type())
            .collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds.len(), 7, "payload kinds seeded: {kinds:?}");
    }

    #[test]
    fn test_wef_event_selector_is_stable_and_seed_hits_4624() {
        let ids = sorted_event_ids();
        assert!(ids.windows(2).all(|w| w[0] < w[1]), "ids must be sorted");
        let (_, bytes) = seeds("wef_event")
            .into_iter()
            .find(|(p, _)| p.ends_with("logon_4624.bin"))
            .unwrap();
        assert_eq!(
            ids[usize::from(bytes[0]) % ids.len()],
            4624,
            "fix the seed's first byte"
        );
        assert_eq!(wef_event(&bytes), 1);
    }

    #[test]
    fn test_wef_envelope_every_events_seed_yields_events() {
        for (path, bytes) in seeds("wef_envelope") {
            if path.ends_with("subscribe.xml") {
                continue;
            }
            assert!(
                wef_envelope(&bytes) > 0,
                "{} yielded no events",
                path.display()
            );
        }
    }

    #[test]
    fn test_text_targets_empty_input_returns_zero() {
        for f in [syslog, wef_event, wef_envelope] {
            assert_eq!(f(&[]), 0);
        }
    }

    #[test]
    fn test_ndjson_targets_every_seed_yields_all_lines() {
        for (target, f) in [("zeek", zeek as fn(&[u8]) -> usize), ("suricata", suricata)] {
            for (path, bytes) in seeds(target) {
                let lines = bytes
                    .split(|b| *b == b'\n')
                    .filter(|l| !l.is_empty())
                    .count();
                assert_eq!(f(&bytes), lines, "{}", path.display());
            }
        }
    }

    #[test]
    fn test_ndjson_targets_skip_bad_line_and_keep_going() {
        let input = b"{\"_path\":\"conn\"}\n\xff\xfe\nnot json\r\n{\"event_type\":\"alert\"}";
        assert_eq!(zeek(input), 2); // both valid JSON lines parse; _path is optional
        assert_eq!(suricata(input), 2);
    }

    #[test]
    fn test_hec_every_seed_yields_records() {
        for (path, bytes) in seeds("hec") {
            assert!(hec(&bytes) > 0, "{}", path.display());
        }
    }

    #[cfg(feature = "otlp")]
    #[test]
    fn test_otlp_every_seed_yields_records() {
        for (path, bytes) in seeds("otlp") {
            assert!(otlp(&bytes) > 0, "{}", path.display());
        }
    }

    #[cfg(feature = "otlp")]
    #[test]
    #[ignore = "regenerates fuzz/seeds/otlp/proto.bin"]
    fn write_otlp_proto_seed() {
        use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
        use prost::Message;
        let json = &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/otlp/json.bin"),
        )
        .unwrap()[1..];
        let req: ExportLogsServiceRequest = serde_json::from_slice(json).unwrap();
        let mut out = vec![0u8];
        out.extend(req.encode_to_vec());
        std::fs::write(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/otlp/proto.bin"),
            out,
        )
        .unwrap();
    }
}
