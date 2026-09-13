//! Criterion micro-benchmarks: the Suricata TCP *receive-path* parse cost that
//! runs once per ingested EVE JSON line on the listener task, upstream of the
//! `SuricataSink::to_record_batch` layer that
//! `suricata_envelope_to_record_batch.rs` covers. Measures
//! `std::str::from_utf8` -> `suricata::parse_line`, exactly as
//! `SuricataListener::handle_tcp_connection` runs them.
//!
//! Deliberately NOT measured: the bounded `read_until` and its oversize guard,
//! the per-record metric increments, and `handler.handle_record`.
//!
//! Three fixtures spanning the EVE event types by volume and by shape. `alert`
//! is the interesting one: it carries a nested `alert` object plus full flow
//! context, so it is several times larger than `flow` or `dns` and is where
//! serde_json cost concentrates. Fixtures are inline because
//! `src/suricata/listener.rs`'s are `#[cfg(test)]` and this bench compiles as
//! an external crate.
//!
//! Run with: `cargo bench --bench suricata_parse_recv_path`

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::suricata::parse_line;
use std::hint::black_box;

const ALERT_LINE: &str = r#"{"timestamp":"2026-01-15T10:30:45.123456+0000","flow_id":1234567890123456,"event_type":"alert","src_ip":"10.0.0.1","src_port":54321,"dest_ip":"10.0.0.2","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2013028,"rev":6,"signature":"ET POLICY curl User-Agent Outbound","category":"Attempted Information Leak","severity":2},"flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":532,"bytes_toclient":1204,"start":"2026-01-15T10:30:44.900000+0000"}}"#;

const FLOW_LINE: &str = r#"{"timestamp":"2026-01-15T10:30:46.000000+0000","flow_id":1234567890123457,"event_type":"flow","src_ip":"10.0.0.1","src_port":54322,"dest_ip":"10.0.0.3","dest_port":80,"proto":"TCP","flow":{"pkts_toserver":10,"pkts_toclient":8,"bytes_toserver":1420,"bytes_toclient":9800,"state":"closed","reason":"shutdown"}}"#;

const DNS_LINE: &str = r#"{"timestamp":"2026-01-15T10:30:47.000000+0000","flow_id":1234567890123458,"event_type":"dns","src_ip":"192.168.1.100","src_port":53322,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","dns":{"type":"query","id":4242,"rrname":"api.example.com","rrtype":"A"}}"#;

fn bench_parse_line(c: &mut Criterion) {
    let mut group = c.benchmark_group("suricata_parse_recv_path");
    group.throughput(Throughput::Elements(1));

    for (name, line) in [
        ("alert", ALERT_LINE),
        ("flow", FLOW_LINE),
        ("dns", DNS_LINE),
    ] {
        let at = chrono::Utc::now();
        // See the zeek bench: guard against timing an early error return.
        assert!(
            parse_line(line, at).is_ok(),
            "fixture {name} must parse; check the JSON literal"
        );
        group.bench_function(name, |b| {
            b.iter(|| black_box(parse_line(black_box(line), black_box(at))))
        });
    }
    group.finish();
}

fn bench_utf8_plus_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("suricata_recv_path_end_to_end");
    group.throughput(Throughput::Elements(1));

    let bytes = ALERT_LINE.as_bytes();
    let at = chrono::Utc::now();
    group.bench_function("alert_from_utf8_then_parse", |b| {
        b.iter(|| {
            let s = std::str::from_utf8(black_box(bytes)).unwrap();
            black_box(parse_line(s, black_box(at)))
        })
    });
    group.finish();
}

criterion_group!(benches, bench_parse_line, bench_utf8_plus_parse);
criterion_main!(benches);
