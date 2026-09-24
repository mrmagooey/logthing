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

use chrono::{DateTime, Utc};

use crate::forwarding::buffered_writer::ParquetSink;
use crate::forwarding::ipfix_s3::IpfixSink;
use crate::forwarding::sflow_s3::SflowSink;
use crate::ipfix::decoder::{IpfixDecoder, MAX_CACHED_TEMPLATES};

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
}
