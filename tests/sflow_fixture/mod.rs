//! Hand-built sFlow v5 datagram shared by the sFlow decoder-fix tests.
#![allow(dead_code)]

fn be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

fn envelope(tag: u32, body: &[u8]) -> Vec<u8> {
    let mut v = be(tag).to_vec();
    v.extend_from_slice(&be(body.len() as u32));
    v.extend_from_slice(body);
    v
}

/// Counter sample with: a 40-byte (short) generic_if_counters record, an
/// ethernet_counters record (format 2), then a valid generic_if_counters
/// record for `if_index`.
fn counter_sample(if_index: u32) -> Vec<u8> {
    let mut valid = vec![0u8; 88];
    valid[0..4].copy_from_slice(&be(if_index));
    valid[4..8].copy_from_slice(&be(6));
    let records = [
        envelope(1, &[0u8; 40]),
        envelope(2, &[0u8; 52]),
        envelope(1, &valid),
    ];
    let mut b = Vec::new();
    for w in [1, 1, records.len() as u32] {
        b.extend_from_slice(&be(w));
    }
    for r in &records {
        b.extend_from_slice(r);
    }
    envelope(2, &b)
}

/// Compact flow sample with one raw-header record: Ethernet / IPv6 / hop-by-hop
/// / TCP 8080 -> 80.
fn flow_sample() -> Vec<u8> {
    let mut f = vec![0u8; 12];
    f.extend_from_slice(&[0x86, 0xDD]);
    f.extend_from_slice(&[0x60, 0, 0, 0, 0, 0, 0, 64]); // next header 0 = hop-by-hop
    f.extend_from_slice(&[0x20, 0x01, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&[0x20, 0x01, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    f.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]); // HBH -> TCP
    f.extend_from_slice(&[0x1F, 0x90, 0x00, 0x50, 0, 0, 0, 0]); // ports
    while !f.len().is_multiple_of(4) {
        f.push(0);
    }
    let mut rec = Vec::new();
    for w in [1, f.len() as u32 + 4, 0, f.len() as u32] {
        rec.extend_from_slice(&be(w));
    }
    rec.extend_from_slice(&f);
    let rec = envelope(1, &rec);
    let mut b = Vec::new();
    for w in [1, 1, 512, 512, 0, 3, 4, 1] {
        b.extend_from_slice(&be(w));
    }
    b.extend_from_slice(&rec);
    envelope(1, &b)
}

/// One datagram: the mixed-validity counter sample, then the IPv6 HBH flow sample.
pub fn mixed_datagram(if_index: u32) -> Vec<u8> {
    let mut d = Vec::new();
    for w in [5, 1, 0x0A00_0001, 0, 1, 1000, 2] {
        d.extend_from_slice(&be(w));
    }
    d.extend_from_slice(&counter_sample(if_index));
    d.extend_from_slice(&flow_sample());
    d
}

/// Assert the rows read back from the `sflow/{flow,counter}` parquet carry the
/// decoded values.
pub fn assert_rows(batches: &[arrow::record_batch::RecordBatch], if_index: u32) {
    use arrow::util::display::array_value_to_string;
    let (mut flow, mut counter) = (0, 0);
    for b in batches {
        let col =
            |n: &str, i: usize| array_value_to_string(b.column_by_name(n).unwrap(), i).unwrap();
        for i in 0..b.num_rows() {
            match col("sample_type", i).as_str() {
                "flow" => {
                    flow += 1;
                    assert_eq!(col("src_port", i), "8080");
                    assert_eq!(col("dst_port", i), "80");
                    assert_eq!(col("ip_protocol", i), "6");
                }
                "counter" => {
                    counter += 1;
                    assert_eq!(col("if_index", i), if_index.to_string());
                    assert!(col("extra", i).contains("\"format\":2"));
                }
                other => panic!("unexpected sample_type {other}"),
            }
        }
    }
    assert_eq!((flow, counter), (1, 1), "one flow row and one counter row");
}
