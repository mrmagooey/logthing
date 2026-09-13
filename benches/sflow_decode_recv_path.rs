//! Criterion micro-benchmarks: the sFlow *receive-path* binary decode cost that
//! runs once per ingested UDP datagram on the listener task, upstream of the
//! `SflowSink::to_record_batch` layer that `sflow_to_record_batch.rs` covers.
//! Measures `sflow::decoder::decode_datagram`, exactly as `SflowListener`'s
//! `recv_from` arm runs it.
//!
//! Unlike IPFIX, the sFlow decoder is stateless — no template cache, so there
//! is no warm/cold distinction to draw here. What varies instead is how deep
//! the parse goes:
//!
//! - `flow_raw_header`: a flow sample carrying a raw packet header, so the
//!   decoder walks Ethernet -> IPv4 -> TCP/UDP to recover the 5-tuple
//!   (`decode_raw_packet_header` -> `parse_ethernet` -> `parse_ipv4` ->
//!   `parse_transport`). The deepest path, and the common one for real
//!   switch traffic.
//! - `flow_sampled_ipv4`: a flow sample carrying a pre-parsed IPv4 record, so
//!   the Ethernet walk is skipped.
//! - `counter`: an interface-counter sample — no packet parse at all, just
//!   fixed-offset field reads.
//!
//! Deliberately NOT measured: `recv_from`, the allowed-IPs check, and
//! `handler.handle_samples`.
//!
//! Byte fixtures are reproduced inline from `src/sflow/decoder.rs`'s
//! `FIXTURE_SFLOW_FLOW_RAW_HEADER`, `FIXTURE_SFLOW_SAMPLED_IPV4` and
//! `FIXTURE_SFLOW_COUNTER`, which are `#[cfg(test)] pub(crate)` and so
//! unreachable from a bench compiling as an external crate. If those change,
//! update these in step.
//!
//! Run with: `cargo bench --bench sflow_decode_recv_path`

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use logthing::sflow::decoder::decode_datagram;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

// --- Fixtures transcribed from src/sflow/decoder.rs (see header) ---

// ── fixture: flow sample with raw packet header (Ethernet/IPv4/TCP → 5-tuple) ──
//
// sFlow v5 datagram layout (all big-endian / XDR, 4-byte aligned):
//
// Datagram header (28 bytes for IPv4 agent):
//   [0..4]   version         = 5  (u32)
//   [4..8]   agent_addr_type = 1  (u32, 1=IPv4)
//   [8..12]  agent_addr      = 10.0.0.1
//   [12..16] sub_agent_id    = 0  (u32)
//   [16..20] sequence_number = 1  (u32)
//   [20..24] uptime_ms       = 1000 (u32)
//   [24..28] num_samples     = 1  (u32)
//
// Flow Sample (format tag 1 = flow_sample):
//   [28..32] data_format     = 0x00000001 (enterprise 0, format 1 = flow_sample)
//   [32..36] sample_length   = N  (u32, length of sample body in bytes)
//   Flow sample body:
//     [36..40] sequence_number = 1
//     [40..44] source_id       = 0x00000001 (type=0 (ifIndex), value=1)
//     [44..48] sampling_rate   = 512
//     [48..52] sample_pool     = 512
//     [52..56] drops           = 0
//     [56..60] input           = 1  (ifIndex)
//     [60..64] output          = 2  (ifIndex)
//     [64..68] num_flow_records = 1
//   Flow record (raw packet header, enterprise 0, format 1):
//     [68..72] flow_data_format = 0x00000001
//     [72..76] flow_data_length = 80  (4 header_protocol + 4 frame_length + 4 stripped + 4 header_length + 64 header_bytes)
//     [76..80] header_protocol  = 1   (Ethernet)
//     [80..84] frame_length     = 98
//     [84..88] stripped         = 0
//     [88..92] header_length    = 64
//     [92..156] header_bytes (64 bytes):
//       Ethernet (14 bytes): dst_mac(6) + src_mac(6) + ethertype(2=0x0800 IPv4)
//       IPv4 (20 bytes): ver_ihl(0x45) tos(0) total_len(84) id(0) flags_frag(0)
//                        ttl(64) protocol(6=TCP) checksum(0) src(192.168.1.10) dst(10.0.0.2)
//       TCP (20 bytes): src_port(8080) dst_port(80) seq(0) ack(0) data_off(0x50) flags(0x02) win(0) cksum(0) urg(0)
//       padding (10 bytes of zeros to reach 64)
const FIXTURE_SFLOW_FLOW_RAW_HEADER: &[u8] = &[
    // ── Datagram header ──
    0x00, 0x00, 0x00, 0x05, // version = 5
    0x00, 0x00, 0x00, 0x01, // agent_addr_type = 1 (IPv4)
    0x0A, 0x00, 0x00, 0x01, // agent_addr = 10.0.0.1
    0x00, 0x00, 0x00, 0x00, // sub_agent_id = 0
    0x00, 0x00, 0x00, 0x01, // sequence_number = 1
    0x00, 0x00, 0x03, 0xE8, // uptime_ms = 1000
    0x00, 0x00, 0x00, 0x01, // num_samples = 1
    // ── Sample envelope: flow_sample (enterprise=0, format=1 → tag=0x00000001) ──
    0x00, 0x00, 0x00, 0x01, // data_format tag
    // sample_length = 32 (body hdr) + 4+4+80 (flow record envelope+body) = 120
    0x00, 0x00, 0x00, 0x78, // sample_length = 120
    // ── Flow sample body header (32 bytes) ──
    0x00, 0x00, 0x00, 0x01, // sequence_number = 1
    0x00, 0x00, 0x00, 0x01, // source_id = 0x00000001
    0x00, 0x00, 0x02, 0x00, // sampling_rate = 512
    0x00, 0x00, 0x02, 0x00, // sample_pool = 512
    0x00, 0x00, 0x00, 0x00, // drops = 0
    0x00, 0x00, 0x00, 0x01, // input_ifindex = 1
    0x00, 0x00, 0x00, 0x02, // output_ifindex = 2
    0x00, 0x00, 0x00, 0x01, // num_flow_records = 1
    // ── Flow record: raw packet header (enterprise=0, format=1 → tag=0x00000001) ──
    0x00, 0x00, 0x00, 0x01, // flow_data_format = 1
    0x00, 0x00, 0x00, 0x50, // flow_data_length = 80
    0x00, 0x00, 0x00, 0x01, // header_protocol = 1 (ETHERNET)
    0x00, 0x00, 0x00, 0x62, // frame_length = 98
    0x00, 0x00, 0x00, 0x00, // stripped = 0
    0x00, 0x00, 0x00, 0x40, // header_length = 64
    // ── Ethernet (14 bytes) ──
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dst MAC = broadcast
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
    0x08, 0x00, // ethertype = IPv4
    // ── IPv4 (20 bytes) ──
    0x45, // version=4, IHL=5
    0x00, // DSCP/ECN
    0x00, 0x54, // total length = 84
    0x00, 0x00, // identification = 0
    0x00, 0x00, // flags + fragment offset = 0
    0x40, // TTL = 64
    0x06, // protocol = 6 (TCP)
    0x00, 0x00, // header checksum = 0
    0xC0, 0xA8, 0x01, 0x0A, // src = 192.168.1.10
    0x0A, 0x00, 0x00, 0x02, // dst = 10.0.0.2
    // ── TCP (20 bytes) ──
    0x1F, 0x90, // src_port = 8080
    0x00, 0x50, // dst_port = 80
    0x00, 0x00, 0x00, 0x00, // seq = 0
    0x00, 0x00, 0x00, 0x00, // ack = 0
    0x50, // data offset = 5 (20 bytes)
    0x02, // flags = SYN
    0x00, 0x00, // window = 0
    0x00, 0x00, // checksum = 0
    0x00, 0x00, // urgent = 0
    // ── padding to reach 64 header bytes (10 bytes) ──
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// ── fixture: flow sample with sampled_ipv4 record (format 3 carries 5-tuple directly) ──
//
// Datagram header: identical to above (28 bytes), num_samples=1.
// Flow sample envelope: tag=0x00000001, length=body_size.
// Flow sample body header: seq=2, src_id=1, rate=1000, pool=1000, drops=0, in=3, out=4, num_records=1.
// Flow record (sampled_ipv4, enterprise=0, format=3 → tag=0x00000003):
//   length = 32 (fixed: 4 len + 4 proto + 4 src_ip + 4 dst_ip + 2 src_port + 2 dst_port + 4 tos + 4 tcp_flags + ... = 32 bytes body)
//   Actually per sFlow v5 spec §5.2.2:
//     length (u32), protocol (u32), src_ip (4), dst_ip (4), src_port (u32), dst_port (u32), tcp_flags (u32), tos (u32) = 32 bytes
const FIXTURE_SFLOW_SAMPLED_IPV4: &[u8] = &[
    // ── Datagram header ──
    0x00, 0x00, 0x00, 0x05, // version = 5
    0x00, 0x00, 0x00, 0x01, // agent_addr_type = 1 (IPv4)
    0x0A, 0x00, 0x00, 0x01, // agent_addr = 10.0.0.1
    0x00, 0x00, 0x00, 0x00, // sub_agent_id = 0
    0x00, 0x00, 0x00, 0x02, // sequence_number = 2
    0x00, 0x00, 0x07, 0xD0, // uptime_ms = 2000
    0x00, 0x00, 0x00, 0x01, // num_samples = 1
    // ── Sample envelope: flow_sample (tag=1) ──
    0x00, 0x00, 0x00, 0x01, // data_format = flow_sample
    // sample_length = 32 (flow hdr) + 4+4+32 (rec envelope + sampled_ipv4 body) = 72
    0x00, 0x00, 0x00, 0x48, // sample_length = 72
    // ── Flow sample body header (32 bytes) ──
    0x00, 0x00, 0x00, 0x02, // sequence_number = 2
    0x00, 0x00, 0x00, 0x01, // source_id = 1
    0x00, 0x00, 0x03, 0xE8, // sampling_rate = 1000
    0x00, 0x00, 0x03, 0xE8, // sample_pool = 1000
    0x00, 0x00, 0x00, 0x00, // drops = 0
    0x00, 0x00, 0x00, 0x03, // input_ifindex = 3
    0x00, 0x00, 0x00, 0x04, // output_ifindex = 4
    0x00, 0x00, 0x00, 0x01, // num_flow_records = 1
    // ── Flow record: sampled_ipv4 (enterprise=0, format=3 → tag=0x00000003) ──
    0x00, 0x00, 0x00, 0x03, // flow_data_format = 3
    0x00, 0x00, 0x00, 0x20, // flow_data_length = 32
    // sampled_ipv4 body (32 bytes):
    // length(u32) + protocol(u32) + src_ip(4) + dst_ip(4) + src_port(u32) + dst_port(u32) + tcp_flags(u32) + tos(u32)
    0x00, 0x00, 0x00, 0x3C, // length = 60 (original packet length)
    0x00, 0x00, 0x00, 0x11, // protocol = 17 (UDP)
    0xAC, 0x10, 0x00, 0x01, // src_ip = 172.16.0.1
    0x08, 0x08, 0x08, 0x08, // dst_ip = 8.8.8.8
    0x00, 0x00, 0xC0, 0x3A, // src_port = 49210 (as u32)
    0x00, 0x00, 0x00, 0x35, // dst_port = 53 (DNS) (as u32)
    0x00, 0x00, 0x00, 0x00, // tcp_flags = 0
    0x00, 0x00, 0x00, 0x00, // tos = 0
];

// ── fixture: counter sample with generic interface counters (format 1) ──
//
// Counter sample (enterprise=0, format=2 → tag=0x00000002):
// Body: sequence_number(u32) + source_id(u32) + num_counter_records(u32) = 12 bytes
// Counter record (generic_interface_counters, enterprise=0, format=1 → tag=0x00000001):
//   ifIndex(u32) ifType(u32) ifSpeed(u64) ifDirection(u32) ifStatus(u32)
//   ifInOctets(u64) ifInUcastPkts(u32) ifInMulticastPkts(u32) ifInBroadcastPkts(u32)
//   ifInDiscards(u32) ifInErrors(u32) ifInUnknownProtos(u32)
//   ifOutOctets(u64) ifOutUcastPkts(u32) ifOutMulticastPkts(u32) ifOutBroadcastPkts(u32)
//   ifOutDiscards(u32) ifOutErrors(u32) ifPromiscuousMode(u32)
//   Total = 4+4+8+4+4+8+4+4+4+4+4+4+8+4+4+4+4+4+4 = 88 bytes
const FIXTURE_SFLOW_COUNTER: &[u8] = &[
    // ── Datagram header ──
    0x00, 0x00, 0x00, 0x05, // version = 5
    0x00, 0x00, 0x00, 0x01, // agent_addr_type = 1 (IPv4)
    0x0A, 0x00, 0x00, 0x01, // agent_addr = 10.0.0.1
    0x00, 0x00, 0x00, 0x00, // sub_agent_id = 0
    0x00, 0x00, 0x00, 0x03, // sequence_number = 3
    0x00, 0x00, 0x0B, 0xB8, // uptime_ms = 3000
    0x00, 0x00, 0x00, 0x01, // num_samples = 1
    // ── Sample envelope: counter_sample (tag=0x00000002) ──
    0x00, 0x00, 0x00, 0x02, // data_format = counter_sample
    // sample_length = 12 (counter body hdr) + 4+4+88 (rec envelope + generic_if_counters) = 108
    0x00, 0x00, 0x00, 0x6C, // sample_length = 108
    // ── Counter sample body header (12 bytes) ──
    0x00, 0x00, 0x00, 0x03, // sequence_number = 3
    0x00, 0x00, 0x00, 0x01, // source_id = 1
    0x00, 0x00, 0x00, 0x01, // num_counter_records = 1
    // ── Counter record: generic_if_counters (enterprise=0, format=1 → tag=0x00000001) ──
    0x00, 0x00, 0x00, 0x01, // counter_data_format = 1
    0x00, 0x00, 0x00, 0x58, // counter_data_length = 88
    // generic_if_counters body (88 bytes):
    0x00, 0x00, 0x00, 0x01, // ifIndex = 1
    0x00, 0x00, 0x00, 0x06, // ifType = 6 (ethernetCsmacd)
    0x00, 0x00, 0x00, 0x00, 0x3B, 0x9A, 0xCA, 0x00, // ifSpeed = 1_000_000_000 bps
    0x00, 0x00, 0x00, 0x01, // ifDirection = 1 (full-duplex)
    0x00, 0x00, 0x00, 0x03, // ifStatus = 3 (ifAdminStatus=up(1) | ifOperStatus=up(2))
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x42, 0x40, // ifInOctets = 1_000_000
    0x00, 0x00, 0x03, 0xE8, // ifInUcastPkts = 1000
    0x00, 0x00, 0x00, 0x0A, // ifInMulticastPkts = 10
    0x00, 0x00, 0x00, 0x05, // ifInBroadcastPkts = 5
    0x00, 0x00, 0x00, 0x00, // ifInDiscards = 0
    0x00, 0x00, 0x00, 0x02, // ifInErrors = 2
    0x00, 0x00, 0x00, 0x00, // ifInUnknownProtos = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xA1, 0x20, // ifOutOctets = 500_000
    0x00, 0x00, 0x01, 0xF4, // ifOutUcastPkts = 500
    0x00, 0x00, 0x00, 0x03, // ifOutMulticastPkts = 3
    0x00, 0x00, 0x00, 0x01, // ifOutBroadcastPkts = 1
    0x00, 0x00, 0x00, 0x00, // ifOutDiscards = 0
    0x00, 0x00, 0x00, 0x01, // ifOutErrors = 1
    0x00, 0x00, 0x00, 0x00, // ifPromiscuousMode = 0
];

fn exporter() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254))
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("sflow_decode_recv_path");
    group.throughput(Throughput::Elements(1));

    for (name, fixture) in [
        ("flow_raw_header", FIXTURE_SFLOW_FLOW_RAW_HEADER),
        ("flow_sampled_ipv4", FIXTURE_SFLOW_SAMPLED_IPV4),
        ("counter", FIXTURE_SFLOW_COUNTER),
    ] {
        // Fail loudly at setup rather than silently benchmarking an error
        // return: a mistranscribed byte would otherwise look like a very fast
        // decode.
        let records = decode_datagram(fixture, exporter())
            .unwrap_or_else(|e| panic!("fixture {name} must decode, got {e}"));
        assert!(!records.is_empty(), "fixture {name} must yield records");

        group.bench_function(name, |b| {
            b.iter(|| black_box(decode_datagram(black_box(fixture), exporter())))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
