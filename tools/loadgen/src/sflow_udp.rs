//! `loadgen sflow-udp` -- paced UDP sFlow v5 load generator.
//!
//! sFlow's collector (`src/sflow/decoder.rs`) is stateless — unlike IPFIX,
//! there is no template cache to prime, so (unlike `ipfix_udp.rs`) this
//! generator needs no resend logic. It only has to get the fixed v5 wire
//! layout right, byte for byte, or `decode_datagram` silently drops the
//! sample (see its module doc: "Sample-level errors ... are logged as
//! warnings and the sample is skipped").
//!
//! Wire format (all big-endian / XDR, matching
//! `FIXTURE_SFLOW_SAMPLED_IPV4` / `FIXTURE_SFLOW_COUNTER` in
//! `src/sflow/decoder.rs` byte-for-byte):
//! - Datagram header (28 bytes for an IPv4 agent): version=5,
//!   agent_addr_type=1 (IPv4), agent_addr, sub_agent_id, sequence_number,
//!   uptime_ms, num_samples.
//! - Each datagram this generator sends carries exactly **two** samples
//!   (`num_samples = 2`): one flow sample and one counter sample. A real
//!   exporter interleaves both kinds, and bundling them here means
//!   "datagrams sent" and "samples sent" are genuinely different numbers
//!   worth reporting separately, not just a naming nicety.
//! - The flow sample (format 1) carries one flow record using
//!   `sampled_ipv4` (format 3) — a fixed 32-byte body with the 5-tuple
//!   inline. This is deliberately *not* `raw_packet_header` (format 1),
//!   which would require hand-rolling a well-formed Ethernet/IPv4/TCP frame
//!   for no extra wire-format coverage: `decode_flow_sample` treats both as
//!   equally valid flow record formats.
//! - The counter sample (format 2) carries one `generic_if_counters`
//!   record (enterprise 0, format 1, fixed 88-byte body).
//!
//! Source/destination addresses (flow sample) and interface index / octet
//! counters (counter sample) are derived from the datagram index so a run
//! of N datagrams produces N genuinely distinct sample pairs, the same
//! convention `ipfix_udp.rs::flow_addrs` uses.

use anyhow::Context;
use clap::Args;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::MissedTickBehavior;

use crate::pacing::tick_record_count;

/// Fixed IPv4 agent address embedded in every datagram's header.
const AGENT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

/// Every datagram carries exactly one flow sample + one counter sample.
const SAMPLES_PER_DATAGRAM: u64 = 2;

#[derive(Args, Debug)]
pub struct SflowUdpArgs {
    /// Target host to send sFlow UDP datagrams to.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Target UDP port. Matches `SflowConfig`'s real default
    /// (`default_sflow_udp_port() -> 6343` in `src/config/mod.rs`).
    #[arg(long, default_value_t = 6343)]
    pub port: u16,

    /// Target sustained rate, in datagrams/sec (each datagram carries 2
    /// samples: one flow sample + one counter sample). 0 means "unbounded"
    /// (send as fast as the socket will accept, no pacing).
    #[arg(long, default_value_t = 10_000)]
    pub target_rate: u64,

    /// How long to send for, in seconds.
    #[arg(long, default_value_t = 60)]
    pub duration_secs: u64,
}

pub async fn run(args: SflowUdpArgs) -> anyhow::Result<()> {
    // Resolve rather than `.parse::<SocketAddr>()` (see ipfix_udp.rs /
    // syslog_udp.rs for why: a docker-compose service name is not a
    // numeric IP).
    let target = tokio::net::lookup_host(format!("{}:{}", args.host, args.port))
        .await
        .with_context(|| format!("resolve target address {}:{}", args.host, args.port))?
        .next()
        .with_context(|| format!("no address resolved for {}:{}", args.host, args.port))?;

    let local: std::net::SocketAddr = if target.is_ipv6() {
        "[::]:0".parse().expect("static addr")
    } else {
        "0.0.0.0:0".parse().expect("static addr")
    };
    let socket = UdpSocket::bind(local)
        .await
        .context("bind local UDP socket")?;
    socket
        .connect(target)
        .await
        .context("connect UDP socket to target")?;

    println!(
        "loadgen sflow-udp: sending to {target} at target_rate={} datagrams/s for {}s \
         (2 samples/datagram)",
        args.target_rate, args.duration_secs
    );

    let duration = Duration::from_secs(args.duration_secs);
    let start = Instant::now();
    let mut sent: u64 = 0;
    let mut seq: u32 = 1;

    let send_result: anyhow::Result<()> = async {
        if args.target_rate == 0 {
            // Unbounded: send as fast as the socket will accept.
            while start.elapsed() < duration {
                socket
                    .send(&build_datagram(seq, sent))
                    .await
                    .context("send sFlow datagram")?;
                seq = seq.wrapping_add(1);
                sent += 1;
            }
        } else {
            // Paced: same 1ms-tick, N-per-tick, fractional-carry pattern as
            // every other loadgen subcommand (see `crate::pacing`).
            let per_tick_interval = crate::pacing::TICK;
            let records_per_tick_target = args.target_rate as f64 * per_tick_interval.as_secs_f64();
            let mut ticker = tokio::time::interval(per_tick_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Burst);
            let mut carry: f64 = 0.0;

            'send_loop: loop {
                if start.elapsed() >= duration {
                    break;
                }
                ticker.tick().await;
                let records_this_tick = tick_record_count(&mut carry, records_per_tick_target);
                for _ in 0..records_this_tick {
                    if start.elapsed() >= duration {
                        break 'send_loop;
                    }
                    socket
                        .send(&build_datagram(seq, sent))
                        .await
                        .context("send sFlow datagram")?;
                    seq = seq.wrapping_add(1);
                    sent += 1;
                }
            }
        }
        Ok(())
    }
    .await;

    let elapsed = start.elapsed();
    if let Err(e) = send_result {
        eprintln!(
            "loadgen sflow-udp: send error after {sent} datagrams in {:.3}s — aborting: {e:#}",
            elapsed.as_secs_f64()
        );
        return Err(e);
    }

    let samples_sent = sent * SAMPLES_PER_DATAGRAM;
    println!(
        "loadgen sflow-udp: sent {sent} datagrams in {:.3}s (achieved rate: {:.1} rec/s); \
         {samples_sent} samples ({:.1} samples/s)",
        elapsed.as_secs_f64(),
        sent as f64 / elapsed.as_secs_f64(),
        samples_sent as f64 / elapsed.as_secs_f64(),
    );

    Ok(())
}

/// Derive distinct source/destination addresses for datagram index `n`, so
/// a run of N datagrams produces N genuinely distinct flow records instead
/// of one flow replayed N times. Same convention as
/// `ipfix_udp.rs::flow_addrs`.
fn flow_addrs(n: u64) -> (Ipv4Addr, Ipv4Addr) {
    let hi = ((n >> 8) & 0xFF) as u8;
    let lo = (n & 0xFF) as u8;
    (
        Ipv4Addr::new(10, 0, hi, lo),
        Ipv4Addr::new(192, 168, hi, lo),
    )
}

/// Build one sFlow v5 datagram: header + one flow sample (sampled_ipv4) +
/// one counter sample (generic_if_counters), both derived from datagram
/// index `n` so consecutive datagrams are genuinely distinct.
fn build_datagram(seq: u32, n: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // ── Datagram header (28 bytes) ──
    buf.extend_from_slice(&5u32.to_be_bytes()); // version = 5
    buf.extend_from_slice(&1u32.to_be_bytes()); // agent_addr_type = 1 (IPv4)
    buf.extend_from_slice(&AGENT_ADDR.octets());
    buf.extend_from_slice(&0u32.to_be_bytes()); // sub_agent_id = 0
    buf.extend_from_slice(&seq.to_be_bytes()); // sequence_number
    buf.extend_from_slice(&seq.to_be_bytes()); // uptime_ms (unused by decoder; reuse seq)
    buf.extend_from_slice(&2u32.to_be_bytes()); // num_samples = 2

    append_flow_sample(&mut buf, seq, n);
    append_counter_sample(&mut buf, seq, n);

    buf
}

/// Append one flow_sample (data_format=1) carrying one sampled_ipv4 (format
/// 3) flow record. Byte-for-byte matches `FIXTURE_SFLOW_SAMPLED_IPV4`'s
/// sample layout in `src/sflow/decoder.rs`.
fn append_flow_sample(buf: &mut Vec<u8>, seq: u32, n: u64) {
    let (src, dst) = flow_addrs(n);
    let src_port = 1024 + (n % 60_000) as u32;
    let dst_port = 443u32;
    let protocol = 6u32; // TCP
    let sampling_rate = 1000u32;
    let input_ifindex = 1 + (n % 4) as u32;
    let output_ifindex = 1 + ((n + 1) % 4) as u32;

    // sample_length = 32 (flow sample body header) + 4+4 (record envelope)
    // + 32 (sampled_ipv4 body) = 72.
    buf.extend_from_slice(&1u32.to_be_bytes()); // data_format = flow_sample
    buf.extend_from_slice(&72u32.to_be_bytes()); // sample_length

    // ── flow_sample body header (32 bytes) ──
    buf.extend_from_slice(&seq.to_be_bytes()); // sequence_number
    buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
    buf.extend_from_slice(&sampling_rate.to_be_bytes());
    buf.extend_from_slice(&sampling_rate.to_be_bytes()); // sample_pool
    buf.extend_from_slice(&0u32.to_be_bytes()); // drops
    buf.extend_from_slice(&input_ifindex.to_be_bytes());
    buf.extend_from_slice(&output_ifindex.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes()); // num_flow_records = 1

    // ── flow record: sampled_ipv4 (format 3) ──
    buf.extend_from_slice(&3u32.to_be_bytes()); // flow_data_format = 3
    buf.extend_from_slice(&32u32.to_be_bytes()); // flow_data_length = 32

    // sampled_ipv4 body (32 bytes): length, protocol, src_ip, dst_ip,
    // src_port, dst_port, tcp_flags, tos.
    buf.extend_from_slice(&60u32.to_be_bytes()); // original packet length (arbitrary)
    buf.extend_from_slice(&protocol.to_be_bytes());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // tcp_flags
    buf.extend_from_slice(&0u32.to_be_bytes()); // tos
}

/// Append one counter_sample (data_format=2) carrying one
/// generic_if_counters (enterprise 0, format 1) record. Byte-for-byte
/// matches `FIXTURE_SFLOW_COUNTER`'s sample layout in
/// `src/sflow/decoder.rs`.
fn append_counter_sample(buf: &mut Vec<u8>, seq: u32, n: u64) {
    let if_index = 1 + (n % 4) as u32;
    let if_in_octets = 1_000_000u64 + n * 1_000;
    let if_out_octets = 500_000u64 + n * 500;
    let if_in_ucast_pkts = 1_000u32 + (n % 10_000) as u32;
    let if_out_ucast_pkts = 500u32 + (n % 5_000) as u32;

    // sample_length = 12 (counter sample body header) + 4+4 (record
    // envelope) + 88 (generic_if_counters body) = 108.
    buf.extend_from_slice(&2u32.to_be_bytes()); // data_format = counter_sample
    buf.extend_from_slice(&108u32.to_be_bytes()); // sample_length

    // ── counter_sample body header (12 bytes) ──
    buf.extend_from_slice(&seq.to_be_bytes()); // sequence_number
    buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
    buf.extend_from_slice(&1u32.to_be_bytes()); // num_counter_records = 1

    // ── counter record: generic_if_counters (enterprise=0, format=1) ──
    buf.extend_from_slice(&1u32.to_be_bytes()); // counter_data_format = 1
    buf.extend_from_slice(&88u32.to_be_bytes()); // counter_data_length = 88

    // generic_if_counters body (88 bytes, see decoder.rs's field-offset
    // comment for the exact layout this mirrors).
    buf.extend_from_slice(&if_index.to_be_bytes());
    buf.extend_from_slice(&6u32.to_be_bytes()); // ifType = 6 (ethernetCsmacd)
    buf.extend_from_slice(&1_000_000_000u64.to_be_bytes()); // ifSpeed
    buf.extend_from_slice(&1u32.to_be_bytes()); // ifDirection = full-duplex
    buf.extend_from_slice(&3u32.to_be_bytes()); // ifStatus = admin+oper up
    buf.extend_from_slice(&if_in_octets.to_be_bytes());
    buf.extend_from_slice(&if_in_ucast_pkts.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // ifInMulticastPkts
    buf.extend_from_slice(&0u32.to_be_bytes()); // ifInBroadcastPkts
    buf.extend_from_slice(&0u32.to_be_bytes()); // ifInDiscards
    buf.extend_from_slice(&0u32.to_be_bytes()); // ifInErrors
    buf.extend_from_slice(&0u32.to_be_bytes()); // ifInUnknownProtos
    buf.extend_from_slice(&if_out_octets.to_be_bytes());
    buf.extend_from_slice(&if_out_ucast_pkts.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // ifOutMulticastPkts
    buf.extend_from_slice(&0u32.to_be_bytes()); // ifOutBroadcastPkts
    buf.extend_from_slice(&0u32.to_be_bytes()); // ifOutDiscards
    buf.extend_from_slice(&0u32.to_be_bytes()); // ifOutErrors
    buf.extend_from_slice(&0u32.to_be_bytes()); // ifPromiscuousMode
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit: header fields land at the exact byte offsets the decoder reads
    /// (`src/sflow/decoder.rs::decode_datagram`), independent of the
    /// decoder itself -- if this drifts from the decoder's expectations,
    /// the integration test below (which runs the real decoder) catches it.
    #[test]
    fn datagram_header_has_expected_fields() {
        let buf = build_datagram(1, 0);
        assert_eq!(&buf[0..4], &5u32.to_be_bytes(), "version must be 5");
        assert_eq!(
            &buf[4..8],
            &1u32.to_be_bytes(),
            "agent_addr_type must be 1 (IPv4)"
        );
        assert_eq!(&buf[8..12], &AGENT_ADDR.octets());
        assert_eq!(&buf[24..28], &2u32.to_be_bytes(), "num_samples must be 2");
    }

    /// Unit: the two sample envelopes right after the header must be
    /// data_format=1 (flow_sample) then data_format=2 (counter_sample), in
    /// that order, with sample_length matching each body's actual size.
    #[test]
    fn datagram_carries_flow_then_counter_sample_with_correct_lengths() {
        let buf = build_datagram(7, 3);
        let flow_data_format = u32::from_be_bytes(buf[28..32].try_into().unwrap());
        let flow_sample_length = u32::from_be_bytes(buf[32..36].try_into().unwrap());
        assert_eq!(flow_data_format, 1);
        assert_eq!(flow_sample_length, 72);

        let counter_start = 36 + flow_sample_length as usize;
        let counter_data_format =
            u32::from_be_bytes(buf[counter_start..counter_start + 4].try_into().unwrap());
        let counter_sample_length = u32::from_be_bytes(
            buf[counter_start + 4..counter_start + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(counter_data_format, 2);
        assert_eq!(counter_sample_length, 108);

        // Total length must match exactly: 28 (hdr) + 8+72 + 8+108.
        assert_eq!(buf.len(), 28 + 8 + 72 + 8 + 108);
    }

    /// Integration: feed real generated bytes into logthing's own sFlow
    /// decoder and assert both samples decode with the expected values.
    /// This is the guard against a generator whose bytes the real decoder
    /// silently drops.
    #[test]
    fn datagram_round_trips_through_real_decoder() {
        use logthing::sflow::SampleType;
        use logthing::sflow::decoder::decode_datagram;
        use std::net::IpAddr;

        let exporter = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let buf = build_datagram(42, 5);
        let records = decode_datagram(&buf, exporter).expect("datagram must decode");
        assert_eq!(records.len(), 2, "expected one flow + one counter record");

        let flow = records
            .iter()
            .find(|r| r.sample_type == SampleType::Flow)
            .expect("must contain a flow record");
        let (expected_src, expected_dst) = flow_addrs(5);
        assert_eq!(flow.src_addr, Some(IpAddr::V4(expected_src)));
        assert_eq!(flow.dst_addr, Some(IpAddr::V4(expected_dst)));
        assert_eq!(flow.dst_port, Some(443));
        assert_eq!(flow.ip_protocol, Some(6));
        assert_eq!(flow.sampling_rate, Some(1000));

        let counter = records
            .iter()
            .find(|r| r.sample_type == SampleType::Counter)
            .expect("must contain a counter record");
        assert_eq!(counter.if_index, Some(1 + (5 % 4)));
        assert_eq!(counter.if_in_octets, Some(1_000_000 + 5 * 1_000));
        assert_eq!(counter.if_out_octets, Some(500_000 + 5 * 500));
    }

    /// Integration: two datagrams at different indices must decode to flow
    /// records with different `src_addr` -- a generator sending one
    /// identical flow repeatedly would measure the wrong thing.
    #[test]
    fn distinct_datagram_indices_yield_distinct_src_addr() {
        use logthing::sflow::SampleType;
        use logthing::sflow::decoder::decode_datagram;
        use std::net::IpAddr;

        let exporter = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let records_a = decode_datagram(&build_datagram(1, 0), exporter).expect("datagram 0");
        let records_b = decode_datagram(&build_datagram(2, 1), exporter).expect("datagram 1");

        let flow_a = records_a
            .iter()
            .find(|r| r.sample_type == SampleType::Flow)
            .unwrap();
        let flow_b = records_b
            .iter()
            .find(|r| r.sample_type == SampleType::Flow)
            .unwrap();
        assert_ne!(flow_a.src_addr, flow_b.src_addr);
    }

    /// Integration: a run of N datagrams must decode to exactly 2N total
    /// records (N flow + N counter) with zero drops -- the load-bearing
    /// proof that `SAMPLES_PER_DATAGRAM` in `run()`'s reporting line
    /// matches what the real decoder actually extracts.
    #[test]
    fn ten_datagrams_decode_to_twenty_records_with_no_drops() {
        use logthing::sflow::decoder::decode_datagram;
        use std::net::IpAddr;

        let exporter = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut total = 0usize;
        for n in 0..10u64 {
            let records = decode_datagram(&build_datagram(n as u32 + 1, n), exporter)
                .unwrap_or_else(|e| panic!("datagram {n} must decode: {e}"));
            total += records.len();
        }
        assert_eq!(total, 10 * SAMPLES_PER_DATAGRAM as usize);
    }
}
