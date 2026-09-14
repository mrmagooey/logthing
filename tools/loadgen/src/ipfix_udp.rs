//! `loadgen ipfix-udp` -- paced UDP IPFIX v10 load generator.
//!
//! IPFIX is stateful on the wire: `logthing`'s collector
//! (`src/ipfix/decoder.rs`) caches templates keyed by
//! `(exporter, observation_domain_id, template_id)` and silently drops any
//! data set whose template it hasn't seen yet, counting the drop in
//! `ipfix_templates_missing`. A generator that sends data sets without ever
//! (re-)sending the template would make the collector drop every datagram
//! and the run would measure nothing. So this subcommand, like a real
//! exporter, sends the template set before any data set and re-sends it on
//! `--template-interval-secs` for the lifetime of the run.
//!
//! Wire format: one fixed template (id 256, IE 8 sourceIPv4Address + IE 12
//! destinationIPv4Address, 4 bytes each), matching
//! `FIXTURE_IPFIX_TEMPLATE_THEN_DATA` in `src/ipfix/decoder.rs`. Each data
//! datagram carries exactly one flow record, with source/destination
//! addresses derived from the flow index so records are genuinely distinct.

use anyhow::Context;
use chrono::Utc;
use clap::Args;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::MissedTickBehavior;

use crate::pacing::tick_record_count;

/// Template id used for every template/data datagram this generator sends.
const TEMPLATE_ID: u16 = 256;

#[derive(Args, Debug)]
pub struct IpfixUdpArgs {
    /// Target host to send IPFIX UDP datagrams to.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Target UDP port. Matches `IpfixConfig`'s real default
    /// (`default_ipfix_udp_port() -> 4739`).
    #[arg(long, default_value_t = 4739)]
    pub port: u16,

    /// Target sustained rate, in flows/sec (one flow record per data
    /// datagram). 0 means "unbounded".
    #[arg(long, default_value_t = 10_000)]
    pub target_rate: u64,

    /// How long to send for, in seconds.
    #[arg(long, default_value_t = 60)]
    pub duration_secs: u64,

    /// How often to re-send the template set, in seconds, as a real exporter
    /// does. A collector that (re)starts mid-run only picks up data sets
    /// again once it sees a fresh template.
    #[arg(long, default_value_t = 60)]
    pub template_interval_secs: u64,
}

pub async fn run(args: IpfixUdpArgs) -> anyhow::Result<()> {
    let target: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .with_context(|| format!("invalid target address {}:{}", args.host, args.port))?;

    // Bind an ephemeral local UDP socket, then `connect` it to fix the peer
    // so sends use `send` instead of `send_to` (see syslog_udp.rs for why).
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind local UDP socket")?;
    socket
        .connect(target)
        .await
        .context("connect UDP socket to target")?;

    println!(
        "loadgen ipfix-udp: sending to {target} at target_rate={} flows/s for {}s \
         (template re-sent every {}s)",
        args.target_rate, args.duration_secs, args.template_interval_secs
    );

    let duration = Duration::from_secs(args.duration_secs);
    let template_interval = Duration::from_secs(args.template_interval_secs);
    let start = Instant::now();
    let mut sent: u64 = 0;
    let mut seq: u32 = 1;

    // Template must go out before any data set -- a data set decoded against
    // a cold cache is silently dropped (see the `cold_decoder` test below).
    socket
        .send(&build_template_datagram(seq))
        .await
        .context("send template datagram")?;
    seq = seq.wrapping_add(1);
    let mut last_template_sent = Instant::now();

    if args.target_rate == 0 {
        // Unbounded: send as fast as the socket will accept.
        while start.elapsed() < duration {
            if last_template_sent.elapsed() >= template_interval {
                socket
                    .send(&build_template_datagram(seq))
                    .await
                    .context("send template datagram")?;
                seq = seq.wrapping_add(1);
                last_template_sent = Instant::now();
            }
            socket
                .send(&build_data_datagram(seq, sent))
                .await
                .context("send data datagram")?;
            seq = seq.wrapping_add(1);
            sent += 1;
        }
    } else {
        // Paced: same 1ms-tick, N-per-tick, fractional-carry pattern as
        // syslog_udp.rs / pacing.rs.
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

            if last_template_sent.elapsed() >= template_interval {
                socket
                    .send(&build_template_datagram(seq))
                    .await
                    .context("send template datagram")?;
                seq = seq.wrapping_add(1);
                last_template_sent = Instant::now();
            }

            let records_this_tick = tick_record_count(&mut carry, records_per_tick_target);
            for _ in 0..records_this_tick {
                if start.elapsed() >= duration {
                    break 'send_loop;
                }
                socket
                    .send(&build_data_datagram(seq, sent))
                    .await
                    .context("send data datagram")?;
                seq = seq.wrapping_add(1);
                sent += 1;
            }
        }
    }

    let elapsed = start.elapsed();
    println!(
        "loadgen ipfix-udp: sent {sent} flows in {:.3}s (achieved rate: {:.1} flows/s)",
        elapsed.as_secs_f64(),
        sent as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}

/// Derive distinct source/destination addresses for flow index `n`, so a run
/// of N flows produces N genuinely distinct records instead of one flow
/// replayed N times.
fn flow_addrs(n: u64) -> (Ipv4Addr, Ipv4Addr) {
    let hi = ((n >> 8) & 0xFF) as u8;
    let lo = (n & 0xFF) as u8;
    (
        Ipv4Addr::new(10, 0, hi, lo),
        Ipv4Addr::new(192, 168, hi, lo),
    )
}

/// Build an IPFIX v10 datagram containing only the template set for template
/// id 256 (IE 8 sourceIPv4Address + IE 12 destinationIPv4Address, 4 bytes
/// each) -- byte-for-byte the template half of
/// `FIXTURE_IPFIX_TEMPLATE_THEN_DATA` in `src/ipfix/decoder.rs`.
fn build_template_datagram(seq: u32) -> Vec<u8> {
    let export_time = Utc::now().timestamp() as u32;
    let mut buf = Vec::with_capacity(32);

    // Message header (16 bytes).
    buf.extend_from_slice(&10u16.to_be_bytes()); // version
    buf.extend_from_slice(&32u16.to_be_bytes()); // total length = 16 hdr + 16 template set
    buf.extend_from_slice(&export_time.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // observation domain id

    // Template Set (16 bytes: 4 hdr + 2 tmpl_id + 2 field_count + 2 fields x 4).
    buf.extend_from_slice(&2u16.to_be_bytes()); // set id = 2 (template set)
    buf.extend_from_slice(&16u16.to_be_bytes()); // set length
    buf.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
    buf.extend_from_slice(&2u16.to_be_bytes()); // field count
    buf.extend_from_slice(&8u16.to_be_bytes()); // ie 8: sourceIPv4Address
    buf.extend_from_slice(&4u16.to_be_bytes()); // length 4
    buf.extend_from_slice(&12u16.to_be_bytes()); // ie 12: destinationIPv4Address
    buf.extend_from_slice(&4u16.to_be_bytes()); // length 4

    buf
}

/// Build an IPFIX v10 datagram containing one data record for template id
/// 256, with addresses derived from flow index `n` -- byte-for-byte the same
/// layout as the data half of `FIXTURE_IPFIX_TEMPLATE_THEN_DATA`.
fn build_data_datagram(seq: u32, n: u64) -> Vec<u8> {
    let export_time = Utc::now().timestamp() as u32;
    let (src, dst) = flow_addrs(n);
    let mut buf = Vec::with_capacity(28);

    // Message header (16 bytes).
    buf.extend_from_slice(&10u16.to_be_bytes()); // version
    buf.extend_from_slice(&28u16.to_be_bytes()); // total length = 16 hdr + 12 data set
    buf.extend_from_slice(&export_time.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // observation domain id

    // Data Set (12 bytes: 4 hdr + 8 data).
    buf.extend_from_slice(&TEMPLATE_ID.to_be_bytes()); // set id = template id
    buf.extend_from_slice(&12u16.to_be_bytes()); // set length
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use logthing::ipfix::decoder::{IpfixDecoder, decode_datagram};
    use std::net::{IpAddr, Ipv4Addr};

    fn exporter() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// Decisive round-trip test: template then data through logthing's own
    /// decoder, proving these are real, parser-accepted IPFIX bytes.
    #[test]
    fn template_then_data_round_trips_through_decoder() {
        let mut dec = IpfixDecoder::new();
        decode_datagram(&mut dec, &build_template_datagram(1), exporter())
            .expect("template datagram must decode");
        let flows = decode_datagram(&mut dec, &build_data_datagram(2, 0), exporter())
            .expect("data datagram must decode");
        assert_eq!(flows.len(), 1);
    }

    /// Pins the exact behaviour the template-resend logic in `run` exists to
    /// prevent: a data datagram sent to a decoder that has never seen the
    /// template yields zero flows (dropped, not decoded), because the
    /// collector has nowhere cached to look up field layout.
    #[test]
    fn data_datagram_against_cold_decoder_yields_no_flows() {
        let mut dec = IpfixDecoder::new();
        let flows = decode_datagram(&mut dec, &build_data_datagram(1, 0), exporter())
            .expect("datagram must still decode as a message even with an uncached template");
        assert_eq!(
            flows.len(),
            0,
            "data set referencing an uncached template must be dropped"
        );
    }

    /// Two data datagrams at different flow indices must decode to flows
    /// with different `src_addr` -- a generator sending one identical flow
    /// repeatedly would measure the wrong thing.
    #[test]
    fn distinct_flow_indices_yield_distinct_src_addr() {
        let mut dec = IpfixDecoder::new();
        decode_datagram(&mut dec, &build_template_datagram(1), exporter()).expect("template");
        let flows_a = decode_datagram(&mut dec, &build_data_datagram(2, 0), exporter())
            .expect("data 0 must decode");
        let flows_b = decode_datagram(&mut dec, &build_data_datagram(3, 1), exporter())
            .expect("data 1 must decode");
        assert_ne!(flows_a[0].src_addr, flows_b[0].src_addr);
    }
}
