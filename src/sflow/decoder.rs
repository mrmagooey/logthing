//! sFlow v5 binary decoder.
//!
//! All sFlow v5 fields are big-endian (XDR) and 4-byte aligned.
//! The decoder is stateless — sFlow v5 carries all necessary context inline.
//!
//! Entry point: `decode_datagram(buf, exporter) -> anyhow::Result<Vec<SflowRecord>>`

use anyhow::{Context, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::sflow::{SampleType, SflowRecord};

/// Maximum number of non-curated (unknown-format / vendor-specific) records
/// accumulated into a single sample's `extra` array.
///
/// `num_flow_records` / `num_counter_records` are attacker-controlled: a
/// single sFlow v5 sample can declare thousands of 8-byte-envelope unknown
/// records, and each one is promoted to a `serde_json::Map` (~632 bytes of
/// heap for a handful of keys) — roughly 80x the wire size per record before
/// this cap. A real exporter emits one or two vendor-specific records per
/// sample (on top of the curated raw_packet_header / sampled_ipv4 /
/// generic_if_counters record), so 8 is generous headroom for any legitimate
/// sample.
///
/// This is also the number that sets the ceiling for one queued
/// `SflowRecord`: `MAX_UNKNOWN_RECORDS_PER_DATAGRAM` never replenishes
/// within a datagram, but it starts *full* for every datagram, so the very
/// first sample can still accept a full `MAX_UNKNOWN_RECORDS_PER_SAMPLE`
/// worth of records. Lowering this value directly lowers
/// `channel_budget::SFLOW_RECORD_BYTES` (see that constant's doc comment for
/// the measured cost and the tradeoff against channel depth) — this is not
/// an independent knob from that one.
///
/// This bound alone is **not sufficient** to bound a *datagram's* total
/// retention: an attacker can pack many small samples into one datagram,
/// each staying under this cap, and defeat it in aggregate. See
/// `MAX_UNKNOWN_RECORDS_PER_DATAGRAM`, which is the bound that actually
/// holds regardless of how records are distributed across samples.
const MAX_UNKNOWN_RECORDS_PER_SAMPLE: usize = 8;

/// Maximum number of non-curated records accumulated into `extra` across an
/// *entire datagram* — shared by every sample decoded from one
/// `decode_datagram` call, decremented as records are accepted, regardless
/// of how the attacker splits records across samples.
///
/// Why a per-sample cap alone does not work: a minimal capped sample costs
/// (on the wire) 8 bytes for the sample envelope (`data_format` +
/// `sample_length`) plus 32 bytes for the flow-sample header
/// (`num_flow_records` at offset 28) plus `MAX_UNKNOWN_RECORDS_PER_SAMPLE`
/// record envelopes of 8 bytes each (zero-length bodies): 8 + 32 + 8x8 = 104
/// bytes total. A 65,535-byte datagram can therefore carry roughly
/// (65535 - 28) / 104 = 629 such samples, i.e. 629 x 8 = 5,032 unknown
/// records if only the per-sample cap applied -- still an unbounded-in-effect
/// amount regardless of the exact per-sample cap value, which is *why* this
/// datagram-wide budget exists rather than trying to size the per-sample cap
/// down further.
///
/// This datagram-wide budget bounds the *aggregate* accepted-record count
/// across every sample in one datagram to 512, regardless of how those
/// records are distributed. At the ~713 bytes/record this decoder allocates
/// for a small/flat non-curated record spread across *many different*
/// samples (measured by `tests/channel_budget_allocator.rs`), that aggregate
/// is 512 x 713 ≈ 365,056 bytes (~365 KB / 356 KiB) of real record data
/// spread across up to 512 different `SflowRecord`s -- versus the original
/// ~5.34 MB concentrated in one record. 512 is comfortably above what a
/// legitimate multi-sample datagram carries: even a busy datagram with ~100
/// samples, each with a couple of vendor-specific extension records, is only
/// ~200 unknown records.
///
/// **This bounds the datagram total, not any single record.** If an attacker
/// concentrates records into as few samples as the per-sample cap allows
/// (worst case: `MAX_UNKNOWN_RECORDS_PER_SAMPLE` records in one sample, which
/// the datagram-wide budget does not prevent since it starts full for every
/// datagram), a single queued `SflowRecord` can still cost as much as
/// `channel_budget::SFLOW_RECORD_BYTES` — see that constant's doc comment for
/// the measured worst case, which is the number that actually bounds one
/// channel slot, not this 713-byte *average-when-spread-out* figure.
///
/// One more thing has to be bounded once this budget exists: a truncation
/// marker is itself a small `serde_json` object (~632 bytes, same node cost
/// as a real record). Once the budget hits zero, letting every remaining
/// sample mint its own marker (a sample needs only one 8-byte record
/// envelope to trigger one) would itself retain close to as much as the
/// records did. `DatagramUnknownBudget` avoids this by never attaching a
/// per-sample marker for datagram-budget exhaustion at all: `total_dropped`
/// accumulates the true count from every sample (not just the first to
/// observe exhaustion), and `decode_datagram` surfaces that real aggregate
/// exactly once per datagram, after every sample has been decoded -- as a
/// `sflow_unknown_records_dropped` metrics counter, a `tracing::warn!`, and
/// (if at least one record decoded from this datagram) one marker appended
/// to the last decoded record's `extra`.
const MAX_UNKNOWN_RECORDS_PER_DATAGRAM: usize = 512;

/// Per-datagram state for `UnknownRecordSink`, shared (via `&mut`) across
/// every sample decoded from one `decode_datagram` call.
struct DatagramUnknownBudget {
    /// Unknown records still accepted before `MAX_UNKNOWN_RECORDS_PER_DATAGRAM`
    /// is reached. Never replenished within a datagram.
    remaining: usize,
    /// True aggregate count of records dropped for exhausting this budget,
    /// across *every* sample in the datagram, not just the first to observe
    /// `remaining == 0`. `decode_datagram` reads this once, after every
    /// sample has been decoded, to report the real total -- see
    /// `MAX_UNKNOWN_RECORDS_PER_DATAGRAM`'s doc comment.
    total_dropped: u64,
}

impl DatagramUnknownBudget {
    fn new() -> Self {
        Self {
            remaining: MAX_UNKNOWN_RECORDS_PER_DATAGRAM,
            total_dropped: 0,
        }
    }
}

/// Accumulates the unknown/vendor-specific records for one sample, subject
/// to two bounds: the sample-local cap (`MAX_UNKNOWN_RECORDS_PER_SAMPLE`) and
/// the datagram-wide budget shared across every sample in this datagram.
/// Either bound dropping a record does not abort parsing of the rest of the
/// sample or datagram.
///
/// Sample-cap drops are reported locally: `finish()` folds them into a
/// per-sample truncation marker, since that count is always accurate the
/// moment the sample finishes. Datagram-budget drops are *not* reported
/// locally -- only `decode_datagram` knows the true aggregate once every
/// sample has run, so it reads `DatagramUnknownBudget::total_dropped`
/// directly and reports it once; see `MAX_UNKNOWN_RECORDS_PER_DATAGRAM`.
struct UnknownRecordSink<'a> {
    records: Vec<serde_json::Value>,
    dropped_sample_cap: u64,
    budget: &'a mut DatagramUnknownBudget,
}

impl<'a> UnknownRecordSink<'a> {
    fn new(budget: &'a mut DatagramUnknownBudget) -> Self {
        Self {
            records: Vec::new(),
            dropped_sample_cap: 0,
            budget,
        }
    }

    fn push(&mut self, value: serde_json::Value) {
        if self.records.len() >= MAX_UNKNOWN_RECORDS_PER_SAMPLE {
            self.dropped_sample_cap += 1;
            return;
        }
        if self.budget.remaining == 0 {
            self.budget.total_dropped += 1;
            return;
        }
        self.records.push(value);
        self.budget.remaining -= 1;
    }

    /// Consume the sink, appending a sample-local truncation marker if the
    /// sample-cap was hit, and return the records. Datagram-budget drops are
    /// not reported here -- see `MAX_UNKNOWN_RECORDS_PER_DATAGRAM`.
    fn finish(mut self) -> Vec<serde_json::Value> {
        if self.dropped_sample_cap > 0 {
            self.records.push(serde_json::json!({
                "truncated": self.dropped_sample_cap,
                "reason": "sample_cap",
            }));
        }
        self.records
    }
}

// ── Bounds-checked read helpers ───────────────────────────────────────────────

fn read_u32(buf: &[u8], off: usize) -> anyhow::Result<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "sflow: truncated at offset {off} (need u32, have {} bytes)",
                buf.len().saturating_sub(off)
            )
        })
}

fn read_u64(buf: &[u8], off: usize) -> anyhow::Result<u64> {
    buf.get(off..off + 8)
        .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "sflow: truncated at offset {off} (need u64, have {} bytes)",
                buf.len().saturating_sub(off)
            )
        })
}

fn read_bytes(buf: &[u8], off: usize, len: usize) -> anyhow::Result<&[u8]> {
    buf.get(off..off + len).ok_or_else(|| {
        anyhow::anyhow!(
            "sflow: truncated at offset {off} (need {len} bytes, have {})",
            buf.len().saturating_sub(off)
        )
    })
}

/// Decode one sFlow v5 UDP datagram.
///
/// Returns `Err` for datagram-level truncation or wrong version.
/// Sample-level errors (truncated sample body, unknown agent address type) are
/// logged as warnings and the sample is skipped — `Ok(partial_records)` is returned.
pub fn decode_datagram(buf: &[u8], _exporter: IpAddr) -> anyhow::Result<Vec<SflowRecord>> {
    metrics::counter!("sflow_datagrams_received").increment(1);

    // ── Datagram header ──────────────────────────────────────────────────────
    // version(4) agent_addr_type(4) agent_addr(4|16) sub_agent_id(4)
    // sequence_number(4) uptime_ms(4) num_samples(4)
    // Minimum for IPv4 agent: 28 bytes

    if buf.len() < 8 {
        bail!(
            "sflow: datagram too short for version+agent_addr_type ({} bytes)",
            buf.len()
        );
    }

    let version = read_u32(buf, 0)?;
    if version != 5 {
        bail!("sflow: unsupported version {version} (only v5 is supported)");
    }

    let agent_addr_type = read_u32(buf, 4)?;
    let (agent_addr, hdr_end) = match agent_addr_type {
        1 => {
            // IPv4: 4 bytes
            let a = read_bytes(buf, 8, 4)?;
            let ip = IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]));
            (ip, 12usize)
        }
        2 => {
            // IPv6: 16 bytes
            let a = read_bytes(buf, 8, 16)?;
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(a);
            (IpAddr::V6(Ipv6Addr::from(bytes)), 24usize)
        }
        other => bail!("sflow: unknown agent_addr_type {other}"),
    };

    // sub_agent_id(4) sequence_number(4) uptime_ms(4) num_samples(4)
    let _sub_agent_id = read_u32(buf, hdr_end)?;
    let _sequence_number = read_u32(buf, hdr_end + 4)?;
    let _uptime_ms = read_u32(buf, hdr_end + 8)?;
    let num_samples = read_u32(buf, hdr_end + 12)?;

    let mut pos = hdr_end + 16;
    let mut records: Vec<SflowRecord> = Vec::new();
    let received_at = chrono::Utc::now();
    // Shared across every sample in this datagram -- see
    // `MAX_UNKNOWN_RECORDS_PER_DATAGRAM` for why a per-sample-only cap is
    // insufficient.
    let mut datagram_budget = DatagramUnknownBudget::new();

    for _ in 0..num_samples {
        // Each sample: data_format(4) + sample_length(4) + body(sample_length)
        if pos + 8 > buf.len() {
            tracing::warn!("sflow: sample envelope truncated at offset {pos}; stopping");
            break;
        }
        let data_format = read_u32(buf, pos)?;
        let sample_length = read_u32(buf, pos + 4)? as usize;
        pos += 8;

        let body_end = pos + sample_length;
        if body_end > buf.len() {
            tracing::warn!(
                "sflow: sample body claims {sample_length} bytes but only {} remain; skipping",
                buf.len() - pos
            );
            break;
        }
        let sample_body = &buf[pos..body_end];
        pos = body_end;

        // data_format encodes enterprise (top 20 bits) and format (bottom 12 bits).
        let enterprise = data_format >> 12;
        let format = data_format & 0xFFF;

        if enterprise != 0 {
            // Vendor-specific sample — skip entirely.
            continue;
        }

        match format {
            1 | 3 => {
                // flow_sample (1) or expanded_flow_sample (3)
                match decode_flow_sample(
                    sample_body,
                    format,
                    agent_addr,
                    received_at,
                    &mut datagram_budget,
                ) {
                    Ok(mut recs) => records.append(&mut recs),
                    Err(e) => {
                        metrics::counter!("sflow_decode_errors").increment(1);
                        tracing::warn!("sflow: flow sample decode error: {e}");
                    }
                }
            }
            2 | 4 => {
                // counter_sample (2) or expanded_counter_sample (4)
                match decode_counter_sample(
                    sample_body,
                    format,
                    agent_addr,
                    received_at,
                    &mut datagram_budget,
                ) {
                    Ok(mut recs) => records.append(&mut recs),
                    Err(e) => {
                        metrics::counter!("sflow_decode_errors").increment(1);
                        tracing::warn!("sflow: counter sample decode error: {e}");
                    }
                }
            }
            _ => {
                tracing::debug!("sflow: unknown sample format {format}; skipping");
            }
        }
    }

    // Surface the TRUE datagram-wide drop total exactly once, now that every
    // sample has been decoded -- see `MAX_UNKNOWN_RECORDS_PER_DATAGRAM`'s doc
    // comment for why this cannot be known (or reported) from inside any one
    // sample.
    if datagram_budget.total_dropped > 0 {
        metrics::counter!("sflow_unknown_records_dropped").increment(datagram_budget.total_dropped);
        tracing::warn!(
            "sflow: datagram-wide unknown-record budget exhausted; dropped {} unknown \
             record(s) across this datagram (not stored in extra)",
            datagram_budget.total_dropped
        );
        if let Some(last) = records.last_mut() {
            let marker = serde_json::json!({
                "truncated": datagram_budget.total_dropped,
                "reason": "datagram_budget",
            });
            match &mut last.extra {
                serde_json::Value::Array(arr) => arr.push(marker),
                other => *other = serde_json::Value::Array(vec![marker]),
            }
        }
    }

    Ok(records)
}

// ── Flow sample decoder ──────────────────────────────────────────────────────

fn decode_flow_sample(
    body: &[u8],
    format: u32,
    agent_addr: IpAddr,
    received_at: chrono::DateTime<chrono::Utc>,
    datagram_budget: &mut DatagramUnknownBudget,
) -> anyhow::Result<Vec<SflowRecord>> {
    // flow_sample (format 1) body layout:
    //   sequence_number(4) source_id(4) sampling_rate(4) sample_pool(4)
    //   drops(4) input(4) output(4) num_flow_records(4) → 32 bytes
    //
    // expanded_flow_sample (format 3) body layout:
    //   sequence_number(4) ds_class(4) ds_index(4) sampling_rate(4) sample_pool(4)
    //   drops(4) input_if_format(4) input_if_value(4) output_if_format(4) output_if_value(4)
    //   num_flow_records(4) → 44 bytes

    let (sampling_rate, input_ifindex, output_ifindex, num_records, mut pos) = if format == 1 {
        if body.len() < 32 {
            bail!("sflow: flow_sample body too short ({} < 32)", body.len());
        }
        let sampling_rate = read_u32(body, 8)?;
        let input_ifindex = read_u32(body, 20)?;
        let output_ifindex = read_u32(body, 24)?;
        let num_records = read_u32(body, 28)?;
        (
            sampling_rate,
            input_ifindex,
            output_ifindex,
            num_records,
            32usize,
        )
    } else {
        // expanded_flow_sample (format 3)
        if body.len() < 44 {
            bail!(
                "sflow: expanded_flow_sample body too short ({} < 44)",
                body.len()
            );
        }
        let sampling_rate = read_u32(body, 12)?;
        // input: format(4) + value(4) at [24..32]; output at [32..40]
        let input_ifindex = read_u32(body, 28)?; // input if_value
        let output_ifindex = read_u32(body, 36)?; // output if_value
        let num_records = read_u32(body, 40)?;
        (
            sampling_rate,
            input_ifindex,
            output_ifindex,
            num_records,
            44usize,
        )
    };

    // Start with an empty record; update 5-tuple fields from flow records.
    let mut rec = SflowRecord {
        sample_type: SampleType::Flow,
        exporter: agent_addr,
        received_at,
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        ip_protocol: None,
        sampling_rate: Some(sampling_rate),
        input_ifindex: Some(input_ifindex),
        output_ifindex: Some(output_ifindex),
        if_index: None,
        if_type: None,
        if_speed: None,
        if_direction: None,
        if_in_octets: None,
        if_out_octets: None,
        if_in_ucast_pkts: None,
        if_out_ucast_pkts: None,
        if_in_errors: None,
        if_out_errors: None,
        extra: serde_json::json!([]),
    };

    let mut unknown = UnknownRecordSink::new(datagram_budget);

    for _ in 0..num_records {
        if pos + 8 > body.len() {
            tracing::warn!("sflow: flow record envelope truncated at {pos}");
            break;
        }
        let flow_data_format = read_u32(body, pos)?;
        let flow_data_length = read_u32(body, pos + 4)? as usize;
        pos += 8;

        let rec_end = pos + flow_data_length;
        if rec_end > body.len() {
            tracing::warn!(
                "sflow: flow record body claims {flow_data_length} bytes but only {} remain",
                body.len() - pos
            );
            break;
        }
        let rec_body = &body[pos..rec_end];
        pos = rec_end;

        let rec_enterprise = flow_data_format >> 12;
        let rec_format = flow_data_format & 0xFFF;

        if rec_enterprise != 0 {
            // Enterprise-specific — store raw in extra, up to the per-sample/
            // per-datagram budget.
            let data_hex = hex::encode(rec_body);
            unknown.push(serde_json::json!({
                "enterprise": rec_enterprise,
                "format": rec_format,
                "length": flow_data_length,
                "data_hex": data_hex,
            }));
            continue;
        }

        match rec_format {
            1 => {
                // raw_packet_header — parse Ethernet/IPv4/IPv6/TCP/UDP to 5-tuple.
                // Soft-catch: a malformed inner header still leaves the flow record
                // emitted with its sampling/ifindex metadata intact.
                if let Err(e) = decode_raw_packet_header(rec_body, &mut rec) {
                    tracing::debug!("sflow: raw_packet_header parse error: {e}");
                }
            }
            3 => {
                // sampled_ipv4 — carries 5-tuple directly.
                // Soft-catch (same convention as raw_packet_header) so a truncated
                // inner body does not drop the whole flow_sample's metadata.
                if let Err(e) = decode_sampled_ipv4(rec_body, &mut rec) {
                    tracing::debug!("sflow: sampled_ipv4 parse error: {e}");
                }
            }
            4 => {
                // sampled_ipv6 — carries 5-tuple directly.
                // Soft-catch (same convention as raw_packet_header).
                if let Err(e) = decode_sampled_ipv6(rec_body, &mut rec) {
                    tracing::debug!("sflow: sampled_ipv6 parse error: {e}");
                }
            }
            other => {
                let data_hex = hex::encode(rec_body);
                unknown.push(serde_json::json!({
                    "format": other,
                    "length": flow_data_length,
                    "data_hex": data_hex,
                }));
            }
        }
    }

    let unknown_records = unknown.finish();
    if !unknown_records.is_empty() {
        rec.extra = serde_json::Value::Array(unknown_records);
    }

    Ok(vec![rec])
}

// ── Raw packet header parse (Ethernet/IPv4/IPv6/TCP/UDP → 5-tuple) ──────────

fn decode_raw_packet_header(body: &[u8], rec: &mut SflowRecord) -> anyhow::Result<()> {
    // raw_packet_header body:
    //   header_protocol(4) frame_length(4) stripped(4) header_length(4)
    //   header_bytes(header_length, padded to 4-byte alignment)
    if body.len() < 16 {
        bail!("raw_packet_header body too short ({} < 16)", body.len());
    }
    let header_protocol = read_u32(body, 0)?;
    let header_length = read_u32(body, 12)? as usize;

    let header_bytes =
        read_bytes(body, 16, header_length).context("raw_packet_header: header_bytes truncated")?;

    match header_protocol {
        1 => parse_ethernet(header_bytes, rec), // ETHERNET
        11 => parse_ipv4(header_bytes, rec),    // IPv4 (raw)
        12 => parse_ipv6(header_bytes, rec),    // IPv6 (raw)
        _ => {
            tracing::debug!("sflow: raw_packet_header: unsupported protocol {header_protocol}");
            Ok(())
        }
    }
}

fn parse_ethernet(buf: &[u8], rec: &mut SflowRecord) -> anyhow::Result<()> {
    // Ethernet II: dst_mac(6) src_mac(6) ethertype(2) [optional 802.1Q vlan tag(4)]
    if buf.len() < 14 {
        bail!("ethernet: too short ({} bytes)", buf.len());
    }
    let mut ethertype = u16::from_be_bytes([buf[12], buf[13]]);
    let mut payload_start = 14usize;

    // 802.1Q VLAN tag (0x8100)
    if ethertype == 0x8100 {
        if buf.len() < 18 {
            bail!("ethernet: 802.1Q too short");
        }
        ethertype = u16::from_be_bytes([buf[16], buf[17]]);
        payload_start = 18;
    }

    match ethertype {
        0x0800 => parse_ipv4(&buf[payload_start..], rec),
        0x86DD => parse_ipv6(&buf[payload_start..], rec),
        _ => Ok(()), // ARP etc — ignore
    }
}

fn parse_ipv4(buf: &[u8], rec: &mut SflowRecord) -> anyhow::Result<()> {
    // IPv4: version_ihl(1) tos(1) total_length(2) ... protocol(1 at byte 9) src(4 at 12) dst(4 at 16)
    if buf.len() < 20 {
        bail!("ipv4: too short ({} bytes)", buf.len());
    }
    let ihl = (buf[0] & 0x0F) as usize * 4;
    if ihl < 20 || ihl > buf.len() {
        bail!("ipv4: invalid IHL {ihl}");
    }
    let protocol = buf[9];
    let src = IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));

    rec.src_addr = Some(src);
    rec.dst_addr = Some(dst);
    rec.ip_protocol = Some(protocol);

    let transport = &buf[ihl..];
    parse_transport(protocol, transport, rec);
    Ok(())
}

fn parse_ipv6(buf: &[u8], rec: &mut SflowRecord) -> anyhow::Result<()> {
    // IPv6: version_tc_fl(4) payload_length(2) next_header(1) hop_limit(1) src(16) dst(16)
    if buf.len() < 40 {
        bail!("ipv6: too short ({} bytes)", buf.len());
    }
    let next_header = buf[6];
    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&buf[8..24]);
    dst_bytes.copy_from_slice(&buf[24..40]);

    rec.src_addr = Some(IpAddr::V6(Ipv6Addr::from(src_bytes)));
    rec.dst_addr = Some(IpAddr::V6(Ipv6Addr::from(dst_bytes)));
    rec.ip_protocol = Some(next_header);

    let transport = &buf[40..];
    parse_transport(next_header, transport, rec);
    Ok(())
}

fn parse_transport(protocol: u8, buf: &[u8], rec: &mut SflowRecord) {
    match protocol {
        // TCP or UDP: src_port(2) dst_port(2) ...
        6 | 17 if buf.len() >= 4 => {
            rec.src_port = Some(u16::from_be_bytes([buf[0], buf[1]]));
            rec.dst_port = Some(u16::from_be_bytes([buf[2], buf[3]]));
        }
        _ => {} // ICMP etc — no port concept
    }
}

// ── sampled_ipv4 (flow record format 3) ─────────────────────────────────────

fn decode_sampled_ipv4(body: &[u8], rec: &mut SflowRecord) -> anyhow::Result<()> {
    // sampled_ipv4 body (32 bytes):
    //   length(4) protocol(4) src_ip(4) dst_ip(4) src_port(4) dst_port(4) tcp_flags(4) tos(4)
    if body.len() < 32 {
        bail!("sampled_ipv4: too short ({} < 32)", body.len());
    }
    let protocol = read_u32(body, 4)? as u8;
    // src_ip at bytes [8..12], dst_ip at bytes [12..16]
    // Safe: body.len() >= 32 checked above
    let src = IpAddr::V4(Ipv4Addr::new(body[8], body[9], body[10], body[11]));
    let dst = IpAddr::V4(Ipv4Addr::new(body[12], body[13], body[14], body[15]));
    let src_port = read_u32(body, 16)? as u16;
    let dst_port = read_u32(body, 20)? as u16;

    rec.src_addr = Some(src);
    rec.dst_addr = Some(dst);
    rec.ip_protocol = Some(protocol);
    rec.src_port = Some(src_port);
    rec.dst_port = Some(dst_port);
    Ok(())
}

// ── sampled_ipv6 (flow record format 4) ─────────────────────────────────────

fn decode_sampled_ipv6(body: &[u8], rec: &mut SflowRecord) -> anyhow::Result<()> {
    // sampled_ipv6 body (52 bytes):
    //   length(4) protocol(4) src_ip(16) dst_ip(16) src_port(4) dst_port(4) tcp_flags(4) priority(4)
    if body.len() < 52 {
        bail!("sampled_ipv6: too short ({} < 52)", body.len());
    }
    let protocol = read_u32(body, 4)? as u8;
    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&body[8..24]);
    dst_bytes.copy_from_slice(&body[24..40]);
    let src_port = read_u32(body, 40)? as u16;
    let dst_port = read_u32(body, 44)? as u16;

    rec.src_addr = Some(IpAddr::V6(Ipv6Addr::from(src_bytes)));
    rec.dst_addr = Some(IpAddr::V6(Ipv6Addr::from(dst_bytes)));
    rec.ip_protocol = Some(protocol);
    rec.src_port = Some(src_port);
    rec.dst_port = Some(dst_port);
    Ok(())
}

// ── Counter sample decoder ───────────────────────────────────────────────────

fn decode_counter_sample(
    body: &[u8],
    format: u32,
    agent_addr: IpAddr,
    received_at: chrono::DateTime<chrono::Utc>,
    datagram_budget: &mut DatagramUnknownBudget,
) -> anyhow::Result<Vec<SflowRecord>> {
    // counter_sample (format 2) body:
    //   sequence_number(4) source_id(4) num_counter_records(4) → 12 bytes
    // expanded_counter_sample (format 4) body:
    //   sequence_number(4) ds_class(4) ds_index(4) num_counter_records(4) → 16 bytes

    let (num_records, mut pos) = if format == 2 {
        if body.len() < 12 {
            bail!("counter_sample body too short ({} < 12)", body.len());
        }
        (read_u32(body, 8)?, 12usize)
    } else {
        if body.len() < 16 {
            bail!(
                "expanded_counter_sample body too short ({} < 16)",
                body.len()
            );
        }
        (read_u32(body, 12)?, 16usize)
    };

    let mut rec = SflowRecord {
        sample_type: SampleType::Counter,
        exporter: agent_addr,
        received_at,
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        ip_protocol: None,
        sampling_rate: None,
        input_ifindex: None,
        output_ifindex: None,
        if_index: None,
        if_type: None,
        if_speed: None,
        if_direction: None,
        if_in_octets: None,
        if_out_octets: None,
        if_in_ucast_pkts: None,
        if_out_ucast_pkts: None,
        if_in_errors: None,
        if_out_errors: None,
        extra: serde_json::json!([]),
    };

    let mut unknown = UnknownRecordSink::new(datagram_budget);

    for _ in 0..num_records {
        if pos + 8 > body.len() {
            tracing::warn!("sflow: counter record envelope truncated at {pos}");
            break;
        }
        let counter_data_format = read_u32(body, pos)?;
        let counter_data_length = read_u32(body, pos + 4)? as usize;
        pos += 8;

        let rec_end = pos + counter_data_length;
        if rec_end > body.len() {
            tracing::warn!(
                "sflow: counter record body claims {counter_data_length} bytes but only {} remain",
                body.len() - pos
            );
            break;
        }
        let rec_body = &body[pos..rec_end];
        pos = rec_end;

        let rec_enterprise = counter_data_format >> 12;
        let rec_format = counter_data_format & 0xFFF;

        if rec_enterprise != 0 || rec_format != 1 {
            // Non-generic counter record — store raw in extra, up to the
            // per-sample/per-datagram budget.
            let data_hex = hex::encode(rec_body);
            unknown.push(serde_json::json!({
                "enterprise": rec_enterprise,
                "format": rec_format,
                "length": counter_data_length,
                "data_hex": data_hex,
            }));
            continue;
        }

        // generic_if_counters (enterprise=0, format=1): 88 bytes
        // Layout (all fields with their byte offsets):
        //   ifIndex(u32)       @ 0
        //   ifType(u32)        @ 4
        //   ifSpeed(u64)       @ 8
        //   ifDirection(u32)   @ 16
        //   ifStatus(u32)      @ 20
        //   ifInOctets(u64)    @ 24
        //   ifInUcastPkts(u32) @ 32
        //   ifInMulticast(u32) @ 36
        //   ifInBroadcast(u32) @ 40
        //   ifInDiscards(u32)  @ 44
        //   ifInErrors(u32)    @ 48
        //   ifInUnknownP(u32)  @ 52
        //   ifOutOctets(u64)   @ 56
        //   ifOutUcastPkts(u32)@ 64
        //   ifOutMulticast(u32)@ 68
        //   ifOutBroadcast(u32)@ 72
        //   ifOutDiscards(u32) @ 76
        //   ifOutErrors(u32)   @ 80
        //   ifPromiscuous(u32) @ 84
        //   Total = 88 bytes
        if rec_body.len() < 88 {
            bail!("generic_if_counters too short ({} < 88)", rec_body.len());
        }
        rec.if_index = Some(read_u32(rec_body, 0)?);
        rec.if_type = Some(read_u32(rec_body, 4)?);
        rec.if_speed = Some(read_u64(rec_body, 8)?);
        rec.if_direction = Some(read_u32(rec_body, 16)?);
        // ifStatus at offset 20 — not separately curated
        rec.if_in_octets = Some(read_u64(rec_body, 24)?);
        rec.if_in_ucast_pkts = Some(read_u32(rec_body, 32)? as u64);
        // ifInMulticastPkts @ 36 — not separately curated
        // ifInBroadcastPkts @ 40 — not separately curated
        // ifInDiscards      @ 44 — not separately curated
        rec.if_in_errors = Some(read_u32(rec_body, 48)?);
        // ifInUnknownProtos @ 52 — not separately curated
        rec.if_out_octets = Some(read_u64(rec_body, 56)?);
        rec.if_out_ucast_pkts = Some(read_u32(rec_body, 64)? as u64);
        // ifOutMulticastPkts @ 68 — not separately curated
        // ifOutBroadcastPkts @ 72 — not separately curated
        // ifOutDiscards      @ 76 — not separately curated
        rec.if_out_errors = Some(read_u32(rec_body, 80)?);
        // ifPromiscuousMode  @ 84 — not separately curated
    }

    let unknown_records = unknown.finish();
    if !unknown_records.is_empty() {
        rec.extra = serde_json::Value::Array(unknown_records);
    }

    Ok(vec![rec])
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn exporter() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

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
    pub(crate) const FIXTURE_SFLOW_FLOW_RAW_HEADER: &[u8] = &[
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
    pub(crate) const FIXTURE_SFLOW_SAMPLED_IPV4: &[u8] = &[
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
    pub(crate) const FIXTURE_SFLOW_COUNTER: &[u8] = &[
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

    // ── fixture: truncated datagram (only datagram header, no samples body) ──
    pub(crate) const FIXTURE_SFLOW_TRUNCATED: &[u8] = &[
        0x00, 0x00, 0x00, 0x05, // version = 5
        0x00, 0x00, 0x00, 0x01, // agent_addr_type = 1 (IPv4)
        0x0A, 0x00, 0x00,
        0x01, // agent_addr = 10.0.0.1
              // missing: sub_agent_id, sequence_number, uptime_ms, num_samples
    ];

    // ── fixture: wrong version (version=4 is not sFlow v5) ──
    pub(crate) const FIXTURE_SFLOW_BAD_VERSION: &[u8] = &[
        0x00, 0x00, 0x00, 0x04, // version = 4 (wrong)
        0x00, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn decode_flow_sample_raw_header_extracts_5tuple() {
        let records = decode_datagram(FIXTURE_SFLOW_FLOW_RAW_HEADER, exporter()).unwrap();
        assert_eq!(records.len(), 1, "expected 1 flow record");
        let r = &records[0];
        assert_eq!(r.sample_type, crate::sflow::SampleType::Flow);
        assert_eq!(r.exporter, exporter());
        assert_eq!(r.src_addr, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        assert_eq!(r.dst_addr, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert_eq!(r.src_port, Some(8080));
        assert_eq!(r.dst_port, Some(80));
        assert_eq!(r.ip_protocol, Some(6)); // TCP
        assert_eq!(r.sampling_rate, Some(512));
        assert_eq!(r.input_ifindex, Some(1));
        assert_eq!(r.output_ifindex, Some(2));
    }

    #[test]
    fn decode_flow_sample_sampled_ipv4_extracts_5tuple() {
        let records = decode_datagram(FIXTURE_SFLOW_SAMPLED_IPV4, exporter()).unwrap();
        assert_eq!(records.len(), 1, "expected 1 flow record");
        let r = &records[0];
        assert_eq!(r.sample_type, crate::sflow::SampleType::Flow);
        assert_eq!(r.src_addr, Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert_eq!(r.dst_addr, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert_eq!(r.src_port, Some(49210));
        assert_eq!(r.dst_port, Some(53));
        assert_eq!(r.ip_protocol, Some(17)); // UDP
        assert_eq!(r.sampling_rate, Some(1000));
        assert_eq!(r.input_ifindex, Some(3));
        assert_eq!(r.output_ifindex, Some(4));
    }

    #[test]
    fn decode_counter_sample_extracts_generic_interface_counters() {
        let records = decode_datagram(FIXTURE_SFLOW_COUNTER, exporter()).unwrap();
        assert_eq!(records.len(), 1, "expected 1 counter record");
        let r = &records[0];
        assert_eq!(r.sample_type, crate::sflow::SampleType::Counter);
        assert_eq!(r.if_index, Some(1));
        assert_eq!(r.if_type, Some(6));
        assert_eq!(r.if_speed, Some(1_000_000_000));
        assert_eq!(r.if_in_octets, Some(1_000_000));
        assert_eq!(r.if_out_octets, Some(500_000));
        assert_eq!(r.if_in_ucast_pkts, Some(1000));
        assert_eq!(r.if_out_ucast_pkts, Some(500));
        assert_eq!(r.if_in_errors, Some(2));
        assert_eq!(r.if_out_errors, Some(1));
        // flow fields absent
        assert!(r.src_addr.is_none());
        assert!(r.dst_addr.is_none());
    }

    #[test]
    fn decode_truncated_datagram_returns_error() {
        let result = decode_datagram(FIXTURE_SFLOW_TRUNCATED, exporter());
        assert!(result.is_err(), "truncated datagram must return Err");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("truncated") || msg.contains("too short"),
            "error must mention truncation; got: {msg}"
        );
    }

    #[test]
    fn decode_wrong_version_returns_error() {
        let result = decode_datagram(FIXTURE_SFLOW_BAD_VERSION, exporter());
        assert!(result.is_err(), "wrong version must return Err");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("version") || msg.contains("4"),
            "error must mention the bad version; got: {msg}"
        );
    }

    #[test]
    fn unknown_flow_record_format_goes_to_extra() {
        // Build a minimal flow sample with one flow record of enterprise=0, format=99 (vendor-specific).
        // The record body is 4 bytes of zeros; the decoder must not error and must store the raw
        // data in extra[].
        // For brevity, copy FIXTURE_SFLOW_FLOW_RAW_HEADER and replace:
        //   flow_data_format offset  [68..72] → 0x00000063 (format=99)
        //   flow_data_length [72..76] → 0x00000004
        //   then 4 bytes of body
        // We rebuild the relevant bytes manually:
        let mut buf = FIXTURE_SFLOW_FLOW_RAW_HEADER.to_vec();
        // flow_data_format is at byte offset 68 in this fixture:
        buf[68] = 0x00;
        buf[69] = 0x00;
        buf[70] = 0x00;
        buf[71] = 0x63; // format=99
        // flow_data_length = 4
        buf[72] = 0x00;
        buf[73] = 0x00;
        buf[74] = 0x00;
        buf[75] = 0x04;
        // Replace remaining bytes (the header_bytes block) with 4 zero bytes,
        // then truncate to the new correct length:
        // New total after format+length bytes: 76 + 4 = 80 bytes
        buf.truncate(76);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Fix sample_length at [32..36]: was 120, now 32 + 4+4+4 = 44
        buf[32] = 0x00;
        buf[33] = 0x00;
        buf[34] = 0x00;
        buf[35] = 0x2C; // 44

        let records = decode_datagram(&buf, exporter()).unwrap();
        assert_eq!(records.len(), 1);
        // The 5-tuple should be absent (no recognised flow record decoded)
        assert!(records[0].src_addr.is_none());
        // extra should contain the unknown record
        let extra = &records[0].extra;
        assert!(
            extra.is_array() || extra.get("unknown_records").is_some() || {
                // Accept either array-at-root or object with a key
                let s = extra.to_string();
                s.contains("format") || s.contains("data_hex")
            },
            "unknown flow record must appear in extra; got: {extra}"
        );
        // The unknown record must be tagged with format=99 and carry hex-encoded data.
        let s = records[0].extra.to_string();
        assert!(
            s.contains("\"data_hex\""),
            "extra must use data_hex key; got: {s}"
        );
        assert!(
            !s.contains("data_base64"),
            "data_base64 key must be gone; got: {s}"
        );
    }

    #[test]
    fn truncated_sampled_ipv4_body_still_emits_flow_metadata() {
        // FIX 2 regression: a truncated sampled_ipv4 inner body must be soft-caught,
        // leaving the 5-tuple None but preserving the flow_sample metadata
        // (sampling_rate / input_ifindex / output_ifindex).
        let mut buf = FIXTURE_SFLOW_SAMPLED_IPV4.to_vec();
        // flow_data_length is at offset 72 in this fixture (after the 32-byte flow
        // sample body header which ends at 68, then flow_data_format at 68..72).
        // Shrink the sampled_ipv4 body from 32 to 4 bytes so it is truncated.
        buf[72] = 0x00;
        buf[73] = 0x00;
        buf[74] = 0x00;
        buf[75] = 0x04; // flow_data_length = 4 (too short for sampled_ipv4)
        // Truncate buffer to the new record length: header ends at 76, +4 body = 80.
        buf.truncate(80);
        // Fix sample_length at [32..36]: 32 (flow hdr) + 4+4 (rec envelope) + 4 = 44.
        buf[32] = 0x00;
        buf[33] = 0x00;
        buf[34] = 0x00;
        buf[35] = 0x2C; // 44

        let records = decode_datagram(&buf, exporter()).unwrap();
        assert_eq!(records.len(), 1, "flow record must still be emitted");
        let r = &records[0];
        // 5-tuple absent because the inner body was truncated.
        assert!(r.src_addr.is_none());
        assert!(r.dst_addr.is_none());
        // Metadata from the flow_sample header is preserved.
        assert_eq!(r.sampling_rate, Some(1000));
        assert_eq!(r.input_ifindex, Some(3));
        assert_eq!(r.output_ifindex, Some(4));
    }

    // ── FIX (sflow extra amplification): cap + truncation marker ────────────

    #[test]
    fn hostile_flow_sample_caps_unknown_records_and_emits_truncation_marker() {
        // Regression for the sFlow extra amplification bug: a single
        // flow_sample declaring thousands of 8-byte-envelope unknown records
        // (format 1001, enterprise 0, zero-length body) must not balloon
        // `extra` 1:1 with the attacker-declared record count.
        const NUM_RECORDS: u32 = 8177;
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes()); // version = 5
        buf.extend_from_slice(&1u32.to_be_bytes()); // agent_addr_type = IPv4
        buf.extend_from_slice(&[10, 0, 0, 1]); // agent_addr
        buf.extend_from_slice(&0u32.to_be_bytes()); // sub_agent_id
        buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
        buf.extend_from_slice(&1u32.to_be_bytes()); // uptime_ms
        buf.extend_from_slice(&1u32.to_be_bytes()); // num_samples = 1

        let sample_body_len = 32 + (NUM_RECORDS as usize) * 8;
        buf.extend_from_slice(&1u32.to_be_bytes()); // data_format = flow_sample
        buf.extend_from_slice(&(sample_body_len as u32).to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
        buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
        buf.extend_from_slice(&512u32.to_be_bytes()); // sampling_rate
        buf.extend_from_slice(&512u32.to_be_bytes()); // sample_pool
        buf.extend_from_slice(&0u32.to_be_bytes()); // drops
        buf.extend_from_slice(&7u32.to_be_bytes()); // input_ifindex
        buf.extend_from_slice(&9u32.to_be_bytes()); // output_ifindex
        buf.extend_from_slice(&NUM_RECORDS.to_be_bytes()); // num_flow_records
        for _ in 0..NUM_RECORDS {
            buf.extend_from_slice(&1001u32.to_be_bytes()); // enterprise 0, format 1001
            buf.extend_from_slice(&0u32.to_be_bytes()); // flow_data_length = 0
        }

        let records =
            decode_datagram(&buf, exporter()).expect("must decode despite hostile record count");
        assert_eq!(records.len(), 1);
        let r = &records[0];
        // Sample metadata still comes through -- the cap doesn't abort the sample.
        assert_eq!(r.sampling_rate, Some(512));
        assert_eq!(r.input_ifindex, Some(7));
        assert_eq!(r.output_ifindex, Some(9));

        let extra = r.extra.as_array().expect("extra must be an array");
        assert_eq!(
            extra.len(),
            MAX_UNKNOWN_RECORDS_PER_SAMPLE + 1,
            "extra must hold at most the cap, plus one truncation marker; got {extra:?}"
        );
        let dropped = NUM_RECORDS as u64 - MAX_UNKNOWN_RECORDS_PER_SAMPLE as u64;
        assert_eq!(
            extra.last().unwrap(),
            &serde_json::json!({ "truncated": dropped, "reason": "sample_cap" }),
            "last element must be a single truncation marker with the dropped count; \
             this datagram only has one sample, so the sample-local cap trips \
             (budget of 512 is untouched, only MAX_UNKNOWN_RECORDS_PER_SAMPLE \
             records were ever accepted)"
        );
    }

    #[test]
    fn normal_flow_sample_unknown_records_under_cap_unaffected() {
        // A handful of vendor-specific records (well under the cap) must all
        // survive into `extra`, untouched, with no truncation marker.
        const NUM_RECORDS: u32 = 3;
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&[10, 0, 0, 1]);
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());

        let sample_body_len = 32 + (NUM_RECORDS as usize) * 8;
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&(sample_body_len as u32).to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&512u32.to_be_bytes());
        buf.extend_from_slice(&512u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&NUM_RECORDS.to_be_bytes());
        for _ in 0..NUM_RECORDS {
            buf.extend_from_slice(&1001u32.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes());
        }

        let records = decode_datagram(&buf, exporter()).unwrap();
        let extra = records[0].extra.as_array().expect("extra must be an array");
        assert_eq!(
            extra.len(),
            NUM_RECORDS as usize,
            "all records under the cap must survive"
        );
        assert!(
            extra.iter().all(|v| v.get("truncated").is_none()),
            "no truncation marker expected below the cap; got {extra:?}"
        );
    }

    #[test]
    fn decoding_continues_after_a_capped_sample() {
        // Two samples in one datagram: the first is hostile and hits the cap,
        // the second is a normal sampled_ipv4 flow. Both must decode --
        // hitting the cap must not abort the rest of the datagram.
        const NUM_RECORDS: u32 = 500;
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&[10, 0, 0, 1]);
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&2u32.to_be_bytes()); // num_samples = 2

        // ── Sample 1: hostile flow_sample ──
        let sample1_body_len = 32 + (NUM_RECORDS as usize) * 8;
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&(sample1_body_len as u32).to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&512u32.to_be_bytes());
        buf.extend_from_slice(&512u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&NUM_RECORDS.to_be_bytes());
        for _ in 0..NUM_RECORDS {
            buf.extend_from_slice(&1001u32.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes());
        }

        // ── Sample 2: sampled_ipv4, reusing the fixture's sample envelope+body ──
        buf.extend_from_slice(&FIXTURE_SFLOW_SAMPLED_IPV4[28..]);

        let records = decode_datagram(&buf, exporter()).unwrap();
        assert_eq!(records.len(), 2, "both samples must decode");

        let capped = &records[0];
        let extra = capped.extra.as_array().expect("extra must be an array");
        assert_eq!(extra.len(), MAX_UNKNOWN_RECORDS_PER_SAMPLE + 1);

        let normal = &records[1];
        assert_eq!(
            normal.src_addr,
            Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)))
        );
        assert_eq!(normal.dst_addr, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert_eq!(normal.src_port, Some(49210));
        assert_eq!(normal.dst_port, Some(53));
    }

    #[test]
    fn hostile_counter_sample_caps_unknown_records_and_emits_truncation_marker() {
        // Same amplification shape as the flow-sample case, but through
        // decode_counter_sample's push site.
        const NUM_RECORDS: u32 = 5000;
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&[10, 0, 0, 1]);
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes()); // num_samples = 1

        let sample_body_len = 12 + (NUM_RECORDS as usize) * 8;
        buf.extend_from_slice(&2u32.to_be_bytes()); // data_format = counter_sample
        buf.extend_from_slice(&(sample_body_len as u32).to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
        buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
        buf.extend_from_slice(&NUM_RECORDS.to_be_bytes()); // num_counter_records
        for _ in 0..NUM_RECORDS {
            buf.extend_from_slice(&1001u32.to_be_bytes()); // enterprise 0, format 1001 (non-generic)
            buf.extend_from_slice(&0u32.to_be_bytes()); // counter_data_length = 0
        }

        let records =
            decode_datagram(&buf, exporter()).expect("must decode despite hostile record count");
        assert_eq!(records.len(), 1);
        let extra = records[0].extra.as_array().expect("extra must be an array");
        assert_eq!(extra.len(), MAX_UNKNOWN_RECORDS_PER_SAMPLE + 1);
        let dropped = NUM_RECORDS as u64 - MAX_UNKNOWN_RECORDS_PER_SAMPLE as u64;
        assert_eq!(
            extra.last().unwrap(),
            &serde_json::json!({ "truncated": dropped, "reason": "sample_cap" })
        );
    }

    // ── FIX ROUND 2 (per-datagram, not per-sample, is the real attack shape) ──

    #[allow(clippy::mutable_key_type)] // false positive: CompositeKey AtomicBool is never hashed
    #[test]
    fn multi_sample_hostile_datagram_caps_total_unknown_records_at_datagram_budget() {
        // The per-sample cap alone does not bound an attacker who splits
        // records across many samples, each staying under the per-sample
        // cap. Build 80 samples, each declaring exactly
        // MAX_UNKNOWN_RECORDS_PER_SAMPLE (8) unknown records -- so no sample
        // ever trips its own per-sample cap -- and confirm the datagram-wide
        // budget (512) is still the bound that holds: only the first 64
        // samples (64*8=512) actually retain records; the remaining 16
        // samples (65-80) each drop all 8 of their records to datagram-budget
        // exhaustion.
        //
        // This is also the regression test for the round-2 review's
        // aggregate-undercount finding: with the old "first observer"
        // design, only sample 65's local 8 would ever be reported. The fix
        // must report the TRUE total -- 16 * 8 = 128 -- not 8.
        const NUM_SAMPLES: u32 = 80;
        const RECORDS_PER_SAMPLE: u32 = MAX_UNKNOWN_RECORDS_PER_SAMPLE as u32;
        let samples_fully_accepted = (MAX_UNKNOWN_RECORDS_PER_DATAGRAM as u32) / RECORDS_PER_SAMPLE;
        assert_eq!(
            samples_fully_accepted, 64,
            "test assumes 512 / 8 == 64 -- update the fixture if the constants change"
        );
        let excess_samples = NUM_SAMPLES - samples_fully_accepted;
        let true_total_dropped = (excess_samples * RECORDS_PER_SAMPLE) as u64;
        assert_eq!(true_total_dropped, 128);

        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&[10, 0, 0, 1]);
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&NUM_SAMPLES.to_be_bytes());

        let sample_body_len = 32 + (RECORDS_PER_SAMPLE as usize) * 8;
        for _ in 0..NUM_SAMPLES {
            buf.extend_from_slice(&1u32.to_be_bytes()); // data_format = flow_sample
            buf.extend_from_slice(&(sample_body_len as u32).to_be_bytes());
            buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
            buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
            buf.extend_from_slice(&512u32.to_be_bytes()); // sampling_rate
            buf.extend_from_slice(&512u32.to_be_bytes()); // sample_pool
            buf.extend_from_slice(&0u32.to_be_bytes()); // drops
            buf.extend_from_slice(&1u32.to_be_bytes()); // input_ifindex
            buf.extend_from_slice(&2u32.to_be_bytes()); // output_ifindex
            buf.extend_from_slice(&RECORDS_PER_SAMPLE.to_be_bytes()); // num_flow_records
            for _ in 0..RECORDS_PER_SAMPLE {
                buf.extend_from_slice(&1001u32.to_be_bytes()); // enterprise 0, format 1001
                buf.extend_from_slice(&0u32.to_be_bytes()); // flow_data_length = 0
            }
        }

        // A DebuggingRecorder lets this assert on the exact
        // sflow_unknown_records_dropped counter value emitted, mirroring
        // `socket_drop_stats_observes_real_kernel_drops` in src/net.rs.
        use metrics::set_default_local_recorder;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        use metrics_util::{CompositeKey, MetricKind};
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = set_default_local_recorder(&recorder);

        let records =
            decode_datagram(&buf, exporter()).expect("must decode despite hostile sample count");
        assert_eq!(
            records.len(),
            NUM_SAMPLES as usize,
            "every sample must decode"
        );

        // Samples 0..64: fully within the datagram budget -- 8 real records, no marker.
        let mut total_accepted_records = 0usize;
        for r in &records[0..64] {
            let extra = r.extra.as_array().expect("extra must be an array");
            assert_eq!(extra.len(), RECORDS_PER_SAMPLE as usize);
            assert!(extra.iter().all(|v| v.get("data_hex").is_some()));
            total_accepted_records += extra.len();
        }
        assert_eq!(
            total_accepted_records, MAX_UNKNOWN_RECORDS_PER_DATAGRAM,
            "the datagram-wide budget, not the per-sample cap, must bound the total"
        );

        // Samples 64..79 (all but the last of the 16 exhausted samples): budget
        // was already zero, no local marker is minted per sample.
        for r in &records[64..79] {
            assert_eq!(
                r.extra,
                serde_json::json!([]),
                "budget-exhausted samples other than the last must carry no local marker"
            );
        }

        // The LAST record in the datagram (sample 80) carries the one
        // aggregate marker, appended by decode_datagram after every sample
        // has run -- and it must report the TRUE total (128), not the 8
        // records dropped by any single sample.
        let last = records.last().unwrap();
        let extra = last.extra.as_array().expect("extra must be an array");
        assert_eq!(
            extra,
            &vec![serde_json::json!({
                "truncated": true_total_dropped,
                "reason": "datagram_budget",
            })],
            "the aggregate marker must report every dropped record across the whole \
             datagram (128), not just the last sample's own 8"
        );

        // The metrics counter must carry the same true aggregate, so an
        // operator alerting on it sees the real number, not an undercount.
        let map = snapshotter.snapshot().into_hashmap();
        let dropped_metric = map
            .get(&CompositeKey::new(
                MetricKind::Counter,
                metrics::Key::from_name("sflow_unknown_records_dropped"),
            ))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .unwrap_or(0);
        assert_eq!(
            dropped_metric, true_total_dropped,
            "sflow_unknown_records_dropped must carry the real aggregate (128), not an \
             undercount from only the first or last sample to observe exhaustion"
        );
    }

    #[test]
    fn multi_sample_hostile_counter_datagram_caps_total_at_datagram_budget() {
        // Same multi-sample-splits-the-per-sample-cap shape as the flow-sample
        // test above, through decode_counter_sample's push site.
        const NUM_SAMPLES: u32 = 80;
        const RECORDS_PER_SAMPLE: u32 = MAX_UNKNOWN_RECORDS_PER_SAMPLE as u32;
        let true_total_dropped =
            (NUM_SAMPLES - MAX_UNKNOWN_RECORDS_PER_DATAGRAM as u32 / RECORDS_PER_SAMPLE) as u64
                * RECORDS_PER_SAMPLE as u64;

        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&[10, 0, 0, 1]);
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&NUM_SAMPLES.to_be_bytes());

        let sample_body_len = 12 + (RECORDS_PER_SAMPLE as usize) * 8;
        for _ in 0..NUM_SAMPLES {
            buf.extend_from_slice(&2u32.to_be_bytes()); // data_format = counter_sample
            buf.extend_from_slice(&(sample_body_len as u32).to_be_bytes());
            buf.extend_from_slice(&1u32.to_be_bytes()); // sequence_number
            buf.extend_from_slice(&1u32.to_be_bytes()); // source_id
            buf.extend_from_slice(&RECORDS_PER_SAMPLE.to_be_bytes()); // num_counter_records
            for _ in 0..RECORDS_PER_SAMPLE {
                buf.extend_from_slice(&1001u32.to_be_bytes());
                buf.extend_from_slice(&0u32.to_be_bytes());
            }
        }

        let records =
            decode_datagram(&buf, exporter()).expect("must decode despite hostile sample count");
        assert_eq!(records.len(), NUM_SAMPLES as usize);

        let total_accepted_records: usize = records
            .iter()
            .filter_map(|r| r.extra.as_array())
            .flat_map(|a| a.iter())
            .filter(|v| v.get("data_hex").is_some())
            .count();
        assert_eq!(
            total_accepted_records, MAX_UNKNOWN_RECORDS_PER_DATAGRAM,
            "counter-sample path must respect the same datagram-wide budget"
        );

        let datagram_budget_markers: Vec<&serde_json::Value> = records
            .iter()
            .filter_map(|r| r.extra.as_array())
            .flat_map(|a| a.iter())
            .filter(|v| v.get("reason") == Some(&serde_json::json!("datagram_budget")))
            .collect();
        assert_eq!(
            datagram_budget_markers.len(),
            1,
            "the datagram-budget marker must be emitted exactly once, not per sample"
        );
        assert_eq!(
            datagram_budget_markers[0],
            &serde_json::json!({ "truncated": true_total_dropped, "reason": "datagram_budget" }),
            "counter-sample path must also report the true aggregate, not a local slice"
        );
    }
}
