use thiserror::Error;

/// Typed value categories for curated IEs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IeType {
    U8,
    U16,
    U32,
    U64,
    Ipv4,
    Ipv6,
    DateTimeMillis,
    DateTimeSysUptime,
}

/// Errors produced by the IPFIX decoder.
#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("packet truncated: need {need} bytes at offset {offset}, have {have}")]
    Truncated {
        offset: usize,
        need: usize,
        have: usize,
    },

    #[error("malformed packet: {reason}")]
    Malformed { reason: String },

    #[error("unknown version {0}")]
    UnknownVersion(u16),
}

/// Look up a curated IANA IE id.
/// Returns `(field_name, value_type)` for known IEs; `None` for unknown.
pub fn ie_info(id: u16) -> Option<(&'static str, IeType)> {
    match id {
        1 => Some(("octetDeltaCount", IeType::U64)),
        2 => Some(("packetDeltaCount", IeType::U64)),
        4 => Some(("protocolIdentifier", IeType::U8)),
        6 => Some(("tcpControlBits", IeType::U8)),
        7 => Some(("sourceTransportPort", IeType::U16)),
        8 => Some(("sourceIPv4Address", IeType::Ipv4)),
        10 => Some(("ingressInterface", IeType::U32)),
        11 => Some(("destinationTransportPort", IeType::U16)),
        12 => Some(("destinationIPv4Address", IeType::Ipv4)),
        14 => Some(("egressInterface", IeType::U32)),
        21 => Some(("flowEndSysUpTime", IeType::DateTimeSysUptime)),
        22 => Some(("flowStartSysUpTime", IeType::DateTimeSysUptime)),
        27 => Some(("sourceIPv6Address", IeType::Ipv6)),
        28 => Some(("destinationIPv6Address", IeType::Ipv6)),
        32 => Some(("icmpTypeCodeIPv4", IeType::U16)),
        56 => Some(("sourceMacAddress", IeType::U64)),
        58 => Some(("vlanId", IeType::U16)),
        60 => Some(("ipVersion", IeType::U8)),
        61 => Some(("flowDirection", IeType::U8)),
        62 => Some(("ipNextHopIPv6Address", IeType::Ipv6)),
        64 => Some(("bgpNextHopIPv6Address", IeType::Ipv6)),
        70 => Some(("mplsTopLabelType", IeType::U8)),
        89 => Some(("forwardingStatus", IeType::U8)),
        96 => Some(("mpls_vpn_rd", IeType::U64)),
        130 => Some(("exporterIPv4Address", IeType::Ipv4)),
        131 => Some(("exporterIPv6Address", IeType::Ipv6)),
        136 => Some(("flowEndReason", IeType::U8)),
        148 => Some(("flowId", IeType::U64)),
        152 => Some(("flowStartMilliseconds", IeType::DateTimeMillis)),
        153 => Some(("flowEndMilliseconds", IeType::DateTimeMillis)),
        176 => Some(("icmpTypeIPv4", IeType::U8)),
        177 => Some(("icmpCodeIPv4", IeType::U8)),
        225 => Some(("postNATSourceIPv4Address", IeType::Ipv4)),
        226 => Some(("postNATDestinationIPv4Address", IeType::Ipv4)),
        227 => Some(("postNAPTSourceTransportPort", IeType::U16)),
        228 => Some(("postNAPTDestinationTransportPort", IeType::U16)),
        _ => None,
    }
}

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Identifies a template within a specific exporter and observation domain.
pub type TemplateKey = (IpAddr, u32, u16);

/// One field specifier from an IPFIX/NetFlow v9 template record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSpecifier {
    /// Information Element id (top bit cleared; enterprise IEs have enterprise_number set).
    pub ie_id: u16,
    /// Declared field length in bytes (0xFFFF = variable-length, not used in phase 1).
    pub length: u16,
    /// Present when the enterprise bit (bit 15) was set in the original ie_id word.
    pub enterprise_number: Option<u32>,
}

/// Stateful IPFIX / NetFlow decoder.
/// Owns the template cache; safe to use single-threaded from a listener task.
pub struct IpfixDecoder {
    pub(crate) cache: HashMap<TemplateKey, Vec<FieldSpecifier>>,
}

impl IpfixDecoder {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }
}

impl Default for IpfixDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Bounds-checked read helpers ----------------------------------------

#[allow(dead_code)]
fn read_u8(buf: &[u8], offset: usize) -> Result<u8, DecodeError> {
    buf.get(offset).copied().ok_or(DecodeError::Truncated {
        offset,
        need: 1,
        have: buf.len().saturating_sub(offset),
    })
}

fn read_u16_be(buf: &[u8], offset: usize) -> Result<u16, DecodeError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| DecodeError::Malformed {
            reason: "offset overflow".into(),
        })?;
    if end > buf.len() {
        return Err(DecodeError::Truncated {
            offset,
            need: 2,
            have: buf.len().saturating_sub(offset),
        });
    }
    Ok(u16::from_be_bytes([buf[offset], buf[offset + 1]]))
}

fn read_u32_be(buf: &[u8], offset: usize) -> Result<u32, DecodeError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| DecodeError::Malformed {
            reason: "offset overflow".into(),
        })?;
    if end > buf.len() {
        return Err(DecodeError::Truncated {
            offset,
            need: 4,
            have: buf.len().saturating_sub(offset),
        });
    }
    Ok(u32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

#[allow(dead_code)]
fn read_u64_be(buf: &[u8], offset: usize) -> Result<u64, DecodeError> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| DecodeError::Malformed {
            reason: "offset overflow".into(),
        })?;
    if end > buf.len() {
        return Err(DecodeError::Truncated {
            offset,
            need: 8,
            have: buf.len().saturating_sub(offset),
        });
    }
    Ok(u64::from_be_bytes(buf[offset..end].try_into().unwrap()))
}

fn read_bytes(buf: &[u8], offset: usize, len: usize) -> Result<&[u8], DecodeError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| DecodeError::Malformed {
            reason: "offset overflow".into(),
        })?;
    if end > buf.len() {
        return Err(DecodeError::Truncated {
            offset,
            need: len,
            have: buf.len().saturating_sub(offset),
        });
    }
    Ok(&buf[offset..end])
}

// ---- Byte fixtures for tests (visible to sibling test modules) -----------

#[cfg(test)]
pub(crate) const FIXTURE_IPFIX_TEMPLATE_THEN_DATA: &[u8] = &[
    // Message header
    0x00, 0x0A, // version = 10
    0x00, 0x2C, // total length = 44 (16 hdr + 16 template set + 12 data set)
    0x67, 0x5C, 0xB0, 0x20, // export_time
    0x00, 0x00, 0x00, 0x01, // sequence
    0x00, 0x00, 0x00, 0x00, // observation domain id = 0
    // Template Set (16 bytes: 4 hdr + 2 tmpl_id + 2 field_count + 2 fields×4)
    0x00, 0x02, // set id = 2
    0x00, 0x10, // length = 16
    0x01, 0x00, // template id = 256
    0x00, 0x02, // field count = 2
    0x00, 0x08, 0x00, 0x04, // ie 8, len 4
    0x00, 0x0C, 0x00, 0x04, // ie 12, len 4
    // Data Set (12 bytes: 4 hdr + 8 data)
    0x01, 0x00, // set id = 256
    0x00, 0x0C, // length = 12
    0xC0, 0xA8, 0x01, 0x01, // 192.168.1.1
    0x0A, 0x00, 0x00, 0x01, // 10.0.0.1
];

#[cfg(test)]
pub(crate) const FIXTURE_IPFIX_TRUNCATED: &[u8] = &[0x00, 0x0A, 0x00];

#[cfg(test)]
pub(crate) const FIXTURE_IPFIX_UNKNOWN_IE: &[u8] = &[
    // Message header (16 bytes)
    0x00, 0x0A, 0x00, 0x24, // total length = 36 (16 hdr + 12 template set + 8 data set)
    0x67, 0x5C, 0xB0, 0x20, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    // Template Set (12 bytes: 4 set header + 2 tmpl_id + 2 field_count + 4 field)
    0x00, 0x02, 0x00, 0x0C, // length = 12
    0x01, 0x01, // template id = 257
    0x00, 0x01, // field count = 1
    0x03, 0xE7, 0x00, 0x04, // ie 999, len 4
    // Data Set (8 bytes: 4 set header + 4 data)
    0x01, 0x01, // set id = 257
    0x00, 0x08, // length = 8
    0xDE, 0xAD, 0xBE, 0xEF, // raw bytes for ie 999
];

#[cfg(test)]
pub(crate) const FIXTURE_IPFIX_MISSING_TEMPLATE: &[u8] = &[
    // Message header
    0x00, 0x0A, 0x00, 0x18, // total length = 24
    0x67, 0x5C, 0xB0, 0x20, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    // Data Set — template 300 not yet cached
    0x01, 0x2C, // set id = 300
    0x00, 0x08, // length = 8
    0xAA, 0xBB, 0xCC, 0xDD,
];

#[cfg(test)]
pub(crate) const FIXTURE_NFV9_TEMPLATE_THEN_DATA: &[u8] = &[
    // NetFlow v9 Header (20 bytes)
    0x00, 0x09, // version = 9
    0x00, 0x02, // count = 2 flowsets
    0x00, 0x0F, 0x42, 0x40, // sys_uptime = 1000000 ms
    0x67, 0x5C, 0xB0, 0x20, // unix_secs (same as IPFIX fixture)
    0x00, 0x00, 0x00, 0x01, // sequence
    0x00, 0x00, 0x00, 0x05, // source_id = 5
    // Template FlowSet (flowset_id = 0)
    // Body: tmpl_id(2) + field_count(2) + 3 fields×4 = 16 bytes; total = 4 hdr + 16 = 20
    0x00, 0x00, // flowset_id = 0
    0x00, 0x14, // length = 20 bytes
    // Template record 256
    0x01, 0x00, // template_id = 256
    0x00, 0x03, // field_count = 3
    0x00, 0x08, 0x00, 0x04, // ie 8, len 4
    0x00, 0x0C, 0x00, 0x04, // ie 12, len 4
    0x00, 0x01, 0x00, 0x04, // ie 1, len 4 (octetDeltaCount)
    // Data FlowSet (flowset_id = 256)
    0x01, 0x00, // flowset_id = 256
    0x00, 0x10, // length = 16 (4 header + 12 data)
    0xAC, 0x10, 0x00, 0x01, // 172.16.0.1
    0x08, 0x08, 0x08, 0x08, // 8.8.8.8
    0x00, 0x00, 0x03, 0xE8, // 1000 octets
];

#[cfg(test)]
pub(crate) const FIXTURE_NFV9_TRUNCATED: &[u8] =
    &[0x00, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[cfg(test)]
pub(crate) const FIXTURE_NFV5_ONE_RECORD: &[u8] = &[
    // Header (24 bytes)
    0x00, 0x05, // version = 5
    0x00, 0x01, // count = 1
    0x00, 0x0F, 0x42, 0x40, // sys_uptime_ms = 1_000_000
    0x67, 0x5C, 0xB0, 0x20, // unix_secs
    0x00, 0x00, 0x00, 0x00, // unix_nsecs
    0x00, 0x00, 0x00, 0x01, // flow_sequence
    0x00, // engine_type
    0x00, // engine_id
    0x00, 0x00, // sampling_interval
    // Record (48 bytes)
    0xC0, 0xA8, 0x01, 0x0A, // srcaddr = 192.168.1.10
    0xC0, 0xA8, 0x01, 0x01, // dstaddr = 192.168.1.1
    0x00, 0x00, 0x00, 0x00, // nexthop = 0.0.0.0
    0x00, 0x01, // input = 1
    0x00, 0x02, // output = 2
    0x00, 0x00, 0x00, 0x05, // dPkts = 5
    0x00, 0x00, 0x01, 0xF4, // dOctets = 500
    0x00, 0x0F, 0x42, 0x00, // first_ms = 999424
    0x00, 0x0F, 0x42, 0x3C, // last_ms  = 999484
    0x1F, 0x90, // srcport = 8080
    0x00, 0x50, // dstport = 80
    0x00, // pad1
    0x18, // tcp_flags = 0x18 (ACK+PSH)
    0x06, // prot = 6 (TCP)
    0x00, // tos
    0x00, 0x00, // src_as
    0x00, 0x00, // dst_as
    0x00, // src_mask
    0x00, // dst_mask
    0x00, 0x00, // pad2
];

#[cfg(test)]
pub(crate) const FIXTURE_NFV5_TRUNCATED: &[u8] = &[
    0x00, 0x05, 0x00, 0x01, // version=5, count=1 (claims 1 record)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, // 24 bytes of header but NO record bytes follow
];

/// Two-record IPFIX v10 fixture: same template as FIXTURE_IPFIX_TEMPLATE_THEN_DATA
/// (template id 256, ie 8 + ie 12, 4 bytes each) but with TWO data records in the data set.
/// Layout:
///   16 bytes: message header  (version=10, total_len=52)
///   16 bytes: template set    (same as FIXTURE_IPFIX_TEMPLATE_THEN_DATA)
///   20 bytes: data set header(4) + record1(8) + record2(8)
/// Used to verify that the decoder returns exactly N flows for N records.
#[cfg(test)]
pub(crate) const FIXTURE_IPFIX_TWO_RECORDS: &[u8] = &[
    // Message header (16 bytes)
    0x00, 0x0A, // version = 10
    0x00, 0x34, // total length = 52
    0x67, 0x5C, 0xB0, 0x20, // export_time
    0x00, 0x00, 0x00, 0x02, // sequence
    0x00, 0x00, 0x00, 0x00, // observation domain id = 0
    // Template Set (16 bytes: 4 hdr + 2 tmpl_id + 2 field_count + 2 fields×4)
    0x00, 0x02, // set id = 2
    0x00, 0x10, // length = 16
    0x01, 0x00, // template id = 256
    0x00, 0x02, // field count = 2
    0x00, 0x08, 0x00, 0x04, // ie 8 (srcIP), len 4
    0x00, 0x0C, 0x00, 0x04, // ie 12 (dstIP), len 4
    // Data Set (20 bytes: 4 hdr + 8 record1 + 8 record2)
    0x01, 0x00, // set id = 256
    0x00, 0x14, // length = 20
    // record 1
    0xC0, 0xA8, 0x01, 0x01, // 192.168.1.1
    0x0A, 0x00, 0x00, 0x01, // 10.0.0.1
    // record 2
    0xC0, 0xA8, 0x01, 0x02, // 192.168.1.2
    0x0A, 0x00, 0x00, 0x02, // 10.0.0.2
];

// ---- IPFIX v10 decode -------------------------------------------------------

use crate::ipfix::FlowRecord;
use chrono::{DateTime, Utc};

/// Decode one IPFIX v10 message from `buf`.
///
/// Template sets encountered in the message are stored in `decoder.cache`.
/// Data sets referencing uncached templates are silently skipped (the
/// `ipfix_templates_missing` counter is incremented).
/// Returns all `FlowRecord`s produced by data sets in this message.
pub fn decode_ipfix(
    decoder: &mut IpfixDecoder,
    buf: &[u8],
    exporter: IpAddr,
) -> Result<Vec<FlowRecord>, DecodeError> {
    // --- Message header (16 bytes) ---
    if buf.len() < 16 {
        return Err(DecodeError::Truncated {
            offset: 0,
            need: 16,
            have: buf.len(),
        });
    }
    let version = read_u16_be(buf, 0)?;
    if version != 10 {
        return Err(DecodeError::UnknownVersion(version));
    }
    let total_len = read_u16_be(buf, 2)? as usize;
    let export_secs = read_u32_be(buf, 4)? as i64;
    let obs_domain_id = read_u32_be(buf, 12)?;

    use chrono::TimeZone;
    let export_time = Utc
        .timestamp_opt(export_secs, 0)
        .single()
        .unwrap_or_else(Utc::now);

    if buf.len() < total_len {
        return Err(DecodeError::Truncated {
            offset: 0,
            need: total_len,
            have: buf.len(),
        });
    }
    let msg = &buf[..total_len];

    let mut records: Vec<FlowRecord> = Vec::new();
    let mut pos = 16usize;

    while pos + 4 <= msg.len() {
        let set_id = read_u16_be(msg, pos)?;
        let set_len = read_u16_be(msg, pos + 2)? as usize;

        if set_len < 4 {
            return Err(DecodeError::Malformed {
                reason: format!("set at offset {pos} has length {set_len} < 4"),
            });
        }
        let set_end = pos
            .checked_add(set_len)
            .ok_or_else(|| DecodeError::Malformed {
                reason: "set length overflow".into(),
            })?;
        if set_end > msg.len() {
            return Err(DecodeError::Truncated {
                offset: pos + 2,
                need: set_len,
                have: msg.len().saturating_sub(pos),
            });
        }
        let set_body = &msg[pos + 4..set_end];

        match set_id {
            2 => {
                // Template Set
                parse_ipfix_template_set(decoder, set_body, exporter, obs_domain_id)?;
            }
            3 => {
                // Options Template Set — parse to keep template cache consistent
                parse_ipfix_options_template_set(decoder, set_body, exporter, obs_domain_id)?;
            }
            id if id >= 256 => {
                // Data Set
                let mut set_records = parse_ipfix_data_set(
                    decoder,
                    set_body,
                    set_id,
                    exporter,
                    obs_domain_id,
                    export_time,
                )?;
                records.append(&mut set_records);
            }
            other => {
                tracing::warn!("ipfix: ignoring reserved set id {other} at offset {pos}");
            }
        }

        pos = set_end;
    }

    Ok(records)
}

fn parse_ipfix_template_set(
    decoder: &mut IpfixDecoder,
    body: &[u8],
    exporter: IpAddr,
    obs_domain_id: u32,
) -> Result<(), DecodeError> {
    let mut pos = 0usize;
    while pos + 4 <= body.len() {
        let template_id = read_u16_be(body, pos)?;
        let field_count = read_u16_be(body, pos + 2)? as usize;
        pos += 4;

        if template_id < 256 {
            return Err(DecodeError::Malformed {
                reason: format!("template id {template_id} < 256 is reserved"),
            });
        }

        let mut fields = Vec::with_capacity(field_count);
        for _ in 0..field_count {
            if pos + 4 > body.len() {
                return Err(DecodeError::Truncated {
                    offset: pos,
                    need: 4,
                    have: body.len().saturating_sub(pos),
                });
            }
            let raw_ie = read_u16_be(body, pos)?;
            let field_len = read_u16_be(body, pos + 2)?;
            pos += 4;

            let enterprise = if raw_ie & 0x8000 != 0 {
                if pos + 4 > body.len() {
                    return Err(DecodeError::Truncated {
                        offset: pos,
                        need: 4,
                        have: body.len().saturating_sub(pos),
                    });
                }
                let pen = read_u32_be(body, pos)?;
                pos += 4;
                Some(pen)
            } else {
                None
            };
            fields.push(FieldSpecifier {
                ie_id: raw_ie & 0x7FFF,
                length: field_len,
                enterprise_number: enterprise,
            });
        }

        let key: TemplateKey = (exporter, obs_domain_id, template_id);
        decoder.cache.insert(key, fields);
        metrics::counter!("ipfix_templates_received").increment(1);
    }
    Ok(())
}

fn parse_ipfix_options_template_set(
    decoder: &mut IpfixDecoder,
    body: &[u8],
    exporter: IpAddr,
    obs_domain_id: u32,
) -> Result<(), DecodeError> {
    // RFC 7011 §3.4.2: Options Template Record header has an extra scope_field_count u16.
    let mut pos = 0usize;
    while pos + 6 <= body.len() {
        let template_id = read_u16_be(body, pos)?;
        let field_count = read_u16_be(body, pos + 2)? as usize;
        let _scope_count = read_u16_be(body, pos + 4)?;
        pos += 6;

        let mut fields = Vec::with_capacity(field_count);
        for _ in 0..field_count {
            if pos + 4 > body.len() {
                break;
            }
            let raw_ie = read_u16_be(body, pos)?;
            let field_len = read_u16_be(body, pos + 2)?;
            pos += 4;
            let enterprise = if raw_ie & 0x8000 != 0 {
                if pos + 4 > body.len() {
                    break;
                }
                let pen = read_u32_be(body, pos)?;
                pos += 4;
                Some(pen)
            } else {
                None
            };
            fields.push(FieldSpecifier {
                ie_id: raw_ie & 0x7FFF,
                length: field_len,
                enterprise_number: enterprise,
            });
        }
        if template_id >= 256 {
            decoder
                .cache
                .insert((exporter, obs_domain_id, template_id), fields);
        }
    }
    Ok(())
}

fn parse_ipfix_data_set(
    decoder: &mut IpfixDecoder,
    body: &[u8],
    set_id: u16,
    exporter: IpAddr,
    obs_domain_id: u32,
    export_time: DateTime<Utc>,
) -> Result<Vec<FlowRecord>, DecodeError> {
    let key: TemplateKey = (exporter, obs_domain_id, set_id);
    let fields = match decoder.cache.get(&key) {
        Some(f) => f.clone(),
        None => {
            metrics::counter!("ipfix_templates_missing").increment(1);
            tracing::debug!(
                "ipfix: no cached template for key ({exporter}, {obs_domain_id}, {set_id}) — skipping data set"
            );
            return Ok(Vec::new());
        }
    };

    let record_len: usize = fields.iter().map(|f| f.length as usize).sum();
    if record_len == 0 {
        return Ok(Vec::new());
    }

    let mut records = Vec::new();
    let mut pos = 0usize;

    while pos + record_len <= body.len() {
        let mut rec = FlowRecord {
            observation_domain_id: obs_domain_id,
            template_id: set_id,
            protocol_version: 10,
            exporter,
            export_time,
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            ip_protocol: None,
            octet_delta_count: None,
            packet_delta_count: None,
            flow_start: None,
            flow_end: None,
            tcp_flags: None,
            input_interface: None,
            output_interface: None,
            extra: serde_json::json!({}),
        };

        for field in &fields {
            let flen = field.length as usize;
            let raw = read_bytes(body, pos, flen)?;
            apply_field_to_record(&mut rec, field, raw);
            pos += flen;
        }

        metrics::counter!("ipfix_flows_decoded").increment(1);
        records.push(rec);
    }

    Ok(records)
}

/// Decode one field value and write it into the appropriate `FlowRecord` column,
/// or into `extra` if the IE is unknown or unsupported.
fn apply_field_to_record(rec: &mut FlowRecord, field: &FieldSpecifier, raw: &[u8]) {
    use serde_json::json;

    // Enterprise IEs → always go to extra
    if let Some(pen) = field.enterprise_number {
        let key = format!("ie{}:{}", pen, field.ie_id);
        let val = hex::encode(raw);
        rec.extra[key] = json!(val);
        return;
    }

    match ie_info(field.ie_id) {
        None => {
            // Unknown IE → hex-encoded in extra
            let key = format!("ie{}", field.ie_id);
            rec.extra[key] = json!(hex::encode(raw));
        }
        Some((name, ie_type)) => match ie_type {
            IeType::Ipv4 => {
                if raw.len() == 4 {
                    let addr = IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]));
                    set_addr_field(rec, field.ie_id, addr);
                } else {
                    rec.extra[name] = json!(hex::encode(raw));
                }
            }
            IeType::Ipv6 => {
                if raw.len() == 16 {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(raw);
                    let addr = IpAddr::V6(Ipv6Addr::from(bytes));
                    set_addr_field(rec, field.ie_id, addr);
                } else {
                    rec.extra[name] = json!(hex::encode(raw));
                }
            }
            IeType::U8 => {
                let val = raw.first().copied().unwrap_or(0);
                set_u8_field(rec, field.ie_id, val);
            }
            IeType::U16 => {
                let val = if raw.len() >= 2 {
                    u16::from_be_bytes([raw[0], raw[1]])
                } else {
                    raw.first().copied().unwrap_or(0) as u16
                };
                set_u16_field(rec, field.ie_id, val);
            }
            IeType::U32 => {
                let val = if raw.len() >= 4 {
                    u32::from_be_bytes(raw[..4].try_into().unwrap())
                } else {
                    // Pad to 4 bytes
                    let mut b = [0u8; 4];
                    b[4 - raw.len()..].copy_from_slice(raw);
                    u32::from_be_bytes(b)
                };
                set_u32_field(rec, field.ie_id, val);
            }
            IeType::U64 => {
                let val = if raw.len() >= 8 {
                    u64::from_be_bytes(raw[..8].try_into().unwrap())
                } else {
                    let mut b = [0u8; 8];
                    b[8 - raw.len()..].copy_from_slice(raw);
                    u64::from_be_bytes(b)
                };
                set_u64_field(rec, field.ie_id, val);
            }
            IeType::DateTimeMillis => {
                if raw.len() >= 8 {
                    let ms = u64::from_be_bytes(raw[..8].try_into().unwrap());
                    use chrono::TimeZone;
                    let secs = (ms / 1000) as i64;
                    let nanos = ((ms % 1000) * 1_000_000) as u32;
                    if let chrono::LocalResult::Single(dt) = Utc.timestamp_opt(secs, nanos) {
                        match field.ie_id {
                            152 => rec.flow_start = Some(dt),
                            153 => rec.flow_end = Some(dt),
                            _ => {
                                rec.extra[name] = json!(dt.to_rfc3339());
                            }
                        }
                    }
                } else {
                    rec.extra[name] = json!(hex::encode(raw));
                }
            }
            IeType::DateTimeSysUptime => {
                // SysUptime fields are ms relative to exporter boot — store as relative ms in extra
                if raw.len() >= 4 {
                    let ms = u32::from_be_bytes(raw[..4].try_into().unwrap());
                    rec.extra[name] = json!(ms);
                } else {
                    rec.extra[name] = json!(hex::encode(raw));
                }
            }
        },
    }
}

fn set_addr_field(rec: &mut FlowRecord, ie_id: u16, addr: IpAddr) {
    match ie_id {
        8 | 225 => rec.src_addr = Some(addr),
        12 | 226 => rec.dst_addr = Some(addr),
        _ => {
            if let Some((name, _)) = ie_info(ie_id) {
                rec.extra[name] = serde_json::json!(addr.to_string());
            }
        }
    }
}

fn set_u8_field(rec: &mut FlowRecord, ie_id: u16, val: u8) {
    match ie_id {
        4 => rec.ip_protocol = Some(val),
        6 => rec.tcp_flags = Some(val),
        _ => {
            if let Some((name, _)) = ie_info(ie_id) {
                rec.extra[name] = serde_json::json!(val);
            }
        }
    }
}

fn set_u16_field(rec: &mut FlowRecord, ie_id: u16, val: u16) {
    match ie_id {
        7 | 227 => rec.src_port = Some(val),
        11 | 228 => rec.dst_port = Some(val),
        _ => {
            if let Some((name, _)) = ie_info(ie_id) {
                rec.extra[name] = serde_json::json!(val);
            }
        }
    }
}

fn set_u32_field(rec: &mut FlowRecord, ie_id: u16, val: u32) {
    match ie_id {
        10 => rec.input_interface = Some(val),
        14 => rec.output_interface = Some(val),
        _ => {
            if let Some((name, _)) = ie_info(ie_id) {
                rec.extra[name] = serde_json::json!(val);
            }
        }
    }
}

fn set_u64_field(rec: &mut FlowRecord, ie_id: u16, val: u64) {
    match ie_id {
        1 => rec.octet_delta_count = Some(val),
        2 => rec.packet_delta_count = Some(val),
        _ => {
            if let Some((name, _)) = ie_info(ie_id) {
                rec.extra[name] = serde_json::json!(val);
            }
        }
    }
}

// ---- NetFlow v9 decode -------------------------------------------------------

/// Decode one NetFlow v9 packet.
///
/// v9 uses the same `decoder.cache` keyed on `(exporter, source_id, template_id)`.
pub fn decode_netflow_v9(
    decoder: &mut IpfixDecoder,
    buf: &[u8],
    exporter: IpAddr,
) -> Result<Vec<FlowRecord>, DecodeError> {
    if buf.len() < 20 {
        return Err(DecodeError::Truncated {
            offset: 0,
            need: 20,
            have: buf.len(),
        });
    }
    let version = read_u16_be(buf, 0)?;
    if version != 9 {
        return Err(DecodeError::UnknownVersion(version));
    }
    let unix_secs = read_u32_be(buf, 8)? as i64;
    let source_id = read_u32_be(buf, 16)?;

    use chrono::TimeZone;
    let export_time = Utc
        .timestamp_opt(unix_secs, 0)
        .single()
        .unwrap_or_else(Utc::now);

    let mut records: Vec<FlowRecord> = Vec::new();
    let mut pos = 20usize;

    while pos + 4 <= buf.len() {
        let flowset_id = read_u16_be(buf, pos)?;
        let flowset_len = read_u16_be(buf, pos + 2)? as usize;
        if flowset_len < 4 {
            return Err(DecodeError::Malformed {
                reason: format!("v9 flowset at {pos} has length {flowset_len} < 4"),
            });
        }
        let flowset_end = pos
            .checked_add(flowset_len)
            .ok_or_else(|| DecodeError::Malformed {
                reason: "v9 flowset length overflow".into(),
            })?;
        if flowset_end > buf.len() {
            return Err(DecodeError::Truncated {
                offset: pos + 2,
                need: flowset_len,
                have: buf.len().saturating_sub(pos),
            });
        }
        let body = &buf[pos + 4..flowset_end];

        match flowset_id {
            0 => {
                // Template FlowSet
                parse_v9_template_flowset(decoder, body, exporter, source_id)?;
            }
            1 => {
                // Options Template FlowSet — skip data decode in phase 1
                tracing::debug!("ipfix: skipping v9 options template flowset");
            }
            id if id >= 256 => {
                let mut set_records =
                    parse_ipfix_data_set(decoder, body, id, exporter, source_id, export_time)?;
                // Correct protocol version (parse_ipfix_data_set sets it to 10)
                for r in &mut set_records {
                    r.protocol_version = 9;
                }
                records.append(&mut set_records);
            }
            _ => {
                tracing::warn!("v9: ignoring reserved flowset id {flowset_id}");
            }
        }

        pos = flowset_end;
    }

    Ok(records)
}

fn parse_v9_template_flowset(
    decoder: &mut IpfixDecoder,
    body: &[u8],
    exporter: IpAddr,
    source_id: u32,
) -> Result<(), DecodeError> {
    let mut pos = 0usize;
    while pos + 4 <= body.len() {
        let template_id = read_u16_be(body, pos)?;
        let field_count = read_u16_be(body, pos + 2)? as usize;
        pos += 4;

        if template_id < 256 {
            // padding zeros at end of flowset
            break;
        }

        let mut fields = Vec::with_capacity(field_count);
        for _ in 0..field_count {
            if pos + 4 > body.len() {
                return Err(DecodeError::Truncated {
                    offset: pos,
                    need: 4,
                    have: body.len().saturating_sub(pos),
                });
            }
            // v9 field specifiers have no enterprise bit
            let ie_id = read_u16_be(body, pos)?;
            let field_len = read_u16_be(body, pos + 2)?;
            pos += 4;
            fields.push(FieldSpecifier {
                ie_id,
                length: field_len,
                enterprise_number: None,
            });
        }
        decoder
            .cache
            .insert((exporter, source_id, template_id), fields);
        metrics::counter!("ipfix_templates_received").increment(1);
    }
    Ok(())
}

// ---- NetFlow v5 decode -------------------------------------------------------

/// Decode one NetFlow v5 packet. No template cache required.
///
/// Synthesises `FlowRecord`s directly from the fixed 48-byte record layout.
/// `template_id` is set to 0 and `observation_domain_id` to 0 (v5 has no concept of either).
pub fn decode_netflow_v5(buf: &[u8], exporter: IpAddr) -> Result<Vec<FlowRecord>, DecodeError> {
    const HEADER_LEN: usize = 24;
    const RECORD_LEN: usize = 48;

    if buf.len() < HEADER_LEN {
        return Err(DecodeError::Truncated {
            offset: 0,
            need: HEADER_LEN,
            have: buf.len(),
        });
    }
    let version = read_u16_be(buf, 0)?;
    if version != 5 {
        return Err(DecodeError::UnknownVersion(version));
    }
    let count = read_u16_be(buf, 2)? as usize;
    let unix_secs = read_u32_be(buf, 8)? as i64;

    use chrono::TimeZone;
    let export_time = Utc
        .timestamp_opt(unix_secs, 0)
        .single()
        .unwrap_or_else(Utc::now);

    let required = HEADER_LEN + count * RECORD_LEN;
    if buf.len() < required {
        return Err(DecodeError::Truncated {
            offset: HEADER_LEN,
            need: count * RECORD_LEN,
            have: buf.len().saturating_sub(HEADER_LEN),
        });
    }

    let mut records = Vec::with_capacity(count);
    for i in 0..count {
        let off = HEADER_LEN + i * RECORD_LEN;
        let r = &buf[off..off + RECORD_LEN];

        let src = Ipv4Addr::new(r[0], r[1], r[2], r[3]);
        let dst = Ipv4Addr::new(r[4], r[5], r[6], r[7]);
        let input_if = u16::from_be_bytes([r[12], r[13]]) as u32;
        let output_if = u16::from_be_bytes([r[14], r[15]]) as u32;
        let d_pkts = u32::from_be_bytes([r[16], r[17], r[18], r[19]]);
        let d_octets = u32::from_be_bytes([r[20], r[21], r[22], r[23]]);
        let first_ms = u32::from_be_bytes([r[24], r[25], r[26], r[27]]);
        let last_ms = u32::from_be_bytes([r[28], r[29], r[30], r[31]]);
        let src_port = u16::from_be_bytes([r[32], r[33]]);
        let dst_port = u16::from_be_bytes([r[34], r[35]]);
        let tcp_flags = r[37];
        let prot = r[38];

        metrics::counter!("ipfix_flows_decoded").increment(1);

        records.push(FlowRecord {
            observation_domain_id: 0,
            template_id: 0,
            protocol_version: 5,
            exporter,
            export_time,
            src_addr: Some(IpAddr::V4(src)),
            dst_addr: Some(IpAddr::V4(dst)),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            ip_protocol: Some(prot),
            octet_delta_count: Some(d_octets as u64),
            packet_delta_count: Some(d_pkts as u64),
            flow_start: None,
            flow_end: None,
            tcp_flags: Some(tcp_flags),
            input_interface: Some(input_if),
            output_interface: Some(output_if),
            extra: serde_json::json!({
                "flowStartSysUpTime": first_ms,
                "flowEndSysUpTime": last_ms,
            }),
        });
    }

    Ok(records)
}

// ---- Version dispatch entry point -------------------------------------------

/// Primary entry point: inspect the first 2 bytes, dispatch to the appropriate decoder.
///
/// Increments `ipfix_datagrams_received` on every call.
/// Returns `Err(DecodeError::Truncated)` for buffers shorter than 2 bytes.
/// Returns `Err(DecodeError::UnknownVersion)` for version values other than 5, 9, 10.
pub fn decode_datagram(
    decoder: &mut IpfixDecoder,
    buf: &[u8],
    exporter: IpAddr,
) -> Result<Vec<FlowRecord>, DecodeError> {
    metrics::counter!("ipfix_datagrams_received").increment(1);

    if buf.len() < 2 {
        return Err(DecodeError::Truncated {
            offset: 0,
            need: 2,
            have: buf.len(),
        });
    }
    let version = read_u16_be(buf, 0)?;
    match version {
        10 => decode_ipfix(decoder, buf, exporter),
        9 => decode_netflow_v9(decoder, buf, exporter),
        5 => decode_netflow_v5(buf, exporter),
        other => Err(DecodeError::UnknownVersion(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ie_info_known_ids_return_correct_type() {
        assert_eq!(ie_info(8), Some(("sourceIPv4Address", IeType::Ipv4)));
        assert_eq!(ie_info(12), Some(("destinationIPv4Address", IeType::Ipv4)));
        assert_eq!(ie_info(27), Some(("sourceIPv6Address", IeType::Ipv6)));
        assert_eq!(ie_info(1), Some(("octetDeltaCount", IeType::U64)));
        assert_eq!(
            ie_info(152),
            Some(("flowStartMilliseconds", IeType::DateTimeMillis))
        );
        assert_eq!(
            ie_info(22),
            Some(("flowStartSysUpTime", IeType::DateTimeSysUptime))
        );
    }

    #[test]
    fn ie_info_unknown_id_returns_none() {
        assert_eq!(ie_info(9999), None);
        assert_eq!(ie_info(0), None);
        assert_eq!(ie_info(255), None);
    }

    #[test]
    fn decode_error_display_truncated() {
        let e = DecodeError::Truncated {
            offset: 4,
            need: 4,
            have: 2,
        };
        let msg = e.to_string();
        assert!(msg.contains("truncated"), "got: {msg}");
        assert!(msg.contains("4"));
    }

    #[test]
    fn decode_error_display_unknown_version() {
        let e = DecodeError::UnknownVersion(99);
        assert!(e.to_string().contains("99"));
    }

    // ---- Tests for read helpers and template cache (Task 3) ----

    #[test]
    fn read_u16_be_requires_two_bytes() {
        let buf = [0xAB_u8, 0xCD];
        assert_eq!(read_u16_be(&buf, 0).unwrap(), 0xABCD);
        // One byte short
        assert!(read_u16_be(&buf, 1).is_err());
        // Out of range
        assert!(read_u16_be(&[], 0).is_err());
    }

    #[test]
    fn read_u32_be_requires_four_bytes() {
        let buf = [0x01_u8, 0x02, 0x03, 0x04, 0xFF];
        assert_eq!(read_u32_be(&buf, 0).unwrap(), 0x01020304);
        assert!(read_u32_be(&buf, 2).is_err()); // only 3 bytes left
    }

    #[test]
    fn read_bytes_slice_is_correct() {
        let buf = [1_u8, 2, 3, 4, 5];
        assert_eq!(read_bytes(&buf, 1, 3).unwrap(), &[2, 3, 4]);
        assert!(read_bytes(&buf, 4, 2).is_err());
    }

    #[test]
    fn template_cache_insert_and_lookup() {
        use std::net::{IpAddr, Ipv4Addr};

        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut decoder = IpfixDecoder::new();
        let key: TemplateKey = (exporter, 0, 256);
        let fields = vec![
            FieldSpecifier {
                ie_id: 8,
                length: 4,
                enterprise_number: None,
            },
            FieldSpecifier {
                ie_id: 12,
                length: 4,
                enterprise_number: None,
            },
        ];
        decoder.cache.insert(key, fields.clone());
        assert_eq!(decoder.cache.get(&key).unwrap().len(), 2);
        assert_eq!(decoder.cache.get(&key).unwrap()[0].ie_id, 8);
    }

    // ---- IPFIX v10 decode tests (Task 4) ----

    #[tokio::test]
    async fn ipfix_template_then_data_decodes_src_dst() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut dec = IpfixDecoder::new();
        let records = decode_ipfix(
            &mut dec,
            FIXTURE_IPFIX_TEMPLATE_THEN_DATA,
            exporter,
        )
        .expect("should decode");
        assert_eq!(records.len(), 1, "one data record");
        let r = &records[0];
        assert_eq!(r.src_addr, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(r.dst_addr, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(r.protocol_version, 10);
        assert_eq!(r.template_id, 256);
        assert_eq!(r.observation_domain_id, 0);
    }

    #[test]
    fn ipfix_truncated_returns_error_not_panic() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut dec = IpfixDecoder::new();
        let result = decode_ipfix(&mut dec, FIXTURE_IPFIX_TRUNCATED, exporter);
        assert!(result.is_err(), "truncated input must error");
    }

    #[test]
    fn ipfix_unknown_ie_goes_to_extra_as_hex() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let mut dec = IpfixDecoder::new();
        let records = decode_ipfix(&mut dec, FIXTURE_IPFIX_UNKNOWN_IE, exporter)
            .expect("should decode");
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(
            r.extra["ie999"], "deadbeef",
            "unknown IE should appear as hex in extra; got: {}",
            r.extra
        );
    }

    #[test]
    fn ipfix_missing_template_skipped_no_error() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        let mut dec = IpfixDecoder::new();
        let records = decode_ipfix(
            &mut dec,
            FIXTURE_IPFIX_MISSING_TEMPLATE,
            exporter,
        )
        .expect("missing template must not error");
        assert_eq!(
            records.len(),
            0,
            "data set with uncached template is skipped"
        );
    }

    // ---- NetFlow v9 decode tests (Task 5) ----

    #[test]
    fn netflow_v9_template_then_data_decodes_correctly() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 1));
        let mut dec = IpfixDecoder::new();
        let records = decode_netflow_v9(&mut dec, FIXTURE_NFV9_TEMPLATE_THEN_DATA, exporter)
            .expect("v9 decode");
        assert_eq!(records.len(), 1, "one data record from v9");
        let r = &records[0];
        assert_eq!(r.src_addr, Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert_eq!(r.dst_addr, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert_eq!(r.octet_delta_count, Some(1000));
        assert_eq!(r.protocol_version, 9);
        assert_eq!(r.observation_domain_id, 5); // source_id
    }

    #[test]
    fn netflow_v9_truncated_returns_error() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut dec = IpfixDecoder::new();
        assert!(decode_netflow_v9(&mut dec, FIXTURE_NFV9_TRUNCATED, exporter).is_err());
    }

    // ---- NetFlow v5 decode tests (Task 6) ----

    #[test]
    fn netflow_v5_single_record_decoded_correctly() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let records = decode_netflow_v5(FIXTURE_NFV5_ONE_RECORD, exporter).expect("v5 decode");
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.src_addr, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        assert_eq!(r.dst_addr, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(r.src_port, Some(8080));
        assert_eq!(r.dst_port, Some(80));
        assert_eq!(r.ip_protocol, Some(6));
        assert_eq!(r.tcp_flags, Some(0x18));
        assert_eq!(r.packet_delta_count, Some(5));
        assert_eq!(r.octet_delta_count, Some(500));
        assert_eq!(r.input_interface, Some(1));
        assert_eq!(r.output_interface, Some(2));
        assert_eq!(r.protocol_version, 5);
        assert_eq!(r.template_id, 0); // synthetic
        assert_eq!(r.observation_domain_id, 0);
    }

    #[test]
    fn netflow_v5_truncated_returns_error() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(decode_netflow_v5(FIXTURE_NFV5_TRUNCATED, exporter).is_err());
    }

    #[test]
    fn netflow_v5_count_zero_returns_empty() {
        use std::net::{IpAddr, Ipv4Addr};
        // Valid header with count=0
        let mut buf = FIXTURE_NFV5_ONE_RECORD.to_vec();
        buf[2] = 0x00;
        buf[3] = 0x00; // count = 0
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let records = decode_netflow_v5(&buf, exporter).expect("count=0 is valid");
        assert_eq!(records.len(), 0);
    }

    // ---- Version dispatch tests (Task 7) ----

    #[test]
    fn dispatch_routes_v10_correctly() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let mut dec = IpfixDecoder::new();
        // FIXTURE_IPFIX_TEMPLATE_THEN_DATA starts with 0x00 0x0A (version 10)
        let records = decode_datagram(&mut dec, FIXTURE_IPFIX_TEMPLATE_THEN_DATA, exporter)
            .expect("dispatch v10");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].protocol_version, 10);
    }

    #[test]
    fn dispatch_routes_v9_correctly() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11));
        let mut dec = IpfixDecoder::new();
        let records = decode_datagram(&mut dec, FIXTURE_NFV9_TEMPLATE_THEN_DATA, exporter)
            .expect("dispatch v9");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].protocol_version, 9);
    }

    #[test]
    fn dispatch_routes_v5_correctly() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 12));
        let mut dec = IpfixDecoder::new();
        let records =
            decode_datagram(&mut dec, FIXTURE_NFV5_ONE_RECORD, exporter).expect("dispatch v5");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].protocol_version, 5);
    }

    #[test]
    fn dispatch_unknown_version_returns_error() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut dec = IpfixDecoder::new();
        let buf: &[u8] = &[0x00, 0x07, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = decode_datagram(&mut dec, buf, exporter).unwrap_err();
        assert!(matches!(err, DecodeError::UnknownVersion(7)));
    }

    #[test]
    fn dispatch_empty_buf_returns_error() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut dec = IpfixDecoder::new();
        assert!(decode_datagram(&mut dec, &[], exporter).is_err());
    }

    // ---- I1: ipfix_flows_decoded counter ownership test ----
    // The decoder (parse_ipfix_data_set / decode_netflow_v5) is the SOLE place
    // that increments ipfix_flows_decoded. DefaultIpfixHandler must NOT also
    // increment it. This test verifies the decoder returns the correct number of
    // flows for a known multi-record fixture; if the handler were double-counting
    // in tests we would notice via integration tests, but the API contract is
    // that flows.len() == the number of records decoded (i.e. the decoder is the
    // authority, and handle_flows just consumes the result).
    #[test]
    fn decoder_returns_exactly_n_flows_for_n_records() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20));
        let mut dec = IpfixDecoder::new();
        // FIXTURE_IPFIX_TWO_RECORDS contains one template set (tmpl 256, 2 fields)
        // and one data set with 2 records. Expect exactly 2 flows returned.
        let records = decode_ipfix(&mut dec, FIXTURE_IPFIX_TWO_RECORDS, exporter)
            .expect("two-record fixture should decode");
        assert_eq!(
            records.len(),
            2,
            "decoder must return exactly 2 flows for a 2-record data set"
        );
        // Verify the two records have distinct addresses
        use std::net::Ipv4Addr as V4;
        assert_eq!(records[0].src_addr, Some(IpAddr::V4(V4::new(192, 168, 1, 1))));
        assert_eq!(records[1].src_addr, Some(IpAddr::V4(V4::new(192, 168, 1, 2))));
    }

    /// NetFlow v5 multi-record: 3 records in one packet → decoder returns 3 flows.
    #[test]
    fn netflow_v5_three_records_returns_three_flows() {
        use std::net::{IpAddr, Ipv4Addr};
        let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 21));
        // Build a v5 packet with count=3 by repeating the record from FIXTURE_NFV5_ONE_RECORD
        let mut pkt = FIXTURE_NFV5_ONE_RECORD.to_vec();
        // Update count to 3
        pkt[2] = 0x00;
        pkt[3] = 0x03;
        // Append 2 more copies of the 48-byte record
        let record = &FIXTURE_NFV5_ONE_RECORD[24..]; // slice off the 24-byte header
        pkt.extend_from_slice(record);
        pkt.extend_from_slice(record);

        let records = decode_netflow_v5(&pkt, exporter).expect("v5 three-record decode");
        assert_eq!(
            records.len(),
            3,
            "decoder must return exactly 3 flows for a 3-record v5 packet"
        );
    }
}
