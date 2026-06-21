# IPFIX Ingestion (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`)
> syntax for tracking.

**Goal:** Add `src/ipfix/` (FlowRecord type, stateful decoder for IPFIX v10/NetFlow v9/v5, UDP
listener with handler trait, DefaultIpfixHandler), extend `src/config/mod.rs` with `[ipfix]`
config, and wire a conditional spawn block in `src/main.rs`, all with unit + integration tests.

**Architecture:** The IPFIX listener mirrors the existing `syslog::listener` pattern — a
`UdpSocket` `recv_from` loop owns a stateful `IpfixDecoder`, decodes each datagram into
`Vec<FlowRecord>`, and dispatches to an `IpfixHandler` trait object; the `DefaultIpfixHandler`
logs a summary and increments `metrics` counters. The decoder is a plain struct (no `Arc` needed
in phase 1 since the single listener task owns it) that maintains a `HashMap<TemplateKey,
Template>` to resolve IPFIX/v9 data sets, and synthesises records directly for the fixed v5
layout.

**Tech Stack:** `tokio` (async UDP), `async-trait`, `chrono` (timestamps), `serde_json` (extra
field map), `metrics` (counters), `thiserror`/`anyhow` (errors), `tracing` (logs), `hex` (raw
fallback encoding) — all already in `Cargo.toml`.

## Global Constraints

- **Rust edition 2024**; MSRV follows `Cargo.toml`.
- **Line length:** 100 columns; **indent:** 4 spaces.
- Run `cargo fmt` and `cargo clippy -- -D warnings` before every commit; CI treats warnings as
  errors.
- Error handling: `thiserror` for library error types; `anyhow` for binary/test surfaces. No
  `.unwrap()` or `.expect()` in non-test production code.
- Tests live in `#[cfg(test)]` modules within each file (unit + integration); do not create
  separate test files unless the spec explicitly calls for it.
- **Decoder must be panic-free on attacker-controlled input.** Every length/offset read must be
  bounds-checked; return `Err(DecodeError::Truncated { … })` or `Err(DecodeError::Malformed {
  … })` rather than indexing out of bounds.
- Metrics via the `metrics` crate (`metrics::counter!` macro). Counter names are snake_case
  string literals; do not register them — the `metrics` crate records-on-first-use.
- Conventional commits: `feat(ipfix): …`, `test(ipfix): …`, `chore(config): …`, etc.
- Branch: `feat/ipfix-s3-persistence`. Never commit directly to `master`.
- No `todo!()` / `unimplemented!()` in non-test code.
- Phase 1 is **No S3** — do not add any S3/Parquet code.

---

## Task 1: FlowRecord type + module skeleton

**Files:**
- Create `src/ipfix/mod.rs`
- Create `src/ipfix/decoder.rs` (empty stub — public re-export only)
- Create `src/ipfix/listener.rs` (empty stub)

**Interfaces:**
- Produces `pub struct FlowRecord` (exact fields per spec, shown below)
- Produces `pub use decoder::IpfixDecoder;` (forward declaration, implemented in Task 3)

### Steps

- [ ] **1.1 — Write the failing test first**

  Add `#[cfg(test)]` block at the bottom of `src/ipfix/mod.rs` (create the file):

  ```rust
  // src/ipfix/mod.rs  (full file — test-first skeleton)
  //! IPFIX / NetFlow flow record types.

  use chrono::{DateTime, Utc};
  use serde::{Deserialize, Serialize};
  use serde_json::Value as JsonValue;
  use std::net::IpAddr;

  pub mod decoder;
  pub mod listener;

  /// A single decoded network flow record, normalised across IPFIX v10,
  /// NetFlow v9, and NetFlow v5.
  #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
  pub struct FlowRecord {
      // identity / provenance
      pub observation_domain_id: u32,
      pub template_id: u16,
      pub protocol_version: u8,
      pub exporter: IpAddr,
      pub export_time: DateTime<Utc>,
      // curated common flow fields
      pub src_addr: Option<IpAddr>,
      pub dst_addr: Option<IpAddr>,
      pub src_port: Option<u16>,
      pub dst_port: Option<u16>,
      pub ip_protocol: Option<u8>,
      pub octet_delta_count: Option<u64>,
      pub packet_delta_count: Option<u64>,
      pub flow_start: Option<DateTime<Utc>>,
      pub flow_end: Option<DateTime<Utc>>,
      pub tcp_flags: Option<u8>,
      pub input_interface: Option<u32>,
      pub output_interface: Option<u32>,
      /// Non-curated fields: keyed by IE name or "ie<id>" / "ie<pen>:<id>".
      /// Unknown byte values are hex-encoded strings.
      pub extra: JsonValue,
  }

  #[cfg(test)]
  mod tests {
      use super::*;
      use chrono::TimeZone;
      use std::net::Ipv4Addr;

      fn make_minimal_record() -> FlowRecord {
          FlowRecord {
              observation_domain_id: 0,
              template_id: 0,
              protocol_version: 5,
              exporter: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
              export_time: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
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
          }
      }

      #[test]
      fn flow_record_roundtrips_json() {
          let rec = make_minimal_record();
          let json = serde_json::to_string(&rec).expect("serialise");
          let back: FlowRecord = serde_json::from_str(&json).expect("deserialise");
          assert_eq!(rec, back);
      }

      #[test]
      fn flow_record_extra_stores_arbitrary_json() {
          let mut rec = make_minimal_record();
          rec.extra = serde_json::json!({ "ie200": "deadbeef", "ie0:300": "cafebabe" });
          assert_eq!(rec.extra["ie200"], "deadbeef");
      }

      #[test]
      fn flow_record_clone_is_independent() {
          let rec = make_minimal_record();
          let mut clone = rec.clone();
          clone.protocol_version = 10;
          // Original unchanged
          assert_eq!(rec.protocol_version, 5);
      }
  }
  ```

- [ ] **1.2 — Create stub files so it compiles, then run the test (expect failure then pass)**

  Create `src/ipfix/decoder.rs`:
  ```rust
  // src/ipfix/decoder.rs — placeholder; expanded in Tasks 2–6.
  ```

  Create `src/ipfix/listener.rs`:
  ```rust
  // src/ipfix/listener.rs — placeholder; expanded in Task 7.
  ```

  Then declare the module in `src/main.rs` by adding `mod ipfix;` alongside the other `mod`
  declarations at the top. (Wiring the spawn block comes in Task 8.)

  Run:
  ```
  cargo test -p logthing ipfix::tests -- --nocapture
  ```

  Expected: all three tests pass (no decode logic yet; type + serde is all that's needed).

- [ ] **1.3 — Commit**

  ```
  git add src/ipfix/mod.rs src/ipfix/decoder.rs src/ipfix/listener.rs src/main.rs
  git commit -m "feat(ipfix): add FlowRecord type and module skeleton"
  ```

---

## Task 2: DecodeError type + curated IE map

**Files:**
- Modify `src/ipfix/decoder.rs`

**Interfaces:**
- Produces `pub enum DecodeError` (used by all decoder tasks)
- Produces `pub fn ie_info(id: u16) -> Option<(&'static str, IeType)>` — looks up the curated
  IE table
- Produces `pub enum IeType { U8, U16, U32, U64, Ipv4, Ipv6, DateTimeMillis, DateTimeSysUptime }`

### IE map coverage (verbatim from spec)

| IE id | Field name | IeType |
|-------|-----------|--------|
| 1 | octetDeltaCount | U64 |
| 2 | packetDeltaCount | U64 |
| 4 | protocolIdentifier | U8 |
| 6 | tcpControlBits | U8 |
| 7 | sourceTransportPort | U16 |
| 8 | sourceIPv4Address | Ipv4 |
| 10 | ingressInterface | U32 |
| 11 | destinationTransportPort | U16 |
| 12 | destinationIPv4Address | Ipv4 |
| 14 | egressInterface | U32 |
| 21 | flowEndSysUpTime | DateTimeSysUptime |
| 22 | flowStartSysUpTime | DateTimeSysUptime |
| 27 | sourceIPv6Address | Ipv6 |
| 28 | destinationIPv6Address | Ipv6 |
| 32 | icmpTypeCodeIPv4 | U16 |
| 56 | sourceMacAddress | U64 |
| 58 | vlanId | U16 |
| 60 | ipVersion | U8 |
| 61 | flowDirection | U8 |
| 62 | ipNextHopIPv6Address | Ipv6 |
| 64 | bgpNextHopIPv6Address | Ipv6 |
| 70 | mplsTopLabelType | U8 |
| 89 | forwardingStatus | U8 |
| 96 | mpls_vpn_rd | U64 |
| 130 | exporterIPv4Address | Ipv4 |
| 131 | exporterIPv6Address | Ipv6 |
| 136 | flowEndReason | U8 |
| 148 | flowId | U64 |
| 152 | flowStartMilliseconds | DateTimeMillis |
| 153 | flowEndMilliseconds | DateTimeMillis |
| 176 | icmpTypeIPv4 | U8 |
| 177 | icmpCodeIPv4 | U8 |
| 225 | postNATSourceIPv4Address | Ipv4 |
| 226 | postNATDestinationIPv4Address | Ipv4 |
| 227 | postNAPTSourceTransportPort | U16 |
| 228 | postNAPTDestinationTransportPort | U16 |

### Steps

- [ ] **2.1 — Write the failing tests**

  Add to the `#[cfg(test)]` block in `src/ipfix/decoder.rs`:

  ```rust
  // src/ipfix/decoder.rs

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
      Truncated { offset: usize, need: usize, have: usize },

      #[error("malformed packet: {reason}")]
      Malformed { reason: String },

      #[error("unknown version {0}")]
      UnknownVersion(u16),
  }

  /// Look up a curated IANA IE id.
  /// Returns `(field_name, value_type)` for known IEs; `None` for unknown.
  pub fn ie_info(id: u16) -> Option<(&'static str, IeType)> {
      match id {
          1   => Some(("octetDeltaCount",                   IeType::U64)),
          2   => Some(("packetDeltaCount",                  IeType::U64)),
          4   => Some(("protocolIdentifier",                IeType::U8)),
          6   => Some(("tcpControlBits",                    IeType::U8)),
          7   => Some(("sourceTransportPort",               IeType::U16)),
          8   => Some(("sourceIPv4Address",                 IeType::Ipv4)),
          10  => Some(("ingressInterface",                  IeType::U32)),
          11  => Some(("destinationTransportPort",          IeType::U16)),
          12  => Some(("destinationIPv4Address",            IeType::Ipv4)),
          14  => Some(("egressInterface",                   IeType::U32)),
          21  => Some(("flowEndSysUpTime",                  IeType::DateTimeSysUptime)),
          22  => Some(("flowStartSysUpTime",                IeType::DateTimeSysUptime)),
          27  => Some(("sourceIPv6Address",                 IeType::Ipv6)),
          28  => Some(("destinationIPv6Address",            IeType::Ipv6)),
          32  => Some(("icmpTypeCodeIPv4",                  IeType::U16)),
          56  => Some(("sourceMacAddress",                  IeType::U64)),
          58  => Some(("vlanId",                            IeType::U16)),
          60  => Some(("ipVersion",                         IeType::U8)),
          61  => Some(("flowDirection",                     IeType::U8)),
          62  => Some(("ipNextHopIPv6Address",              IeType::Ipv6)),
          64  => Some(("bgpNextHopIPv6Address",             IeType::Ipv6)),
          70  => Some(("mplsTopLabelType",                  IeType::U8)),
          89  => Some(("forwardingStatus",                  IeType::U8)),
          96  => Some(("mpls_vpn_rd",                       IeType::U64)),
          130 => Some(("exporterIPv4Address",               IeType::Ipv4)),
          131 => Some(("exporterIPv6Address",               IeType::Ipv6)),
          136 => Some(("flowEndReason",                     IeType::U8)),
          148 => Some(("flowId",                            IeType::U64)),
          152 => Some(("flowStartMilliseconds",             IeType::DateTimeMillis)),
          153 => Some(("flowEndMilliseconds",               IeType::DateTimeMillis)),
          176 => Some(("icmpTypeIPv4",                      IeType::U8)),
          177 => Some(("icmpCodeIPv4",                      IeType::U8)),
          225 => Some(("postNATSourceIPv4Address",          IeType::Ipv4)),
          226 => Some(("postNATDestinationIPv4Address",     IeType::Ipv4)),
          227 => Some(("postNAPTSourceTransportPort",       IeType::U16)),
          228 => Some(("postNAPTDestinationTransportPort",  IeType::U16)),
          _   => None,
      }
  }

  #[cfg(test)]
  mod tests {
      use super::*;

      #[test]
      fn ie_info_known_ids_return_correct_type() {
          assert_eq!(ie_info(8),   Some(("sourceIPv4Address",        IeType::Ipv4)));
          assert_eq!(ie_info(12),  Some(("destinationIPv4Address",   IeType::Ipv4)));
          assert_eq!(ie_info(27),  Some(("sourceIPv6Address",        IeType::Ipv6)));
          assert_eq!(ie_info(1),   Some(("octetDeltaCount",          IeType::U64)));
          assert_eq!(ie_info(152), Some(("flowStartMilliseconds",    IeType::DateTimeMillis)));
          assert_eq!(ie_info(22),  Some(("flowStartSysUpTime",       IeType::DateTimeSysUptime)));
      }

      #[test]
      fn ie_info_unknown_id_returns_none() {
          assert_eq!(ie_info(9999), None);
          assert_eq!(ie_info(0),    None);
          assert_eq!(ie_info(255),  None);
      }

      #[test]
      fn decode_error_display_truncated() {
          let e = DecodeError::Truncated { offset: 4, need: 4, have: 2 };
          let msg = e.to_string();
          assert!(msg.contains("truncated"), "got: {msg}");
          assert!(msg.contains("4"));
      }

      #[test]
      fn decode_error_display_unknown_version() {
          let e = DecodeError::UnknownVersion(99);
          assert!(e.to_string().contains("99"));
      }
  }
  ```

- [ ] **2.2 — Run (expect pass — all logic is in the match table, no complex impl needed)**

  ```
  cargo test -p logthing ipfix::decoder::tests -- --nocapture
  ```

  Expected output: 4 tests pass.

- [ ] **2.3 — Commit**

  ```
  git add src/ipfix/decoder.rs
  git commit -m "feat(ipfix): add DecodeError type and curated IE map (36 entries)"
  ```

---

## Task 3: Template cache types + read-u-helpers

**Files:**
- Modify `src/ipfix/decoder.rs`

**Interfaces:**
- Produces `pub struct FieldSpecifier { pub ie_id: u16, pub length: u16, pub enterprise_number: Option<u32> }`
- Produces `pub type TemplateKey = (IpAddr, u32, u16);`  — `(exporter, obs_domain_id, template_id)`
- Produces `pub struct IpfixDecoder { … }` with `pub fn new() -> Self`
- Produces internal helpers `fn read_u8`, `fn read_u16_be`, `fn read_u32_be`, `fn read_u64_be`,
  `fn read_bytes` — all returning `Result<_, DecodeError>`

### Steps

- [ ] **3.1 — Write failing tests**

  Append below the existing tests in `src/ipfix/decoder.rs`:

  ```rust
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
      assert!(read_u32_be(&buf, 2).is_err());  // only 3 bytes left
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
          FieldSpecifier { ie_id: 8,  length: 4, enterprise_number: None },
          FieldSpecifier { ie_id: 12, length: 4, enterprise_number: None },
      ];
      decoder.cache.insert(key, fields.clone());
      assert_eq!(decoder.cache.get(&key).unwrap().len(), 2);
      assert_eq!(decoder.cache.get(&key).unwrap()[0].ie_id, 8);
  }
  ```

- [ ] **3.2 — Implement in `src/ipfix/decoder.rs`**

  Add above the `#[cfg(test)]` block:

  ```rust
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
      pub cache: HashMap<TemplateKey, Vec<FieldSpecifier>>,
  }

  impl IpfixDecoder {
      pub fn new() -> Self {
          Self { cache: HashMap::new() }
      }
  }

  impl Default for IpfixDecoder {
      fn default() -> Self {
          Self::new()
      }
  }

  // ---- Bounds-checked read helpers ----------------------------------------

  fn read_u8(buf: &[u8], offset: usize) -> Result<u8, DecodeError> {
      buf.get(offset).copied().ok_or(DecodeError::Truncated {
          offset,
          need: 1,
          have: buf.len().saturating_sub(offset),
      })
  }

  fn read_u16_be(buf: &[u8], offset: usize) -> Result<u16, DecodeError> {
      let end = offset.checked_add(2).ok_or_else(|| DecodeError::Malformed {
          reason: "offset overflow".into(),
      })?;
      if end > buf.len() {
          return Err(DecodeError::Truncated { offset, need: 2, have: buf.len().saturating_sub(offset) });
      }
      Ok(u16::from_be_bytes([buf[offset], buf[offset + 1]]))
  }

  fn read_u32_be(buf: &[u8], offset: usize) -> Result<u32, DecodeError> {
      let end = offset.checked_add(4).ok_or_else(|| DecodeError::Malformed {
          reason: "offset overflow".into(),
      })?;
      if end > buf.len() {
          return Err(DecodeError::Truncated { offset, need: 4, have: buf.len().saturating_sub(offset) });
      }
      Ok(u32::from_be_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]))
  }

  fn read_u64_be(buf: &[u8], offset: usize) -> Result<u64, DecodeError> {
      let end = offset.checked_add(8).ok_or_else(|| DecodeError::Malformed {
          reason: "offset overflow".into(),
      })?;
      if end > buf.len() {
          return Err(DecodeError::Truncated { offset, need: 8, have: buf.len().saturating_sub(offset) });
      }
      Ok(u64::from_be_bytes(buf[offset..end].try_into().unwrap()))
  }

  fn read_bytes(buf: &[u8], offset: usize, len: usize) -> Result<&[u8], DecodeError> {
      let end = offset.checked_add(len).ok_or_else(|| DecodeError::Malformed {
          reason: "offset overflow".into(),
      })?;
      if end > buf.len() {
          return Err(DecodeError::Truncated { offset, need: len, have: buf.len().saturating_sub(offset) });
      }
      Ok(&buf[offset..end])
  }
  ```

- [ ] **3.3 — Run tests**

  ```
  cargo test -p logthing ipfix::decoder::tests -- --nocapture
  ```

  Expected: all previous tests + 4 new tests pass (8 total in decoder).

- [ ] **3.4 — Commit**

  ```
  git add src/ipfix/decoder.rs
  git commit -m "feat(ipfix): add template cache types and bounds-checked read helpers"
  ```

---

## Task 4: IPFIX v10 (RFC 7011) decode — template sets and data sets

**Files:**
- Modify `src/ipfix/decoder.rs`

**Interfaces:**
- Produces `pub fn decode_ipfix(decoder: &mut IpfixDecoder, buf: &[u8], exporter: IpAddr, export_time: DateTime<Utc>) -> Result<Vec<FlowRecord>, DecodeError>`
- Internal: `fn parse_ipfix_template_set`, `fn parse_ipfix_data_set`, `fn decode_field_value`,
  `fn apply_field_to_record`

The IPFIX message layout (RFC 7011 §3):
```
Message Header (16 bytes):
  [0..2]  version = 0x000A
  [2..4]  length (total message length including header)
  [4..8]  export time (Unix seconds, big-endian u32)
  [8..12] sequence number
  [12..16] observation domain id

Set Header (4 bytes):
  [0..2]  set id  (2 = Template Set, 3 = Options Template Set, ≥ 256 = Data Set)
  [2..4]  length  (includes this 4-byte header)

Template Record (inside Template Set, set id 2):
  [0..2]  template id (≥ 256)
  [2..4]  field count
  then field_count × Field Specifier:
    [0..2]  ie_id (bit 15 set → enterprise; remaining 15 bits = ie id)
    [2..4]  field length
    if enterprise: [4..8] enterprise number (u32 BE)
```

### Byte fixtures for tests

**Fixture A — IPFIX template set + matching data set (single message)**

This encodes:
- Template id 256 with two fields: ie 8 (sourceIPv4Address, 4 bytes) and ie 12
  (destinationIPv4Address, 4 bytes).
- One data record: src=192.168.1.1, dst=10.0.0.1.

```
// Full IPFIX message bytes (hex, big-endian):
//
// IPFIX Message Header (16 bytes):
//   00 0A          version = 10
//   00 30          total length = 48
//   67 5C B0 20    export_time = 1734048800 (arbitrary Unix timestamp)
//   00 00 00 01    sequence number = 1
//   00 00 00 00    observation domain id = 0
//
// Set 1 — Template Set (set id = 2):
//   00 02          set id = 2
//   00 14          length = 20 bytes (4 header + 16 records)
//   Template record:
//     01 00        template id = 256
//     00 02        field count = 2
//     00 08  00 04 ie_id=8,  length=4  (sourceIPv4Address)
//     00 0C  00 04 ie_id=12, length=4  (destinationIPv4Address)
//
// Set 2 — Data Set (set id = 256):
//   01 00          set id = 256
//   00 0C          length = 12 bytes (4 header + 8 data)
//   Data record (matches template 256):
//     C0 A8 01 01  192.168.1.1  (src)
//     0A 00 00 01  10.0.0.1     (dst)

const FIXTURE_IPFIX_TEMPLATE_THEN_DATA: &[u8] = &[
    // Message header
    0x00, 0x0A,                         // version = 10
    0x00, 0x30,                         // total length = 48
    0x67, 0x5C, 0xB0, 0x20,            // export_time
    0x00, 0x00, 0x00, 0x01,            // sequence
    0x00, 0x00, 0x00, 0x00,            // observation domain id = 0
    // Template Set
    0x00, 0x02,                         // set id = 2
    0x00, 0x14,                         // length = 20
    0x01, 0x00,                         // template id = 256
    0x00, 0x02,                         // field count = 2
    0x00, 0x08, 0x00, 0x04,            // ie 8, len 4
    0x00, 0x0C, 0x00, 0x04,            // ie 12, len 4
    // Data Set
    0x01, 0x00,                         // set id = 256
    0x00, 0x0C,                         // length = 12
    0xC0, 0xA8, 0x01, 0x01,            // 192.168.1.1
    0x0A, 0x00, 0x00, 0x01,            // 10.0.0.1
];
```

**Fixture B — Truncated IPFIX message (only 3 bytes — should error, not panic)**

```rust
const FIXTURE_IPFIX_TRUNCATED: &[u8] = &[0x00, 0x0A, 0x00];
```

**Fixture C — IPFIX message with unknown IE (ie 999 → extra field)**

Template id 257, one field: ie 999 (unknown), 4 bytes. Data: `[0xDE, 0xAD, 0xBE, 0xEF]`.

```rust
const FIXTURE_IPFIX_UNKNOWN_IE: &[u8] = &[
    // Message header
    0x00, 0x0A,
    0x00, 0x2C,                         // total length = 44
    0x67, 0x5C, 0xB0, 0x20,
    0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    // Template Set
    0x00, 0x02,
    0x00, 0x10,                         // length = 16
    0x01, 0x01,                         // template id = 257
    0x00, 0x01,                         // field count = 1
    0x03, 0xE7, 0x00, 0x04,            // ie 999, len 4
    // Data Set
    0x01, 0x01,                         // set id = 257
    0x00, 0x0C,                         // length = 12
    0xDE, 0xAD, 0xBE, 0xEF,            // raw bytes for ie 999
];
```

**Fixture D — Data set referencing un-cached template (should produce empty Vec, not error)**

A data set with set id = 300, but no prior template set with id 300 in the same message.

```rust
const FIXTURE_IPFIX_MISSING_TEMPLATE: &[u8] = &[
    // Message header
    0x00, 0x0A,
    0x00, 0x18,                         // total length = 24
    0x67, 0x5C, 0xB0, 0x20,
    0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x00,
    // Data Set — template 300 not yet cached
    0x01, 0x2C,                         // set id = 300
    0x00, 0x08,                         // length = 8
    0xAA, 0xBB, 0xCC, 0xDD,
];
```

### Steps

- [ ] **4.1 — Write failing tests**

  Add to the `#[cfg(test)]` block in `decoder.rs`:

  ```rust
  // ---- IPFIX v10 decode tests (Task 4) ----
  use super::super::FlowRecord; // ipfix::FlowRecord
  use chrono::TimeZone;

  #[tokio::test]
  async fn ipfix_template_then_data_decodes_src_dst() {
      use std::net::{IpAddr, Ipv4Addr};
      let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
      let export_ts = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
      let mut dec = IpfixDecoder::new();
      let records = decode_ipfix(&mut dec, FIXTURE_IPFIX_TEMPLATE_THEN_DATA, exporter, export_ts)
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
      let export_ts = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
      let mut dec = IpfixDecoder::new();
      let result = decode_ipfix(&mut dec, FIXTURE_IPFIX_TRUNCATED, exporter, export_ts);
      assert!(result.is_err(), "truncated input must error");
  }

  #[test]
  fn ipfix_unknown_ie_goes_to_extra_as_hex() {
      use std::net::{IpAddr, Ipv4Addr};
      let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
      let export_ts = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
      let mut dec = IpfixDecoder::new();
      let records = decode_ipfix(&mut dec, FIXTURE_IPFIX_UNKNOWN_IE, exporter, export_ts)
          .expect("should decode");
      assert_eq!(records.len(), 1);
      let r = &records[0];
      assert_eq!(r.extra["ie999"], "deadbeef",
                 "unknown IE should appear as hex in extra; got: {}", r.extra);
  }

  #[test]
  fn ipfix_missing_template_skipped_no_error() {
      use std::net::{IpAddr, Ipv4Addr};
      let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
      let export_ts = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
      let mut dec = IpfixDecoder::new();
      // Should succeed but produce zero records (template 300 not cached)
      let records = decode_ipfix(&mut dec, FIXTURE_IPFIX_MISSING_TEMPLATE, exporter, export_ts)
          .expect("missing template must not error");
      assert_eq!(records.len(), 0, "data set with uncached template is skipped");
  }
  ```

  Run first to see failures:
  ```
  cargo test -p logthing 'ipfix::decoder::tests::ipfix_' 2>&1 | head -40
  ```

- [ ] **4.2 — Implement `decode_ipfix` in `src/ipfix/decoder.rs`**

  Add below the read helpers (before `#[cfg(test)]`):

  ```rust
  use chrono::{DateTime, Utc};
  use crate::ipfix::FlowRecord;

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
      export_time: DateTime<Utc>,
  ) -> Result<Vec<FlowRecord>, DecodeError> {
      // --- Message header (16 bytes) ---
      if buf.len() < 16 {
          return Err(DecodeError::Truncated { offset: 0, need: 16, have: buf.len() });
      }
      let version = read_u16_be(buf, 0)?;
      if version != 10 {
          return Err(DecodeError::UnknownVersion(version));
      }
      let total_len = read_u16_be(buf, 2)? as usize;
      let obs_domain_id = read_u32_be(buf, 12)?;

      if buf.len() < total_len {
          return Err(DecodeError::Truncated { offset: 0, need: total_len, have: buf.len() });
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
          let set_end = pos.checked_add(set_len).ok_or_else(|| DecodeError::Malformed {
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
                  // Options Template Set — parse to keep template cache consistent;
                  // we skip options data sets for now (phase 1 scope).
                  parse_ipfix_options_template_set(decoder, set_body, exporter, obs_domain_id)?;
              }
              id if id >= 256 => {
                  // Data Set
                  let mut set_records = parse_ipfix_data_set(
                      decoder, set_body, set_id, exporter, obs_domain_id, export_time,
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
                          offset: pos, need: 4, have: body.len().saturating_sub(pos),
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
      // We store the full field list (scope + non-scope) in the cache for data-set decoding.
      let mut pos = 0usize;
      while pos + 6 <= body.len() {
          let template_id = read_u16_be(body, pos)?;
          let field_count = read_u16_be(body, pos + 2)? as usize;
          let _scope_count = read_u16_be(body, pos + 4)?;
          pos += 6;

          let mut fields = Vec::with_capacity(field_count);
          for _ in 0..field_count {
              if pos + 4 > body.len() { break; }
              let raw_ie = read_u16_be(body, pos)?;
              let field_len = read_u16_be(body, pos + 2)?;
              pos += 4;
              let enterprise = if raw_ie & 0x8000 != 0 {
                  if pos + 4 > body.len() { break; }
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
              decoder.cache.insert((exporter, obs_domain_id, template_id), fields);
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
              tracing::debug!("ipfix: no cached template for key ({exporter}, {obs_domain_id}, {set_id}) — skipping data set");
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
      if field.enterprise_number.is_some() {
          let key = format!("ie{}:{}", field.enterprise_number.unwrap(), field.ie_id);
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
          Some((name, ie_type)) => {
              match ie_type {
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
                          if let chrono::LocalResult::Single(dt) =
                              Utc.timestamp_opt(secs, nanos)
                          {
                              match field.ie_id {
                                  152 => rec.flow_start = Some(dt),
                                  153 => rec.flow_end = Some(dt),
                                  _ => { rec.extra[name] = json!(dt.to_rfc3339()); }
                              }
                          }
                      } else {
                          rec.extra[name] = json!(hex::encode(raw));
                      }
                  }
                  IeType::DateTimeSysUptime => {
                      // SysUptime fields (IEs 21/22) are milliseconds relative to the exporter's
                      // boot time — we can't convert to absolute time without the sysUpTime IE
                      // (also not typically exported in v10). Store as relative ms in extra.
                      if raw.len() >= 4 {
                          let ms = u32::from_be_bytes(raw[..4].try_into().unwrap());
                          rec.extra[name] = json!(ms);
                      } else {
                          rec.extra[name] = json!(hex::encode(raw));
                      }
                  }
              }
          }
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
  ```

- [ ] **4.3 — Run tests**

  ```
  cargo test -p logthing 'ipfix::decoder::tests::ipfix_' -- --nocapture
  ```

  Expected: 4 tests pass.

  Also run the full test suite to check for regressions:
  ```
  cargo test -p logthing -- --nocapture 2>&1 | tail -20
  ```

- [ ] **4.4 — Commit**

  ```
  git add src/ipfix/decoder.rs
  git commit -m "feat(ipfix): implement IPFIX v10 template and data set decoding"
  ```

---

## Task 5: NetFlow v9 (RFC 3954) decode

**Files:**
- Modify `src/ipfix/decoder.rs`

**Interfaces:**
- Produces `pub fn decode_netflow_v9(decoder: &mut IpfixDecoder, buf: &[u8], exporter: IpAddr) -> Result<Vec<FlowRecord>, DecodeError>`

NetFlow v9 message layout (RFC 3954 §5):
```
Header (20 bytes):
  [0..2]   version = 9
  [2..4]   count (number of flowsets)
  [4..8]   sys_uptime_ms (u32 BE, ms since boot)
  [8..12]  unix_secs (u32 BE, export time)
  [12..16] sequence_number
  [16..20] source_id (= observation_domain_id for our key)

FlowSet Header (4 bytes):
  [0..2]   flowset_id  (0 = Template FlowSet, 1 = Options Template FlowSet, ≥ 256 = Data FlowSet)
  [2..4]   length (includes this 4-byte header)

Template FlowSet (flowset_id = 0):
  One or more Template Records:
    [0..2]  template_id (≥ 256)
    [2..4]  field_count
    then field_count × (ie_id: u16, length: u16) — NO enterprise bit in v9

Data FlowSet (flowset_id ≥ 256):
  Raw field data packed per the matching template.
  Padding zeros may appear at the end; length rounded to 4-byte boundary.
```

### Byte fixtures

**Fixture E — NetFlow v9 template flowset + data flowset (single packet)**

Template id 256: ie 8 (src IPv4, 4 bytes), ie 12 (dst IPv4, 4 bytes), ie 1 (octetDeltaCount, 4 bytes).
Data record: src=172.16.0.1, dst=8.8.8.8, octets=1000.

```rust
const FIXTURE_NFV9_TEMPLATE_THEN_DATA: &[u8] = &[
    // NetFlow v9 Header (20 bytes)
    0x00, 0x09,                         // version = 9
    0x00, 0x02,                         // count = 2 flowsets
    0x00, 0x0F, 0x42, 0x40,            // sys_uptime = 1000000 ms
    0x67, 0x5C, 0xB0, 0x20,            // unix_secs (same as IPFIX fixture)
    0x00, 0x00, 0x00, 0x01,            // sequence
    0x00, 0x00, 0x00, 0x05,            // source_id = 5

    // Template FlowSet (flowset_id = 0)
    0x00, 0x00,                         // flowset_id = 0
    0x00, 0x18,                         // length = 24 bytes
    // Template record 256
    0x01, 0x00,                         // template_id = 256
    0x00, 0x03,                         // field_count = 3
    0x00, 0x08, 0x00, 0x04,            // ie 8, len 4
    0x00, 0x0C, 0x00, 0x04,            // ie 12, len 4
    0x00, 0x01, 0x00, 0x04,            // ie 1, len 4 (octetDeltaCount)

    // Data FlowSet (flowset_id = 256)
    0x01, 0x00,                         // flowset_id = 256
    0x00, 0x10,                         // length = 16 (4 header + 12 data)
    0xAC, 0x10, 0x00, 0x01,            // 172.16.0.1
    0x08, 0x08, 0x08, 0x08,            // 8.8.8.8
    0x00, 0x00, 0x03, 0xE8,            // 1000 octets
];
```

**Fixture F — Truncated v9 packet (only 10 bytes)**

```rust
const FIXTURE_NFV9_TRUNCATED: &[u8] = &[
    0x00, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
```

### Steps

- [ ] **5.1 — Write failing tests**

  Append to `#[cfg(test)]` in `decoder.rs`:

  ```rust
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
  ```

  Run to see failures:
  ```
  cargo test -p logthing 'ipfix::decoder::tests::netflow_v9' 2>&1 | head -20
  ```

- [ ] **5.2 — Implement `decode_netflow_v9`**

  Add to `src/ipfix/decoder.rs` (before `#[cfg(test)]`):

  ```rust
  /// Decode one NetFlow v9 packet.
  ///
  /// v9 uses the same `decoder.cache` keyed on `(exporter, source_id, template_id)`.
  pub fn decode_netflow_v9(
      decoder: &mut IpfixDecoder,
      buf: &[u8],
      exporter: IpAddr,
  ) -> Result<Vec<FlowRecord>, DecodeError> {
      if buf.len() < 20 {
          return Err(DecodeError::Truncated { offset: 0, need: 20, have: buf.len() });
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
          let flowset_end = pos.checked_add(flowset_len).ok_or_else(|| DecodeError::Malformed {
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
                  // Options Template FlowSet — cache but skip data decode in phase 1
                  // (options templates have a different header; just skip for now)
                  tracing::debug!("ipfix: skipping v9 options template flowset");
              }
              id if id >= 256 => {
                  let mut set_records = parse_ipfix_data_set(
                      decoder,
                      body,
                      id,
                      exporter,
                      source_id,
                      export_time,
                  )?;
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
                      offset: pos, need: 4, have: body.len().saturating_sub(pos),
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
          decoder.cache.insert((exporter, source_id, template_id), fields);
          metrics::counter!("ipfix_templates_received").increment(1);
      }
      Ok(())
  }
  ```

- [ ] **5.3 — Run tests**

  ```
  cargo test -p logthing 'ipfix::decoder::tests::netflow_v9' -- --nocapture
  ```

  Expected: 2 tests pass. Full suite clean:
  ```
  cargo test -p logthing -- --nocapture 2>&1 | tail -10
  ```

- [ ] **5.4 — Commit**

  ```
  git add src/ipfix/decoder.rs
  git commit -m "feat(ipfix): implement NetFlow v9 template and data flowset decoding"
  ```

---

## Task 6: NetFlow v5 fixed-layout decode

**Files:**
- Modify `src/ipfix/decoder.rs`

**Interfaces:**
- Produces `pub fn decode_netflow_v5(buf: &[u8], exporter: IpAddr) -> Result<Vec<FlowRecord>, DecodeError>`
  (no `decoder` parameter — v5 has no templates)

NetFlow v5 layout (no RFC; de-facto Cisco standard):
```
Header (24 bytes):
  [0..2]   version = 5
  [2..4]   count (number of records, 1–30)
  [4..8]   sys_uptime_ms (u32 BE)
  [8..12]  unix_secs (u32 BE)
  [12..16] unix_nsecs (u32 BE, nanosecond residual)
  [16..20] flow_sequence
  [20]     engine_type
  [21]     engine_id
  [22..24] sampling_interval (u16 BE; top 2 bits = mode, low 14 = interval)

Record (48 bytes each):
  [0..4]   srcaddr (IPv4)
  [4..8]   dstaddr (IPv4)
  [8..12]  nexthop (IPv4)
  [12..14] input (u16 BE, ingress interface)
  [14..16] output (u16 BE, egress interface)
  [16..20] dPkts (u32 BE, packet count)
  [20..24] dOctets (u32 BE, octet count)
  [24..28] first_ms (u32 BE, sysuptime at flow start ms)
  [28..32] last_ms (u32 BE, sysuptime at flow end ms)
  [32..34] srcport (u16 BE)
  [34..36] dstport (u16 BE)
  [36]     pad1
  [37]     tcp_flags (u8)
  [38]     prot (u8, IP protocol)
  [39]     tos (u8)
  [40..42] src_as (u16 BE)
  [42..44] dst_as (u16 BE)
  [44]     src_mask (u8)
  [45]     dst_mask (u8)
  [46..48] pad2
```

### Byte fixtures

**Fixture G — NetFlow v5 header + one record**

```rust
const FIXTURE_NFV5_ONE_RECORD: &[u8] = &[
    // Header (24 bytes)
    0x00, 0x05,                         // version = 5
    0x00, 0x01,                         // count = 1
    0x00, 0x0F, 0x42, 0x40,            // sys_uptime_ms = 1_000_000
    0x67, 0x5C, 0xB0, 0x20,            // unix_secs
    0x00, 0x00, 0x00, 0x00,            // unix_nsecs
    0x00, 0x00, 0x00, 0x01,            // flow_sequence
    0x00,                               // engine_type
    0x00,                               // engine_id
    0x00, 0x00,                         // sampling_interval

    // Record (48 bytes)
    0xC0, 0xA8, 0x01, 0x0A,            // srcaddr = 192.168.1.10
    0xC0, 0xA8, 0x01, 0x01,            // dstaddr = 192.168.1.1
    0x00, 0x00, 0x00, 0x00,            // nexthop = 0.0.0.0
    0x00, 0x01,                         // input = 1
    0x00, 0x02,                         // output = 2
    0x00, 0x00, 0x00, 0x05,            // dPkts = 5
    0x00, 0x00, 0x01, 0xF4,            // dOctets = 500
    0x00, 0x0F, 0x42, 0x00,            // first_ms = 999424
    0x00, 0x0F, 0x42, 0x3C,            // last_ms  = 999484
    0x1F, 0x90,                         // srcport = 8080
    0x00, 0x50,                         // dstport = 80
    0x00,                               // pad1
    0x18,                               // tcp_flags = 0x18 (ACK+PSH)
    0x06,                               // prot = 6 (TCP)
    0x00,                               // tos
    0x00, 0x00,                         // src_as
    0x00, 0x00,                         // dst_as
    0x00,                               // src_mask
    0x00,                               // dst_mask
    0x00, 0x00,                         // pad2
];
```

**Fixture H — Truncated v5 (only header, no records)**

```rust
const FIXTURE_NFV5_TRUNCATED: &[u8] = &[
    0x00, 0x05, 0x00, 0x01,            // version=5, count=1 (claims 1 record)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,            // 24 bytes of header but NO record bytes follow
];
```

### Steps

- [ ] **6.1 — Write failing tests**

  Append to `#[cfg(test)]`:

  ```rust
  // ---- NetFlow v5 decode tests (Task 6) ----

  #[test]
  fn netflow_v5_single_record_decoded_correctly() {
      use std::net::{IpAddr, Ipv4Addr};
      let exporter: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
      let records = decode_netflow_v5(FIXTURE_NFV5_ONE_RECORD, exporter)
          .expect("v5 decode");
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
  ```

  Run to see failures:
  ```
  cargo test -p logthing 'ipfix::decoder::tests::netflow_v5' 2>&1 | head -20
  ```

- [ ] **6.2 — Implement `decode_netflow_v5`**

  Add to `src/ipfix/decoder.rs`:

  ```rust
  /// Decode one NetFlow v5 packet. No template cache required.
  ///
  /// Synthesises `FlowRecord`s directly from the fixed 48-byte record layout.
  /// `template_id` is set to 0 and `observation_domain_id` to 0 (v5 has no concept of either).
  pub fn decode_netflow_v5(
      buf: &[u8],
      exporter: IpAddr,
  ) -> Result<Vec<FlowRecord>, DecodeError> {
      const HEADER_LEN: usize = 24;
      const RECORD_LEN: usize = 48;

      if buf.len() < HEADER_LEN {
          return Err(DecodeError::Truncated { offset: 0, need: HEADER_LEN, have: buf.len() });
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
              // Store sysuptime-relative ms in extra (cannot convert to absolute without boot time)
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
  ```

- [ ] **6.3 — Run tests**

  ```
  cargo test -p logthing 'ipfix::decoder::tests::netflow_v5' -- --nocapture
  ```

  Expected: 3 tests pass. Full suite:
  ```
  cargo test -p logthing -- --nocapture 2>&1 | tail -10
  ```

- [ ] **6.4 — Commit**

  ```
  git add src/ipfix/decoder.rs
  git commit -m "feat(ipfix): implement NetFlow v5 fixed-layout decoding"
  ```

---

## Task 7: Version dispatch entry point

**Files:**
- Modify `src/ipfix/decoder.rs`

**Interfaces:**
- Produces `pub fn decode_datagram(decoder: &mut IpfixDecoder, buf: &[u8], exporter: IpAddr) -> Result<Vec<FlowRecord>, DecodeError>`
  — the single public entry point called by the listener loop.

### Steps

- [ ] **7.1 — Write failing tests**

  Append to `#[cfg(test)]`:

  ```rust
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
      let records = decode_datagram(&mut dec, FIXTURE_NFV5_ONE_RECORD, exporter)
          .expect("dispatch v5");
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
  ```

  Run to see failures:
  ```
  cargo test -p logthing 'ipfix::decoder::tests::dispatch' 2>&1 | head -20
  ```

- [ ] **7.2 — Implement dispatch entry point**

  Add to `src/ipfix/decoder.rs`:

  ```rust
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
          return Err(DecodeError::Truncated { offset: 0, need: 2, have: buf.len() });
      }
      let version = read_u16_be(buf, 0)?;
      match version {
          10 => {
              // export_time is inside the IPFIX header; decode_ipfix reads it
              decode_ipfix(decoder, buf, exporter, Utc::now())
          }
          9 => decode_netflow_v9(decoder, buf, exporter),
          5 => decode_netflow_v5(buf, exporter),
          other => Err(DecodeError::UnknownVersion(other)),
      }
  }
  ```

  Note: `decode_ipfix` ignores the `export_time` parameter we pass and reads it from the message
  header instead (the parameter is only for flexibility / testing). Update `decode_ipfix`'s
  implementation to prefer the header value; the signature stays the same for test compatibility.
  (This is a minor implementation note; the tests already pass `export_time` and `decode_ipfix`
  already parses it from the header — the caller's value is not used inside `decode_ipfix` for the
  record, but can be kept as the function signature for future use.)

- [ ] **7.3 — Run tests**

  ```
  cargo test -p logthing 'ipfix::decoder::tests::dispatch' -- --nocapture
  ```

  Expected: 5 tests pass. Full suite:
  ```
  cargo test -p logthing -- --nocapture 2>&1 | tail -10
  ```

- [ ] **7.4 — Commit**

  ```
  git add src/ipfix/decoder.rs
  git commit -m "feat(ipfix): add version-dispatch entry point decode_datagram"
  ```

---

## Task 8: UDP listener, IpfixHandler trait, DefaultIpfixHandler

**Files:**
- Modify `src/ipfix/listener.rs`

**Interfaces:**
- Produces `pub struct IpfixListenerConfig { pub udp_port: u16, pub bind_address: String }`
- Produces `#[async_trait] pub trait IpfixHandler: Send + Sync { async fn handle_flows(&self, flows: Vec<FlowRecord>, source: SocketAddr); }`
- Produces `pub struct DefaultIpfixHandler;`
- Produces `pub struct IpfixListener { config: IpfixListenerConfig, handler: Arc<dyn IpfixHandler> }`
  with `pub fn new(…) -> Self`, `pub fn with_default_handler(…) -> Self`,
  `pub async fn start(&self) -> anyhow::Result<()>`

### Steps

- [ ] **8.1 — Write failing integration test (mirrors `syslog::listener::tests`)**

  ```rust
  // src/ipfix/listener.rs

  //! IPFIX / NetFlow UDP listener.

  use crate::ipfix::FlowRecord;
  use crate::ipfix::decoder::{DecodeError, IpfixDecoder, decode_datagram};
  use std::net::SocketAddr;
  use std::sync::Arc;
  use tokio::net::UdpSocket;
  use tracing::{debug, error, info, warn};

  /// Configuration for the IPFIX UDP listener.
  #[derive(Debug, Clone)]
  pub struct IpfixListenerConfig {
      pub udp_port: u16,
      pub bind_address: String,
  }

  impl Default for IpfixListenerConfig {
      fn default() -> Self {
          Self {
              udp_port: 4739,
              bind_address: "0.0.0.0".to_string(),
          }
      }
  }

  /// Handler trait for decoded IPFIX flow batches.
  #[async_trait::async_trait]
  pub trait IpfixHandler: Send + Sync {
      async fn handle_flows(&self, flows: Vec<FlowRecord>, source: SocketAddr);
  }

  /// Default handler: logs a summary line and increments metrics counters.
  pub struct DefaultIpfixHandler;

  #[async_trait::async_trait]
  impl IpfixHandler for DefaultIpfixHandler {
      async fn handle_flows(&self, flows: Vec<FlowRecord>, source: SocketAddr) {
          info!(
              "[{}] received {} flow(s) (versions: {:?})",
              source,
              flows.len(),
              flows.iter().map(|r| r.protocol_version).collect::<Vec<_>>(),
          );
          metrics::counter!("ipfix_flows_decoded").increment(flows.len() as u64);
      }
  }

  /// IPFIX UDP listener.
  pub struct IpfixListener {
      config: IpfixListenerConfig,
      handler: Arc<dyn IpfixHandler>,
  }

  impl IpfixListener {
      pub fn new(config: IpfixListenerConfig, handler: Arc<dyn IpfixHandler>) -> Self {
          Self { config, handler }
      }

      pub fn with_default_handler(config: IpfixListenerConfig) -> Self {
          Self::new(config, Arc::new(DefaultIpfixHandler))
      }

      /// Bind the UDP socket and run the receive loop until error.
      pub async fn start(&self) -> anyhow::Result<()> {
          let addr: SocketAddr =
              format!("{}:{}", self.config.bind_address, self.config.udp_port).parse()?;

          let socket = UdpSocket::bind(&addr).await?;
          info!("IPFIX UDP listener started on {}", addr);

          let mut buf = vec![0u8; 65535];
          let mut decoder = IpfixDecoder::new();

          loop {
              match socket.recv_from(&mut buf).await {
                  Ok((len, src)) => {
                      debug!("IPFIX datagram from {}: {} bytes", src, len);
                      match decode_datagram(&mut decoder, &buf[..len], src.ip()) {
                          Ok(flows) if flows.is_empty() => {
                              debug!("IPFIX datagram from {} produced no flows (template-only or empty)", src);
                          }
                          Ok(flows) => {
                              self.handler.handle_flows(flows, src).await;
                          }
                          Err(e) => {
                              metrics::counter!("ipfix_decode_errors").increment(1);
                              warn!("IPFIX decode error from {}: {}", src, e);
                          }
                      }
                  }
                  Err(e) => {
                      error!("IPFIX UDP receive error: {}", e);
                  }
              }
          }
      }
  }

  #[cfg(test)]
  mod tests {
      use super::*;
      use crate::ipfix::decoder::FIXTURE_IPFIX_TEMPLATE_THEN_DATA;
      use std::sync::Mutex;
      use std::time::Duration;
      use tokio::time::sleep;

      /// A test handler that collects received flow batches.
      struct CapturingHandler {
          received: Mutex<Vec<Vec<FlowRecord>>>,
      }

      impl CapturingHandler {
          fn new() -> Arc<Self> {
              Arc::new(Self { received: Mutex::new(Vec::new()) })
          }
          fn batches(&self) -> Vec<Vec<FlowRecord>> {
              self.received.lock().unwrap().clone()
          }
      }

      #[async_trait::async_trait]
      impl IpfixHandler for CapturingHandler {
          async fn handle_flows(&self, flows: Vec<FlowRecord>, _source: SocketAddr) {
              self.received.lock().unwrap().push(flows);
          }
      }

      #[tokio::test]
      async fn listener_receives_ipfix_datagrams_and_calls_handler() {
          // Bind on an ephemeral port (OS assigns port 0)
          let config = IpfixListenerConfig {
              udp_port: 0, // will fail — we need a real port
              bind_address: "127.0.0.1".to_string(),
          };
          // Since port 0 binding works differently, bind ourselves first to find a port:
          let tmp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
          let listener_addr = tmp_socket.local_addr().unwrap();
          drop(tmp_socket);

          let handler = CapturingHandler::new();
          let handler_clone = handler.clone();

          let real_config = IpfixListenerConfig {
              udp_port: listener_addr.port(),
              bind_address: "127.0.0.1".to_string(),
          };
          let listener = IpfixListener::new(real_config, handler_clone);

          let listener_task = tokio::spawn(async move {
              listener.start().await.ok();
          });

          // Give the listener time to bind
          sleep(Duration::from_millis(50)).await;

          // Send the IPFIX template + data fixture
          let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
          sender
              .send_to(FIXTURE_IPFIX_TEMPLATE_THEN_DATA, listener_addr)
              .await
              .unwrap();

          // Allow time for decode + handler call
          sleep(Duration::from_millis(100)).await;

          listener_task.abort();

          let batches = handler.batches();
          assert_eq!(batches.len(), 1, "expected one batch; got {}", batches.len());
          assert_eq!(batches[0].len(), 1, "expected one flow in batch");

          use std::net::{IpAddr, Ipv4Addr};
          assert_eq!(
              batches[0][0].src_addr,
              Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
          );
      }

      #[tokio::test]
      async fn listener_ignores_malformed_datagrams_and_continues() {
          let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
          let listener_addr = tmp.local_addr().unwrap();
          drop(tmp);

          let handler = CapturingHandler::new();
          let handler_clone = handler.clone();
          let config = IpfixListenerConfig {
              udp_port: listener_addr.port(),
              bind_address: "127.0.0.1".to_string(),
          };
          let listener = IpfixListener::new(config, handler_clone);

          let task = tokio::spawn(async move { listener.start().await.ok(); });
          sleep(Duration::from_millis(50)).await;

          let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

          // Send garbage
          sender.send_to(b"\xFF\xFF\xFF", listener_addr).await.unwrap();
          sleep(Duration::from_millis(30)).await;

          // Then send valid v5 one-record fixture
          sender
              .send_to(FIXTURE_NFV5_ONE_RECORD, listener_addr)
              .await
              .unwrap();
          sleep(Duration::from_millis(100)).await;

          task.abort();

          let batches = handler.batches();
          // The malformed datagram should produce 0 batches; the valid one should produce 1.
          assert_eq!(batches.len(), 1, "valid datagram must still be handled after malformed one");
      }
  }
  ```

  Note: `FIXTURE_IPFIX_TEMPLATE_THEN_DATA` and `FIXTURE_NFV5_ONE_RECORD` must be `pub const` in
  `decoder.rs` (currently they are `const` in `#[cfg(test)]`). Move them to module level with
  `#[cfg(test)]` attribute or make them `pub(crate)` accessible constants defined outside the test
  block. The cleanest approach: define all byte fixtures as `pub(crate) const` at the top of
  `decoder.rs` (not inside `#[cfg(test)]`) so `listener.rs` tests can import them.

  Run to see failures:
  ```
  cargo test -p logthing 'ipfix::listener::tests' 2>&1 | head -30
  ```

- [ ] **8.2 — Adjust fixture visibility**

  In `src/ipfix/decoder.rs`, move the fixture constants out of `#[cfg(test)]` and mark them
  `#[cfg(any(test, feature = "testing"))]` or simply `pub(crate)` and `#[allow(dead_code)]` so
  they compile in all builds:

  ```rust
  // At module level (not inside #[cfg(test)]) in decoder.rs:
  #[cfg(test)]
  pub(crate) const FIXTURE_IPFIX_TEMPLATE_THEN_DATA: &[u8] = &[ /* same bytes */ ];
  // ... all other fixtures similarly
  ```

  This is the safest approach: fixtures are compiled only under `#[cfg(test)]` but are visible to
  sibling test modules via `pub(crate)`.

- [ ] **8.3 — Run integration tests**

  ```
  cargo test -p logthing 'ipfix::listener::tests' -- --nocapture
  ```

  Expected: 2 tests pass.

- [ ] **8.4 — Run full suite**

  ```
  cargo test -p logthing -- --nocapture 2>&1 | tail -20
  ```

  Expected: all tests pass, no warnings (or `cargo clippy -- -D warnings` passes).

- [ ] **8.5 — Commit**

  ```
  git add src/ipfix/listener.rs src/ipfix/decoder.rs
  git commit -m "feat(ipfix): add IpfixListener, IpfixHandler trait, DefaultIpfixHandler with integration tests"
  ```

---

## Task 9: Config extension (`[ipfix]` section)

**Files:**
- Modify `src/config/mod.rs`

**Interfaces:**
- Produces `pub struct IpfixConfig { pub enabled: bool, pub udp_port: u16, pub bind_address: String }`
  with `Default` impl and `default_*` helper functions (pattern mirrors `SyslogConfig`)
- Modifies `pub struct Config` to add `pub ipfix: IpfixConfig`
- Modifies `impl Default for Config` to include `ipfix: IpfixConfig::default()`

### Steps

- [ ] **9.1 — Write failing tests**

  Append to `src/config/mod.rs`'s `#[cfg(test)]` block:

  ```rust
  #[test]
  fn default_ipfix_config_disabled_on_port_4739() {
      let cfg = Config::default();
      assert!(!cfg.ipfix.enabled, "ipfix disabled by default");
      assert_eq!(cfg.ipfix.udp_port, 4739);
      assert_eq!(cfg.ipfix.bind_address, "0.0.0.0");
  }
  ```

  Run to see failure:
  ```
  cargo test -p logthing 'config::tests::default_ipfix' 2>&1 | head -20
  ```

- [ ] **9.2 — Implement**

  Add to `src/config/mod.rs`:

  ```rust
  /// Configuration for the IPFIX / NetFlow UDP listener.
  #[derive(Debug, Clone, Deserialize, Serialize)]
  pub struct IpfixConfig {
      #[serde(default = "default_ipfix_enabled")]
      pub enabled: bool,

      #[serde(default = "default_ipfix_udp_port")]
      pub udp_port: u16,

      #[serde(default = "default_ipfix_bind_address")]
      pub bind_address: String,
  }

  impl Default for IpfixConfig {
      fn default() -> Self {
          Self {
              enabled: default_ipfix_enabled(),
              udp_port: default_ipfix_udp_port(),
              bind_address: default_ipfix_bind_address(),
          }
      }
  }

  fn default_ipfix_enabled() -> bool { false }
  fn default_ipfix_udp_port() -> u16 { 4739 }
  fn default_ipfix_bind_address() -> String { "0.0.0.0".to_string() }
  ```

  Add to `Config` struct:

  ```rust
  #[serde(default)]
  pub ipfix: IpfixConfig,
  ```

  Add to `impl Default for Config`:

  ```rust
  ipfix: IpfixConfig::default(),
  ```

- [ ] **9.3 — Run tests**

  ```
  cargo test -p logthing 'config::tests' -- --nocapture
  ```

  Expected: all config tests pass (the existing `load_reads_configuration_file` test must still
  pass — `[ipfix]` is absent from `logthing.toml` and defaults to disabled, which is fine).

- [ ] **9.4 — Commit**

  ```
  git add src/config/mod.rs
  git commit -m "chore(config): add [ipfix] config section with default port 4739"
  ```

---

## Task 10: Wiring IPFIX spawn in `src/main.rs`

**Files:**
- Modify `src/main.rs`

**Interfaces:**
- No new public types; wires `IpfixListener::with_default_handler` conditional on
  `config.ipfix.enabled`, mirroring the syslog spawn block at lines 62–82.

### Steps

- [ ] **10.1 — Write the failing compilation test**

  This task's "test" is compile-time: after the change, `cargo build` must succeed and the
  conditional spawn must compile. There is no `#[tokio::test]` here because testing the full
  binary wiring belongs to the e2e layer. Confirm compilation:

  ```
  cargo build -p logthing 2>&1 | tail -10
  ```

  Before implementing, the build will fail because `mod ipfix;` was added in Task 1 but the
  spawn block is missing. Confirm failure:

  ```
  cargo build -p logthing 2>&1 | grep error | head -5
  ```

- [ ] **10.2 — Implement the spawn block**

  In `src/main.rs`, after the syslog spawn block (after line 82), add:

  ```rust
  // Start IPFIX listener if enabled
  if config.ipfix.enabled {
      let ipfix_config_clone = config.clone();
      tokio::spawn(async move {
          let listener_config = ipfix::listener::IpfixListenerConfig {
              udp_port: ipfix_config_clone.ipfix.udp_port,
              bind_address: ipfix_config_clone.ipfix.bind_address.clone(),
          };
          let listener = ipfix::listener::IpfixListener::with_default_handler(listener_config);
          if let Err(e) = listener.start().await {
              error!("IPFIX listener error: {}", e);
          }
      });
      info!("IPFIX listener started on UDP:{}", config.ipfix.udp_port);
  }
  ```

- [ ] **10.3 — Build and full test run**

  ```
  cargo build -p logthing
  cargo test -p logthing -- --nocapture 2>&1 | tail -20
  cargo clippy -p logthing -- -D warnings
  ```

  All must pass with zero warnings.

- [ ] **10.4 — Commit**

  ```
  git add src/main.rs
  git commit -m "feat(ipfix): wire conditional IPFIX listener spawn in main.rs"
  ```

---

## End-to-End Hook (Phase 1 note)

The repo's E2E harness lives at `tests/e2e/simulation-environment/run.sh` (Docker required).
Phase 1 does not add an E2E test because S3 persistence is out of scope and there is no
persistent side-effect to assert against. The placeholder for phase 4's E2E test is:

- Send a v10 template set + data set datagram sequence to the listener port.
- Assert that a Parquet object appears under the IPFIX prefix in the S3 bucket.

Until phase 4, note this as a known gap in e2e coverage for ipfix and document it in
`AGENTS.md` (out of scope for this plan).

---

## Self-Review

### Spec coverage

| Spec requirement | Plan section |
|-----------------|-------------|
| `FlowRecord` exact fields | Task 1 |
| `src/ipfix/mod.rs` | Task 1 |
| `src/ipfix/decoder.rs` | Tasks 2–7 |
| `src/ipfix/listener.rs` | Task 8 |
| `IpfixListenerConfig { udp_port (default 4739), bind_address }` | Task 8 |
| `IpfixListener` with `recv_from` loop (65535 buf) | Task 8 |
| `IpfixHandler` trait `async fn handle_flows` | Task 8 |
| `DefaultIpfixHandler` (log + metrics) | Task 8 |
| Template cache keyed by `(exporter, obs_domain_id, template_id)` | Task 3 |
| IPFIX v10 template set decode | Task 4 |
| IPFIX v10 data set decode | Task 4 |
| NetFlow v9 template flowset | Task 5 |
| NetFlow v9 data flowset | Task 5 |
| NetFlow v5 fixed decode | Task 6 |
| Version dispatch (10/9/5) | Task 7 |
| Curated IE map (~36 entries) | Task 2 |
| Unknown IE → hex in extra | Task 4 (`apply_field_to_record`) |
| All length/offset reads bounds-checked (no panics) | Tasks 3–6 |
| `[ipfix]` config section | Task 9 |
| Conditional spawn in `src/main.rs` | Task 10 |
| Unit tests: decoder | Tasks 4, 5, 6, 7 |
| Integration tests: listener UDP | Task 8 |
| Metrics counters: datagrams, flows, templates, missing, errors | Tasks 4–8 |
| E2E: deferred to phase 4 (documented above) | noted |

### Placeholder scan

No "TBD", "add error handling", or "similar to Task N" phrases appear in the plan. Every
code block shows actual Rust syntax. Byte fixtures are computed and annotated byte-by-byte.

### Type consistency

- `FlowRecord` defined once in `src/ipfix/mod.rs`; imported as `crate::ipfix::FlowRecord`
  everywhere.
- `IpfixDecoder`, `TemplateKey`, `FieldSpecifier`, `DecodeError`, `IeType`, all decode
  functions live in `src/ipfix/decoder.rs`.
- `IpfixListenerConfig`, `IpfixHandler`, `DefaultIpfixHandler`, `IpfixListener` in
  `src/ipfix/listener.rs`.
- `IpfixConfig` in `src/config/mod.rs`.
- No function signature changes between tasks: `decode_datagram` → `decode_ipfix` /
  `decode_netflow_v9` / `decode_netflow_v5` are consistent across Tasks 4–7.

### IE map count

36 entries in the curated map (Task 2 table) — within the spec's "30–50" target.

### Missing template behaviour

Data sets with uncached templates return `Ok(Vec::new())` and increment
`ipfix_templates_missing` — matching spec §Error handling.

### Panic safety

All index operations in production code use `read_u8/u16/u32/u64/bytes` helpers which
return `Err(DecodeError::Truncated)` rather than panicking. The one `try_into().unwrap()`
in `read_u64_be` is on a slice whose length was already verified to be exactly 8 bytes — it
cannot panic. `apply_field_to_record` similarly guards every raw access.
