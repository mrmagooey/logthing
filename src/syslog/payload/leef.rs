// src/syslog/payload/leef.rs
//! LEEF (Log Event Extended Format) sub-parser.
//!
//! LEEF 1.0:  `LEEF:1.0|Vendor|Product|Version|EventID|<tab-separated k=v>`
//! LEEF 2.0:  `LEEF:2.0|Vendor|Product|Version|EventID|<delim>|<delim-separated k=v>`
//!             where `<delim>` is a one-char literal (e.g. `|`) or a hex escape
//!             (`0x7C` = `|`; `0x09` = `\t`).  If the delimiter field is empty
//!             or absent the default delimiter is `\t`.

use crate::syslog::SyslogMessage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeefRecord {
    pub leef_version: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub event_id: String,
    /// Present only for LEEF 2.0 that includes the delimiter field.
    pub delimiter: Option<char>,
    pub attributes: HashMap<String, String>,
}

/// Decode the LEEF 2.0 delimiter field.
/// Accepts: `0x<HH>` hex notation, a single literal character, or empty → `\t`.
fn decode_delimiter(s: &str) -> char {
    let s = s.trim();
    if s.is_empty() || s == "\\t" || s == "\t" {
        return '\t';
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
        && let Ok(n) = u8::from_str_radix(hex, 16)
    {
        return n as char;
    }
    s.chars().next().unwrap_or('\t')
}

/// Parse `k=v` pairs separated by `delim`.
fn parse_attributes(pairs: &str, delim: char) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in pairs.split(delim) {
        if let Some(eq) = pair.find('=') {
            let key = pair[..eq].trim().to_string();
            let val = pair[eq + 1..].to_string();
            if !key.is_empty() {
                map.insert(key, val);
            }
        }
    }
    map
}

pub fn try_parse(msg: &SyslogMessage) -> Option<LeefRecord> {
    let m = &msg.message;
    if !m.starts_with("LEEF:") {
        return None;
    }
    let rest = &m["LEEF:".len()..];

    // Split on '|' to extract the fixed header fields.
    // splitn(7) gives at most 7 parts; the 7th part contains all remaining content
    // (including any embedded '|' delimiters in the attribute blob).
    let mut parts = rest.splitn(7, '|');
    let leef_version = parts.next()?.to_string();
    let vendor       = parts.next()?.to_string();
    let product      = parts.next()?.to_string();
    let version      = parts.next()?.to_string();
    let event_id     = parts.next()?.to_string();

    // seg6 is the 6th pipe-segment:
    //   LEEF 1.0 → the entire tab-separated attribute blob
    //   LEEF 2.0 pipe delimiter → just the delimiter field (e.g. "0x7C")
    //   LEEF 2.0 non-pipe delimiter → delimiter_char + attribute blob (e.g. "\tsrc=…\tdst=…")
    let seg6 = parts.next().unwrap_or("");

    let (delimiter, attributes) = if leef_version == "2.0" {
        // Try to consume a 7th segment. When the LEEF 2.0 delimiter is '|', the
        // fixed-field separator already split delimiter-field from the pairs blob, so
        // splitn puts the pairs blob in seg7. When the delimiter is not '|' (e.g. '\t'),
        // no additional pipe exists and everything after the 5th '|' is in seg6.
        if let Some(pairs_blob) = parts.next() {
            // seg6 = delimiter field only; seg7 = attribute pairs
            let delim = decode_delimiter(seg6);
            let attrs = parse_attributes(pairs_blob, delim);
            (Some(delim), attrs)
        } else if seg6.is_empty() {
            // Empty delimiter field, no pairs → default tab delimiter.
            (Some('\t'), HashMap::new())
        } else if seg6.starts_with("0x") || seg6.starts_with("0X") {
            // Hex delimiter spec (e.g. "0x7C") with no trailing pipe and no pairs blob.
            // Decode the hex; attributes are empty.
            (Some(decode_delimiter(seg6)), HashMap::new())
        } else {
            // Literal first-char delimiter convention: the first char of seg6 IS the
            // delimiter and the rest of seg6 is the attribute pairs blob
            // (e.g. "\tsrc=…\tdst=…").
            let delim = seg6.chars().next().unwrap_or('\t');
            let pairs_blob = &seg6[delim.len_utf8()..];
            let attrs = parse_attributes(pairs_blob, delim);
            (Some(delim), attrs)
        }
    } else {
        // LEEF 1.0: seg6 is the entire attribute blob, tab-delimited.
        let attrs = parse_attributes(seg6, '\t');
        (None, attrs)
    };

    Some(LeefRecord {
        leef_version,
        vendor,
        product,
        version,
        event_id,
        delimiter,
        attributes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};

    fn msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 14, severity: 6, facility: 1,
            timestamp: None, hostname: Some("qradar".into()),
            app_name: None, proc_id: None, msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    // LEEF 1.0: no delimiter field; pairs separated by \t (tab).
    const LEEF_1_0: &str =
        "LEEF:1.0|Vendor|Product|1.0|LoginSuccess|src=192.168.1.10\tdst=10.0.0.1\tusrName=bob";

    // LEEF 2.0: delimiter field (0x7C = '|') after EventID.
    const LEEF_2_0: &str =
        "LEEF:2.0|Vendor|Product|2.0|EventID|0x7C|src=192.168.1.10|dst=10.0.0.1|usrName=alice";

    // LEEF 2.0 with tab delimiter (default when field is absent or 0x09).
    const LEEF_2_0_TAB: &str =
        "LEEF:2.0|Vendor|Product|2.0|EventID|\tsrc=192.168.1.10\tdst=10.0.0.1";

    const NOT_LEEF: &str = "CEF:0|Vendor|Product|1.0|100|Name|5|";

    #[test]
    fn parses_leef_1_0_with_tab_delimiter() {
        let rec = try_parse(&msg(LEEF_1_0)).expect("must parse");
        assert_eq!(rec.leef_version, "1.0");
        assert_eq!(rec.vendor, "Vendor");
        assert_eq!(rec.product, "Product");
        assert_eq!(rec.version, "1.0");
        assert_eq!(rec.event_id, "LoginSuccess");
        assert_eq!(rec.attributes.get("src").map(|s| s.as_str()), Some("192.168.1.10"));
        assert_eq!(rec.attributes.get("usrName").map(|s| s.as_str()), Some("bob"));
        assert!(rec.delimiter.is_none(), "LEEF 1.0 has no delimiter field");
    }

    #[test]
    fn parses_leef_2_0_with_pipe_delimiter() {
        let rec = try_parse(&msg(LEEF_2_0)).expect("must parse");
        assert_eq!(rec.leef_version, "2.0");
        assert_eq!(rec.event_id, "EventID");
        assert_eq!(rec.delimiter, Some('|'));
        assert_eq!(rec.attributes.get("dst").map(|s| s.as_str()), Some("10.0.0.1"));
        assert_eq!(rec.attributes.get("usrName").map(|s| s.as_str()), Some("alice"));
    }

    #[test]
    fn parses_leef_2_0_tab_delimiter_field() {
        let rec = try_parse(&msg(LEEF_2_0_TAB)).expect("must parse");
        assert_eq!(rec.leef_version, "2.0");
        // delimiter field is "\t" → '\t'
        assert_eq!(rec.delimiter, Some('\t'));
        assert_eq!(rec.attributes.get("src").map(|s| s.as_str()), Some("192.168.1.10"));
    }

    #[test]
    fn parses_leef_2_0_hex_delimiter_no_pairs() {
        // Regression: hex delimiter spec with no trailing pipe and no pairs blob.
        // Must decode "0x7C" → '|', not naively take the first char '0'.
        let rec = try_parse(&msg("LEEF:2.0|V|P|v|ID|0x7C")).expect("must parse");
        assert_eq!(rec.leef_version, "2.0");
        assert_eq!(rec.event_id, "ID");
        assert_eq!(rec.delimiter, Some('|'));
        assert!(rec.attributes.is_empty());
    }

    #[test]
    fn rejects_cef_prefix() {
        assert!(try_parse(&msg(NOT_LEEF)).is_none());
    }

    #[test]
    fn rejects_truncated_leef() {
        // Only 3 pipe fields
        assert!(try_parse(&msg("LEEF:1.0|Vendor|Product")).is_none());
    }
}
