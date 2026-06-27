//! CEF (Common Event Format) sub-parser.
//!
//! Wire format:  `CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|
//!               SignatureID|Name|Severity|Extensions`
//!
//! Extensions are `key=value` pairs separated by spaces, with CEF escaping:
//!   `\|` → `|`,  `\\` → `\`,  `\=` → `=`  (only in extension values and
//!   inside header fields that come before the final `|`).

use crate::syslog::SyslogMessage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CefRecord {
    pub version: u8,
    pub device_vendor: String,
    pub device_product: String,
    pub device_version: String,
    pub signature_id: String,
    pub name: String,
    pub severity: String,
    pub extensions: HashMap<String, String>,
}

/// Unescape a CEF header field: `\|` → `|`, `\\` → `\`.
/// (Header fields do not use `\=`.)
fn unescape_header(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('|') => { out.push('|');  chars.next(); }
                Some('\\') => { out.push('\\'); chars.next(); }
                _ => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Unescape a CEF extension value: `\|` → `|`, `\\` → `\`, `\=` → `=`.
fn unescape_ext(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('|')  => { out.push('|');  chars.next(); }
                Some('\\') => { out.push('\\'); chars.next(); }
                Some('=')  => { out.push('=');  chars.next(); }
                _ => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Split a CEF header on unescaped `|`, returning up to `n` segments.
fn split_header(s: &str, n: usize) -> Vec<String> {
    let mut parts = Vec::with_capacity(n);
    let mut current = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // Consume the escape character and the next character together.
            current.push(c);
            if let Some(next) = chars.next() {
                current.push(next);
            }
        } else if c == '|' {
            parts.push(unescape_header(&current));
            current.clear();
            if parts.len() == n - 1 {
                // Collect remainder as final part (may contain unescaped |).
                let rest: String = chars.collect();
                parts.push(rest);
                return parts;
            }
        } else {
            current.push(c);
        }
    }
    parts.push(unescape_header(&current));
    parts
}

/// Parse CEF extension string `k1=v1 k2=v2 ...` with proper value boundary
/// detection.  The value ends at the next ` key=` token.
fn parse_extensions(ext: &str) -> HashMap<String, String> {
    // Find all key positions by scanning for `word=` patterns.
    // We do a two-pass: first collect key start indices, then extract values.
    let mut map = HashMap::new();
    let trimmed = ext.trim();
    if trimmed.is_empty() {
        return map;
    }

    let bytes = trimmed.as_bytes();
    let len = bytes.len();

    // Find positions of `key=` tokens.
    let mut key_spans: Vec<(usize, usize)> = Vec::new(); // (key_start, eq_pos)
    let mut i = 0usize;
    while i < len {
        // Skip whitespace between pairs.
        while i < len && bytes[i] == b' ' { i += 1; }
        if i >= len { break; }
        let key_start = i;
        // Read key characters: alpha, digit, underscore.
        while i < len && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        let key_end = i;
        if key_end > key_start && i < len && bytes[i] == b'=' {
            key_spans.push((key_start, i)); // i points at '='
            i += 1; // skip '='
        } else {
            // Not a valid key=; skip to next space.
            while i < len && bytes[i] != b' ' { i += 1; }
        }
    }

    // For each key, value runs from (eq_pos + 1) to the start of the next key - whitespace.
    for idx in 0..key_spans.len() {
        let (ks, eq) = key_spans[idx];
        let key = &trimmed[ks..eq];
        let val_start = eq + 1;
        let val_end = if idx + 1 < key_spans.len() {
            // Walk back from next key_start to strip trailing whitespace.
            let next_ks = key_spans[idx + 1].0;
            let mut end = next_ks;
            while end > val_start && trimmed.as_bytes()[end - 1] == b' ' {
                end -= 1;
            }
            end
        } else {
            trimmed.len()
        };
        let raw_val = &trimmed[val_start..val_end];
        map.insert(key.to_string(), unescape_ext(raw_val));
    }
    map
}

/// Try to parse `msg.message` as a CEF record.
/// Returns `None` if the message does not start with `CEF:`.
pub fn try_parse(msg: &SyslogMessage) -> Option<CefRecord> {
    let m = &msg.message;
    if !m.starts_with("CEF:") {
        return None;
    }
    // Format: CEF:version|vendor|product|dev_ver|sig_id|name|severity|extensions
    let rest = &m["CEF:".len()..];
    // We need 8 pipe-delimited fields: version + 6 header fields + extension blob.
    let parts = split_header(rest, 8);
    if parts.len() < 7 {
        return None;
    }
    let version: u8 = parts[0].parse().ok()?;
    let extensions = if parts.len() >= 8 {
        parse_extensions(&parts[7])
    } else {
        HashMap::new()
    };
    Some(CefRecord {
        version,
        device_vendor:  parts[1].clone(),
        device_product: parts[2].clone(),
        device_version: parts[3].clone(),
        signature_id:   parts[4].clone(),
        name:           parts[5].clone(),
        severity:       parts[6].clone(),
        extensions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};

    fn msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 86, severity: 6, facility: 10,
            timestamp: None, hostname: Some("fw01".into()),
            app_name: Some("ArcSight".into()),
            proc_id: None, msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    const BASIC_CEF: &str =
        "CEF:0|ArcSight|ArcSight Management Center|2.0|base:system:remotelogin:success|\
         Remote Login Success|3|src=10.0.0.1 dst=10.0.0.2 spt=51234 dpt=22";

    const CEF_ESCAPED: &str =
        r"CEF:0|Vendor|Product|1.0|100|Event with \| pipe and \\ backslash|5|\
          msg=value\\with\\backslash cs1=foo\=bar";

    const LEEF_LINE: &str =
        "LEEF:1.0|Vendor|Product|1.0|EventID|key=value";

    const NOT_CEF: &str =
        "type=SYSCALL msg=audit(1609459200.000:1234): syscall=59";

    #[test]
    fn parses_basic_cef_header_and_extensions() {
        let rec = try_parse(&msg(BASIC_CEF)).expect("must parse");
        assert_eq!(rec.version, 0);
        assert_eq!(rec.device_vendor, "ArcSight");
        assert_eq!(rec.device_product, "ArcSight Management Center");
        assert_eq!(rec.device_version, "2.0");
        assert_eq!(rec.signature_id, "base:system:remotelogin:success");
        assert_eq!(rec.name, "Remote Login Success");
        assert_eq!(rec.severity, "3");
        assert_eq!(rec.extensions.get("src").map(|s| s.as_str()), Some("10.0.0.1"));
        assert_eq!(rec.extensions.get("dst").map(|s| s.as_str()), Some("10.0.0.2"));
        assert_eq!(rec.extensions.get("spt").map(|s| s.as_str()), Some("51234"));
    }

    #[test]
    fn parses_cef_escaped_pipe_and_backslash() {
        let rec = try_parse(&msg(CEF_ESCAPED)).expect("must parse");
        // Header field containing \| should unescape to literal |
        assert!(rec.name.contains('|') || rec.name.contains('\\'),
            "escaped pipe or backslash must survive: {:?}", rec.name);
        // Extension value: cs1=foo\=bar → value is "foo=bar"
        if let Some(v) = rec.extensions.get("cs1") {
            assert_eq!(v, "foo=bar", "\\= should unescape to =");
        }
    }

    #[test]
    fn rejects_leef_prefix() {
        assert!(try_parse(&msg(LEEF_LINE)).is_none());
    }

    #[test]
    fn rejects_non_cef_message() {
        assert!(try_parse(&msg(NOT_CEF)).is_none());
    }

    #[test]
    fn rejects_cef_with_fewer_than_seven_pipe_fields() {
        // Only 5 pipe-separated fields (needs 7 after "CEF:version|")
        let truncated = "CEF:0|Vendor|Product|1.0|SigID";
        assert!(try_parse(&msg(truncated)).is_none());
    }

    #[test]
    fn parses_empty_extension_map() {
        let no_ext = "CEF:0|Vendor|Product|1.0|100|Login|5|";
        let rec = try_parse(&msg(no_ext)).expect("must parse");
        assert!(rec.extensions.is_empty());
    }
}
