// src/syslog/payload/auditd.rs
//! Linux auditd sub-parser (single-record; no multi-line reassembly).
//!
//! Expects:  `type=<TYPE> msg=audit(<epoch.ms>:<serial>): k=v k="v" ...`

use crate::syslog::SyslogMessage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

/// Match:  `type=<TYPE> msg=audit(<id>):`
static AUDITD_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^type=(\S+)\s+msg=audit\(([^)]+)\):\s*").unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditdRecord {
    pub record_type: String,
    pub audit_id: String,
    pub fields: HashMap<String, String>,
}

/// Parse `k=v k="v" ...` pairs from an auditd body.
/// Values may be bare words or double-quoted strings.
fn parse_kv_pairs(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let bytes = body.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    while i < len {
        // Skip spaces.
        while i < len && bytes[i] == b' ' { i += 1; }
        if i >= len { break; }

        // Read key.
        let key_start = i;
        while i < len && bytes[i] != b'=' && bytes[i] != b' ' { i += 1; }
        if i >= len || bytes[i] != b'=' { break; }
        let key = body[key_start..i].to_string();
        i += 1; // skip '='

        if i >= len { map.insert(key, String::new()); break; }

        // Read value: quoted or unquoted.
        let val = if bytes[i] == b'"' {
            i += 1; // skip opening quote
            let val_start = i;
            while i < len && bytes[i] != b'"' { i += 1; }
            let v = body[val_start..i].to_string();
            if i < len { i += 1; } // skip closing quote
            v
        } else {
            let val_start = i;
            while i < len && bytes[i] != b' ' { i += 1; }
            body[val_start..i].to_string()
        };
        map.insert(key, val);
    }
    map
}

pub fn try_parse(msg: &SyslogMessage) -> Option<AuditdRecord> {
    let m = &msg.message;
    let caps = AUDITD_HEADER_RE.captures(m)?;
    let record_type = caps.get(1)?.as_str().to_string();
    let audit_id    = caps.get(2)?.as_str().to_string();
    let body_start  = caps.get(0)?.end();
    let body        = &m[body_start..];
    let fields      = parse_kv_pairs(body);
    Some(AuditdRecord { record_type, audit_id, fields })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};

    fn msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 80, severity: 0, facility: 10,
            timestamp: None, hostname: Some("server".into()),
            app_name: Some("kernel".into()),
            proc_id: None, msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    const SYSCALL: &str =
        "type=SYSCALL msg=audit(1609459200.000:1234): arch=c000003e syscall=59 \
         success=yes exit=0 a0=7f1234 a1=0 a2=0 a3=0 items=3 ppid=1000 pid=2000 \
         auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 \
         tty=pts0 ses=42 comm=\"bash\" exe=\"/bin/bash\" key=\"exec\"";

    const LOGIN: &str =
        "type=LOGIN msg=audit(1609459201.000:1235): pid=2001 uid=0 \
         old-auid=4294967295 auid=1001 tty=(none) old-ses=4294967295 ses=43 res=1";

    const PATH_RECORD: &str =
        "type=PATH msg=audit(1609459202.000:1236): item=0 name=\"/bin/bash\" \
         inode=131074 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 \
         nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0";

    const NOT_AUDITD: &str =
        "CEF:0|Vendor|Product|1.0|100|Name|5|";

    const MISSING_MSG_FIELD: &str =
        "type=SYSCALL arch=c000003e syscall=59";

    #[test]
    fn parses_syscall_record() {
        let rec = try_parse(&msg(SYSCALL)).expect("must parse");
        assert_eq!(rec.record_type, "SYSCALL");
        assert_eq!(rec.audit_id, "1609459200.000:1234");
        assert_eq!(rec.fields.get("syscall").map(|s| s.as_str()), Some("59"));
        assert_eq!(rec.fields.get("comm").map(|s| s.as_str()), Some("bash"));
        assert_eq!(rec.fields.get("exe").map(|s| s.as_str()), Some("/bin/bash"));
        assert_eq!(rec.fields.get("key").map(|s| s.as_str()), Some("exec"));
    }

    #[test]
    fn parses_login_record() {
        let rec = try_parse(&msg(LOGIN)).expect("must parse");
        assert_eq!(rec.record_type, "LOGIN");
        assert_eq!(rec.audit_id, "1609459201.000:1235");
        assert_eq!(rec.fields.get("auid").map(|s| s.as_str()), Some("1001"));
        assert_eq!(rec.fields.get("res").map(|s| s.as_str()), Some("1"));
    }

    #[test]
    fn parses_path_record_with_quoted_name() {
        let rec = try_parse(&msg(PATH_RECORD)).expect("must parse");
        assert_eq!(rec.record_type, "PATH");
        assert_eq!(rec.fields.get("name").map(|s| s.as_str()), Some("/bin/bash"));
    }

    #[test]
    fn rejects_non_auditd_message() {
        assert!(try_parse(&msg(NOT_AUDITD)).is_none());
    }

    #[test]
    fn rejects_auditd_without_msg_field() {
        assert!(try_parse(&msg(MISSING_MSG_FIELD)).is_none());
    }
}
