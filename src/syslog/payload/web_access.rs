// src/syslog/payload/web_access.rs
//! Apache / Nginx Combined Log Format sub-parser.
//!
//! Pattern:  `host ident authuser [date] "method path proto" status bytes "referer" "ua"`

use crate::syslog::SyslogMessage;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static COMBINED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)""#,
    )
    .unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAccessRecord {
    pub client_ip: String,
    pub ident: Option<String>,
    pub authuser: Option<String>,
    pub timestamp_str: String,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub status: u16,
    pub bytes: Option<u64>,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
}

/// Convert `-` to `None`.
fn opt_hyphen(s: &str) -> Option<String> {
    if s == "-" { None } else { Some(s.to_string()) }
}

pub fn try_parse(msg: &SyslogMessage) -> Option<WebAccessRecord> {
    let caps = COMBINED_RE.captures(&msg.message)?;
    let client_ip     = caps.get(1)?.as_str().to_string();
    // ident preserves the raw value (including "-") as Some — it is an
    // RFC 1413 identifier token, not an optional absent marker.
    let ident         = caps.get(2).map(|m| m.as_str().to_string());
    let authuser      = caps.get(3).and_then(|m| opt_hyphen(m.as_str()));
    let timestamp_str = caps.get(4)?.as_str().to_string();
    let method        = caps.get(5)?.as_str().to_string();
    let path          = caps.get(6)?.as_str().to_string();
    let protocol      = caps.get(7)?.as_str().to_string();
    let status: u16   = caps.get(8)?.as_str().parse().ok()?;
    let bytes         = caps.get(9).and_then(|m| {
        let s = m.as_str();
        if s == "-" { None } else { s.parse().ok() }
    });
    let referer       = caps.get(10).and_then(|m| opt_hyphen(m.as_str()));
    let user_agent    = caps.get(11).and_then(|m| opt_hyphen(m.as_str()));

    Some(WebAccessRecord {
        client_ip,
        ident,
        authuser,
        timestamp_str,
        method,
        path,
        protocol,
        status,
        bytes,
        referer,
        user_agent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};

    fn msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 134, severity: 6, facility: 16,
            timestamp: None, hostname: Some("web01".into()),
            app_name: Some("nginx".into()),
            proc_id: None, msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    // Apache/Nginx combined log format.
    const COMBINED: &str = r#"192.168.1.100 - bob [15/Jan/2024:10:30:45 +0000] "GET /api/v1/users HTTP/1.1" 200 4523 "https://example.com/page" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36""#;

    // Hyphen for ident and authuser fields.
    const ANON: &str = r#"10.0.0.1 - - [15/Jan/2024:10:31:00 +0000] "POST /login HTTP/1.1" 302 0 "-" "curl/7.68.0""#;

    // 404 response.
    const NOT_FOUND: &str = r#"172.16.0.5 - - [15/Jan/2024:10:32:15 +0000] "GET /missing HTTP/2.0" 404 162 "-" "-""#;

    const NOT_WEB: &str = "type=SYSCALL msg=audit(1609459200.000:1): syscall=59";

    #[test]
    fn parses_combined_log_with_auth_user() {
        let rec = try_parse(&msg(COMBINED)).expect("must parse");
        assert_eq!(rec.client_ip, "192.168.1.100");
        assert_eq!(rec.ident, Some("-".into()));
        assert_eq!(rec.authuser, Some("bob".into()));
        assert_eq!(rec.method, "GET");
        assert_eq!(rec.path, "/api/v1/users");
        assert_eq!(rec.protocol, "HTTP/1.1");
        assert_eq!(rec.status, 200);
        assert_eq!(rec.bytes, Some(4523));
        assert_eq!(rec.referer.as_deref(), Some("https://example.com/page"));
        assert!(rec.user_agent.as_deref().unwrap().starts_with("Mozilla"));
    }

    #[test]
    fn parses_anonymous_request_with_hyphens() {
        let rec = try_parse(&msg(ANON)).expect("must parse");
        assert_eq!(rec.client_ip, "10.0.0.1");
        assert_eq!(rec.authuser, None);
        assert_eq!(rec.method, "POST");
        assert_eq!(rec.status, 302);
        assert_eq!(rec.bytes, Some(0));
        assert_eq!(rec.referer, None);
    }

    #[test]
    fn parses_404_response() {
        let rec = try_parse(&msg(NOT_FOUND)).expect("must parse");
        assert_eq!(rec.status, 404);
        assert_eq!(rec.path, "/missing");
    }

    #[test]
    fn rejects_non_web_message() {
        assert!(try_parse(&msg(NOT_WEB)).is_none());
    }

    #[test]
    fn hyphen_referer_becomes_none() {
        let rec = try_parse(&msg(ANON)).expect("must parse");
        assert!(rec.referer.is_none(), "'-' referer must become None");
    }

    #[test]
    fn hyphen_user_agent_becomes_none() {
        let rec = try_parse(&msg(NOT_FOUND)).expect("must parse");
        assert!(rec.user_agent.is_none(), "'-' user agent must become None");
    }
}
