//! FreeRADIUS sub-parser.
//!
//! Handles:
//!   `Login OK: [user] (from client <nas> port <n> [cli <ip>])`
//!   `Login incorrect [(<method>)]: [user] (from client <nas> port <n> [cli <ip>])`

use crate::syslog::SyslogMessage;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// Login OK line.
/// Groups: (username, client, port, client_ip?)
static RADIUS_OK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^Login OK:\s+\[([^\]]+)\]\s+\(from client\s+(\S+)\s+port\s+(\S+)(?:\s+cli\s+(\S+))?\)",
    )
    .unwrap()
});

/// Login incorrect line (with optional auth method in parens).
/// Groups: (method?, username, client, port, client_ip?)
static RADIUS_FAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^Login incorrect(?:\s+\(([^)]+)\))?:\s+\[([^\]]+)\]\s+\(from client\s+(\S+)\s+port\s+(\S+)(?:\s+cli\s+(\S+))?\)",
    )
    .unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusRecord {
    /// `"ok"` or `"fail"`
    pub outcome: String,
    pub username: Option<String>,
    pub method: Option<String>,
    pub client: Option<String>,
    pub port: Option<String>,
    pub client_ip: Option<String>,
}

pub fn try_parse(msg: &SyslogMessage) -> Option<RadiusRecord> {
    let m = &msg.message;

    if let Some(caps) = RADIUS_OK_RE.captures(m) {
        return Some(RadiusRecord {
            outcome:   "ok".to_string(),
            username:  caps.get(1).map(|m| m.as_str().to_string()),
            method:    None,
            client:    caps.get(2).map(|m| m.as_str().to_string()),
            port:      caps.get(3).map(|m| m.as_str().to_string()),
            client_ip: caps.get(4).map(|m| m.as_str().to_string()),
        });
    }

    if let Some(caps) = RADIUS_FAIL_RE.captures(m) {
        return Some(RadiusRecord {
            outcome:   "fail".to_string(),
            method:    caps.get(1).map(|m| m.as_str().to_string()),
            username:  caps.get(2).map(|m| m.as_str().to_string()),
            client:    caps.get(3).map(|m| m.as_str().to_string()),
            port:      caps.get(4).map(|m| m.as_str().to_string()),
            client_ip: caps.get(5).map(|m| m.as_str().to_string()),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::{SyslogMessage, SyslogProtocol};

    fn msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 85, severity: 5, facility: 10,
            timestamp: None, hostname: Some("radius-server".into()),
            app_name: Some("radiusd".into()),
            proc_id: None, msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    const LOGIN_OK: &str =
        "Login OK: [alice] (from client vpn port 10 cli 10.0.0.5)";
    const LOGIN_OK_NO_CLI: &str =
        "Login OK: [bob] (from client corp port 2)";
    const LOGIN_FAIL: &str =
        "Login incorrect (PAP): [charlie] (from client vpn port 10 cli 10.0.0.7)";
    const LOGIN_FAIL_SIMPLE: &str =
        "Login incorrect: [dave] (from client corp port 5)";
    const NOT_RADIUS: &str =
        "DHCPACK on 10.0.0.5 to aa:bb:cc:dd:ee:ff via eth0";

    #[test]
    fn parses_login_ok() {
        let rec = try_parse(&msg(LOGIN_OK)).expect("must parse");
        assert_eq!(rec.outcome, "ok");
        assert_eq!(rec.username.as_deref(), Some("alice"));
        assert_eq!(rec.client.as_deref(), Some("vpn"));
        assert_eq!(rec.port.as_deref(), Some("10"));
        assert_eq!(rec.client_ip.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn parses_login_ok_without_cli() {
        let rec = try_parse(&msg(LOGIN_OK_NO_CLI)).expect("must parse");
        assert_eq!(rec.outcome, "ok");
        assert_eq!(rec.username.as_deref(), Some("bob"));
        assert!(rec.client_ip.is_none());
    }

    #[test]
    fn parses_login_incorrect_with_method() {
        let rec = try_parse(&msg(LOGIN_FAIL)).expect("must parse");
        assert_eq!(rec.outcome, "fail");
        assert_eq!(rec.username.as_deref(), Some("charlie"));
        assert_eq!(rec.method.as_deref(), Some("PAP"));
    }

    #[test]
    fn parses_login_incorrect_without_method() {
        let rec = try_parse(&msg(LOGIN_FAIL_SIMPLE)).expect("must parse");
        assert_eq!(rec.outcome, "fail");
        assert_eq!(rec.username.as_deref(), Some("dave"));
        assert!(rec.method.is_none());
    }

    #[test]
    fn rejects_non_radius_message() {
        assert!(try_parse(&msg(NOT_RADIUS)).is_none());
    }
}
