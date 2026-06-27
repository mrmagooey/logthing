//! ISC DHCP sub-parser.
//!
//! Handles: DHCPACK, DHCPOFFER, DHCPREQUEST, DHCPDISCOVER, DHCPRELEASE, DHCPNAK.

use crate::syslog::SyslogMessage;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// DHCPACK / DHCPOFFER / DHCPNAK — "on/to" pattern with optional hostname + interface.
/// Groups: (type, ip, mac, hostname?, interface?)
static DHCP_ON_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(DHCPACK|DHCPOFFER|DHCPNAK)\s+on\s+(\S+)\s+to\s+([\da-fA-F:]+)(?:\s+\(([^)]+)\))?(?:\s+via\s+(\S+))?",
    )
    .unwrap()
});

/// DHCPREQUEST / DHCPRELEASE — "for/of ... from" pattern.
/// Groups: (type, ip, mac, hostname?, interface?)
static DHCP_FROM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(DHCPREQUEST|DHCPRELEASE)\s+(?:for|of)\s+(\S+)\s+from\s+([\da-fA-F:]+)(?:\s+\(([^)]+)\))?(?:\s+via\s+(\S+))?",
    )
    .unwrap()
});

/// DHCPDISCOVER — "from <mac>" with no IP.
/// Groups: (mac, hostname?, interface?)
static DHCP_DISCOVER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^DHCPDISCOVER\s+from\s+([\da-fA-F:]+)(?:\s+\(([^)]+)\))?(?:\s+via\s+(\S+))?",
    )
    .unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpRecord {
    pub message_type: String,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub interface: Option<String>,
}

pub fn try_parse(msg: &SyslogMessage) -> Option<DhcpRecord> {
    let m = &msg.message;

    if let Some(caps) = DHCP_ON_RE.captures(m) {
        return Some(DhcpRecord {
            message_type: caps.get(1)?.as_str().to_string(),
            ip_address:   Some(caps.get(2)?.as_str().to_string()),
            mac_address:  Some(caps.get(3)?.as_str().to_string()),
            hostname:     caps.get(4).map(|m| m.as_str().to_string()),
            interface:    caps.get(5).map(|m| m.as_str().to_string()),
        });
    }

    if let Some(caps) = DHCP_FROM_RE.captures(m) {
        return Some(DhcpRecord {
            message_type: caps.get(1)?.as_str().to_string(),
            ip_address:   Some(caps.get(2)?.as_str().to_string()),
            mac_address:  Some(caps.get(3)?.as_str().to_string()),
            hostname:     caps.get(4).map(|m| m.as_str().to_string()),
            interface:    caps.get(5).map(|m| m.as_str().to_string()),
        });
    }

    if let Some(caps) = DHCP_DISCOVER_RE.captures(m) {
        return Some(DhcpRecord {
            message_type: "DHCPDISCOVER".to_string(),
            ip_address:   None,
            mac_address:  Some(caps.get(1)?.as_str().to_string()),
            hostname:     caps.get(2).map(|m| m.as_str().to_string()),
            interface:    caps.get(3).map(|m| m.as_str().to_string()),
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
            priority: 30, severity: 6, facility: 3,
            timestamp: None, hostname: Some("dhcp-server".into()),
            app_name: Some("dhcpd".into()),
            proc_id: None, msg_id: None,
            message: text.to_string(),
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        }
    }

    const DHCPACK: &str =
        "DHCPACK on 10.0.0.5 to aa:bb:cc:dd:ee:ff (myhost) via eth0";
    const DHCPOFFER: &str =
        "DHCPOFFER on 10.0.0.100 to cc:dd:ee:ff:00:11 via eth1";
    const DHCPREQUEST: &str =
        "DHCPREQUEST for 10.0.0.5 from aa:bb:cc:dd:ee:ff (myhost) via eth0";
    const DHCPDISCOVER: &str =
        "DHCPDISCOVER from aa:bb:cc:dd:ee:ff (myhost) via eth0";
    const DHCPRELEASE: &str =
        "DHCPRELEASE of 10.0.0.5 from aa:bb:cc:dd:ee:ff (myhost) via eth0";
    const DHCPNAK: &str =
        "DHCPNAK on 10.0.0.5 to aa:bb:cc:dd:ee:ff";
    const NOT_DHCP: &str =
        "Login OK: [alice] (from client vpn port 10)";

    #[test]
    fn parses_dhcpack() {
        let rec = try_parse(&msg(DHCPACK)).expect("must parse");
        assert_eq!(rec.message_type, "DHCPACK");
        assert_eq!(rec.ip_address.as_deref(), Some("10.0.0.5"));
        assert_eq!(rec.mac_address.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(rec.hostname.as_deref(), Some("myhost"));
        assert_eq!(rec.interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn parses_dhcpoffer_without_hostname() {
        let rec = try_parse(&msg(DHCPOFFER)).expect("must parse");
        assert_eq!(rec.message_type, "DHCPOFFER");
        assert_eq!(rec.ip_address.as_deref(), Some("10.0.0.100"));
        assert!(rec.hostname.is_none());
    }

    #[test]
    fn parses_dhcprequest() {
        let rec = try_parse(&msg(DHCPREQUEST)).expect("must parse");
        assert_eq!(rec.message_type, "DHCPREQUEST");
        assert_eq!(rec.ip_address.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn parses_dhcpdiscover() {
        let rec = try_parse(&msg(DHCPDISCOVER)).expect("must parse");
        assert_eq!(rec.message_type, "DHCPDISCOVER");
        assert!(rec.ip_address.is_none());
        assert_eq!(rec.mac_address.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn parses_dhcprelease() {
        let rec = try_parse(&msg(DHCPRELEASE)).expect("must parse");
        assert_eq!(rec.message_type, "DHCPRELEASE");
        assert_eq!(rec.ip_address.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn parses_dhcpnak_without_hostname_or_interface() {
        let rec = try_parse(&msg(DHCPNAK)).expect("must parse");
        assert_eq!(rec.message_type, "DHCPNAK");
        assert_eq!(rec.ip_address.as_deref(), Some("10.0.0.5"));
        assert!(rec.interface.is_none());
    }

    #[test]
    fn rejects_non_dhcp_message() {
        assert!(try_parse(&msg(NOT_DHCP)).is_none());
    }
}
