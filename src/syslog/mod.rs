//! Syslog message parser supporting RFC 3164 (BSD syslog) and RFC 5424 formats

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Parsed syslog message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogMessage {
    pub priority: u8,
    pub severity: u8,
    pub facility: u8,
    pub timestamp: Option<DateTime<Utc>>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub proc_id: Option<String>,
    pub msg_id: Option<String>,
    pub message: String,
    pub structured_data: Option<HashMap<String, HashMap<String, String>>>,
    pub protocol: SyslogProtocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyslogProtocol {
    Rfc3164,
    Rfc5424,
    Unknown,
}

/// Syslog severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Informational = 6,
    Debug = 7,
}

impl Severity {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Severity::Emergency),
            1 => Some(Severity::Alert),
            2 => Some(Severity::Critical),
            3 => Some(Severity::Error),
            4 => Some(Severity::Warning),
            5 => Some(Severity::Notice),
            6 => Some(Severity::Informational),
            7 => Some(Severity::Debug),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Emergency => "EMERGENCY",
            Severity::Alert => "ALERT",
            Severity::Critical => "CRITICAL",
            Severity::Error => "ERROR",
            Severity::Warning => "WARNING",
            Severity::Notice => "NOTICE",
            Severity::Informational => "INFO",
            Severity::Debug => "DEBUG",
        }
    }
}

/// Syslog facilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Facility {
    Kernel = 0,
    User = 1,
    Mail = 2,
    System = 3,
    Security = 4,
    Syslog = 5,
    LinePrinter = 6,
    News = 7,
    Uucp = 8,
    Clock = 9,
    Authpriv = 10,
    Ftp = 11,
    Ntp = 12,
    Audit = 13,
    Alert = 14,
    Clock2 = 15,
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

impl Facility {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Facility::Kernel),
            1 => Some(Facility::User),
            2 => Some(Facility::Mail),
            3 => Some(Facility::System),
            4 => Some(Facility::Security),
            5 => Some(Facility::Syslog),
            6 => Some(Facility::LinePrinter),
            7 => Some(Facility::News),
            8 => Some(Facility::Uucp),
            9 => Some(Facility::Clock),
            10 => Some(Facility::Authpriv),
            11 => Some(Facility::Ftp),
            12 => Some(Facility::Ntp),
            13 => Some(Facility::Audit),
            14 => Some(Facility::Alert),
            15 => Some(Facility::Clock2),
            16 => Some(Facility::Local0),
            17 => Some(Facility::Local1),
            18 => Some(Facility::Local2),
            19 => Some(Facility::Local3),
            20 => Some(Facility::Local4),
            21 => Some(Facility::Local5),
            22 => Some(Facility::Local6),
            23 => Some(Facility::Local7),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Facility::Kernel => "kernel",
            Facility::User => "user",
            Facility::Mail => "mail",
            Facility::System => "system",
            Facility::Security => "security",
            Facility::Syslog => "syslog",
            Facility::LinePrinter => "lp",
            Facility::News => "news",
            Facility::Uucp => "uucp",
            Facility::Clock => "clock",
            Facility::Authpriv => "authpriv",
            Facility::Ftp => "ftp",
            Facility::Ntp => "ntp",
            Facility::Audit => "audit",
            Facility::Alert => "alert",
            Facility::Clock2 => "clock2",
            Facility::Local0 => "local0",
            Facility::Local1 => "local1",
            Facility::Local2 => "local2",
            Facility::Local3 => "local3",
            Facility::Local4 => "local4",
            Facility::Local5 => "local5",
            Facility::Local6 => "local6",
            Facility::Local7 => "local7",
        }
    }
}

impl SyslogMessage {
    /// Parse a syslog message (auto-detects RFC 3164 or RFC 5424)
    pub fn parse(input: &str) -> Option<Self> {
        // Try RFC 5424 first (starts with version number after priority)
        if let Some(msg) = Self::parse_rfc5424(input) {
            return Some(msg);
        }

        // Fall back to RFC 3164
        Self::parse_rfc3164(input)
    }

    /// Parse RFC 5424 formatted syslog message
    fn parse_rfc5424(input: &str) -> Option<Self> {
        // RFC 5424 format: <priority>version timestamp hostname app-name procid msgid [structured-data] msg
        // Example: <34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 [example@32473 iut="3"] 'su root' failed

        let re = Regex::new(r"^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*?)$")
            .ok()?;

        let caps = re.captures(input)?;

        let priority: u8 = caps.get(1)?.as_str().parse().ok()?;
        let severity = priority & 0x07;
        let facility = (priority >> 3) & 0x1f;

        let timestamp_str = caps.get(3)?.as_str();
        let timestamp = DateTime::parse_from_rfc3339(timestamp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .ok();

        let hostname = caps.get(4).and_then(|m| {
            let s = m.as_str();
            if s == "-" { None } else { Some(s.to_string()) }
        });

        let app_name = caps.get(5).and_then(|m| {
            let s = m.as_str();
            if s == "-" { None } else { Some(s.to_string()) }
        });

        let proc_id = caps.get(6).and_then(|m| {
            let s = m.as_str();
            if s == "-" { None } else { Some(s.to_string()) }
        });

        let msg_id = caps.get(7).and_then(|m| {
            let s = m.as_str();
            if s == "-" { None } else { Some(s.to_string()) }
        });

        let rest = caps.get(8)?.as_str();

        // Parse structured data and message
        let (structured_data, message) = Self::parse_structured_data(rest);

        Some(SyslogMessage {
            priority,
            severity,
            facility,
            timestamp,
            hostname,
            app_name,
            proc_id,
            msg_id,
            message,
            structured_data,
            protocol: SyslogProtocol::Rfc5424,
        })
    }

    /// Parse RFC 3164 (BSD syslog) formatted message
    fn parse_rfc3164(input: &str) -> Option<Self> {
        // RFC 3164 format: <priority>timestamp hostname tag[pid]: message
        // Example: <34>Oct 11 22:14:15 mymachine su: 'su root' failed

        let re =
            Regex::new(r"^<(\d{1,3})>([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*?)$")
                .ok()?;

        let caps = re.captures(input)?;

        let priority: u8 = caps.get(1)?.as_str().parse().ok()?;
        let severity = priority & 0x07;
        let facility = (priority >> 3) & 0x1f;

        let timestamp_str = caps.get(2)?.as_str();
        let timestamp = Self::parse_rfc3164_timestamp(timestamp_str);

        let hostname = Some(caps.get(3)?.as_str().to_string());

        let rest = caps.get(4)?.as_str();

        // Parse tag and message
        let (app_name, proc_id, message) = Self::parse_rfc3164_tag(rest);

        Some(SyslogMessage {
            priority,
            severity,
            facility,
            timestamp,
            hostname,
            app_name,
            proc_id,
            msg_id: None,
            message,
            structured_data: None,
            protocol: SyslogProtocol::Rfc3164,
        })
    }

    /// Parse RFC 3164 timestamp (assumes current year)
    fn parse_rfc3164_timestamp(ts_str: &str) -> Option<DateTime<Utc>> {
        // RFC 3164 uses: "Oct 11 22:14:15" format (no year)
        let re = Regex::new(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$").ok()?;
        let caps = re.captures(ts_str)?;

        let month_str = caps.get(1)?.as_str();
        let day: u32 = caps.get(2)?.as_str().parse().ok()?;
        let hour: u32 = caps.get(3)?.as_str().parse().ok()?;
        let minute: u32 = caps.get(4)?.as_str().parse().ok()?;
        let second: u32 = caps.get(5)?.as_str().parse().ok()?;

        let month = match month_str.to_lowercase().as_str() {
            "jan" => 1,
            "feb" => 2,
            "mar" => 3,
            "apr" => 4,
            "may" => 5,
            "jun" => 6,
            "jul" => 7,
            "aug" => 8,
            "sep" => 9,
            "oct" => 10,
            "nov" => 11,
            "dec" => 12,
            _ => return None,
        };

        // Assume current year
        let year = Utc::now().year();
        let naive_date = NaiveDate::from_ymd_opt(year, month, day)?;
        let naive_datetime = naive_date.and_hms_opt(hour, minute, second)?;

        Some(DateTime::from_naive_utc_and_offset(naive_datetime, Utc))
    }

    /// Parse RFC 3164 tag and extract app_name, proc_id, and message
    fn parse_rfc3164_tag(rest: &str) -> (Option<String>, Option<String>, String) {
        // Tag format: "tag[pid]: " or "tag: "
        let re = Regex::new(r"^([^:\[]+)(?:\[(\d+)\])?:\s*(.*)$").unwrap();

        if let Some(caps) = re.captures(rest) {
            let app_name = Some(caps.get(1).unwrap().as_str().to_string());
            let proc_id = caps.get(2).map(|m| m.as_str().to_string());
            let message = caps.get(3).unwrap().as_str().to_string();
            (app_name, proc_id, message)
        } else {
            (None, None, rest.to_string())
        }
    }

    /// Parse structured data from RFC 5424
    fn parse_structured_data(
        rest: &str,
    ) -> (Option<HashMap<String, HashMap<String, String>>>, String) {
        let mut structured_data = HashMap::new();
        let mut remaining = rest;

        // Check if it starts with structured data
        if rest.starts_with('[') {
            // Extract SD elements
            let sd_re = Regex::new(r"\[([^\]]+)\]").unwrap();
            let mut last_end = 0;

            for cap in sd_re.captures_iter(rest) {
                let sd_element = cap.get(1).unwrap().as_str();
                let sd_id: String;
                let mut params = HashMap::new();

                // Parse SD-ID and parameters
                let parts: Vec<&str> = sd_element.split_whitespace().collect();
                if !parts.is_empty() {
                    sd_id = parts[0].to_string();

                    // Parse param="value" pairs
                    let param_re = Regex::new(r#"(\S+)="([^"]*)""#).unwrap();
                    for param_cap in param_re.captures_iter(sd_element) {
                        let key = param_cap.get(1).unwrap().as_str().to_string();
                        let value = param_cap.get(2).unwrap().as_str().to_string();
                        params.insert(key, value);
                    }

                    structured_data.insert(sd_id, params);
                    last_end = cap.get(0).unwrap().end();
                }
            }

            remaining = rest[last_end..].trim_start();
        }

        let message = if remaining.starts_with("\u{feff}") {
            // Strip BOM if present
            remaining[3..].to_string()
        } else {
            remaining.to_string()
        };

        if structured_data.is_empty() {
            (None, message)
        } else {
            (Some(structured_data), message)
        }
    }

    /// Get severity as enum
    pub fn severity(&self) -> Option<Severity> {
        Severity::from_u8(self.severity)
    }

    /// Get facility as enum
    pub fn facility(&self) -> Option<Facility> {
        Facility::from_u8(self.facility)
    }

    /// Get severity as string
    pub fn severity_str(&self) -> String {
        self.severity()
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|| format!("UNKNOWN({})", self.severity))
    }

    /// Get facility as string
    pub fn facility_str(&self) -> String {
        self.facility()
            .map(|f| f.as_str().to_string())
            .unwrap_or_else(|| format!("UNKNOWN({})", self.facility))
    }
}

/// Syslog listener module for UDP and TCP
pub mod listener;

/// Parse DNS syslog records
pub mod dns {
    use super::*;

    /// DNS query log entry
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DnsLogEntry {
        pub timestamp: DateTime<Utc>,
        pub client_ip: String,
        pub query_name: String,
        pub query_type: String,
        pub response_code: String,
        pub response_ips: Vec<String>,
        pub duration_ms: Option<f64>,
    }

    /// Parse common DNS syslog formats
    impl DnsLogEntry {
        /// Parse BIND/named DNS query log format
        /// Example: client 192.168.1.100#12345: query: example.com IN A + (192.168.1.1)
        pub fn from_bind_format(message: &str) -> Option<Self> {
            let re = Regex::new(
                r"client\s+(\d+\.\d+\.\d+\.\d+)#\d+:\s+query:\s+(\S+)\s+(\S+)\s+(\S+)\s+.*\((\d+\.\d+\.\d+\.\d+)\)"
            ).ok()?;

            let caps = re.captures(message)?;

            Some(DnsLogEntry {
                timestamp: Utc::now(),
                client_ip: caps.get(1)?.as_str().to_string(),
                query_name: caps.get(2)?.as_str().to_string(),
                query_type: caps.get(4)?.as_str().to_string(),
                response_code: "NOERROR".to_string(),
                response_ips: vec![caps.get(5)?.as_str().to_string()],
                duration_ms: None,
            })
        }

        /// Parse Unbound DNS log format
        /// Example: info: 192.168.1.100 example.com. A IN
        pub fn from_unbound_format(message: &str) -> Option<Self> {
            let re = Regex::new(r"info:\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\S+)").ok()?;

            let caps = re.captures(message)?;

            Some(DnsLogEntry {
                timestamp: Utc::now(),
                client_ip: caps.get(1)?.as_str().to_string(),
                query_name: caps.get(2)?.as_str().trim_end_matches('.').to_string(),
                query_type: caps.get(3)?.as_str().to_string(),
                response_code: "NOERROR".to_string(),
                response_ips: vec![],
                duration_ms: None,
            })
        }

        /// Parse PowerDNS log format
        /// Example: Remote 192.168.1.100 wants 'example.com|A', do = 0, bufsize = 512
        pub fn from_powerdns_format(message: &str) -> Option<Self> {
            let re =
                Regex::new(r"Remote\s+(\d+\.\d+\.\d+\.\d+)\s+wants\s+'([^|]+)\|([^']+)'").ok()?;

            let caps = re.captures(message)?;

            Some(DnsLogEntry {
                timestamp: Utc::now(),
                client_ip: caps.get(1)?.as_str().to_string(),
                query_name: caps.get(2)?.as_str().to_string(),
                query_type: caps.get(3)?.as_str().to_string(),
                response_code: "NOERROR".to_string(),
                response_ips: vec![],
                duration_ms: None,
            })
        }

        /// Parse from syslog message (auto-detect format)
        pub fn from_syslog(syslog: &SyslogMessage) -> Option<Self> {
            let msg = &syslog.message;

            // Try BIND format first
            if let Some(entry) = Self::from_bind_format(msg) {
                return Some(entry);
            }

            // Try Unbound format
            if let Some(entry) = Self::from_unbound_format(msg) {
                return Some(entry);
            }

            // Try PowerDNS format
            if let Some(entry) = Self::from_powerdns_format(msg) {
                return Some(entry);
            }

            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rfc3164() {
        let msg = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
        let parsed = SyslogMessage::parse(msg).unwrap();

        assert_eq!(parsed.priority, 34);
        assert_eq!(parsed.severity, 2); // Critical
        assert_eq!(parsed.facility, 4); // Security
        assert_eq!(parsed.hostname, Some("mymachine".to_string()));
        assert_eq!(parsed.app_name, Some("su".to_string()));
        assert!(parsed.message.contains("'su root' failed"));
        assert!(matches!(parsed.protocol, SyslogProtocol::Rfc3164));
    }

    #[test]
    fn test_parse_rfc5424() {
        let msg = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick";
        let parsed = SyslogMessage::parse(msg).unwrap();

        assert_eq!(parsed.priority, 34);
        assert_eq!(parsed.severity, 2);
        assert_eq!(parsed.facility, 4);
        assert_eq!(parsed.hostname, Some("mymachine.example.com".to_string()));
        assert_eq!(parsed.app_name, Some("su".to_string()));
        assert!(parsed.message.contains("'su root' failed"));
        assert!(matches!(parsed.protocol, SyslogProtocol::Rfc5424));
    }

    #[test]
    fn test_parse_rfc5424_with_structured_data() {
        let msg = r#"<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - [example@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry"#;
        let parsed = SyslogMessage::parse(msg).unwrap();

        assert_eq!(parsed.priority, 165);
        assert!(parsed.structured_data.is_some());
        let sd = parsed.structured_data.unwrap();
        assert!(sd.contains_key("example@32473"));
        let params = sd.get("example@32473").unwrap();
        assert_eq!(params.get("iut"), Some(&"3".to_string()));
        assert_eq!(params.get("eventID"), Some(&"1011".to_string()));
    }

    #[test]
    fn test_dns_bind_format() {
        let msg = "client 192.168.1.100#12345: query: example.com IN A + (192.168.1.1)";
        let entry = dns::DnsLogEntry::from_bind_format(msg).unwrap();

        assert_eq!(entry.client_ip, "192.168.1.100");
        assert_eq!(entry.query_name, "example.com");
        assert_eq!(entry.query_type, "A");
        assert_eq!(entry.response_ips, vec!["192.168.1.1"]);
    }

    #[test]
    fn test_dns_unbound_format() {
        let msg = "info: 192.168.1.100 example.com. A IN";
        let entry = dns::DnsLogEntry::from_unbound_format(msg).unwrap();

        assert_eq!(entry.client_ip, "192.168.1.100");
        assert_eq!(entry.query_name, "example.com");
        assert_eq!(entry.query_type, "A");
    }

    #[test]
    fn test_dns_powerdns_format() {
        let msg = "Remote 192.168.1.100 wants 'example.com|A', do = 0, bufsize = 512";
        let entry = dns::DnsLogEntry::from_powerdns_format(msg).unwrap();

        assert_eq!(entry.client_ip, "192.168.1.100");
        assert_eq!(entry.query_name, "example.com");
        assert_eq!(entry.query_type, "A");
    }

    #[test]
    fn test_full_dns_syslog() {
        // Example: BIND DNS query logged via syslog
        let syslog_msg = "<134>Jan 15 10:30:45 dns-server named[1234]: client 192.168.1.100#12345: query: example.com IN A + (93.184.216.34)";
        let syslog = SyslogMessage::parse(syslog_msg).unwrap();
        let dns = dns::DnsLogEntry::from_syslog(&syslog).unwrap();

        assert_eq!(dns.client_ip, "192.168.1.100");
        assert_eq!(dns.query_name, "example.com");
        assert_eq!(dns.query_type, "A");
        assert_eq!(dns.response_ips, vec!["93.184.216.34"]);
    }
}
