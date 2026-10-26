//! Syslog message parser supporting RFC 3164 (BSD syslog) and RFC 5424 formats

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;

type SdElements = HashMap<String, HashMap<String, String>>;
type StructuredData = Option<SdElements>;

// --- Module-level static regexes (compiled once per process) ---

/// RFC 5424 header: <priority>version timestamp hostname app-name procid msgid [sd] msg
static RFC5424_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*?)$").unwrap()
});

/// RFC 3164 header: <priority>timestamp hostname rest
static RFC3164_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^<(\d{1,3})>([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*?)$").unwrap()
});

/// RFC 3164 header with no `<PRI>` prefix (some devices omit it entirely).
static RFC3164_NOPRI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*?)$").unwrap()
});

/// RFC 3164 timestamp: "Mon DD HH:MM:SS"
static RFC3164_TS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$").unwrap());

/// RFC 3164 tag + pid: "tag[pid]: message" or "tag: message". The tag is a single token:
/// no whitespace, `=` or `(`, so prose or `key=value` text with a later colon is not a tag.
static RFC3164_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([^:\[\s=(]+)(?:\[(\d+)\])?:\s*(.*)$").unwrap());

/// DNS BIND format
static DNS_BIND_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"client\s+(\d+\.\d+\.\d+\.\d+)#\d+:\s+query:\s+(\S+)\s+(\S+)\s+(\S+)\s+.*\((\d+\.\d+\.\d+\.\d+)\)",
    )
    .unwrap()
});

/// DNS Unbound format
static DNS_UNBOUND_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"info:\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\S+)").unwrap());

/// DNS PowerDNS format
static DNS_POWERDNS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Remote\s+(\d+\.\d+\.\d+\.\d+)\s+wants\s+'([^|]+)\|([^']+)'").unwrap()
});

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
    /// Parse a syslog message (auto-detects RFC 3164 or RFC 5424).
    ///
    /// Attempts to parse as RFC 5424 first, then falls back to RFC 3164 (BSD syslog).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use logthing::syslog::SyslogMessage;
    ///
    /// // Parse RFC 3164 format (BSD syslog)
    /// let rfc3164 = "<134>Jan 15 10:30:45 myhost myapp[1234]: Test message";
    /// if let Some(msg) = SyslogMessage::parse(rfc3164) {
    ///     println!("Host: {:?}, Message: {}", msg.hostname, msg.message);
    ///     println!("Severity: {}, Facility: {}", msg.severity, msg.facility);
    /// }
    ///
    /// // Parse RFC 5424 format (modern syslog)
    /// let rfc5424 = "<134>1 2024-01-15T10:30:45.000Z myhost myapp 1234 - - Test message";
    /// if let Some(msg) = SyslogMessage::parse(rfc5424) {
    ///     println!("Protocol: {:?}", msg.protocol);
    /// }
    /// ```
    pub fn parse(input: &str) -> Option<Self> {
        // Every header regex below ends in `(.*?)$`. Rust's regex `.` never
        // crosses `\n`, and unlike some other regex flavors `$` has no
        // trailing-newline exception (it only matches absolute end-of-haystack
        // without multi-line mode) — so an untrimmed line terminator silently
        // fails all three parse attempts. Strip it once, here, for every caller.
        let input = input.strip_suffix('\n').unwrap_or(input);
        let input = input.strip_suffix('\r').unwrap_or(input);

        // Try RFC 5424 first (starts with version number after priority)
        if let Some(msg) = Self::parse_rfc5424(input) {
            return Some(msg);
        }

        // Fall back to RFC 3164
        if let Some(msg) = Self::parse_rfc3164(input) {
            return Some(msg);
        }

        // Some devices (e.g. Ubiquiti UDM CEF/LEEF forwarding) omit <PRI> entirely.
        Self::parse_no_pri(input)
    }

    /// Fallback for messages with no `<PRI>` prefix at all.
    ///
    /// Tried only after both RFC 5424 and RFC 3164 (with PRI) fail. Targeted,
    /// not a catch-all: garbage text must still return `None` here so
    /// `test_parse_invalid_syslog` / `test_parse_empty_message` keep passing.
    ///
    /// Tier 1: RFC-3164-shaped line minus `<PRI>`.
    /// Tier 2: bare recognized payload prefix (CEF/LEEF only — the only two
    /// payload formats in `payload/` that are unambiguous by prefix alone).
    fn parse_no_pri(input: &str) -> Option<Self> {
        // RFC 3164 §4.3.3 default when PRI is missing: facility=user(1), severity=notice(5).
        const DEFAULT_PRIORITY: u8 = (1 << 3) | 5;

        if let Some(caps) = RFC3164_NOPRI_RE.captures(input) {
            let priority = DEFAULT_PRIORITY;
            let severity = priority & 0x07;
            let facility = (priority >> 3) & 0x1f;

            let timestamp_str = caps.get(1)?.as_str();
            let timestamp = Self::parse_rfc3164_timestamp(timestamp_str);

            let hostname = Some(caps.get(2)?.as_str().to_string());

            let rest = caps.get(3)?.as_str();
            let (app_name, proc_id, message) = Self::split_tag_or_payload(rest);

            return Some(SyslogMessage {
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
                protocol: SyslogProtocol::Unknown,
            });
        }

        if input.starts_with("CEF:") || input.starts_with("LEEF:") {
            let priority = DEFAULT_PRIORITY;
            let severity = priority & 0x07;
            let facility = (priority >> 3) & 0x1f;

            return Some(SyslogMessage {
                priority,
                severity,
                facility,
                timestamp: None,
                hostname: None,
                app_name: None,
                proc_id: None,
                msg_id: None,
                message: input.to_string(),
                structured_data: None,
                protocol: SyslogProtocol::Unknown,
            });
        }

        // A `<PRI>` prefix that the 5424/3164 header regexes rejected. Keep the line rather
        // than drop it: a valid PRI is honoured and stripped from the message; a PRI above 191
        // is not valid, so the raw line (prefix included) is kept with the default priority.
        if let Some((digits, body)) = Self::split_pri_prefix(input) {
            let (priority, message) = match Self::parse_pri(digits) {
                Some(p) => (p, body),
                None => (DEFAULT_PRIORITY, input),
            };
            return Some(SyslogMessage {
                priority,
                severity: priority & 0x07,
                facility: (priority >> 3) & 0x1f,
                timestamp: None,
                hostname: None,
                app_name: None,
                proc_id: None,
                msg_id: None,
                message: message.to_string(),
                structured_data: None,
                protocol: SyslogProtocol::Unknown,
            });
        }

        None
    }

    /// Split `<1-3 digits>rest` into the digits and `rest`.
    fn split_pri_prefix(input: &str) -> Option<(&str, &str)> {
        let inner = input.strip_prefix('<')?;
        let digits = inner.bytes().take_while(u8::is_ascii_digit).count();
        if !(1..=3).contains(&digits) {
            return None;
        }
        Some((&inner[..digits], inner[digits..].strip_prefix('>')?))
    }

    /// Parse the `<PRI>` digits; `None` when above 191 (the maximum valid PRI, 23 * 8 + 7).
    fn parse_pri(s: &str) -> Option<u8> {
        s.parse::<u8>().ok().filter(|p| *p <= 191)
    }

    /// Split an RFC 3164 body into tag/pid/message, except that a bare CEF/LEEF payload is
    /// never treated as a tag (some devices, e.g. UDM-style forwarding, send it right after
    /// the hostname).
    fn split_tag_or_payload(rest: &str) -> (Option<String>, Option<String>, String) {
        if rest.starts_with("CEF:") || rest.starts_with("LEEF:") {
            (None, None, rest.to_string())
        } else {
            Self::parse_rfc3164_tag(rest)
        }
    }

    /// Parse RFC 5424 formatted syslog message
    fn parse_rfc5424(input: &str) -> Option<Self> {
        // RFC 5424 format: <priority>version timestamp hostname app-name procid msgid [structured-data] msg
        // Example: <34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 [example@32473 iut="3"] 'su root' failed

        let caps = RFC5424_RE.captures(input)?;

        let priority = Self::parse_pri(caps.get(1)?.as_str())?;
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

        let caps = RFC3164_RE.captures(input)?;

        let priority = Self::parse_pri(caps.get(1)?.as_str())?;
        let severity = priority & 0x07;
        let facility = (priority >> 3) & 0x1f;

        let timestamp_str = caps.get(2)?.as_str();
        let timestamp = Self::parse_rfc3164_timestamp(timestamp_str);

        let hostname = Some(caps.get(3)?.as_str().to_string());

        let rest = caps.get(4)?.as_str();

        let (app_name, proc_id, message) = Self::split_tag_or_payload(rest);

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

    /// Parse an RFC 3164 (BSD syslog) timestamp such as `"Oct 11 22:14:15"`.
    ///
    /// The wire format carries neither a year nor a timezone, so both are
    /// inferred:
    ///
    /// - **Year** — taken from `Utc::now()` at parse time. Parsing happens
    ///   inline as the message is received, so this is effectively receipt
    ///   time. Known limitation: a message parsed after a long buffering
    ///   delay that straddles a year boundary can take the wrong year. Fixing
    ///   that means threading the record's own `received_at` through this
    ///   function and its callers.
    /// - **Timezone** — assumed UTC. There is no sender-timezone handling
    ///   anywhere in this codebase; a sender in another zone will have its
    ///   timestamps offset accordingly.
    ///
    /// RFC 5424 messages are unaffected: they carry a full date and explicit
    /// offset and are parsed unambiguously by `parse_rfc5424`.
    fn parse_rfc3164_timestamp(ts_str: &str) -> Option<DateTime<Utc>> {
        // RFC 3164 uses: "Oct 11 22:14:15" format (no year)
        let caps = RFC3164_TS_RE.captures(ts_str)?;

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
        if let Some(caps) = RFC3164_TAG_RE.captures(rest) {
            let app_name = Some(caps.get(1).unwrap().as_str().to_string());
            let proc_id = caps.get(2).map(|m| m.as_str().to_string());
            let message = caps.get(3).unwrap().as_str().to_string();
            (app_name, proc_id, message)
        } else {
            (None, None, rest.to_string())
        }
    }

    /// Parse structured data from RFC 5424
    fn parse_structured_data(rest: &str) -> (StructuredData, String) {
        let strip_bom = |m: &str| m.strip_prefix('\u{feff}').unwrap_or(m).to_string();

        // NILVALUE: no structured data, the message follows.
        if rest == "-" {
            return (None, String::new());
        }
        if let Some(msg) = rest.strip_prefix("- ") {
            return (None, strip_bom(msg));
        }
        if rest.starts_with('[')
            && let Some((sd, end)) = Self::scan_structured_data(rest)
        {
            return (Some(sd), strip_bom(rest[end..].trim_start()));
        }
        // No SD, or malformed SD: the whole remainder is the message.
        (None, strip_bom(rest))
    }

    /// Scan the adjacent leading `[...]` SD elements of `rest`. Returns the parsed elements
    /// and the byte offset just past the last `]`, or `None` if an element is malformed.
    /// Only ASCII delimiters are inspected, so offsets are always char boundaries.
    fn scan_structured_data(rest: &str) -> Option<(SdElements, usize)> {
        let b = rest.as_bytes();
        let mut sd = HashMap::new();
        let mut pos = 0;
        while b.get(pos) == Some(&b'[') {
            pos += 1;
            let id_start = pos;
            while pos < b.len() && b[pos] != b' ' && b[pos] != b']' {
                pos += 1;
            }
            if pos == id_start || pos >= b.len() {
                return None;
            }
            let mut params = HashMap::new();
            let id = rest[id_start..pos].to_string();
            loop {
                match b.get(pos)? {
                    b']' => {
                        pos += 1;
                        break;
                    }
                    b' ' => pos += 1,
                    _ => {
                        let name_start = pos;
                        while *b.get(pos)? != b'=' {
                            if matches!(b[pos], b' ' | b']') {
                                return None;
                            }
                            pos += 1;
                        }
                        let name = rest[name_start..pos].to_string();
                        pos += 1;
                        let value = Self::scan_param_value(b, &mut pos)?;
                        params.insert(name, value);
                    }
                }
            }
            sd.insert(id, params);
        }
        Some((sd, pos))
    }

    /// Scan a quoted PARAM-VALUE starting at the opening `"` (`*pos`), unescaping `\"`, `\\`
    /// and `\]`. Leaves `*pos` just past the closing quote.
    fn scan_param_value(b: &[u8], pos: &mut usize) -> Option<String> {
        if *b.get(*pos)? != b'"' {
            return None;
        }
        *pos += 1;
        let mut value = Vec::new();
        loop {
            match *b.get(*pos)? {
                b'"' => break,
                b'\\' if matches!(b.get(*pos + 1), Some(b'"' | b'\\' | b']')) => {
                    value.push(b[*pos + 1]);
                    *pos += 2;
                }
                c => {
                    value.push(c);
                    *pos += 1;
                }
            }
        }
        *pos += 1;
        String::from_utf8(value).ok()
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

pub mod payload;

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
            let caps = super::DNS_BIND_RE.captures(message)?;

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
            let caps = super::DNS_UNBOUND_RE.captures(message)?;

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
            let caps = super::DNS_POWERDNS_RE.captures(message)?;

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
mod differential_tests;

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
        assert_eq!(parsed.message, "'su root' failed for lonvick");
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
    fn test_parse_rfc5424_nilvalue_sd_stripped() {
        let m = SyslogMessage::parse(
            "<34>1 2003-10-11T22:14:15.003Z host su - ID47 - 'su root' failed",
        )
        .unwrap();
        assert_eq!(m.message, "'su root' failed");
        assert!(m.structured_data.is_none());
        let m = SyslogMessage::parse("<34>1 2003-10-11T22:14:15.003Z host su - ID47 -").unwrap();
        assert_eq!(m.message, "");
    }

    #[test]
    fn test_parse_rfc5424_sd_stops_at_first_non_bracket() {
        let m =
            SyslogMessage::parse(r#"<1>1 - h a - - [a@1 x="1"] user [admin] logged in"#).unwrap();
        assert_eq!(m.message, "user [admin] logged in");
        let sd = m.structured_data.unwrap();
        assert_eq!(sd.len(), 1);
        assert_eq!(sd["a@1"]["x"], "1");

        let m = SyslogMessage::parse(r#"<1>1 - h a - - [a@1 x="1"][b@2 y="2"]msg"#).unwrap();
        assert_eq!(m.structured_data.unwrap().len(), 2);
        assert_eq!(m.message, "msg");
    }

    #[test]
    fn test_parse_rfc5424_sd_escapes_unescaped() {
        let m = SyslogMessage::parse(r#"<1>1 - h a - - [a@1 x="q\"uote\]d\\"] m"#).unwrap();
        assert_eq!(m.structured_data.unwrap()["a@1"]["x"], r#"q"uote]d\"#);
        assert_eq!(m.message, "m");
    }

    #[test]
    fn test_parse_rfc5424_sd_non_ascii_value() {
        let m = SyslogMessage::parse(r#"<1>1 - h a - - [a@1 x="héllo"] msg"#).unwrap();
        assert_eq!(m.structured_data.unwrap()["a@1"]["x"], "héllo");
        assert_eq!(m.message, "msg");
    }

    #[test]
    fn test_parse_rfc5424_sd_unterminated_is_message() {
        for body in [r#"[a@1 x="1" tail"#, r#"[a@1 x="1"#, "[a@1", "[]"] {
            let m = SyslogMessage::parse(&format!("<1>1 - h a - - {body}")).unwrap();
            assert!(m.structured_data.is_none(), "{body}");
            assert_eq!(m.message, body);
        }
    }

    #[test]
    fn test_parse_rfc3164_cef_payload_not_eaten_as_tag() {
        let m =
            SyslogMessage::parse("<134>Jan 15 10:30:45 host CEF:0|V|P|1|100|Name|5|src=1.2.3.4")
                .unwrap();
        assert_eq!(m.app_name, None);
        assert!(m.message.starts_with("CEF:0|"));
        let rec = crate::syslog::payload::dispatch(&m);
        assert!(matches!(rec, crate::syslog::payload::SyslogPayload::Cef(_)));
    }

    #[test]
    fn test_parse_rfc3164_leef_payload_not_eaten_as_tag() {
        let m = SyslogMessage::parse("<134>Jan 15 10:30:45 host LEEF:1.0|V|P|1|Evt|src=1.2.3.4")
            .unwrap();
        assert_eq!(m.app_name, None);
        assert!(m.message.starts_with("LEEF:1.0|"));
    }

    #[test]
    fn test_parse_rfc3164_auditd_untagged() {
        let line = "type=SYSCALL msg=audit(1609459200.000:1234): arch=c000003e";
        let m = SyslogMessage::parse(&format!("<134>Jan 15 10:30:45 host {line}")).unwrap();
        assert_eq!(m.app_name, None);
        assert_eq!(m.message, line);
        let rec = crate::syslog::payload::dispatch(&m);
        assert!(matches!(
            rec,
            crate::syslog::payload::SyslogPayload::Auditd(_)
        ));
    }

    #[test]
    fn test_parse_rfc3164_colon_in_text_not_tag() {
        let line = "Failed password for root from 1.2.3.4 port 22: x";
        let m = SyslogMessage::parse(&format!("<134>Jan 15 10:30:45 host {line}")).unwrap();
        assert_eq!(m.app_name, None);
        assert_eq!(m.message, line);
    }

    #[test]
    fn test_parse_rfc3164_tag_with_pid_regression() {
        let m = SyslogMessage::parse("<134>Jan 15 10:30:45 host sshd[123]: Accepted").unwrap();
        assert_eq!(m.app_name.as_deref(), Some("sshd"));
        assert_eq!(m.proc_id.as_deref(), Some("123"));
        assert_eq!(m.message, "Accepted");
    }

    #[test]
    fn test_parse_pri_over_191_falls_back() {
        let line = "<200>Jan 15 10:30:45 h msg";
        let m = SyslogMessage::parse(line).unwrap();
        assert_eq!(m.message, line);
        assert_eq!((m.priority, m.facility, m.severity), (13, 1, 5));
        assert!(matches!(m.protocol, SyslogProtocol::Unknown));
        let m = SyslogMessage::parse("<200>1 - h a - - - x").unwrap();
        assert_eq!(m.message, "<200>1 - h a - - - x");
        // 191 is the highest valid PRI.
        let m = SyslogMessage::parse("<191>Jan 15 10:30:45 h msg").unwrap();
        assert_eq!((m.facility, m.severity), (23, 7));
        // Non-PRI garbage still returns None.
        assert!(SyslogMessage::parse("<abc>garbage").is_none());
    }

    #[test]
    fn test_parse_valid_pri_unparsable_header_keeps_real_priority() {
        let m = SyslogMessage::parse("<34>free text").unwrap();
        assert_eq!((m.priority, m.facility, m.severity), (34, 4, 2));
        assert_eq!(m.message, "free text");
        assert!(matches!(m.protocol, SyslogProtocol::Unknown));
        let m = SyslogMessage::parse("<200>x").unwrap();
        assert_eq!(m.priority, 13);
        assert_eq!(m.message, "<200>x");
    }

    #[test]
    fn test_parse_pri_edge_forms() {
        let m = SyslogMessage::parse("<013>free text").unwrap();
        assert_eq!(m.priority, 13);
        assert_eq!(m.message, "free text");
        let m = SyslogMessage::parse("<0>free text").unwrap();
        assert_eq!((m.priority, m.facility, m.severity), (0, 0, 0));
        // Four digits is not a PRI at all: unchanged behaviour, line is not parsed.
        assert!(SyslogMessage::parse("<1000>free text").is_none());
    }

    #[test]
    fn test_parse_rfc5424_sd_malformed_forms_are_message() {
        for body in [
            r#"[a@1 x=1] m"#,
            r#"[a@1 x=v" y="2"] m"#,
            r#"[a@1 x="a\"] m"#,
            r#"[a@1 x="1"][b@2 y=2] m"#,
        ] {
            let m = SyslogMessage::parse(&format!("<1>1 - h a - - {body}")).unwrap();
            assert!(m.structured_data.is_none(), "{body}");
            assert_eq!(m.message, body);
        }
        // An escaped backslash right before the closing quote is a complete value.
        let m = SyslogMessage::parse(r#"<1>1 - h a - - [a@1 x="a\\"] m"#).unwrap();
        assert_eq!(m.structured_data.unwrap()["a@1"]["x"], r"a\");
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

    #[test]
    fn test_parse_invalid_syslog() {
        let result = SyslogMessage::parse("not a valid syslog message");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_empty_message() {
        let result = SyslogMessage::parse("");
        assert!(result.is_none());
    }

    #[test]
    fn test_facility_str() {
        let msg = "<0>Oct 11 22:14:15 mymachine test: message";
        let parsed = SyslogMessage::parse(msg).unwrap();
        assert_eq!(parsed.facility_str(), "kernel");

        // Priority 128 = facility 16 (local0) * 8 + severity 0
        let msg2 = "<128>Oct 11 22:14:15 mymachine test: message";
        let parsed2 = SyslogMessage::parse(msg2).unwrap();
        assert_eq!(parsed2.facility_str(), "local0");
    }

    #[test]
    fn test_severity_str() {
        let msg = "<0>Oct 11 22:14:15 mymachine test: message";
        let parsed = SyslogMessage::parse(msg).unwrap();
        assert_eq!(parsed.severity_str(), "EMERGENCY");

        let msg2 = "<6>Oct 11 22:14:15 mymachine test: message";
        let parsed2 = SyslogMessage::parse(msg2).unwrap();
        assert_eq!(parsed2.severity_str(), "INFO");
    }

    #[test]
    fn test_parse_rfc3164_variants() {
        // With hostname and app
        let msg = "<34>Oct 11 22:14:15 mymachine myapp: test message";
        let parsed = SyslogMessage::parse(msg).unwrap();
        assert_eq!(parsed.hostname, Some("mymachine".to_string()));
        assert_eq!(parsed.app_name, Some("myapp".to_string()));

        // With process ID
        let msg2 = "<34>Oct 11 22:14:15 mymachine myapp[1234]: test message";
        let parsed2 = SyslogMessage::parse(msg2).unwrap();
        assert_eq!(parsed2.app_name, Some("myapp".to_string()));
    }

    #[test]
    fn test_parse_rfc5424_variants() {
        // With msgid and structured data
        let msg = r#"<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 msgid1 [example@32473 iut="3"] An application event"#;
        let parsed = SyslogMessage::parse(msg).unwrap();
        assert_eq!(parsed.msg_id, Some("msgid1".to_string()));

        // Minimal RFC5424
        let msg2 = "<34>1 2003-10-11T22:14:15Z host app - - - message";
        let parsed2 = SyslogMessage::parse(msg2).unwrap();
        assert_eq!(parsed2.hostname, Some("host".to_string()));
    }

    #[test]
    fn test_dns_bind_format_variants() {
        // Standard BIND format - works with the current regex
        let msg = "client 192.168.1.100#12345: query: example.com IN A + (192.168.1.1)";
        let entry = dns::DnsLogEntry::from_bind_format(msg).unwrap();
        assert_eq!(entry.client_ip, "192.168.1.100");
        assert_eq!(entry.response_ips, vec!["192.168.1.1"]);

        // CNAME response with valid IP
        let msg2 = "client 192.168.1.100#12345: query: www.example.com IN CNAME + (93.184.216.34)";
        let entry2 = dns::DnsLogEntry::from_bind_format(msg2).unwrap();
        assert_eq!(entry2.query_type, "CNAME");
    }

    #[test]
    fn test_dns_non_dns_message() {
        let syslog =
            SyslogMessage::parse("<34>Oct 11 22:14:15 mymachine app: regular message without DNS")
                .unwrap();
        let dns = dns::DnsLogEntry::from_syslog(&syslog);
        assert!(dns.is_none());
    }

    #[test]
    fn test_dns_bind_format_invalid() {
        let result = dns::DnsLogEntry::from_bind_format("not a valid bind format");
        assert!(result.is_none());
    }

    #[test]
    fn test_dns_unbound_format_invalid() {
        let result = dns::DnsLogEntry::from_unbound_format("not valid");
        assert!(result.is_none());
    }

    #[test]
    fn test_dns_powerdns_format_invalid() {
        let result = dns::DnsLogEntry::from_powerdns_format("not valid");
        assert!(result.is_none());
    }

    #[test]
    fn test_severity_from_u8() {
        assert_eq!(Severity::from_u8(0), Some(Severity::Emergency));
        assert_eq!(Severity::from_u8(3), Some(Severity::Error));
        assert_eq!(Severity::from_u8(6), Some(Severity::Informational));
        assert_eq!(Severity::from_u8(7), Some(Severity::Debug));
    }

    #[test]
    fn test_facility_from_u8() {
        assert_eq!(Facility::from_u8(0), Some(Facility::Kernel));
        assert_eq!(Facility::from_u8(4), Some(Facility::Security));
        assert_eq!(Facility::from_u8(16), Some(Facility::Local0));
    }

    #[test]
    fn test_parse_no_pri_rfc3164_shaped_cef() {
        let msg = "Jan 15 10:30:45 fw01 arcsight: CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4";
        let parsed = SyslogMessage::parse(msg).unwrap();

        assert_eq!(parsed.priority, 13);
        assert_eq!(parsed.severity, 5);
        assert_eq!(parsed.facility, 1);
        assert!(matches!(parsed.protocol, SyslogProtocol::Unknown));
        assert!(parsed.message.contains("CEF:0|"));
    }

    #[test]
    fn test_parse_no_pri_rfc3164_shaped_cef_no_tag() {
        // Hostname immediately followed by a bare CEF/LEEF payload, with no
        // separate app-tag in between (e.g. UDM-Pro style forwarding). The
        // greedy tag regex must not eat the "CEF:"/"LEEF:" prefix.
        let cef = "Jan 15 10:30:45 UDM-Pro CEF:0|Ubiquiti|IDS|1.0|100|Alert|5|src=1.2.3.4";
        let parsed = SyslogMessage::parse(cef).unwrap();
        assert_eq!(parsed.hostname, Some("UDM-Pro".to_string()));
        assert_eq!(parsed.app_name, None);
        assert_eq!(
            parsed.message,
            "CEF:0|Ubiquiti|IDS|1.0|100|Alert|5|src=1.2.3.4"
        );
        assert!(parsed.message.starts_with("CEF:"));

        let leef = "Jan 15 10:30:45 UDM-Pro LEEF:1.0|Ubiquiti|IDS|1.0|EventID|key=value";
        let parsed = SyslogMessage::parse(leef).unwrap();
        assert_eq!(parsed.hostname, Some("UDM-Pro".to_string()));
        assert_eq!(parsed.app_name, None);
        assert_eq!(
            parsed.message,
            "LEEF:1.0|Ubiquiti|IDS|1.0|EventID|key=value"
        );
        assert!(parsed.message.starts_with("LEEF:"));
    }

    #[test]
    fn test_parse_no_pri_bare_cef() {
        let msg = "CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4";
        let parsed = SyslogMessage::parse(msg).unwrap();

        assert_eq!(parsed.hostname, None);
        assert_eq!(parsed.message, msg);
        assert_eq!(parsed.priority, 13);
    }

    #[test]
    fn test_parse_no_pri_bare_leef() {
        let msg = "LEEF:1.0|Vendor|Product|1.0|EventID|key=value";
        let parsed = SyslogMessage::parse(msg).unwrap();

        assert_eq!(parsed.hostname, None);
        assert_eq!(parsed.message, msg);
        assert_eq!(parsed.priority, 13);
    }

    #[test]
    fn test_parse_rfc3164_trailing_newline() {
        let msg = "<134>Jan 15 10:30:45 fw01 arcsight: CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4\n";
        let parsed = SyslogMessage::parse(msg).unwrap();

        assert!(matches!(parsed.protocol, SyslogProtocol::Rfc3164));
        assert!(!parsed.message.ends_with('\n'));
        assert_eq!(
            parsed.message,
            "CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4"
        );
    }

    #[test]
    fn test_parse_rfc3164_trailing_crlf() {
        let msg = "<134>Jan 15 10:30:45 fw01 arcsight: CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4\r\n";
        let parsed = SyslogMessage::parse(msg).unwrap();

        assert!(matches!(parsed.protocol, SyslogProtocol::Rfc3164));
        assert!(!parsed.message.ends_with('\r'));
        assert!(!parsed.message.ends_with('\n'));
        assert_eq!(
            parsed.message,
            "CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4"
        );
    }

    #[test]
    fn test_parse_no_pri_bare_cef_trailing_newline() {
        let msg = "CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4\n";
        let parsed = SyslogMessage::parse(msg).unwrap();

        assert_eq!(
            parsed.message,
            "CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4"
        );
    }

    #[test]
    fn test_facility_debug() {
        let f = Facility::System;
        let debug_str = format!("{:?}", f);
        assert_eq!(debug_str, "System");
    }

    #[test]
    fn test_severity_from_u8_and_as_str_cover_every_level() {
        let expected = [
            "EMERGENCY",
            "ALERT",
            "CRITICAL",
            "ERROR",
            "WARNING",
            "NOTICE",
            "INFO",
            "DEBUG",
        ];
        for (n, name) in expected.iter().enumerate() {
            let sev = Severity::from_u8(n as u8).expect("0..=7 are valid severities");
            assert_eq!(sev.as_str(), *name);
            assert_eq!(sev as usize, n);
        }
        assert!(Severity::from_u8(8).is_none());
        assert!(Severity::from_u8(255).is_none());
    }

    #[test]
    fn test_facility_from_u8_and_as_str_cover_every_facility() {
        let expected = [
            "kernel", "user", "mail", "system", "security", "syslog", "lp", "news", "uucp",
            "clock", "authpriv", "ftp", "ntp", "audit", "alert", "clock2", "local0", "local1",
            "local2", "local3", "local4", "local5", "local6", "local7",
        ];
        for (n, name) in expected.iter().enumerate() {
            let fac = Facility::from_u8(n as u8).expect("0..=23 are valid facilities");
            assert_eq!(fac.as_str(), *name);
            assert_eq!(fac as usize, n);
        }
        assert!(Facility::from_u8(24).is_none());
        assert!(Facility::from_u8(255).is_none());
    }

    #[test]
    fn test_rfc3164_timestamp_parses_nov_dec_and_rejects_unknown_month() {
        use chrono::{Datelike, Timelike};
        let nov = SyslogMessage::parse_rfc3164_timestamp("Nov 5 01:02:03").unwrap();
        assert_eq!((nov.month(), nov.day()), (11, 5));
        assert_eq!((nov.hour(), nov.minute(), nov.second()), (1, 2, 3));
        let dec = SyslogMessage::parse_rfc3164_timestamp("DEC 31 23:59:58").unwrap();
        assert_eq!((dec.month(), dec.day()), (12, 31));
        // Matches the shape regex but is not a month name.
        assert!(SyslogMessage::parse_rfc3164_timestamp("Foo 11 22:14:15").is_none());
    }

    #[test]
    fn test_rfc5424_sd_param_name_containing_space_leaves_message_unparsed() {
        let m = SyslogMessage::parse(r#"<1>1 - h a - - [a@1 bad name="1"] text"#).unwrap();
        assert!(m.structured_data.is_none());
        assert_eq!(m.message, r#"[a@1 bad name="1"] text"#);
    }

    #[test]
    fn test_dns_from_syslog_detects_unbound_and_powerdns() {
        let mut m = SyslogMessage::parse("<30>Oct 11 22:14:15 dns unbound: x").unwrap();
        m.message = "info: 192.168.1.100 example.com. A IN".to_string();
        let unbound = dns::DnsLogEntry::from_syslog(&m).expect("unbound line must parse");
        assert_eq!(unbound.client_ip, "192.168.1.100");
        assert_eq!(unbound.query_name, "example.com");
        assert_eq!(unbound.query_type, "A");

        m.message = "Remote 10.1.2.3 wants 'host.example|AAAA', do = 0, bufsize = 512".to_string();
        let pdns = dns::DnsLogEntry::from_syslog(&m).expect("powerdns line must parse");
        assert_eq!(pdns.client_ip, "10.1.2.3");
        assert_eq!(pdns.query_name, "host.example");
        assert_eq!(pdns.query_type, "AAAA");

        m.message = "nothing dns related".to_string();
        assert!(dns::DnsLogEntry::from_syslog(&m).is_none());
    }

    #[test]
    fn test_parse_rfc3164_unicode_digit_timestamp_keeps_message_with_no_timestamp() {
        let m = SyslogMessage::parse("<34>Oct 1\u{663} 22:14:15 host app: hello").unwrap();
        assert!(m.timestamp.is_none());
        assert_eq!(m.hostname.as_deref(), Some("host"));
        assert_eq!(m.app_name.as_deref(), Some("app"));
        assert_eq!(m.message, "hello");
        assert!(matches!(m.protocol, SyslogProtocol::Rfc3164));
    }

    #[test]
    fn test_parse_rfc3164_impossible_date_keeps_message_with_no_timestamp() {
        let m = SyslogMessage::parse("<34>Feb 30 10:30:45 host app: hi").unwrap();
        assert!(m.timestamp.is_none());
        assert_eq!(m.app_name.as_deref(), Some("app"));
        assert_eq!(m.message, "hi");
        let m = SyslogMessage::parse("<34>Oct 11 25:30:45 host app: hi").unwrap();
        assert!(m.timestamp.is_none());
    }

    #[test]
    fn test_parse_rfc3164_empty_pid_is_not_a_tag() {
        let m = SyslogMessage::parse("<34>Oct 11 22:14:15 host app[]: hi").unwrap();
        assert_eq!(m.app_name, None);
        assert_eq!(m.proc_id, None);
        assert_eq!(m.message, "app[]: hi");
    }

    #[test]
    fn test_parse_rfc3164_newline_inside_separator_run_still_parses() {
        let m = SyslogMessage::parse("<34>Oct 11 22:14:15 host \nbody").unwrap();
        assert_eq!(m.hostname.as_deref(), Some("host"));
        assert_eq!(m.message, "body");
        assert!(matches!(m.protocol, SyslogProtocol::Rfc3164));
    }

    #[test]
    fn test_parse_rfc3164_newline_in_rest_falls_back_to_pri_only() {
        let m = SyslogMessage::parse("<34>Oct 11 22:14:15 host a\nb").unwrap();
        assert_eq!(m.hostname, None);
        assert_eq!(m.message, "Oct 11 22:14:15 host a\nb");
        assert!(matches!(m.protocol, SyslogProtocol::Unknown));
    }

    #[test]
    fn test_parse_rfc3164_cr_mid_line_is_not_special() {
        let m = SyslogMessage::parse("<34>Oct 11 22:14:15 host app: a\rb").unwrap();
        assert_eq!(m.app_name.as_deref(), Some("app"));
        assert_eq!(m.message, "a\rb");
    }

    #[test]
    fn test_parse_rfc3164_unicode_whitespace_after_hostname_is_a_separator() {
        let m = SyslogMessage::parse("<34>Oct 11 22:14:15 host\u{A0}app: hi").unwrap();
        assert_eq!(m.hostname.as_deref(), Some("host"));
        assert_eq!(m.app_name.as_deref(), Some("app"));
    }
}
