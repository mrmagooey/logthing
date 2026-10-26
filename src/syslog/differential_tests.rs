//! Differential test: the RFC 3164 scanners (and the RFC 5424 pre-check) must produce exactly
//! the same `Option<SyslogMessage>` as the original regex pipeline for every input.
//!
//! `oracle` is a verbatim copy of the pre-scanner `SyslogMessage::parse` pipeline (5424, 3164,
//! no-PRI, CEF/LEEF, `<PRI>`-only fallback). It reuses `parse_rfc5424`, `split_pri_prefix` and
//! `parse_pri`, which the scanner work does not touch. Comparison goes through
//! `serde_json::to_value` (`SyslogMessage` has no `PartialEq`, and `Value` objects are
//! order-insensitive, which matters for the structured-data `HashMap`s).

use super::{SyslogMessage, SyslogProtocol};
use std::path::{Path, PathBuf};

mod oracle {
    use super::{SyslogMessage, SyslogProtocol};
    use chrono::{DateTime, Datelike, NaiveDate, Utc};
    use regex::Regex;
    use std::sync::LazyLock;

    static RFC3164_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^<(\d{1,3})>([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*?)$")
            .unwrap()
    });
    static RFC3164_NOPRI_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*?)$").unwrap()
    });
    static RFC3164_TS_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$").unwrap()
    });
    static RFC3164_TAG_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^([^:\[\s=(]+)(?:\[(\d+)\])?:\s*(.*)$").unwrap());

    pub fn parse(input: &str) -> Option<SyslogMessage> {
        let input = input.strip_suffix('\n').unwrap_or(input);
        let input = input.strip_suffix('\r').unwrap_or(input);
        if let Some(msg) = SyslogMessage::parse_rfc5424(input) {
            return Some(msg);
        }
        if let Some(msg) = parse_rfc3164(input) {
            return Some(msg);
        }
        parse_no_pri(input)
    }

    fn parse_no_pri(input: &str) -> Option<SyslogMessage> {
        const DEFAULT_PRIORITY: u8 = (1 << 3) | 5;

        if let Some(caps) = RFC3164_NOPRI_RE.captures(input) {
            let priority = DEFAULT_PRIORITY;
            let timestamp = parse_timestamp(caps.get(1)?.as_str());
            let hostname = Some(caps.get(2)?.as_str().to_string());
            let (app_name, proc_id, message) = split_tag_or_payload(caps.get(3)?.as_str());
            return Some(SyslogMessage {
                priority,
                severity: priority & 0x07,
                facility: (priority >> 3) & 0x1f,
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
            return Some(SyslogMessage {
                priority,
                severity: priority & 0x07,
                facility: (priority >> 3) & 0x1f,
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

        if let Some((digits, body)) = SyslogMessage::split_pri_prefix(input) {
            let (priority, message) = match SyslogMessage::parse_pri(digits) {
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

    fn split_tag_or_payload(rest: &str) -> (Option<String>, Option<String>, String) {
        if rest.starts_with("CEF:") || rest.starts_with("LEEF:") {
            (None, None, rest.to_string())
        } else {
            parse_tag(rest)
        }
    }

    fn parse_rfc3164(input: &str) -> Option<SyslogMessage> {
        let caps = RFC3164_RE.captures(input)?;
        let priority = SyslogMessage::parse_pri(caps.get(1)?.as_str())?;
        let timestamp = parse_timestamp(caps.get(2)?.as_str());
        let hostname = Some(caps.get(3)?.as_str().to_string());
        let (app_name, proc_id, message) = split_tag_or_payload(caps.get(4)?.as_str());
        Some(SyslogMessage {
            priority,
            severity: priority & 0x07,
            facility: (priority >> 3) & 0x1f,
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

    fn parse_timestamp(ts_str: &str) -> Option<DateTime<Utc>> {
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
        let year = Utc::now().year();
        let naive_date = NaiveDate::from_ymd_opt(year, month, day)?;
        let naive_datetime = naive_date.and_hms_opt(hour, minute, second)?;
        Some(DateTime::from_naive_utc_and_offset(naive_datetime, Utc))
    }

    fn parse_tag(rest: &str) -> (Option<String>, Option<String>, String) {
        if let Some(caps) = RFC3164_TAG_RE.captures(rest) {
            let app_name = Some(caps.get(1).unwrap().as_str().to_string());
            let proc_id = caps.get(2).map(|m| m.as_str().to_string());
            let message = caps.get(3).unwrap().as_str().to_string();
            (app_name, proc_id, message)
        } else {
            (None, None, rest.to_string())
        }
    }
}

/// Adversarial alphabet: ASCII digit, Unicode digit U+0663, every ASCII whitespace kind, the
/// Unicode whitespace that the regex `\s` accepts (U+0085, U+00A0, U+3000), the tag
/// metacharacters, an ASCII letter and a non-ASCII letter.
const ALPHABET: [&str; 18] = [
    "7", "\u{663}", " ", "\t", "\n", "\r", "\u{0B}", "\u{0C}", "\u{A0}", "\u{85}", "\u{3000}", ":",
    "[", "]", "=", "(", "a", "\u{E9}",
];

/// Templates: each entry is a slot; concatenating the defaults gives a valid line.
const T3164: &[&str] = &[
    "<",
    "134",
    ">",
    "Jan",
    " ",
    "15",
    " ",
    "10",
    ":",
    "30",
    ":",
    "45",
    " ",
    "myhost",
    " ",
    "app",
    "[",
    "42",
    "]",
    ":",
    " ",
    "hello world",
];
const TNOPRI: &[&str] = &[
    "",
    "",
    "",
    "Jan",
    " ",
    "15",
    " ",
    "10",
    ":",
    "30",
    ":",
    "45",
    " ",
    "myhost",
    " ",
    "app",
    "[",
    "42",
    "]",
    ":",
    " ",
    "hello world",
];
const T5424: &[&str] = &[
    "<",
    "134",
    ">",
    "1",
    " ",
    "2024-01-15T10:30:45Z",
    " ",
    "myhost",
    " ",
    "app",
    " ",
    "42",
    " ",
    "ID1",
    " ",
    "-",
    " ",
    "hello world",
];
const TCEF: &[&str] = &[
    "<",
    "134",
    ">",
    "Jan",
    " ",
    "15",
    " ",
    "10",
    ":",
    "30",
    ":",
    "45",
    " ",
    "myhost",
    " ",
    "CEF:0|V|P|1|100|N|5|src=1.2.3.4",
];
const TBARE: &[&str] = &["CEF:0|V|P|1|100|N|5|src=1.2.3.4"];
const TFREE: &[&str] = &["<", "34", ">", "free text"];
const TEMPLATES: [&[&str]; 6] = [T3164, TNOPRI, T5424, TCEF, TBARE, TFREE];

/// Months for the random generator (the enumeration varies the slot with alphabet strings).
const MONTHS: [&str; 6] = ["Jan", "feb", "MAR", "Foo", "Feb", "dEc"];
/// Day/PRI/hour edge values for the random generator.
const NUMBERS: [&str; 10] = [
    "0", "00", "1", "31", "30", "99", "123", "191", "192", "1000",
];

/// Maximum slot-string length used by the default (debug) subset. If the default differential tests
/// take more than 10 s in a debug build, lower this to 1.
const SUBSET_MAX_LEN: usize = 2;

fn assert_same(line: &str) {
    let new = serde_json::to_value(SyslogMessage::parse(line)).unwrap();
    let old = serde_json::to_value(oracle::parse(line)).unwrap();
    assert_eq!(new, old, "parse differs from the regex oracle for {line:?}");
}

/// Every string over `ALPHABET` with length `0..=max_len`.
fn all_strings(max_len: usize) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut layer = vec![String::new()];
    for _ in 0..max_len {
        let mut next = Vec::with_capacity(layer.len() * ALPHABET.len());
        for prefix in &layer {
            for a in ALPHABET {
                next.push(format!("{prefix}{a}"));
            }
        }
        out.extend(next.iter().cloned());
        layer = next;
    }
    out
}

/// One-slot-at-a-time enumeration around every template. Returns the number of lines checked.
fn run_enumeration(max_len: usize) -> usize {
    let strings = all_strings(max_len);
    let mut checked = 0;
    for template in TEMPLATES {
        for slot in 0..template.len() {
            for s in &strings {
                let mut line = String::new();
                for (i, piece) in template.iter().enumerate() {
                    line.push_str(if i == slot { s } else { piece });
                }
                assert_same(&line);
                checked += 1;
            }
        }
    }
    checked
}

/// xorshift64* (no new dependency, fully deterministic).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn alphabet_string(&mut self, max_len: usize) -> String {
        let len = self.below(max_len + 1);
        (0..len)
            .map(|_| ALPHABET[self.below(ALPHABET.len())])
            .collect()
    }
}

/// A random line: 10% pure noise over the alphabet plus structure characters, otherwise a random
/// template with each slot replaced (probability 1/3) by an alphabet string, a month, or a number.
fn random_line(rng: &mut Rng) -> String {
    if rng.below(10) == 0 {
        const NOISE: [&str; 12] = ["<", ">", "J", "n", "1", "-", "C", "E", "F", "o", "O", "0"];
        let len = rng.below(41);
        return (0..len)
            .map(|_| {
                if rng.below(2) == 0 {
                    ALPHABET[rng.below(ALPHABET.len())]
                } else {
                    NOISE[rng.below(NOISE.len())]
                }
            })
            .collect();
    }
    let template = TEMPLATES[rng.below(TEMPLATES.len())];
    let mut line = String::new();
    for piece in template {
        if rng.below(3) == 0 {
            match rng.below(3) {
                0 => line.push_str(&rng.alphabet_string(4)),
                1 => line.push_str(MONTHS[rng.below(MONTHS.len())]),
                _ => line.push_str(NUMBERS[rng.below(NUMBERS.len())]),
            }
        } else {
            line.push_str(piece);
        }
    }
    line
}

fn run_random(count: usize) {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..count {
        assert_same(&random_line(&mut rng));
    }
}

/// Inputs copied from the existing `syslog::tests` plus terminator and PRI edge cases.
const CURATED: &[&str] = &[
    "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
    "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed",
    "<34>1 2003-10-11T22:14:15.003Z host su - ID47 -",
    "<1>1 - h a - - [a@1 x=\"1\"] user [admin] logged in",
    "<1>1 - h a - - [a@1 x=\"1\"][b@2 y=\"2\"]msg",
    "<1>1 - h a - - [a@1 x=\"héllo\"] msg",
    "<134>Jan 15 10:30:45 host CEF:0|V|P|1|100|Name|5|src=1.2.3.4",
    "<134>Jan 15 10:30:45 host LEEF:1.0|V|P|1|Evt|src=1.2.3.4",
    "<134>Jan 15 10:30:45 host sshd[123]: Accepted",
    "<134>Jan 15 10:30:45 host type=USER_AUTH msg=audit(1): pid=1 uid=0",
    "<134>Jan 15 10:30:45 host see note: this is prose",
    "<200>Jan 15 10:30:45 h msg",
    "<191>Jan 15 10:30:45 h msg",
    "<200>1 - h a - - - x",
    "<abc>garbage",
    "<34>free text",
    "<200>x",
    "<013>free text",
    "<0>free text",
    "<1000>free text",
    "<0>Oct 11 22:14:15 mymachine test: message",
    "<128>Oct 11 22:14:15 mymachine test: message",
    "<34>Oct 11 22:14:15 mymachine myapp[1234]: test message",
    "Jan 15 10:30:45 fw01 arcsight: CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4",
    "Jan 15 10:30:45 UDM-Pro CEF:0|Ubiquiti|IDS|1.0|100|Alert|5|src=1.2.3.4",
    "Jan 15 10:30:45 UDM-Pro LEEF:1.0|Ubiquiti|IDS|1.0|EventID|key=value",
    "CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4",
    "LEEF:1.0|Vendor|Product|1.0|EventID|key=value",
    "<134>Jan 15 10:30:45 fw01 arcsight: CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4\n",
    "<134>Jan 15 10:30:45 fw01 arcsight: CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4\r\n",
    "CEF:0|Vendor|Product|1.0|100|Login|5|src=1.2.3.4\n",
    "<134>Jan 15 10:30:45 h app: m\n\n",
    "<134>Jan 15 10:30:45 h app: m\r\r\n",
    "<30>Oct 11 22:14:15 dns unbound: x",
    "not a valid syslog message",
    "",
    "\n",
    "\r\n",
    "<",
    "<>",
    "<1",
    "<134>Nov 5 01:02:03 h a: b",
    "<134>DEC 31 23:59:58 h a: b",
    "<134>Foo 11 22:14:15 h a: b",
    "<134>Feb 30 10:30:45 host app: hi",
    "<134>Oct 1\u{663} 22:14:15 host app: hello",
    "<134>Oct 11 22:14:15 host app[]: hi",
    "<134>Oct 11 22:14:15 host app[12x]: hi",
    "<134>Oct 11 22:14:15 host \nbody",
    "<134>Oct 11 22:14:15 host a\nb",
    "<134>Oct 11 22:14:15 host\u{A0}app: hi",
    "<134>Oct 11 22:14:15 h\u{E9}st app: hi",
    "<134>Oct   5\t22:14:15   host   app:   spaced out",
];

fn read_files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter_map(|p| std::fs::read(&p).ok().map(|b| (p, b)))
        .collect();
    out.sort();
    out
}

fn check_file_contents(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    assert_same(&text);
    for line in text.split('\n') {
        assert_same(line);
    }
}

/// Committed seeds and regressions (`fuzz/seeds/syslog*`, `fuzz/regressions/syslog*`; the latter
/// may not exist) and the local-only gitignored `fuzz/corpus/syslog` (skipped with a note when absent).
fn replay_fuzz_inputs() -> usize {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz");
    let mut replayed = 0;
    for parent in ["seeds", "regressions"] {
        let Ok(dirs) = std::fs::read_dir(root.join(parent)) else {
            continue;
        };
        for dir in dirs.filter_map(Result::ok) {
            if dir.file_name().to_string_lossy().starts_with("syslog") {
                for (_, bytes) in read_files(&dir.path()) {
                    check_file_contents(&bytes);
                    replayed += 1;
                }
            }
        }
    }
    let corpus = root.join("corpus/syslog");
    if corpus.is_dir() {
        for (_, bytes) in read_files(&corpus) {
            check_file_contents(&bytes);
            replayed += 1;
        }
    } else {
        eprintln!("note: {} absent, corpus replay skipped", corpus.display());
    }
    replayed
}

#[test]
fn test_syslog_differential_curated_inputs() {
    for line in CURATED {
        assert_same(line);
    }
}

#[test]
fn test_syslog_differential_fuzz_seeds_and_corpus() {
    assert!(replay_fuzz_inputs() > 0, "no syslog seed files found");
}

#[test]
fn test_syslog_differential_enumerated_subset() {
    assert!(run_enumeration(SUBSET_MAX_LEN) > 10_000);
}

#[test]
fn test_syslog_differential_random_subset() {
    run_random(20_000);
}

/// Full volume: >= 600k enumerated + 200k random. Run in release:
/// `cargo test --release --lib -- --ignored syslog_differential`.
#[test]
#[ignore = "full volume; run in release"]
fn test_syslog_differential_full_volume() {
    let enumerated = run_enumeration(4);
    run_random(200_000);
    eprintln!("syslog_differential_full_volume: enumerated={enumerated} random=200000");
    assert!(enumerated >= 600_000);
}
