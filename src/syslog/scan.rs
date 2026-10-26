//! Byte scanners for the RFC 3164 hot path.
//!
//! Each scanner replaces one regex of `src/syslog/mod.rs` and is exact with respect to it:
//! the regexes are anchored and every greedy run in them has no alternative match, so a single
//! deterministic left-to-right scan decides the match. Rust's regex `\d`, `\s` and `\S` are
//! Unicode-aware, so the scanners only handle ASCII: on the first non-ASCII byte they examine
//! (inside a scanned run, or as the byte that terminates it) they return [`Miss::Fallback`]
//! and the caller runs the original regex.

/// Why a scanner produced no match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Miss {
    /// The regex provably cannot match this input.
    NoMatch,
    /// A non-ASCII byte was reached where Unicode class semantics matter; run the regex.
    Fallback,
}

/// ASCII members of the regex `\s` class: 0x09-0x0D and 0x20.
#[inline]
const fn is_ws(b: u8) -> bool {
    matches!(b, 0x09..=0x0D | 0x20)
}

/// Left-to-right cursor over the bytes of a `&str`. Only ASCII bytes are ever consumed, so
/// `i` is always a char boundary.
struct Cursor<'a> {
    s: &'a str,
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            s,
            b: s.as_bytes(),
            i: 0,
        }
    }

    /// Next byte without consuming it; `Fallback` on a non-ASCII byte, `None` at the end.
    #[inline]
    fn peek(&self) -> Result<Option<u8>, Miss> {
        match self.b.get(self.i) {
            None => Ok(None),
            Some(&c) if c.is_ascii() => Ok(Some(c)),
            Some(_) => Err(Miss::Fallback),
        }
    }

    /// Consume the literal byte `want`.
    #[inline]
    fn expect(&mut self, want: u8) -> Result<(), Miss> {
        if self.peek()? == Some(want) {
            self.i += 1;
            Ok(())
        } else {
            Err(Miss::NoMatch)
        }
    }

    /// `\d{min,max}` (ASCII digits); returns the byte range consumed.
    fn digits(&mut self, min: usize, max: usize) -> Result<(usize, usize), Miss> {
        let start = self.i;
        while self.i - start < max && matches!(self.peek()?, Some(b'0'..=b'9')) {
            self.i += 1;
        }
        if self.i - start < min {
            Err(Miss::NoMatch)
        } else {
            Ok((start, self.i))
        }
    }

    /// `\s{min,}` (greedy run of ASCII whitespace).
    fn ws(&mut self, min: usize) -> Result<(), Miss> {
        let start = self.i;
        while matches!(self.peek()?, Some(c) if is_ws(c)) {
            self.i += 1;
        }
        if self.i - start < min {
            Err(Miss::NoMatch)
        } else {
            Ok(())
        }
    }

    /// `\S+` (greedy run of non-whitespace, at least one byte); returns the byte range.
    fn nonws(&mut self) -> Result<(usize, usize), Miss> {
        let start = self.i;
        while matches!(self.peek()?, Some(c) if !is_ws(c)) {
            self.i += 1;
        }
        if self.i == start {
            Err(Miss::NoMatch)
        } else {
            Ok((start, self.i))
        }
    }

    /// Start offset of a trailing `(.*?)$` / `(.*)$` (the unconsumed tail); the tail must
    /// contain no `\n`.
    fn tail_start(&self) -> Result<usize, Miss> {
        if self.b[self.i..].contains(&b'\n') {
            Err(Miss::NoMatch)
        } else {
            Ok(self.i)
        }
    }

    /// `\d{n}` digits already scanned at `(start, end)`, as a number.
    fn number(&self, (start, end): (usize, usize)) -> u32 {
        self.b[start..end]
            .iter()
            .fold(0, |acc, d| acc * 10 + u32::from(d - b'0'))
    }

    fn slice(&self, (start, end): (usize, usize)) -> &'a str {
        &self.s[start..end]
    }
}

/// The fields of an RFC 3164 timestamp `Mon DD HH:MM:SS`.
#[derive(Debug, Clone, Copy)]
pub(super) struct TsParts {
    /// Month abbreviation, ASCII-lowercased (`[A-Za-z]{3}` was verified).
    pub month: [u8; 3],
    /// Day of month digits as scanned (1-2 digits; range not validated).
    pub day: u32,
    /// Hour digits as scanned (range not validated).
    pub hour: u32,
    /// Minute digits as scanned (range not validated).
    pub minute: u32,
    /// Second digits as scanned (range not validated).
    pub second: u32,
}

/// `[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}` starting at the cursor.
fn timestamp_fields(c: &mut Cursor) -> Result<TsParts, Miss> {
    let mut month = [0u8; 3];
    for m in &mut month {
        match c.peek()? {
            Some(ch) if ch.is_ascii_alphabetic() => {
                *m = ch.to_ascii_lowercase();
                c.i += 1;
            }
            _ => return Err(Miss::NoMatch),
        }
    }
    c.ws(1)?;
    let day = c.digits(1, 2)?;
    c.ws(1)?;
    let hour = c.digits(2, 2)?;
    c.expect(b':')?;
    let minute = c.digits(2, 2)?;
    c.expect(b':')?;
    let second = c.digits(2, 2)?;
    Ok(TsParts {
        month,
        day: c.number(day),
        hour: c.number(hour),
        minute: c.number(minute),
        second: c.number(second),
    })
}

/// Scan a whole string as `^Mon\s+D{1,2}\s+HH:MM:SS$` (the old `RFC3164_TS_RE`).
pub(super) fn timestamp(s: &str) -> Result<TsParts, Miss> {
    let mut c = Cursor::new(s);
    let parts = timestamp_fields(&mut c)?;
    if c.i == c.b.len() {
        Ok(parts)
    } else {
        Err(Miss::NoMatch)
    }
}

/// Month number for a lowercased 3-letter abbreviation; `None` for anything else.
pub(super) fn month_number(month: [u8; 3]) -> Option<u32> {
    Some(match &month {
        b"jan" => 1,
        b"feb" => 2,
        b"mar" => 3,
        b"apr" => 4,
        b"may" => 5,
        b"jun" => 6,
        b"jul" => 7,
        b"aug" => 8,
        b"sep" => 9,
        b"oct" => 10,
        b"nov" => 11,
        b"dec" => 12,
        _ => return None,
    })
}

/// A scanned RFC 3164 tag: `tag[pid]: message` or `tag: message`.
#[derive(Debug)]
pub(super) struct Tag<'a> {
    /// The tag name (everything before `[` or `:`).
    pub name: &'a str,
    /// The `[pid]` digits, when present.
    pub pid: Option<&'a str>,
    /// The message after `:` and any following whitespace.
    pub message: &'a str,
}

/// Scan `^([^:\[\s=(]+)(?:\[(\d+)\])?:\s*(.*)$` (the old `RFC3164_TAG_RE`).
pub(super) fn tag(rest: &str) -> Result<Tag<'_>, Miss> {
    let mut c = Cursor::new(rest);
    while let Some(ch) = c.peek()? {
        if matches!(ch, b':' | b'[' | b'=' | b'(') || is_ws(ch) {
            break;
        }
        c.i += 1;
    }
    if c.i == 0 {
        return Err(Miss::NoMatch);
    }
    let name_end = c.i;
    let pid = if c.peek()? == Some(b'[') {
        c.i += 1;
        let digits = c.digits(1, usize::MAX)?;
        c.expect(b']')?;
        Some(c.slice(digits))
    } else {
        None
    };
    c.expect(b':')?;
    c.ws(0)?;
    let msg_start = c.tail_start()?;
    Ok(Tag {
        name: c.slice((0, name_end)),
        pid,
        message: &rest[msg_start..],
    })
}

/// A scanned RFC 3164 header: `[<pri>]timestamp hostname rest`.
#[derive(Debug)]
pub(super) struct Header<'a> {
    /// The `<PRI>` digits (`None` for the no-PRI form). Range validation is the caller's job.
    pub pri: Option<&'a str>,
    /// The `Mon DD HH:MM:SS` timestamp text.
    pub timestamp: &'a str,
    /// The hostname token (maximal non-whitespace run).
    pub hostname: &'a str,
    /// Everything after the whitespace that follows the hostname.
    pub rest: &'a str,
}

/// Scan `^<(\d{1,3})>(TS)\s+(\S+)\s+(.*?)$` (`with_pri`, the old `RFC3164_RE`) or
/// `^(TS)\s+(\S+)\s+(.*?)$` (the old `RFC3164_NOPRI_RE`), where TS is
/// `[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}`.
pub(super) fn header(input: &str, with_pri: bool) -> Result<Header<'_>, Miss> {
    let mut c = Cursor::new(input);
    let pri = if with_pri {
        c.expect(b'<')?;
        let digits = c.digits(1, 3)?;
        c.expect(b'>')?;
        Some(c.slice(digits))
    } else {
        None
    };
    let ts_start = c.i;
    timestamp_fields(&mut c)?;
    let timestamp = c.slice((ts_start, c.i));
    c.ws(1)?;
    let hostname = c.nonws()?;
    c.ws(1)?;
    let rest = c.tail_start()?;
    Ok(Header {
        pri,
        timestamp,
        hostname: c.slice(hostname),
        rest: &input[rest..],
    })
}

/// Necessary condition for `RFC5424_RE` (`^<(\d{1,3})>(\d)\s+...`): `<`, 1-3 digits, `>`, one
/// digit, then whitespace. Returns `false` only when ASCII bytes prove the regex cannot match;
/// a non-ASCII byte in the checked prefix returns `true` so the regex decides.
pub(super) fn may_be_rfc5424(input: &str) -> bool {
    fn prefix(c: &mut Cursor) -> Result<(), Miss> {
        c.expect(b'<')?;
        c.digits(1, 3)?;
        c.expect(b'>')?;
        c.digits(1, 1)?;
        c.ws(1)
    }
    prefix(&mut Cursor::new(input)) != Err(Miss::NoMatch)
}

#[cfg(test)]
mod tests {
    use super::{Miss, header, may_be_rfc5424, month_number, tag, timestamp};

    fn ts(s: &str) -> Result<(Option<u32>, u32, u32, u32, u32), Miss> {
        timestamp(s).map(|p| (month_number(p.month), p.day, p.hour, p.minute, p.second))
    }

    #[test]
    fn test_timestamp_accepts_one_and_two_digit_days() {
        assert_eq!(ts("Jan 15 10:30:45"), Ok((Some(1), 15, 10, 30, 45)));
        assert_eq!(ts("Jan 5 10:30:45"), Ok((Some(1), 5, 10, 30, 45)));
    }

    #[test]
    fn test_timestamp_accepts_runs_of_any_ascii_whitespace() {
        assert_eq!(ts("Oct   5\t\t22:14:15"), Ok((Some(10), 5, 22, 14, 15)));
        assert_eq!(
            ts("Oct\u{0B}5\u{0C}22:14:15"),
            Ok((Some(10), 5, 22, 14, 15))
        );
        assert_eq!(ts("Oct\n5\r22:14:15"), Ok((Some(10), 5, 22, 14, 15)));
    }

    #[test]
    fn test_timestamp_month_is_case_insensitive_and_table_driven() {
        assert_eq!(ts("DEC 31 23:59:58").unwrap().0, Some(12));
        assert_eq!(ts("dEc 31 23:59:58").unwrap().0, Some(12));
        assert_eq!(ts("Foo 11 22:14:15").unwrap().0, None);
        for (i, m) in [
            "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(
                ts(&format!("{m} 1 00:00:00")).unwrap().0,
                Some(i as u32 + 1)
            );
        }
    }

    #[test]
    fn test_timestamp_rejects_malformed_shapes_without_fallback() {
        assert_eq!(ts("Jan 123 10:30:45"), Err(Miss::NoMatch)); // 3-digit day
        assert_eq!(ts("Jan 15 1:30:45"), Err(Miss::NoMatch)); // 1-digit hour
        assert_eq!(ts("Jan15 10:30:45"), Err(Miss::NoMatch)); // no separator
        assert_eq!(ts("Jan 15 10:30:45 "), Err(Miss::NoMatch)); // trailing space
        assert_eq!(ts("Jan 15 10:30:45\u{E9}"), Err(Miss::NoMatch)); // trailing non-ASCII
        assert_eq!(ts("Ja1 15 10:30:45"), Err(Miss::NoMatch));
        assert_eq!(ts(""), Err(Miss::NoMatch));
    }

    #[test]
    fn test_timestamp_unicode_digit_or_whitespace_falls_back() {
        assert_eq!(ts("Jan 1\u{663} 10:30:45"), Err(Miss::Fallback));
        assert_eq!(ts("Jan\u{A0}15 10:30:45"), Err(Miss::Fallback));
        assert_eq!(ts("Jan 15\u{3000}10:30:45"), Err(Miss::Fallback));
        assert_eq!(ts("\u{E9}an 15 10:30:45"), Err(Miss::Fallback));
    }

    #[test]
    fn test_tag_with_and_without_pid() {
        let t = tag("sshd[123]: Accepted").unwrap();
        assert_eq!(
            (t.name, t.pid, t.message),
            ("sshd", Some("123"), "Accepted")
        );
        let t = tag("su: 'su root' failed").unwrap();
        assert_eq!((t.name, t.pid, t.message), ("su", None, "'su root' failed"));
        let t = tag("app:msg").unwrap();
        assert_eq!((t.name, t.pid, t.message), ("app", None, "msg"));
        let t = tag("app:").unwrap();
        assert_eq!((t.name, t.pid, t.message), ("app", None, ""));
    }

    #[test]
    fn test_tag_admits_closing_bracket_and_paren_but_not_metacharacters() {
        let t = tag("x]: y").unwrap();
        assert_eq!(t.name, "x]");
        let t = tag("a)b: y").unwrap();
        assert_eq!(t.name, "a)b");
        assert_eq!(tag("a b: c").unwrap_err(), Miss::NoMatch);
        assert_eq!(tag("k=v: x").unwrap_err(), Miss::NoMatch);
        assert_eq!(tag("f(x): y").unwrap_err(), Miss::NoMatch);
        assert_eq!(tag(": x").unwrap_err(), Miss::NoMatch);
        assert_eq!(tag("[1]: x").unwrap_err(), Miss::NoMatch);
        assert_eq!(tag("").unwrap_err(), Miss::NoMatch);
        assert_eq!(tag("nocolon").unwrap_err(), Miss::NoMatch);
    }

    #[test]
    fn test_tag_bad_pid_forms_are_not_tags() {
        assert_eq!(tag("app[]: x").unwrap_err(), Miss::NoMatch);
        assert_eq!(tag("app[12x]: x").unwrap_err(), Miss::NoMatch);
        assert_eq!(tag("app[12: x").unwrap_err(), Miss::NoMatch);
        assert_eq!(tag("app[12]x: y").unwrap_err(), Miss::NoMatch);
        assert_eq!(tag("app[12]").unwrap_err(), Miss::NoMatch);
    }

    #[test]
    fn test_tag_whitespace_after_colon_is_consumed_including_newline() {
        assert_eq!(tag("app:  \t x").unwrap().message, "x");
        assert_eq!(tag("app: \nfoo").unwrap().message, "foo");
        assert_eq!(tag("app: a\nb").unwrap_err(), Miss::NoMatch);
        assert_eq!(tag("app:\r").unwrap().message, "");
        assert_eq!(tag("app: a\rb").unwrap().message, "a\rb");
    }

    #[test]
    fn test_tag_non_ascii_in_scanned_region_falls_back() {
        assert_eq!(tag("\u{E9}pp: x").unwrap_err(), Miss::Fallback);
        assert_eq!(tag("app\u{A0}: x").unwrap_err(), Miss::Fallback);
        assert_eq!(tag("app:\u{A0}x").unwrap_err(), Miss::Fallback);
        assert_eq!(tag("app[1\u{663}]: x").unwrap_err(), Miss::Fallback);
    }

    #[test]
    fn test_tag_non_ascii_only_in_message_is_matched_without_fallback() {
        let t = tag("app: h\u{E9}llo \u{663}").unwrap();
        assert_eq!(t.message, "h\u{E9}llo \u{663}");
    }

    #[test]
    fn test_header_with_pri_splits_fields() {
        let h = header("<134>Jan 15 10:30:45 myhost app[1]: hi there", true).unwrap();
        assert_eq!(h.pri, Some("134"));
        assert_eq!(h.timestamp, "Jan 15 10:30:45");
        assert_eq!(h.hostname, "myhost");
        assert_eq!(h.rest, "app[1]: hi there");
    }

    #[test]
    fn test_header_without_pri_splits_fields() {
        let h = header("Jan  5 10:30:45   fw01   CEF:0|a|b", false).unwrap();
        assert_eq!(h.pri, None);
        assert_eq!(h.timestamp, "Jan  5 10:30:45");
        assert_eq!(h.hostname, "fw01");
        assert_eq!(h.rest, "CEF:0|a|b");
        // The no-PRI scanner does not accept a PRI prefix and vice versa.
        assert_eq!(
            header("<134>Jan 15 10:30:45 h x", false).unwrap_err(),
            Miss::NoMatch
        );
        assert_eq!(
            header("Jan 15 10:30:45 h x", true).unwrap_err(),
            Miss::NoMatch
        );
    }

    #[test]
    fn test_header_pri_shapes() {
        assert!(header("<1>Jan 15 10:30:45 h x", true).is_ok());
        assert!(header("<999>Jan 15 10:30:45 h x", true).is_ok()); // range is checked by parse_pri
        assert_eq!(
            header("<1000>Jan 15 10:30:45 h x", true).unwrap_err(),
            Miss::NoMatch
        );
        assert_eq!(
            header("<>Jan 15 10:30:45 h x", true).unwrap_err(),
            Miss::NoMatch
        );
        assert_eq!(
            header("<13 Jan 15 10:30:45 h x", true).unwrap_err(),
            Miss::NoMatch
        );
    }

    #[test]
    fn test_header_requires_whitespace_after_hostname() {
        assert_eq!(
            header("<1>Jan 15 10:30:45 host", true).unwrap_err(),
            Miss::NoMatch
        );
        assert_eq!(
            header("<1>Jan 15 10:30:45 ", true).unwrap_err(),
            Miss::NoMatch
        );
        let h = header("<1>Jan 15 10:30:45 host ", true).unwrap();
        assert_eq!((h.hostname, h.rest), ("host", ""));
    }

    #[test]
    fn test_header_newline_rules() {
        // `\s+` may consume a newline; the rest may not contain one.
        let h = header("<1>Jan 15 10:30:45 host \nbody", true).unwrap();
        assert_eq!((h.hostname, h.rest), ("host", "body"));
        let h = header("<1>Jan 15 10:30:45 host \n", true).unwrap();
        assert_eq!(h.rest, "");
        assert_eq!(
            header("<1>Jan 15 10:30:45 host a\nb", true).unwrap_err(),
            Miss::NoMatch
        );
        assert_eq!(
            header("<1>Jan 15 10:30:45 host \nbody\n", true).unwrap_err(),
            Miss::NoMatch
        );
        let h = header("<1>Jan 15 10:30:45 host a\rb", true).unwrap();
        assert_eq!(h.rest, "a\rb");
    }

    #[test]
    fn test_header_hostname_is_the_maximal_non_whitespace_run() {
        let h = header("<1>Jan 15 10:30:45 a:b[1]=(x) y", true).unwrap();
        assert_eq!((h.hostname, h.rest), ("a:b[1]=(x)", "y"));
    }

    #[test]
    fn test_header_non_ascii_where_class_matters_falls_back() {
        assert_eq!(
            header("<1>Jan 1\u{663} 10:30:45 h x", true).unwrap_err(),
            Miss::Fallback
        );
        assert_eq!(
            header("<\u{663}>Jan 15 10:30:45 h x", true).unwrap_err(),
            Miss::Fallback
        );
        assert_eq!(
            header("<1>Jan 15 10:30:45 h\u{E9}st x", true).unwrap_err(),
            Miss::Fallback
        );
        assert_eq!(
            header("<1>Jan 15 10:30:45 host\u{A0}x", true).unwrap_err(),
            Miss::Fallback
        );
        assert_eq!(
            header("<1>Jan 15 10:30:45 host \u{85}x", true).unwrap_err(),
            Miss::Fallback
        );
        assert_eq!(
            header("<1>Jan 15 10:30:45\u{3000}host x", true).unwrap_err(),
            Miss::Fallback
        );
    }

    #[test]
    fn test_header_no_pri_non_ascii_hostname_falls_back() {
        assert_eq!(
            header("Jan 15 10:30:45 h\u{E9}st x", false).unwrap_err(),
            Miss::Fallback
        );
    }

    #[test]
    fn test_header_non_ascii_only_in_rest_is_matched_without_fallback() {
        let h = header("<1>Jan 15 10:30:45 host x\u{E9}\u{663}", true).unwrap();
        assert_eq!(h.rest, "x\u{E9}\u{663}");
    }

    #[test]
    fn test_precheck_accepts_rfc5424_prefixes() {
        assert!(may_be_rfc5424("<34>1 2003-10-11T22:14:15.003Z h a - - - m"));
        assert!(may_be_rfc5424("<1>1 - h a - - -"));
        assert!(may_be_rfc5424("<165>9\t- h a - - -"));
        assert!(may_be_rfc5424("<165>1\n- h a - - -"));
        assert!(may_be_rfc5424("<165>1\u{0B}x"));
    }

    #[test]
    fn test_precheck_rejects_rfc3164_and_other_lines() {
        assert!(!may_be_rfc5424("<134>Jan 15 10:30:45 host app: msg"));
        assert!(!may_be_rfc5424("Jan 15 10:30:45 host app: msg"));
        assert!(!may_be_rfc5424("<1000>1 - h a - - -")); // 4-digit PRI
        assert!(!may_be_rfc5424("<>1 - h")); // no PRI digits
        assert!(!may_be_rfc5424("<34>12 - h")); // two-digit version
        assert!(!may_be_rfc5424("<34>1")); // no whitespace after version
        assert!(!may_be_rfc5424("<34>1-")); // no whitespace after version
        assert!(!may_be_rfc5424("<34"));
        assert!(!may_be_rfc5424(""));
        assert!(!may_be_rfc5424("CEF:0|a|b"));
    }

    #[test]
    fn test_precheck_never_skips_when_a_non_ascii_byte_decides() {
        assert!(may_be_rfc5424("<\u{663}>1 - h a - - -")); // Unicode digit in PRI
        assert!(may_be_rfc5424("<34>\u{663} - h a - - -")); // Unicode digit version
        assert!(may_be_rfc5424("<34>1\u{A0}- h a - - -")); // Unicode whitespace after version
        assert!(may_be_rfc5424("<34>1\u{85}x"));
        assert!(may_be_rfc5424("\u{E9}"));
    }
}
