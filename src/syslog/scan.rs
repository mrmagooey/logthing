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

    /// The end of a trailing `(.*?)$` / `(.*)$`: the remaining input must contain no `\n`.
    fn rest(&self) -> Result<usize, Miss> {
        if self.b[self.i..].contains(&b'\n') {
            Err(Miss::NoMatch)
        } else {
            Ok(self.i)
        }
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
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

fn number(c: &Cursor, (start, end): (usize, usize)) -> u32 {
    c.b[start..end]
        .iter()
        .fold(0, |acc, d| acc * 10 + u32::from(d - b'0'))
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
        day: number(c, day),
        hour: number(c, hour),
        minute: number(c, minute),
        second: number(c, second),
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
    pub name: &'a str,
    pub pid: Option<&'a str>,
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
    let message = c.rest()?;
    Ok(Tag {
        name: c.slice((0, name_end)),
        pid,
        message: &rest[message..],
    })
}

#[cfg(test)]
mod tests {
    use super::{Miss, month_number, tag, timestamp};

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
}
