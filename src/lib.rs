// Library target — single authoritative module home for all crate modules.
// The binary target (main.rs) uses `logthing::` instead of re-declaring modules.

// result_large_err misfires on idiomatic axum `Result<T, Response>` handlers
// (clippy 1.98 counts the >=128-byte Response as an oversized Err variant);
// these are cold admin endpoints, boxing would be noise for no benefit.
#[allow(clippy::result_large_err)]
pub mod admin;
pub mod config;
pub mod forwarding;
#[doc(hidden)]
pub mod fuzz_harness;
pub mod ingest;
pub mod ipfix;
pub mod metrics_descriptions;
pub mod middleware;
pub mod models;
pub mod net;
pub mod parser;
pub mod profiling;
pub mod protocol;
pub mod server;
pub mod sflow;
pub mod shutdown;
pub mod stats;
pub mod suricata;
pub mod syslog;
#[cfg(test)]
pub(crate) mod test_support;
pub mod zeek;

/// Truncate `s` to at most `max_bytes` bytes, walking back to the nearest
/// UTF-8 character boundary so the result is always a valid `&str`.
///
/// Slicing a wire-derived string with a raw byte index (`&s[..100]`) panics
/// when the cut lands inside a multi-byte character. Every log site that
/// truncates untrusted input must use this instead.
pub(crate) fn truncate_for_log(s: &str, max_bytes: usize) -> &str {
    let mut end = max_bytes.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Truncate for logging like [`truncate_for_log`], additionally replacing
/// control characters with U+FFFD.
///
/// A syslog UDP datagram is an opaque blob: an embedded newline makes the
/// envelope parse fail, so the raw bytes reach the parse-error log site with
/// the newline intact. Under the default plain-text log format that lets an
/// unauthenticated sender forge what looks like a separate operator log
/// entry, or inject ANSI escapes into an operator's terminal.
///
/// Returns `Cow::Borrowed` when there is nothing to replace.
pub(crate) fn sanitize_for_log(s: &str, max_bytes: usize) -> std::borrow::Cow<'_, str> {
    let truncated = truncate_for_log(s, max_bytes);
    if truncated.chars().any(|c| c.is_control()) {
        std::borrow::Cow::Owned(
            truncated
                .chars()
                .map(|c| if c.is_control() { '\u{fffd}' } else { c })
                .collect(),
        )
    } else {
        std::borrow::Cow::Borrowed(truncated)
    }
}

#[cfg(test)]
mod sanitize_for_log_tests {
    use super::sanitize_for_log;

    #[test]
    fn passes_clean_input_through_without_allocating() {
        assert!(matches!(
            sanitize_for_log("clean message", 100),
            std::borrow::Cow::Borrowed("clean message")
        ));
    }

    #[test]
    fn replaces_newlines_that_would_forge_a_log_line() {
        let forged = "ok\nERROR fake entry";
        assert_eq!(sanitize_for_log(forged, 100), "ok\u{fffd}ERROR fake entry");
    }

    #[test]
    fn replaces_ansi_escape_sequences() {
        assert_eq!(sanitize_for_log("a\u{1b}[31mred", 100), "a\u{fffd}[31mred");
    }

    #[test]
    fn still_truncates_on_a_char_boundary() {
        let s = format!("{}{}", "x".repeat(98), '\u{1F600}');
        assert_eq!(sanitize_for_log(&s, 100).len(), 98);
    }
}

#[cfg(test)]
mod truncate_for_log_tests {
    use super::truncate_for_log;

    #[test]
    fn returns_whole_string_when_under_budget() {
        assert_eq!(truncate_for_log("hello", 100), "hello");
    }

    #[test]
    fn truncates_ascii_at_exact_byte_budget() {
        assert_eq!(truncate_for_log("aaaaaaaaaa", 4), "aaaa");
    }

    #[test]
    fn walks_back_off_a_multibyte_boundary_instead_of_panicking() {
        // 98 ASCII bytes then a 4-byte char straddling byte 100.
        let s = format!("{}{}", "x".repeat(98), '\u{1F600}');
        let out = truncate_for_log(&s, 100);
        assert_eq!(out.len(), 98, "must cut back to the boundary at 98");
        assert!(out.chars().all(|c| c == 'x'));
    }

    #[test]
    fn handles_budget_of_zero_and_empty_input() {
        assert_eq!(truncate_for_log("hello", 0), "");
        assert_eq!(truncate_for_log("", 10), "");
    }

    #[test]
    fn handles_a_string_that_is_entirely_one_multibyte_char() {
        assert_eq!(truncate_for_log("\u{1F600}", 2), "");
    }
}
