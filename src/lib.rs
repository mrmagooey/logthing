// Library target — single authoritative module home for all crate modules.
// The binary target (main.rs) uses `logthing::` instead of re-declaring modules.

// result_large_err misfires on idiomatic axum `Result<T, Response>` handlers
// (clippy 1.98 counts the >=128-byte Response as an oversized Err variant);
// these are cold admin endpoints, boxing would be noise for no benefit.
#[allow(clippy::result_large_err)]
pub mod admin;
pub mod config;
pub mod forwarding;
pub mod ingest;
pub mod ipfix;
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
