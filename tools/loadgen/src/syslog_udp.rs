//! `loadgen syslog-udp` -- paced UDP syslog load generator.
//!
//! Encodes messages matching the two wire shapes `logthing`'s syslog parser
//! (`logthing::syslog::SyslogMessage::parse`, RFC3164 branch) actually
//! accepts:
//! - Raw (`--structured` off, default): a plain RFC3164 line with a free-text
//!   message body -- exercises header parsing only.
//! - Structured (`--structured` on): the RFC3164 message body is a CEF
//!   payload (`CEF:0|...`), which additionally exercises
//!   `logthing::syslog::payload::dispatch`'s sub-parser try-chain when the
//!   server has `parse_payloads=true` -- see
//!   `docs/superpowers/specs/2026-07-05-performance-testing-strategy-design.md`
//!   §3's note on this being the meaningfully heavier cost path.
//!
//! Each UDP datagram is exactly one message, with NO trailing newline: the
//! `regex` crate's `.` does not match `\n` by default, so a trailing
//! newline would make `logthing`'s `$`-anchored RFC3164 regex fail to
//! match the whole datagram.

use anyhow::Context;
use chrono::{Datelike, Timelike, Utc};
use clap::Args;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::MissedTickBehavior;

#[derive(Args, Debug)]
pub struct SyslogUdpArgs {
    /// Target host to send UDP syslog datagrams to.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Target UDP port. Matches `SyslogConfig`'s real default
    /// (`default_syslog_udp_port() -> 514`); override for a CI run bound to
    /// a non-privileged port.
    #[arg(long, default_value_t = 514)]
    pub port: u16,

    /// Target sustained rate, in records/sec. 0 means "unbounded" (send as
    /// fast as the socket will accept, no pacing).
    #[arg(long, default_value_t = 10_000)]
    pub target_rate: u64,

    /// How long to send for, in seconds.
    #[arg(long, default_value_t = 60)]
    pub duration_secs: u64,

    /// Send CEF-payload messages (exercises the `parse_payloads` sub-parser
    /// chain) instead of plain free-text RFC3164 messages.
    #[arg(long, default_value_t = false)]
    pub structured: bool,
}

pub async fn run(args: SyslogUdpArgs) -> anyhow::Result<()> {
    let target: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .with_context(|| format!("invalid target address {}:{}", args.host, args.port))?;

    // Bind an ephemeral local UDP socket, then `connect` it to fix the peer
    // so sends use `send` instead of `send_to` -- one syscall's worth of
    // argument marshalling less per datagram at high rates. The server side
    // still sees each of these as an independent `recv_from` datagram
    // (UDP has no real "connection"), matching its existing listener
    // behavior exactly.
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind local UDP socket")?;
    socket
        .connect(target)
        .await
        .context("connect UDP socket to target")?;

    println!(
        "loadgen syslog-udp: sending to {target} at target_rate={} rec/s for {}s (structured={})",
        args.target_rate, args.duration_secs, args.structured
    );

    let duration = Duration::from_secs(args.duration_secs);
    let start = Instant::now();
    let mut sent: u64 = 0;

    if args.target_rate == 0 {
        // Unbounded: send as fast as the socket will accept.
        while start.elapsed() < duration {
            let msg = build_message(sent, args.structured);
            socket
                .send(msg.as_bytes())
                .await
                .context("send UDP datagram")?;
            sent += 1;
        }
    } else {
        // Paced: same 1ms-tick, N-per-tick pattern already established by
        // examples/flush_decoupling_benchmark.rs for TCP pacing -- ticks
        // faster than practical per-record timer resolution would allow,
        // batching multiple sends per tick instead of chasing unrealistic
        // per-record timer precision.
        let per_tick_interval = Duration::from_micros(1000);
        let records_per_tick_target = args.target_rate as f64 * per_tick_interval.as_secs_f64();
        let mut ticker = tokio::time::interval(per_tick_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Burst);
        // Fractional accumulator: at low rates `records_per_tick_target` is
        // below 1 (e.g. target_rate=100 -> 0.1/tick), so rounding per tick
        // would floor to 0 forever or clamp to 1 forever -- either loses the
        // requested rate entirely. Accumulating the fractional remainder and
        // emitting whenever it crosses an integer boundary honors the target
        // rate exactly over many ticks instead.
        let mut carry: f64 = 0.0;

        'send_loop: loop {
            if start.elapsed() >= duration {
                break;
            }
            ticker.tick().await;
            carry += records_per_tick_target;
            let records_this_tick = carry.floor() as u64;
            carry -= records_this_tick as f64;
            for _ in 0..records_this_tick {
                if start.elapsed() >= duration {
                    break 'send_loop;
                }
                let msg = build_message(sent, args.structured);
                socket
                    .send(msg.as_bytes())
                    .await
                    .context("send UDP datagram")?;
                sent += 1;
            }
        }
    }

    let elapsed = start.elapsed();
    println!(
        "loadgen syslog-udp: sent {sent} datagrams in {:.3}s (achieved rate: {:.1} rec/s)",
        elapsed.as_secs_f64(),
        sent as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}

/// Build one syslog message. No trailing newline (see module doc comment).
fn build_message(n: u64, structured: bool) -> String {
    let now = Utc::now();
    // RFC3164 timestamp: "Mon D HH:MM:SS" (day is NOT zero-padded --
    // RFC3164_TS_RE in logthing::syslog accepts 1-2 digit days either way).
    let timestamp = format!(
        "{} {} {:02}:{:02}:{:02}",
        month_abbrev(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let hostname = "loadgen-host";
    let pri = 134; // facility=16 (local0) * 8 + severity=6 (informational)

    if structured {
        format!(
            "<{pri}>{timestamp} {hostname} loadgen: CEF:0|Loadgen|SyntheticFirewall|1.0|100|\
             Synthetic Blocked Connection|5|src=10.0.{}.{} dst=10.1.0.1 spt={} dpt=443 cnt={n}",
            (n / 256) % 256,
            n % 256,
            1024 + (n % 60_000),
        )
    } else {
        format!(
            "<{pri}>{timestamp} {hostname} loadgen[{}]: synthetic load-test message #{n}",
            std::process::id(),
        )
    }
}

fn month_abbrev(m: u32) -> &'static str {
    const NAMES: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    NAMES[(m as usize).saturating_sub(1).min(11)]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard against silent wire-format drift: build a message
    /// with logthing's OWN `SyslogMessage::parse` (not a hand-rolled
    /// regex copy) and assert it round-trips. This is the cheapest possible
    /// proof that this subcommand's bytes are real, parser-accepted syslog.
    #[test]
    fn raw_message_parses_as_rfc3164() {
        let msg = build_message(42, false);
        let parsed = logthing::syslog::SyslogMessage::parse(&msg)
            .expect("raw loadgen message must parse as RFC3164");
        assert_eq!(parsed.hostname.as_deref(), Some("loadgen-host"));
        assert!(parsed.message.contains("synthetic load-test message #42"));
    }

    #[test]
    fn structured_message_parses_and_message_field_starts_with_cef() {
        let msg = build_message(7, true);
        let parsed = logthing::syslog::SyslogMessage::parse(&msg)
            .expect("structured loadgen message must parse as RFC3164");
        assert!(
            parsed.message.starts_with("CEF:"),
            "message field must start with CEF: for the cef sub-parser to match, got: {}",
            parsed.message
        );
    }
}
