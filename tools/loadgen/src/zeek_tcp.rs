//! `loadgen zeek-tcp` -- paced TCP Zeek NDJSON load generator.
//!
//! Unlike `syslog-udp`'s one-datagram-per-message model, Zeek's TCP
//! listener (`src/zeek/listener.rs`) is connection-oriented: it reads
//! newline-delimited JSON off one persistent stream, the way a real log
//! shipper (e.g. filebeat tailing a `.log` file) does. This subcommand
//! opens ONE TCP connection and holds it for the whole run, writing
//! `\n`-terminated JSON records through a `BufWriter` so a 10k/s run isn't
//! one syscall per record.
//!
//! On any write error the run aborts immediately rather than reconnecting:
//! a silent reconnect-and-resume would paper over exactly the server-side
//! backpressure this generator exists to help measure.

use anyhow::Context;
use clap::Args;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::time::MissedTickBehavior;

use crate::pacing::tick_record_count;

#[derive(Args, Debug)]
pub struct ZeekTcpArgs {
    /// Target host to open the Zeek TCP connection to.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Target TCP port. Matches `ZeekListenerConfig::default()`'s
    /// `tcp_port` (see `src/zeek/listener.rs`).
    #[arg(long, default_value_t = 47760)]
    pub port: u16,

    /// Target sustained rate, in records/sec. 0 means "unbounded" (write as
    /// fast as the connection will accept, no pacing).
    #[arg(long, default_value_t = 10_000)]
    pub target_rate: u64,

    /// How long to send for, in seconds.
    #[arg(long, default_value_t = 60)]
    pub duration_secs: u64,

    /// Which Zeek stream (`_path`) to emit records for. `"conn"` emits the
    /// real conn.log field set; any other value exercises the listener's
    /// envelope-schema fallback path with a generic field set.
    #[arg(long, default_value = "conn")]
    pub log_path: String,
}

pub async fn run(args: ZeekTcpArgs) -> anyhow::Result<()> {
    let target_addr = format!("{}:{}", args.host, args.port);
    let stream = TcpStream::connect(&target_addr)
        .await
        .with_context(|| format!("connect TCP stream to {target_addr}"))?;
    let mut writer = BufWriter::new(stream);

    println!(
        "loadgen zeek-tcp: sending to {target_addr} at target_rate={} rec/s for {}s (log_path={})",
        args.target_rate, args.duration_secs, args.log_path
    );

    let duration = Duration::from_secs(args.duration_secs);
    let start = Instant::now();
    let mut sent: u64 = 0;

    // Write errors are handled here rather than bubbled straight out of the
    // loops below so we can report `sent` before aborting -- a partial run
    // is still interpretable if we say how far it got.
    let write_result: anyhow::Result<()> = async {
        if args.target_rate == 0 {
            // Unbounded: write as fast as the connection will accept.
            while start.elapsed() < duration {
                write_record(&mut writer, sent, &args.log_path).await?;
                sent += 1;
            }
        } else {
            // Same 1ms-tick, fractional-carry pacing as syslog-udp -- see
            // `crate::pacing` for why the carry accumulator is shared rather
            // than reimplemented here.
            let per_tick_interval = crate::pacing::TICK;
            let records_per_tick_target = args.target_rate as f64 * per_tick_interval.as_secs_f64();
            let mut ticker = tokio::time::interval(per_tick_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Burst);
            let mut carry: f64 = 0.0;

            'send_loop: loop {
                if start.elapsed() >= duration {
                    break;
                }
                ticker.tick().await;
                let records_this_tick = tick_record_count(&mut carry, records_per_tick_target);
                for _ in 0..records_this_tick {
                    if start.elapsed() >= duration {
                        break 'send_loop;
                    }
                    write_record(&mut writer, sent, &args.log_path).await?;
                    sent += 1;
                }
            }
        }

        // Flush the tail of the run -- BufWriter otherwise leaves the last
        // partial buffer unsent once the process exits.
        writer.flush().await.context("flush zeek TCP stream")?;
        Ok(())
    }
    .await;

    if let Err(e) = write_result {
        eprintln!(
            "loadgen zeek-tcp: write error after {sent} records written -- aborting, no reconnect: {e:#}"
        );
        return Err(e);
    }

    let elapsed = start.elapsed();
    println!(
        "loadgen zeek-tcp: sent {sent} records in {:.3}s (achieved rate: {:.1} rec/s)",
        elapsed.as_secs_f64(),
        sent as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}

async fn write_record(
    writer: &mut BufWriter<TcpStream>,
    n: u64,
    log_path: &str,
) -> anyhow::Result<()> {
    let line = build_record(n, log_path);
    writer
        .write_all(line.as_bytes())
        .await
        .context("write zeek record")?;
    writer
        .write_all(b"\n")
        .await
        .context("write zeek record newline")?;
    Ok(())
}

/// Build one Zeek NDJSON record for `log_path`. No trailing newline -- the
/// caller appends `\n` when writing.
///
/// `n` seeds `uid`, `id.orig_p`, and `orig_bytes`/`resp_bytes` so consecutive
/// records are genuinely distinct rows, not the same row repeated N times.
fn build_record(n: u64, log_path: &str) -> String {
    let now = chrono::Utc::now();
    let ts = now.timestamp() as f64 + f64::from(now.timestamp_subsec_micros()) / 1e6;

    let value = if log_path == "conn" {
        // Real conn.log field set. Zeek's own JSON output uses flat, literally
        // dotted keys for the connection 4-tuple (not a nested "id" object) --
        // see `src/zeek/schema.rs`'s `json_str(value, "id.orig_h")` lookups.
        json!({
            "_path": "conn",
            "ts": ts,
            "uid": format!("CLoadgen{n:016x}"),
            "id.orig_h": format!("10.0.{}.{}", (n / 256) % 256, n % 256),
            "id.orig_p": 1024 + (n % 60_000),
            "id.resp_h": "10.1.0.1",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF",
            "orig_bytes": 100 + (n % 10_000),
            "resp_bytes": 200 + ((n * 7) % 20_000),
            "duration": 0.01 + (n % 1000) as f64 / 1000.0,
        })
    } else {
        // No modelled schema for this stream (e.g. "weird") -- a generic but
        // still varying field set is enough to exercise the listener's
        // envelope-schema fallback path without pretending to know a real
        // field set we don't model.
        json!({
            "_path": log_path,
            "ts": ts,
            "uid": format!("CLoadgen{n:016x}"),
            "seq": n,
            "note": "loadgen synthetic record",
        })
    };

    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard against silent wire-format drift: build a record
    /// with logthing's OWN `zeek::parse_line` (not a hand-rolled JSON
    /// shape check) and assert it round-trips.
    #[test]
    fn conn_record_parses_with_logthings_own_parser() {
        let line = build_record(42, "conn");
        let parsed = logthing::zeek::parse_line(&line, chrono::Utc::now())
            .expect("loadgen zeek line must parse with logthing's own parser");
        assert_eq!(parsed.record.log_path, "conn");
        assert!(!parsed.path_was_missing);
    }

    /// A generator emitting identical rows N times measures the wrong thing:
    /// two records at different sequence numbers must differ in `uid`.
    #[test]
    fn distinct_sequence_numbers_yield_distinct_uids() {
        let a = logthing::zeek::parse_line(&build_record(1, "conn"), chrono::Utc::now()).unwrap();
        let b = logthing::zeek::parse_line(&build_record(2, "conn"), chrono::Utc::now()).unwrap();
        assert_ne!(a.record.fields["uid"], b.record.fields["uid"]);
    }

    /// `--log-path` values outside the modelled set (e.g. "weird") must
    /// still produce parseable NDJSON, and the listener's real `_path`
    /// must survive rather than falling back to "unknown".
    #[test]
    fn unmodelled_stream_still_parses_with_its_own_log_path() {
        let line = build_record(1, "weird");
        let parsed = logthing::zeek::parse_line(&line, chrono::Utc::now())
            .expect("unmodelled-stream loadgen line must still parse");
        assert_eq!(parsed.record.log_path, "weird");
        assert!(!parsed.path_was_missing);
    }
}
