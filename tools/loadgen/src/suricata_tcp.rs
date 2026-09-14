//! `loadgen suricata-tcp` -- paced TCP Suricata EVE JSON load generator.
//!
//! Same TCP NDJSON transport as `zeek-tcp` (see that module for the
//! rationale): Suricata's TCP listener (`src/suricata/listener.rs`) is also
//! connection-oriented, reading newline-delimited JSON off one persistent
//! stream. This subcommand opens ONE TCP connection and holds it for the
//! whole run, writing `\n`-terminated JSON records through a `BufWriter` so
//! a 10k/s run isn't one syscall per record.
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
pub struct SuricataTcpArgs {
    /// Target host to open the Suricata TCP connection to.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Target TCP port. Matches `SuricataListenerConfig::default()`'s
    /// `tcp_port` (see `src/suricata/listener.rs`).
    #[arg(long, default_value_t = 47761)]
    pub port: u16,

    /// Target sustained rate, in records/sec. 0 means "unbounded" (write as
    /// fast as the connection will accept, no pacing).
    #[arg(long, default_value_t = 10_000)]
    pub target_rate: u64,

    /// How long to send for, in seconds.
    #[arg(long, default_value_t = 60)]
    pub duration_secs: u64,

    /// Which EVE `event_type` to emit records for. `"alert"` emits the real
    /// alert field set (nested `alert` and `flow` objects); any other value
    /// exercises the listener's fallback path with a generic field set.
    #[arg(long, default_value = "alert")]
    pub event_type: String,
}

pub async fn run(args: SuricataTcpArgs) -> anyhow::Result<()> {
    let target_addr = format!("{}:{}", args.host, args.port);
    let stream = TcpStream::connect(&target_addr)
        .await
        .with_context(|| format!("connect TCP stream to {target_addr}"))?;
    let mut writer = BufWriter::new(stream);

    println!(
        "loadgen suricata-tcp: sending to {target_addr} at target_rate={} rec/s for {}s (event_type={})",
        args.target_rate, args.duration_secs, args.event_type
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
                write_record(&mut writer, sent, &args.event_type).await?;
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
                    write_record(&mut writer, sent, &args.event_type).await?;
                    sent += 1;
                }
            }
        }

        // Flush the tail of the run -- BufWriter otherwise leaves the last
        // partial buffer unsent once the process exits.
        writer.flush().await.context("flush suricata TCP stream")?;
        Ok(())
    }
    .await;

    if let Err(e) = write_result {
        eprintln!(
            "loadgen suricata-tcp: write error after {sent} records written -- aborting, no reconnect: {e:#}"
        );
        return Err(e);
    }

    let elapsed = start.elapsed();
    println!(
        "loadgen suricata-tcp: sent {sent} records in {:.3}s (achieved rate: {:.1} rec/s)",
        elapsed.as_secs_f64(),
        sent as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}

async fn write_record(
    writer: &mut BufWriter<TcpStream>,
    n: u64,
    event_type: &str,
) -> anyhow::Result<()> {
    let line = build_record(n, event_type);
    writer
        .write_all(line.as_bytes())
        .await
        .context("write suricata record")?;
    writer
        .write_all(b"\n")
        .await
        .context("write suricata record newline")?;
    Ok(())
}

/// Build one Suricata EVE NDJSON record for `event_type`. No trailing
/// newline -- the caller appends `\n` when writing.
///
/// `n` seeds `flow_id`, ports and byte counts so consecutive records are
/// genuinely distinct rows, not the same row repeated N times.
fn build_record(n: u64, event_type: &str) -> String {
    let now = chrono::Utc::now();
    let ts = now.to_rfc3339_opts(chrono::SecondsFormat::Micros, false);
    let flow_id = 1_234_567_890_123_456_u64 + n;
    let src_port = 1024 + (n % 60_000);
    let dest_port = 443;

    let value = if event_type == "alert" {
        // Real EVE alert field set -- see `benches/suricata_parse_recv_path.rs`'s
        // `ALERT_LINE` fixture for the shape this mirrors.
        json!({
            "timestamp": ts,
            "flow_id": flow_id,
            "event_type": "alert",
            "src_ip": format!("10.0.{}.{}", (n / 256) % 256, n % 256),
            "src_port": src_port,
            "dest_ip": "10.1.0.1",
            "dest_port": dest_port,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2_013_028,
                "rev": 6,
                "signature": "ET POLICY curl User-Agent Outbound",
                "category": "Attempted Information Leak",
                "severity": 1 + (n % 3),
            },
            "flow": {
                "pkts_toserver": 4 + (n % 20),
                "pkts_toclient": 3 + (n % 15),
                "bytes_toserver": 500 + (n % 10_000),
                "bytes_toclient": 1200 + ((n * 7) % 20_000),
                "start": ts,
            },
        })
    } else {
        // No modelled schema for this event type -- a generic but still
        // varying field set is enough to exercise the listener's fallback
        // path without pretending to know a real field set we don't model.
        json!({
            "timestamp": ts,
            "flow_id": flow_id,
            "event_type": event_type,
            "src_ip": format!("10.0.{}.{}", (n / 256) % 256, n % 256),
            "src_port": src_port,
            "dest_ip": "10.1.0.1",
            "dest_port": dest_port,
            "proto": "TCP",
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
    /// with logthing's OWN `suricata::parse_line` (not a hand-rolled JSON
    /// shape check) and assert it round-trips.
    #[test]
    fn alert_record_parses_with_logthings_own_parser() {
        let line = build_record(42, "alert");
        let parsed = logthing::suricata::parse_line(&line, chrono::Utc::now())
            .expect("loadgen suricata line must parse with logthing's own parser");
        assert_eq!(parsed.record.event_type, "alert");
        assert!(!parsed.event_type_was_missing);
    }

    /// A generator emitting identical rows N times measures the wrong thing:
    /// two records at different sequence numbers must differ in `flow_id`.
    #[test]
    fn distinct_sequence_numbers_yield_distinct_records() {
        let a =
            logthing::suricata::parse_line(&build_record(1, "alert"), chrono::Utc::now()).unwrap();
        let b =
            logthing::suricata::parse_line(&build_record(2, "alert"), chrono::Utc::now()).unwrap();
        assert_ne!(a.record.fields["flow_id"], b.record.fields["flow_id"]);
    }

    /// `--event-type` values outside the modelled set (e.g. "flow") must
    /// still produce parseable NDJSON, and the listener's real `event_type`
    /// must survive rather than falling back to "unknown".
    #[test]
    fn unmodelled_event_type_still_parses_with_its_own_event_type() {
        let line = build_record(1, "flow");
        let parsed = logthing::suricata::parse_line(&line, chrono::Utc::now())
            .expect("unmodelled-event-type loadgen line must still parse");
        assert_eq!(parsed.record.event_type, "flow");
        assert!(!parsed.event_type_was_missing);
    }
}
