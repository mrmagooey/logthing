//! `loadgen` -- wire-format load generator for a live `logthing` instance.
//!
//! Three of the seven formats in
//! `docs/superpowers/specs/2026-07-05-performance-testing-strategy-design.md`
//! are implemented: `syslog-udp`, `zeek-tcp`, `ipfix-udp`. The remaining four
//! (suricata, sflow, hec, otlp) are still deferred -- see that design's
//! "Deferred" section for what each would need. Suricata is the cheapest next
//! one: it is the same TCP NDJSON shape as `zeek-tcp`.

mod ipfix_udp;
mod pacing;
mod syslog_udp;
mod zeek_tcp;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "loadgen", about = "logthing wire-format load generator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Send syslog messages over UDP at a paced rate.
    SyslogUdp(syslog_udp::SyslogUdpArgs),
    /// Send Zeek NDJSON records over a single TCP connection at a paced rate.
    ZeekTcp(zeek_tcp::ZeekTcpArgs),
    /// Send IPFIX v10 datagrams over UDP at a paced rate, re-sending the
    /// template set on an interval as a real exporter does.
    IpfixUdp(ipfix_udp::IpfixUdpArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::SyslogUdp(args) => syslog_udp::run(args).await,
        Command::ZeekTcp(args) => zeek_tcp::run(args).await,
        Command::IpfixUdp(args) => ipfix_udp::run(args).await,
    }
}
