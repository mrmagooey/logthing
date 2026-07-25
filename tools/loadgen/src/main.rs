//! `loadgen` -- wire-format load generator for a live `logthing` instance.
//!
//! Concrete first deliverable: exactly one subcommand, `syslog-udp` (see
//! `src/syslog_udp.rs`). The other 6 formats (ipfix, zeek, suricata, sflow,
//! hec, otlp) are deliberately not implemented yet -- see
//! `docs/superpowers/plans/2026-07-24-performance-testing-infrastructure.md`'s
//! "Deferred" section for what each would need.

mod syslog_udp;

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::SyslogUdp(args) => syslog_udp::run(args).await,
    }
}
