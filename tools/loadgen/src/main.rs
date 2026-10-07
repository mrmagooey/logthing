//! `loadgen` -- wire-format load generator for a live `logthing` instance.
//!
//! Every format is implemented: `syslog-udp`, `zeek-tcp`, `ipfix-udp`, `suricata-tcp`,
//! `sflow-udp`, `hec-http`, `generic-http`, `otlp-http`. The three HTTP subcommands treat
//! `503` as backpressure (see `backpressure`) and report it separately from errors.

mod backpressure;
mod generic_http;
mod hec_http;
mod ipfix_udp;
mod otlp_http;
mod pacing;
mod pii;
mod sflow_udp;
mod suricata_tcp;
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
    /// Send Suricata EVE NDJSON records over a single TCP connection at a
    /// paced rate.
    SuricataTcp(suricata_tcp::SuricataTcpArgs),
    /// Send sFlow v5 datagrams over UDP at a paced rate, each carrying one
    /// flow sample and one counter sample.
    SflowUdp(sflow_udp::SflowUdpArgs),
    /// Send Splunk HEC events over HTTP (`/services/collector/event`) at a
    /// paced, concurrent rate.
    HecHttp(hec_http::HecHttpArgs),
    /// Send generic NDJSON records over HTTP (`/ingest`) at a paced,
    /// concurrent rate.
    GenericHttp(generic_http::GenericHttpArgs),
    /// Send OTLP/HTTP protobuf logs (`/v1/logs`) at a paced, concurrent rate.
    OtlpHttp(otlp_http::OtlpHttpArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::SyslogUdp(args) => syslog_udp::run(args).await,
        Command::ZeekTcp(args) => zeek_tcp::run(args).await,
        Command::IpfixUdp(args) => ipfix_udp::run(args).await,
        Command::SuricataTcp(args) => suricata_tcp::run(args).await,
        Command::SflowUdp(args) => sflow_udp::run(args).await,
        Command::HecHttp(args) => hec_http::run(args).await,
        Command::GenericHttp(args) => generic_http::run(args).await,
        Command::OtlpHttp(args) => otlp_http::run(args).await,
    }
}
