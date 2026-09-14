//! Stub — filled in by Task 10. Registered up front so `main.rs` is written
//! once and the two new subcommands never contend for it.
use clap::Args;

#[derive(Args, Debug)]
pub struct IpfixUdpArgs {}

pub async fn run(_args: IpfixUdpArgs) -> anyhow::Result<()> {
    anyhow::bail!("not yet implemented")
}
