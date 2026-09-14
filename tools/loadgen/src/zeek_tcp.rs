//! Stub — filled in by Task 9. Registered up front so `main.rs` is written
//! once and the two new subcommands never contend for it.
use clap::Args;

#[derive(Args, Debug)]
pub struct ZeekTcpArgs {}

pub async fn run(_args: ZeekTcpArgs) -> anyhow::Result<()> {
    anyhow::bail!("not yet implemented")
}
