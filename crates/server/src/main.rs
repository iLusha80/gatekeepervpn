use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "gatekeeper-server")]
#[command(about = "GatekeeperVPN Server")]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "server.toml")]
    config: String,

    /// Listen address
    #[arg(short, long, default_value = "0.0.0.0:51820")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    log::info!("Starting GatekeeperVPN server on {}", args.listen);

    // TODO: Initialize server
    // TODO: Load config
    // TODO: Start listening for connections

    Ok(())
}
