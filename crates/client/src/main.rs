use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "gatekeeper-client")]
#[command(about = "GatekeeperVPN Client")]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "client.toml")]
    config: String,

    /// Server address
    #[arg(short, long)]
    server: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    log::info!("Starting GatekeeperVPN client");
    log::info!("Config: {}", args.config);

    // TODO: Load config
    // TODO: Connect to server
    // TODO: Perform handshake
    // TODO: Create TUN interface

    Ok(())
}
