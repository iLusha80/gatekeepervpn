use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::UdpSocket;

use gatekeeper_client::{connection, handshake, test_mode};
use gatekeeper_common::config::keys;
use gatekeeper_common::{ClientConfig, PacketObfuscator};

#[derive(Parser, Debug)]
#[command(name = "gatekeeper-client")]
#[command(about = "GatekeeperVPN Client")]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "client.toml")]
    config: String,

    /// Server address (overrides config)
    #[arg(short, long)]
    server: Option<String>,

    /// Test mode: send a message and exit (no TUN)
    #[arg(short, long)]
    test: bool,

    /// Message to send in test mode
    #[arg(short, long, default_value = "Hello from GatekeeperVPN!")]
    message: String,
}

fn load_config(path: &str) -> Result<ClientConfig> {
    if Path::new(path).exists() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;
        toml::from_str(&content).with_context(|| format!("Failed to parse config file: {}", path))
    } else {
        log::warn!("Config file not found: {}, using defaults", path);
        Ok(ClientConfig::default())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    // Load config
    let mut config = load_config(&args.config)?;

    // Override with CLI args
    if let Some(server) = args.server {
        config.server = server;
    }

    // Validate config
    if config.private_key.is_empty() {
        log::warn!("No private key configured, generating ephemeral keypair");
        let keypair = gatekeeper_common::crypto::generate_keypair()?;
        config.private_key = keys::encode(&keypair.private);
        log::info!("Client public key: {}", keys::encode(&keypair.public));
    }

    if config.server_public_key.is_empty() {
        anyhow::bail!("Server public key is required. Set 'server_public_key' in config.");
    }

    let private_key = keys::decode(&config.private_key).context("Invalid private key format")?;
    let server_public_key =
        keys::decode(&config.server_public_key).context("Invalid server public key format")?;

    // Create obfuscator
    let obfuscator = PacketObfuscator::new(&config.obfuscation, &server_public_key)
        .context("Failed to create packet obfuscator")?;
    if config.obfuscation.enabled {
        if obfuscator.generated_psk().is_some() {
            log::info!("Obfuscation PSK auto-derived from server public key");
        }
        log::info!(
            "Packet obfuscation enabled (header_size={}, padding={}-{}, junk={}-{})",
            config.obfuscation.header_size,
            config.obfuscation.min_padding,
            config.obfuscation.max_padding,
            config.obfuscation.junk_min,
            config.obfuscation.junk_max
        );
    }
    let obfuscator = Arc::new(obfuscator);

    if args.test {
        // Test mode - single connection, no reconnect
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket
            .connect(&config.server)
            .await
            .with_context(|| format!("Failed to connect to {}", config.server))?;

        log::info!("Connecting to server: {}", config.server);

        let mut transport =
            handshake::perform_handshake(&socket, &private_key, &server_public_key, &obfuscator)
                .await?;
        test_mode::run_test_mode(&socket, &mut transport, &args.message, &obfuscator).await?;
    } else {
        // VPN mode with reconnection support
        connection::run_with_reconnect(&config, &private_key, &server_public_key, obfuscator)
            .await?;
    }

    Ok(())
}
