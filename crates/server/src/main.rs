//! GatekeeperVPN Server
//!
//! VPN server with:
//! - Per-client authorization via peers.toml
//! - Unicast routing based on destination IP
//! - Hot-reload of peers configuration

mod config;
mod echo;
mod server;
mod signal;
mod vpn;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use gatekeeper_common::config::keys;
use gatekeeper_common::{PacketObfuscator, VpnMetrics, configure_socket};

use crate::config::{DEFAULT_PEERS_FILE, load_config, load_peers_config};
use crate::server::Server;

#[derive(Parser, Debug)]
#[command(name = "gatekeeper-server")]
#[command(about = "GatekeeperVPN Server")]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "server.toml")]
    config: String,

    /// Path to peers file
    #[arg(short, long, default_value = DEFAULT_PEERS_FILE)]
    peers: String,

    /// Listen address (overrides config)
    #[arg(short, long)]
    listen: Option<String>,

    /// Echo mode: don't create TUN, just echo packets back
    #[arg(short, long)]
    echo: bool,

    /// Disable peer authorization (allow any client)
    #[arg(long)]
    no_auth: bool,

    /// Enable metrics collection and stats file output
    #[arg(long)]
    stats: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    // Load config
    let mut config = load_config(&args.config)?;

    // Override with CLI args
    if let Some(listen) = args.listen {
        config.listen = listen;
    }

    // Check if private key is set
    if config.private_key.is_empty() {
        log::warn!("No private key configured, generating ephemeral keypair");
        let keypair = gatekeeper_common::crypto::generate_keypair()?;
        config.private_key = keys::encode(&keypair.private);
        log::info!("Server public key: {}", keys::encode(&keypair.public));
        log::info!("(Save this in client config as server_public_key)");
    }

    let private_key = keys::decode(&config.private_key).context("Invalid private key format")?;
    let server_public_key = gatekeeper_common::crypto::public_key_from_private(&private_key)
        .context("Failed to derive server public key")?;

    // Create server with authorization
    let auth_enabled = !args.no_auth;
    let server = Arc::new(Mutex::new(Server::new(private_key, auth_enabled)));

    // Load peers configuration
    let peers_path = PathBuf::from(&args.peers);
    if auth_enabled {
        match load_peers_config(&peers_path) {
            Ok(peers_config) => {
                let mut srv = server.lock().await;
                srv.load_peers(&peers_config);
            }
            Err(e) => {
                log::warn!("Failed to load peers.toml: {}. Authorization disabled.", e);
                let mut srv = server.lock().await;
                srv.auth_enabled = false;
            }
        }
    } else {
        log::warn!("Authorization disabled (--no-auth flag)");
    }

    // Create UDP socket
    let socket = UdpSocket::bind(&config.listen)
        .await
        .with_context(|| format!("Failed to bind to {}", config.listen))?;

    // Configure socket buffers for high-throughput
    if let Err(e) = configure_socket(&socket) {
        log::warn!("Failed to configure socket buffers: {}", e);
    }

    log::info!("GatekeeperVPN server listening on {}", config.listen);

    let socket = Arc::new(socket);
    let metrics = Arc::new(VpnMetrics::new());

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

    if args.echo {
        log::info!("Running in ECHO mode (no TUN)");
        echo::run_echo_mode(socket, server, metrics, obfuscator).await
    } else {
        log::info!("Running in VPN mode");
        if args.stats {
            log::info!("Stats enabled, writing to: {}", config.stats_file);
        }
        vpn::run_vpn_mode(
            socket, server, &config, peers_path, metrics, args.stats, obfuscator,
        )
        .await
    }
}
