use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use gatekeeper_common::config::keys;
use gatekeeper_common::{ClientConfig, Initiator, Packet, PacketType};

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

    /// Message to send (for testing)
    #[arg(short, long, default_value = "Hello from GatekeeperVPN!")]
    message: String,
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const RECV_TIMEOUT: Duration = Duration::from_secs(10);

fn load_config(path: &str) -> Result<ClientConfig> {
    if Path::new(path).exists() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path))
    } else {
        log::warn!("Config file not found: {}, using defaults", path);
        Ok(ClientConfig::default())
    }
}

async fn recv_packet(socket: &UdpSocket, timeout_duration: Duration) -> Result<Packet> {
    let mut buf = vec![0u8; 65535];

    let len = timeout(timeout_duration, socket.recv(&mut buf))
        .await
        .context("Receive timeout")?
        .context("Failed to receive packet")?;

    let data = Bytes::copy_from_slice(&buf[..len]);
    Packet::decode(data).context("Failed to decode packet")
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
        anyhow::bail!("Server public key is required. Set 'server_public_key' in config or use --server-public-key");
    }

    let private_key = keys::decode(&config.private_key)
        .context("Invalid private key format")?;
    let server_public_key = keys::decode(&config.server_public_key)
        .context("Invalid server public key format")?;

    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(&config.server).await
        .with_context(|| format!("Failed to connect to {}", config.server))?;

    log::info!("Connecting to server: {}", config.server);

    // === HANDSHAKE ===
    log::info!("Starting handshake...");

    let mut initiator = Initiator::new(&private_key, &server_public_key)
        .context("Failed to create initiator")?;

    // Send handshake init
    let init_msg = initiator.write_message(&[])
        .context("Failed to create handshake init")?;
    let init_packet = Packet::handshake_init(init_msg);

    socket.send(&init_packet.encode()).await
        .context("Failed to send handshake init")?;
    log::debug!("Sent handshake init ({} bytes)", init_packet.encode().len());

    // Receive handshake response
    let response_packet = timeout(HANDSHAKE_TIMEOUT, recv_packet(&socket, HANDSHAKE_TIMEOUT))
        .await
        .context("Handshake timeout")?
        .context("Failed to receive handshake response")?;

    if response_packet.packet_type != PacketType::HandshakeResponse {
        anyhow::bail!("Expected HandshakeResponse, got {:?}", response_packet.packet_type);
    }

    // Process response
    initiator.read_message(&response_packet.payload)
        .context("Failed to process handshake response")?;

    if !initiator.is_finished() {
        anyhow::bail!("Handshake not completed after response");
    }

    log::info!("Handshake complete!");

    // Convert to transport mode
    let mut transport = initiator.into_transport()
        .context("Failed to enter transport mode")?;

    // === SEND TEST MESSAGE ===
    log::info!("Sending message: {}", args.message);

    let encrypted = transport.encrypt(args.message.as_bytes())
        .context("Failed to encrypt message")?;
    let data_packet = Packet::data(encrypted);

    socket.send(&data_packet.encode()).await
        .context("Failed to send data")?;

    // Receive echo response
    let echo_packet = recv_packet(&socket, RECV_TIMEOUT)
        .await
        .context("Failed to receive echo response")?;

    if echo_packet.packet_type != PacketType::Data {
        anyhow::bail!("Expected Data packet, got {:?}", echo_packet.packet_type);
    }

    let decrypted = transport.decrypt(&echo_packet.payload)
        .context("Failed to decrypt response")?;

    log::info!("Received: {}", String::from_utf8_lossy(&decrypted));

    log::info!("Connection test successful!");

    Ok(())
}
