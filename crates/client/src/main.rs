use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

use gatekeeper_common::config::keys;
use gatekeeper_common::{ClientConfig, Initiator, Packet, PacketType, Transport, TunConfig, TunDevice};

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

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

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

async fn perform_handshake(
    socket: &UdpSocket,
    private_key: &[u8],
    server_public_key: &[u8],
) -> Result<Transport> {
    log::info!("Starting handshake...");

    let mut initiator = Initiator::new(private_key, server_public_key)
        .context("Failed to create initiator")?;

    // Send handshake init
    let init_msg = initiator.write_message(&[])
        .context("Failed to create handshake init")?;
    let init_packet = Packet::handshake_init(init_msg);

    socket.send(&init_packet.encode()).await
        .context("Failed to send handshake init")?;

    // Receive handshake response
    let response_packet = recv_packet(socket, HANDSHAKE_TIMEOUT)
        .await
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

    initiator.into_transport()
        .context("Failed to enter transport mode")
}

/// Test mode: send a message and receive echo
async fn run_test_mode(
    socket: &UdpSocket,
    transport: &mut Transport,
    message: &str,
) -> Result<()> {
    log::info!("Test mode: sending message: {}", message);

    let encrypted = transport.encrypt(message.as_bytes())
        .context("Failed to encrypt message")?;
    let data_packet = Packet::data(encrypted);

    socket.send(&data_packet.encode()).await
        .context("Failed to send data")?;

    // Receive echo response
    let echo_packet = recv_packet(socket, Duration::from_secs(10))
        .await
        .context("Failed to receive echo response")?;

    if echo_packet.packet_type != PacketType::Data {
        anyhow::bail!("Expected Data packet, got {:?}", echo_packet.packet_type);
    }

    let decrypted = transport.decrypt(&echo_packet.payload)
        .context("Failed to decrypt response")?;

    log::info!("Received: {}", String::from_utf8_lossy(&decrypted));
    log::info!("Test successful!");

    Ok(())
}

/// VPN mode: tunnel traffic through TUN interface
async fn run_vpn_mode(
    socket: Arc<UdpSocket>,
    transport: Arc<Mutex<Transport>>,
    config: &ClientConfig,
) -> Result<()> {
    // Parse TUN config
    let tun_address: Ipv4Addr = config.tun_address.parse()
        .context("Invalid TUN address")?;
    let tun_netmask: Ipv4Addr = config.tun_netmask.parse()
        .context("Invalid TUN netmask")?;

    let tun_config = TunConfig {
        name: None,
        address: tun_address,
        netmask: tun_netmask,
        mtu: config.tun_mtu,
    };

    // Create TUN device (requires root)
    let tun_device = TunDevice::create(tun_config).await
        .context("Failed to create TUN device. Are you running as root?")?;

    log::info!("VPN tunnel established on {}", tun_device.name());

    // Split TUN device for concurrent read/write
    let (mut tun_reader, mut tun_writer) = tun_device.split();

    // Clone for tasks
    let socket_tx = socket.clone();
    let socket_rx = socket;
    let transport_tx = transport.clone();
    let transport_rx = transport;

    // Task 1: TUN -> UDP (outgoing traffic)
    let outgoing = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            // Read IP packet from TUN
            let n = match tun_reader.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                Ok(_) => continue,
                Err(e) => {
                    log::error!("TUN read error: {}", e);
                    break;
                }
            };

            log::debug!("TUN -> UDP: {} bytes", n);

            // Encrypt and send
            let encrypted = {
                let mut transport = transport_tx.lock().await;
                match transport.encrypt(&buf[..n]) {
                    Ok(data) => data,
                    Err(e) => {
                        log::error!("Encrypt error: {}", e);
                        continue;
                    }
                }
            };

            let packet = Packet::data(encrypted);
            if let Err(e) = socket_tx.send(&packet.encode()).await {
                log::error!("UDP send error: {}", e);
            }
        }
    });

    // Task 2: UDP -> TUN (incoming traffic)
    let incoming = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            // Receive encrypted packet from server
            let n = match socket_rx.recv(&mut buf).await {
                Ok(n) if n > 0 => n,
                Ok(_) => continue,
                Err(e) => {
                    log::error!("UDP recv error: {}", e);
                    break;
                }
            };

            // Decode packet
            let packet = match Packet::decode(Bytes::copy_from_slice(&buf[..n])) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("Invalid packet: {}", e);
                    continue;
                }
            };

            if packet.packet_type != PacketType::Data {
                log::warn!("Unexpected packet type: {:?}", packet.packet_type);
                continue;
            }

            // Decrypt
            let plaintext = {
                let mut transport = transport_rx.lock().await;
                match transport.decrypt(&packet.payload) {
                    Ok(data) => data,
                    Err(e) => {
                        log::error!("Decrypt error: {}", e);
                        continue;
                    }
                }
            };

            log::debug!("UDP -> TUN: {} bytes", plaintext.len());

            // Write to TUN
            if let Err(e) = tun_writer.write(&plaintext).await {
                log::error!("TUN write error: {}", e);
            }
        }
    });

    // Wait for either task to finish (shouldn't happen normally)
    tokio::select! {
        _ = outgoing => log::error!("Outgoing task finished unexpectedly"),
        _ = incoming => log::error!("Incoming task finished unexpectedly"),
    }

    Ok(())
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

    let private_key = keys::decode(&config.private_key)
        .context("Invalid private key format")?;
    let server_public_key = keys::decode(&config.server_public_key)
        .context("Invalid server public key format")?;

    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(&config.server).await
        .with_context(|| format!("Failed to connect to {}", config.server))?;

    log::info!("Connecting to server: {}", config.server);

    // Perform handshake
    let transport = perform_handshake(&socket, &private_key, &server_public_key).await?;

    if args.test {
        // Test mode
        let mut transport = transport;
        run_test_mode(&socket, &mut transport, &args.message).await?;
    } else {
        // VPN mode
        let socket = Arc::new(socket);
        let transport = Arc::new(Mutex::new(transport));
        run_vpn_mode(socket, transport, &config).await?;
    }

    Ok(())
}
