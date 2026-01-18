use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use gatekeeper_common::config::keys;
use gatekeeper_common::{Packet, PacketType, Responder, ServerConfig, Transport};

#[derive(Parser, Debug)]
#[command(name = "gatekeeper-server")]
#[command(about = "GatekeeperVPN Server")]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "server.toml")]
    config: String,

    /// Listen address (overrides config)
    #[arg(short, long)]
    listen: Option<String>,
}

/// Client session state (transport ready after handshake)
type ClientState = Transport;

/// Server state
struct Server {
    /// Server's private key
    private_key: Vec<u8>,
    /// Connected clients
    clients: HashMap<SocketAddr, ClientState>,
}

impl Server {
    fn new(private_key: Vec<u8>) -> Self {
        Self {
            private_key,
            clients: HashMap::new(),
        }
    }

    /// Handle incoming packet from a client
    fn handle_packet(&mut self, addr: SocketAddr, packet: Packet) -> Result<Option<Packet>> {
        match packet.packet_type {
            PacketType::HandshakeInit => {
                log::info!("[{}] Handshake init received", addr);

                // Create new responder for this client
                let mut responder = Responder::new(&self.private_key)
                    .context("Failed to create responder")?;

                // Process handshake init message
                let payload = responder
                    .read_message(&packet.payload)
                    .context("Failed to read handshake init")?;

                if !payload.is_empty() {
                    log::debug!("[{}] Handshake payload: {:?}", addr, payload);
                }

                // Generate response
                let response = responder
                    .write_message(&[])
                    .context("Failed to write handshake response")?;

                // IK handshake completes in 2 messages
                log::info!("[{}] Handshake complete", addr);
                if let Some(remote_key) = responder.get_remote_static() {
                    log::info!("[{}] Client public key: {}", addr, keys::encode(remote_key));
                }

                // Convert to transport mode
                let transport = responder
                    .into_transport()
                    .context("Failed to enter transport mode")?;
                self.clients.insert(addr, transport);

                Ok(Some(Packet::handshake_response(response)))
            }

            PacketType::HandshakeResponse => {
                log::warn!("[{}] Unexpected handshake response from client", addr);
                Ok(None)
            }

            PacketType::Data => {
                // Get client's transport state
                match self.clients.get_mut(&addr) {
                    Some(transport) => {
                        // Decrypt the data
                        let plaintext = transport
                            .decrypt(&packet.payload)
                            .context("Failed to decrypt packet")?;

                        log::info!(
                            "[{}] Received: {} ({} bytes)",
                            addr,
                            String::from_utf8_lossy(&plaintext),
                            plaintext.len()
                        );

                        // Echo back (encrypted)
                        let response_data = format!("Echo: {}", String::from_utf8_lossy(&plaintext));
                        let encrypted = transport
                            .encrypt(response_data.as_bytes())
                            .context("Failed to encrypt response")?;

                        Ok(Some(Packet::data(encrypted)))
                    }
                    None => {
                        log::warn!("[{}] Data from unknown client", addr);
                        Ok(None)
                    }
                }
            }
        }
    }
}

fn load_config(path: &str) -> Result<ServerConfig> {
    if Path::new(path).exists() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path))
    } else {
        log::warn!("Config file not found: {}, using defaults", path);
        Ok(ServerConfig::default())
    }
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
        // Generate a new keypair for demo purposes
        log::warn!("No private key configured, generating ephemeral keypair");
        let keypair = gatekeeper_common::crypto::generate_keypair()?;
        config.private_key = keys::encode(&keypair.private);
        log::info!("Server public key: {}", keys::encode(&keypair.public));
        log::info!("(Save this in client config as server_public_key)");
    }

    let private_key = keys::decode(&config.private_key)
        .context("Invalid private key format")?;

    // Create UDP socket
    let socket = UdpSocket::bind(&config.listen)
        .await
        .with_context(|| format!("Failed to bind to {}", config.listen))?;

    log::info!("GatekeeperVPN server listening on {}", config.listen);

    let server = Arc::new(Mutex::new(Server::new(private_key)));
    let mut buf = vec![0u8; 65535];

    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let data = Bytes::copy_from_slice(&buf[..len]);

        log::debug!("[{}] Received {} bytes", addr, len);

        // Parse packet
        let packet = match Packet::decode(data) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("[{}] Invalid packet: {}", addr, e);
                continue;
            }
        };

        // Handle packet
        let response = {
            let mut server = server.lock().await;
            server.handle_packet(addr, packet)
        };

        match response {
            Ok(Some(response_packet)) => {
                let response_data = response_packet.encode();
                if let Err(e) = socket.send_to(&response_data, addr).await {
                    log::error!("[{}] Failed to send response: {}", addr, e);
                }
            }
            Ok(None) => {}
            Err(e) => {
                log::error!("[{}] Error handling packet: {}", addr, e);
            }
        }
    }
}
