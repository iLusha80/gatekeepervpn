use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::sync::Mutex;

use gatekeeper_common::config::keys;
use gatekeeper_common::{
    Error as CommonError, Packet, PacketType, Responder, ServerConfig, Transport, TunConfig,
    TunDevice, VpnErrorLoggers, configure_socket, print_nat_instructions,
};

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

    /// Echo mode: don't create TUN, just echo packets back
    #[arg(short, long)]
    echo: bool,
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

    /// Handle handshake init from a client
    fn handle_handshake(
        &mut self,
        addr: SocketAddr,
        payload: &[u8],
    ) -> Result<(Packet, Transport)> {
        log::info!("[{}] Handshake init received", addr);

        // Create new responder for this client
        let mut responder =
            Responder::new(&self.private_key).context("Failed to create responder")?;

        // Process handshake init message
        responder
            .read_message(payload)
            .context("Failed to read handshake init")?;

        // Generate response
        let response = responder
            .write_message(&[])
            .context("Failed to write handshake response")?;

        log::info!("[{}] Handshake complete", addr);
        if let Some(remote_key) = responder.get_remote_static() {
            log::info!("[{}] Client public key: {}", addr, keys::encode(remote_key));
        }

        // Convert to transport mode
        let transport = responder
            .into_transport()
            .context("Failed to enter transport mode")?;

        Ok((Packet::handshake_response(response), transport))
    }
}

fn load_config(path: &str) -> Result<ServerConfig> {
    if Path::new(path).exists() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;
        toml::from_str(&content).with_context(|| format!("Failed to parse config file: {}", path))
    } else {
        log::warn!("Config file not found: {}, using defaults", path);
        Ok(ServerConfig::default())
    }
}

/// Echo mode: just echo back decrypted data
async fn run_echo_mode(socket: Arc<UdpSocket>, server: Arc<Mutex<Server>>) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    let error_loggers = VpnErrorLoggers::new();

    loop {
        // Wait for packet or shutdown signal
        let (len, addr) = tokio::select! {
            result = socket.recv_from(&mut buf) => result?,
            _ = signal::ctrl_c() => {
                log::info!("Received shutdown signal (Ctrl+C)");
                log::info!("Server shutting down...");
                return Ok(());
            }
        };
        let data = Bytes::copy_from_slice(&buf[..len]);

        let packet = match Packet::decode(data) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("[{}] Invalid packet: {}", addr, e);
                continue;
            }
        };

        let response = {
            let mut server = server.lock().await;

            match packet.packet_type {
                PacketType::HandshakeInit => match server.handle_handshake(addr, &packet.payload) {
                    Ok((response, transport)) => {
                        server.clients.insert(addr, transport);
                        Some(response)
                    }
                    Err(e) => {
                        log::error!("[{}] Handshake error: {}", addr, e);
                        None
                    }
                },
                PacketType::HandshakeResponse => {
                    log::warn!("[{}] Unexpected handshake response", addr);
                    None
                }
                PacketType::Data => {
                    match server.clients.get_mut(&addr) {
                        Some(transport) => {
                            match transport.decrypt(&packet.payload) {
                                Ok(plaintext) => {
                                    log::info!(
                                        "[{}] Received: {} ({} bytes)",
                                        addr,
                                        String::from_utf8_lossy(&plaintext),
                                        plaintext.len()
                                    );

                                    // Echo back
                                    let response_data =
                                        format!("Echo: {}", String::from_utf8_lossy(&plaintext));
                                    match transport.encrypt(response_data.as_bytes()) {
                                        Ok(encrypted) => Some(Packet::data(encrypted)),
                                        Err(e) => {
                                            log::error!("[{}] Encrypt error: {}", addr, e);
                                            None
                                        }
                                    }
                                }
                                Err(e) => {
                                    // Differentiate between replay and crypto errors
                                    if matches!(e, CommonError::ReplayedPacket) {
                                        error_loggers.decrypt_replay.debug(&format!(
                                            "[{}] Replayed/out-of-order packet dropped",
                                            addr
                                        ));
                                    } else {
                                        error_loggers
                                            .decrypt_crypto
                                            .warn(&format!("[{}] Decrypt error: {}", addr, e));
                                    }
                                    None
                                }
                            }
                        }
                        None => {
                            log::warn!("[{}] Data from unknown client", addr);
                            None
                        }
                    }
                }
                PacketType::KeepAlive => {
                    if server.clients.contains_key(&addr) {
                        log::debug!("[{}] KeepAlive received", addr);
                        Some(Packet::keep_alive_ack())
                    } else {
                        log::warn!("[{}] KeepAlive from unknown client", addr);
                        None
                    }
                }
                PacketType::KeepAliveAck => {
                    log::debug!("[{}] Unexpected KeepAliveAck from client", addr);
                    None
                }
            }
        };

        if let Some(response_packet) = response {
            if let Err(e) = socket.send_to(&response_packet.encode(), addr).await {
                log::error!("[{}] Failed to send response: {}", addr, e);
            }
        }
    }
}

/// VPN mode: forward traffic between UDP and TUN
async fn run_vpn_mode(
    socket: Arc<UdpSocket>,
    server: Arc<Mutex<Server>>,
    config: &ServerConfig,
) -> Result<()> {
    // Parse TUN config
    let tun_address: Ipv4Addr = config.tun_address.parse().context("Invalid TUN address")?;
    let tun_netmask: Ipv4Addr = config.tun_netmask.parse().context("Invalid TUN netmask")?;

    let tun_config = TunConfig {
        name: None,
        address: tun_address,
        netmask: tun_netmask,
        mtu: config.tun_mtu,
    };

    // Create TUN device (requires root)
    let tun_device = TunDevice::create(tun_config)
        .await
        .context("Failed to create TUN device. Are you running as root?")?;

    log::info!("VPN server TUN interface: {}", tun_device.name());

    // Print NAT setup instructions
    // Simplified: assume /24 subnet based on server address (e.g., 10.0.0.1 -> 10.0.0.0/24)
    let subnet = config
        .tun_address
        .rsplitn(2, '.')
        .skip(1)
        .next()
        .unwrap_or("10.0.0");
    let vpn_subnet = format!("{}.0/24", subnet);
    print_nat_instructions(tun_device.name(), &vpn_subnet);

    let (mut tun_reader, mut tun_writer) = tun_device.split();

    // Rate-limited error loggers
    let error_loggers = Arc::new(VpnErrorLoggers::new());

    let socket_tx = socket.clone();
    let socket_rx = socket;
    let server_tx = server.clone();
    let server_rx = server;
    let loggers_rx = error_loggers.clone();
    let loggers_tx = error_loggers;

    // Task 1: UDP -> TUN (incoming from clients)
    let udp_to_tun = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];

        loop {
            let (len, addr) = match socket_rx.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    log::error!("UDP recv error: {}", e);
                    continue;
                }
            };

            let data = Bytes::copy_from_slice(&buf[..len]);
            let packet = match Packet::decode(data) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("[{}] Invalid packet: {}", addr, e);
                    continue;
                }
            };

            let mut server = server_rx.lock().await;

            match packet.packet_type {
                PacketType::HandshakeInit => match server.handle_handshake(addr, &packet.payload) {
                    Ok((response, transport)) => {
                        server.clients.insert(addr, transport);
                        if let Err(e) = socket_rx.send_to(&response.encode(), addr).await {
                            log::error!("[{}] Failed to send handshake response: {}", addr, e);
                        }
                    }
                    Err(e) => {
                        log::error!("[{}] Handshake error: {}", addr, e);
                    }
                },
                PacketType::HandshakeResponse => {
                    log::warn!("[{}] Unexpected handshake response", addr);
                }
                PacketType::Data => {
                    if let Some(transport) = server.clients.get_mut(&addr) {
                        match transport.decrypt(&packet.payload) {
                            Ok(plaintext) => {
                                log::debug!("[{}] UDP -> TUN: {} bytes", addr, plaintext.len());
                                if let Err(e) = tun_writer.write(&plaintext).await {
                                    loggers_rx
                                        .tun_write
                                        .warn(&format!("TUN write error: {}", e));
                                }
                            }
                            Err(e) => {
                                // Differentiate between replay and crypto errors
                                if matches!(e, CommonError::ReplayedPacket) {
                                    loggers_rx.decrypt_replay.debug(&format!(
                                        "[{}] Replayed/out-of-order packet dropped",
                                        addr
                                    ));
                                } else {
                                    loggers_rx
                                        .decrypt_crypto
                                        .warn(&format!("[{}] Decrypt error: {}", addr, e));
                                }
                            }
                        }
                    } else {
                        log::warn!("[{}] Data from unknown client", addr);
                    }
                }
                PacketType::KeepAlive => {
                    if server.clients.contains_key(&addr) {
                        log::debug!("[{}] KeepAlive received", addr);
                        let response = Packet::keep_alive_ack();
                        if let Err(e) = socket_rx.send_to(&response.encode(), addr).await {
                            log::error!("[{}] Failed to send KeepAliveAck: {}", addr, e);
                        }
                    } else {
                        log::warn!("[{}] KeepAlive from unknown client", addr);
                    }
                }
                PacketType::KeepAliveAck => {
                    log::debug!("[{}] Unexpected KeepAliveAck from client", addr);
                }
            }
        }
    });

    // Task 2: TUN -> UDP (outgoing to clients)
    // Note: Simple implementation sends to first connected client
    // A real VPN would parse IP headers to determine destination
    let tun_to_udp = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];

        loop {
            let n = match tun_reader.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                Ok(_) => continue,
                Err(e) => {
                    log::error!("TUN read error: {}", e);
                    continue;
                }
            };

            let server = server_tx.lock().await;

            // Send to all connected clients (broadcast for simplicity)
            // A real VPN would route based on IP destination
            for (addr, _transport) in server.clients.iter() {
                // Note: We need mutable access to transport for encryption
                // This is a simplified version - real impl would use separate
                // encryption state or lock per client
                log::debug!("TUN -> UDP [{}]: {} bytes", addr, n);
            }
            drop(server);

            // For now, we need a different approach for TUN -> UDP
            // because we need mutable access to transport
            let mut server = server_tx.lock().await;
            let client_addrs: Vec<_> = server.clients.keys().copied().collect();

            for addr in client_addrs {
                if let Some(transport) = server.clients.get_mut(&addr) {
                    match transport.encrypt(&buf[..n]) {
                        Ok(encrypted) => {
                            let packet = Packet::data(encrypted);
                            if let Err(e) = socket_tx.send_to(&packet.encode(), addr).await {
                                loggers_tx
                                    .udp_send
                                    .warn(&format!("[{}] UDP send error: {}", addr, e));
                            }
                        }
                        Err(e) => {
                            log::error!("[{}] Encrypt error: {}", addr, e);
                        }
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = udp_to_tun => log::error!("UDP->TUN task finished unexpectedly"),
        _ = tun_to_udp => log::error!("TUN->UDP task finished unexpectedly"),
        _ = signal::ctrl_c() => {
            log::info!("Received shutdown signal (Ctrl+C)");
            log::info!("Server shutting down...");
        }
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
    let server = Arc::new(Mutex::new(Server::new(private_key)));

    if args.echo {
        log::info!("Running in ECHO mode (no TUN)");
        run_echo_mode(socket, server).await
    } else {
        log::info!("Running in VPN mode");
        run_vpn_mode(socket, server, &config).await
    }
}
