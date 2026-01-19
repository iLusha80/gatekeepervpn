//! GatekeeperVPN Server
//!
//! VPN server with:
//! - Per-client authorization via peers.toml
//! - Unicast routing based on destination IP
//! - Hot-reload of peers configuration

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::time::interval;

use gatekeeper_common::config::keys;
use gatekeeper_common::{
    Error as CommonError, NatConfig, Packet, PacketType, PeersConfig, Responder, ServerConfig,
    Transport, TunConfig, TunDevice, VpnErrorLoggers, configure_socket, enable_ip_forwarding,
    get_destination_ip, print_nat_instructions, setup_nat,
};

/// Default peers file location
const DEFAULT_PEERS_FILE: &str = "/etc/gatekeeper/peers.toml";
/// Interval for checking peers.toml changes
const PEERS_RELOAD_INTERVAL_SECS: u64 = 5;

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
}

/// Connected client session
#[allow(dead_code)]
struct ConnectedClient {
    /// Transport state for encryption/decryption
    transport: Transport,
    /// Client's public key (for future use: key rotation, audit logs)
    public_key: [u8; 32],
    /// Assigned VPN IP address (stored for reference, routing uses ip_to_addr map)
    assigned_ip: Ipv4Addr,
    /// Client name from peers.toml
    name: String,
    /// Last activity timestamp
    last_activity: Instant,
}

/// Authorized peer info (from peers.toml)
#[derive(Clone)]
struct AuthorizedPeer {
    name: String,
    public_key: [u8; 32],
    assigned_ip: Ipv4Addr,
}

/// Server state
struct Server {
    /// Server's private key
    private_key: Vec<u8>,
    /// Connected clients by socket address
    clients_by_addr: HashMap<SocketAddr, ConnectedClient>,
    /// Map VPN IP -> socket address (for unicast routing)
    ip_to_addr: HashMap<Ipv4Addr, SocketAddr>,
    /// Authorized peers (white list from peers.toml)
    authorized_peers: HashMap<[u8; 32], AuthorizedPeer>,
    /// Authorization enabled
    auth_enabled: bool,
}

impl Server {
    fn new(private_key: Vec<u8>, auth_enabled: bool) -> Self {
        Self {
            private_key,
            clients_by_addr: HashMap::new(),
            ip_to_addr: HashMap::new(),
            authorized_peers: HashMap::new(),
            auth_enabled,
        }
    }

    /// Load authorized peers from PeersConfig
    fn load_peers(&mut self, peers_config: &PeersConfig) {
        self.authorized_peers.clear();

        for peer in &peers_config.peers {
            if let Ok(key_bytes) = keys::decode(&peer.public_key) {
                if key_bytes.len() == 32 {
                    let mut key_array = [0u8; 32];
                    key_array.copy_from_slice(&key_bytes);

                    self.authorized_peers.insert(
                        key_array,
                        AuthorizedPeer {
                            name: peer.name.clone(),
                            public_key: key_array,
                            assigned_ip: peer.assigned_ip,
                        },
                    );
                }
            }
        }

        log::info!(
            "Loaded {} authorized peer(s) from peers.toml",
            self.authorized_peers.len()
        );
    }

    /// Reload peers (hot-reload)
    fn reload_peers(&mut self, peers_config: &PeersConfig) {
        let old_count = self.authorized_peers.len();
        self.load_peers(peers_config);
        let new_count = self.authorized_peers.len();

        if new_count != old_count {
            log::info!(
                "Peers reloaded: {} -> {} authorized peer(s)",
                old_count,
                new_count
            );
        }
    }

    /// Check if a public key is authorized
    fn is_authorized(&self, public_key: &[u8; 32]) -> Option<&AuthorizedPeer> {
        if !self.auth_enabled {
            return None; // Auth disabled, return None but allow
        }
        self.authorized_peers.get(public_key)
    }

    /// Handle handshake init from a client
    fn handle_handshake(
        &mut self,
        addr: SocketAddr,
        payload: &[u8],
    ) -> Result<(Packet, Transport, Option<AuthorizedPeer>)> {
        log::info!("[{}] Handshake init received", addr);

        // Create new responder for this client
        let mut responder =
            Responder::new(&self.private_key).context("Failed to create responder")?;

        // Process handshake init message
        responder
            .read_message(payload)
            .context("Failed to read handshake init")?;

        // Get client's public key
        let remote_key = responder
            .get_remote_static()
            .context("Failed to get remote public key")?;

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(remote_key);

        log::info!("[{}] Client public key: {}", addr, keys::encode(&key_array));

        // Check authorization
        let authorized_peer = if self.auth_enabled {
            match self.is_authorized(&key_array) {
                Some(peer) => {
                    log::info!(
                        "[{}] Client '{}' authorized (IP: {})",
                        addr,
                        peer.name,
                        peer.assigned_ip
                    );
                    Some(peer.clone())
                }
                None => {
                    log::warn!("[{}] Unauthorized client, rejecting", addr);
                    anyhow::bail!("Client not authorized");
                }
            }
        } else {
            log::info!("[{}] Authorization disabled, allowing connection", addr);
            None
        };

        // Generate response
        let response = responder
            .write_message(&[])
            .context("Failed to write handshake response")?;

        log::info!("[{}] Handshake complete", addr);

        // Convert to transport mode
        let transport = responder
            .into_transport()
            .context("Failed to enter transport mode")?;

        Ok((
            Packet::handshake_response(response),
            transport,
            authorized_peer,
        ))
    }

    /// Register a connected client
    fn register_client(
        &mut self,
        addr: SocketAddr,
        transport: Transport,
        public_key: [u8; 32],
        peer: Option<AuthorizedPeer>,
    ) {
        let (name, assigned_ip) = if let Some(p) = peer {
            (p.name, p.assigned_ip)
        } else {
            // For unauthorized mode, assign a temporary name and IP
            let name = format!("unknown-{}", addr.port());
            let assigned_ip = Ipv4Addr::new(0, 0, 0, 0);
            (name, assigned_ip)
        };

        // Remove any existing mapping for this IP
        if assigned_ip != Ipv4Addr::new(0, 0, 0, 0) {
            self.ip_to_addr.insert(assigned_ip, addr);
        }

        let client = ConnectedClient {
            transport,
            public_key,
            assigned_ip,
            name,
            last_activity: Instant::now(),
        };

        self.clients_by_addr.insert(addr, client);
    }

    /// Remove a disconnected client (for future use: timeout handling)
    #[allow(dead_code)]
    fn remove_client(&mut self, addr: &SocketAddr) {
        if let Some(client) = self.clients_by_addr.remove(addr) {
            self.ip_to_addr.remove(&client.assigned_ip);
            log::info!(
                "[{}] Client '{}' disconnected (IP: {})",
                addr,
                client.name,
                client.assigned_ip
            );
        }
    }

    /// Get socket address for a VPN IP (unicast routing)
    fn get_addr_for_ip(&self, ip: Ipv4Addr) -> Option<SocketAddr> {
        self.ip_to_addr.get(&ip).copied()
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

fn load_peers_config(path: &Path) -> Result<PeersConfig> {
    if path.exists() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read peers file: {}", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse peers file: {}", path.display()))
    } else {
        log::warn!(
            "Peers file not found: {}, authorization disabled",
            path.display()
        );
        Ok(PeersConfig::default())
    }
}

fn get_file_modified_time(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
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
                    Ok((response, transport, peer)) => {
                        let mut key_array = [0u8; 32];
                        if let Some(ref p) = peer {
                            key_array = p.public_key;
                        }
                        server.register_client(addr, transport, key_array, peer);
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
                    match server.clients_by_addr.get_mut(&addr) {
                        Some(client) => {
                            client.last_activity = Instant::now();
                            match client.transport.decrypt(&packet.payload) {
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
                                    match client.transport.encrypt(response_data.as_bytes()) {
                                        Ok(encrypted) => Some(Packet::data(encrypted)),
                                        Err(e) => {
                                            log::error!("[{}] Encrypt error: {}", addr, e);
                                            None
                                        }
                                    }
                                }
                                Err(e) => {
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
                    if server.clients_by_addr.contains_key(&addr) {
                        if let Some(client) = server.clients_by_addr.get_mut(&addr) {
                            client.last_activity = Instant::now();
                        }
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

/// VPN mode: forward traffic between UDP and TUN with unicast routing
async fn run_vpn_mode(
    socket: Arc<UdpSocket>,
    server: Arc<Mutex<Server>>,
    config: &ServerConfig,
    peers_path: PathBuf,
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

    // Setup NAT if enabled
    let subnet = config
        .tun_address
        .rsplitn(2, '.')
        .skip(1)
        .next()
        .unwrap_or("10.0.0");
    let vpn_subnet = format!("{}.0/24", subnet);

    if config.enable_nat {
        log::info!("Configuring NAT...");

        // Enable IP forwarding
        if let Err(e) = enable_ip_forwarding() {
            log::error!("Failed to enable IP forwarding: {}", e);
            log::error!("NAT will not work without IP forwarding!");
            print_nat_instructions(tun_device.name(), &vpn_subnet);
        } else {
            // Setup NAT rules
            let nat_config = NatConfig {
                tun_interface: tun_device.name().to_string(),
                external_interface: config.external_interface.clone(),
                vpn_subnet: vpn_subnet.clone(),
            };

            if let Err(e) = setup_nat(&nat_config) {
                log::error!("Failed to setup NAT: {}", e);
                log::error!("You may need to configure NAT manually:");
                print_nat_instructions(tun_device.name(), &vpn_subnet);
            } else {
                log::info!("NAT configured successfully on interface {}", config.external_interface);
            }
        }
    } else {
        log::warn!("NAT configuration disabled (enable_nat = false)");
        log::warn!("Clients will not have internet access unless you configure NAT manually:");
        print_nat_instructions(tun_device.name(), &vpn_subnet);
    }

    let (mut tun_reader, mut tun_writer) = tun_device.split();

    // Rate-limited error loggers
    let error_loggers = Arc::new(VpnErrorLoggers::new());

    let socket_tx = socket.clone();
    let socket_rx = socket;
    let server_tx = server.clone();
    let server_rx = server.clone();
    let server_reload = server;
    let loggers_rx = error_loggers.clone();
    let loggers_tx = error_loggers;

    // Task 0: Hot-reload peers.toml
    let peers_watcher = tokio::spawn(async move {
        let mut last_modified = get_file_modified_time(&peers_path);
        let mut check_interval = interval(Duration::from_secs(PEERS_RELOAD_INTERVAL_SECS));

        loop {
            check_interval.tick().await;

            let current_modified = get_file_modified_time(&peers_path);

            if current_modified != last_modified {
                log::info!("peers.toml changed, reloading...");

                match load_peers_config(&peers_path) {
                    Ok(new_peers) => {
                        let mut server = server_reload.lock().await;
                        server.reload_peers(&new_peers);
                    }
                    Err(e) => {
                        log::error!("Failed to reload peers.toml: {}", e);
                    }
                }

                last_modified = current_modified;
            }
        }
    });

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
                    Ok((response, transport, peer)) => {
                        let mut key_array = [0u8; 32];
                        if let Some(ref p) = peer {
                            key_array = p.public_key;
                        }
                        server.register_client(addr, transport, key_array, peer);
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
                    if let Some(client) = server.clients_by_addr.get_mut(&addr) {
                        client.last_activity = Instant::now();
                        match client.transport.decrypt(&packet.payload) {
                            Ok(plaintext) => {
                                log::debug!(
                                    "[{}] {} UDP -> TUN: {} bytes",
                                    addr,
                                    client.name,
                                    plaintext.len()
                                );
                                if let Err(e) = tun_writer.write(&plaintext).await {
                                    loggers_rx
                                        .tun_write
                                        .warn(&format!("TUN write error: {}", e));
                                }
                            }
                            Err(e) => {
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
                    if let Some(client) = server.clients_by_addr.get_mut(&addr) {
                        client.last_activity = Instant::now();
                        log::debug!("[{}] {} KeepAlive received", addr, client.name);
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

    // Task 2: TUN -> UDP (outgoing to clients) with UNICAST routing
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

            // Parse destination IP from packet for unicast routing
            let dst_ip = match get_destination_ip(&buf[..n]) {
                Ok(ip) => ip,
                Err(_) => {
                    log::debug!("Failed to parse destination IP, skipping packet");
                    continue;
                }
            };

            let mut server = server_tx.lock().await;

            // Unicast: find the specific client for this destination IP
            if let Some(addr) = server.get_addr_for_ip(dst_ip) {
                if let Some(client) = server.clients_by_addr.get_mut(&addr) {
                    match client.transport.encrypt(&buf[..n]) {
                        Ok(encrypted) => {
                            let packet = Packet::data(encrypted);
                            if let Err(e) = socket_tx.send_to(&packet.encode(), addr).await {
                                loggers_tx
                                    .udp_send
                                    .warn(&format!("[{}] UDP send error: {}", addr, e));
                            } else {
                                log::debug!("TUN -> UDP [{}] {}: {} bytes", addr, client.name, n);
                            }
                        }
                        Err(e) => {
                            log::error!("[{}] Encrypt error: {}", addr, e);
                        }
                    }
                }
            } else {
                // Destination IP not found - could be a broadcast or unknown destination
                log::debug!("No route for destination IP: {}", dst_ip);
            }
        }
    });

    tokio::select! {
        _ = udp_to_tun => log::error!("UDP->TUN task finished unexpectedly"),
        _ = tun_to_udp => log::error!("TUN->UDP task finished unexpectedly"),
        _ = peers_watcher => log::error!("Peers watcher task finished unexpectedly"),
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

    if args.echo {
        log::info!("Running in ECHO mode (no TUN)");
        run_echo_mode(socket, server).await
    } else {
        log::info!("Running in VPN mode");
        run_vpn_mode(socket, server, &config, peers_path).await
    }
}
