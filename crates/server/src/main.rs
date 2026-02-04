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
    CookieState, Error as CommonError, HandshakeRateLimiter, NatConfig, Packet, PacketObfuscator,
    PacketType, PeersConfig, RateLimitDecision, Responder, ServerConfig, Transport, TunConfig,
    TunDevice, VpnErrorLoggers, VpnMetrics, cleanup_nat, configure_socket, enable_ip_forwarding,
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

    /// Enable metrics collection and stats file output
    #[arg(long)]
    stats: bool,
}

/// Connected client session
struct ConnectedClient {
    /// Transport state for encryption/decryption
    transport: Transport,
    /// Assigned VPN IP address
    assigned_ip: Ipv4Addr,
    /// Client name from peers.toml
    name: String,
    /// Last activity timestamp
    last_activity: Instant,
    /// Current UDP endpoint (mutable — changes on roaming)
    endpoint: SocketAddr,
}

/// Authorized peer info (from peers.toml)
#[derive(Clone)]
struct AuthorizedPeer {
    name: String,
    assigned_ip: Ipv4Addr,
}

/// Server state
struct Server {
    /// Server's private key
    private_key: Vec<u8>,
    /// Connected clients by VPN IP (primary key)
    clients: HashMap<Ipv4Addr, ConnectedClient>,
    /// Reverse index: UDP endpoint -> VPN IP (for fast lookup)
    endpoint_to_ip: HashMap<SocketAddr, Ipv4Addr>,
    /// Authorized peers (white list from peers.toml)
    authorized_peers: HashMap<[u8; 32], AuthorizedPeer>,
    /// Authorization enabled
    auth_enabled: bool,
    /// Cookie state for DoS protection
    cookie_state: CookieState,
    /// Handshake rate limiter
    rate_limiter: HandshakeRateLimiter,
}

impl Server {
    fn new(private_key: Vec<u8>, auth_enabled: bool) -> Self {
        Self {
            private_key,
            clients: HashMap::new(),
            endpoint_to_ip: HashMap::new(),
            authorized_peers: HashMap::new(),
            auth_enabled,
            cookie_state: CookieState::new(),
            rate_limiter: HandshakeRateLimiter::new(),
        }
    }

    /// Number of connected clients
    fn client_count(&self) -> usize {
        self.clients.len()
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

        // Remove old endpoint mapping if this IP was already connected
        if let Some(old_client) = self.clients.get(&assigned_ip) {
            self.endpoint_to_ip.remove(&old_client.endpoint);
        }

        let client = ConnectedClient {
            transport,
            assigned_ip,
            name,
            last_activity: Instant::now(),
            endpoint: addr,
        };

        if assigned_ip != Ipv4Addr::new(0, 0, 0, 0) {
            self.clients.insert(assigned_ip, client);
            self.endpoint_to_ip.insert(addr, assigned_ip);
        }
    }

    /// Remove a disconnected client by VPN IP
    fn remove_client_by_ip(&mut self, vpn_ip: &Ipv4Addr) {
        if let Some(client) = self.clients.remove(vpn_ip) {
            self.endpoint_to_ip.remove(&client.endpoint);
            log::info!(
                "[{}] Client '{}' disconnected (IP: {})",
                client.endpoint,
                client.name,
                client.assigned_ip
            );
        }
    }

    /// Update client endpoint after roaming detection
    fn update_client_endpoint(&mut self, vpn_ip: &Ipv4Addr, new_addr: SocketAddr) {
        if let Some(client) = self.clients.get_mut(vpn_ip) {
            let old_addr = client.endpoint;
            self.endpoint_to_ip.remove(&old_addr);
            client.endpoint = new_addr;
            client.last_activity = Instant::now();
            self.endpoint_to_ip.insert(new_addr, *vpn_ip);
            log::info!(
                "Roaming detected for '{}' (IP: {}): {} -> {}",
                client.name,
                vpn_ip,
                old_addr,
                new_addr
            );
        }
    }

    /// Try to find a client that can decrypt this payload (brute-force roaming detection)
    fn detect_roaming(&self, payload: &[u8]) -> Option<Ipv4Addr> {
        for (vpn_ip, client) in &self.clients {
            if client.transport.can_decrypt(payload) {
                return Some(*vpn_ip);
            }
        }
        None
    }

    /// Remove clients inactive for longer than the given timeout
    fn cleanup_inactive_clients(&mut self, timeout: Duration) -> usize {
        let now = Instant::now();
        let inactive: Vec<Ipv4Addr> = self
            .clients
            .iter()
            .filter(|(_, client)| now.duration_since(client.last_activity) > timeout)
            .map(|(ip, _)| *ip)
            .collect();

        let count = inactive.len();
        for ip in inactive {
            self.remove_client_by_ip(&ip);
        }
        count
    }

    /// Get client for a VPN IP (unicast routing)
    fn get_client_for_ip(&self, ip: Ipv4Addr) -> Option<&ConnectedClient> {
        self.clients.get(&ip)
    }

    /// Get client by endpoint address
    fn get_client_by_endpoint_mut(&mut self, addr: &SocketAddr) -> Option<&mut ConnectedClient> {
        if let Some(vpn_ip) = self.endpoint_to_ip.get(addr) {
            self.clients.get_mut(vpn_ip)
        } else {
            None
        }
    }
}

/// Wait for shutdown signal (SIGINT or SIGTERM)
async fn shutdown_signal() {
    let ctrl_c = signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            signal::unix::signal(signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => log::info!("Received SIGINT (Ctrl+C)"),
            _ = sigterm.recv() => log::info!("Received SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        log::info!("Received shutdown signal");
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
async fn run_echo_mode(
    socket: Arc<UdpSocket>,
    server: Arc<Mutex<Server>>,
    metrics: Arc<VpnMetrics>,
    obfuscator: Arc<PacketObfuscator>,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    let error_loggers = VpnErrorLoggers::new();

    loop {
        // Wait for packet or shutdown signal
        let (len, addr) = tokio::select! {
            result = socket.recv_from(&mut buf) => result?,
            _ = shutdown_signal() => {
                log::info!("Server shutting down...");
                return Ok(());
            }
        };
        let data = Bytes::copy_from_slice(&buf[..len]);

        let packet = match obfuscator.deobfuscate(data) {
            Ok(p) => p,
            Err(_) => {
                // Could be a junk packet — silently ignore
                continue;
            }
        };

        let response = {
            let mut server = server.lock().await;

            // Rotate cookie secret if needed
            server.cookie_state.maybe_rotate();

            match packet.packet_type {
                PacketType::HandshakeInit => {
                    let client_ip = addr.ip();
                    match server.rate_limiter.check(&client_ip) {
                        RateLimitDecision::Drop => {
                            log::debug!("[{}] Handshake dropped (per-IP rate limit)", addr);
                            None
                        }
                        RateLimitDecision::RequireCookie => {
                            log::debug!("[{}] Sending cookie challenge", addr);
                            let cookie = server.cookie_state.generate_cookie(&client_ip);
                            server.rate_limiter.record(&client_ip);
                            Some(Packet::cookie_reply(cookie))
                        }
                        RateLimitDecision::Allow => {
                            server.rate_limiter.record(&client_ip);
                            match server.handle_handshake(addr, &packet.payload) {
                                Ok((response, transport, peer)) => {
                                    server.register_client(addr, transport, peer);
                                    metrics.record_handshake_ok();
                                    metrics.set_active_clients(server.client_count() as u64);
                                    Some(response)
                                }
                                Err(e) => {
                                    log::error!("[{}] Handshake error: {}", addr, e);
                                    metrics.record_handshake_fail();
                                    None
                                }
                            }
                        }
                    }
                }
                PacketType::HandshakeInitCookie => {
                    let client_ip = addr.ip();
                    match server.rate_limiter.check(&client_ip) {
                        RateLimitDecision::Drop => {
                            log::debug!("[{}] Cookie handshake dropped (per-IP rate limit)", addr);
                            None
                        }
                        _ => match packet.parse_cookie_and_payload() {
                            Ok((cookie, handshake_payload)) => {
                                if !server.cookie_state.validate_cookie(&client_ip, &cookie) {
                                    log::warn!("[{}] Invalid cookie, rejecting", addr);
                                    None
                                } else {
                                    server.rate_limiter.record(&client_ip);
                                    match server.handle_handshake(addr, &handshake_payload) {
                                        Ok((response, transport, peer)) => {
                                            server.register_client(addr, transport, peer);
                                            metrics.record_handshake_ok();
                                            metrics
                                                .set_active_clients(server.client_count() as u64);
                                            Some(response)
                                        }
                                        Err(e) => {
                                            log::error!("[{}] Handshake error: {}", addr, e);
                                            metrics.record_handshake_fail();
                                            None
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("[{}] Invalid cookie packet: {}", addr, e);
                                None
                            }
                        },
                    }
                }
                PacketType::HandshakeResponse => {
                    log::warn!("[{}] Unexpected handshake response", addr);
                    None
                }
                PacketType::CookieReply => {
                    log::warn!("[{}] Unexpected CookieReply from client", addr);
                    None
                }
                PacketType::Data => {
                    // Fast path: known endpoint
                    let client = server.get_client_by_endpoint_mut(&addr);
                    if let Some(client) = client {
                        client.last_activity = Instant::now();
                        metrics.record_received(packet.payload.len() as u64);
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
                                    Ok(encrypted) => {
                                        metrics.record_sent(encrypted.len() as u64);
                                        Some(Packet::data(encrypted))
                                    }
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
                                    metrics.record_replay();
                                } else {
                                    error_loggers
                                        .decrypt_crypto
                                        .warn(&format!("[{}] Decrypt error: {}", addr, e));
                                }
                                None
                            }
                        }
                    } else {
                        // Slow path: roaming detection via brute-force decrypt
                        if let Some(vpn_ip) = server.detect_roaming(&packet.payload) {
                            server.update_client_endpoint(&vpn_ip, addr);
                            metrics.record_roaming();
                            // Now decrypt normally
                            if let Some(client) = server.clients.get_mut(&vpn_ip) {
                                client.last_activity = Instant::now();
                                metrics.record_received(packet.payload.len() as u64);
                                match client.transport.decrypt(&packet.payload) {
                                    Ok(plaintext) => {
                                        log::info!(
                                            "[{}] Received (roamed): {} ({} bytes)",
                                            addr,
                                            String::from_utf8_lossy(&plaintext),
                                            plaintext.len()
                                        );
                                        let response_data = format!(
                                            "Echo: {}",
                                            String::from_utf8_lossy(&plaintext)
                                        );
                                        match client.transport.encrypt(response_data.as_bytes()) {
                                            Ok(encrypted) => {
                                                metrics.record_sent(encrypted.len() as u64);
                                                Some(Packet::data(encrypted))
                                            }
                                            Err(e) => {
                                                log::error!("[{}] Encrypt error: {}", addr, e);
                                                None
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        log::error!(
                                            "[{}] Decrypt error after roaming: {}",
                                            addr,
                                            e
                                        );
                                        None
                                    }
                                }
                            } else {
                                None
                            }
                        } else {
                            log::warn!("[{}] Data from unknown client", addr);
                            None
                        }
                    }
                }
                PacketType::KeepAlive => {
                    if let Some(client) = server.get_client_by_endpoint_mut(&addr) {
                        client.last_activity = Instant::now();
                        log::debug!("[{}] KeepAlive received", addr);
                        Some(Packet::keep_alive_ack())
                    } else {
                        log::debug!(
                            "[{}] KeepAlive from unknown endpoint (roaming pending)",
                            addr
                        );
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
            // Send junk packets before handshake response
            if response_packet.packet_type == PacketType::HandshakeResponse {
                let junk_count = obfuscator.junk_count();
                for _ in 0..junk_count {
                    let junk = obfuscator.generate_junk_packet();
                    let _ = socket.send_to(&junk, addr).await;
                }
            }
            if let Err(e) = socket
                .send_to(&obfuscator.obfuscate(&response_packet), addr)
                .await
            {
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
    metrics: Arc<VpnMetrics>,
    enable_stats: bool,
    obfuscator: Arc<PacketObfuscator>,
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

    let tun_name = tun_device.name().to_string();
    log::info!("VPN server TUN interface: {}", tun_name);

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
            print_nat_instructions(&tun_name, &vpn_subnet);
        } else {
            // Setup NAT rules
            let nat_config = NatConfig {
                tun_interface: tun_name.clone(),
                external_interface: config.external_interface.clone(),
                vpn_subnet: vpn_subnet.clone(),
            };

            if let Err(e) = setup_nat(&nat_config) {
                log::error!("Failed to setup NAT: {}", e);
                log::error!("You may need to configure NAT manually:");
                print_nat_instructions(&tun_name, &vpn_subnet);
            } else {
                log::info!(
                    "NAT configured successfully on interface {}",
                    config.external_interface
                );
            }
        }
    } else {
        log::warn!("NAT configuration disabled (enable_nat = false)");
        log::warn!("Clients will not have internet access unless you configure NAT manually:");
        print_nat_instructions(&tun_name, &vpn_subnet);
    }

    let (mut tun_reader, mut tun_writer) = tun_device.split();

    // Rate-limited error loggers
    let error_loggers = Arc::new(VpnErrorLoggers::new());

    let socket_tx = socket.clone();
    let socket_rx = socket;
    let server_tx = server.clone();
    let server_rx = server.clone();
    let server_cleanup_task = server.clone();
    let server_cleanup = server.clone();
    let server_reload = server;
    let loggers_rx = error_loggers.clone();
    let loggers_tx = error_loggers;
    let metrics_rx = metrics.clone();
    let metrics_tx = metrics.clone();
    let metrics_cleanup = metrics.clone();
    let metrics_stats = metrics.clone();
    let obfuscator_rx = obfuscator.clone();
    let obfuscator_tx = obfuscator;

    let client_timeout = config.client_timeout;
    let stats_file = config.stats_file.clone();

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
            let packet = match obfuscator_rx.deobfuscate(data) {
                Ok(p) => p,
                Err(_) => {
                    // Could be a junk packet — silently ignore
                    continue;
                }
            };

            let mut server = server_rx.lock().await;

            // Rotate cookie secret if needed
            server.cookie_state.maybe_rotate();

            match packet.packet_type {
                PacketType::HandshakeInit => {
                    let client_ip = addr.ip();
                    match server.rate_limiter.check(&client_ip) {
                        RateLimitDecision::Drop => {
                            log::debug!("[{}] Handshake dropped (per-IP rate limit)", addr);
                        }
                        RateLimitDecision::RequireCookie => {
                            log::debug!("[{}] Sending cookie challenge", addr);
                            let cookie = server.cookie_state.generate_cookie(&client_ip);
                            server.rate_limiter.record(&client_ip);
                            let reply = Packet::cookie_reply(cookie);
                            if let Err(e) = socket_rx
                                .send_to(&obfuscator_rx.obfuscate(&reply), addr)
                                .await
                            {
                                log::error!("[{}] Failed to send cookie reply: {}", addr, e);
                            }
                        }
                        RateLimitDecision::Allow => {
                            server.rate_limiter.record(&client_ip);
                            match server.handle_handshake(addr, &packet.payload) {
                                Ok((response, transport, peer)) => {
                                    server.register_client(addr, transport, peer);
                                    metrics_rx.record_handshake_ok();
                                    metrics_rx.set_active_clients(server.client_count() as u64);
                                    // Send junk packets before handshake response
                                    let junk_count = obfuscator_rx.junk_count();
                                    for _ in 0..junk_count {
                                        let junk = obfuscator_rx.generate_junk_packet();
                                        let _ = socket_rx.send_to(&junk, addr).await;
                                    }
                                    if let Err(e) = socket_rx
                                        .send_to(&obfuscator_rx.obfuscate(&response), addr)
                                        .await
                                    {
                                        log::error!(
                                            "[{}] Failed to send handshake response: {}",
                                            addr,
                                            e
                                        );
                                    }
                                }
                                Err(e) => {
                                    log::error!("[{}] Handshake error: {}", addr, e);
                                    metrics_rx.record_handshake_fail();
                                }
                            }
                        }
                    }
                }
                PacketType::HandshakeInitCookie => {
                    let client_ip = addr.ip();
                    match server.rate_limiter.check(&client_ip) {
                        RateLimitDecision::Drop => {
                            log::debug!("[{}] Cookie handshake dropped (per-IP rate limit)", addr);
                        }
                        _ => match packet.parse_cookie_and_payload() {
                            Ok((cookie, handshake_payload)) => {
                                if !server.cookie_state.validate_cookie(&client_ip, &cookie) {
                                    log::warn!("[{}] Invalid cookie, rejecting", addr);
                                } else {
                                    server.rate_limiter.record(&client_ip);
                                    match server.handle_handshake(addr, &handshake_payload) {
                                        Ok((response, transport, peer)) => {
                                            server.register_client(addr, transport, peer);
                                            metrics_rx.record_handshake_ok();
                                            metrics_rx
                                                .set_active_clients(server.client_count() as u64);
                                            // Send junk packets before handshake response
                                            let junk_count = obfuscator_rx.junk_count();
                                            for _ in 0..junk_count {
                                                let junk = obfuscator_rx.generate_junk_packet();
                                                let _ = socket_rx.send_to(&junk, addr).await;
                                            }
                                            if let Err(e) = socket_rx
                                                .send_to(&obfuscator_rx.obfuscate(&response), addr)
                                                .await
                                            {
                                                log::error!(
                                                    "[{}] Failed to send handshake response: {}",
                                                    addr,
                                                    e
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            log::error!("[{}] Handshake error: {}", addr, e);
                                            metrics_rx.record_handshake_fail();
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("[{}] Invalid cookie packet: {}", addr, e);
                            }
                        },
                    }
                }
                PacketType::HandshakeResponse => {
                    log::warn!("[{}] Unexpected handshake response", addr);
                }
                PacketType::CookieReply => {
                    log::warn!("[{}] Unexpected CookieReply from client", addr);
                }
                PacketType::Data => {
                    // Fast path: known endpoint
                    let known = server.endpoint_to_ip.contains_key(&addr);
                    if known {
                        if let Some(client) = server.get_client_by_endpoint_mut(&addr) {
                            client.last_activity = Instant::now();
                            metrics_rx.record_received(packet.payload.len() as u64);
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
                                        metrics_rx.record_replay();
                                    } else {
                                        loggers_rx
                                            .decrypt_crypto
                                            .warn(&format!("[{}] Decrypt error: {}", addr, e));
                                    }
                                }
                            }
                        }
                    } else {
                        // Slow path: roaming detection via brute-force decrypt
                        if let Some(vpn_ip) = server.detect_roaming(&packet.payload) {
                            server.update_client_endpoint(&vpn_ip, addr);
                            metrics_rx.record_roaming();
                            // Decrypt after roaming
                            if let Some(client) = server.clients.get_mut(&vpn_ip) {
                                client.last_activity = Instant::now();
                                metrics_rx.record_received(packet.payload.len() as u64);
                                match client.transport.decrypt(&packet.payload) {
                                    Ok(plaintext) => {
                                        log::debug!(
                                            "[{}] {} UDP -> TUN (roamed): {} bytes",
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
                                        log::error!(
                                            "[{}] Decrypt error after roaming: {}",
                                            addr,
                                            e
                                        );
                                    }
                                }
                            }
                        } else {
                            log::warn!("[{}] Data from unknown client", addr);
                        }
                    }
                }
                PacketType::KeepAlive => {
                    if let Some(client) = server.get_client_by_endpoint_mut(&addr) {
                        client.last_activity = Instant::now();
                        log::debug!("[{}] {} KeepAlive received", addr, client.name);
                        let response = Packet::keep_alive_ack();
                        if let Err(e) = socket_rx
                            .send_to(&obfuscator_rx.obfuscate(&response), addr)
                            .await
                        {
                            log::error!("[{}] Failed to send KeepAliveAck: {}", addr, e);
                        }
                    } else {
                        log::debug!(
                            "[{}] KeepAlive from unknown endpoint (roaming pending)",
                            addr
                        );
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

            let server = server_tx.lock().await;

            // Unicast: find the specific client for this destination IP
            if let Some(client) = server.get_client_for_ip(dst_ip) {
                let addr = client.endpoint;
                match client.transport.encrypt(&buf[..n]) {
                    Ok(encrypted) => {
                        metrics_tx.record_sent(encrypted.len() as u64);
                        let packet = Packet::data(encrypted);
                        if let Err(e) = socket_tx
                            .send_to(&obfuscator_tx.obfuscate(&packet), addr)
                            .await
                        {
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
            } else {
                // Destination IP not found - could be a broadcast or unknown destination
                log::debug!("No route for destination IP: {}", dst_ip);
            }
        }
    });

    // Task 3: Cleanup inactive clients
    let cleanup_task = tokio::spawn(async move {
        if client_timeout == 0 {
            // Timeout disabled, wait forever
            std::future::pending::<()>().await;
            return;
        }

        let timeout_duration = Duration::from_secs(client_timeout);
        let mut cleanup_interval = interval(Duration::from_secs(30));

        loop {
            cleanup_interval.tick().await;
            let mut server = server_cleanup_task.lock().await;
            let removed = server.cleanup_inactive_clients(timeout_duration);
            if removed > 0 {
                log::info!(
                    "Cleaned up {} inactive client(s) (timeout: {}s)",
                    removed,
                    client_timeout
                );
                metrics_cleanup.set_active_clients(server.client_count() as u64);
            }
        }
    });

    // Task 4: Stats writer (if enabled)
    let stats_writer = tokio::spawn(async move {
        if !enable_stats {
            std::future::pending::<()>().await;
            return;
        }

        let mut stats_interval = interval(Duration::from_secs(10));
        loop {
            stats_interval.tick().await;
            let json = metrics_stats.to_json();
            if let Err(e) = std::fs::write(&stats_file, &json) {
                log::warn!("Failed to write stats file: {}", e);
            }
            log::debug!("Stats: {}", metrics_stats.format_summary());
        }
    });

    // Build NAT config for cleanup
    let nat_config = if config.enable_nat {
        Some(NatConfig {
            tun_interface: tun_name.clone(),
            external_interface: config.external_interface.clone(),
            vpn_subnet: vpn_subnet.clone(),
        })
    } else {
        None
    };

    tokio::select! {
        _ = udp_to_tun => log::error!("UDP->TUN task finished unexpectedly"),
        _ = tun_to_udp => log::error!("TUN->UDP task finished unexpectedly"),
        _ = peers_watcher => log::error!("Peers watcher task finished unexpectedly"),
        _ = cleanup_task => log::error!("Cleanup task finished unexpectedly"),
        _ = stats_writer => log::error!("Stats writer task finished unexpectedly"),
        _ = shutdown_signal() => {
            log::info!("Server shutting down...");
        }
    }

    // Cleanup NAT rules
    if let Some(ref nat_cfg) = nat_config {
        log::info!("Cleaning up NAT rules...");
        if let Err(e) = cleanup_nat(nat_cfg) {
            log::error!("Failed to cleanup NAT: {}", e);
        }
    }

    let client_count = server_cleanup.lock().await.client_count();
    log::info!("Server stopped. {} client(s) were connected.", client_count);

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
        run_echo_mode(socket, server, metrics, obfuscator).await
    } else {
        log::info!("Running in VPN mode");
        if args.stats {
            log::info!("Stats enabled, writing to: {}", config.stats_file);
        }
        run_vpn_mode(
            socket, server, &config, peers_path, metrics, args.stats, obfuscator,
        )
        .await
    }
}
