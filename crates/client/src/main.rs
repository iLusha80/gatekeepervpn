use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::time::{interval, timeout};

use gatekeeper_common::config::keys;
use gatekeeper_common::{
    ClientConfig, DnsConfig, DnsState, Error as CommonError, Initiator, Packet, PacketObfuscator,
    PacketType, RouteConfig, Transport, TunConfig, TunDevice, TunReader, TunWriter,
    VpnErrorLoggers, VpnMetrics, cleanup_dns, cleanup_routes, configure_socket, setup_dns,
    setup_routes, update_server_route,
};

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

async fn recv_packet(
    socket: &UdpSocket,
    timeout_duration: Duration,
    obfuscator: &PacketObfuscator,
) -> Result<Packet> {
    let mut buf = vec![0u8; 65535];

    loop {
        let len = timeout(timeout_duration, socket.recv(&mut buf))
            .await
            .context("Receive timeout")?
            .context("Failed to receive packet")?;

        let data = Bytes::copy_from_slice(&buf[..len]);
        match obfuscator.deobfuscate(data) {
            Ok(p) => return Ok(p),
            Err(_) => {
                // Could be a junk packet — silently ignore and wait for next
                continue;
            }
        }
    }
}

async fn perform_handshake(
    socket: &UdpSocket,
    private_key: &[u8],
    server_public_key: &[u8],
    obfuscator: &PacketObfuscator,
) -> Result<Transport> {
    log::info!("Starting handshake...");

    let mut initiator =
        Initiator::new(private_key, server_public_key).context("Failed to create initiator")?;

    // Send junk packets before handshake init
    let junk_count = obfuscator.junk_count();
    for _ in 0..junk_count {
        let junk = obfuscator.generate_junk_packet();
        let _ = socket.send(&junk).await;
    }

    // Send handshake init
    let init_msg = initiator
        .write_message(&[])
        .context("Failed to create handshake init")?;
    let init_packet = Packet::handshake_init(init_msg.clone());

    socket
        .send(&obfuscator.obfuscate(&init_packet))
        .await
        .context("Failed to send handshake init")?;

    // Receive response (may be HandshakeResponse or CookieReply)
    let response_packet = recv_packet(socket, HANDSHAKE_TIMEOUT, obfuscator)
        .await
        .context("Failed to receive handshake response")?;

    let response_packet = if response_packet.packet_type == PacketType::CookieReply {
        // Server requested cookie challenge — resend with cookie
        if response_packet.payload.len() != 32 {
            anyhow::bail!("Invalid CookieReply payload size");
        }
        let mut cookie = [0u8; 32];
        cookie.copy_from_slice(&response_packet.payload);

        log::info!("Server requested cookie challenge, resending with cookie...");

        let cookie_packet = Packet::handshake_init_cookie(cookie, init_msg);
        socket
            .send(&obfuscator.obfuscate(&cookie_packet))
            .await
            .context("Failed to send handshake init with cookie")?;

        // Wait for actual HandshakeResponse
        recv_packet(socket, HANDSHAKE_TIMEOUT, obfuscator)
            .await
            .context("Failed to receive handshake response after cookie")?
    } else {
        response_packet
    };

    if response_packet.packet_type != PacketType::HandshakeResponse {
        anyhow::bail!(
            "Expected HandshakeResponse, got {:?}",
            response_packet.packet_type
        );
    }

    // Process response
    initiator
        .read_message(&response_packet.payload)
        .context("Failed to process handshake response")?;

    if !initiator.is_finished() {
        anyhow::bail!("Handshake not completed after response");
    }

    log::info!("Handshake complete!");

    initiator
        .into_transport()
        .context("Failed to enter transport mode")
}

/// Test mode: send a message and receive echo
async fn run_test_mode(
    socket: &UdpSocket,
    transport: &mut Transport,
    message: &str,
    obfuscator: &PacketObfuscator,
) -> Result<()> {
    log::info!("Test mode: sending message: {}", message);

    let encrypted = transport
        .encrypt(message.as_bytes())
        .context("Failed to encrypt message")?;
    let data_packet = Packet::data(encrypted);

    socket
        .send(&obfuscator.obfuscate(&data_packet))
        .await
        .context("Failed to send data")?;

    // Receive echo response
    let echo_packet = recv_packet(socket, Duration::from_secs(10), obfuscator)
        .await
        .context("Failed to receive echo response")?;

    if echo_packet.packet_type != PacketType::Data {
        anyhow::bail!("Expected Data packet, got {:?}", echo_packet.packet_type);
    }

    let decrypted = transport
        .decrypt(&echo_packet.payload)
        .context("Failed to decrypt response")?;

    log::info!("Received: {}", String::from_utf8_lossy(&decrypted));
    log::info!("Test successful!");

    Ok(())
}

/// Shared state for connection tracking
struct ConnectionState {
    /// Timestamp of last received packet (as seconds since start)
    last_received: AtomicU64,
    /// Start time for timestamp calculations
    start_time: Instant,
}

impl ConnectionState {
    fn new() -> Self {
        Self {
            last_received: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    fn update_last_received(&self) {
        let elapsed = self.start_time.elapsed().as_secs();
        self.last_received.store(elapsed, Ordering::Relaxed);
    }

    fn seconds_since_last_received(&self) -> u64 {
        let elapsed = self.start_time.elapsed().as_secs();
        let last = self.last_received.load(Ordering::Relaxed);
        elapsed.saturating_sub(last)
    }
}

/// Check if an IO error indicates the network interface is gone
/// (EADDRNOTAVAIL on macOS = error 49, ENETUNREACH on Linux = error 101)
fn is_network_unreachable(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::NetworkUnreachable
    )
}

/// Reason why the VPN data loop exited
enum VpnExitReason {
    /// Graceful shutdown (SIGINT/SIGTERM)
    Shutdown,
    /// KeepAlive timeout — try soft roam
    ConnectionTimeout,
}

/// VPN data loop: tunnel traffic through TUN interface.
/// Returns the reason for exiting.
async fn run_vpn_loop(
    socket: &UdpSocket,
    transport: &Transport,
    tun_reader: &mut TunReader,
    tun_writer: &mut TunWriter,
    keepalive_interval: u64,
    keepalive_timeout: u64,
    obfuscator: &PacketObfuscator,
) -> VpnExitReason {
    let conn_state = ConnectionState::new();
    conn_state.update_last_received();

    let metrics = VpnMetrics::new();
    let error_loggers = VpnErrorLoggers::new();

    let mut tun_buf = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];

    let mut keepalive_ticker = interval(Duration::from_secs(if keepalive_interval > 0 {
        keepalive_interval
    } else {
        3600 // effectively disabled
    }));

    if keepalive_interval > 0 {
        log::info!(
            "Keep-alive enabled: interval={}s, timeout={}s",
            keepalive_interval,
            keepalive_timeout
        );
    }

    loop {
        tokio::select! {
            // TUN -> UDP (outgoing traffic)
            result = tun_reader.read(&mut tun_buf) => {
                match result {
                    Ok(n) if n > 0 => {
                        log::debug!("TUN -> UDP: {} bytes", n);
                        match transport.encrypt(&tun_buf[..n]) {
                            Ok(encrypted) => {
                                metrics.record_sent(encrypted.len() as u64);
                                let packet = Packet::data(encrypted);
                                if let Err(e) = socket.send(&obfuscator.obfuscate(&packet)).await {
                                    if is_network_unreachable(&e) {
                                        log::warn!("Network interface lost, triggering roam");
                                        return VpnExitReason::ConnectionTimeout;
                                    }
                                    error_loggers.udp_send.warn(&format!("UDP send error: {}", e));
                                }
                            }
                            Err(e) => {
                                log::error!("Encrypt error: {}", e);
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("TUN read error: {}", e);
                        return VpnExitReason::Shutdown;
                    }
                }
            }
            // UDP -> TUN (incoming traffic)
            result = socket.recv(&mut udp_buf) => {
                match result {
                    Ok(n) if n > 0 => {
                        conn_state.update_last_received();
                        if let Ok(packet) = obfuscator.deobfuscate(Bytes::copy_from_slice(&udp_buf[..n])) {
                            match packet.packet_type {
                                PacketType::Data => {
                                    metrics.record_received(packet.payload.len() as u64);
                                    match transport.decrypt(&packet.payload) {
                                        Ok(plaintext) => {
                                            log::debug!("UDP -> TUN: {} bytes", plaintext.len());
                                            if let Err(e) = tun_writer.write(&plaintext).await {
                                                error_loggers.tun_write.warn(&format!("TUN write error: {}", e));
                                            }
                                        }
                                        Err(e) => {
                                            if matches!(e, CommonError::ReplayedPacket) {
                                                error_loggers.decrypt_replay.debug(&format!("Replayed/out-of-order packet dropped"));
                                            } else {
                                                error_loggers.decrypt_crypto.warn(&format!("Decrypt error: {}", e));
                                            }
                                        }
                                    }
                                }
                                PacketType::KeepAliveAck => {
                                    log::debug!("KeepAliveAck received");
                                }
                                _ => {
                                    log::warn!("Unexpected packet type: {:?}", packet.packet_type);
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("UDP recv error: {}", e);
                        return VpnExitReason::Shutdown;
                    }
                }
            }
            // Keep-alive sender + timeout check
            _ = keepalive_ticker.tick() => {
                if keepalive_interval == 0 {
                    continue;
                }
                let since_last = conn_state.seconds_since_last_received();
                if since_last > keepalive_timeout {
                    log::error!("Connection timeout: no response for {} seconds", since_last);
                    return VpnExitReason::ConnectionTimeout;
                }
                let packet = Packet::keep_alive();
                if let Err(e) = socket.send(&obfuscator.obfuscate(&packet)).await {
                    if is_network_unreachable(&e) {
                        log::warn!("Network interface lost (keepalive), triggering roam");
                        return VpnExitReason::ConnectionTimeout;
                    }
                    log::error!("Failed to send keep-alive: {}", e);
                } else {
                    log::debug!("KeepAlive sent");
                }
            }
            // Shutdown signal
            _ = shutdown_signal() => {
                return VpnExitReason::Shutdown;
            }
        }
    }
}

/// VPN mode: setup TUN, routes, DNS, then run data loop with soft roaming support
async fn run_vpn_mode(
    socket: Arc<UdpSocket>,
    transport: Arc<Transport>,
    config: &ClientConfig,
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

    log::info!("VPN tunnel established on {}", tun_device.name());

    // Setup routes if configured
    let server_ip: Ipv4Addr = config
        .server
        .split(':')
        .next()
        .and_then(|s| s.parse().ok())
        .context("Invalid server IP in config")?;

    let vpn_gateway_ip = {
        let octets = tun_address.octets();
        Ipv4Addr::new(octets[0], octets[1], octets[2], 1)
    };

    let route_config = RouteConfig {
        tun_name: tun_device.name().to_string(),
        tun_gateway: tun_address,
        server_ip,
        vpn_gateway_ip,
        route_all_traffic: config.route_all_traffic,
        routed_subnets: config.routed_subnets.clone(),
    };

    if config.route_all_traffic || !config.routed_subnets.is_empty() {
        if let Err(e) = setup_routes(&route_config) {
            log::error!("Failed to setup routes: {}", e);
            log::warn!("Continuing without routing - you may need to configure routes manually");
        }
    }

    // Setup DNS if configured
    let dns_state: Option<DnsState> = if !config.dns_servers.is_empty() {
        let dns_config = DnsConfig::new(config.dns_servers.clone());
        match setup_dns(&dns_config) {
            Ok(state) => {
                log::info!("DNS configured: {:?}", config.dns_servers);
                Some(state)
            }
            Err(e) => {
                log::error!("Failed to setup DNS: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Split TUN device for concurrent read/write
    let (mut tun_reader, mut tun_writer) = tun_device.split();

    let keepalive_interval = config.keepalive_interval;
    let keepalive_timeout = config.keepalive_timeout;
    let server_addr = config.server.clone();

    // Soft roam loop: on timeout, recreate socket and retry with same transport
    let mut current_socket = socket;
    loop {
        let reason = run_vpn_loop(
            &current_socket,
            &transport,
            &mut tun_reader,
            &mut tun_writer,
            keepalive_interval,
            keepalive_timeout,
            &obfuscator,
        )
        .await;

        match reason {
            VpnExitReason::Shutdown => break,
            VpnExitReason::ConnectionTimeout => {
                log::info!("Attempting soft roam (new socket, same session)...");

                // Brief delay to let the new network interface stabilize
                tokio::time::sleep(Duration::from_millis(500)).await;

                // Update route to VPN server through new default gateway
                if let Err(e) = update_server_route(server_ip) {
                    log::warn!("Failed to update server route: {}", e);
                    // Continue anyway — route might still work
                }

                // Create new UDP socket
                let new_socket = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("Failed to create new socket for roaming: {}", e);
                        break;
                    }
                };
                if let Err(e) = new_socket.connect(&server_addr).await {
                    log::error!("Failed to connect new socket: {}", e);
                    break;
                }
                if let Err(e) = configure_socket(&new_socket) {
                    log::warn!("Failed to configure new socket buffers: {}", e);
                }

                // Send roam ping — encrypted empty Data packet to trigger roaming detection on server
                match transport.encrypt(b"") {
                    Ok(encrypted) => {
                        let ping = Packet::data(encrypted);
                        if let Err(e) = new_socket.send(&obfuscator.obfuscate(&ping)).await {
                            log::error!("Failed to send roam ping: {}", e);
                            break;
                        }
                        log::info!("Roam ping sent, waiting for server response...");
                    }
                    Err(e) => {
                        log::error!("Failed to encrypt roam ping: {}", e);
                        break;
                    }
                }

                // Wait for response with short timeout
                let mut buf = [0u8; 65535];
                match timeout(Duration::from_secs(5), new_socket.recv(&mut buf)).await {
                    Ok(Ok(_)) => {
                        log::info!("Soft roam successful — server responded on new endpoint");
                        current_socket = Arc::new(new_socket);
                        // Continue loop — will restart run_vpn_loop with new socket
                    }
                    Ok(Err(e)) => {
                        log::error!("Soft roam failed (recv error): {}", e);
                        break;
                    }
                    Err(_) => {
                        log::warn!("Soft roam failed (timeout) — falling back to re-handshake");
                        break;
                    }
                }
            }
        }
    }

    // Cleanup DNS
    log::info!("Cleaning up...");
    if let Some(ref state) = dns_state {
        if let Err(e) = cleanup_dns(state) {
            log::error!("Failed to cleanup DNS: {}", e);
        } else {
            log::info!("DNS restored successfully");
        }
    }

    // Cleanup routes
    if config.route_all_traffic || !config.routed_subnets.is_empty() {
        if let Err(e) = cleanup_routes(&route_config) {
            log::error!("Failed to cleanup routes: {}", e);
        } else {
            log::info!("Routes cleaned up successfully");
        }
    }

    Ok(())
}

/// Single connection attempt (connect, handshake, run VPN)
async fn run_vpn_connection(
    config: &ClientConfig,
    private_key: &[u8],
    server_public_key: &[u8],
    obfuscator: Arc<PacketObfuscator>,
) -> Result<()> {
    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket
        .connect(&config.server)
        .await
        .with_context(|| format!("Failed to connect to {}", config.server))?;

    // Configure socket buffers for high-throughput
    if let Err(e) = configure_socket(&socket) {
        log::warn!("Failed to configure socket buffers: {}", e);
    }

    log::info!("Connecting to server: {}", config.server);

    // Perform handshake
    let transport = perform_handshake(&socket, private_key, server_public_key, &obfuscator).await?;

    // VPN mode with soft roaming support
    let socket = Arc::new(socket);
    let transport = Arc::new(transport);
    run_vpn_mode(socket, transport, config, obfuscator).await
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
            perform_handshake(&socket, &private_key, &server_public_key, &obfuscator).await?;
        run_test_mode(&socket, &mut transport, &args.message, &obfuscator).await?;
    } else {
        // VPN mode with reconnection support
        let mut attempt = 0u32;

        loop {
            attempt += 1;

            if config.max_reconnect_attempts > 0 && attempt > config.max_reconnect_attempts {
                log::error!(
                    "Max reconnect attempts ({}) reached, giving up",
                    config.max_reconnect_attempts
                );
                break;
            }

            if attempt > 1 {
                log::info!(
                    "Reconnection attempt {} (max: {})",
                    attempt,
                    if config.max_reconnect_attempts == 0 {
                        "unlimited".to_string()
                    } else {
                        config.max_reconnect_attempts.to_string()
                    }
                );
            }

            match run_vpn_connection(
                &config,
                &private_key,
                &server_public_key,
                obfuscator.clone(),
            )
            .await
            {
                Ok(()) => {
                    log::info!("VPN connection ended normally");
                    break;
                }
                Err(e) => {
                    log::error!("VPN connection error: {}", e);

                    if !config.reconnect_enabled {
                        log::info!("Reconnection disabled, exiting");
                        return Err(e);
                    }

                    log::info!(
                        "Waiting {} seconds before reconnecting...",
                        config.reconnect_delay
                    );
                    tokio::time::sleep(Duration::from_secs(config.reconnect_delay)).await;
                }
            }
        }
    }

    Ok(())
}
