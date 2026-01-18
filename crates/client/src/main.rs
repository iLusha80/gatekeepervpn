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
use tokio::sync::Mutex;
use tokio::time::{interval, timeout};

use gatekeeper_common::config::keys;
use gatekeeper_common::{
    ClientConfig, Error as CommonError, Initiator, Packet, PacketType, RouteConfig, Transport,
    TunConfig, TunDevice, VpnErrorLoggers, cleanup_routes, configure_socket, setup_routes,
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

    let mut initiator =
        Initiator::new(private_key, server_public_key).context("Failed to create initiator")?;

    // Send handshake init
    let init_msg = initiator
        .write_message(&[])
        .context("Failed to create handshake init")?;
    let init_packet = Packet::handshake_init(init_msg);

    socket
        .send(&init_packet.encode())
        .await
        .context("Failed to send handshake init")?;

    // Receive handshake response
    let response_packet = recv_packet(socket, HANDSHAKE_TIMEOUT)
        .await
        .context("Failed to receive handshake response")?;

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
async fn run_test_mode(socket: &UdpSocket, transport: &mut Transport, message: &str) -> Result<()> {
    log::info!("Test mode: sending message: {}", message);

    let encrypted = transport
        .encrypt(message.as_bytes())
        .context("Failed to encrypt message")?;
    let data_packet = Packet::data(encrypted);

    socket
        .send(&data_packet.encode())
        .await
        .context("Failed to send data")?;

    // Receive echo response
    let echo_packet = recv_packet(socket, Duration::from_secs(10))
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

/// VPN mode: tunnel traffic through TUN interface
async fn run_vpn_mode(
    socket: Arc<UdpSocket>,
    transport: Arc<Mutex<Transport>>,
    config: &ClientConfig,
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

    let route_config = RouteConfig {
        tun_name: tun_device.name().to_string(),
        tun_gateway: tun_address,
        server_ip,
        route_all_traffic: config.route_all_traffic,
        routed_subnets: config.routed_subnets.clone(),
    };

    if config.route_all_traffic || !config.routed_subnets.is_empty() {
        if let Err(e) = setup_routes(&route_config) {
            log::error!("Failed to setup routes: {}", e);
            log::warn!("Continuing without routing - you may need to configure routes manually");
        }
    }

    // Split TUN device for concurrent read/write
    let (mut tun_reader, mut tun_writer) = tun_device.split();

    // Shared connection state
    let conn_state = Arc::new(ConnectionState::new());
    conn_state.update_last_received(); // Initial timestamp

    // Rate-limited error loggers
    let error_loggers = Arc::new(VpnErrorLoggers::new());

    // Clone for tasks
    let socket_tx = socket.clone();
    let socket_rx = socket.clone();
    let socket_ka = socket;
    let transport_tx = transport.clone();
    let transport_rx = transport;
    let conn_state_rx = conn_state.clone();
    let conn_state_ka = conn_state;
    let loggers_tx = error_loggers.clone();
    let loggers_rx = error_loggers;

    let keepalive_interval = config.keepalive_interval;
    let keepalive_timeout = config.keepalive_timeout;

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
                let transport = transport_tx.lock().await;
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
                // Rate-limited warning for buffer overflow (common during bursts)
                loggers_tx.udp_send.warn(&format!("UDP send error: {}", e));
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

            // Update connection state
            conn_state_rx.update_last_received();

            // Decode packet
            let packet = match Packet::decode(Bytes::copy_from_slice(&buf[..n])) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("Invalid packet: {}", e);
                    continue;
                }
            };

            match packet.packet_type {
                PacketType::Data => {
                    // Decrypt
                    let plaintext = {
                        let transport = transport_rx.lock().await;
                        match transport.decrypt(&packet.payload) {
                            Ok(data) => data,
                            Err(e) => {
                                // Differentiate between replay and crypto errors
                                if matches!(e, CommonError::ReplayedPacket) {
                                    // Replayed/out-of-order packets are normal in UDP
                                    loggers_rx
                                        .decrypt_replay
                                        .debug(&format!("Replayed/out-of-order packet dropped"));
                                } else {
                                    // Actual crypto errors are more concerning
                                    loggers_rx
                                        .decrypt_crypto
                                        .warn(&format!("Decrypt error: {}", e));
                                }
                                continue;
                            }
                        }
                    };

                    log::debug!("UDP -> TUN: {} bytes", plaintext.len());

                    // Write to TUN
                    if let Err(e) = tun_writer.write(&plaintext).await {
                        loggers_rx
                            .tun_write
                            .warn(&format!("TUN write error: {}", e));
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
    });

    // Task 3: Keep-alive sender
    let keepalive = tokio::spawn(async move {
        if keepalive_interval == 0 {
            log::info!("Keep-alive disabled");
            return;
        }

        log::info!(
            "Keep-alive enabled: interval={}s, timeout={}s",
            keepalive_interval,
            keepalive_timeout
        );

        let mut ticker = interval(Duration::from_secs(keepalive_interval));

        loop {
            ticker.tick().await;

            // Check timeout
            let since_last = conn_state_ka.seconds_since_last_received();
            if since_last > keepalive_timeout {
                log::error!("Connection timeout: no response for {} seconds", since_last);
                break;
            }

            // Send keep-alive
            let packet = Packet::keep_alive();
            if let Err(e) = socket_ka.send(&packet.encode()).await {
                log::error!("Failed to send keep-alive: {}", e);
            } else {
                log::debug!("KeepAlive sent");
            }
        }
    });

    // Wait for any task to finish or shutdown signal
    tokio::select! {
        _ = outgoing => log::error!("Outgoing task finished unexpectedly"),
        _ = incoming => log::error!("Incoming task finished unexpectedly"),
        _ = keepalive => log::error!("Keep-alive task finished (connection timeout)"),
        _ = signal::ctrl_c() => {
            log::info!("Received shutdown signal (Ctrl+C)");
        }
    }

    // Cleanup routes
    log::info!("Cleaning up...");
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
    let transport = perform_handshake(&socket, private_key, server_public_key).await?;

    // VPN mode
    let socket = Arc::new(socket);
    let transport = Arc::new(Mutex::new(transport));
    run_vpn_mode(socket, transport, config).await
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

    if args.test {
        // Test mode - single connection, no reconnect
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket
            .connect(&config.server)
            .await
            .with_context(|| format!("Failed to connect to {}", config.server))?;

        log::info!("Connecting to server: {}", config.server);

        let mut transport = perform_handshake(&socket, &private_key, &server_public_key).await?;
        run_test_mode(&socket, &mut transport, &args.message).await?;
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

            match run_vpn_connection(&config, &private_key, &server_public_key).await {
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
