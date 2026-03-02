use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use gatekeeper_common::{
    ClientConfig, DnsConfig, DnsState, Error as CommonError, Packet, PacketObfuscator, PacketType,
    RouteConfig, Transport, TunConfig, TunDevice, TunReader, TunWriter, VpnErrorLoggers,
    VpnMetrics, cleanup_dns, cleanup_routes, configure_socket, setup_dns, setup_routes,
    update_server_route,
};

use crate::signal::shutdown_signal;

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

/// Generate a jittered keepalive interval (±30% of base).
/// For base=25s, returns a random duration in [17, 33] seconds.
pub fn jittered_keepalive_interval(base_secs: u64) -> Duration {
    if base_secs == 0 {
        return Duration::from_secs(3600);
    }
    let min = (base_secs as f64 * 0.7) as u64;
    let max = (base_secs as f64 * 1.3) as u64;
    let jittered = rand::rng().random_range(min..=max);
    Duration::from_secs(jittered)
}

/// Reason why the VPN data loop exited
pub enum VpnExitReason {
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

    let keepalive_sleep = tokio::time::sleep(jittered_keepalive_interval(keepalive_interval));
    // Pin for reuse in select!
    tokio::pin!(keepalive_sleep);

    if keepalive_interval > 0 {
        log::info!(
            "Keep-alive enabled: interval={}s (±30% jitter), timeout={}s",
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
            // Keep-alive sender + timeout check (jittered interval)
            _ = &mut keepalive_sleep => {
                if keepalive_interval == 0 {
                    keepalive_sleep.set(tokio::time::sleep(Duration::from_secs(3600)));
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
                // Schedule next keepalive with new random jitter
                keepalive_sleep.set(tokio::time::sleep(jittered_keepalive_interval(keepalive_interval)));
            }
            // Shutdown signal
            _ = shutdown_signal() => {
                return VpnExitReason::Shutdown;
            }
        }
    }
}

/// VPN mode: setup TUN, routes, DNS, then run data loop with soft roaming support
pub async fn run_vpn_mode(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jittered_keepalive_interval_range() {
        // base=25s → range [17, 33]
        for _ in 0..1000 {
            let d = jittered_keepalive_interval(25);
            let secs = d.as_secs();
            assert!(
                (17..=33).contains(&secs),
                "jittered interval {} out of range [17, 33]",
                secs
            );
        }
    }

    #[test]
    fn test_jittered_keepalive_interval_zero_disabled() {
        let d = jittered_keepalive_interval(0);
        assert_eq!(
            d.as_secs(),
            3600,
            "zero base should return 3600s (disabled)"
        );
    }

    #[test]
    fn test_jittered_keepalive_interval_mean_near_base() {
        let n = 10_000;
        let base = 25u64;
        let sum: u64 = (0..n)
            .map(|_| jittered_keepalive_interval(base).as_secs())
            .sum();
        let mean = sum as f64 / n as f64;
        // Mean should be approximately 25 (within ±2)
        assert!(
            (mean - base as f64).abs() < 2.0,
            "mean {} too far from base {}",
            mean,
            base
        );
    }

    #[test]
    fn test_jittered_keepalive_interval_not_constant() {
        // Verify jitter actually varies (not all same value)
        let values: Vec<u64> = (0..100)
            .map(|_| jittered_keepalive_interval(25).as_secs())
            .collect();
        let unique: std::collections::HashSet<u64> = values.into_iter().collect();
        assert!(
            unique.len() > 1,
            "jittered intervals should vary, got only {:?}",
            unique
        );
    }
}
