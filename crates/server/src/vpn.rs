use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::interval;

use gatekeeper_common::{
    Error as CommonError, NatConfig, Packet, PacketObfuscator, PacketType, RateLimitDecision,
    ServerConfig, TunConfig, TunDevice, VpnErrorLoggers, VpnMetrics, cleanup_nat,
    enable_ip_forwarding, get_destination_ip, print_nat_instructions, setup_nat,
};

use crate::config::{PEERS_RELOAD_INTERVAL_SECS, get_file_modified_time, load_peers_config};
use crate::server::Server;
use crate::signal::shutdown_signal;

/// VPN mode: forward traffic between UDP and TUN with unicast routing
pub(crate) async fn run_vpn_mode(
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
                                        let junk = obfuscator_rx.generate_junk_packet(None);
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
                                                let junk = obfuscator_rx.generate_junk_packet(None);
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
