use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use gatekeeper_common::{
    Error as CommonError, Packet, PacketObfuscator, PacketType, RateLimitDecision, VpnErrorLoggers,
    VpnMetrics,
};

use crate::server::Server;
use crate::signal::shutdown_signal;

/// Echo mode: just echo back decrypted data
pub(crate) async fn run_echo_mode(
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
                    let junk = obfuscator.generate_junk_packet(None);
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
