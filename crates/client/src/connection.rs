use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use gatekeeper_common::{ClientConfig, PacketObfuscator, configure_socket};

use crate::handshake::perform_handshake;
use crate::vpn::run_vpn_mode;

/// Single connection attempt (connect, handshake, run VPN)
pub async fn run_vpn_connection(
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

/// Run VPN with reconnection support
pub async fn run_with_reconnect(
    config: &ClientConfig,
    private_key: &[u8],
    server_public_key: &[u8],
    obfuscator: Arc<PacketObfuscator>,
) -> Result<()> {
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

        match run_vpn_connection(config, private_key, server_public_key, obfuscator.clone()).await {
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

    Ok(())
}
