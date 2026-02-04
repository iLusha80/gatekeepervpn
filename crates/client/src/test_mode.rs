use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use gatekeeper_common::{Packet, PacketObfuscator, PacketType, Transport};

use crate::handshake::recv_packet;

/// Test mode: send a message and receive echo
pub(crate) async fn run_test_mode(
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
