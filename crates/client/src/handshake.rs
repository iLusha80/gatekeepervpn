use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use gatekeeper_common::{Initiator, Packet, PacketObfuscator, PacketType, Transport};

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn recv_packet(
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

pub async fn perform_handshake(
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
