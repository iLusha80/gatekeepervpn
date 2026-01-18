//! Socket utilities for VPN connections

use std::io;

use socket2::{Domain, Protocol, SockRef, Type};
use tokio::net::UdpSocket;

/// Default UDP buffer size (2MB for high-throughput)
pub const DEFAULT_BUFFER_SIZE: usize = 2 * 1024 * 1024;

/// Configure UDP socket with larger buffers for high-throughput
///
/// This helps prevent "No buffer space available" errors during
/// traffic bursts by increasing both send and receive buffer sizes.
pub fn configure_socket_buffers(socket: &UdpSocket, size: usize) -> io::Result<()> {
    // Use socket2 to access low-level socket options
    let sock_ref = SockRef::from(socket);

    // Set send buffer size
    if let Err(e) = sock_ref.set_send_buffer_size(size) {
        log::warn!(
            "Failed to set send buffer size: {} (continuing with default)",
            e
        );
    } else {
        log::debug!("UDP send buffer set to {} bytes", size);
    }

    // Set receive buffer size
    if let Err(e) = sock_ref.set_recv_buffer_size(size) {
        log::warn!(
            "Failed to set recv buffer size: {} (continuing with default)",
            e
        );
    } else {
        log::debug!("UDP recv buffer set to {} bytes", size);
    }

    Ok(())
}

/// Configure socket with default buffer size
pub fn configure_socket(socket: &UdpSocket) -> io::Result<()> {
    configure_socket_buffers(socket, DEFAULT_BUFFER_SIZE)
}

/// Create a UDP socket with configured buffer sizes
pub fn create_udp_socket(addr: &str) -> io::Result<std::net::UdpSocket> {
    use std::net::ToSocketAddrs;

    let addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid address"))?;

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // Set buffer sizes before binding
    let _ = socket.set_send_buffer_size(DEFAULT_BUFFER_SIZE);
    let _ = socket.set_recv_buffer_size(DEFAULT_BUFFER_SIZE);

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    Ok(socket.into())
}
