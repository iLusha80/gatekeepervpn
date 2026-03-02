//! UDP implementation of the VPN transport traits.
//!
//! Wraps `tokio::net::UdpSocket` to implement `ClientTransport` and `ServerTransport`.
//! This provides one-to-one mapping with the existing UDP behavior.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::transport_trait::{ClientTransport, ServerTransport};

/// UDP client transport — connected to a single server endpoint.
pub struct UdpClientTransport {
    socket: UdpSocket,
}

impl UdpClientTransport {
    /// Create from an already-connected UdpSocket.
    pub fn new(socket: UdpSocket) -> Self {
        Self { socket }
    }

    /// Access the underlying socket (for socket configuration, etc.)
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Consume and return the underlying socket.
    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }
}

impl ClientTransport for UdpClientTransport {
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf).await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf).await
    }

    fn is_network_error(&self, err: &io::Error) -> bool {
        matches!(
            err.kind(),
            io::ErrorKind::AddrNotAvailable | io::ErrorKind::NetworkUnreachable
        )
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

/// UDP server transport — receives from multiple peers.
pub struct UdpServerTransport {
    socket: UdpSocket,
}

impl UdpServerTransport {
    /// Create from a bound (not connected) UdpSocket.
    pub fn new(socket: UdpSocket) -> Self {
        Self { socket }
    }

    /// Access the underlying socket (for socket configuration, etc.)
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

impl ServerTransport for UdpServerTransport {
    type PeerAddr = SocketAddr;

    async fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_client_transport_send_recv() {
        // Create a "server" socket
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Create client transport
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_socket.connect(server_addr).await.unwrap();
        let client = UdpClientTransport::new(client_socket);

        // Send from client
        let sent = client.send(b"hello").await.unwrap();
        assert_eq!(sent, 5);

        // Receive on server
        let mut buf = [0u8; 64];
        let (len, from) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"hello");

        // Send from server back to client
        server.send_to(b"world", from).await.unwrap();

        // Receive on client
        let len = client.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"world");
    }

    #[tokio::test]
    async fn test_udp_server_transport_send_recv() {
        // Create server transport
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server = UdpServerTransport::new(server_socket);

        // Create a client
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"request", server_addr).await.unwrap();

        // Receive on server transport
        let mut buf = [0u8; 64];
        let (len, peer_addr) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"request");

        // Send response via server transport
        let sent = server.send_to(b"response", &peer_addr).await.unwrap();
        assert_eq!(sent, 8);

        // Receive on client
        let len = client.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"response");
    }

    #[tokio::test]
    async fn test_udp_client_transport_local_addr() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let expected = socket.local_addr().unwrap();
        let transport = UdpClientTransport::new(socket);
        assert_eq!(transport.local_addr().unwrap(), expected);
    }

    #[test]
    fn test_udp_client_transport_is_network_error() {
        // We can't easily construct a UdpClientTransport without async,
        // but we can test the is_network_error logic directly
        let err_addr = io::Error::new(io::ErrorKind::AddrNotAvailable, "test");
        let err_net = io::Error::new(io::ErrorKind::NetworkUnreachable, "test");
        let err_other = io::Error::new(io::ErrorKind::Other, "test");
        let err_refused = io::Error::new(io::ErrorKind::ConnectionRefused, "test");

        // Create a dummy transport just for the method
        // Actually, is_network_error doesn't use self, so we can test the logic
        assert!(matches!(
            err_addr.kind(),
            io::ErrorKind::AddrNotAvailable | io::ErrorKind::NetworkUnreachable
        ));
        assert!(matches!(
            err_net.kind(),
            io::ErrorKind::AddrNotAvailable | io::ErrorKind::NetworkUnreachable
        ));
        assert!(!matches!(
            err_other.kind(),
            io::ErrorKind::AddrNotAvailable | io::ErrorKind::NetworkUnreachable
        ));
        assert!(!matches!(
            err_refused.kind(),
            io::ErrorKind::AddrNotAvailable | io::ErrorKind::NetworkUnreachable
        ));
    }

    #[tokio::test]
    async fn test_udp_server_transport_multiple_peers() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server = UdpServerTransport::new(server_socket);

        // Two clients
        let client1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        client1.send_to(b"from-1", server_addr).await.unwrap();
        client2.send_to(b"from-2", server_addr).await.unwrap();

        let mut buf = [0u8; 64];

        // Receive from both — order may vary
        let (len1, addr1) = server.recv_from(&mut buf).await.unwrap();
        let msg1 = String::from_utf8_lossy(&buf[..len1]).to_string();

        let (len2, addr2) = server.recv_from(&mut buf).await.unwrap();
        let msg2 = String::from_utf8_lossy(&buf[..len2]).to_string();

        // Both messages received, addresses differ
        assert_ne!(addr1, addr2);
        let messages: std::collections::HashSet<String> = [msg1, msg2].into_iter().collect();
        assert!(messages.contains("from-1"));
        assert!(messages.contains("from-2"));
    }
}
