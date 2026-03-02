//! Transport abstraction for pluggable network transports (UDP, WS-over-TLS, etc.)
//!
//! These traits allow the VPN client and server to use different network
//! transports without changing the core VPN logic.

use std::fmt::Debug;
use std::hash::Hash;
use std::io;
use std::net::SocketAddr;

/// Client-side transport: connected to a single server endpoint.
///
/// Implementations: `UdpClientTransport`, `WsTlsClientTransport` (future).
pub trait ClientTransport: Send + Sync {
    /// Send data to the connected server.
    fn send(&self, buf: &[u8]) -> impl Future<Output = io::Result<usize>> + Send;

    /// Receive data from the server.
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;

    /// Check if an IO error indicates network loss (triggers roaming).
    /// For UDP: EADDRNOTAVAIL, ENETUNREACH.
    /// For WsTls: any IO error (TCP connection broken).
    fn is_network_error(&self, err: &io::Error) -> bool;

    /// Get the local address of this transport.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// Server-side transport: receives from multiple peers.
///
/// Generic over `PeerAddr` to support different addressing schemes:
/// - UDP: `PeerAddr = SocketAddr`
/// - WsTls: `PeerAddr = WsSessionId` (future)
pub trait ServerTransport: Send + Sync {
    /// Peer address type (SocketAddr for UDP, session ID for WS, etc.)
    type PeerAddr: Clone + Eq + Hash + Send + Sync + Debug + 'static;

    /// Send data to a specific peer.
    fn send_to(
        &self,
        buf: &[u8],
        addr: &Self::PeerAddr,
    ) -> impl Future<Output = io::Result<usize>> + Send;

    /// Receive data from any peer, returning the data length and sender address.
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, Self::PeerAddr)>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock client transport for testing
    struct MockClientTransport {
        send_data: Mutex<Vec<Vec<u8>>>,
        recv_data: Mutex<Vec<Vec<u8>>>,
    }

    impl MockClientTransport {
        fn new() -> Self {
            Self {
                send_data: Mutex::new(Vec::new()),
                recv_data: Mutex::new(Vec::new()),
            }
        }

        fn push_recv_data(&self, data: Vec<u8>) {
            self.recv_data.lock().unwrap().push(data);
        }

        fn get_sent_data(&self) -> Vec<Vec<u8>> {
            self.send_data.lock().unwrap().clone()
        }
    }

    impl ClientTransport for MockClientTransport {
        async fn send(&self, buf: &[u8]) -> io::Result<usize> {
            self.send_data.lock().unwrap().push(buf.to_vec());
            Ok(buf.len())
        }

        async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut queue = self.recv_data.lock().unwrap();
            if let Some(data) = queue.pop() {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            } else {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no data"))
            }
        }

        fn is_network_error(&self, err: &io::Error) -> bool {
            matches!(
                err.kind(),
                io::ErrorKind::AddrNotAvailable | io::ErrorKind::NetworkUnreachable
            )
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
    }

    /// Mock server transport for testing
    struct MockServerTransport {
        sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
        recv_queue: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    }

    impl MockServerTransport {
        fn new() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                recv_queue: Mutex::new(Vec::new()),
            }
        }

        fn push_incoming(&self, data: Vec<u8>, addr: SocketAddr) {
            self.recv_queue.lock().unwrap().push((data, addr));
        }
    }

    impl ServerTransport for MockServerTransport {
        type PeerAddr = SocketAddr;

        async fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize> {
            self.sent.lock().unwrap().push((buf.to_vec(), *addr));
            Ok(buf.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let mut queue = self.recv_queue.lock().unwrap();
            if let Some((data, addr)) = queue.pop() {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok((len, addr))
            } else {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no data"))
            }
        }
    }

    #[tokio::test]
    async fn test_mock_client_transport_send_recv() {
        let transport = MockClientTransport::new();

        // Send data
        let sent = transport.send(b"hello").await.unwrap();
        assert_eq!(sent, 5);
        assert_eq!(transport.get_sent_data(), vec![b"hello".to_vec()]);

        // Receive data
        transport.push_recv_data(b"world".to_vec());
        let mut buf = [0u8; 64];
        let received = transport.recv(&mut buf).await.unwrap();
        assert_eq!(received, 5);
        assert_eq!(&buf[..received], b"world");
    }

    #[tokio::test]
    async fn test_mock_client_transport_network_error() {
        let transport = MockClientTransport::new();
        let err = io::Error::new(io::ErrorKind::AddrNotAvailable, "addr not available");
        assert!(transport.is_network_error(&err));

        let err = io::Error::new(io::ErrorKind::Other, "other error");
        assert!(!transport.is_network_error(&err));
    }

    #[tokio::test]
    async fn test_mock_server_transport_send_recv() {
        let transport = MockServerTransport::new();
        let peer: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        // Receive from peer
        transport.push_incoming(b"request".to_vec(), peer);
        let mut buf = [0u8; 64];
        let (len, addr) = transport.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(addr, peer);
        assert_eq!(&buf[..len], b"request");

        // Send to peer
        let sent = transport.send_to(b"response", &peer).await.unwrap();
        assert_eq!(sent, 8);
    }

    #[tokio::test]
    async fn test_mock_client_recv_empty_returns_error() {
        let transport = MockClientTransport::new();
        let mut buf = [0u8; 64];
        let result = transport.recv(&mut buf).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_client_transport_local_addr() {
        let transport = MockClientTransport::new();
        let addr = transport.local_addr().unwrap();
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
    }
}
