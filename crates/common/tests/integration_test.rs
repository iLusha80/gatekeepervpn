//! Integration test for UDP handshake and encrypted communication

use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::timeout;

use gatekeeper_common::crypto::generate_keypair;
use gatekeeper_common::{Initiator, Packet, PacketType, Responder};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn test_udp_handshake_and_echo() {
    // Generate keypairs
    let server_keys = generate_keypair().unwrap();
    let client_keys = generate_keypair().unwrap();

    let server_private = server_keys.private.clone();
    let server_public = server_keys.public.clone();
    let client_private = client_keys.private.clone();

    // Create server socket
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    // Channel to signal server is ready
    let (tx, rx) = oneshot::channel();

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        tx.send(()).unwrap();

        // Receive handshake init
        let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
        let packet = Packet::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        assert_eq!(packet.packet_type, PacketType::HandshakeInit);

        // Create responder and process init
        let mut responder = Responder::new(&server_private).unwrap();
        responder.read_message(&packet.payload).unwrap();

        // Send response
        let response = responder.write_message(&[]).unwrap();
        let response_packet = Packet::handshake_response(response);
        server_socket
            .send_to(&response_packet.encode(), client_addr)
            .await
            .unwrap();

        assert!(responder.is_finished());
        let transport = responder.into_transport().unwrap();

        // Receive encrypted data
        let (len, _) = server_socket.recv_from(&mut buf).await.unwrap();
        let packet = Packet::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        assert_eq!(packet.packet_type, PacketType::Data);

        let plaintext = transport.decrypt(&packet.payload).unwrap();
        assert_eq!(&plaintext, b"Hello, Server!");

        // Send echo response
        let echo_msg = format!("Echo: {}", String::from_utf8_lossy(&plaintext));
        let encrypted = transport.encrypt(echo_msg.as_bytes()).unwrap();
        let echo_packet = Packet::data(encrypted);
        server_socket
            .send_to(&echo_packet.encode(), client_addr)
            .await
            .unwrap();

        "server_done"
    });

    // Wait for server to be ready
    rx.await.unwrap();

    // Client
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_socket.connect(server_addr).await.unwrap();

    let mut initiator = Initiator::new(&client_private, &server_public).unwrap();

    // Send handshake init
    let init_msg = initiator.write_message(&[]).unwrap();
    let init_packet = Packet::handshake_init(init_msg);
    client_socket.send(&init_packet.encode()).await.unwrap();

    // Receive response
    let mut buf = vec![0u8; 65535];
    let len = timeout(TEST_TIMEOUT, client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let packet = Packet::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
    assert_eq!(packet.packet_type, PacketType::HandshakeResponse);

    initiator.read_message(&packet.payload).unwrap();
    assert!(initiator.is_finished());

    let transport = initiator.into_transport().unwrap();

    // Send encrypted data
    let encrypted = transport.encrypt(b"Hello, Server!").unwrap();
    let data_packet = Packet::data(encrypted);
    client_socket.send(&data_packet.encode()).await.unwrap();

    // Receive echo
    let len = timeout(TEST_TIMEOUT, client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let packet = Packet::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
    assert_eq!(packet.packet_type, PacketType::Data);

    let plaintext = transport.decrypt(&packet.payload).unwrap();
    assert_eq!(&plaintext, b"Echo: Hello, Server!");

    // Wait for server
    let result = timeout(TEST_TIMEOUT, server_handle).await.unwrap().unwrap();
    assert_eq!(result, "server_done");
}
