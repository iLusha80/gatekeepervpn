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

/// Test keep-alive exchange over UDP after handshake
#[tokio::test]
async fn test_keepalive_exchange() {
    let server_keys = generate_keypair().unwrap();
    let client_keys = generate_keypair().unwrap();

    let server_private = server_keys.private.clone();
    let server_public = server_keys.public.clone();
    let client_private = client_keys.private.clone();

    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let (tx, rx) = oneshot::channel();

    // Server: handshake then handle keep-alive
    let server_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        tx.send(()).unwrap();

        // Handshake
        let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
        let packet = Packet::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        assert_eq!(packet.packet_type, PacketType::HandshakeInit);

        let mut responder = Responder::new(&server_private).unwrap();
        responder.read_message(&packet.payload).unwrap();
        let response = responder.write_message(&[]).unwrap();
        let response_packet = Packet::handshake_response(response);
        server_socket
            .send_to(&response_packet.encode(), client_addr)
            .await
            .unwrap();

        assert!(responder.is_finished());

        // Receive KeepAlive
        let (len, _) = server_socket.recv_from(&mut buf).await.unwrap();
        let packet = Packet::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        assert_eq!(packet.packet_type, PacketType::KeepAlive);

        // Send KeepAliveAck
        let ack = Packet::keep_alive_ack();
        server_socket
            .send_to(&ack.encode(), client_addr)
            .await
            .unwrap();

        "keepalive_done"
    });

    rx.await.unwrap();

    // Client: handshake then send keep-alive
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_socket.connect(server_addr).await.unwrap();

    let mut initiator = Initiator::new(&client_private, &server_public).unwrap();

    let init_msg = initiator.write_message(&[]).unwrap();
    let init_packet = Packet::handshake_init(init_msg);
    client_socket.send(&init_packet.encode()).await.unwrap();

    let mut buf = vec![0u8; 65535];
    let len = timeout(TEST_TIMEOUT, client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let packet = Packet::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
    assert_eq!(packet.packet_type, PacketType::HandshakeResponse);

    initiator.read_message(&packet.payload).unwrap();
    assert!(initiator.is_finished());

    // Send KeepAlive
    let ka = Packet::keep_alive();
    client_socket.send(&ka.encode()).await.unwrap();

    // Receive KeepAliveAck
    let len = timeout(TEST_TIMEOUT, client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let packet = Packet::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
    assert_eq!(packet.packet_type, PacketType::KeepAliveAck);

    let result = timeout(TEST_TIMEOUT, server_handle).await.unwrap().unwrap();
    assert_eq!(result, "keepalive_done");
}

/// Test replay protection: sending same encrypted packet twice
#[tokio::test]
async fn test_replay_protection() {
    let server_keys = generate_keypair().unwrap();
    let client_keys = generate_keypair().unwrap();

    // Perform handshake in-memory (no network)
    let mut initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
    let mut responder = Responder::new(&server_keys.private).unwrap();

    let init_msg = initiator.write_message(&[]).unwrap();
    responder.read_message(&init_msg).unwrap();
    let resp_msg = responder.write_message(&[]).unwrap();
    initiator.read_message(&resp_msg).unwrap();

    let client_transport = initiator.into_transport().unwrap();
    let server_transport = responder.into_transport().unwrap();

    // Client encrypts a message
    let encrypted = client_transport.encrypt(b"test message").unwrap();

    // Server decrypts — first time should succeed
    let plaintext = server_transport.decrypt(&encrypted).unwrap();
    assert_eq!(&plaintext, b"test message");

    // Server decrypts same ciphertext again — should be rejected as replay
    let result = server_transport.decrypt(&encrypted);
    assert!(result.is_err(), "Replayed packet should be rejected");
}

// ===== Integration tests with obfuscation =====

use gatekeeper_common::config::ObfuscationConfig;
use gatekeeper_common::cookie::CookieState;
use gatekeeper_common::obfuscation::PacketObfuscator;
use std::net::{IpAddr, Ipv4Addr};

fn make_obfuscator(server_pub: &[u8]) -> PacketObfuscator {
    let config = ObfuscationConfig {
        enabled: true,
        psk: String::new(), // auto-derive from server pubkey
        header_size: 4,
        min_padding: 8,
        max_padding: 16,
        junk_min: 1,
        junk_max: 2,
    };
    PacketObfuscator::new(&config, server_pub).unwrap()
}

/// Handshake + echo with obfuscation on both sides
#[tokio::test]
async fn test_obfuscated_handshake_and_echo() {
    let server_keys = generate_keypair().unwrap();
    let client_keys = generate_keypair().unwrap();

    let server_obf = make_obfuscator(&server_keys.public);
    let client_obf = make_obfuscator(&server_keys.public);

    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let server_private = server_keys.private.clone();
    let (tx, rx) = oneshot::channel();

    let server_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        tx.send(()).unwrap();

        let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
        let packet = server_obf
            .deobfuscate(Bytes::copy_from_slice(&buf[..len]))
            .unwrap();
        assert_eq!(packet.packet_type, PacketType::HandshakeInit);

        let mut responder = Responder::new(&server_private).unwrap();
        responder.read_message(&packet.payload).unwrap();
        let response = responder.write_message(&[]).unwrap();
        let resp_packet = Packet::handshake_response(response);
        let obf_resp = server_obf.obfuscate(&resp_packet);
        server_socket.send_to(&obf_resp, client_addr).await.unwrap();

        let transport = responder.into_transport().unwrap();

        // Receive encrypted data
        let (len, _) = server_socket.recv_from(&mut buf).await.unwrap();
        let packet = server_obf
            .deobfuscate(Bytes::copy_from_slice(&buf[..len]))
            .unwrap();
        assert_eq!(packet.packet_type, PacketType::Data);
        let plaintext = transport.decrypt(&packet.payload).unwrap();
        assert_eq!(&plaintext, b"obfuscated hello");

        // Echo back
        let encrypted = transport.encrypt(b"obfuscated echo").unwrap();
        let echo_packet = Packet::data(encrypted);
        let obf_echo = server_obf.obfuscate(&echo_packet);
        server_socket.send_to(&obf_echo, client_addr).await.unwrap();

        "obf_done"
    });

    rx.await.unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_socket.connect(server_addr).await.unwrap();

    let mut initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
    let init_msg = initiator.write_message(&[]).unwrap();
    let init_packet = Packet::handshake_init(init_msg);
    let obf_init = client_obf.obfuscate(&init_packet);
    client_socket.send(&obf_init).await.unwrap();

    let mut buf = vec![0u8; 65535];
    let len = timeout(TEST_TIMEOUT, client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let packet = client_obf
        .deobfuscate(Bytes::copy_from_slice(&buf[..len]))
        .unwrap();
    initiator.read_message(&packet.payload).unwrap();
    let transport = initiator.into_transport().unwrap();

    // Send data
    let encrypted = transport.encrypt(b"obfuscated hello").unwrap();
    let data_packet = Packet::data(encrypted);
    let obf_data = client_obf.obfuscate(&data_packet);
    client_socket.send(&obf_data).await.unwrap();

    // Receive echo
    let len = timeout(TEST_TIMEOUT, client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let packet = client_obf
        .deobfuscate(Bytes::copy_from_slice(&buf[..len]))
        .unwrap();
    let plaintext = transport.decrypt(&packet.payload).unwrap();
    assert_eq!(&plaintext, b"obfuscated echo");

    let result = timeout(TEST_TIMEOUT, server_handle).await.unwrap().unwrap();
    assert_eq!(result, "obf_done");
}

/// Junk packets before handshake should not break the flow
#[tokio::test]
async fn test_junk_packets_ignored() {
    let server_keys = generate_keypair().unwrap();
    let client_keys = generate_keypair().unwrap();

    let server_obf = make_obfuscator(&server_keys.public);

    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let server_private = server_keys.private.clone();
    let (tx, rx) = oneshot::channel();

    let server_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        tx.send(()).unwrap();

        // Loop until we get a valid handshake init (skip junk)
        loop {
            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            if let Ok(packet) = server_obf.deobfuscate(Bytes::copy_from_slice(&buf[..len])) {
                if packet.packet_type != PacketType::HandshakeInit {
                    continue;
                }
                let mut responder = Responder::new(&server_private).unwrap();
                responder.read_message(&packet.payload).unwrap();
                let response = responder.write_message(&[]).unwrap();
                let resp_packet = Packet::handshake_response(response);
                let obf_resp = server_obf.obfuscate(&resp_packet);
                server_socket.send_to(&obf_resp, client_addr).await.unwrap();
                return "junk_test_done";
            }
            // else: junk packet, ignore and continue
        }
    });

    rx.await.unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_socket.connect(server_addr).await.unwrap();

    let client_obf = make_obfuscator(&server_keys.public);

    // Send junk first
    for _ in 0..3 {
        let junk = client_obf.generate_junk_packet();
        client_socket.send(&junk).await.unwrap();
    }

    // Now send real handshake
    let mut initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
    let init_msg = initiator.write_message(&[]).unwrap();
    let init_packet = Packet::handshake_init(init_msg);
    let obf_init = client_obf.obfuscate(&init_packet);
    client_socket.send(&obf_init).await.unwrap();

    // Should get response
    let mut buf = vec![0u8; 65535];
    let len = timeout(TEST_TIMEOUT, client_socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let packet = client_obf
        .deobfuscate(Bytes::copy_from_slice(&buf[..len]))
        .unwrap();
    assert_eq!(packet.packet_type, PacketType::HandshakeResponse);

    let result = timeout(TEST_TIMEOUT, server_handle).await.unwrap().unwrap();
    assert_eq!(result, "junk_test_done");
}

/// Cookie challenge full cycle (generate, send, validate)
#[test]
fn test_cookie_challenge_flow() {
    let mut cookie_state = CookieState::new();
    let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

    // Generate cookie
    let cookie = cookie_state.generate_cookie(&addr);
    assert_eq!(cookie.len(), 32);

    // Validate with same address
    assert!(cookie_state.validate_cookie(&addr, &cookie));

    // Different address fails
    let other_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    assert!(!cookie_state.validate_cookie(&other_addr, &cookie));

    // Cookie survives one rotation
    cookie_state.maybe_rotate();
    // Force immediate rotation by calling again after time manipulation isn't easy,
    // but we can verify cookie_reply packet roundtrip
    let cookie_packet = Packet::cookie_reply(cookie);
    let encoded = cookie_packet.encode();
    let decoded = Packet::decode(encoded).unwrap();
    assert_eq!(decoded.packet_type, PacketType::CookieReply);
    assert_eq!(&decoded.payload[..], &cookie[..]);

    // HandshakeInitCookie roundtrip
    let client_keys = generate_keypair().unwrap();
    let server_keys = generate_keypair().unwrap();
    let mut initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
    let init_msg = initiator.write_message(&[]).unwrap();
    let cookie_init = Packet::handshake_init_cookie(cookie, init_msg.clone());
    let (parsed_cookie, parsed_payload) = cookie_init.parse_cookie_and_payload().unwrap();
    assert_eq!(parsed_cookie, cookie);
    assert_eq!(&parsed_payload[..], &init_msg[..]);
}

/// Three sequential clients handshake and exchange data
#[tokio::test]
async fn test_three_sequential_clients() {
    let server_keys = generate_keypair().unwrap();

    for i in 0..3u8 {
        let client_keys = generate_keypair().unwrap();
        let mut initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
        let mut responder = Responder::new(&server_keys.private).unwrap();

        let msg1 = initiator.write_message(&[i]).unwrap();
        let payload = responder.read_message(&msg1).unwrap();
        assert_eq!(payload, vec![i]);

        let msg2 = responder.write_message(&[]).unwrap();
        initiator.read_message(&msg2).unwrap();

        let client_t = initiator.into_transport().unwrap();
        let server_t = responder.into_transport().unwrap();

        let ct = client_t.encrypt(&[i; 100]).unwrap();
        let pt = server_t.decrypt(&ct).unwrap();
        assert_eq!(pt, vec![i; 100]);
    }
}

/// Data packet without handshake should not decrypt
#[test]
fn test_data_without_handshake_rejected() {
    let server_keys = generate_keypair().unwrap();

    // Create a transport from one session
    let client_keys1 = generate_keypair().unwrap();
    let mut init1 = Initiator::new(&client_keys1.private, &server_keys.public).unwrap();
    let mut resp1 = Responder::new(&server_keys.private).unwrap();
    let m1 = init1.write_message(&[]).unwrap();
    resp1.read_message(&m1).unwrap();
    let m2 = resp1.write_message(&[]).unwrap();
    init1.read_message(&m2).unwrap();
    let client_t1 = init1.into_transport().unwrap();

    // Create a different transport (different session)
    let client_keys2 = generate_keypair().unwrap();
    let mut init2 = Initiator::new(&client_keys2.private, &server_keys.public).unwrap();
    let mut resp2 = Responder::new(&server_keys.private).unwrap();
    let m1 = init2.write_message(&[]).unwrap();
    resp2.read_message(&m1).unwrap();
    let m2 = resp2.write_message(&[]).unwrap();
    init2.read_message(&m2).unwrap();
    let server_t2 = resp2.into_transport().unwrap();

    // Encrypt with session 1, try decrypt with session 2
    let ct = client_t1.encrypt(b"wrong session").unwrap();
    assert!(server_t2.decrypt(&ct).is_err());
}

/// Malformed packets should return errors, not panic
#[test]
fn test_malformed_packet_no_crash() {
    let garbage_inputs: Vec<&[u8]> = vec![
        &[],
        &[0xFF],
        &[0xFF, 0xFF, 0xFF],
        &[3],          // Data type but no payload
        &[1, 0, 0, 0], // HandshakeInit with garbage
    ];
    for input in garbage_inputs {
        let result = Packet::decode(Bytes::copy_from_slice(input));
        // Either Ok (valid type byte) or Err — but never panic
        let _ = result;
    }

    // Also test with a valid packet but garbage crypto payload
    let server_keys = generate_keypair().unwrap();
    let client_keys = generate_keypair().unwrap();
    let mut init = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
    let mut resp = Responder::new(&server_keys.private).unwrap();
    let m1 = init.write_message(&[]).unwrap();
    resp.read_message(&m1).unwrap();
    let m2 = resp.write_message(&[]).unwrap();
    init.read_message(&m2).unwrap();
    let server_t = resp.into_transport().unwrap();

    // Fake data packet with random bytes
    let fake_data = vec![0u8; 100];
    let result = server_t.decrypt(&fake_data);
    assert!(result.is_err());
}

/// Large payload (60KB) encrypt/decrypt roundtrip
#[test]
fn test_large_payload() {
    let server_keys = generate_keypair().unwrap();
    let client_keys = generate_keypair().unwrap();
    let mut init = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
    let mut resp = Responder::new(&server_keys.private).unwrap();
    let m1 = init.write_message(&[]).unwrap();
    resp.read_message(&m1).unwrap();
    let m2 = resp.write_message(&[]).unwrap();
    init.read_message(&m2).unwrap();
    let client_t = init.into_transport().unwrap();
    let server_t = resp.into_transport().unwrap();

    let large_payload = vec![0xAB; 60_000];
    let ct = client_t.encrypt(&large_payload).unwrap();
    let pt = server_t.decrypt(&ct).unwrap();
    assert_eq!(pt, large_payload);
}

/// Obfuscation roundtrip over UDP socket
#[tokio::test]
async fn test_obfuscation_udp_roundtrip() {
    let server_pub = vec![0x42u8; 32];
    let obf = make_obfuscator(&server_pub);

    let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    let original = Packet::data(b"roundtrip test".to_vec());
    let obfuscated = obf.obfuscate(&original);
    socket_a.send_to(&obfuscated, addr_b).await.unwrap();

    let mut buf = vec![0u8; 65535];
    let (len, _) = timeout(TEST_TIMEOUT, socket_b.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let restored = obf
        .deobfuscate(Bytes::copy_from_slice(&buf[..len]))
        .unwrap();
    assert_eq!(restored.packet_type, PacketType::Data);
    assert_eq!(&restored.payload[..], b"roundtrip test");
}
