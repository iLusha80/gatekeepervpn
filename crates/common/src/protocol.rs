//! Wire protocol for GatekeeperVPN
//!
//! Packet format:
//! ```text
//! +------+------------------+
//! | Type | Payload          |
//! | 1B   | variable         |
//! +------+------------------+
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::Error;

/// Packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// First handshake message (client -> server)
    HandshakeInit = 1,
    /// Second handshake message (server -> client)
    HandshakeResponse = 2,
    /// Encrypted data packet
    Data = 3,
    /// Keep-alive ping (client -> server)
    KeepAlive = 4,
    /// Keep-alive pong (server -> client)
    KeepAliveAck = 5,
    /// Cookie reply (server -> client, DoS protection)
    CookieReply = 6,
    /// Handshake init with cookie (client -> server, DoS protection)
    HandshakeInitCookie = 7,
}

impl TryFrom<u8> for PacketType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PacketType::HandshakeInit),
            2 => Ok(PacketType::HandshakeResponse),
            3 => Ok(PacketType::Data),
            4 => Ok(PacketType::KeepAlive),
            5 => Ok(PacketType::KeepAliveAck),
            6 => Ok(PacketType::CookieReply),
            7 => Ok(PacketType::HandshakeInitCookie),
            _ => Err(Error::InvalidPacket),
        }
    }
}

/// A protocol packet
#[derive(Debug, Clone)]
pub struct Packet {
    pub packet_type: PacketType,
    pub payload: Bytes,
}

impl Packet {
    /// Create a new packet
    pub fn new(packet_type: PacketType, payload: impl Into<Bytes>) -> Self {
        Self {
            packet_type,
            payload: payload.into(),
        }
    }

    /// Create handshake init packet
    pub fn handshake_init(payload: impl Into<Bytes>) -> Self {
        Self::new(PacketType::HandshakeInit, payload)
    }

    /// Create handshake response packet
    pub fn handshake_response(payload: impl Into<Bytes>) -> Self {
        Self::new(PacketType::HandshakeResponse, payload)
    }

    /// Create data packet
    pub fn data(payload: impl Into<Bytes>) -> Self {
        Self::new(PacketType::Data, payload)
    }

    /// Create keep-alive packet
    pub fn keep_alive() -> Self {
        Self::new(PacketType::KeepAlive, Bytes::new())
    }

    /// Create keep-alive acknowledgment packet
    pub fn keep_alive_ack() -> Self {
        Self::new(PacketType::KeepAliveAck, Bytes::new())
    }

    /// Create cookie reply packet (server -> client)
    pub fn cookie_reply(cookie: [u8; 32]) -> Self {
        Self::new(PacketType::CookieReply, cookie.to_vec())
    }

    /// Create handshake init with cookie packet (client -> server)
    pub fn handshake_init_cookie(cookie: [u8; 32], handshake_payload: impl Into<Bytes>) -> Self {
        let payload: Bytes = handshake_payload.into();
        let mut buf = BytesMut::with_capacity(32 + payload.len());
        buf.put_slice(&cookie);
        buf.put_slice(&payload);
        Self::new(PacketType::HandshakeInitCookie, buf.freeze())
    }

    /// Parse cookie from HandshakeInitCookie payload
    pub fn parse_cookie_and_payload(&self) -> Result<([u8; 32], Bytes), Error> {
        if self.payload.len() < 32 {
            return Err(Error::InvalidPacket);
        }
        let mut cookie = [0u8; 32];
        cookie.copy_from_slice(&self.payload[..32]);
        let handshake_payload = self.payload.slice(32..);
        Ok((cookie, handshake_payload))
    }

    /// Encode packet to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + self.payload.len());
        buf.put_u8(self.packet_type as u8);
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    /// Decode packet from bytes
    pub fn decode(mut data: Bytes) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::InvalidPacket);
        }

        let packet_type = PacketType::try_from(data.get_u8())?;
        let payload = data;

        Ok(Self {
            packet_type,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_encode_decode() {
        let original = Packet::data(b"hello world".to_vec());
        let encoded = original.encode();
        let decoded = Packet::decode(encoded).unwrap();

        assert_eq!(decoded.packet_type, PacketType::Data);
        assert_eq!(&decoded.payload[..], b"hello world");
    }

    #[test]
    fn test_handshake_packets() {
        let init = Packet::handshake_init(vec![1, 2, 3]);
        assert_eq!(init.packet_type, PacketType::HandshakeInit);

        let resp = Packet::handshake_response(vec![4, 5, 6]);
        assert_eq!(resp.packet_type, PacketType::HandshakeResponse);
    }

    #[test]
    fn test_invalid_packet_type() {
        let data = Bytes::from(vec![99, 1, 2, 3]); // 99 is invalid type
        let result = Packet::decode(data);
        assert!(matches!(result, Err(Error::InvalidPacket)));
    }

    #[test]
    fn test_empty_packet() {
        let data = Bytes::new();
        let result = Packet::decode(data);
        assert!(matches!(result, Err(Error::InvalidPacket)));
    }

    #[test]
    fn test_keepalive_packets() {
        let ka = Packet::keep_alive();
        assert_eq!(ka.packet_type, PacketType::KeepAlive);
        assert!(ka.payload.is_empty());

        // Encode -> decode roundtrip
        let encoded = ka.encode();
        let decoded = Packet::decode(encoded).unwrap();
        assert_eq!(decoded.packet_type, PacketType::KeepAlive);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_keepalive_ack_packets() {
        let ka_ack = Packet::keep_alive_ack();
        assert_eq!(ka_ack.packet_type, PacketType::KeepAliveAck);
        assert!(ka_ack.payload.is_empty());

        // Encode -> decode roundtrip
        let encoded = ka_ack.encode();
        let decoded = Packet::decode(encoded).unwrap();
        assert_eq!(decoded.packet_type, PacketType::KeepAliveAck);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_all_packet_types_roundtrip() {
        let cookie = [42u8; 32];
        let packets = vec![
            Packet::handshake_init(vec![1, 2, 3]),
            Packet::handshake_response(vec![4, 5, 6]),
            Packet::data(vec![7, 8, 9]),
            Packet::keep_alive(),
            Packet::keep_alive_ack(),
            Packet::cookie_reply(cookie),
            Packet::handshake_init_cookie(cookie, vec![10, 11, 12]),
        ];

        for original in packets {
            let ptype = original.packet_type;
            let encoded = original.encode();
            let decoded = Packet::decode(encoded).unwrap();
            assert_eq!(
                decoded.packet_type, ptype,
                "Roundtrip failed for {:?}",
                ptype
            );
        }
    }

    #[test]
    fn test_cookie_reply_roundtrip() {
        let cookie = [0xAB; 32];
        let packet = Packet::cookie_reply(cookie);
        let encoded = packet.encode();
        let decoded = Packet::decode(encoded).unwrap();

        assert_eq!(decoded.packet_type, PacketType::CookieReply);
        assert_eq!(decoded.payload.len(), 32);
        assert_eq!(&decoded.payload[..], &cookie[..]);
    }

    #[test]
    fn test_handshake_init_cookie_roundtrip() {
        let cookie = [0xCD; 32];
        let handshake_data = vec![1, 2, 3, 4, 5];
        let packet = Packet::handshake_init_cookie(cookie, handshake_data.clone());
        let encoded = packet.encode();
        let decoded = Packet::decode(encoded).unwrap();

        assert_eq!(decoded.packet_type, PacketType::HandshakeInitCookie);
        let (parsed_cookie, parsed_payload) = decoded.parse_cookie_and_payload().unwrap();
        assert_eq!(parsed_cookie, cookie);
        assert_eq!(&parsed_payload[..], &handshake_data[..]);
    }
}
