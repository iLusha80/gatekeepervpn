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
}

impl TryFrom<u8> for PacketType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PacketType::HandshakeInit),
            2 => Ok(PacketType::HandshakeResponse),
            3 => Ok(PacketType::Data),
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
}
