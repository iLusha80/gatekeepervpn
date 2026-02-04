//! UDP packet obfuscation for DPI resistance
//!
//! Wire format (when enabled):
//! ```text
//! [random_header:H bytes][type^key:1B][payload:NB][random_padding:PB][padding_len:2B LE]
//! ```

use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;

use crate::Error;
use crate::config::ObfuscationConfig;
use crate::protocol::Packet;

/// Packet obfuscator/deobfuscator
pub struct PacketObfuscator {
    enabled: bool,
    header_key: [u8; 32],
    header_size: usize,
    min_padding: usize,
    max_padding: usize,
    junk_min: u8,
    junk_max: u8,
}

impl PacketObfuscator {
    /// Create a new obfuscator from config
    pub fn new(config: &ObfuscationConfig) -> Result<Self, Error> {
        if !config.enabled {
            return Ok(Self {
                enabled: false,
                header_key: [0u8; 32],
                header_size: 0,
                min_padding: 0,
                max_padding: 0,
                junk_min: 0,
                junk_max: 0,
            });
        }

        if config.psk.is_empty() {
            return Err(Error::Obfuscation(
                "PSK is required when obfuscation is enabled".to_string(),
            ));
        }

        let psk_bytes = crate::config::keys::decode(&config.psk)
            .map_err(|_| Error::Obfuscation("invalid PSK: base64 decode failed".to_string()))?;

        if psk_bytes.len() != 32 {
            return Err(Error::Obfuscation(format!(
                "PSK must be 32 bytes, got {}",
                psk_bytes.len()
            )));
        }

        // Derive header key from PSK using BLAKE2s
        let header_key = derive_header_key(&psk_bytes);

        if config.min_padding > config.max_padding {
            return Err(Error::Obfuscation(
                "min_padding must be <= max_padding".to_string(),
            ));
        }

        if config.junk_min > config.junk_max {
            return Err(Error::Obfuscation(
                "junk_min must be <= junk_max".to_string(),
            ));
        }

        Ok(Self {
            enabled: true,
            header_key,
            header_size: config.header_size,
            min_padding: config.min_padding,
            max_padding: config.max_padding,
            junk_min: config.junk_min,
            junk_max: config.junk_max,
        })
    }

    /// Returns whether obfuscation is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Obfuscate a packet for sending
    pub fn obfuscate(&self, packet: &Packet) -> Bytes {
        if !self.enabled {
            return packet.encode();
        }

        let encoded = packet.encode();
        let mut rng = rand::rng();

        // Calculate padding length
        let padding_len = if self.min_padding == self.max_padding {
            self.min_padding
        } else {
            rng.random_range(self.min_padding..=self.max_padding)
        };

        let total_size = self.header_size + encoded.len() + padding_len + 2;
        let mut buf = BytesMut::with_capacity(total_size);

        // 1. Random header
        if self.header_size > 0 {
            let mut header = vec![0u8; self.header_size];
            rng.fill(&mut header[..]);
            buf.put_slice(&header);
        }

        // 2. XOR packet type byte with header_key[0]
        buf.put_u8(encoded[0] ^ self.header_key[0]);

        // 3. Payload (rest of encoded packet)
        if encoded.len() > 1 {
            buf.put_slice(&encoded[1..]);
        }

        // 4. Random padding
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            rng.fill(&mut padding[..]);
            buf.put_slice(&padding);
        }

        // 5. Padding length (2 bytes LE) at the end
        buf.put_u16_le(padding_len as u16);

        buf.freeze()
    }

    /// Deobfuscate a received packet
    pub fn deobfuscate(&self, data: Bytes) -> Result<Packet, Error> {
        if !self.enabled {
            return Packet::decode(data);
        }

        // Minimum size: header_size + 1 (type) + 2 (padding_len)
        let min_size = self.header_size + 1 + 2;
        if data.len() < min_size {
            return Err(Error::InvalidPacket);
        }

        // 1. Read padding_len from last 2 bytes
        let padding_len = u16::from_le_bytes([data[data.len() - 2], data[data.len() - 1]]) as usize;

        // Validate: enough data after stripping header, padding, and padding_len
        if data.len() < 2 + padding_len {
            return Err(Error::InvalidPacket);
        }
        let content_end = data.len() - 2 - padding_len;
        if content_end <= self.header_size {
            return Err(Error::InvalidPacket);
        }

        // 2. Strip header
        let content_start = self.header_size;

        // 3. Extract the actual packet bytes
        let packet_data = &data[content_start..content_end];
        if packet_data.is_empty() {
            return Err(Error::InvalidPacket);
        }

        // 4. XOR first byte to restore PacketType
        let mut restored = BytesMut::with_capacity(packet_data.len());
        restored.put_u8(packet_data[0] ^ self.header_key[0]);
        if packet_data.len() > 1 {
            restored.put_slice(&packet_data[1..]);
        }

        Packet::decode(restored.freeze())
    }

    /// Generate a junk packet (random bytes, 16-128 bytes)
    pub fn generate_junk_packet(&self) -> Bytes {
        let mut rng = rand::rng();
        let size = rng.random_range(16..=128);
        let mut data = vec![0u8; size];
        rng.fill(&mut data[..]);
        Bytes::from(data)
    }

    /// Return random junk count in [junk_min, junk_max]
    pub fn junk_count(&self) -> usize {
        if !self.enabled || self.junk_max == 0 {
            return 0;
        }
        if self.junk_min == self.junk_max {
            return self.junk_min as usize;
        }
        let mut rng = rand::rng();
        rng.random_range(self.junk_min..=self.junk_max) as usize
    }
}

/// Derive a 32-byte header key from PSK using BLAKE2s
fn derive_header_key(psk: &[u8]) -> [u8; 32] {
    use blake2::Blake2sMac;
    use blake2::digest::Mac;
    use blake2::digest::consts::U32;

    type Blake2sMac256 = Blake2sMac<U32>;

    let mac = Blake2sMac256::new_from_slice(psk).expect("BLAKE2s accepts any key size");
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::keys;
    use crate::protocol::PacketType;

    fn test_psk() -> String {
        keys::encode(&[0xABu8; 32])
    }

    fn enabled_config() -> ObfuscationConfig {
        ObfuscationConfig {
            enabled: true,
            psk: test_psk(),
            header_size: 4,
            min_padding: 8,
            max_padding: 32,
            junk_min: 1,
            junk_max: 3,
        }
    }

    #[test]
    fn test_roundtrip_data_packet() {
        let obf = PacketObfuscator::new(&enabled_config()).unwrap();
        let original = Packet::data(b"hello world".to_vec());

        let obfuscated = obf.obfuscate(&original);
        let restored = obf.deobfuscate(obfuscated).unwrap();

        assert_eq!(restored.packet_type, PacketType::Data);
        assert_eq!(&restored.payload[..], b"hello world");
    }

    #[test]
    fn test_roundtrip_all_packet_types() {
        let obf = PacketObfuscator::new(&enabled_config()).unwrap();
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
            let obfuscated = obf.obfuscate(&original);
            let restored = obf.deobfuscate(obfuscated).unwrap();
            assert_eq!(
                restored.packet_type, ptype,
                "Roundtrip failed for {:?}",
                ptype
            );
        }
    }

    #[test]
    fn test_obfuscated_differs_from_plain() {
        let obf = PacketObfuscator::new(&enabled_config()).unwrap();
        let packet = Packet::data(b"test".to_vec());

        let plain = packet.encode();
        let obfuscated = obf.obfuscate(&packet);

        // Obfuscated should be larger (header + padding + 2 bytes padding_len)
        assert!(obfuscated.len() > plain.len());
        // First byte should differ (XOR'd + random header prefix)
        assert_ne!(obfuscated[0], plain[0]);
    }

    #[test]
    fn test_padding_applied() {
        let config = ObfuscationConfig {
            enabled: true,
            psk: test_psk(),
            header_size: 0,
            min_padding: 16,
            max_padding: 16, // fixed padding for deterministic test
            junk_min: 0,
            junk_max: 0,
        };
        let obf = PacketObfuscator::new(&config).unwrap();
        let packet = Packet::data(b"x".to_vec());

        let plain = packet.encode(); // 1 type + 1 payload = 2
        let obfuscated = obf.obfuscate(&packet);

        // Expected: 0 header + 2 (type+payload) + 16 padding + 2 padding_len = 20
        assert_eq!(obfuscated.len(), plain.len() + 16 + 2);
    }

    #[test]
    fn test_header_applied() {
        let config = ObfuscationConfig {
            enabled: true,
            psk: test_psk(),
            header_size: 8,
            min_padding: 0,
            max_padding: 0,
            junk_min: 0,
            junk_max: 0,
        };
        let obf = PacketObfuscator::new(&config).unwrap();
        let packet = Packet::data(b"x".to_vec());

        let plain = packet.encode(); // 2 bytes
        let obfuscated = obf.obfuscate(&packet);

        // Expected: 8 header + 2 (type+payload) + 0 padding + 2 padding_len = 12
        assert_eq!(obfuscated.len(), 8 + plain.len() + 2);
    }

    #[test]
    fn test_disabled_mode_passthrough() {
        let config = ObfuscationConfig::default(); // enabled = false
        let obf = PacketObfuscator::new(&config).unwrap();
        let packet = Packet::data(b"hello".to_vec());

        let plain = packet.encode();
        let obfuscated = obf.obfuscate(&packet);

        assert_eq!(plain, obfuscated);

        let restored = obf.deobfuscate(obfuscated).unwrap();
        assert_eq!(restored.packet_type, PacketType::Data);
        assert_eq!(&restored.payload[..], b"hello");
    }

    #[test]
    fn test_invalid_data_returns_error() {
        let obf = PacketObfuscator::new(&enabled_config()).unwrap();

        // Too short
        let result = obf.deobfuscate(Bytes::from(vec![1, 2]));
        assert!(result.is_err());

        // Corrupted padding_len (points beyond data)
        let mut bad = vec![0u8; 10];
        bad[8] = 0xFF; // padding_len LE = 0x00FF = 255, way too large
        bad[9] = 0x00;
        let result = obf.deobfuscate(Bytes::from(bad));
        assert!(result.is_err());
    }

    #[test]
    fn test_junk_packet_generation() {
        let obf = PacketObfuscator::new(&enabled_config()).unwrap();
        let junk = obf.generate_junk_packet();
        assert!(junk.len() >= 16 && junk.len() <= 128);
    }

    #[test]
    fn test_junk_count_range() {
        let obf = PacketObfuscator::new(&enabled_config()).unwrap();
        for _ in 0..50 {
            let count = obf.junk_count();
            assert!(count >= 1 && count <= 3);
        }
    }

    #[test]
    fn test_junk_count_disabled() {
        let config = ObfuscationConfig::default();
        let obf = PacketObfuscator::new(&config).unwrap();
        assert_eq!(obf.junk_count(), 0);
    }

    #[test]
    fn test_psk_required_when_enabled() {
        let config = ObfuscationConfig {
            enabled: true,
            psk: String::new(),
            ..Default::default()
        };
        let result = PacketObfuscator::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_psk_length() {
        let config = ObfuscationConfig {
            enabled: true,
            psk: keys::encode(&[0u8; 16]), // 16 bytes instead of 32
            ..Default::default()
        };
        let result = PacketObfuscator::new(&config);
        assert!(result.is_err());
    }
}
