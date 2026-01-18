//! Noise Protocol Handshake implementation
//!
//! Uses Noise IK pattern:
//! - Initiator (client) knows responder's (server) static public key
//! - Provides mutual authentication and forward secrecy

use snow::{Builder, HandshakeState, StatelessTransportState};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::Error;
use crate::crypto::NOISE_PATTERN;

/// Maximum size for handshake messages
pub const MAX_HANDSHAKE_MSG_SIZE: usize = 256;

/// Handshake initiator (client side)
pub struct Initiator {
    state: HandshakeState,
}

impl Initiator {
    /// Create a new initiator with local keypair and remote's public key
    ///
    /// # Arguments
    /// * `local_private` - Our private key (32 bytes)
    /// * `remote_public` - Server's public key (32 bytes)
    pub fn new(local_private: &[u8], remote_public: &[u8]) -> Result<Self, Error> {
        let state = Builder::new(NOISE_PATTERN.parse().unwrap())
            .local_private_key(local_private)?
            .remote_public_key(remote_public)?
            .build_initiator()?;

        Ok(Self { state })
    }

    /// Write first handshake message (-> e, es, s, ss)
    ///
    /// Returns the message to send to responder
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; MAX_HANDSHAKE_MSG_SIZE];
        let len = self.state.write_message(payload, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Read response from responder (<- e, ee, se)
    ///
    /// Returns the decrypted payload
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; MAX_HANDSHAKE_MSG_SIZE];
        let len = self.state.read_message(message, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Check if handshake is complete
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Convert to transport mode after handshake completion
    pub fn into_transport(self) -> Result<Transport, Error> {
        if !self.state.is_handshake_finished() {
            return Err(Error::HandshakeNotCompleted);
        }
        let transport = self.state.into_stateless_transport_mode()?;
        Ok(Transport::new(transport))
    }
}

/// Handshake responder (server side)
pub struct Responder {
    state: HandshakeState,
}

impl Responder {
    /// Create a new responder with local keypair
    ///
    /// # Arguments
    /// * `local_private` - Our private key (32 bytes)
    pub fn new(local_private: &[u8]) -> Result<Self, Error> {
        let state = Builder::new(NOISE_PATTERN.parse().unwrap())
            .local_private_key(local_private)?
            .build_responder()?;

        Ok(Self { state })
    }

    /// Read first message from initiator (-> e, es, s, ss)
    ///
    /// Returns the decrypted payload
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; MAX_HANDSHAKE_MSG_SIZE];
        let len = self.state.read_message(message, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Write response message (<- e, ee, se)
    ///
    /// Returns the message to send to initiator
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; MAX_HANDSHAKE_MSG_SIZE];
        let len = self.state.write_message(payload, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Check if handshake is complete
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Get the remote peer's static public key after handshake
    pub fn get_remote_static(&self) -> Option<&[u8]> {
        self.state.get_remote_static()
    }

    /// Convert to transport mode after handshake completion
    pub fn into_transport(self) -> Result<Transport, Error> {
        if !self.state.is_handshake_finished() {
            return Err(Error::HandshakeNotCompleted);
        }
        let transport = self.state.into_stateless_transport_mode()?;
        Ok(Transport::new(transport))
    }
}

/// Encrypted transport after handshake completion
///
/// Uses StatelessTransportState with explicit nonce for each packet,
/// allowing out-of-order packet delivery over UDP.
pub struct Transport {
    state: StatelessTransportState,
    /// Counter for outgoing messages
    send_counter: AtomicU64,
    /// Sliding window for replay protection
    recv_window: SlidingWindow,
}

/// Maximum overhead added by encryption (poly1305 tag + 8-byte counter)
pub const TRANSPORT_OVERHEAD: usize = 16;

/// Counter size in bytes (prepended to each encrypted message)
pub const COUNTER_SIZE: usize = 8;

/// Sliding window size for replay protection (bits)
const WINDOW_SIZE: u64 = 2048;

/// Sliding window for replay protection and out-of-order handling
struct SlidingWindow {
    /// Highest nonce seen
    highest: AtomicU64,
    /// Bitmap for nonces in window [highest - WINDOW_SIZE + 1, highest]
    bitmap: std::sync::Mutex<Vec<u64>>,
}

impl SlidingWindow {
    fn new() -> Self {
        Self {
            highest: AtomicU64::new(0),
            bitmap: std::sync::Mutex::new(vec![0u64; (WINDOW_SIZE / 64) as usize]),
        }
    }

    /// Check if nonce is valid (not replayed) and mark as seen
    /// Returns true if valid, false if replayed or too old
    fn check_and_mark(&self, nonce: u64) -> bool {
        let highest = self.highest.load(Ordering::Relaxed);

        // Too old - outside the window
        if nonce + WINDOW_SIZE <= highest {
            return false;
        }

        let mut bitmap = self.bitmap.lock().unwrap();

        // If new highest, update and shift window
        if nonce > highest {
            let shift = nonce - highest;
            if shift >= WINDOW_SIZE {
                // Reset bitmap
                for b in bitmap.iter_mut() {
                    *b = 0;
                }
            } else {
                // Shift bitmap
                let shift_words = (shift / 64) as usize;
                let shift_bits = (shift % 64) as u32;

                if shift_words > 0 {
                    bitmap.rotate_left(shift_words);
                    for b in bitmap.iter_mut().rev().take(shift_words) {
                        *b = 0;
                    }
                }
                if shift_bits > 0 {
                    let mut carry = 0u64;
                    for b in bitmap.iter_mut() {
                        let new_carry = *b >> (64 - shift_bits);
                        *b = (*b << shift_bits) | carry;
                        carry = new_carry;
                    }
                }
            }
            self.highest.store(nonce, Ordering::Relaxed);
        }

        // Calculate position in bitmap
        let current_highest = self.highest.load(Ordering::Relaxed);
        let index = current_highest - nonce;
        let word_idx = (index / 64) as usize;
        let bit_idx = (index % 64) as u32;

        if word_idx >= bitmap.len() {
            return false;
        }

        // Check if already seen
        let mask = 1u64 << bit_idx;
        if bitmap[word_idx] & mask != 0 {
            return false; // Replay
        }

        // Mark as seen
        bitmap[word_idx] |= mask;
        true
    }
}

impl Transport {
    fn new(state: StatelessTransportState) -> Self {
        Self {
            state,
            send_counter: AtomicU64::new(0),
            recv_window: SlidingWindow::new(),
        }
    }

    /// Encrypt a message with explicit counter
    ///
    /// Returns: [8-byte counter][encrypted ciphertext]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);

        let mut buf = vec![0u8; COUNTER_SIZE + plaintext.len() + TRANSPORT_OVERHEAD];

        // Write counter (little-endian)
        buf[..COUNTER_SIZE].copy_from_slice(&counter.to_le_bytes());

        // Encrypt with counter as nonce
        let len = self
            .state
            .write_message(counter, plaintext, &mut buf[COUNTER_SIZE..])?;
        buf.truncate(COUNTER_SIZE + len);

        Ok(buf)
    }

    /// Decrypt a message with explicit counter
    ///
    /// Input: [8-byte counter][encrypted ciphertext]
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() < COUNTER_SIZE + TRANSPORT_OVERHEAD {
            return Err(Error::InvalidPacket);
        }

        // Read counter
        let counter = u64::from_le_bytes(data[..COUNTER_SIZE].try_into().unwrap());

        // Check replay protection
        if !self.recv_window.check_and_mark(counter) {
            return Err(Error::ReplayedPacket);
        }

        // Decrypt
        let ciphertext = &data[COUNTER_SIZE..];
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self.state.read_message(counter, ciphertext, &mut buf)?;
        buf.truncate(len);

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;

    #[test]
    fn test_handshake_ik() {
        // Generate keypairs
        let client_keys = generate_keypair().unwrap();
        let server_keys = generate_keypair().unwrap();

        // Create initiator (client) with server's public key
        let mut initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();

        // Create responder (server)
        let mut responder = Responder::new(&server_keys.private).unwrap();

        // Step 1: Client -> Server (-> e, es, s, ss)
        let msg1 = initiator.write_message(b"hello").unwrap();
        assert!(!initiator.is_finished());

        // Step 2: Server processes and responds (<- e, ee, se)
        let payload1 = responder.read_message(&msg1).unwrap();
        assert_eq!(&payload1, b"hello");

        let msg2 = responder.write_message(b"world").unwrap();
        assert!(responder.is_finished());

        // Step 3: Client processes response
        let payload2 = initiator.read_message(&msg2).unwrap();
        assert_eq!(&payload2, b"world");
        assert!(initiator.is_finished());

        // Verify server got client's public key
        assert_eq!(
            responder.get_remote_static(),
            Some(client_keys.public.as_slice())
        );
    }

    #[test]
    fn test_transport_encryption() {
        // Setup handshake
        let client_keys = generate_keypair().unwrap();
        let server_keys = generate_keypair().unwrap();

        let mut initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
        let mut responder = Responder::new(&server_keys.private).unwrap();

        // Complete handshake
        let msg1 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg1).unwrap();
        let msg2 = responder.write_message(&[]).unwrap();
        initiator.read_message(&msg2).unwrap();

        // Convert to transport mode
        let client_transport = initiator.into_transport().unwrap();
        let server_transport = responder.into_transport().unwrap();

        // Test encryption/decryption client -> server
        let plaintext = b"secret message from client";
        let ciphertext = client_transport.encrypt(plaintext).unwrap();
        let decrypted = server_transport.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);

        // Test encryption/decryption server -> client
        let plaintext2 = b"secret response from server";
        let ciphertext2 = server_transport.encrypt(plaintext2).unwrap();
        let decrypted2 = client_transport.decrypt(&ciphertext2).unwrap();
        assert_eq!(&decrypted2, plaintext2);
    }

    #[test]
    fn test_handshake_not_completed_error() {
        let client_keys = generate_keypair().unwrap();
        let server_keys = generate_keypair().unwrap();

        let initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();

        // Try to convert to transport before handshake is complete
        let result = initiator.into_transport();
        assert!(matches!(result, Err(Error::HandshakeNotCompleted)));
    }
}
