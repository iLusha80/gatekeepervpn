//! Noise Protocol Handshake implementation
//!
//! Uses Noise IK pattern:
//! - Initiator (client) knows responder's (server) static public key
//! - Provides mutual authentication and forward secrecy

use blake2::Blake2sMac;
use blake2::digest::Mac;
use blake2::digest::consts::U8;
use snow::{Builder, HandshakeState, StatelessTransportState};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::Error;
use crate::crypto::NOISE_PATTERN;

/// BLAKE2s MAC producing 8-byte output for counter mask derivation
type Blake2sMac64 = Blake2sMac<U8>;

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
        let handshake_hash = self.state.get_handshake_hash().to_vec();
        let transport = self.state.into_stateless_transport_mode()?;
        Ok(Transport::new(transport, &handshake_hash))
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
        let handshake_hash = self.state.get_handshake_hash().to_vec();
        let transport = self.state.into_stateless_transport_mode()?;
        Ok(Transport::new(transport, &handshake_hash))
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
    /// XOR mask for counter bytes on the wire (anti-DPI: hides monotonic counter)
    counter_mask: [u8; 8],
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
    fn new(state: StatelessTransportState, handshake_hash: &[u8]) -> Self {
        // Derive counter_mask from handshake_hash using keyed BLAKE2s
        let counter_mask = Self::derive_counter_mask(handshake_hash);
        Self {
            state,
            send_counter: AtomicU64::new(0),
            recv_window: SlidingWindow::new(),
            counter_mask,
        }
    }

    /// Derive an 8-byte counter mask from the handshake hash.
    /// Both sides derive the same mask since they share the same handshake_hash.
    fn derive_counter_mask(handshake_hash: &[u8]) -> [u8; 8] {
        let mut mac =
            Blake2sMac64::new_from_slice(b"counter-mask").expect("BLAKE2s accepts any key size");
        mac.update(handshake_hash);
        let result = mac.finalize();
        let bytes = result.into_bytes();
        let mut mask = [0u8; 8];
        mask.copy_from_slice(&bytes);
        mask
    }

    /// XOR counter bytes with counter_mask for on-wire obfuscation
    fn mask_counter(&self, counter: u64) -> [u8; 8] {
        let counter_bytes = counter.to_le_bytes();
        let mut masked = [0u8; 8];
        for i in 0..8 {
            masked[i] = counter_bytes[i] ^ self.counter_mask[i];
        }
        masked
    }

    /// Unmask counter bytes from on-wire format back to real counter
    fn unmask_counter(&self, masked_bytes: &[u8; 8]) -> u64 {
        let mut counter_bytes = [0u8; 8];
        for i in 0..8 {
            counter_bytes[i] = masked_bytes[i] ^ self.counter_mask[i];
        }
        u64::from_le_bytes(counter_bytes)
    }

    /// Encrypt a message with explicit counter
    ///
    /// Returns: [8-byte masked counter][encrypted ciphertext]
    /// The counter is XORed with counter_mask on the wire to prevent DPI
    /// from identifying the monotonically increasing plaintext nonce.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);

        let mut buf = vec![0u8; COUNTER_SIZE + plaintext.len() + TRANSPORT_OVERHEAD];

        // Write masked counter (anti-DPI: not plaintext monotonic)
        buf[..COUNTER_SIZE].copy_from_slice(&self.mask_counter(counter));

        // Encrypt with real counter as nonce (AEAD uses unmasked value)
        let len = self
            .state
            .write_message(counter, plaintext, &mut buf[COUNTER_SIZE..])?;
        buf.truncate(COUNTER_SIZE + len);

        Ok(buf)
    }

    /// Проверяет, может ли этот transport расшифровать пакет.
    /// Не обновляет replay window — используется для roaming detection.
    pub fn can_decrypt(&self, data: &[u8]) -> bool {
        if data.len() < COUNTER_SIZE + TRANSPORT_OVERHEAD {
            return false;
        }
        let masked_bytes: [u8; 8] = data[..COUNTER_SIZE].try_into().unwrap();
        let counter = self.unmask_counter(&masked_bytes);
        let ciphertext = &data[COUNTER_SIZE..];
        let mut buf = vec![0u8; ciphertext.len()];
        self.state
            .read_message(counter, ciphertext, &mut buf)
            .is_ok()
    }

    /// Decrypt a message with explicit counter
    ///
    /// Input: [8-byte masked counter][encrypted ciphertext]
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() < COUNTER_SIZE + TRANSPORT_OVERHEAD {
            return Err(Error::InvalidPacket);
        }

        // Read and unmask counter
        let masked_bytes: [u8; 8] = data[..COUNTER_SIZE].try_into().unwrap();
        let counter = self.unmask_counter(&masked_bytes);

        // Check replay protection (with real counter)
        if !self.recv_window.check_and_mark(counter) {
            return Err(Error::ReplayedPacket);
        }

        // Decrypt with real counter as nonce
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
    fn test_can_decrypt_valid_key() {
        let client_keys = generate_keypair().unwrap();
        let server_keys = generate_keypair().unwrap();

        let mut initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
        let mut responder = Responder::new(&server_keys.private).unwrap();

        let msg1 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg1).unwrap();
        let msg2 = responder.write_message(&[]).unwrap();
        initiator.read_message(&msg2).unwrap();

        let client_transport = initiator.into_transport().unwrap();
        let server_transport = responder.into_transport().unwrap();

        let ciphertext = client_transport.encrypt(b"test data").unwrap();
        assert!(server_transport.can_decrypt(&ciphertext));
    }

    #[test]
    fn test_can_decrypt_wrong_key() {
        let client_keys = generate_keypair().unwrap();
        let server_keys = generate_keypair().unwrap();
        let other_server_keys = generate_keypair().unwrap();

        // Session 1: client <-> server
        let mut initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
        let mut responder = Responder::new(&server_keys.private).unwrap();

        let msg1 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg1).unwrap();
        let msg2 = responder.write_message(&[]).unwrap();
        initiator.read_message(&msg2).unwrap();

        let client_transport = initiator.into_transport().unwrap();

        // Session 2: different server (wrong key)
        let other_client_keys = generate_keypair().unwrap();
        let mut initiator2 =
            Initiator::new(&other_client_keys.private, &other_server_keys.public).unwrap();
        let mut responder2 = Responder::new(&other_server_keys.private).unwrap();

        let msg1b = initiator2.write_message(&[]).unwrap();
        responder2.read_message(&msg1b).unwrap();
        let msg2b = responder2.write_message(&[]).unwrap();
        initiator2.read_message(&msg2b).unwrap();

        let other_transport = responder2.into_transport().unwrap();

        let ciphertext = client_transport.encrypt(b"test data").unwrap();
        assert!(!other_transport.can_decrypt(&ciphertext));
    }

    #[test]
    fn test_can_decrypt_no_side_effects() {
        let client_keys = generate_keypair().unwrap();
        let server_keys = generate_keypair().unwrap();

        let mut initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
        let mut responder = Responder::new(&server_keys.private).unwrap();

        let msg1 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg1).unwrap();
        let msg2 = responder.write_message(&[]).unwrap();
        initiator.read_message(&msg2).unwrap();

        let client_transport = initiator.into_transport().unwrap();
        let server_transport = responder.into_transport().unwrap();

        let ciphertext = client_transport.encrypt(b"test data").unwrap();

        // can_decrypt should not affect replay window
        assert!(server_transport.can_decrypt(&ciphertext));
        assert!(server_transport.can_decrypt(&ciphertext));

        // decrypt should still work after can_decrypt calls
        let plaintext = server_transport.decrypt(&ciphertext).unwrap();
        assert_eq!(&plaintext, b"test data");
    }

    #[test]
    fn test_can_decrypt_short_data() {
        let client_keys = generate_keypair().unwrap();
        let server_keys = generate_keypair().unwrap();

        let mut initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
        let mut responder = Responder::new(&server_keys.private).unwrap();

        let msg1 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg1).unwrap();
        let msg2 = responder.write_message(&[]).unwrap();
        initiator.read_message(&msg2).unwrap();

        let server_transport = responder.into_transport().unwrap();

        assert!(!server_transport.can_decrypt(&[]));
        assert!(!server_transport.can_decrypt(&[0; 10]));
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

    // Helper: complete handshake and return (client_transport, server_transport)
    fn make_transport_pair() -> (Transport, Transport) {
        let client_keys = generate_keypair().unwrap();
        let server_keys = generate_keypair().unwrap();

        let mut initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
        let mut responder = Responder::new(&server_keys.private).unwrap();

        let msg1 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg1).unwrap();
        let msg2 = responder.write_message(&[]).unwrap();
        initiator.read_message(&msg2).unwrap();

        let client_t = initiator.into_transport().unwrap();
        let server_t = responder.into_transport().unwrap();
        (client_t, server_t)
    }

    // ===== SlidingWindow tests (through Transport) =====

    #[test]
    fn test_sliding_window_sequential_nonces() {
        let (client_t, server_t) = make_transport_pair();
        for i in 0..10u32 {
            let ct = client_t.encrypt(&i.to_le_bytes()).unwrap();
            let pt = server_t.decrypt(&ct).unwrap();
            assert_eq!(pt, i.to_le_bytes());
        }
    }

    #[test]
    fn test_sliding_window_replay_rejected() {
        let (client_t, server_t) = make_transport_pair();
        let ct = client_t.encrypt(b"msg").unwrap();
        server_t.decrypt(&ct).unwrap();
        // Second decrypt of same ciphertext must fail
        assert!(matches!(server_t.decrypt(&ct), Err(Error::ReplayedPacket)));
    }

    #[test]
    fn test_sliding_window_out_of_order() {
        let (client_t, server_t) = make_transport_pair();
        // Encrypt 3 messages (nonces 0,1,2)
        let ct0 = client_t.encrypt(b"zero").unwrap();
        let ct1 = client_t.encrypt(b"one").unwrap();
        let ct2 = client_t.encrypt(b"two").unwrap();
        // Decrypt in order 2, 0, 1
        assert_eq!(server_t.decrypt(&ct2).unwrap(), b"two");
        assert_eq!(server_t.decrypt(&ct0).unwrap(), b"zero");
        assert_eq!(server_t.decrypt(&ct1).unwrap(), b"one");
    }

    #[test]
    fn test_sliding_window_too_old_nonce() {
        let (client_t, server_t) = make_transport_pair();
        // Encrypt first message (nonce 0)
        let ct_old = client_t.encrypt(b"old").unwrap();
        // Advance nonce beyond window (WINDOW_SIZE = 2048)
        for _ in 0..2049 {
            let ct = client_t.encrypt(b"x").unwrap();
            server_t.decrypt(&ct).unwrap();
        }
        // Now nonce 0 is outside the window
        assert!(matches!(
            server_t.decrypt(&ct_old),
            Err(Error::ReplayedPacket)
        ));
    }

    #[test]
    fn test_sliding_window_large_gap() {
        let (client_t, server_t) = make_transport_pair();
        // Encrypt but skip some nonces (encrypt 1000 messages, only decrypt last)
        let mut ciphertexts = Vec::new();
        for i in 0..1001u32 {
            ciphertexts.push(client_t.encrypt(&i.to_le_bytes()).unwrap());
        }
        // Decrypt only the last one — big jump from 0 to 1000
        let pt = server_t.decrypt(&ciphertexts[1000]).unwrap();
        assert_eq!(pt, 1000u32.to_le_bytes());
    }

    #[test]
    fn test_sliding_window_full_reset_beyond_window() {
        let (client_t, server_t) = make_transport_pair();
        // Encrypt a few messages
        for _ in 0..5 {
            let ct = client_t.encrypt(b"a").unwrap();
            server_t.decrypt(&ct).unwrap();
        }
        // Skip more than WINDOW_SIZE nonces
        for _ in 0..2100 {
            client_t.encrypt(b"skip").unwrap(); // not decrypted
        }
        // Now encrypt and decrypt — should work (bitmap was fully reset)
        let ct = client_t.encrypt(b"after_reset").unwrap();
        assert_eq!(server_t.decrypt(&ct).unwrap(), b"after_reset");
    }

    #[test]
    fn test_sliding_window_boundary_edge() {
        let (client_t, server_t) = make_transport_pair();
        // Encrypt messages with nonces 0..=2047 (fill window exactly)
        let mut cts: Vec<Vec<u8>> = Vec::new();
        for _ in 0..2048 {
            cts.push(client_t.encrypt(b"b").unwrap());
        }
        // Decrypt only the last one (nonce 2047)
        server_t.decrypt(&cts[2047]).unwrap();
        // Nonce 0 is exactly at boundary: highest(2047) - 0 = 2047 < WINDOW_SIZE(2048) => still valid
        assert!(server_t.decrypt(&cts[0]).is_ok());
    }

    #[test]
    fn test_sliding_window_many_packets() {
        let (client_t, server_t) = make_transport_pair();
        for i in 0..5000u32 {
            let ct = client_t.encrypt(&i.to_le_bytes()).unwrap();
            let pt = server_t.decrypt(&ct).unwrap();
            assert_eq!(pt, i.to_le_bytes());
        }
    }

    #[test]
    fn test_transport_empty_payload() {
        let (client_t, server_t) = make_transport_pair();
        let ct = client_t.encrypt(b"").unwrap();
        let pt = server_t.decrypt(&ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_handshake_wrong_server_key() {
        let client_keys = generate_keypair().unwrap();
        let server_keys = generate_keypair().unwrap();
        let wrong_keys = generate_keypair().unwrap();

        // Client uses wrong server public key
        let mut initiator = Initiator::new(&client_keys.private, &wrong_keys.public).unwrap();
        let mut responder = Responder::new(&server_keys.private).unwrap();

        let msg1 = initiator.write_message(&[]).unwrap();
        // Responder should fail to read — wrong static key
        assert!(responder.read_message(&msg1).is_err());
    }

    // ===== Counter mask tests (anti-DPI) =====

    #[test]
    fn test_counter_mask_not_zero() {
        let (client_t, _) = make_transport_pair();
        // counter_mask should not be all zeros (extremely unlikely)
        assert_ne!(client_t.counter_mask, [0u8; 8]);
    }

    #[test]
    fn test_counter_mask_same_for_both_sides() {
        // Both sides derive the same counter_mask from the same handshake_hash
        let client_keys = generate_keypair().unwrap();
        let server_keys = generate_keypair().unwrap();

        let mut initiator = Initiator::new(&client_keys.private, &server_keys.public).unwrap();
        let mut responder = Responder::new(&server_keys.private).unwrap();

        let msg1 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg1).unwrap();
        let msg2 = responder.write_message(&[]).unwrap();
        initiator.read_message(&msg2).unwrap();

        let client_t = initiator.into_transport().unwrap();
        let server_t = responder.into_transport().unwrap();

        assert_eq!(client_t.counter_mask, server_t.counter_mask);
    }

    #[test]
    fn test_masked_counter_differs_from_plaintext() {
        let (client_t, _) = make_transport_pair();
        let ciphertext = client_t.encrypt(b"test").unwrap();
        // The first 8 bytes are the masked counter (nonce=0)
        let on_wire_counter = &ciphertext[..COUNTER_SIZE];
        let plaintext_counter = 0u64.to_le_bytes();
        // With counter_mask != 0, the masked counter should differ from plaintext
        assert_ne!(on_wire_counter, &plaintext_counter);
    }

    #[test]
    fn test_counter_mask_roundtrip() {
        let (client_t, _) = make_transport_pair();
        // mask -> unmask should return original counter
        for counter in [0u64, 1, 42, 1000, u64::MAX] {
            let masked = client_t.mask_counter(counter);
            let unmasked = client_t.unmask_counter(&masked);
            assert_eq!(
                counter, unmasked,
                "roundtrip failed for counter {}",
                counter
            );
        }
    }

    #[test]
    fn test_encrypt_decrypt_with_counter_mask() {
        let (client_t, server_t) = make_transport_pair();
        // Encrypt/decrypt should still work correctly with counter masking
        for i in 0..100u32 {
            let msg = format!("message {}", i);
            let ct = client_t.encrypt(msg.as_bytes()).unwrap();
            let pt = server_t.decrypt(&ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_can_decrypt_with_counter_mask() {
        let (client_t, server_t) = make_transport_pair();
        let ct = client_t.encrypt(b"test can_decrypt with mask").unwrap();
        // can_decrypt should work correctly with masked counter
        assert!(server_t.can_decrypt(&ct));
        // After can_decrypt, decrypt should still work
        let pt = server_t.decrypt(&ct).unwrap();
        assert_eq!(pt, b"test can_decrypt with mask");
    }

    #[test]
    fn test_different_sessions_different_masks() {
        let (client_t1, _) = make_transport_pair();
        let (client_t2, _) = make_transport_pair();
        // Different handshake sessions should produce different counter masks
        // (because handshake_hash includes ephemeral keys)
        assert_ne!(client_t1.counter_mask, client_t2.counter_mask);
    }
}
