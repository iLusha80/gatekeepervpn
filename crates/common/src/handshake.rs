//! Noise Protocol Handshake implementation
//!
//! Uses Noise IK pattern:
//! - Initiator (client) knows responder's (server) static public key
//! - Provides mutual authentication and forward secrecy

use snow::{Builder, HandshakeState, TransportState};

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
        Ok(Transport::new(self.state.into_transport_mode()?))
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
        Ok(Transport::new(self.state.into_transport_mode()?))
    }
}

/// Encrypted transport after handshake completion
pub struct Transport {
    state: TransportState,
}

/// Maximum overhead added by encryption (poly1305 tag)
pub const TRANSPORT_OVERHEAD: usize = 16;

impl Transport {
    fn new(state: TransportState) -> Self {
        Self { state }
    }

    /// Encrypt a message
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    ///
    /// Returns encrypted ciphertext
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; plaintext.len() + TRANSPORT_OVERHEAD];
        let len = self.state.write_message(plaintext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypt a message
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data
    ///
    /// Returns decrypted plaintext
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self.state.read_message(ciphertext, &mut buf)?;
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
        let mut client_transport = initiator.into_transport().unwrap();
        let mut server_transport = responder.into_transport().unwrap();

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
