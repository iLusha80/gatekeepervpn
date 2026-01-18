//! Cryptographic primitives for GatekeeperVPN
//!
//! Uses Noise Protocol Framework (IK pattern) with:
//! - X25519 for key exchange
//! - ChaCha20-Poly1305 for symmetric encryption
//! - BLAKE2s for hashing

use snow::{Builder, Keypair};

use crate::Error;

/// Noise protocol pattern: IK
/// - I: Initiator sends their static key
/// - K: Responder's static key is known to initiator
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Generate a new X25519 keypair
pub fn generate_keypair() -> Result<Keypair, Error> {
    let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
    Ok(builder.generate_keypair()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let keypair = generate_keypair().unwrap();
        assert_eq!(keypair.public.len(), 32);
        assert_eq!(keypair.private.len(), 32);
    }
}
