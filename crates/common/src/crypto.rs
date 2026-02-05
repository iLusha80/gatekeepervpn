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

/// Derive public key from private key (X25519) using snow's DH
pub fn public_key_from_private(private_key: &[u8]) -> Result<Vec<u8>, Error> {
    use snow::resolvers::{CryptoResolver, DefaultResolver};

    let resolver = DefaultResolver;
    let dh = resolver
        .resolve_dh(&snow::params::DHChoice::Curve25519)
        .ok_or(Error::InvalidKey)?;

    let mut dh_state = dh;
    dh_state.set(private_key);
    Ok(dh_state.pubkey().to_vec())
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

    #[test]
    fn test_public_key_from_private_length() {
        let keypair = generate_keypair().unwrap();
        let pubkey = public_key_from_private(&keypair.private).unwrap();
        assert_eq!(pubkey.len(), 32);
    }

    #[test]
    fn test_public_key_from_private_deterministic() {
        let keypair = generate_keypair().unwrap();
        let pub1 = public_key_from_private(&keypair.private).unwrap();
        let pub2 = public_key_from_private(&keypair.private).unwrap();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_public_key_matches_keypair() {
        let keypair = generate_keypair().unwrap();
        let derived = public_key_from_private(&keypair.private).unwrap();
        assert_eq!(derived, keypair.public);
    }
}
