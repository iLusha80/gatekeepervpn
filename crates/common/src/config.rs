//! Configuration structures for server and client

use serde::{Deserialize, Serialize};

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen address (e.g., "0.0.0.0:51820")
    pub listen: String,
    /// Server's private key (base64 encoded)
    pub private_key: String,
    /// TUN interface IP address
    #[serde(default = "default_server_tun_address")]
    pub tun_address: String,
    /// TUN interface netmask
    #[serde(default = "default_tun_netmask_server")]
    pub tun_netmask: String,
    /// TUN MTU
    #[serde(default = "default_tun_mtu_server")]
    pub tun_mtu: u16,
}

fn default_server_tun_address() -> String {
    "10.0.0.1".to_string()
}

fn default_tun_netmask_server() -> String {
    "255.255.255.0".to_string()
}

fn default_tun_mtu_server() -> u16 {
    1400
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:51820".to_string(),
            private_key: String::new(),
            tun_address: default_server_tun_address(),
            tun_netmask: default_tun_netmask_server(),
            tun_mtu: default_tun_mtu_server(),
        }
    }
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server address (e.g., "127.0.0.1:51820")
    pub server: String,
    /// Client's private key (base64 encoded)
    pub private_key: String,
    /// Server's public key (base64 encoded)
    pub server_public_key: String,
    /// TUN interface IP address
    #[serde(default = "default_tun_address")]
    pub tun_address: String,
    /// TUN interface netmask
    #[serde(default = "default_tun_netmask")]
    pub tun_netmask: String,
    /// TUN MTU
    #[serde(default = "default_tun_mtu")]
    pub tun_mtu: u16,
}

fn default_tun_address() -> String {
    "10.0.0.2".to_string()
}

fn default_tun_netmask() -> String {
    "255.255.255.0".to_string()
}

fn default_tun_mtu() -> u16 {
    1400
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:51820".to_string(),
            private_key: String::new(),
            server_public_key: String::new(),
            tun_address: default_tun_address(),
            tun_netmask: default_tun_netmask(),
            tun_mtu: default_tun_mtu(),
        }
    }
}

/// Base64 encoding/decoding utilities for keys
pub mod keys {
    use base64::{engine::general_purpose::STANDARD, Engine};

    use crate::Error;

    /// Encode bytes to base64 string
    pub fn encode(data: &[u8]) -> String {
        STANDARD.encode(data)
    }

    /// Decode base64 string to bytes
    pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
        STANDARD.decode(s).map_err(|_| Error::InvalidKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_encode_decode() {
        let original = b"32-byte-key-for-testing-purposes";
        let encoded = keys::encode(original);
        let decoded = keys::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.listen, "0.0.0.0:51820");
    }

    #[test]
    fn test_client_config_default() {
        let config = ClientConfig::default();
        assert_eq!(config.server, "127.0.0.1:51820");
    }
}
