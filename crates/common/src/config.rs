//! Configuration structures for server and client

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

// ============================================================================
// Peer Configuration (for per-client management)
// ============================================================================

/// Configuration for a single VPN peer (client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Human-readable name (e.g., "laptop-ilya")
    pub name: String,
    /// Client's public key (base64 encoded)
    pub public_key: String,
    /// Assigned VPN IP address
    pub assigned_ip: Ipv4Addr,
    /// Creation timestamp (ISO 8601)
    #[serde(default = "default_created_at")]
    pub created_at: String,
}

fn default_created_at() -> String {
    chrono::Utc::now().to_rfc3339()
}

impl PeerConfig {
    /// Create a new peer config
    pub fn new(name: String, public_key: String, assigned_ip: Ipv4Addr) -> Self {
        Self {
            name,
            public_key,
            assigned_ip,
            created_at: default_created_at(),
        }
    }
}

/// Peers configuration file (peers.toml)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeersConfig {
    /// Network address (e.g., "10.10.10.0")
    pub subnet: String,
    /// Subnet mask in CIDR notation (e.g., 24)
    pub subnet_mask: u8,
    /// Next IP to allocate (for sequential allocation)
    pub next_ip: Ipv4Addr,
    /// List of configured peers
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

impl PeersConfig {
    /// Create a new peers config with default /24 subnet
    pub fn new_default() -> Self {
        Self {
            subnet: "10.10.10.0".to_string(),
            subnet_mask: 24,
            next_ip: Ipv4Addr::new(10, 10, 10, 2),
            peers: Vec::new(),
        }
    }

    /// Create a new peers config with custom subnet
    pub fn new(subnet: String, subnet_mask: u8) -> Self {
        // Parse subnet and calculate first client IP (.2)
        let network: Ipv4Addr = subnet.parse().unwrap_or(Ipv4Addr::new(10, 10, 10, 0));
        let octets = network.octets();
        let next_ip = Ipv4Addr::new(octets[0], octets[1], octets[2], 2);

        Self {
            subnet,
            subnet_mask,
            next_ip,
            peers: Vec::new(),
        }
    }

    /// Find a peer by name
    pub fn find_by_name(&self, name: &str) -> Option<&PeerConfig> {
        self.peers.iter().find(|p| p.name == name)
    }

    /// Find a peer by public key
    pub fn find_by_public_key(&self, public_key: &str) -> Option<&PeerConfig> {
        self.peers.iter().find(|p| p.public_key == public_key)
    }

    /// Find a peer by assigned IP
    pub fn find_by_ip(&self, ip: Ipv4Addr) -> Option<&PeerConfig> {
        self.peers.iter().find(|p| p.assigned_ip == ip)
    }

    /// Add a peer
    pub fn add_peer(&mut self, peer: PeerConfig) {
        self.peers.push(peer);
    }

    /// Remove a peer by name, returns the removed peer if found
    pub fn remove_peer(&mut self, name: &str) -> Option<PeerConfig> {
        if let Some(pos) = self.peers.iter().position(|p| p.name == name) {
            Some(self.peers.remove(pos))
        } else {
            None
        }
    }

    /// Get server address (first IP in subnet, e.g., 10.10.10.1)
    pub fn server_address(&self) -> Ipv4Addr {
        let network: Ipv4Addr = self.subnet.parse().unwrap_or(Ipv4Addr::new(10, 10, 10, 0));
        let octets = network.octets();
        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3].saturating_add(1))
    }
}

impl Default for PeersConfig {
    fn default() -> Self {
        Self::new_default()
    }
}

// ============================================================================
// Server Configuration
// ============================================================================

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
    /// External network interface for NAT (e.g., "eth0", "ens3", "en0")
    #[serde(default = "default_external_interface")]
    pub external_interface: String,
    /// Enable automatic NAT configuration
    #[serde(default = "default_enable_nat")]
    pub enable_nat: bool,
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

fn default_external_interface() -> String {
    #[cfg(target_os = "linux")]
    {
        "eth0".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "en0".to_string()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "eth0".to_string()
    }
}

fn default_enable_nat() -> bool {
    true
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:51820".to_string(),
            private_key: String::new(),
            tun_address: default_server_tun_address(),
            tun_netmask: default_tun_netmask_server(),
            tun_mtu: default_tun_mtu_server(),
            external_interface: default_external_interface(),
            enable_nat: default_enable_nat(),
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
    /// Keep-alive interval in seconds (0 to disable)
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval: u64,
    /// Keep-alive timeout in seconds (connection considered dead if no response)
    #[serde(default = "default_keepalive_timeout")]
    pub keepalive_timeout: u64,
    /// Route all traffic through VPN (full tunnel)
    #[serde(default)]
    pub route_all_traffic: bool,
    /// Specific subnets to route through VPN (if not routing all)
    #[serde(default)]
    pub routed_subnets: Vec<String>,
    /// Enable automatic reconnection
    #[serde(default = "default_reconnect_enabled")]
    pub reconnect_enabled: bool,
    /// Delay between reconnection attempts in seconds
    #[serde(default = "default_reconnect_delay")]
    pub reconnect_delay: u64,
    /// Maximum number of reconnection attempts (0 = unlimited)
    #[serde(default = "default_max_reconnect_attempts")]
    pub max_reconnect_attempts: u32,
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

fn default_keepalive_interval() -> u64 {
    25 // Send keep-alive every 25 seconds
}

fn default_keepalive_timeout() -> u64 {
    60 // Consider connection dead after 60 seconds without response
}

fn default_reconnect_enabled() -> bool {
    true
}

fn default_reconnect_delay() -> u64 {
    5 // Wait 5 seconds before reconnecting
}

fn default_max_reconnect_attempts() -> u32 {
    0 // Unlimited reconnect attempts
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
            keepalive_interval: default_keepalive_interval(),
            keepalive_timeout: default_keepalive_timeout(),
            route_all_traffic: false,
            routed_subnets: vec![],
            reconnect_enabled: default_reconnect_enabled(),
            reconnect_delay: default_reconnect_delay(),
            max_reconnect_attempts: default_max_reconnect_attempts(),
        }
    }
}

/// Base64 encoding/decoding utilities for keys
pub mod keys {
    use base64::{Engine, engine::general_purpose::STANDARD};

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
