use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use gatekeeper_common::config::keys;
use gatekeeper_common::{
    CookieState, HandshakeRateLimiter, Packet, PeersConfig, Responder, Transport,
};

/// Connected client session
pub(crate) struct ConnectedClient {
    /// Transport state for encryption/decryption
    pub(crate) transport: Transport,
    /// Assigned VPN IP address
    pub(crate) assigned_ip: Ipv4Addr,
    /// Client name from peers.toml
    pub(crate) name: String,
    /// Last activity timestamp
    pub(crate) last_activity: Instant,
    /// Current UDP endpoint (mutable — changes on roaming)
    pub(crate) endpoint: SocketAddr,
}

/// Authorized peer info (from peers.toml)
#[derive(Clone)]
pub(crate) struct AuthorizedPeer {
    pub(crate) name: String,
    pub(crate) assigned_ip: Ipv4Addr,
}

/// Server state
pub(crate) struct Server {
    /// Server's private key
    pub(crate) private_key: Vec<u8>,
    /// Connected clients by VPN IP (primary key)
    pub(crate) clients: HashMap<Ipv4Addr, ConnectedClient>,
    /// Reverse index: UDP endpoint -> VPN IP (for fast lookup)
    pub(crate) endpoint_to_ip: HashMap<SocketAddr, Ipv4Addr>,
    /// Authorized peers (white list from peers.toml)
    authorized_peers: HashMap<[u8; 32], AuthorizedPeer>,
    /// Authorization enabled
    pub(crate) auth_enabled: bool,
    /// Cookie state for DoS protection
    pub(crate) cookie_state: CookieState,
    /// Handshake rate limiter
    pub(crate) rate_limiter: HandshakeRateLimiter,
}

impl Server {
    pub(crate) fn new(private_key: Vec<u8>, auth_enabled: bool) -> Self {
        Self {
            private_key,
            clients: HashMap::new(),
            endpoint_to_ip: HashMap::new(),
            authorized_peers: HashMap::new(),
            auth_enabled,
            cookie_state: CookieState::new(),
            rate_limiter: HandshakeRateLimiter::new(),
        }
    }

    /// Number of connected clients
    pub(crate) fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Load authorized peers from PeersConfig
    pub(crate) fn load_peers(&mut self, peers_config: &PeersConfig) {
        self.authorized_peers.clear();

        for peer in &peers_config.peers {
            if let Ok(key_bytes) = keys::decode(&peer.public_key) {
                if key_bytes.len() == 32 {
                    let mut key_array = [0u8; 32];
                    key_array.copy_from_slice(&key_bytes);

                    self.authorized_peers.insert(
                        key_array,
                        AuthorizedPeer {
                            name: peer.name.clone(),
                            assigned_ip: peer.assigned_ip,
                        },
                    );
                }
            }
        }

        log::info!(
            "Loaded {} authorized peer(s) from peers.toml",
            self.authorized_peers.len()
        );
    }

    /// Reload peers (hot-reload)
    pub(crate) fn reload_peers(&mut self, peers_config: &PeersConfig) {
        let old_count = self.authorized_peers.len();
        self.load_peers(peers_config);
        let new_count = self.authorized_peers.len();

        if new_count != old_count {
            log::info!(
                "Peers reloaded: {} -> {} authorized peer(s)",
                old_count,
                new_count
            );
        }
    }

    /// Check if a public key is authorized
    fn is_authorized(&self, public_key: &[u8; 32]) -> Option<&AuthorizedPeer> {
        if !self.auth_enabled {
            return None; // Auth disabled, return None but allow
        }
        self.authorized_peers.get(public_key)
    }

    /// Handle handshake init from a client
    pub(crate) fn handle_handshake(
        &mut self,
        addr: SocketAddr,
        payload: &[u8],
    ) -> Result<(Packet, Transport, Option<AuthorizedPeer>)> {
        log::info!("[{}] Handshake init received", addr);

        // Create new responder for this client
        let mut responder =
            Responder::new(&self.private_key).context("Failed to create responder")?;

        // Process handshake init message
        responder
            .read_message(payload)
            .context("Failed to read handshake init")?;

        // Get client's public key
        let remote_key = responder
            .get_remote_static()
            .context("Failed to get remote public key")?;

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(remote_key);

        log::info!("[{}] Client public key: {}", addr, keys::encode(&key_array));

        // Check authorization
        let authorized_peer = if self.auth_enabled {
            match self.is_authorized(&key_array) {
                Some(peer) => {
                    log::info!(
                        "[{}] Client '{}' authorized (IP: {})",
                        addr,
                        peer.name,
                        peer.assigned_ip
                    );
                    Some(peer.clone())
                }
                None => {
                    log::warn!("[{}] Unauthorized client, rejecting", addr);
                    anyhow::bail!("Client not authorized");
                }
            }
        } else {
            log::info!("[{}] Authorization disabled, allowing connection", addr);
            None
        };

        // Generate response
        let response = responder
            .write_message(&[])
            .context("Failed to write handshake response")?;

        log::info!("[{}] Handshake complete", addr);

        // Convert to transport mode
        let transport = responder
            .into_transport()
            .context("Failed to enter transport mode")?;

        Ok((
            Packet::handshake_response(response),
            transport,
            authorized_peer,
        ))
    }

    /// Register a connected client
    pub(crate) fn register_client(
        &mut self,
        addr: SocketAddr,
        transport: Transport,
        peer: Option<AuthorizedPeer>,
    ) {
        let (name, assigned_ip) = if let Some(p) = peer {
            (p.name, p.assigned_ip)
        } else {
            // For unauthorized mode, assign a temporary name and IP
            let name = format!("unknown-{}", addr.port());
            let assigned_ip = Ipv4Addr::new(0, 0, 0, 0);
            (name, assigned_ip)
        };

        // Remove old endpoint mapping if this IP was already connected
        if let Some(old_client) = self.clients.get(&assigned_ip) {
            self.endpoint_to_ip.remove(&old_client.endpoint);
        }

        let client = ConnectedClient {
            transport,
            assigned_ip,
            name,
            last_activity: Instant::now(),
            endpoint: addr,
        };

        if assigned_ip != Ipv4Addr::new(0, 0, 0, 0) {
            self.clients.insert(assigned_ip, client);
            self.endpoint_to_ip.insert(addr, assigned_ip);
        }
    }

    /// Remove a disconnected client by VPN IP
    fn remove_client_by_ip(&mut self, vpn_ip: &Ipv4Addr) {
        if let Some(client) = self.clients.remove(vpn_ip) {
            self.endpoint_to_ip.remove(&client.endpoint);
            log::info!(
                "[{}] Client '{}' disconnected (IP: {})",
                client.endpoint,
                client.name,
                client.assigned_ip
            );
        }
    }

    /// Update client endpoint after roaming detection
    pub(crate) fn update_client_endpoint(&mut self, vpn_ip: &Ipv4Addr, new_addr: SocketAddr) {
        if let Some(client) = self.clients.get_mut(vpn_ip) {
            let old_addr = client.endpoint;
            self.endpoint_to_ip.remove(&old_addr);
            client.endpoint = new_addr;
            client.last_activity = Instant::now();
            self.endpoint_to_ip.insert(new_addr, *vpn_ip);
            log::info!(
                "Roaming detected for '{}' (IP: {}): {} -> {}",
                client.name,
                vpn_ip,
                old_addr,
                new_addr
            );
        }
    }

    /// Try to find a client that can decrypt this payload (brute-force roaming detection)
    pub(crate) fn detect_roaming(&self, payload: &[u8]) -> Option<Ipv4Addr> {
        for (vpn_ip, client) in &self.clients {
            if client.transport.can_decrypt(payload) {
                return Some(*vpn_ip);
            }
        }
        None
    }

    /// Remove clients inactive for longer than the given timeout
    pub(crate) fn cleanup_inactive_clients(&mut self, timeout: Duration) -> usize {
        let now = Instant::now();
        let inactive: Vec<Ipv4Addr> = self
            .clients
            .iter()
            .filter(|(_, client)| now.duration_since(client.last_activity) > timeout)
            .map(|(ip, _)| *ip)
            .collect();

        let count = inactive.len();
        for ip in inactive {
            self.remove_client_by_ip(&ip);
        }
        count
    }

    /// Get client for a VPN IP (unicast routing)
    pub(crate) fn get_client_for_ip(&self, ip: Ipv4Addr) -> Option<&ConnectedClient> {
        self.clients.get(&ip)
    }

    /// Get client by endpoint address
    pub(crate) fn get_client_by_endpoint_mut(
        &mut self,
        addr: &SocketAddr,
    ) -> Option<&mut ConnectedClient> {
        if let Some(vpn_ip) = self.endpoint_to_ip.get(addr) {
            self.clients.get_mut(vpn_ip)
        } else {
            None
        }
    }
}
