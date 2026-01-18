//! GatekeeperVPN CLI tool (gkvpn)
//!
//! Manages keypairs, server configuration, and client profiles.
//!
//! # Commands
//! - `generate-server` - Generate server keypair and configuration
//! - `generate-client` - Generate standalone client configuration
//! - `show-public` - Show public key from private key
//! - `add` - Add a new client profile
//! - `remove` - Remove a client profile
//! - `list` - List all client profiles
//! - `show` - Show client profile configuration

use std::fs;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use x25519_dalek::{PublicKey, StaticSecret};

use gatekeeper_common::config::keys;
use gatekeeper_common::crypto::generate_keypair;
use gatekeeper_common::{ClientConfig, PeerConfig, PeersConfig, ServerConfig};

/// Default configuration directory
const DEFAULT_CONFIG_DIR: &str = "/etc/gatekeeper";
/// Default peers file name
const PEERS_FILE: &str = "peers.toml";
/// Default profiles directory name
const PROFILES_DIR: &str = "profiles";

#[derive(Parser)]
#[command(name = "gkvpn")]
#[command(about = "GatekeeperVPN management CLI")]
#[command(version)]
struct Cli {
    /// Configuration directory
    #[arg(short = 'd', long, default_value = DEFAULT_CONFIG_DIR, global = true)]
    config_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate server keypair and configuration
    GenerateServer {
        /// Output file path (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Listen address
        #[arg(long, default_value = "0.0.0.0:51820")]
        listen: String,

        /// TUN interface IP address
        #[arg(long, default_value = "10.10.10.1")]
        tun_address: String,
    },

    /// Generate client keypair and configuration (standalone, without peers.toml)
    GenerateClient {
        /// Server's public key (base64 encoded)
        #[arg(short, long)]
        server_key: String,

        /// Server address
        #[arg(long, default_value = "127.0.0.1:51820")]
        server: String,

        /// Output file path (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// TUN interface IP address
        #[arg(long, default_value = "10.0.0.2")]
        tun_address: String,
    },

    /// Show public key from private key
    ShowPublic {
        /// Private key (base64 encoded)
        #[arg(short, long)]
        key: String,
    },

    /// Initialize peers configuration
    Init {
        /// Subnet (e.g., "10.10.10.0")
        #[arg(long, default_value = "10.10.10.0")]
        subnet: String,

        /// Subnet mask (CIDR notation)
        #[arg(long, default_value = "24")]
        mask: u8,

        /// Force overwrite existing configuration
        #[arg(short, long)]
        force: bool,
    },

    /// Add a new client profile
    Add {
        /// Client name (e.g., "laptop-ilya")
        name: String,

        /// Server address for client config (e.g., "vpn.example.com:51820")
        #[arg(long)]
        server_address: Option<String>,

        /// Server's public key (read from server.toml if not specified)
        #[arg(long)]
        server_key: Option<String>,

        /// Specific IP to assign (auto-allocate if not specified)
        #[arg(long)]
        ip: Option<Ipv4Addr>,
    },

    /// Remove a client profile
    Remove {
        /// Client name
        name: String,
    },

    /// List all client profiles
    List,

    /// Show client profile configuration
    Show {
        /// Client name
        name: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateServer {
            output,
            listen,
            tun_address,
        } => generate_server_config(output, listen, tun_address),

        Commands::GenerateClient {
            server_key,
            server,
            output,
            tun_address,
        } => generate_client_config(server_key, server, output, tun_address),

        Commands::ShowPublic { key } => show_public_key(key),

        Commands::Init {
            subnet,
            mask,
            force,
        } => init_peers(&cli.config_dir, subnet, mask, force),

        Commands::Add {
            name,
            server_address,
            server_key,
            ip,
        } => add_client(&cli.config_dir, name, server_address, server_key, ip),

        Commands::Remove { name } => remove_client(&cli.config_dir, name),

        Commands::List => list_clients(&cli.config_dir),

        Commands::Show { name } => show_client(&cli.config_dir, name),
    }
}

// ============================================================================
// Server/Client generation (existing functionality)
// ============================================================================

fn generate_server_config(
    output: Option<PathBuf>,
    listen: String,
    tun_address: String,
) -> Result<()> {
    let keypair = generate_keypair().context("Failed to generate keypair")?;

    let private_key = keys::encode(&keypair.private);
    let public_key = keys::encode(&keypair.public);

    let config = ServerConfig {
        listen,
        private_key,
        tun_address,
        ..Default::default()
    };

    let toml_str = toml::to_string_pretty(&config).context("Failed to serialize config")?;

    let output_with_comment = format!(
        "# Server public key (share with clients):\n# server_public_key = \"{}\"\n\n{}",
        public_key, toml_str
    );

    write_output(output, &output_with_comment)?;

    eprintln!("Server public key: {}", public_key);

    Ok(())
}

fn generate_client_config(
    server_key: String,
    server: String,
    output: Option<PathBuf>,
    tun_address: String,
) -> Result<()> {
    // Validate server key
    let decoded = keys::decode(&server_key).context("Invalid server public key")?;
    if decoded.len() != 32 {
        bail!("Server public key must be 32 bytes (got {})", decoded.len());
    }

    let keypair = generate_keypair().context("Failed to generate keypair")?;

    let private_key = keys::encode(&keypair.private);
    let public_key = keys::encode(&keypair.public);

    let config = ClientConfig {
        server,
        private_key,
        server_public_key: server_key,
        tun_address,
        ..Default::default()
    };

    let toml_str = toml::to_string_pretty(&config).context("Failed to serialize config")?;

    let output_with_comment = format!(
        "# Client public key (for server allowlist if needed):\n# client_public_key = \"{}\"\n\n{}",
        public_key, toml_str
    );

    write_output(output, &output_with_comment)?;

    eprintln!("Client public key: {}", public_key);

    Ok(())
}

fn show_public_key(private_key_b64: String) -> Result<()> {
    let private_key = keys::decode(&private_key_b64).context("Invalid private key")?;

    if private_key.len() != 32 {
        bail!("Private key must be 32 bytes (got {})", private_key.len());
    }

    let private_array: [u8; 32] = private_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid private key length"))?;

    let secret = StaticSecret::from(private_array);
    let public = PublicKey::from(&secret);

    let public_key_b64 = keys::encode(public.as_bytes());

    println!("{}", public_key_b64);

    Ok(())
}

// ============================================================================
// Profile management commands
// ============================================================================

fn init_peers(config_dir: &Path, subnet: String, mask: u8, force: bool) -> Result<()> {
    let peers_path = config_dir.join(PEERS_FILE);
    let profiles_path = config_dir.join(PROFILES_DIR);

    // Check if already exists
    if peers_path.exists() && !force {
        bail!(
            "peers.toml already exists at {}. Use --force to overwrite.",
            peers_path.display()
        );
    }

    // Create directories
    fs::create_dir_all(config_dir).with_context(|| {
        format!(
            "Failed to create config directory: {}",
            config_dir.display()
        )
    })?;
    fs::create_dir_all(&profiles_path).with_context(|| {
        format!(
            "Failed to create profiles directory: {}",
            profiles_path.display()
        )
    })?;

    // Create peers config
    let peers = PeersConfig::new(subnet.clone(), mask);
    let toml_str = toml::to_string_pretty(&peers).context("Failed to serialize peers config")?;

    fs::write(&peers_path, toml_str)
        .with_context(|| format!("Failed to write peers.toml: {}", peers_path.display()))?;

    eprintln!("Initialized peers configuration:");
    eprintln!("  Subnet: {}/{}", subnet, mask);
    eprintln!("  Server IP: {}", peers.server_address());
    eprintln!("  Config: {}", peers_path.display());
    eprintln!("  Profiles: {}", profiles_path.display());

    Ok(())
}

fn add_client(
    config_dir: &Path,
    name: String,
    server_address: Option<String>,
    server_key: Option<String>,
    specific_ip: Option<Ipv4Addr>,
) -> Result<()> {
    let peers_path = config_dir.join(PEERS_FILE);
    let profiles_path = config_dir.join(PROFILES_DIR);
    let server_toml_path = config_dir.join("server.toml");

    // Validate name
    if name.is_empty() || name.contains(|c: char| !c.is_alphanumeric() && c != '-' && c != '_') {
        bail!("Invalid client name. Use alphanumeric characters, dashes, and underscores.");
    }

    // Load peers config
    let mut peers = load_peers_config(&peers_path)?;

    // Check if name already exists
    if peers.find_by_name(&name).is_some() {
        bail!("Client '{}' already exists", name);
    }

    // Allocate IP
    let assigned_ip = if let Some(ip) = specific_ip {
        // Validate IP is in subnet
        if !is_ip_in_subnet(ip, &peers.subnet, peers.subnet_mask) {
            bail!(
                "IP {} is not in subnet {}/{}",
                ip,
                peers.subnet,
                peers.subnet_mask
            );
        }
        // Check if already assigned
        if peers.find_by_ip(ip).is_some() {
            bail!("IP {} is already assigned to another client", ip);
        }
        ip
    } else {
        allocate_next_ip(&mut peers)?
    };

    // Generate keypair
    let keypair = generate_keypair().context("Failed to generate keypair")?;
    let private_key = keys::encode(&keypair.private);
    let public_key = keys::encode(&keypair.public);

    // Get server public key
    let server_public_key = if let Some(key) = server_key {
        key
    } else {
        read_server_public_key(&server_toml_path)?
    };

    // Get server address
    let server = server_address.unwrap_or_else(|| "YOUR_SERVER_ADDRESS:51820".to_string());

    // Create peer config
    let peer = PeerConfig::new(name.clone(), public_key.clone(), assigned_ip);

    // Create client config file
    let client_config = ClientConfig {
        server,
        private_key,
        server_public_key,
        tun_address: assigned_ip.to_string(),
        tun_netmask: netmask_from_cidr(peers.subnet_mask).to_string(),
        ..Default::default()
    };

    let client_toml =
        toml::to_string_pretty(&client_config).context("Failed to serialize client config")?;

    let client_config_content = format!(
        "# Client profile: {}\n# Public key: {}\n# Assigned IP: {}\n\n{}",
        name, public_key, assigned_ip, client_toml
    );

    // Create profiles directory if not exists
    fs::create_dir_all(&profiles_path).with_context(|| {
        format!(
            "Failed to create profiles directory: {}",
            profiles_path.display()
        )
    })?;

    // Write client profile
    let profile_path = profiles_path.join(format!("{}.conf", name));
    fs::write(&profile_path, &client_config_content)
        .with_context(|| format!("Failed to write profile: {}", profile_path.display()))?;

    // Add to peers and save
    peers.add_peer(peer);
    save_peers_config(&peers_path, &peers)?;

    eprintln!("Added client '{}':", name);
    eprintln!("  Assigned IP: {}", assigned_ip);
    eprintln!("  Public key: {}", public_key);
    eprintln!("  Profile: {}", profile_path.display());

    Ok(())
}

fn remove_client(config_dir: &Path, name: String) -> Result<()> {
    let peers_path = config_dir.join(PEERS_FILE);
    let profiles_path = config_dir.join(PROFILES_DIR);
    let profile_path = profiles_path.join(format!("{}.conf", name));

    // Load peers config
    let mut peers = load_peers_config(&peers_path)?;

    // Remove from peers
    let removed = peers.remove_peer(&name);
    if removed.is_none() {
        bail!("Client '{}' not found", name);
    }

    // Save peers config
    save_peers_config(&peers_path, &peers)?;

    // Remove profile file if exists
    if profile_path.exists() {
        fs::remove_file(&profile_path)
            .with_context(|| format!("Failed to remove profile: {}", profile_path.display()))?;
    }

    let peer = removed.unwrap();
    eprintln!("Removed client '{}':", name);
    eprintln!("  Released IP: {}", peer.assigned_ip);

    Ok(())
}

fn list_clients(config_dir: &Path) -> Result<()> {
    let peers_path = config_dir.join(PEERS_FILE);

    // Load peers config
    let peers = load_peers_config(&peers_path)?;

    if peers.peers.is_empty() {
        println!("No clients configured.");
        println!("\nUse 'gkvpn add <name>' to add a client.");
        return Ok(());
    }

    // Print header
    println!(
        "{:<20} {:<16} {:<48} {}",
        "NAME", "IP", "PUBLIC KEY", "CREATED"
    );
    println!("{}", "-".repeat(100));

    // Print clients
    for peer in &peers.peers {
        // Truncate public key for display
        let key_display = if peer.public_key.len() > 44 {
            format!("{}...", &peer.public_key[..41])
        } else {
            peer.public_key.clone()
        };

        // Format date
        let date = if peer.created_at.len() >= 10 {
            &peer.created_at[..10]
        } else {
            &peer.created_at
        };

        println!(
            "{:<20} {:<16} {:<48} {}",
            peer.name, peer.assigned_ip, key_display, date
        );
    }

    println!("\nTotal: {} client(s)", peers.peers.len());
    println!("Subnet: {}/{}", peers.subnet, peers.subnet_mask);

    Ok(())
}

fn show_client(config_dir: &Path, name: String) -> Result<()> {
    let profiles_path = config_dir.join(PROFILES_DIR);
    let profile_path = profiles_path.join(format!("{}.conf", name));

    if !profile_path.exists() {
        bail!(
            "Profile for '{}' not found at {}",
            name,
            profile_path.display()
        );
    }

    let content = fs::read_to_string(&profile_path)
        .with_context(|| format!("Failed to read profile: {}", profile_path.display()))?;

    println!("{}", content);

    Ok(())
}

// ============================================================================
// Helper functions
// ============================================================================

fn write_output(output: Option<PathBuf>, content: &str) -> Result<()> {
    match output {
        Some(path) => {
            fs::write(&path, content)
                .with_context(|| format!("Failed to write to {}", path.display()))?;
            eprintln!("Configuration written to: {}", path.display());
        }
        None => {
            io::stdout()
                .write_all(content.as_bytes())
                .context("Failed to write to stdout")?;
        }
    }
    Ok(())
}

fn load_peers_config(path: &Path) -> Result<PeersConfig> {
    if !path.exists() {
        bail!(
            "peers.toml not found at {}. Run 'gkvpn init' first.",
            path.display()
        );
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read peers.toml: {}", path.display()))?;

    toml::from_str(&content)
        .with_context(|| format!("Failed to parse peers.toml: {}", path.display()))
}

fn save_peers_config(path: &Path, peers: &PeersConfig) -> Result<()> {
    let toml_str = toml::to_string_pretty(peers).context("Failed to serialize peers config")?;
    fs::write(path, toml_str)
        .with_context(|| format!("Failed to write peers.toml: {}", path.display()))
}

fn read_server_public_key(server_toml_path: &Path) -> Result<String> {
    if !server_toml_path.exists() {
        bail!(
            "server.toml not found at {}. Specify --server-key manually.",
            server_toml_path.display()
        );
    }

    let content = fs::read_to_string(server_toml_path)
        .with_context(|| format!("Failed to read server.toml: {}", server_toml_path.display()))?;

    let config: ServerConfig = toml::from_str(&content).with_context(|| {
        format!(
            "Failed to parse server.toml: {}",
            server_toml_path.display()
        )
    })?;

    // Derive public key from private key
    let private_bytes = keys::decode(&config.private_key).context("Invalid server private key")?;
    if private_bytes.len() != 32 {
        bail!("Server private key must be 32 bytes");
    }

    let private_array: [u8; 32] = private_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid private key length"))?;

    let secret = StaticSecret::from(private_array);
    let public = PublicKey::from(&secret);

    Ok(keys::encode(public.as_bytes()))
}

fn allocate_next_ip(peers: &mut PeersConfig) -> Result<Ipv4Addr> {
    // Get all assigned IPs
    let assigned: std::collections::HashSet<Ipv4Addr> =
        peers.peers.iter().map(|p| p.assigned_ip).collect();

    // Start from next_ip and find first available
    let mut current = peers.next_ip;
    let broadcast = broadcast_from_subnet(&peers.subnet, peers.subnet_mask)?;

    loop {
        // Skip if assigned
        if !assigned.contains(&current) {
            // Update next_ip
            peers.next_ip = next_ip_in_subnet(current, &peers.subnet, peers.subnet_mask);
            return Ok(current);
        }

        // Move to next
        current = next_ip_in_subnet(current, &peers.subnet, peers.subnet_mask);

        // Check if we've wrapped around
        if current == peers.next_ip {
            bail!(
                "No available IPs in subnet {}/{}",
                peers.subnet,
                peers.subnet_mask
            );
        }

        // Safety: don't exceed broadcast
        if current >= broadcast {
            current = first_client_ip(&peers.subnet)?;
        }
    }
}

fn is_ip_in_subnet(ip: Ipv4Addr, subnet: &str, mask: u8) -> bool {
    let network: Ipv4Addr = match subnet.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    let ip_u32 = u32::from(ip);
    let network_u32 = u32::from(network);
    let host_bits = 32 - mask;
    let network_mask = !((1u32 << host_bits) - 1);

    (ip_u32 & network_mask) == (network_u32 & network_mask)
}

fn broadcast_from_subnet(subnet: &str, mask: u8) -> Result<Ipv4Addr> {
    let network: Ipv4Addr = subnet
        .parse()
        .with_context(|| format!("Invalid subnet: {}", subnet))?;

    let network_u32 = u32::from(network);
    let host_bits = 32 - mask;
    let broadcast = network_u32 | ((1u32 << host_bits) - 1);

    Ok(Ipv4Addr::from(broadcast))
}

fn first_client_ip(subnet: &str) -> Result<Ipv4Addr> {
    let network: Ipv4Addr = subnet
        .parse()
        .with_context(|| format!("Invalid subnet: {}", subnet))?;

    let network_u32 = u32::from(network);
    // First client IP is .2 (skip .0 network and .1 server)
    Ok(Ipv4Addr::from(network_u32 + 2))
}

fn next_ip_in_subnet(current: Ipv4Addr, subnet: &str, mask: u8) -> Ipv4Addr {
    let current_u32 = u32::from(current);
    let network: Ipv4Addr = subnet.parse().unwrap_or(Ipv4Addr::new(10, 10, 10, 0));
    let network_u32 = u32::from(network);
    let host_bits = 32 - mask;
    let broadcast = network_u32 | ((1u32 << host_bits) - 1);

    let next = current_u32 + 1;
    if next >= broadcast {
        // Wrap to first client IP
        Ipv4Addr::from(network_u32 + 2)
    } else {
        Ipv4Addr::from(next)
    }
}

fn netmask_from_cidr(mask: u8) -> Ipv4Addr {
    let host_bits = 32 - mask;
    let netmask = !((1u32 << host_bits) - 1);
    Ipv4Addr::from(netmask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_keypair() {
        let keypair = generate_keypair().unwrap();

        let private_array: [u8; 32] = keypair.private.clone().try_into().unwrap();
        let secret = StaticSecret::from(private_array);
        let derived_public = PublicKey::from(&secret);

        assert_eq!(derived_public.as_bytes().to_vec(), keypair.public);
    }

    #[test]
    fn test_show_public_key_consistency() {
        let keypair = generate_keypair().unwrap();
        let private_b64 = keys::encode(&keypair.private);
        let expected_public_b64 = keys::encode(&keypair.public);

        let private_bytes = keys::decode(&private_b64).unwrap();
        let private_array: [u8; 32] = private_bytes.try_into().unwrap();
        let secret = StaticSecret::from(private_array);
        let public = PublicKey::from(&secret);
        let actual_public_b64 = keys::encode(public.as_bytes());

        assert_eq!(actual_public_b64, expected_public_b64);
    }

    #[test]
    fn test_is_ip_in_subnet() {
        assert!(is_ip_in_subnet(
            Ipv4Addr::new(10, 10, 10, 5),
            "10.10.10.0",
            24
        ));
        assert!(is_ip_in_subnet(
            Ipv4Addr::new(10, 10, 10, 254),
            "10.10.10.0",
            24
        ));
        assert!(!is_ip_in_subnet(
            Ipv4Addr::new(10, 10, 11, 5),
            "10.10.10.0",
            24
        ));
        assert!(!is_ip_in_subnet(
            Ipv4Addr::new(192, 168, 1, 1),
            "10.10.10.0",
            24
        ));
    }

    #[test]
    fn test_netmask_from_cidr() {
        assert_eq!(netmask_from_cidr(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(netmask_from_cidr(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(netmask_from_cidr(8), Ipv4Addr::new(255, 0, 0, 0));
    }

    #[test]
    fn test_broadcast_from_subnet() {
        assert_eq!(
            broadcast_from_subnet("10.10.10.0", 24).unwrap(),
            Ipv4Addr::new(10, 10, 10, 255)
        );
        assert_eq!(
            broadcast_from_subnet("10.10.0.0", 16).unwrap(),
            Ipv4Addr::new(10, 10, 255, 255)
        );
    }

    #[test]
    fn test_first_client_ip() {
        assert_eq!(
            first_client_ip("10.10.10.0").unwrap(),
            Ipv4Addr::new(10, 10, 10, 2)
        );
    }
}
