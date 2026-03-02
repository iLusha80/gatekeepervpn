//! GatekeeperVPN CLI tool (gkvpn)
//!
//! Unified management and VPN client CLI.
//!
//! # VPN Commands
//! - `connect` / `up` - Connect to VPN server
//! - `disconnect` / `down` - Disconnect from VPN
//! - `status` - Show VPN server status
//!
//! # Management Commands
//! - `generate-server` - Generate server keypair and configuration
//! - `generate-client` - Generate standalone client configuration
//! - `show-public` - Show public key from private key
//! - `init` - Initialize peers configuration
//! - `add` - Add a new client profile
//! - `remove` - Remove a client profile
//! - `list` - List all client profiles
//! - `show` - Show client profile configuration

use std::fs;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use x25519_dalek::{PublicKey, StaticSecret};

use gatekeeper_common::config::keys;
use gatekeeper_common::crypto::generate_keypair;
use gatekeeper_common::{ClientConfig, PacketObfuscator, PeerConfig, PeersConfig, ServerConfig};

/// Default configuration directory
const DEFAULT_CONFIG_DIR: &str = "/etc/gatekeeper";
/// Default peers file name
const PEERS_FILE: &str = "peers.toml";
/// Default profiles directory name
const PROFILES_DIR: &str = "profiles";
/// Default PID file path
const PID_FILE: &str = "/var/run/gkvpn.pid";

#[derive(Parser)]
#[command(name = "gkvpn")]
#[command(about = "GatekeeperVPN — fast & secure VPN")]
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
    /// Connect to VPN server
    #[command(alias = "up")]
    Connect {
        /// Profile name (looks in /etc/gatekeeper/profiles/<name>.conf)
        /// or path to config file
        profile: Option<String>,

        /// Path to config file (overrides profile)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Server address (overrides config)
        #[arg(short, long)]
        server: Option<String>,

        /// Verbose output (debug logging)
        #[arg(short, long)]
        verbose: bool,

        /// Test mode: handshake + echo message, no TUN
        #[arg(short, long)]
        test: bool,

        /// Message to send in test mode
        #[arg(short, long, default_value = "Hello from GatekeeperVPN!")]
        message: String,
    },

    /// Disconnect from VPN (stop running gkvpn connect)
    #[command(alias = "down")]
    Disconnect {
        /// PID file path
        #[arg(long, default_value = PID_FILE)]
        pid_file: PathBuf,
    },

    /// Generate server keypair and configuration
    GenerateServer {
        /// Output file path (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Listen address
        #[arg(long, default_value = "0.0.0.0:8443")]
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
        #[arg(long, default_value = "127.0.0.1:8443")]
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

        /// Server address for client config (e.g., "vpn.example.com:8443")
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

    /// Generate a pre-shared key for obfuscation (32 random bytes, base64)
    GeneratePsk,

    /// Show VPN server status (reads stats file)
    Status {
        /// Path to stats file
        #[arg(long, default_value = "/tmp/gatekeeper-vpn.stats")]
        stats_file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Connect {
            profile,
            config,
            server,
            verbose,
            test,
            message,
        } => {
            cmd_connect(
                &cli.config_dir,
                profile,
                config,
                server,
                verbose,
                test,
                message,
            )
            .await
        }

        Commands::Disconnect { pid_file } => cmd_disconnect(&pid_file),

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

        Commands::GeneratePsk => generate_psk(),

        Commands::Status { stats_file } => show_status(&stats_file),
    }
}

// ============================================================================
// VPN connect / disconnect
// ============================================================================

/// Resolve config file path from profile name or explicit path
fn resolve_config_path(
    config_dir: &Path,
    profile: Option<String>,
    config: Option<PathBuf>,
) -> Result<PathBuf> {
    // Explicit --config takes priority
    if let Some(path) = config {
        if !path.exists() {
            bail!("Config file not found: {}", path.display());
        }
        return Ok(path);
    }

    // Profile name: look in profiles directory
    if let Some(name) = profile {
        // Check if it's already a file path
        let as_path = Path::new(&name);
        if as_path.exists() {
            return Ok(as_path.to_path_buf());
        }

        // Look in profiles directory
        let profile_path = config_dir.join(PROFILES_DIR).join(format!("{}.conf", name));
        if profile_path.exists() {
            return Ok(profile_path);
        }

        bail!(
            "Profile '{}' not found.\n  Looked in: {}\n  Use 'gkvpn list' to see available profiles.\n  Or specify full path: gkvpn connect -c /path/to/config.conf",
            name,
            profile_path.display()
        );
    }

    // No profile, no config: look for single profile or default
    let profiles_dir = config_dir.join(PROFILES_DIR);
    if profiles_dir.exists() {
        let entries: Vec<_> = fs::read_dir(&profiles_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "conf" || ext == "toml")
            })
            .collect();

        if entries.len() == 1 {
            return Ok(entries[0].path());
        }

        if entries.len() > 1 {
            let names: Vec<String> = entries
                .iter()
                .filter_map(|e| {
                    e.path()
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                })
                .collect();
            bail!(
                "Multiple profiles found. Specify one:\n  {}\n\nUsage: gkvpn connect <profile-name>",
                names.join("\n  ")
            );
        }
    }

    // Fall back to client.toml in current directory
    let default_path = PathBuf::from("client.toml");
    if default_path.exists() {
        return Ok(default_path);
    }

    bail!(
        "No config file found.\n  Use: gkvpn connect <profile-name>\n  Or:  gkvpn connect -c /path/to/config.conf\n  Available profiles: gkvpn list"
    );
}

async fn cmd_connect(
    config_dir: &Path,
    profile: Option<String>,
    config: Option<PathBuf>,
    server_override: Option<String>,
    verbose: bool,
    test: bool,
    message: String,
) -> Result<()> {
    // Init logging
    let log_level = if verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    // Resolve config file
    let config_path = resolve_config_path(config_dir, profile, config)?;
    log::info!("Using config: {}", config_path.display());

    // Load config
    let content = fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config: {}", config_path.display()))?;
    let mut client_config: ClientConfig = toml::from_str(&content)
        .with_context(|| format!("Failed to parse config: {}", config_path.display()))?;

    // Override server address
    if let Some(server) = server_override {
        client_config.server = server;
    }

    // Validate
    if client_config.private_key.is_empty() {
        log::warn!("No private key configured, generating ephemeral keypair");
        let keypair = generate_keypair()?;
        client_config.private_key = keys::encode(&keypair.private);
        log::info!("Client public key: {}", keys::encode(&keypair.public));
    }

    if client_config.server_public_key.is_empty() {
        bail!("Server public key is required. Set 'server_public_key' in config.");
    }

    let private_key =
        keys::decode(&client_config.private_key).context("Invalid private key format")?;
    let server_public_key =
        keys::decode(&client_config.server_public_key).context("Invalid server public key")?;

    // Create obfuscator
    let obfuscator = PacketObfuscator::new(&client_config.obfuscation, &server_public_key)
        .context("Failed to create packet obfuscator")?;
    if client_config.obfuscation.enabled {
        log::info!(
            "Packet obfuscation enabled (header_size={}, padding={}-{}, junk={}-{})",
            client_config.obfuscation.header_size,
            client_config.obfuscation.min_padding,
            client_config.obfuscation.max_padding,
            client_config.obfuscation.junk_min,
            client_config.obfuscation.junk_max
        );
    }
    let obfuscator = Arc::new(obfuscator);

    // Write PID file (best-effort, may fail without root)
    let pid = std::process::id();
    if let Err(e) = fs::write(PID_FILE, pid.to_string()) {
        log::debug!(
            "Could not write PID file {}: {} (non-critical)",
            PID_FILE,
            e
        );
    }

    let result = if test {
        // Test mode
        use tokio::net::UdpSocket;
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket
            .connect(&client_config.server)
            .await
            .with_context(|| format!("Failed to connect to {}", client_config.server))?;
        log::info!("Connecting to server: {}", client_config.server);

        let mut transport = gatekeeper_client::handshake::perform_handshake(
            &socket,
            &private_key,
            &server_public_key,
            &obfuscator,
        )
        .await?;
        gatekeeper_client::test_mode::run_test_mode(&socket, &mut transport, &message, &obfuscator)
            .await
    } else {
        // VPN mode with reconnection
        gatekeeper_client::connection::run_with_reconnect(
            &client_config,
            &private_key,
            &server_public_key,
            obfuscator,
        )
        .await
    };

    // Cleanup PID file
    let _ = fs::remove_file(PID_FILE);

    result
}

fn cmd_disconnect(pid_file: &Path) -> Result<()> {
    if !pid_file.exists() {
        bail!(
            "PID file not found: {}\nIs gkvpn connect running?",
            pid_file.display()
        );
    }

    let content = fs::read_to_string(pid_file)
        .with_context(|| format!("Failed to read PID file: {}", pid_file.display()))?;

    let pid: i32 = content
        .trim()
        .parse()
        .with_context(|| format!("Invalid PID in file: '{}'", content.trim()))?;

    // Check if process exists
    let exists = unsafe { libc::kill(pid, 0) } == 0;
    if !exists {
        // Process doesn't exist, clean up stale PID file
        let _ = fs::remove_file(pid_file);
        bail!("Process {} is not running (stale PID file removed)", pid);
    }

    // Send SIGTERM
    let result = unsafe { libc::kill(pid, libc::SIGTERM) };
    if result != 0 {
        bail!(
            "Failed to send SIGTERM to process {}. Try: sudo gkvpn disconnect",
            pid
        );
    }

    eprintln!("Sent SIGTERM to gkvpn (PID {})", pid);

    // Clean up PID file
    let _ = fs::remove_file(pid_file);

    Ok(())
}

// ============================================================================
// PSK generation
// ============================================================================

fn generate_psk() -> Result<()> {
    use rand::RngCore;
    let mut psk = [0u8; 32];
    rand::rng().fill_bytes(&mut psk);
    let encoded = keys::encode(&psk);
    println!("{}", encoded);
    eprintln!("Add this to [obfuscation] section as 'psk' in both server and client configs.");
    Ok(())
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
    let server = server_address.unwrap_or_else(|| "YOUR_SERVER_ADDRESS:8443".to_string());

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

fn show_status(stats_file: &Path) -> Result<()> {
    if !stats_file.exists() {
        bail!(
            "Stats file not found: {}\nIs the server running with --stats flag?",
            stats_file.display()
        );
    }

    let content = fs::read_to_string(stats_file)
        .with_context(|| format!("Failed to read stats file: {}", stats_file.display()))?;

    // Parse simple JSON manually (no serde_json dependency)
    // Format: {"key":value,...}
    let content = content.trim();
    if !content.starts_with('{') || !content.ends_with('}') {
        bail!("Invalid stats file format");
    }

    let inner = &content[1..content.len() - 1];
    let mut values: Vec<(&str, &str)> = Vec::new();

    for pair in inner.split(',') {
        if let Some((key, value)) = pair.split_once(':') {
            let key = key.trim().trim_matches('"');
            let value = value.trim();
            values.push((key, value));
        }
    }

    println!("GatekeeperVPN Server Status");
    println!("{}", "=".repeat(40));

    for (key, value) in &values {
        let label = match *key {
            "uptime_secs" => {
                let secs: u64 = value.parse().unwrap_or(0);
                let hours = secs / 3600;
                let minutes = (secs % 3600) / 60;
                let seconds = secs % 60;
                println!(
                    "{:<25} {:02}:{:02}:{:02}",
                    "Uptime:", hours, minutes, seconds
                );
                continue;
            }
            "active_clients" => "Active clients:",
            "packets_sent" => "Packets sent:",
            "packets_received" => "Packets received:",
            "bytes_sent" => "Bytes sent:",
            "bytes_received" => "Bytes received:",
            "handshakes_completed" => "Handshakes OK:",
            "handshakes_failed" => "Handshakes failed:",
            "replay_packets_dropped" => "Replay dropped:",
            _ => key,
        };

        // Format bytes fields
        if *key == "bytes_sent" || *key == "bytes_received" {
            let bytes: u64 = value.parse().unwrap_or(0);
            println!("{:<25} {}", label, format_bytes_display(bytes));
        } else {
            println!("{:<25} {}", label, value);
        }
    }

    Ok(())
}

fn format_bytes_display(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
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
    use std::fs;

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

    #[test]
    fn test_resolve_config_path_explicit_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("test.conf");
        fs::write(&config_file, "test").unwrap();

        let result = resolve_config_path(dir.path(), None, Some(config_file.clone()));
        assert_eq!(result.unwrap(), config_file);
    }

    #[test]
    fn test_resolve_config_path_profile_name() {
        let dir = tempfile::tempdir().unwrap();
        let profiles_dir = dir.path().join(PROFILES_DIR);
        fs::create_dir_all(&profiles_dir).unwrap();
        let profile = profiles_dir.join("laptop.conf");
        fs::write(&profile, "test").unwrap();

        let result = resolve_config_path(dir.path(), Some("laptop".to_string()), None);
        assert_eq!(result.unwrap(), profile);
    }

    #[test]
    fn test_resolve_config_path_single_profile() {
        let dir = tempfile::tempdir().unwrap();
        let profiles_dir = dir.path().join(PROFILES_DIR);
        fs::create_dir_all(&profiles_dir).unwrap();
        let profile = profiles_dir.join("my-vpn.conf");
        fs::write(&profile, "test").unwrap();

        let result = resolve_config_path(dir.path(), None, None);
        assert_eq!(result.unwrap(), profile);
    }

    #[test]
    fn test_resolve_config_path_multiple_profiles_error() {
        let dir = tempfile::tempdir().unwrap();
        let profiles_dir = dir.path().join(PROFILES_DIR);
        fs::create_dir_all(&profiles_dir).unwrap();
        fs::write(profiles_dir.join("a.conf"), "test").unwrap();
        fs::write(profiles_dir.join("b.conf"), "test").unwrap();

        let result = resolve_config_path(dir.path(), None, None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Multiple profiles")
        );
    }

    #[test]
    fn test_resolve_config_path_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let result = resolve_config_path(dir.path(), Some("nonexistent".to_string()), None);
        assert!(result.is_err());
    }
}
