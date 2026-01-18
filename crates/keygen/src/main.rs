//! GatekeeperVPN key generation utility
//!
//! Generates keypairs and configuration files for server and client.

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use x25519_dalek::{PublicKey, StaticSecret};

use gatekeeper_common::config::keys;
use gatekeeper_common::crypto::generate_keypair;
use gatekeeper_common::{ClientConfig, ServerConfig};

#[derive(Parser)]
#[command(name = "gatekeeper-keygen")]
#[command(about = "GatekeeperVPN key and config generator")]
#[command(version)]
struct Cli {
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
        #[arg(long, default_value = "10.0.0.1")]
        tun_address: String,
    },

    /// Generate client keypair and configuration
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
    }
}

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
        anyhow::bail!("Server public key must be 32 bytes (got {})", decoded.len());
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
        anyhow::bail!("Private key must be 32 bytes (got {})", private_key.len());
    }

    let private_array: [u8; 32] = private_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid private key length"))?;

    // Use x25519-dalek to derive public key from private key
    let secret = StaticSecret::from(private_array);
    let public = PublicKey::from(&secret);

    let public_key_b64 = keys::encode(public.as_bytes());

    println!("{}", public_key_b64);

    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_keypair() {
        let keypair = generate_keypair().unwrap();

        // Derive public key using x25519-dalek
        let private_array: [u8; 32] = keypair.private.clone().try_into().unwrap();
        let secret = StaticSecret::from(private_array);
        let derived_public = PublicKey::from(&secret);

        // The derived public key should match snow's public key
        assert_eq!(derived_public.as_bytes().to_vec(), keypair.public);
    }

    #[test]
    fn test_show_public_key_consistency() {
        let keypair = generate_keypair().unwrap();
        let private_b64 = keys::encode(&keypair.private);
        let expected_public_b64 = keys::encode(&keypair.public);

        // Decode and derive
        let private_bytes = keys::decode(&private_b64).unwrap();
        let private_array: [u8; 32] = private_bytes.try_into().unwrap();
        let secret = StaticSecret::from(private_array);
        let public = PublicKey::from(&secret);
        let actual_public_b64 = keys::encode(public.as_bytes());

        assert_eq!(actual_public_b64, expected_public_b64);
    }
}
