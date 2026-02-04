use std::path::Path;
use std::time::SystemTime;

use anyhow::{Context, Result};

use gatekeeper_common::{PeersConfig, ServerConfig};

/// Default peers file location
pub(crate) const DEFAULT_PEERS_FILE: &str = "/etc/gatekeeper/peers.toml";
/// Interval for checking peers.toml changes
pub(crate) const PEERS_RELOAD_INTERVAL_SECS: u64 = 5;

pub(crate) fn load_config(path: &str) -> Result<ServerConfig> {
    if Path::new(path).exists() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;
        toml::from_str(&content).with_context(|| format!("Failed to parse config file: {}", path))
    } else {
        log::warn!("Config file not found: {}, using defaults", path);
        Ok(ServerConfig::default())
    }
}

pub(crate) fn load_peers_config(path: &Path) -> Result<PeersConfig> {
    if path.exists() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read peers file: {}", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse peers file: {}", path.display()))
    } else {
        log::warn!(
            "Peers file not found: {}, authorization disabled",
            path.display()
        );
        Ok(PeersConfig::default())
    }
}

pub(crate) fn get_file_modified_time(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}
