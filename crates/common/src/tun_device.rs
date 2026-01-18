//! TUN device abstraction for GatekeeperVPN
//!
//! Provides async TUN device creation and packet I/O.

use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tun::AbstractDevice;

use crate::Error;

/// TUN device configuration
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (e.g., "utun3" on macOS, "tun0" on Linux)
    /// If None, system will assign automatically
    pub name: Option<String>,
    /// Local IP address for the TUN interface
    pub address: Ipv4Addr,
    /// Netmask (e.g., 255.255.255.0)
    pub netmask: Ipv4Addr,
    /// MTU (Maximum Transmission Unit)
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            address: Ipv4Addr::new(10, 0, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1400, // Lower than ethernet MTU to account for encryption overhead
        }
    }
}

impl TunConfig {
    /// Create config for VPN client
    pub fn client(address: Ipv4Addr) -> Self {
        Self {
            address,
            ..Default::default()
        }
    }

    /// Create config for VPN server
    pub fn server(address: Ipv4Addr) -> Self {
        Self {
            address,
            ..Default::default()
        }
    }
}

/// Async TUN device wrapper
pub struct TunDevice {
    device: tun::AsyncDevice,
    name: String,
}

impl TunDevice {
    /// Create a new TUN device with the given configuration
    ///
    /// **Requires root/admin privileges on most systems**
    pub async fn create(config: TunConfig) -> Result<Self, Error> {
        let mut tun_config = tun::Configuration::default();

        tun_config
            .address(config.address)
            .netmask(config.netmask)
            .mtu(config.mtu)
            .up();

        #[cfg(target_os = "linux")]
        {
            tun_config.platform_config(|platform| {
                platform.ensure_root_privileges(true);
            });
        }

        if let Some(ref name) = config.name {
            #[allow(deprecated)]
            tun_config.name(name);
        }

        let device = tun::create_as_async(&tun_config).map_err(|e| Error::Tun(e.to_string()))?;

        let name = device
            .tun_name()
            .map_err(|e: tun::Error| Error::Tun(e.to_string()))?;

        log::info!("Created TUN device: {}", name);
        log::info!("  Address: {}", config.address);
        log::info!("  Netmask: {}", config.netmask);
        log::info!("  MTU: {}", config.mtu);

        Ok(Self { device, name })
    }

    /// Get the device name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Split into reader and writer for concurrent operations
    pub fn split(self) -> (TunReader, TunWriter) {
        let (reader, writer) = tokio::io::split(self.device);
        (TunReader { inner: reader }, TunWriter { inner: writer })
    }
}

/// TUN device reader half
pub struct TunReader {
    inner: ReadHalf<tun::AsyncDevice>,
}

impl TunReader {
    /// Read a packet from the TUN device
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let n = self.inner.read(buf).await?;
        Ok(n)
    }
}

/// TUN device writer half
pub struct TunWriter {
    inner: WriteHalf<tun::AsyncDevice>,
}

impl TunWriter {
    /// Write a packet to the TUN device
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        let n = self.inner.write(buf).await?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = TunConfig::default();
        assert_eq!(config.address, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(config.mtu, 1400);
    }

    #[test]
    fn test_config_client() {
        let config = TunConfig::client(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(config.address, Ipv4Addr::new(10, 0, 0, 5));
    }
}
