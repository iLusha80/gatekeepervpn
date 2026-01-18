//! Routing configuration for VPN client
//!
//! Platform-specific route management for directing traffic through the VPN tunnel.

use std::net::Ipv4Addr;
use std::process::Command;

use crate::Error;

/// Route configuration
#[derive(Debug, Clone)]
pub struct RouteConfig {
    /// TUN interface name
    pub tun_name: String,
    /// TUN gateway address (usually same as TUN address on client)
    pub tun_gateway: Ipv4Addr,
    /// VPN server IP address (needs direct route to original gateway)
    pub server_ip: Ipv4Addr,
    /// Whether to route all traffic through VPN
    pub route_all_traffic: bool,
    /// Specific subnets to route through VPN (if not routing all)
    pub routed_subnets: Vec<String>,
}

/// Get the current default gateway
#[cfg(target_os = "macos")]
pub fn get_default_gateway() -> Result<Ipv4Addr, Error> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| Error::Io(e))?;

    if !output.status.success() {
        return Err(Error::Route("Failed to get default gateway".into()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("gateway:") {
            let gateway = line.trim_start_matches("gateway:").trim();
            return gateway
                .parse()
                .map_err(|_| Error::Route(format!("Invalid gateway: {}", gateway)));
        }
    }

    Err(Error::Route("Default gateway not found".into()))
}

#[cfg(target_os = "linux")]
pub fn get_default_gateway() -> Result<Ipv4Addr, Error> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| Error::Io(e))?;

    if !output.status.success() {
        return Err(Error::Route("Failed to get default gateway".into()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Format: "default via 192.168.1.1 dev eth0"
    for part in stdout.split_whitespace() {
        if let Ok(ip) = part.parse::<Ipv4Addr>() {
            return Ok(ip);
        }
    }

    Err(Error::Route("Default gateway not found".into()))
}

/// Set up routes for VPN
#[cfg(target_os = "macos")]
pub fn setup_routes(config: &RouteConfig) -> Result<(), Error> {
    let original_gateway = get_default_gateway()?;
    log::info!("Original default gateway: {}", original_gateway);

    // 1. Add route to VPN server through original gateway
    log::info!(
        "Adding route to VPN server {} via {}",
        config.server_ip,
        original_gateway
    );
    let status = Command::new("sudo")
        .args([
            "route",
            "-n",
            "add",
            "-host",
            &config.server_ip.to_string(),
            &original_gateway.to_string(),
        ])
        .status()
        .map_err(|e| Error::Io(e))?;

    if !status.success() {
        log::warn!("Failed to add route to VPN server (might already exist)");
    }

    if config.route_all_traffic {
        // 2. Replace default route with TUN
        // On macOS, we add more specific routes that override the default
        log::info!("Setting up full tunnel routing through {}", config.tun_name);

        // Route 0.0.0.0/1 through TUN (covers 0.0.0.0 - 127.255.255.255)
        let status = Command::new("sudo")
            .args([
                "route",
                "-n",
                "add",
                "-net",
                "0.0.0.0/1",
                "-interface",
                &config.tun_name,
            ])
            .status()
            .map_err(|e| Error::Io(e))?;

        if !status.success() {
            return Err(Error::Route("Failed to add route 0.0.0.0/1".into()));
        }

        // Route 128.0.0.0/1 through TUN (covers 128.0.0.0 - 255.255.255.255)
        let status = Command::new("sudo")
            .args([
                "route",
                "-n",
                "add",
                "-net",
                "128.0.0.0/1",
                "-interface",
                &config.tun_name,
            ])
            .status()
            .map_err(|e| Error::Io(e))?;

        if !status.success() {
            return Err(Error::Route("Failed to add route 128.0.0.0/1".into()));
        }
    } else {
        // Route only specific subnets
        for subnet in &config.routed_subnets {
            log::info!("Adding route for {} through {}", subnet, config.tun_name);
            let status = Command::new("sudo")
                .args([
                    "route",
                    "-n",
                    "add",
                    "-net",
                    subnet,
                    "-interface",
                    &config.tun_name,
                ])
                .status()
                .map_err(|e| Error::Io(e))?;

            if !status.success() {
                log::warn!("Failed to add route for {}", subnet);
            }
        }
    }

    log::info!("Routes configured successfully");
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn setup_routes(config: &RouteConfig) -> Result<(), Error> {
    let original_gateway = get_default_gateway()?;
    log::info!("Original default gateway: {}", original_gateway);

    // 1. Add route to VPN server through original gateway
    log::info!(
        "Adding route to VPN server {} via {}",
        config.server_ip,
        original_gateway
    );
    let status = Command::new("sudo")
        .args([
            "ip",
            "route",
            "add",
            &format!("{}/32", config.server_ip),
            "via",
            &original_gateway.to_string(),
        ])
        .status()
        .map_err(|e| Error::Io(e))?;

    if !status.success() {
        log::warn!("Failed to add route to VPN server (might already exist)");
    }

    if config.route_all_traffic {
        log::info!("Setting up full tunnel routing through {}", config.tun_name);

        // Route 0.0.0.0/1 through TUN
        let status = Command::new("sudo")
            .args(["ip", "route", "add", "0.0.0.0/1", "dev", &config.tun_name])
            .status()
            .map_err(|e| Error::Io(e))?;

        if !status.success() {
            return Err(Error::Route("Failed to add route 0.0.0.0/1".into()));
        }

        // Route 128.0.0.0/1 through TUN
        let status = Command::new("sudo")
            .args(["ip", "route", "add", "128.0.0.0/1", "dev", &config.tun_name])
            .status()
            .map_err(|e| Error::Io(e))?;

        if !status.success() {
            return Err(Error::Route("Failed to add route 128.0.0.0/1".into()));
        }
    } else {
        for subnet in &config.routed_subnets {
            log::info!("Adding route for {} through {}", subnet, config.tun_name);
            let status = Command::new("sudo")
                .args(["ip", "route", "add", subnet, "dev", &config.tun_name])
                .status()
                .map_err(|e| Error::Io(e))?;

            if !status.success() {
                log::warn!("Failed to add route for {}", subnet);
            }
        }
    }

    log::info!("Routes configured successfully");
    Ok(())
}

/// Clean up routes when VPN disconnects
#[cfg(target_os = "macos")]
pub fn cleanup_routes(config: &RouteConfig) -> Result<(), Error> {
    log::info!("Cleaning up routes...");

    // Remove route to VPN server
    let _ = Command::new("sudo")
        .args([
            "route",
            "-n",
            "delete",
            "-host",
            &config.server_ip.to_string(),
        ])
        .status();

    if config.route_all_traffic {
        // Remove TUN routes
        let _ = Command::new("sudo")
            .args(["route", "-n", "delete", "-net", "0.0.0.0/1"])
            .status();

        let _ = Command::new("sudo")
            .args(["route", "-n", "delete", "-net", "128.0.0.0/1"])
            .status();
    } else {
        for subnet in &config.routed_subnets {
            let _ = Command::new("sudo")
                .args(["route", "-n", "delete", "-net", subnet])
                .status();
        }
    }

    log::info!("Routes cleaned up");
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn cleanup_routes(config: &RouteConfig) -> Result<(), Error> {
    log::info!("Cleaning up routes...");

    // Remove route to VPN server
    let _ = Command::new("sudo")
        .args(["ip", "route", "delete", &format!("{}/32", config.server_ip)])
        .status();

    if config.route_all_traffic {
        let _ = Command::new("sudo")
            .args(["ip", "route", "delete", "0.0.0.0/1"])
            .status();

        let _ = Command::new("sudo")
            .args(["ip", "route", "delete", "128.0.0.0/1"])
            .status();
    } else {
        for subnet in &config.routed_subnets {
            let _ = Command::new("sudo")
                .args(["ip", "route", "delete", subnet])
                .status();
        }
    }

    log::info!("Routes cleaned up");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_config() {
        let config = RouteConfig {
            tun_name: "utun5".to_string(),
            tun_gateway: "10.0.0.2".parse().unwrap(),
            server_ip: "1.2.3.4".parse().unwrap(),
            route_all_traffic: true,
            routed_subnets: vec![],
        };

        assert_eq!(config.tun_name, "utun5");
        assert!(config.route_all_traffic);
    }
}
