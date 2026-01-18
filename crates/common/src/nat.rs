//! NAT and IP forwarding configuration for VPN server
//!
//! Provides helper functions and scripts for configuring NAT on the server.

use std::process::Command;

use crate::Error;

/// NAT configuration
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// TUN interface name
    pub tun_interface: String,
    /// External interface (e.g., eth0, en0)
    pub external_interface: String,
    /// VPN subnet (e.g., "10.0.0.0/24")
    pub vpn_subnet: String,
}

/// Enable IP forwarding
#[cfg(target_os = "linux")]
pub fn enable_ip_forwarding() -> Result<(), Error> {
    log::info!("Enabling IP forwarding...");

    let status = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .status()
        .map_err(|e| Error::Io(e))?;

    if !status.success() {
        return Err(Error::Route("Failed to enable IP forwarding".into()));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
pub fn enable_ip_forwarding() -> Result<(), Error> {
    log::info!("Enabling IP forwarding...");

    let status = Command::new("sysctl")
        .args(["-w", "net.inet.ip.forwarding=1"])
        .status()
        .map_err(|e| Error::Io(e))?;

    if !status.success() {
        return Err(Error::Route("Failed to enable IP forwarding".into()));
    }

    Ok(())
}

/// Setup NAT using iptables (Linux)
#[cfg(target_os = "linux")]
pub fn setup_nat(config: &NatConfig) -> Result<(), Error> {
    log::info!("Setting up NAT with iptables...");

    // Enable masquerading for VPN traffic
    let status = Command::new("iptables")
        .args([
            "-t", "nat",
            "-A", "POSTROUTING",
            "-s", &config.vpn_subnet,
            "-o", &config.external_interface,
            "-j", "MASQUERADE",
        ])
        .status()
        .map_err(|e| Error::Io(e))?;

    if !status.success() {
        return Err(Error::Route("Failed to add MASQUERADE rule".into()));
    }

    // Allow forwarding from TUN to external
    let status = Command::new("iptables")
        .args([
            "-A", "FORWARD",
            "-i", &config.tun_interface,
            "-o", &config.external_interface,
            "-j", "ACCEPT",
        ])
        .status()
        .map_err(|e| Error::Io(e))?;

    if !status.success() {
        return Err(Error::Route("Failed to add FORWARD rule (TUN -> external)".into()));
    }

    // Allow forwarding from external to TUN (established connections)
    let status = Command::new("iptables")
        .args([
            "-A", "FORWARD",
            "-i", &config.external_interface,
            "-o", &config.tun_interface,
            "-m", "state",
            "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT",
        ])
        .status()
        .map_err(|e| Error::Io(e))?;

    if !status.success() {
        return Err(Error::Route("Failed to add FORWARD rule (external -> TUN)".into()));
    }

    log::info!("NAT configured successfully");
    Ok(())
}

/// Setup NAT using pf (macOS)
#[cfg(target_os = "macos")]
pub fn setup_nat(config: &NatConfig) -> Result<(), Error> {
    log::info!("Setting up NAT with pf...");

    // Create pf rules
    let pf_rules = format!(
        r#"
nat on {} from {} to any -> ({})
pass in on {} all
pass out on {} all
"#,
        config.external_interface,
        config.vpn_subnet,
        config.external_interface,
        config.tun_interface,
        config.tun_interface,
    );

    // Write rules to temp file
    let rules_path = "/tmp/gatekeeper_pf.conf";
    std::fs::write(rules_path, &pf_rules)
        .map_err(|e| Error::Io(e))?;

    // Load rules
    let status = Command::new("pfctl")
        .args(["-ef", rules_path])
        .status()
        .map_err(|e| Error::Io(e))?;

    if !status.success() {
        return Err(Error::Route("Failed to load pf rules".into()));
    }

    log::info!("NAT configured successfully");
    Ok(())
}

/// Generate setup script for manual execution
pub fn generate_setup_script(config: &NatConfig) -> String {
    #[cfg(target_os = "linux")]
    {
        format!(
            r#"#!/bin/bash
# GatekeeperVPN Server NAT Setup Script
# Run as root

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# Setup NAT with iptables
iptables -t nat -A POSTROUTING -s {subnet} -o {ext} -j MASQUERADE
iptables -A FORWARD -i {tun} -o {ext} -j ACCEPT
iptables -A FORWARD -i {ext} -o {tun} -m state --state RELATED,ESTABLISHED -j ACCEPT

# Save iptables rules (Debian/Ubuntu)
# iptables-save > /etc/iptables/rules.v4

# Save iptables rules (CentOS/RHEL)
# service iptables save

echo "NAT setup complete!"
"#,
            subnet = config.vpn_subnet,
            ext = config.external_interface,
            tun = config.tun_interface,
        )
    }

    #[cfg(target_os = "macos")]
    {
        format!(
            r#"#!/bin/bash
# GatekeeperVPN Server NAT Setup Script
# Run as root

# Enable IP forwarding
sysctl -w net.inet.ip.forwarding=1

# Create pf rules file
cat > /tmp/gatekeeper_pf.conf << 'EOF'
nat on {ext} from {subnet} to any -> ({ext})
pass in on {tun} all
pass out on {tun} all
EOF

# Load pf rules
pfctl -ef /tmp/gatekeeper_pf.conf

echo "NAT setup complete!"
"#,
            subnet = config.vpn_subnet,
            ext = config.external_interface,
            tun = config.tun_interface,
        )
    }
}

/// Generate cleanup script
#[allow(unused_variables)]
pub fn generate_cleanup_script(config: &NatConfig) -> String {
    #[cfg(target_os = "linux")]
    {
        format!(
            r#"#!/bin/bash
# GatekeeperVPN Server NAT Cleanup Script
# Run as root

# Remove iptables rules
iptables -t nat -D POSTROUTING -s {subnet} -o {ext} -j MASQUERADE
iptables -D FORWARD -i {tun} -o {ext} -j ACCEPT
iptables -D FORWARD -i {ext} -o {tun} -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "NAT rules removed!"
"#,
            subnet = config.vpn_subnet,
            ext = config.external_interface,
            tun = config.tun_interface,
        )
    }

    #[cfg(target_os = "macos")]
    {
        r#"#!/bin/bash
# GatekeeperVPN Server NAT Cleanup Script
# Run as root

# Disable pf
pfctl -d

# Remove rules file
rm -f /tmp/gatekeeper_pf.conf

echo "NAT rules removed!"
"#
        .to_string()
    }
}

/// Print NAT setup instructions
pub fn print_nat_instructions(tun_name: &str, vpn_subnet: &str) {
    println!();
    println!("=== NAT Setup Instructions ===");
    println!();
    println!("To enable internet access for VPN clients, configure NAT on the server:");
    println!();

    #[cfg(target_os = "linux")]
    {
        println!("1. Enable IP forwarding:");
        println!("   sudo sysctl -w net.ipv4.ip_forward=1");
        println!();
        println!("2. Setup NAT (replace 'eth0' with your external interface):");
        println!("   sudo iptables -t nat -A POSTROUTING -s {} -o eth0 -j MASQUERADE", vpn_subnet);
        println!("   sudo iptables -A FORWARD -i {} -o eth0 -j ACCEPT", tun_name);
        println!("   sudo iptables -A FORWARD -i eth0 -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT", tun_name);
    }

    #[cfg(target_os = "macos")]
    {
        println!("1. Enable IP forwarding:");
        println!("   sudo sysctl -w net.inet.ip.forwarding=1");
        println!();
        println!("2. Setup NAT (replace 'en0' with your external interface):");
        println!("   Create /etc/pf.anchors/gatekeeper with:");
        println!("   nat on en0 from {} to any -> (en0)", vpn_subnet);
        println!("   pass in on {} all", tun_name);
        println!();
        println!("3. Enable pf:");
        println!("   sudo pfctl -ef /etc/pf.anchors/gatekeeper");
    }

    println!();
    println!("===========================");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_config() {
        let config = NatConfig {
            tun_interface: "utun5".to_string(),
            external_interface: "en0".to_string(),
            vpn_subnet: "10.0.0.0/24".to_string(),
        };

        assert_eq!(config.tun_interface, "utun5");
        assert_eq!(config.vpn_subnet, "10.0.0.0/24");
    }

    #[test]
    fn test_generate_setup_script() {
        let config = NatConfig {
            tun_interface: "utun5".to_string(),
            external_interface: "en0".to_string(),
            vpn_subnet: "10.0.0.0/24".to_string(),
        };

        let script = generate_setup_script(&config);
        assert!(script.contains("10.0.0.0/24"));
    }
}
