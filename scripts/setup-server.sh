#!/bin/bash
# GatekeeperVPN Server Setup Script for Ubuntu VPS
# Run as root or with sudo

set -e

echo "=== GatekeeperVPN Server Setup ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo bash setup-server.sh"
    exit 1
fi

# Step 1: Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "[1/6] Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "[1/6] Rust already installed"
fi

# Step 2: Install build dependencies
echo "[2/6] Installing build dependencies..."
apt-get update -qq
apt-get install -y -qq build-essential pkg-config

# Step 3: Build the project
echo "[3/6] Building GatekeeperVPN (release mode)..."
cd "$(dirname "$0")/.."
cargo build --release

# Step 4: Install binaries
echo "[4/6] Installing binaries to /usr/local/bin..."
cp target/release/gatekeeper-server /usr/local/bin/
cp target/release/gatekeeper-keygen /usr/local/bin/
chmod +x /usr/local/bin/gatekeeper-server /usr/local/bin/gatekeeper-keygen

# Step 5: Generate server config
echo "[5/6] Generating server configuration..."
mkdir -p /etc/gatekeeper

if [ ! -f /etc/gatekeeper/server.toml ]; then
    gatekeeper-keygen generate-server \
        --listen "0.0.0.0:51820" \
        --tun-address "10.0.0.1" \
        -o /etc/gatekeeper/server.toml

    echo ""
    echo "=========================================="
    echo "IMPORTANT: Save the server public key above!"
    echo "You will need it for client configuration."
    echo "=========================================="
else
    echo "Config already exists at /etc/gatekeeper/server.toml"
    echo "To regenerate, delete it first: rm /etc/gatekeeper/server.toml"
fi

# Step 6: Setup firewall and NAT
echo "[6/6] Setting up firewall and NAT..."

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-gatekeeper.conf
sysctl -p /etc/sysctl.d/99-gatekeeper.conf

# Detect main network interface
MAIN_IF=$(ip route | grep default | awk '{print $5}' | head -1)
echo "Detected main interface: $MAIN_IF"

# Setup iptables
iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o "$MAIN_IF" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o "$MAIN_IF" -j MASQUERADE

iptables -C FORWARD -i utun+ -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i utun+ -j ACCEPT

iptables -C FORWARD -o utun+ -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -o utun+ -j ACCEPT

# Also for tun+ (Linux naming)
iptables -C FORWARD -i tun+ -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i tun+ -j ACCEPT

iptables -C FORWARD -o tun+ -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -o tun+ -j ACCEPT

# Open UDP port
if command -v ufw &> /dev/null; then
    ufw allow 51820/udp
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To start the server:"
echo "  sudo gatekeeper-server -c /etc/gatekeeper/server.toml"
echo ""
echo "To run in background:"
echo "  sudo nohup gatekeeper-server -c /etc/gatekeeper/server.toml > /var/log/gatekeeper.log 2>&1 &"
echo ""
echo "To view server public key:"
echo "  head -2 /etc/gatekeeper/server.toml"
echo ""
