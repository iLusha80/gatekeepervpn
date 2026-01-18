#!/bin/bash
# GatekeeperVPN Client Setup Script for macOS
# Run with: bash setup-client.sh <SERVER_PUBLIC_KEY> <SERVER_IP>

set -e

echo "=== GatekeeperVPN Client Setup ==="
echo ""

# Check arguments
if [ $# -lt 2 ]; then
    echo "Usage: bash setup-client.sh <SERVER_PUBLIC_KEY> <SERVER_IP>"
    echo ""
    echo "Example:"
    echo "  bash setup-client.sh 'ABC123...xyz=' '203.0.113.50'"
    echo ""
    echo "Get SERVER_PUBLIC_KEY from server: head -2 /etc/gatekeeper/server.toml"
    exit 1
fi

SERVER_KEY="$1"
SERVER_IP="$2"
SERVER_PORT="${3:-51820}"

# Step 1: Build the project
echo "[1/3] Building GatekeeperVPN (release mode)..."
cd "$(dirname "$0")/.."
cargo build --release

# Step 2: Create config directory
echo "[2/3] Creating configuration..."
mkdir -p ~/.config/gatekeeper

# Step 3: Generate client config
CONFIG_FILE=~/.config/gatekeeper/client.toml

if [ ! -f "$CONFIG_FILE" ]; then
    ./target/release/gatekeeper-keygen generate-client \
        --server-key "$SERVER_KEY" \
        --server "${SERVER_IP}:${SERVER_PORT}" \
        --tun-address "10.0.0.2" \
        -o "$CONFIG_FILE"

    echo ""
    echo "=========================================="
    echo "Client configuration saved to: $CONFIG_FILE"
    echo "=========================================="
else
    echo "Config already exists at $CONFIG_FILE"
    echo "To regenerate, delete it first: rm $CONFIG_FILE"
fi

echo ""
echo "[3/3] Setup complete!"
echo ""
echo "=== How to Connect ==="
echo ""
echo "To start VPN (requires sudo for TUN):"
echo "  sudo ./target/release/gatekeeper-client -c ~/.config/gatekeeper/client.toml"
echo ""
echo "To test connection (echo mode, no TUN):"
echo "  ./target/release/gatekeeper-client -c ~/.config/gatekeeper/client.toml --test"
echo ""
echo "After connecting, verify with:"
echo "  ping 10.0.0.1        # ping VPN server"
echo "  curl ifconfig.me     # should show server IP"
echo ""
