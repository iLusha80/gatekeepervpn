#!/bin/bash
#
# Fix GatekeeperVPN Installation Script
#
# Исправляет проблемы после неполной установки:
# - Исправляет external_interface в конфигурации
# - Удаляет старые NAT правила
# - Создает systemd сервис
# - Запускает и проверяет сервер
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

CONFIG_DIR="/etc/gatekeeper"
INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

print_msg() {
    local color=$1
    local msg=$2
    echo -e "${color}${msg}${NC}"
}

print_step() {
    echo ""
    print_msg "$CYAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$BLUE" "  ▶ $1"
    print_msg "$CYAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Check root
if [[ $EUID -ne 0 ]]; then
    print_msg "$RED" "❌ Error: This script must be run as root (use sudo)"
    exit 1
fi

print_msg "$CYAN" "╔════════════════════════════════════════════════════════════╗"
print_msg "$CYAN" "║                                                            ║"
print_msg "$CYAN" "║     GatekeeperVPN Installation Fix Script                 ║"
print_msg "$CYAN" "║                                                            ║"
print_msg "$CYAN" "╚════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Fix external_interface in config
print_step "Fixing external_interface in configuration"

if [[ ! -f "$CONFIG_DIR/server.toml" ]]; then
    print_msg "$RED" "❌ Config file not found: $CONFIG_DIR/server.toml"
    exit 1
fi

# Detect correct interface
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [[ -z "$INTERFACE" ]]; then
    print_msg "$RED" "❌ Could not detect network interface"
    exit 1
fi

print_msg "$YELLOW" "Detected interface: $INTERFACE"

# Fix external_interface (remove any newlines or invalid chars)
sed -i 's/external_interface = ".*"/external_interface = "'"$INTERFACE"'"/' "$CONFIG_DIR/server.toml"

# Verify
CURRENT_IF=$(grep 'external_interface' "$CONFIG_DIR/server.toml" | cut -d'"' -f2)
if [[ "$CURRENT_IF" == "$INTERFACE" ]]; then
    print_msg "$GREEN" "✓ external_interface set to: $INTERFACE"
else
    print_msg "$RED" "❌ Failed to fix external_interface"
    exit 1
fi

# Step 2: Clean up old NAT rules
print_step "Cleaning up old NAT rules"

# Remove old 10.0.0.0/24 rules
iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null && \
    print_msg "$GREEN" "✓ Removed old NAT rule: 10.0.0.0/24 -> eth0" || \
    print_msg "$YELLOW" "⚠ Old NAT rule not found (may be OK)"

iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o ens3 -j MASQUERADE 2>/dev/null && \
    print_msg "$GREEN" "✓ Removed old NAT rule: 10.0.0.0/24 -> ens3" || true

# Remove duplicate rules for eth0 (non-existent interface)
iptables -t nat -D POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE 2>/dev/null && \
    print_msg "$GREEN" "✓ Removed invalid NAT rule: 10.10.10.0/24 -> eth0" || true

iptables -D FORWARD -i tun0 -o eth0 -j ACCEPT 2>/dev/null && \
    print_msg "$GREEN" "✓ Removed invalid FORWARD rule: tun0 -> eth0" || true

iptables -D FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null && \
    print_msg "$GREEN" "✓ Removed invalid FORWARD rule: eth0 -> tun0" || true

print_msg "$GREEN" "✓ Old NAT rules cleaned up"

# Step 3: Ensure correct NAT rules are present
print_step "Verifying NAT rules"

# Check if correct NAT rule exists
if ! iptables -t nat -C POSTROUTING -s 10.10.10.0/24 -o "$INTERFACE" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o "$INTERFACE" -j MASQUERADE
    print_msg "$GREEN" "✓ Added NAT rule: 10.10.10.0/24 -> $INTERFACE"
else
    print_msg "$GREEN" "✓ NAT rule already exists"
fi

# Check FORWARD rules
if ! iptables -C FORWARD -i tun+ -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -i tun+ -j ACCEPT
    print_msg "$GREEN" "✓ Added FORWARD rule: tun+ -> any"
else
    print_msg "$GREEN" "✓ FORWARD rule already exists"
fi

if ! iptables -C FORWARD -o tun+ -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -o tun+ -j ACCEPT
    print_msg "$GREEN" "✓ Added FORWARD rule: any -> tun+"
else
    print_msg "$GREEN" "✓ FORWARD rule already exists"
fi

# Save rules
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save >/dev/null 2>&1
    print_msg "$GREEN" "✓ iptables rules saved"
fi

# Step 4: Create systemd service
print_step "Creating systemd service"

if [[ -f "$SYSTEMD_DIR/gatekeeper.service" ]]; then
    print_msg "$YELLOW" "⚠ Service file already exists, overwriting..."
fi

cat > "$SYSTEMD_DIR/gatekeeper.service" << EOF
[Unit]
Description=GatekeeperVPN Server
Documentation=https://github.com/your-org/gatekeepervpn
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/gatekeeper-server -c $CONFIG_DIR/server.toml -p $CONFIG_DIR/peers.toml
Restart=always
RestartSec=5
LimitNOFILE=65535

# Security
NoNewPrivileges=no
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF

print_msg "$GREEN" "✓ Systemd service created"

# Step 5: Enable and start service
print_step "Starting GatekeeperVPN service"

systemctl daemon-reload
systemctl enable gatekeeper.service >/dev/null 2>&1
print_msg "$GREEN" "✓ Service enabled"

# Stop if running
if systemctl is-active --quiet gatekeeper.service; then
    print_msg "$YELLOW" "⚠ Stopping existing service..."
    systemctl stop gatekeeper.service
fi

# Start service
systemctl start gatekeeper.service
sleep 2

# Check status
if systemctl is-active --quiet gatekeeper.service; then
    print_msg "$GREEN" "✓ Service started successfully"
else
    print_msg "$RED" "❌ Service failed to start"
    print_msg "$YELLOW" "Checking logs..."
    journalctl -u gatekeeper -n 20 --no-pager
    exit 1
fi

# Step 6: Verification
print_step "Verification"

echo ""
print_msg "$BLUE" "Service Status:"
systemctl status gatekeeper.service --no-pager -l | head -n 15

echo ""
print_msg "$BLUE" "Configuration:"
grep external_interface "$CONFIG_DIR/server.toml"
grep enable_nat "$CONFIG_DIR/server.toml"

echo ""
print_msg "$BLUE" "NAT Rules:"
iptables -t nat -L POSTROUTING -n | grep -E "(Chain|MASQUERADE)" | grep -v "^$"

echo ""
print_msg "$BLUE" "FORWARD Rules:"
iptables -L FORWARD -n | grep -E "(Chain|tun)" | head -n 5

echo ""
print_msg "$BLUE" "Recent Logs:"
journalctl -u gatekeeper -n 10 --no-pager

# Final summary
print_step "Installation Fixed! ✓"

echo ""
print_msg "$GREEN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print_msg "$GREEN" "  GatekeeperVPN Server is now running!"
print_msg "$GREEN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

SERVER_IP=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)

echo "🌐 Server Address: $SERVER_IP:51820"
echo "🔧 Manage Service:  systemctl status/restart/stop gatekeeper"
echo "📊 View Logs:       journalctl -u gatekeeper -f"
echo ""
echo "👥 Next Steps:"
echo "   1. Add a client:   gkvpn add \"client-name\" --server-address $SERVER_IP:51820"
echo "   2. Copy profile:   /etc/gatekeeper/profiles/client-name.conf"
echo "   3. Connect client: gatekeeper-client -c client-name.conf"
echo ""
print_msg "$GREEN" "✓ Ready to accept client connections!"
echo ""
