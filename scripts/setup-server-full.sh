#!/bin/bash
#
# GatekeeperVPN Full Server Setup Script
#
# Полная автоматическая установка и настройка сервера на чистой системе:
# - Установка зависимостей
# - Сборка проекта
# - Установка бинарников
# - Генерация конфигурации
# - Настройка NAT и firewall
# - Создание systemd сервиса
# - Запуск сервера
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Default values
DEFAULT_SUBNET="10.10.10.0"
DEFAULT_MASK=24
DEFAULT_PORT=51820
CONFIG_DIR="/etc/gatekeeper"
INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SUBNET=""
MASK=""
SERVER_IP=""
PORT=""
INTERFACE=""

# Print colored message
print_msg() {
    local color=$1
    local msg=$2
    echo -e "${color}${msg}${NC}"
}

# Print step header
print_step() {
    echo ""
    print_msg "$CYAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$BLUE" "  ▶ $1"
    print_msg "$CYAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_msg "$RED" "❌ Error: This script must be run as root (use sudo)"
        exit 1
    fi
    print_msg "$GREEN" "✓ Running as root"
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME=$ID
        OS_VERSION=$VERSION_ID
    else
        OS_NAME="unknown"
    fi

    if [[ "$OS_NAME" =~ ^(debian|ubuntu)$ ]]; then
        PKG_MANAGER="apt-get"
    elif [[ "$OS_NAME" =~ ^(centos|rhel|fedora)$ ]]; then
        PKG_MANAGER="yum"
    else
        PKG_MANAGER="unknown"
    fi
}

# Install system dependencies
install_dependencies() {
    print_step "Installing system dependencies"

    detect_os

    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        print_msg "$YELLOW" "Updating package list..."
        apt-get update -qq

        print_msg "$YELLOW" "Installing required packages..."
        apt-get install -y \
            build-essential \
            pkg-config \
            libssl-dev \
            curl \
            git \
            iptables \
            iptables-persistent \
            netfilter-persistent

        print_msg "$GREEN" "✓ System packages installed"

    elif [[ "$PKG_MANAGER" == "yum" ]]; then
        print_msg "$YELLOW" "Installing required packages..."
        yum install -y \
            gcc \
            gcc-c++ \
            make \
            pkgconfig \
            openssl-devel \
            curl \
            git \
            iptables-services

        print_msg "$GREEN" "✓ System packages installed"
    else
        print_msg "$YELLOW" "⚠ Unknown package manager, skipping system packages"
    fi
}

# Install Rust
install_rust() {
    print_step "Checking Rust installation"

    if command -v cargo &> /dev/null; then
        RUST_VERSION=$(rustc --version | cut -d' ' -f2)
        print_msg "$GREEN" "✓ Rust already installed: $RUST_VERSION"
        return
    fi

    print_msg "$YELLOW" "Installing Rust..."

    # Install rustup for root user
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

    # Source cargo env
    source "$HOME/.cargo/env"

    RUST_VERSION=$(rustc --version | cut -d' ' -f2)
    print_msg "$GREEN" "✓ Rust installed: $RUST_VERSION"
}

# Get network interface for NAT
get_interface() {
    print_step "Detecting network interface"

    # Try to auto-detect
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

    if [[ -z "$INTERFACE" ]]; then
        print_msg "$RED" "❌ Could not auto-detect network interface"
        exit 1
    fi

    # Verify interface exists
    if ! ip link show "$INTERFACE" &> /dev/null; then
        print_msg "$RED" "❌ Interface $INTERFACE not found"
        exit 1
    fi

    # Get interface IP
    INTERFACE_IP=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)

    print_msg "$GREEN" "✓ External interface: $INTERFACE ($INTERFACE_IP)"
}

# Configure subnet
configure_subnet() {
    print_step "Configuring VPN subnet"

    # Use defaults for automated setup
    SUBNET=$DEFAULT_SUBNET
    MASK=$DEFAULT_MASK

    # Calculate server IP (first usable)
    IFS='.' read -r -a octets <<< "$SUBNET"
    SERVER_IP="${octets[0]}.${octets[1]}.${octets[2]}.$((octets[3] + 1))"

    print_msg "$GREEN" "✓ Subnet: $SUBNET/$MASK"
    print_msg "$GREEN" "✓ Server IP: $SERVER_IP"
}

# Configure port
configure_port() {
    print_step "Configuring server port"

    PORT=$DEFAULT_PORT

    print_msg "$GREEN" "✓ Port: $PORT/udp"
}

# Build project
build_project() {
    print_step "Building GatekeeperVPN from source"

    cd "$PROJECT_ROOT"

    # Ensure cargo is in PATH
    export PATH="$HOME/.cargo/bin:$PATH"

    print_msg "$YELLOW" "Running cargo build --release (this may take a few minutes)..."
    cargo build --release 2>&1 | grep -E "(Compiling|Finished)" || true

    if [[ ! -f "$PROJECT_ROOT/target/release/gatekeeper-server" ]]; then
        print_msg "$RED" "❌ Build failed: gatekeeper-server binary not found"
        exit 1
    fi

    print_msg "$GREEN" "✓ Build complete"
}

# Install binaries
install_binaries() {
    print_step "Installing binaries"

    install -m 755 "$PROJECT_ROOT/target/release/gatekeeper-server" "$INSTALL_DIR/"
    install -m 755 "$PROJECT_ROOT/target/release/gatekeeper-client" "$INSTALL_DIR/"
    install -m 755 "$PROJECT_ROOT/target/release/gkvpn" "$INSTALL_DIR/"

    print_msg "$GREEN" "✓ Installed to $INSTALL_DIR/"
    print_msg "$GREEN" "  - gatekeeper-server"
    print_msg "$GREEN" "  - gatekeeper-client"
    print_msg "$GREEN" "  - gkvpn"
}

# Generate configuration
generate_config() {
    print_step "Generating server configuration"

    mkdir -p "$CONFIG_DIR"
    mkdir -p "$CONFIG_DIR/profiles"

    # Generate server config with keys
    "$INSTALL_DIR/gkvpn" generate-server \
        --listen "0.0.0.0:$PORT" \
        --tun-address "$SERVER_IP" \
        --output "$CONFIG_DIR/server.toml"

    # Add NAT configuration
    cat >> "$CONFIG_DIR/server.toml" << EOF

# NAT configuration
# External network interface for internet access
external_interface = "$INTERFACE"

# Enable automatic NAT configuration (requires root)
enable_nat = true
EOF

    # Initialize peers
    "$INSTALL_DIR/gkvpn" --config-dir "$CONFIG_DIR" init \
        --subnet "$SUBNET" \
        --mask "$MASK" \
        --force

    # Set permissions
    chmod 600 "$CONFIG_DIR/server.toml"
    chmod 600 "$CONFIG_DIR/peers.toml"
    chmod 755 "$CONFIG_DIR/profiles"

    print_msg "$GREEN" "✓ Configuration generated at $CONFIG_DIR/"
}

# Setup IP forwarding
setup_ip_forwarding() {
    print_step "Enabling IP forwarding"

    # Enable immediately
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # Make persistent
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-gatekeeper.conf

    # Verify
    FORWARD_STATUS=$(sysctl -n net.ipv4.ip_forward)
    if [[ "$FORWARD_STATUS" == "1" ]]; then
        print_msg "$GREEN" "✓ IP forwarding enabled"
    else
        print_msg "$RED" "❌ Failed to enable IP forwarding"
        exit 1
    fi
}

# Setup NAT and firewall
setup_nat() {
    print_step "Configuring NAT and firewall"

    local VPN_SUBNET="$SUBNET/$MASK"

    print_msg "$YELLOW" "Setting up iptables rules..."

    # NAT: POSTROUTING (masquerade VPN traffic)
    iptables -t nat -C POSTROUTING -s "$VPN_SUBNET" -o "$INTERFACE" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "$VPN_SUBNET" -o "$INTERFACE" -j MASQUERADE

    print_msg "$GREEN" "  ✓ NAT rule added: $VPN_SUBNET -> $INTERFACE"

    # FORWARD: Allow VPN traffic forwarding
    iptables -C FORWARD -i tun+ -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i tun+ -j ACCEPT

    iptables -C FORWARD -o tun+ -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -o tun+ -j ACCEPT

    print_msg "$GREEN" "  ✓ FORWARD rules added for tun interfaces"

    # FORWARD: Specific interface forwarding
    iptables -C FORWARD -i tun+ -o "$INTERFACE" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i tun+ -o "$INTERFACE" -j ACCEPT

    iptables -C FORWARD -i "$INTERFACE" -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$INTERFACE" -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

    print_msg "$GREEN" "  ✓ FORWARD rules added: tun+ <-> $INTERFACE"

    # Save iptables rules
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save
        print_msg "$GREEN" "  ✓ Rules saved via netfilter-persistent"
    elif command -v iptables-save &> /dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        print_msg "$GREEN" "  ✓ Rules saved to /etc/iptables/rules.v4"
    fi

    # Open VPN port in firewall (if ufw is active)
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "$PORT/udp" > /dev/null
        print_msg "$GREEN" "  ✓ UFW: opened port $PORT/udp"
    fi

    print_msg "$GREEN" "✓ NAT and firewall configured successfully"
}

# Verify NAT configuration
verify_nat() {
    print_step "Verifying NAT configuration"

    local VPN_SUBNET="$SUBNET/$MASK"

    # Check MASQUERADE rule
    if iptables -t nat -L POSTROUTING -n | grep -q "$VPN_SUBNET"; then
        print_msg "$GREEN" "✓ NAT MASQUERADE rule present"
    else
        print_msg "$RED" "❌ NAT MASQUERADE rule missing!"
        return 1
    fi

    # Check FORWARD rules
    if iptables -L FORWARD -n | grep -q "tun"; then
        print_msg "$GREEN" "✓ FORWARD rules present"
    else
        print_msg "$RED" "❌ FORWARD rules missing!"
        return 1
    fi
}

# Create systemd service
install_systemd() {
    print_step "Installing systemd service"

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

# Security hardening
NoNewPrivileges=no
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload

    # Enable service
    systemctl enable gatekeeper.service

    print_msg "$GREEN" "✓ Systemd service installed and enabled"
}

# Start service
start_service() {
    print_step "Starting GatekeeperVPN server"

    systemctl start gatekeeper.service

    # Wait a moment for service to start
    sleep 2

    # Check status
    if systemctl is-active --quiet gatekeeper.service; then
        print_msg "$GREEN" "✓ Server started successfully"
    else
        print_msg "$RED" "❌ Server failed to start"
        print_msg "$YELLOW" "Check logs with: journalctl -u gatekeeper -n 50"
        exit 1
    fi
}

# Print summary
print_summary() {
    print_step "Installation Complete! 🎉"

    echo ""
    print_msg "$GREEN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$GREEN" "  GatekeeperVPN Server is running!"
    print_msg "$GREEN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    echo "📁 Configuration:"
    echo "   Config directory:  $CONFIG_DIR"
    echo "   Server config:     $CONFIG_DIR/server.toml"
    echo "   Peers config:      $CONFIG_DIR/peers.toml"
    echo "   Client profiles:   $CONFIG_DIR/profiles/"
    echo ""

    echo "🌐 Network:"
    echo "   Server address:    $INTERFACE_IP:$PORT"
    echo "   VPN subnet:        $SUBNET/$MASK"
    echo "   VPN server IP:     $SERVER_IP"
    echo "   External interface: $INTERFACE"
    echo ""

    echo "🔧 Service Management:"
    echo "   Status:   systemctl status gatekeeper"
    echo "   Stop:     systemctl stop gatekeeper"
    echo "   Start:    systemctl start gatekeeper"
    echo "   Restart:  systemctl restart gatekeeper"
    echo "   Logs:     journalctl -u gatekeeper -f"
    echo ""

    echo "👥 Client Management:"
    echo "   Add client:     gkvpn add \"client-name\" --server-address $INTERFACE_IP:$PORT"
    echo "   List clients:   gkvpn list"
    echo "   Show profile:   gkvpn show \"client-name\""
    echo "   Remove client:  gkvpn remove \"client-name\""
    echo ""

    echo "📊 Diagnostics:"
    echo "   Run diagnostics:  bash $SCRIPT_DIR/diagnose.sh"
    echo ""

    print_msg "$YELLOW" "⚠️  Next steps:"
    echo "   1. Add your first client: gkvpn add \"myclient\" --server-address $INTERFACE_IP:$PORT"
    echo "   2. Copy the client profile from: $CONFIG_DIR/profiles/myclient.conf"
    echo "   3. Run the client: gatekeeper-client -c myclient.conf"
    echo ""
}

# Main installation flow
main() {
    clear
    print_msg "$CYAN" "╔════════════════════════════════════════════════════════════════╗"
    print_msg "$CYAN" "║                                                                ║"
    print_msg "$CYAN" "║        GatekeeperVPN Full Server Installation                 ║"
    print_msg "$CYAN" "║                                                                ║"
    print_msg "$CYAN" "╚════════════════════════════════════════════════════════════════╝"
    echo ""

    check_root
    get_interface
    configure_subnet
    configure_port

    echo ""
    print_msg "$YELLOW" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$YELLOW" "  Installation Settings"
    print_msg "$YELLOW" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  VPN Subnet:         $SUBNET/$MASK"
    echo "  Server VPN IP:      $SERVER_IP"
    echo "  Server Port:        $PORT/udp"
    echo "  External Interface: $INTERFACE ($INTERFACE_IP)"
    echo "  Install Directory:  $INSTALL_DIR"
    echo "  Config Directory:   $CONFIG_DIR"
    print_msg "$YELLOW" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    read -p "Continue with installation? [Y/n]: " confirm
    confirm=${confirm:-Y}

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_msg "$RED" "Installation cancelled."
        exit 0
    fi

    echo ""
    print_msg "$CYAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$CYAN" "  Starting installation..."
    print_msg "$CYAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    install_dependencies
    install_rust
    build_project
    install_binaries
    generate_config
    setup_ip_forwarding
    setup_nat
    verify_nat
    install_systemd
    start_service
    print_summary

    print_msg "$GREEN" "✓ Installation completed successfully!"
    echo ""
}

main "$@"
