#!/bin/bash
#
# GatekeeperVPN Server Setup Script
#
# Полная автоматическая установка и настройка сервера:
# - Установка зависимостей
# - Сборка проекта
# - Установка бинарников
# - Генерация конфигурации
# - Настройка NAT и firewall
# - Создание systemd сервиса
# - Запуск сервера
#

# НЕ используем set -e чтобы контролировать ошибки
set -o pipefail

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
LOG_FILE="/tmp/gatekeeper-setup-$(date +%Y%m%d-%H%M%S).log"
SUBNET=""
MASK=""
SERVER_IP=""
PORT=""
INTERFACE=""
INTERFACE_IP=""

# Redirect all output to log file AND console
exec > >(tee -a "$LOG_FILE")
exec 2>&1

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

# Error handler
error_exit() {
    local msg="$1"
    print_msg "$RED" "❌ ERROR: $msg"
    print_msg "$YELLOW" ""
    print_msg "$YELLOW" "Installation log saved to: $LOG_FILE"
    print_msg "$YELLOW" "Please send this log file for troubleshooting."
    exit 1
}

# Trap errors
trap 'error_exit "Script failed at line $LINENO"' ERR

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
        apt-get update -qq || error_exit "Failed to update package list"

        print_msg "$YELLOW" "Installing required packages..."
        apt-get install -y \
            build-essential \
            pkg-config \
            libssl-dev \
            curl \
            git \
            iptables \
            iptables-persistent \
            netfilter-persistent || error_exit "Failed to install system packages"

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
            iptables-services || error_exit "Failed to install system packages"

        print_msg "$GREEN" "✓ System packages installed"
    else
        print_msg "$YELLOW" "⚠ Unknown package manager, skipping system packages"
    fi
}

# Install Rust
install_rust() {
    print_step "Checking Rust installation"

    # Check if cargo is available (including in PATH)
    if command -v cargo &> /dev/null; then
        RUST_VERSION=$(rustc --version | cut -d' ' -f2)
        print_msg "$GREEN" "✓ Rust already installed: $RUST_VERSION"
        return
    fi

    # Try to source cargo env if it exists
    if [[ -f "$HOME/.cargo/env" ]]; then
        source "$HOME/.cargo/env"
        if command -v cargo &> /dev/null; then
            RUST_VERSION=$(rustc --version | cut -d' ' -f2)
            print_msg "$GREEN" "✓ Rust found in $HOME/.cargo: $RUST_VERSION"
            return
        fi
    fi

    print_msg "$YELLOW" "Installing Rust..."

    # Install rustup
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable || \
        error_exit "Failed to install Rust"

    # Source cargo env
    source "$HOME/.cargo/env" || error_exit "Failed to source cargo environment"

    # Verify installation
    if ! command -v cargo &> /dev/null; then
        error_exit "Cargo not found after installation"
    fi

    RUST_VERSION=$(rustc --version | cut -d' ' -f2)
    print_msg "$GREEN" "✓ Rust installed: $RUST_VERSION"
}

# Get network interface
get_interface() {
    print_step "Detecting network interface"

    # Try to auto-detect
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

    if [[ -z "$INTERFACE" ]]; then
        error_exit "Could not auto-detect network interface"
    fi

    # Verify interface exists
    if ! ip link show "$INTERFACE" &> /dev/null; then
        error_exit "Interface $INTERFACE not found"
    fi

    # Get interface IP
    INTERFACE_IP=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)

    if [[ -z "$INTERFACE_IP" ]]; then
        error_exit "Could not get IP address for interface $INTERFACE"
    fi

    print_msg "$GREEN" "✓ External interface: $INTERFACE ($INTERFACE_IP)"
}

# Configure subnet
configure_subnet() {
    print_step "Configuring VPN subnet"

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

    cd "$PROJECT_ROOT" || error_exit "Failed to change to project directory"

    # Ensure cargo is in PATH
    if [[ -f "$HOME/.cargo/env" ]]; then
        source "$HOME/.cargo/env"
    fi
    export PATH="$HOME/.cargo/bin:$PATH"

    # Verify cargo is available
    if ! command -v cargo &> /dev/null; then
        error_exit "Cargo not found in PATH"
    fi

    print_msg "$YELLOW" "Running cargo build --release (this may take a few minutes)..."
    cargo build --release || error_exit "Cargo build failed"

    if [[ ! -f "$PROJECT_ROOT/target/release/gatekeeper-server" ]]; then
        error_exit "Build failed: gatekeeper-server binary not found"
    fi

    print_msg "$GREEN" "✓ Build complete"
}

# Install binaries
install_binaries() {
    print_step "Installing binaries"

    install -m 755 "$PROJECT_ROOT/target/release/gatekeeper-server" "$INSTALL_DIR/" || \
        error_exit "Failed to install gatekeeper-server"
    install -m 755 "$PROJECT_ROOT/target/release/gatekeeper-client" "$INSTALL_DIR/" || \
        error_exit "Failed to install gatekeeper-client"
    install -m 755 "$PROJECT_ROOT/target/release/gkvpn" "$INSTALL_DIR/" || \
        error_exit "Failed to install gkvpn"

    print_msg "$GREEN" "✓ Installed to $INSTALL_DIR/"
    print_msg "$GREEN" "  - gatekeeper-server"
    print_msg "$GREEN" "  - gatekeeper-client"
    print_msg "$GREEN" "  - gkvpn"
}

# Generate configuration
generate_config() {
    print_step "Generating server configuration"

    mkdir -p "$CONFIG_DIR" || error_exit "Failed to create config directory"
    mkdir -p "$CONFIG_DIR/profiles" || error_exit "Failed to create profiles directory"

    # Backup old config if exists
    if [[ -f "$CONFIG_DIR/server.toml" ]]; then
        print_msg "$YELLOW" "Backing up existing config..."
        mv "$CONFIG_DIR/server.toml" "$CONFIG_DIR/server.toml.backup-$(date +%Y%m%d-%H%M%S)"
    fi

    # Generate server config with keys
    "$INSTALL_DIR/gkvpn" generate-server \
        --listen "0.0.0.0:$PORT" \
        --tun-address "$SERVER_IP" \
        --output "$CONFIG_DIR/server.toml" || error_exit "Failed to generate server config"

    # Replace NAT configuration values (gkvpn already adds these fields with defaults)
    # We need to UPDATE them, not ADD new ones
    sed -i "s/^external_interface = .*/external_interface = \"$INTERFACE\"/" "$CONFIG_DIR/server.toml" || \
        error_exit "Failed to update external_interface"
    sed -i "s/^enable_nat = .*/enable_nat = true/" "$CONFIG_DIR/server.toml" || \
        error_exit "Failed to update enable_nat"

    # Initialize peers
    "$INSTALL_DIR/gkvpn" --config-dir "$CONFIG_DIR" init \
        --subnet "$SUBNET" \
        --mask "$MASK" \
        --force || error_exit "Failed to initialize peers"

    # Set permissions
    chmod 600 "$CONFIG_DIR/server.toml" || error_exit "Failed to set permissions on server.toml"
    chmod 600 "$CONFIG_DIR/peers.toml" || error_exit "Failed to set permissions on peers.toml"
    chmod 755 "$CONFIG_DIR/profiles" || error_exit "Failed to set permissions on profiles dir"

    print_msg "$GREEN" "✓ Configuration generated at $CONFIG_DIR/"
}

# Setup IP forwarding
setup_ip_forwarding() {
    print_step "Enabling IP forwarding"

    # Enable immediately
    sysctl -w net.ipv4.ip_forward=1 > /dev/null || error_exit "Failed to enable IP forwarding"

    # Make persistent
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-gatekeeper.conf || \
        error_exit "Failed to make IP forwarding persistent"

    # Verify
    FORWARD_STATUS=$(sysctl -n net.ipv4.ip_forward)
    if [[ "$FORWARD_STATUS" == "1" ]]; then
        print_msg "$GREEN" "✓ IP forwarding enabled"
    else
        error_exit "IP forwarding verification failed"
    fi
}

# Setup NAT and firewall
setup_nat() {
    print_step "Configuring NAT and firewall"

    local VPN_SUBNET="$SUBNET/$MASK"

    print_msg "$YELLOW" "Setting up iptables rules..."

    # NAT: POSTROUTING (masquerade VPN traffic)
    if ! iptables -t nat -C POSTROUTING -s "$VPN_SUBNET" -o "$INTERFACE" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "$VPN_SUBNET" -o "$INTERFACE" -j MASQUERADE || \
            error_exit "Failed to add NAT rule"
    fi
    print_msg "$GREEN" "  ✓ NAT rule added: $VPN_SUBNET -> $INTERFACE"

    # FORWARD: Allow VPN traffic forwarding
    if ! iptables -C FORWARD -i tun+ -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i tun+ -j ACCEPT || error_exit "Failed to add FORWARD rule"
    fi

    if ! iptables -C FORWARD -o tun+ -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -o tun+ -j ACCEPT || error_exit "Failed to add FORWARD rule"
    fi
    print_msg "$GREEN" "  ✓ FORWARD rules added for tun interfaces"

    # FORWARD: Specific interface forwarding
    if ! iptables -C FORWARD -i tun+ -o "$INTERFACE" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i tun+ -o "$INTERFACE" -j ACCEPT || error_exit "Failed to add FORWARD rule"
    fi

    if ! iptables -C FORWARD -i "$INTERFACE" -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$INTERFACE" -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT || \
            error_exit "Failed to add FORWARD rule"
    fi
    print_msg "$GREEN" "  ✓ FORWARD rules added: tun+ <-> $INTERFACE"

    # Save iptables rules
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save >/dev/null 2>&1 || print_msg "$YELLOW" "  ⚠ Failed to save iptables rules"
        print_msg "$GREEN" "  ✓ Rules saved via netfilter-persistent"
    elif command -v iptables-save &> /dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 || print_msg "$YELLOW" "  ⚠ Failed to save iptables rules"
        print_msg "$GREEN" "  ✓ Rules saved to /etc/iptables/rules.v4"
    fi

    # Open VPN port in firewall (if ufw is active)
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$PORT/udp" > /dev/null 2>&1 || true
        print_msg "$GREEN" "  ✓ UFW: opened port $PORT/udp"
    fi

    print_msg "$GREEN" "✓ NAT and firewall configured successfully"
}

# Create systemd service
install_systemd() {
    print_step "Installing systemd service"

    cat > "$SYSTEMD_DIR/gatekeeper.service" << EOF || error_exit "Failed to create systemd service"
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
    systemctl daemon-reload || error_exit "Failed to reload systemd"

    # Enable service
    systemctl enable gatekeeper.service || error_exit "Failed to enable service"

    print_msg "$GREEN" "✓ Systemd service installed and enabled"
}

# Start service
start_service() {
    print_step "Starting GatekeeperVPN server"

    systemctl start gatekeeper.service || error_exit "Failed to start service"

    # Wait for service to start
    sleep 3

    # Check status
    if systemctl is-active --quiet gatekeeper.service; then
        print_msg "$GREEN" "✓ Server started successfully"
    else
        print_msg "$RED" "❌ Server failed to start"
        print_msg "$YELLOW" "Last 20 log lines:"
        journalctl -u gatekeeper -n 20 --no-pager
        error_exit "Service failed to start"
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

    print_msg "$GREEN" "📝 Installation log saved to: $LOG_FILE"
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
    print_msg "$BLUE" "📝 Logging to: $LOG_FILE"
    echo ""

    check_root

    # Check if already installed
    if [[ -f "$CONFIG_DIR/server.toml" ]] || [[ -f "$SYSTEMD_DIR/gatekeeper.service" ]]; then
        print_msg "$YELLOW" ""
        print_msg "$YELLOW" "⚠️  WARNING: Existing installation detected!"
        print_msg "$YELLOW" ""
        if [[ -f "$CONFIG_DIR/server.toml" ]]; then
            print_msg "$YELLOW" "   - Found config: $CONFIG_DIR/server.toml"
        fi
        if [[ -f "$SYSTEMD_DIR/gatekeeper.service" ]]; then
            print_msg "$YELLOW" "   - Found service: $SYSTEMD_DIR/gatekeeper.service"
        fi
        print_msg "$YELLOW" ""
        print_msg "$YELLOW" "   Old config will be backed up before reinstalling."
        print_msg "$YELLOW" "   Clients (peers.toml) will NOT be deleted."
        print_msg "$YELLOW" ""
        read -p "Continue with reinstallation? [y/N]: " reinstall_confirm
        if [[ ! "$reinstall_confirm" =~ ^[Yy]$ ]]; then
            print_msg "$RED" "Installation cancelled."
            print_msg "$YELLOW" "To manually fix configuration, run: bash scripts/fix-installation.sh"
            exit 0
        fi
    fi

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
    install_systemd
    start_service
    print_summary

    print_msg "$GREEN" "✓ Installation completed successfully!"
    echo ""
}

main "$@"
