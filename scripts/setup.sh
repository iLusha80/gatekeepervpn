#!/bin/bash
#
# GatekeeperVPN Server Setup Script
#
# Interactive setup for:
# - Building and installing binaries
# - Generating server configuration
# - Creating peers.toml
# - Setting up NAT and firewall
# - Creating systemd service
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEFAULT_SUBNET="10.10.10.0"
DEFAULT_MASK=24
DEFAULT_PORT=51820
CONFIG_DIR="/etc/gatekeeper"
INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            echo "debian"
        elif command -v dnf &> /dev/null; then
            echo "fedora"
        elif command -v yum &> /dev/null; then
            echo "centos"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Print colored message
print_msg() {
    local color=$1
    local msg=$2
    echo -e "${color}${msg}${NC}"
}

# Print step header
print_step() {
    echo ""
    print_msg "$BLUE" "==> $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_msg "$RED" "Error: This script must be run as root"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    print_step "Checking dependencies..."

    local missing=()

    # Check for cargo
    if ! command -v cargo &> /dev/null; then
        missing+=("cargo (Rust)")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        print_msg "$RED" "Missing dependencies: ${missing[*]}"
        print_msg "$YELLOW" "Please install them and run this script again."
        exit 1
    fi

    print_msg "$GREEN" "All dependencies found."
}

# Select subnet interactively
select_subnet() {
    print_step "Select VPN subnet"

    echo ""
    echo "Choose a subnet for your VPN:"
    echo ""
    echo "  1) 10.10.10.0/24  - 253 clients (recommended for small deployments)"
    echo "  2) 10.10.0.0/16   - 65533 clients (large deployments)"
    echo "  3) Custom subnet"
    echo ""

    read -p "Selection [1]: " choice
    choice=${choice:-1}

    case $choice in
        1)
            SUBNET="10.10.10.0"
            MASK=24
            ;;
        2)
            SUBNET="10.10.0.0"
            MASK=16
            ;;
        3)
            read -p "Enter subnet (e.g., 192.168.100.0): " SUBNET
            SUBNET=${SUBNET:-$DEFAULT_SUBNET}
            read -p "Enter mask (e.g., 24): " MASK
            MASK=${MASK:-$DEFAULT_MASK}
            ;;
        *)
            SUBNET=$DEFAULT_SUBNET
            MASK=$DEFAULT_MASK
            ;;
    esac

    # Calculate server IP (first usable)
    IFS='.' read -r -a octets <<< "$SUBNET"
    SERVER_IP="${octets[0]}.${octets[1]}.${octets[2]}.$((octets[3] + 1))"

    print_msg "$GREEN" "Selected: $SUBNET/$MASK (Server IP: $SERVER_IP)"
}

# Get server port
get_port() {
    print_step "Configure server port"

    read -p "UDP port [$DEFAULT_PORT]: " PORT
    PORT=${PORT:-$DEFAULT_PORT}

    print_msg "$GREEN" "Using port: $PORT"
}

# Get network interface for NAT
get_interface() {
    print_step "Configure NAT"

    # Try to detect default interface
    if [[ $(detect_os) == "macos" ]]; then
        DEFAULT_IF=$(route -n get default 2>/dev/null | grep interface | awk '{print $2}')
    else
        DEFAULT_IF=$(ip route | grep default | awk '{print $5}' | head -n1)
    fi

    echo ""
    echo "Network interface for NAT (internet-facing):"
    read -p "Interface [$DEFAULT_IF]: " INTERFACE
    INTERFACE=${INTERFACE:-$DEFAULT_IF}

    print_msg "$GREEN" "Using interface: $INTERFACE"
}

# Build project
build_project() {
    print_step "Building GatekeeperVPN..."

    # Find project root (script is in scripts/)
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

    cd "$PROJECT_ROOT"

    cargo build --release

    print_msg "$GREEN" "Build complete."
}

# Install binaries
install_binaries() {
    print_step "Installing binaries to $INSTALL_DIR..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

    install -m 755 "$PROJECT_ROOT/target/release/gatekeeper-server" "$INSTALL_DIR/"
    install -m 755 "$PROJECT_ROOT/target/release/gatekeeper-client" "$INSTALL_DIR/"
    install -m 755 "$PROJECT_ROOT/target/release/gkvpn" "$INSTALL_DIR/"

    print_msg "$GREEN" "Binaries installed."
}

# Generate server configuration
generate_config() {
    print_step "Generating server configuration..."

    # Create config directory
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$CONFIG_DIR/profiles"

    # Generate server config with keys
    "$INSTALL_DIR/gkvpn" generate-server \
        --listen "0.0.0.0:$PORT" \
        --tun-address "$SERVER_IP" \
        --output "$CONFIG_DIR/server.toml"

    # Initialize peers
    "$INSTALL_DIR/gkvpn" --config-dir "$CONFIG_DIR" init \
        --subnet "$SUBNET" \
        --mask "$MASK" \
        --force

    # Set permissions
    chmod 600 "$CONFIG_DIR/server.toml"
    chmod 600 "$CONFIG_DIR/peers.toml"

    print_msg "$GREEN" "Configuration generated at $CONFIG_DIR/"
}

# Setup firewall and NAT (Linux)
setup_firewall_linux() {
    print_step "Setting up firewall and NAT..."

    # Enable IP forwarding
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-gatekeeper.conf
    sysctl -w net.ipv4.ip_forward=1

    local VPN_SUBNET="$SUBNET/$MASK"

    # Check for nftables vs iptables
    if command -v nft &> /dev/null && systemctl is-active --quiet nftables; then
        print_msg "$YELLOW" "Using nftables..."

        # Create nftables rules
        cat > /etc/nftables.d/gatekeeper.conf << EOF
table ip gatekeeper {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr $VPN_SUBNET oifname "$INTERFACE" masquerade
    }

    chain forward {
        type filter hook forward priority filter; policy accept;
        ip saddr $VPN_SUBNET accept
        ip daddr $VPN_SUBNET accept
    }
}
EOF
        nft -f /etc/nftables.d/gatekeeper.conf

    else
        print_msg "$YELLOW" "Using iptables..."

        # NAT masquerading
        iptables -t nat -A POSTROUTING -s "$VPN_SUBNET" -o "$INTERFACE" -j MASQUERADE

        # Allow forwarding
        iptables -A FORWARD -s "$VPN_SUBNET" -j ACCEPT
        iptables -A FORWARD -d "$VPN_SUBNET" -j ACCEPT

        # Save rules
        if command -v iptables-save &> /dev/null; then
            if [[ -d /etc/iptables ]]; then
                iptables-save > /etc/iptables/rules.v4
            fi
        fi
    fi

    # Open UDP port
    if command -v ufw &> /dev/null; then
        ufw allow "$PORT/udp"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port="$PORT/udp"
        firewall-cmd --reload
    fi

    print_msg "$GREEN" "Firewall and NAT configured."
}

# Setup firewall (macOS)
setup_firewall_macos() {
    print_step "Setting up NAT (macOS)..."

    local VPN_SUBNET="$SUBNET/$MASK"

    # Enable IP forwarding
    sysctl -w net.inet.ip.forwarding=1

    # Create pf anchor for NAT
    cat > /etc/pf.anchors/gatekeeper << EOF
# GatekeeperVPN NAT rules
nat on $INTERFACE from $VPN_SUBNET to any -> ($INTERFACE)
pass in on utun+ all
pass out on utun+ all
EOF

    # Add anchor to pf.conf if not present
    if ! grep -q "gatekeeper" /etc/pf.conf; then
        echo "nat-anchor \"gatekeeper\"" >> /etc/pf.conf
        echo "anchor \"gatekeeper\"" >> /etc/pf.conf
        echo "load anchor \"gatekeeper\" from \"/etc/pf.anchors/gatekeeper\"" >> /etc/pf.conf
    fi

    # Load rules
    pfctl -f /etc/pf.conf
    pfctl -e 2>/dev/null || true

    print_msg "$GREEN" "NAT configured (macOS)."
    print_msg "$YELLOW" "Note: macOS NAT rules are not persistent across reboots."
    print_msg "$YELLOW" "Add 'pfctl -f /etc/pf.conf' to a startup script."
}

# Install systemd service (Linux only)
install_systemd() {
    if [[ $(detect_os) == "macos" ]]; then
        print_msg "$YELLOW" "Skipping systemd setup on macOS."
        return
    fi

    print_step "Installing systemd service..."

    cat > "$SYSTEMD_DIR/gatekeeper.service" << EOF
[Unit]
Description=GatekeeperVPN Server
Documentation=https://github.com/your-org/gatekeepervpn
After=network.target network-online.target
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

    # Enable and start service
    systemctl enable gatekeeper.service
    systemctl start gatekeeper.service

    print_msg "$GREEN" "Systemd service installed and started."
}

# Print summary
print_summary() {
    print_step "Setup Complete!"

    echo ""
    echo "Configuration:"
    echo "  Config directory: $CONFIG_DIR"
    echo "  Server config:    $CONFIG_DIR/server.toml"
    echo "  Peers config:     $CONFIG_DIR/peers.toml"
    echo "  Profiles:         $CONFIG_DIR/profiles/"
    echo ""
    echo "Network:"
    echo "  Subnet:     $SUBNET/$MASK"
    echo "  Server IP:  $SERVER_IP"
    echo "  Port:       $PORT/UDP"
    echo ""
    echo "Commands:"
    echo "  Add client:     gkvpn add \"client-name\" --server-address YOUR_SERVER_IP:$PORT"
    echo "  List clients:   gkvpn list"
    echo "  Show profile:   gkvpn show \"client-name\""
    echo "  Remove client:  gkvpn remove \"client-name\""
    echo ""

    if [[ $(detect_os) != "macos" ]]; then
        echo "Service:"
        echo "  Status:   systemctl status gatekeeper"
        echo "  Logs:     journalctl -u gatekeeper -f"
        echo "  Restart:  systemctl restart gatekeeper"
        echo ""
    fi

    print_msg "$GREEN" "GatekeeperVPN is ready!"
    print_msg "$YELLOW" "Don't forget to replace YOUR_SERVER_IP with your actual server IP when adding clients."
}

# Main
main() {
    print_msg "$BLUE" "========================================"
    print_msg "$BLUE" "    GatekeeperVPN Server Setup"
    print_msg "$BLUE" "========================================"

    check_root
    check_dependencies

    OS=$(detect_os)
    print_msg "$GREEN" "Detected OS: $OS"

    select_subnet
    get_port
    get_interface

    echo ""
    print_msg "$YELLOW" "Ready to install with the following settings:"
    echo "  Subnet:     $SUBNET/$MASK"
    echo "  Server IP:  $SERVER_IP"
    echo "  Port:       $PORT"
    echo "  Interface:  $INTERFACE"
    echo ""

    read -p "Continue? [Y/n]: " confirm
    confirm=${confirm:-Y}

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_msg "$RED" "Aborted."
        exit 1
    fi

    build_project
    install_binaries
    generate_config

    if [[ "$OS" == "macos" ]]; then
        setup_firewall_macos
    else
        setup_firewall_linux
    fi

    install_systemd

    print_summary
}

main "$@"
