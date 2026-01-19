#!/bin/bash
#
# GatekeeperVPN Diagnostic Script
#
# Проверяет настройку сервера и диагностирует проблемы:
# - IP forwarding
# - NAT/iptables rules
# - Network interfaces
# - Server configuration
# - TUN device
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

CONFIG_DIR="/etc/gatekeeper"
SERVER_CONFIG="$CONFIG_DIR/server.toml"

# Print colored message
print_msg() {
    local color=$1
    local msg=$2
    echo -e "${color}${msg}${NC}"
}

# Print section header
print_section() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$BLUE" "  $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_msg "$YELLOW" "Warning: Not running as root. Some checks may fail."
        echo ""
    fi
}

# Check 1: Server configuration
check_config() {
    print_section "1. Server Configuration"

    if [[ ! -f "$SERVER_CONFIG" ]]; then
        print_msg "$RED" "✗ Server config not found: $SERVER_CONFIG"
        return 1
    fi

    print_msg "$GREEN" "✓ Config file exists: $SERVER_CONFIG"
    echo ""

    # Parse config
    if grep -q "external_interface" "$SERVER_CONFIG"; then
        EXTERNAL_IF=$(grep "external_interface" "$SERVER_CONFIG" | cut -d'"' -f2)
        print_msg "$GREEN" "✓ external_interface = \"$EXTERNAL_IF\""
    else
        print_msg "$RED" "✗ external_interface not set in config!"
        print_msg "$YELLOW" "  Add this line to $SERVER_CONFIG:"
        print_msg "$YELLOW" "  external_interface = \"YOUR_INTERFACE\""
        return 1
    fi

    if grep -q "enable_nat.*true" "$SERVER_CONFIG"; then
        print_msg "$GREEN" "✓ enable_nat = true"
    else
        print_msg "$YELLOW" "⚠ enable_nat is not enabled"
    fi

    # Check TUN address
    if grep -q "tun_address" "$SERVER_CONFIG"; then
        TUN_ADDR=$(grep "tun_address" "$SERVER_CONFIG" | cut -d'"' -f2)
        print_msg "$GREEN" "✓ tun_address = \"$TUN_ADDR\""
    fi
}

# Check 2: Network interfaces
check_interfaces() {
    print_section "2. Network Interfaces"

    echo "Available interfaces:"
    if command -v ip &> /dev/null; then
        ip -4 addr show | grep -E "^[0-9]+:|inet " | sed 's/^/  /'
    else
        ifconfig | grep -E "^[a-z]|inet " | sed 's/^/  /'
    fi

    echo ""

    # Check if external interface exists
    if [[ -n "$EXTERNAL_IF" ]]; then
        if ip link show "$EXTERNAL_IF" &> /dev/null; then
            print_msg "$GREEN" "✓ External interface $EXTERNAL_IF exists"
        else
            print_msg "$RED" "✗ External interface $EXTERNAL_IF NOT FOUND!"
            print_msg "$YELLOW" "  Update external_interface in $SERVER_CONFIG"
        fi
    fi

    # Check for TUN devices
    echo ""
    echo "TUN devices:"
    if ip link show | grep -q "tun"; then
        ip link show | grep "tun" | sed 's/^/  /'
        print_msg "$GREEN" "✓ TUN devices found"
    else
        print_msg "$YELLOW" "⚠ No TUN devices found (server may not be running)"
    fi
}

# Check 3: IP forwarding
check_ip_forwarding() {
    print_section "3. IP Forwarding"

    if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then
        FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
        if [[ "$FORWARD" == "1" ]]; then
            print_msg "$GREEN" "✓ IP forwarding is ENABLED"
        else
            print_msg "$RED" "✗ IP forwarding is DISABLED!"
            print_msg "$YELLOW" "  Enable with: sudo sysctl -w net.ipv4.ip_forward=1"
            print_msg "$YELLOW" "  Make permanent: echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-gatekeeper.conf"
        fi
    else
        print_msg "$YELLOW" "⚠ Cannot check IP forwarding (not Linux)"
    fi
}

# Check 4: NAT/iptables rules
check_nat() {
    print_section "4. NAT Rules (iptables)"

    if ! command -v iptables &> /dev/null; then
        print_msg "$YELLOW" "⚠ iptables not found (macOS?)"
        return
    fi

    # Check MASQUERADE rule
    echo ""
    echo "NAT POSTROUTING rules:"
    iptables -t nat -L POSTROUTING -n -v --line-numbers 2>/dev/null | sed 's/^/  /' || print_msg "$RED" "✗ Cannot read iptables (run as root)"

    if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "MASQUERADE"; then
        print_msg "$GREEN" "✓ MASQUERADE rule found"
    else
        print_msg "$RED" "✗ No MASQUERADE rule found!"
        if [[ -n "$EXTERNAL_IF" ]]; then
            print_msg "$YELLOW" "  Add with: sudo iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o $EXTERNAL_IF -j MASQUERADE"
        fi
    fi

    # Check FORWARD rules
    echo ""
    echo "FORWARD rules:"
    iptables -L FORWARD -n -v --line-numbers 2>/dev/null | sed 's/^/  /' || print_msg "$RED" "✗ Cannot read iptables (run as root)"

    if iptables -L FORWARD -n 2>/dev/null | grep -q "tun"; then
        print_msg "$GREEN" "✓ FORWARD rules for TUN found"
    else
        print_msg "$YELLOW" "⚠ No FORWARD rules for TUN interfaces"
    fi
}

# Check 5: Service status
check_service() {
    print_section "5. Service Status"

    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet gatekeeper; then
            print_msg "$GREEN" "✓ gatekeeper.service is RUNNING"
            echo ""
            echo "Recent logs:"
            journalctl -u gatekeeper -n 10 --no-pager | sed 's/^/  /'
        else
            print_msg "$RED" "✗ gatekeeper.service is NOT running"
            print_msg "$YELLOW" "  Start with: sudo systemctl start gatekeeper"
        fi
    else
        print_msg "$YELLOW" "⚠ systemd not available (check manually)"
    fi
}

# Check 6: Connectivity
check_connectivity() {
    print_section "6. Connectivity Tests"

    # Check if server can reach internet
    if ping -c 1 -W 2 8.8.8.8 &> /dev/null; then
        print_msg "$GREEN" "✓ Server can reach internet (ping 8.8.8.8)"
    else
        print_msg "$RED" "✗ Server cannot reach internet!"
    fi

    # Check DNS
    if ping -c 1 -W 2 google.com &> /dev/null; then
        print_msg "$GREEN" "✓ DNS resolution works"
    else
        print_msg "$YELLOW" "⚠ DNS resolution may be broken"
    fi
}

# Provide recommendations
print_recommendations() {
    print_section "Recommendations"

    echo "Common fixes for VPN connectivity issues:"
    echo ""
    echo "1. Check server.toml configuration:"
    echo "   external_interface should be your internet-facing interface (NOT tun0)"
    echo "   Run: ip route show default"
    echo ""
    echo "2. Ensure IP forwarding is enabled:"
    echo "   sudo sysctl -w net.ipv4.ip_forward=1"
    echo ""
    echo "3. Setup NAT rules (replace ens3 with your interface):"
    echo "   sudo iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o ens3 -j MASQUERADE"
    echo "   sudo iptables -A FORWARD -i tun+ -j ACCEPT"
    echo "   sudo iptables -A FORWARD -o tun+ -j ACCEPT"
    echo ""
    echo "4. Restart the server after config changes:"
    echo "   sudo systemctl restart gatekeeper"
    echo ""
}

# Print summary
print_summary() {
    print_section "Diagnostic Summary"

    ISSUES=0

    if [[ ! -f "$SERVER_CONFIG" ]]; then
        ((ISSUES++))
        print_msg "$RED" "• Config file missing"
    fi

    if ! grep -q "external_interface" "$SERVER_CONFIG" 2>/dev/null; then
        ((ISSUES++))
        print_msg "$RED" "• external_interface not configured"
    fi

    if [[ -f /proc/sys/net/ipv4/ip_forward ]] && [[ $(cat /proc/sys/net/ipv4/ip_forward) != "1" ]]; then
        ((ISSUES++))
        print_msg "$RED" "• IP forwarding disabled"
    fi

    if command -v iptables &> /dev/null && ! iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "MASQUERADE"; then
        ((ISSUES++))
        print_msg "$RED" "• NAT not configured"
    fi

    echo ""
    if [[ $ISSUES -eq 0 ]]; then
        print_msg "$GREEN" "✓ No critical issues found!"
    else
        print_msg "$YELLOW" "⚠ Found $ISSUES issue(s) - see recommendations above"
    fi
}

# Main
main() {
    print_msg "$BLUE" "╔════════════════════════════════════════╗"
    print_msg "$BLUE" "║   GatekeeperVPN Diagnostic Tool       ║"
    print_msg "$BLUE" "╚════════════════════════════════════════╝"

    check_root
    check_config || true
    check_interfaces || true
    check_ip_forwarding || true
    check_nat || true
    check_service || true
    check_connectivity || true
    print_recommendations
    print_summary

    echo ""
}

main "$@"
