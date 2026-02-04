#!/bin/bash
# Fix portable AP setup issues on Armbian

echo "=== Fixing Portable AP Setup Issues ==="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Please run this script as root (sudo)${NC}"
        exit 1
    fi
}

# Function to stop conflicting services
stop_conflicting_services() {
    echo -e "${YELLOW}Stopping conflicting services...${NC}"
    
    # Stop NetworkManager
    systemctl stop NetworkManager 2>/dev/null
    systemctl disable NetworkManager 2>/dev/null
    
    # Stop hostapd
    systemctl stop hostapd 2>/dev/null
    systemctl disable hostapd 2>/dev/null
    
    # Stop dnsmasq
    systemctl stop dnsmasq 2>/dev/null
    systemctl disable dnsmasq 2>/dev/null
    
    # Kill any existing hostapd processes
    pkill -f hostapd 2>/dev/null
    
    echo -e "${GREEN}Services stopped${NC}"
}

# Function to reset network interface
reset_interface() {
    local iface="$1"
    
    echo -e "${YELLOW}Resetting interface $iface...${NC}"
    
    # Bring interface down
    ip link set "$iface" down 2>/dev/null
    
    # Clear any existing IP addresses
    ip addr flush dev "$iface" 2>/dev/null
    
    # Bring interface up
    ip link set "$iface" up 2>/dev/null
    
    # Wait for interface to be ready
    sleep 2
    
    echo -e "${GREEN}Interface $iface reset${NC}"
}

# Function to setup hostapd config
setup_hostapd_config() {
    local iface="$1"
    local ssid="$2"
    local channel="$3"
    
    echo -e "${YELLOW}Creating hostapd config...${NC}"
    
    # Create hostapd.conf
    cat > /tmp/hostapd.conf << EOF
interface=$iface
driver=nl80211
ssid=$ssid
hw_mode=g
channel=$channel
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=cyberpwn123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF
    
    echo -e "${GREEN}Hostapd config created at /tmp/hostapd.conf${NC}"
}

# Function to setup dnsmasq config
setup_dnsmasq_config() {
    local iface="$1"
    
    echo -e "${YELLOW}Creating dnsmasq config...${NC}"
    
    # Create dnsmasq.conf
    cat > /tmp/dnsmasq.conf << EOF
interface=$iface
dhcp-range=192.168.4.100,192.168.4.200,12h
dhcp-option=3,192.168.4.1
dhcp-option=6,192.168.4.1
server=8.8.8.8
domain-needed
bogus-priv
EOF
    
    echo -e "${GREEN}Dnsmasq config created at /tmp/dnsmasq.conf${NC}"
}

# Function to start AP
start_ap() {
    local iface="$1"
    
    echo -e "${YELLOW}Starting Access Point...${NC}"
    
    # Assign IP to interface
    ip addr add 192.168.4.1/24 dev "$iface" 2>/dev/null
    
    # Start dnsmasq
    dnsmasq -C /tmp/dnsmasq.conf --interface="$iface" 2>/dev/null &
    DNAMASQ_PID=$!
    
    # Start hostapd
    hostapd /tmp/hostapd.conf 2>/dev/null &
    HOSTAPD_PID=$!
    
    # Wait a bit
    sleep 3
    
    # Check if processes are running
    if kill -0 $DNAMASQ_PID 2>/dev/null && kill -0 $HOSTAPD_PID 2>/dev/null; then
        echo -e "${GREEN}Access Point started successfully!${NC}"
        echo -e "${GREEN}SSID: CyberPWN-AP${NC}"
        echo -e "${GREEN}Password: cyberpwn123${NC}"
        echo -e "${GREEN}IP: 192.168.4.1${NC}"
        echo ""
        echo -e "${YELLOW}To stop AP: kill $HOSTAPD_PID $DNAMASQ_PID${NC}"
        return 0
    else
        echo -e "${RED}Failed to start Access Point${NC}"
        return 1
    fi
}

# Main execution
check_root

# Find wireless interface
WIFI_IFACE=$(iwconfig 2>/dev/null | grep -E "^[a-zA-Z0-9]+" | awk '{print $1}' | head -1)

if [ -z "$WIFI_IFACE" ]; then
    echo -e "${RED}No wireless interface found${NC}"
    exit 1
fi

echo -e "${GREEN}Found wireless interface: $WIFI_IFACE${NC}"

# Stop conflicting services
stop_conflicting_services

# Reset interface
reset_interface "$WIFI_IFACE"

# Setup configs
setup_hostapd_config "$WIFI_IFACE" "CyberPWN-AP" "6"
setup_dnsmasq_config "$WIFI_IFACE"

# Start AP
start_ap "$WIFI_IFACE"

echo ""
echo "=== AP Setup Complete ==="
