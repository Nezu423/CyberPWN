#!/bin/bash
# Alternative AP setup using create_ap (more reliable for BTT CB1)

echo "=== Alternative AP Setup (create_ap) ==="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
SSID="PWN"
PASSWORD="pwn12345"  # 8+ characters for WPA2
AP_IFACE="wlan0"
AP_IP="192.168.4.1"
INTERNET_IFACE=""  # No internet sharing

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run this script as root (sudo)${NC}"
    exit 1
fi

# Check if interface exists
if ! iwconfig "$AP_IFACE" >/dev/null 2>&1; then
    echo -e "${RED}ERROR: AP interface $AP_IFACE not found${NC}"
    exit 1
fi

# Stop existing APs
echo -e "${YELLOW}Stopping existing APs...${NC}"
pkill -f hostapd 2>/dev/null
pkill -f dnsmasq 2>/dev/null
pkill -f create_ap 2>/dev/null

# Reset interface
echo -e "${YELLOW}Resetting $AP_IFACE...${NC}"
nmcli dev set "$AP_IFACE" managed no 2>/dev/null || true
ip link set "$AP_IFACE" down 2>/dev/null
sleep 1
ip addr flush dev "$AP_IFACE" 2>/dev/null
ip link set "$AP_IFACE" up 2>/dev/null
sleep 2

# Try method 1: create_ap (if available)
if command -v create_ap >/dev/null 2>&1; then
    echo -e "${GREEN}Using create_ap...${NC}"
    
    # Start create_ap with password and single client limit
    create_ap --daemon --pidfile /tmp/create_ap.pid \
        --hostapd-log /tmp/hostapd.log \
        --freq-band 2.4 \
        --channel 6 \
        --max-clients 1 \
        --wifi-pwd "$PASSWORD" \
        "$AP_IFACE" "$INTERNET_IFACE" "$SSID"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}AP started with create_ap${NC}"
        echo -e "${GREEN}SSID: $SSID${NC}"
        echo -e "${GREEN}Password: $PASSWORD${NC}"
        echo -e "${GREEN}IP: $AP_IP${NC}"
        echo -e "${GREEN}Website: http://$AP_IP:5000${NC}"
        exit 0
    else
        echo -e "${RED}create_ap failed${NC}"
    fi
fi

# Method 2: Simple hostapd with minimal config
echo -e "${YELLOW}Trying minimal hostapd...${NC}"

# Create minimal config with password
cat > /tmp/minimal_ap.conf << EOF
interface=$AP_IFACE
driver=nl80211
ssid=$SSID
channel=6
hw_mode=g
wpa=2
wpa_passphrase=$PASSWORD
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

# Test if interface supports AP mode
echo -e "${YELLOW}Testing interface capabilities...${NC}"
if iw phy "$AP_IFACE" info 2>/dev/null | grep -q "AP"; then
    echo -e "${GREEN}Interface supports AP mode${NC}"
else
    echo -e "${RED}Interface may not support AP mode${NC}"
    echo -e "${YELLOW}Trying anyway...${NC}"
fi

# Try to start hostapd
echo -e "${YELLOW}Starting hostapd...${NC}"
hostapd -B -P /tmp/hostapd.pid /tmp/minimal_ap.conf 2>/dev/null

# Check if it started
sleep 3
if pgrep -f "hostapd.*minimal_ap.conf" >/dev/null; then
    echo -e "${GREEN}Basic AP started with WPA2${NC}"
    
    # Set IP address
    ip addr add "$AP_IP/24" dev "$AP_IFACE" 2>/dev/null
    
    # Start dnsmasq with proper DHCP
    echo -e "${YELLOW}Starting DHCP server...${NC}"
    dnsmasq --interface="$AP_IFACE" \
        --bind-interfaces \
        --dhcp-range=192.168.4.100,192.168.4.100,255.255.255.0,12h \
        --dhcp-option=3,$AP_IP \
        --dhcp-option=6,$AP_IP \
        --address=/#/$AP_IP \
        --no-resolv \
        --server=8.8.8.8 \
        --domain-needed \
        --bogus-priv \
        --daemon 2>/dev/null
    
    # Verify dnsmasq is running
    sleep 2
    if pgrep dnsmasq >/dev/null; then
        echo -e "${GREEN}DHCP server started${NC}"
    else
        echo -e "${YELLOW}DHCP server may not be running${NC}"
    fi
    
    echo -e "${GREEN}AP Setup Complete${NC}"
    echo -e "${GREEN}SSID: $SSID${NC}"
    echo -e "${GREEN}Password: $PASSWORD${NC}"
    echo -e "${GREEN}IP: $AP_IP${NC}"
    echo -e "${GREEN}Website: http://$AP_IP:5000${NC}"
    echo -e "${GREEN}Client should get IP: 192.168.4.100${NC}"
else
    echo -e "${RED}All methods failed${NC}"
    echo -e "${YELLOW}Debug info:${NC}"
    echo "Interface status:"
    iwconfig "$AP_IFACE" 2>/dev/null || echo "  No interface info"
    echo ""
    echo "Available WiFi interfaces:"
    iwconfig 2>/dev/null | grep -E "^[a-zA-Z]" || echo "  No WiFi interfaces"
    exit 1
fi
