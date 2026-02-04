#!/bin/bash
# Ultra-simple AP setup without dnsmasq - uses built-in DHCP

echo "=== Simple AP Setup (No dnsmasq) ==="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
SSID="PWN"
PASSWORD="pwn12345"
AP_IFACE="wlan0"
AP_IP="192.168.4.1"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Run as root: sudo $0${NC}"
    exit 1
fi

# Stop everything
echo -e "${YELLOW}Stopping services...${NC}"
pkill hostapd 2>/dev/null
pkill dnsmasq 2>/dev/null
pkill create_ap 2>/dev/null

# Reset interface
echo -e "${YELLOW}Resetting $AP_IFACE...${NC}"
nmcli dev set "$AP_IFACE" managed no 2>/dev/null || true
ip link set "$AP_IFACE" down 2>/dev/null
sleep 1
ip addr flush "$AP_IFACE" 2>/dev/null
ip link set "$AP_IFACE" up 2>/dev/null
sleep 2

# Set IP
echo -e "${YELLOW}Setting IP $AP_IP...${NC}"
ip addr add "$AP_IP/24" dev "$AP_IFACE"

# Method 1: Try create_ap with built-in DHCP
if command -v create_ap >/dev/null 2>&1; then
    echo -e "${GREEN}Trying create_ap with built-in DHCP...${NC}"
    
    create_ap --daemon \
        --pidfile /tmp/create_ap.pid \
        --freq-band 2.4 \
        --channel 6 \
        --max-clients 1 \
        --wifi-pwd "$PASSWORD" \
        "$AP_IFACE" "" "$SSID"
    
    sleep 3
    if pgrep create_ap >/dev/null; then
        echo -e "${GREEN}SUCCESS: create_ap running${NC}"
        echo -e "${GREEN}SSID: $SSID${NC}"
        echo -e "${GREEN}Password: $PASSWORD${NC}"
        echo -e "${GREEN}AP IP: $AP_IP${NC}"
        echo -e "${GREEN}Website: http://$AP_IP:5000${NC}"
        echo -e "${GREEN}Client should get IP automatically${NC}"
        exit 0
    else
        echo -e "${RED}create_ap failed${NC}"
    fi
fi

# Method 2: hostapd + udhcpd (alternative DHCP)
echo -e "${YELLOW}Trying hostapd + udhcpd...${NC}"

# Create hostapd config
cat > /tmp/hostapd.conf << EOF
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

# Start hostapd
hostapd -B -P /tmp/hostapd.pid /tmp/hostapd.conf 2>/dev/null
sleep 2

if pgrep hostapd >/dev/null; then
    echo -e "${GREEN}hostapd started${NC}"
    
    # Try udhcpd if available
    if command -v udhcpd >/dev/null 2>&1; then
        echo -e "${GREEN}Starting udhcpd...${NC}"
        
        # Create udhcpd config
        cat > /tmp/udhcpd.conf << EOF
start     192.168.4.100
end       192.168.4.100
interface $AP_IFACE
opt dns   192.168.4.1
opt router 192.168.4.1
EOF
        
        # Start udhcpd
        udhcpd /tmp/udhcpd.conf 2>/dev/null
        
        sleep 2
        if pgrep udhcpd >/dev/null; then
            echo -e "${GREEN}udhcpd started${NC}"
            echo -e "${GREEN}SUCCESS: AP with DHCP running${NC}"
        else
            echo -e "${YELLOW}udhcpd failed, AP running without DHCP${NC}"
        fi
    else
        echo -e "${YELLOW}udhcpd not available, AP running without DHCP${NC}"
    fi
    
    echo -e "${GREEN}AP Setup Complete${NC}"
    echo -e "${GREEN}SSID: $SSID${NC}"
    echo -e "${GREEN}Password: $PASSWORD${NC}"
    echo -e "${GREEN}AP IP: $AP_IP${NC}"
    echo -e "${GREEN}Website: http://$AP_IP:5000${NC}"
    echo ""
    echo -e "${YELLOW}CLIENT SETUP (if no DHCP):${NC}"
    echo -e "${YELLOW}Static IP: 192.168.4.100${NC}"
    echo -e "${YELLOW}Gateway: 192.168.4.1${NC}"
    echo -e "${YELLOW}DNS: 192.168.4.1${NC}"
    
else
    echo -e "${RED}hostapd failed to start${NC}"
    echo -e "${YELLOW}Manual setup instructions:${NC}"
    echo "1. Connect to SSID: $SSID"
    echo "2. Set static IP: 192.168.4.100"
    echo "3. Set gateway: 192.168.4.1"
    echo "4. Set DNS: 192.168.4.1"
    echo "5. Go to: http://192.168.4.1:5000"
    exit 1
fi
