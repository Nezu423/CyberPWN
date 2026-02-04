#!/bin/bash
# Clear APs and connect to WiFi network

echo "=== Clear APs & Connect to WiFi ==="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# WiFi credentials
SSID="ATTKESWnbh"
PASSWORD="oiseeu812"

# Function to start NetworkManager if needed
start_networkmanager() {
    if ! systemctl is-active NetworkManager >/dev/null 2>&1; then
        echo -e "${YELLOW}Starting NetworkManager...${NC}"
        systemctl start NetworkManager 2>/dev/null
        sleep 3
        if systemctl is-active NetworkManager >/dev/null 2>&1; then
            echo -e "${GREEN}NetworkManager started${NC}"
        else
            echo -e "${RED}Failed to start NetworkManager${NC}"
            return 1
        fi
    fi
    return 0
}

# Function to stop APs
stop_aps() {
    echo -e "${YELLOW}Stopping Access Points...${NC}"
    
    # Kill hostapd processes
    pkill -f hostapd 2>/dev/null
    echo "  - hostapd stopped"
    
    # Kill dnsmasq processes
    pkill -f dnsmasq 2>/dev/null
    echo "  - dnsmasq stopped"
    
    # Reset wlan0 (AP interface)
    if iwconfig wlan0 >/dev/null 2>&1; then
        ip link set wlan0 down 2>/dev/null
        ip addr flush dev wlan0 2>/dev/null
        nmcli dev set wlan0 managed yes 2>/dev/null || true
        ip link set wlan0 up 2>/dev/null
        echo "  - wlan0 (AP) reset"
    fi
    
    # Reset wlan1 (scan interface)
    if iwconfig wlan1 >/dev/null 2>&1; then
        ip link set wlan1 down 2>/dev/null
        ip addr flush dev wlan1 2>/dev/null
        nmcli dev set wlan1 managed yes 2>/dev/null || true
        ip link set wlan1 up 2>/dev/null
        echo "  - wlan1 (scan) reset"
    fi
    
    sleep 2
    echo -e "${GREEN}APs cleared${NC}"
}

# Function to connect to WiFi
connect_wifi() {
    echo -e "${YELLOW}Connecting to WiFi: $SSID${NC}"
    
    # Try to start NetworkManager first
    if ! start_networkmanager; then
        echo -e "${RED}Cannot connect without NetworkManager${NC}"
        return 1
    fi
    
    # Disconnect first
    nmcli device wifi disconnect 2>/dev/null
    
    # Connect to specified network on wlan1
    if nmcli device wifi connect "$SSID" password "$PASSWORD" ifname wlan1; then
        echo -e "${GREEN}Connected to $SSID${NC}"
        
        # Get IP address
        IP=$(nmcli -t -4 device show wlan1 | grep IP4.ADDRESS | head -1 | cut -d: -f2)
        if [ -n "$IP" ]; then
            echo -e "${GREEN}IP Address: $IP${NC}"
        fi
        
        return 0
    else
        echo -e "${RED}Failed to connect to $SSID${NC}"
        return 1
    fi
}

# Function to show status
show_status() {
    echo ""
    echo -e "${YELLOW}=== WiFi Status ===${NC}"
    
    # Show wlan0 status
    echo -e "${GREEN}wlan0 (AP Interface):${NC}"
    iwconfig wlan0 2>/dev/null | grep -E "(Mode|ESSID|Frequency)" || echo "  Not available"
    echo ""
    
    # Show wlan1 status
    echo -e "${GREEN}wlan1 (Scan Interface):${NC}"
    iwconfig wlan1 2>/dev/null | grep -E "(Mode|ESSID|Frequency)" || echo "  Not available"
    
    # Show IP addresses
    echo ""
    echo -e "${GREEN}IP Addresses:${NC}"
    ip addr show wlan0 2>/dev/null | grep "inet " | awk '{print "  wlan0: " $2}' || echo "  wlan0: No IP"
    ip addr show wlan1 2>/dev/null | grep "inet " | awk '{print "  wlan1: " $2}' || echo "  wlan1: No IP"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run this script as root (sudo)${NC}"
    exit 1
fi

# Main execution
stop_aps

if connect_wifi; then
    show_status
    echo ""
    echo -e "${GREEN}Success! You can now:${NC}"
    echo "  - Use wlan1 for WiFi operations"
    echo "  - Start AP on wlan0 when needed"
    echo "  - Access the web interface"
else
    echo ""
    echo -e "${RED}Connection failed. Check:${NC}"
    echo "  - WiFi network name and password"
    echo "  - Network availability"
    echo "  - Interface status"
fi
