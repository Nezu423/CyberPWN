#!/bin/bash
# Ultra-simple AP setup for BTT CB1

echo "=== Simple AP Setup ==="
echo ""

# Configuration
AP_IFACE="wlan0"
SSID="PWN"
AP_IP="192.168.4.1"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo $0"
    exit 1
fi

# Stop everything
echo "Stopping services..."
pkill hostapd 2>/dev/null
pkill dnsmasq 2>/dev/null

# Reset interface
echo "Resetting $AP_IFACE..."
ip link set $AP_IFACE down 2>/dev/null
ip addr flush $AP_IFACE 2>/dev/null
ip link set $AP_IFACE up 2>/dev/null
sleep 2

# Set IP
echo "Setting IP $AP_IP..."
ip addr add $AP_IP/24 dev $AP_IFACE

# Create absolute minimal config
echo "Creating minimal config..."
cat > /tmp/simple.conf << EOF
interface=$AP_IFACE
driver=nl80211
ssid=$SSID
channel=6
hw_mode=g
EOF

# Start hostapd
echo "Starting hostapd..."
hostapd /tmp/simple.conf &

# Wait and check
sleep 5
if pgrep hostapd >/dev/null; then
    echo "SUCCESS: AP running"
    echo "SSID: $SSID (no password)"
    echo "IP: $AP_IP"
    echo "Connect and go to http://$AP_IP:5000"
else
    echo "FAILED: hostapd not running"
    echo "Try: iwconfig $AP_IFACE"
    exit 1
fi
