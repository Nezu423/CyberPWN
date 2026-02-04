#!/bin/bash
# Quick fix for portable AP interface errors

echo "=== Quick AP Interface Fix ==="
echo ""

# Find wireless interface
WIFI_IFACE=$(iwconfig 2>/dev/null | grep -E "^[a-zA-Z0-9]+" | awk '{print $1}' | head -1)

if [ -z "$WIFI_IFACE" ]; then
    echo "No wireless interface found"
    exit 1
fi

echo "Found wireless interface: $WIFI_IFACE"

# Stop conflicting services
echo "Stopping NetworkManager..."
systemctl stop NetworkManager 2>/dev/null
systemctl disable NetworkManager 2>/dev/null

# Kill existing processes
echo "Killing existing hostapd/dnsmasq..."
pkill -f hostapd 2>/dev/null
pkill -f dnsmasq 2>/dev/null

# Reset interface
echo "Resetting interface $WIFI_IFACE..."
ip link set "$WIFI_IFACE" down
ip addr flush dev "$WIFI_IFACE"
ip link set "$WIFI_IFACE" up
sleep 2

# Create minimal hostapd config
echo "Creating minimal hostapd config..."
cat > /tmp/hostapd_minimal.conf << EOF
interface=$WIFI_IFACE
driver=nl80211
ssid=TestAP
hw_mode=g
channel=6
EOF

# Test hostapd
echo "Testing hostapd..."
if timeout 5 hostapd -dd /tmp/hostapd_minimal.conf 2>&1 | grep -q "interface setup"; then
    echo "SUCCESS: Interface setup works"
else
    echo "FAILED: Interface setup failed"
    echo "Trying alternative driver..."
    
    # Try with different driver
    cat > /tmp/hostapd_minimal.conf << EOF
interface=$WIFI_IFACE
driver=rtl871xdrv
ssid=TestAP
hw_mode=g
channel=6
EOF
    
    if timeout 5 hostapd -dd /tmp/hostapd_minimal.conf 2>&1 | grep -q "interface setup"; then
        echo "SUCCESS: Interface setup works with rtl871xdrv"
    else
        echo "FAILED: Interface setup failed with all drivers"
        exit 1
    fi
fi

echo ""
echo "Interface fix complete. You can now try setting up your AP."
