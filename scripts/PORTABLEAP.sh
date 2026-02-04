#!/bin/bash
# Start Evil Twin AP: release wlan0 from NM, set 192.168.4.1, hostapd + dnsmasq.
# Usage: sudo ./start_evil_twin_ap.sh <SSID>
# When AP is up, open http://192.168.4.1:5000 from any device connected to the AP.

set -e
SSID="CPWN"
AP_PASS="062823"
# Project root (parent of scripts/)
BASE="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$BASE/evil_twin.conf"
IFACE="${AP_IFACE:-wlan0}"
AP_IP="192.168.4.1"
AP_NET="192.168.4.0/24"
DHCP_START="192.168.4.10"
DHCP_END="192.168.4.50"
DNSMASQ_CONF="/tmp/cyberpwn_dnsmasq_${IFACE}.conf"
HOSTAPD_PID="/tmp/cyberpwn_hostapd.pid"

# 1) Write hostapd config
cat > "$CONFIG" << EOF
# Evil Twin AP - $SSID
interface=$IFACE
driver=nl80211
ssid=$SSID
channel=6
hw_mode=g
EOF

cat >> "$CONFIG" << EOF
wpa=2
wpa_passphrase=$AP_PASS
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

# 2) Release interface from NetworkManager
nmcli dev set "$IFACE" managed no 2>/dev/null || true
sleep 1
ip link set "$IFACE" down
ip addr flush dev "$IFACE"
ip addr add "$AP_IP/24" dev "$IFACE"
ip link set "$IFACE" up
sleep 1

# 3) dnsmasq for DHCP (clients get 192.168.4.x, gateway 192.168.4.1)
cat > "$DNSMASQ_CONF" << EOF
interface=$IFACE
bind-interfaces
dhcp-range=${DHCP_START},${DHCP_END},255.255.255.0,12h
dhcp-option=3,$AP_IP
EOF
pkill -f "dnsmasq.*$DNSMASQ_CONF" 2>/dev/null || true
dnsmasq -C "$DNSMASQ_CONF" -q 2>/dev/null &

# 4) hostapd in background (no -d)
pkill -f "hostapd.*$CONFIG" 2>/dev/null || true
sleep 1
hostapd -B -P "$HOSTAPD_PID" "$CONFIG" 2>/dev/null || hostapd -B "$CONFIG"

echo "AP up: SSID=$SSID (WPA2), open http://${AP_IP}:5000"
