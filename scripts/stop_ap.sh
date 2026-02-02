#!/bin/bash
# Stop Evil Twin AP: kill hostapd and dnsmasq, give wlan0 back to NetworkManager.
# Usage: sudo ./stop_ap.sh

IFACE="${AP_IFACE:-wlan0}"
DNSMASQ_CONF="/tmp/cyberpwn_dnsmasq_${IFACE}.conf"
HOSTAPD_PID="/tmp/cyberpwn_hostapd.pid"

pkill -f "hostapd.*evil_twin.conf" 2>/dev/null || true
[ -f "$HOSTAPD_PID" ] && kill "$(cat "$HOSTAPD_PID")" 2>/dev/null || true
rm -f "$HOSTAPD_PID"
pkill -f "dnsmasq.*$DNSMASQ_CONF" 2>/dev/null || true
rm -f "$DNSMASQ_CONF"

ip link set "$IFACE" down 2>/dev/null || true
ip addr flush dev "$IFACE" 2>/dev/null || true
nmcli dev set "$IFACE" managed yes 2>/dev/null || true
ip link set "$IFACE" up 2>/dev/null || true

echo "AP stopped; $IFACE returned to NetworkManager."
