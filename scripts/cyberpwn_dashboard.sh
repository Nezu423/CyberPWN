#!/bin/bash
# cyberpwn_dashboard.sh - Colorful Armbian login dashboard

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# System usage
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
MEM_USAGE=$(free -m | awk '/Mem:/ { printf("%s/%s MB (%.2f%%)", $3, $2, $3/$2 * 100.0) }')
DISK_USAGE=$(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')

# CPU temp
if [ -f /etc/armbianmonitor/datasources/soctemp ]; then
  CPU_TEMP=$(cat /etc/armbianmonitor/datasources/soctemp)
  CPU_TEMP=$(awk "BEGIN {printf \"%.1f\", $CPU_TEMP/1000}")
else
  CPU_TEMP=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null)
  CPU_TEMP=$(awk "BEGIN {printf \"%.1f\", $CPU_TEMP/1000}")
fi

# Service status
SERVICE="cyberpwn.service"
SERVICE_STATUS=$(systemctl is-active $SERVICE)
if [ "$SERVICE_STATUS" = "active" ]; then
  SERVICE_STATUS_MSG="${GREEN}ACTIVE${NC}"
else
  SERVICE_STATUS_MSG="${RED}INACTIVE${NC}"
fi

# WiFi status
WIFI_IF=$(iw dev 2>/dev/null | awk '/Interface/ {print $2; exit}')
if [ -n "$WIFI_IF" ]; then
  WIFI_SSID=$(iwgetid -r)
  WIFI_IP=$(ip addr show $WIFI_IF | awk '/inet / {print $2}' | cut -d/ -f1)
  WIFI_SIGNAL=$(iwconfig $WIFI_IF 2>/dev/null | awk -F= '/Signal level/ {print $3}' | awk '{print $1}')
else
  WIFI_SSID="N/A"
  WIFI_IP="N/A"
  WIFI_SIGNAL="N/A"
fi

# Print dashboard
echo -e "${CYAN}========= CyberPWN Armbian Dashboard =========${NC}"
echo -e "${YELLOW}CPU Usage:   ${NC}$CPU_USAGE%"
echo -e "${YELLOW}RAM Usage:   ${NC}$MEM_USAGE"
echo -e "${YELLOW}Disk Usage:  ${NC}$DISK_USAGE"
echo -e "${YELLOW}CPU Temp:    ${NC}$CPU_TEMP°C"
echo -e "${MAGENTA}WiFi:        ${NC}SSID: $WIFI_SSID | IP: $WIFI_IP | Signal: $WIFI_SIGNAL dBm"
echo -e "${BLUE}Service:     ${NC}$SERVICE_STATUS_MSG"
echo -e "${CYAN}---------------------------------------------${NC}"
echo -e "${GREEN}To start service:   ${NC}sudo systemctl start $SERVICE"
echo -e "${RED}To stop service:    ${NC}sudo systemctl stop $SERVICE"
echo -e "${YELLOW}To disable service: ${NC}sudo systemctl disable $SERVICE"
echo -e "${CYAN}=============================================${NC}\n"
clear
# Rotating Aphex Twin ASCII logo (simple 4-frame animation)
logo1="   _   _\n  / \\ / \\ \n |   V   |\n |  / \\  |\n  \\_/ \\_/ "
logo2="   _   _\n  \\ / \\ /\n |   V   |\n |  \\ /  |\n  /_\\ /_\\ "
logo3="   _   _\n  / \\ / \\ \n |   ^   |\n |  \\ /  |\n  /_\\ /_\\ "
logo4="   _   _\n  \\ / \\ /\n |   ^   |\n |  / \\  |\n  \\_/ \\_/ "
logos=($logo1 "$logo2" "$logo3" "$logo4")

# Animate logo
for i in {0..3}; do
  clear
  echo -e "${MAGENTA}${logos[$i]}${NC}"
  sleep 0.1
done
clear
echo -e "${MAGENTA}${logos[0]}${NC}"

echo -e "${CYAN}========= CyberPWN Armbian Dashboard =========${NC}"
echo -e "${YELLOW}CPU Usage:   ${NC}$CPU_USAGE%"
echo -e "${YELLOW}RAM Usage:   ${NC}$MEM_USAGE"
echo -e "${YELLOW}Disk Usage:  ${NC}$DISK_USAGE"
echo -e "${YELLOW}CPU Temp:    ${NC}$CPU_TEMP°C"
echo -e "${MAGENTA}WiFi:        ${NC}SSID: $WIFI_SSID | IP: $WIFI_IP | Signal: $WIFI_SIGNAL dBm"
echo -e "${BLUE}Service:     ${NC}$SERVICE_STATUS_MSG"
echo -e "${CYAN}---------------------------------------------${NC}"

# OSC 8 hyperlinks for supported terminals (will show as clickable links in some terminals)
OSC8_START="\033]8;;"
OSC8_END="\033]8;;\033\\"
echo -e "${GREEN}To start service:   ${NC}${OSC8_START}command:sudo systemctl start $SERVICE${OSC8_END}sudo systemctl start $SERVICE${OSC8_START}${OSC8_END}"
echo -e "${RED}To stop service:    ${NC}${OSC8_START}command:sudo systemctl stop $SERVICE${OSC8_END}sudo systemctl stop $SERVICE${OSC8_START}${OSC8_END}"
echo -e "${YELLOW}To disable service: ${NC}${OSC8_START}command:sudo systemctl disable $SERVICE${OSC8_END}sudo systemctl disable $SERVICE${OSC8_START}${OSC8_END}"
echo -e "${CYAN}=============================================${NC}\n"
