#!/bin/bash
# cyberpwn_dashboard.sh - CyberPWN Server Monitoring Dashboard for Linux/Armbian
# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Server configuration
SERVER_HOST="192.168.4.1"
SERVER_PORT="5000"
SERVER_URL="http://${SERVER_HOST}:${SERVER_PORT}"

# Log file for API calls
LOG_FILE="/tmp/cyberpwn_api.log"
API_COUNT_FILE="/tmp/cyberpwn_api_count.txt"

# Initialize counters
echo "0" > "$API_COUNT_FILE"
echo "0" > "/tmp/error_count.txt"

# Function to display header
display_header() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    CYBERPWN SERVER MONITOR                    ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to get server info
get_server_info() {
    local server_url=$(get_server_url)
    local response=$(curl -s -m 5 "$server_url" 2>/dev/null)
    if [ $? -eq 0 ] && [ "$response" != "" ]; then
        echo "$response" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(f'Bound IP: {data.get(\"primary_ip\", \"Unknown\")}')
    print(f'Hostname: {data.get(\"hostname\", \"Unknown\")}')
    print(f'Port: {data.get(\"port\", \"Unknown\")}')
    if data.get('all_ips'):
        print(f'All IPs: {\", \".join(data[\"all_ips\"])}')
    print(f'Binding Status: {data.get(\"binding_status\", \"Unknown\")}')
    print(f'Expected Primary: {data.get(\"expected_primary\", \"Unknown\")}')
except Exception as e:
    print(f'Parse Error: {e}')
"
    else
        echo -e "${RED}Server Status: OFFLINE${NC}"
        echo "Bound IP: Unknown"
        echo "Hostname: Unknown"
        echo "Port: 5000"
        echo "Binding Status: Unknown"
    fi
}

# Function to check if server is running
check_server_status() {
    # Try multiple methods to check if server is running
    if curl -s -m 2 "$SERVER_URL/api/server/info" >/dev/null 2>&1; then
        echo -e "${GREEN}RUNNING${NC}"
        return 0
    elif curl -s -m 2 "http://localhost:5000/api/server/info" >/dev/null 2>&1; then
        echo -e "${GREEN}RUNNING${NC}"
        return 0
    elif curl -s -m 2 "http://127.0.0.1:5000/api/server/info" >/dev/null 2>&1; then
        echo -e "${GREEN}RUNNING${NC}"
        return 0
    else
        echo -e "${RED}OFFLINE${NC}"
        return 1
    fi
}

# Function to get actual server URL
get_server_url() {
    # Try different URLs to find the running server
    local urls=(
        "$SERVER_URL/api/server/info"
        "http://localhost:5000/api/server/info"
        "http://127.0.0.1:5000/api/server/info"
    )
    
    for url in "${urls[@]}"; do
        if curl -s -m 2 "$url" >/dev/null 2>&1; then
            echo "${url}"
            return 0
        fi
    done
    
    echo "$SERVER_URL/api/server/info"
    return 1
}

# Function to monitor API calls
monitor_api_calls() {
    local log_file="$1"
    local count_file="$2"
    
    # Check if log file exists and has content
    if [ -f "$log_file" ] && [ -s "$log_file" ]; then
        local total_calls=$(wc -l < "$log_file" 2>/dev/null || echo "0")
        local errors=$(grep -c "HTTP [45][0-9][0-9]" "$log_file" 2>/dev/null || echo "0")
        local success=$((total_calls - errors))
        
        echo "$total_calls" > "$count_file"
        echo "$errors" > "/tmp/error_count.txt"
        
        if [ "$total_calls" -gt 0 ]; then
            local success_rate=$((success * 100 / total_calls))
            echo "Total: $total_calls | Success: $success_rate% | Errors: $errors"
        else
            echo "Total: 0 | Success: 100% | Errors: 0"
        fi
    else
        echo "Total: 0 | Success: 100% | Errors: 0"
    fi
}

# Function to show recent API activity
show_recent_api_calls() {
    local log_file="$1"
    if [ -f "$log_file" ] && [ -s "$log_file" ]; then
        echo "=== Recent API Calls (Last 10) ==="
        tail -10 "$log_file" | while IFS= read -r line; do
            local timestamp=$(echo "$line" | grep -o '\[.*\]' | head -1)
            local method=$(echo "$line" | grep -o '"[A-Z]*"' | head -1 | tr -d '"')
            local path=$(echo "$line" | grep -o '/api/[^"]*' | head -1)
            local status=$(echo "$line" | grep -o 'HTTP [0-9][0-9][0-9]' | head -1)
            
            if [ "$status" != "" ]; then
                if [ "${status:4:1}" = "2" ]; then
                    status_color="${GREEN} "
                else
                    status_color="${RED} "
                fi
            else
                status_color="${YELLOW} "
            fi
            
            echo -e "${timestamp} ${method} ${path} ${status_color}${status}${NC} "
        done
    else
        echo "No API activity yet"
    fi
}

# Function to show system stats
show_system_stats() {
    echo "=== System Statistics ==="
    
    # CPU usage
    if command -v top >/dev/null 2>&1; then
        local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' | sed 's/%,//g')
        echo -e "CPU Usage: ${YELLOW}${cpu_usage}%${NC}"
    fi
    
    # Memory usage
    if command -v free >/dev/null 2>&1; then
        local mem_info=$(free -m | awk '/Mem:/ {printf("%.1f%%", $3/$2 * 100.0)}')
        echo -e "Memory: ${YELLOW}${mem_info}${NC}"
    fi
    
    # Disk usage
    if command -v df >/dev/null 2>&1; then
        local disk_info=$(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')
        echo -e "Disk: ${YELLOW}${disk_info}${NC}"
    fi
    
    # Network interfaces
    if command -v ip >/dev/null 2>&1; then
        echo -e "Network Interfaces:"
        ip addr show | grep -E "inet [0-9]" | while read -r line; do
            local interface=$(echo "$line" | awk '{print $2}' | cut -d: -f1)
            local ip=$(echo "$line" | awk '{print $2}' | cut -d/ -f1)
            echo -e "  ${CYAN}${interface}${NC}: ${GREEN}${ip}${NC}"
        done
    fi
    
    # Temperature (if available)
    if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
        local temp=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null)
        local temp_c=$(awk "BEGIN {printf \"%.1f\", $temp/1000}" <<< "$temp")
        echo -e "CPU Temp: ${YELLOW}${temp_c}°C${NC}"
    fi
}

# Function to show active processes
show_processes() {
    echo "=== CyberPWN Processes ==="
    
    # Check if server process is running
    if pgrep -f "python.*server.py" >/dev/null 2>&1; then
        local server_pid=$(pgrep -f "python.*server.py" | head -1)
        local server_cpu=$(ps -p "$server_pid" -o %cpu --no-headers 2>/dev/null | tr -d ' ')
        local server_mem=$(ps -p "$server_pid" -o %mem --no-headers 2>/dev/null | tr -d ' ')
        echo -e "Server (PID: ${server_pid}): ${YELLOW}CPU ${server_cpu}% | MEM ${server_mem}%${NC}"
    else
        echo -e "${RED}Server process not running${NC}"
    fi
    
    # Check for nmcli (WiFi)
    if pgrep nmcli >/dev/null 2>&1; then
        echo -e "${GREEN}nmcli (WiFi management)${NC}"
    fi
    
    # Check for nmap
    if command -v nmap >/dev/null 2>&1; then
        echo -e "${GREEN}nmap (network scanning)${NC}"
    fi
    
    # Check for WiFi interface
    if command -v iwconfig >/dev/null 2>&1; then
        local wifi_iface=$(iwconfig 2>/dev/null | grep -E "^[a-zA-Z0-9]+" | awk '{print $1}' | head -1)
        if [ -n "$wifi_iface" ]; then
            local wifi_ssid=$(iwgetid "$wifi_iface" 2>/dev/null | awk -F '"' '{print $2}')
            local wifi_ip=$(ip addr show "$wifi_iface" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -1)
            echo -e "${CYAN}WiFi Interface: ${wifi_iface}${NC}"
            if [ -n "$wifi_ssid" ]; then
                echo -e "${CYAN}Connected to: ${wifi_ssid}${NC}"
            fi
            if [ -n "$wifi_ip" ]; then
                echo -e "${CYAN}IP Address: ${wifi_ip}${NC}"
            fi
        fi
    fi
    
    # Check for CyberPWN service (systemd)
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active cyberpwn >/dev/null 2>&1; then
            echo -e "${GREEN}CyberPWN Service: ACTIVE${NC}"
        else
            echo -e "${RED}CyberPWN Service: INACTIVE${NC}"
        fi
        if systemctl is-enabled cyberpwn >/dev/null 2>&1; then
            echo -e "${GREEN}CyberPWN Service: ENABLED${NC}"
        else
            echo -e "${YELLOW}CyberPWN Service: DISABLED${NC}"
        fi
    else
        echo -e "${YELLOW}systemd not available${NC}"
    fi
}

# Function to ping IP addresses
ping_ip() {
    local ip="$1"
    local count="${2:-3}"
    
    if command -v ping >/dev/null 2>&1; then
        # Use Linux ping
        local result=$(ping -c "$count" -W 2 "$ip" 2>/dev/null)
        if [ $? -eq 0 ]; then
            local avg_time=$(echo "$result" | tail -1 | awk -F'/' '{print $5}')
            echo -e "${GREEN}REACHABLE${NC} (${avg_time}ms avg)"
            return 0
        else
            echo -e "${RED}UNREACHABLE${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}ping command not available${NC}"
        return 2
    fi
}

# Function to check server connectivity
check_server_connectivity() {
    echo "=== Server Connectivity Check ==="
    
    # Get server info first
    local server_url=$(get_server_url | sed 's|/api/server/info||')
    local server_ip=$(curl -s "$server_url/api/server/info" 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('primary_ip', 'Unknown'))
except:
    pass
" 2>/dev/null)
    
    if [ "$server_ip" = "" ] || [ "$server_ip" = "Unknown" ]; then
        echo -e "${RED}Could not determine server IP${NC}"
        return 1
    fi
    
    echo -e "Server IP: ${CYAN}${server_ip}${NC}"
    
    # Ping the server IP
    echo -n "Ping ${server_ip}: "
    ping_ip "$server_ip"
    
    # Test HTTP connectivity
    echo -n "HTTP ${server_url}: "
    if curl -s -m 5 "$server_url/api/server/info" >/dev/null 2>&1; then
        echo -e "${GREEN}REACHABLE${NC}"
    else
        echo -e "${RED}UNREACHABLE${NC}"
    fi
    
    # Get WiFi IP and ping server from WiFi interface
    if command -v iwconfig >/dev/null 2>&1; then
        local wifi_iface=$(iwconfig 2>/dev/null | grep -E "^[a-zA-Z0-9]+" | awk '{print $1}' | head -1)
        if [ -n "$wifi_iface" ]; then
            local wifi_ip=$(ip addr show "$wifi_iface" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -1)
            if [ -n "$wifi_ip" ] && [ "$wifi_ip" != "$server_ip" ]; then
                echo ""
                echo -e "WiFi IP: ${CYAN}${wifi_ip}${NC}"
                echo -n "Ping server from WiFi: "
                ping_ip "$server_ip"
            fi
        fi
    fi
    
    return 0
}

# Function to check CyberPWN service status
check_cyberpwn_service() {
    echo "=== CyberPWN Service Status ==="
    
    if ! command -v systemctl >/dev/null 2>&1; then
        echo -e "${RED}systemd not available${NC}"
        echo -e "${YELLOW}Cannot check service status${NC}"
        return 1
    fi
    
    # Check if service exists
    if ! systemctl list-unit-files | grep -q "cyberpwn.service"; then
        echo -e "${RED}CyberPWN service not found${NC}"
        echo -e "${YELLOW}Service file: /etc/systemd/system/cyberpwn.service${NC}"
        return 1
    fi
    
    # Check service status
    local service_status=$(systemctl is-active cyberpwn 2>/dev/null)
    local service_enabled=$(systemctl is-enabled cyberpwn 2>/dev/null)
    
    case "$service_status" in
        "active")
            echo -e "${GREEN}CyberPWN Service: ACTIVE${NC}"
            ;;
        "inactive")
            echo -e "${RED}CyberPWN Service: INACTIVE${NC}"
            ;;
        "failed")
            echo -e "${RED}CyberPWN Service: FAILED${NC}"
            ;;
        "activating")
            echo -e "${YELLOW}CyberPWN Service: ACTIVATING${NC}"
            ;;
        "deactivating")
            echo -e "${YELLOW}CyberPWN Service: DEACTIVATING${NC}"
            ;;
        *)
            echo -e "${RED}CyberPWN Service: UNKNOWN ($service_status)${NC}"
            ;;
    esac
    
    case "$service_enabled" in
        "enabled")
            echo -e "${GREEN}CyberPWN Service: ENABLED (auto-start)${NC}"
            ;;
        "disabled")
            echo -e "${YELLOW}CyberPWN Service: DISABLED (no auto-start)${NC}"
            ;;
        *)
            echo -e "${YELLOW}CyberPWN Service: UNKNOWN ENABLEMENT ($service_enabled)${NC}"
            ;;
    esac
    
    # Show service details if active
    if [ "$service_status" = "active" ]; then
        echo ""
        echo "=== Service Details ==="
        systemctl status cyberpwn --no-pager -l | head -10
    fi
    
    return 0
}

# Function to test API endpoints
test_api_endpoints() {
    echo "=== API Endpoint Tests ==="
    
    local server_url=$(get_server_url | sed 's|/api/server/info||')
    local endpoints=(
        "/api/server/info"
        "/api/sniffer/beacon"
        "/api/wardriving/raw"
        "/api/wifi/connect"
        "/api/wifi/disconnect"
        "/api/nmap/scan"
    )
    
    echo "Testing with server URL: ${server_url}"
    echo ""
    
    for endpoint in "${endpoints[@]}"; do
        echo -n "Testing $endpoint... "
        local start_time=$(date +%s)
        local response=$(curl -s -m 5 -w "%{http_code}" "${server_url}${endpoint}" 2>/dev/null)
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        if [ "$response" = "200" ]; then
            echo -e "${GREEN}OK${NC} (${duration}s)"
            # Log the successful call
            echo "[$(date '+%H:%M:%S')] POST $endpoint 200" >> "$LOG_FILE"
        else
            echo -e "${RED}FAILED${NC} (${response} ${duration}s)"
            # Log the failed call
            echo "[$(date '+%H:%M:%S')] POST $endpoint $response" >> "$LOG_FILE"
        fi
    done
}

# Function to show bound IP
show_bound_ip() {
    echo "=== Server Binding Information ==="
    
    local server_url=$(get_server_url)
    local actual_server_url=$(echo "$server_url" | sed 's|/api/server/info||')
    
    # Check if server is running on primary IP
    if check_server_status; then
        echo -e "Server URL: ${GREEN}${actual_server_url}${NC}"
        
        # Get actual bound IP from server
        local actual_ip=$(curl -s "$server_url" 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('primary_ip', 'Unknown'))
except:
    pass
" 2>/dev/null)
        
        if [ "$actual_ip" != "" ] && [ "$actual_ip" != "Unknown" ]; then
            echo -e "Actual IP: ${GREEN}${actual_ip}${NC}"
            
            # Check if it's the expected primary IP
            if [ "$actual_ip" = "$SERVER_HOST" ]; then
                echo -e "Status: ${GREEN}Successfully bound to ${SERVER_HOST}${NC}"
                echo -e "Configuration: ${GREEN}OPTIMAL${NC}"
            else
                echo -e "Status: ${YELLOW}Fallback binding (${actual_ip})${NC}"
                echo -e "Expected: ${SERVER_HOST}"
                echo -e "Configuration: ${YELLOW}SUBOPTIMAL${NC}"
                echo -e "Recommendation: Restart server for optimal access"
            fi
        else
            echo -e "Status: ${RED}Could not determine bound IP${NC}"
        fi
    else
        echo -e "${RED}Server is OFFLINE${NC}"
        echo -e "Expected binding: ${SERVER_HOST}:${SERVER_PORT}"
        echo -e "Trying fallback URLs: localhost:5000, 127.0.0.1:5000"
    fi
}

# Function to display real-time dashboard
show_dashboard() {
    while true; do
        display_header
        
        # Server Status
        echo -e "${WHITE}SERVER STATUS:${NC}"
        local server_status=$(check_server_status && echo "ONLINE" || echo "OFFLINE")
        echo -e "Status: $server_status"
        echo ""
        
        # Server Connectivity
        echo -e "${WHITE}SERVER CONNECTIVITY:${NC}"
        check_server_connectivity
        echo ""
        
        # Server Binding
        echo -e "${WHITE}SERVER BINDING:${NC} "
        show_bound_ip
        echo ""
        
        # API Activity
        echo -e "${WHITE}API ACTIVITY:${NC} "
        monitor_api_calls "$LOG_FILE" "$API_COUNT_FILE"
        echo ""
        
        # Recent API Calls
        show_recent_api_calls "$LOG_FILE"
        echo ""
        
        # System Stats
        show_system_stats
        echo ""
        
        # Processes
        echo -e "${WHITE}PROCESSES & SERVICES:${NC}"
        show_processes
        echo ""
        
        # Service Status
        echo -e "${WHITE}CYBERPWN SERVICE:${NC}"
        check_cyberpwn_service
        echo ""
        
        # Refresh info
        echo -e "${CYAN}Last Updated: $(date '+%Y-%m-%d %H:%M:%S')${NC} "
        echo -e "${CYAN}Next refresh in 10 seconds...${NC} "
        echo ""
        echo -e "${MAGENTA}Press Ctrl+C to exit${NC} "
        
        sleep 10
    done
}

# Function to run comprehensive test
run_comprehensive_test() {
    echo -e "${CYAN}Running Comprehensive CyberPWN Server Test...${NC} "
    echo ""
    
    # Test server connectivity
    echo "1. Testing server connectivity... "
    if check_server_status; then
        echo -e "${GREEN} Server is accessible${NC} "
    else
        echo -e "${RED} Server is not accessible${NC} "
        echo "Please start the server first: python server.py "
        exit 1
    fi
    echo ""
    
    # Test API endpoints
    echo "2. Testing API endpoints... "
    test_api_endpoints
    echo ""
    
    # Show final server info
    echo "3. Final server information... "
    get_server_info
    echo ""
    
    echo -e "${GREEN}Test completed!${NC} "
}

# Main menu
case "${1:-dashboard}" in
    "dashboard")
        show_dashboard
        ;;
    "test")
        run_comprehensive_test
        ;;
    "server")
        get_server_info
        ;;
    "status")
        check_server_status
        ;;
    "service")
        check_cyberpwn_service
        ;;
    "ping")
        check_server_connectivity
        ;;
    "apis")
        monitor_api_calls "$LOG_FILE" "$API_COUNT_FILE"
        ;;
    "help")
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  dashboard  - Show real-time monitoring dashboard (default)"
        echo "  test      - Run comprehensive server test"
        echo "  server    - Show server binding information"
        echo "  status    - Check if server is running"
        echo "  service   - Check CyberPWN service status"
        echo "  ping      - Check server connectivity with ping"
        echo "  apis      - Show API call statistics"
        echo "  help      - Show this help message"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' for available commands"
        exit 1
        ;;
esac
