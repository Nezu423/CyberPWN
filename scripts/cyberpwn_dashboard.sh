#!/bin/bash
# cyberpwn_dashboard.sh - CyberPWN Server Monitoring Dashboard
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
    local response=$(curl -s -m 5 "$SERVER_URL/api/server/info" 2>/dev/null)
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
except:
    pass
"
    else
        echo -e "${RED}Server Status: OFFLINE${NC}"
        echo "Bound IP: Unknown"
        echo "Hostname: Unknown"
        echo "Port: 5000"
    fi
}

# Function to check if server is running
check_server_status() {
    if curl -s -m 2 "$SERVER_URL/api/server/info" >/dev/null 2>&1; then
        echo -e "${GREEN}RUNNING${NC}"
        return 0
    else
        echo -e "${RED}OFFLINE${NC}"
        return 1
    fi
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
        echo -e "CPU Usage: ${YELLOW}${cpu_usage}%${NC} "
    fi
    
    # Memory usage
    if command -v free >/dev/null 2>&1; then
        local mem_info=$(free -m | awk '/Mem:/ {printf("%.1f%%", $3/$2 * 100.0)}')
        echo -e "Memory: ${YELLOW}${mem_info}${NC} "
    fi
    
    # Disk usage
    if command -v df >/dev/null 2>&1; then
        local disk_info=$(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')
        echo -e "Disk: ${YELLOW}${disk_info}${NC} "
    fi
    
    # Network interfaces
    if command -v ip >/dev/null 2>&1; then
        echo -e "Network Interfaces:"
        ip addr show | grep -E "inet [0-9]" | while read -r line; do
            local interface=$(echo "$line" | awk '{print $2}' | cut -d: -f1)
            local ip=$(echo "$line" | awk '{print $2}' | cut -d/ -f1)
            echo -e "  ${CYAN}${interface}${NC}: ${GREEN}${ip}${NC} "
        done
    fi
}

# Function to show active processes
show_processes() {
    echo "=== CyberPWN Processes ==="
    
    # Check if server process is running
    if pgrep -f "python.*server.py" >/dev/null; then
        local server_pid=$(pgrep -f "python.*server.py" | head -1)
        local server_cpu=$(ps -p "$server_pid" -o %cpu --no-headers)
        local server_mem=$(ps -p "$server_pid" -o %mem --no-headers)
        echo -e "Server (PID: ${server_pid}): ${YELLOW}CPU ${server_cpu}% | MEM ${server_mem}%${NC} "
    else
        echo -e "${RED}Server process not running${NC} "
    fi
    
    # Check for nmcli (WiFi)
    if pgrep nmcli >/dev/null; then
        echo -e "${GREEN}nmcli (WiFi management)${NC} "
    fi
    
    # Check for nmap
    if command -v nmap >/dev/null 2>&1; then
        echo -e "${GREEN}nmap (network scanning)${NC} "
    fi
}

# Function to test API endpoints
test_api_endpoints() {
    echo "=== API Endpoint Tests ==="
    
    local endpoints=(
        "/api/server/info"
        "/api/sniffer/beacon"
        "/api/wardriving/raw"
        "/api/wifi/connect"
        "/api/wifi/disconnect"
        "/api/nmap/scan"
    )
    
    for endpoint in "${endpoints[@]}"; do
        echo -n "Testing $endpoint... "
        local start_time=$(date +%s)
        local response=$(curl -s -m 5 -w "%{http_code}" "$SERVER_URL$endpoint" 2>/dev/null)
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        if [ "$response" = "200" ]; then
            echo -e "${GREEN}OK${NC} (${duration}s) "
            # Log the successful call
            echo "[$(date '+%H:%M:%S')] POST $endpoint 200" >> "$LOG_FILE"
        else
            echo -e "${RED}FAILED${NC} (${response} ${duration}s) "
            # Log the failed call
            echo "[$(date '+%H:%M:%S')] POST $endpoint $response" >> "$LOG_FILE"
        fi
    done
}

# Function to show bound IP
show_bound_ip() {
    echo "=== Server Binding Information ==="
    
    # Check if server is running on primary IP
    if check_server_status; then
        echo -e "Primary Binding: ${GREEN}${SERVER_HOST}:${SERVER_PORT}${NC} "
        
        # Get actual bound IP from server
        local actual_ip=$(curl -s "$SERVER_URL/api/server_info" 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('primary_ip', 'Unknown'))
except:
    pass
" 2>/dev/null)
        
        if [ "$actual_ip" != "" ] && [ "$actual_ip" != "Unknown" ]; then
            if [ "$actual_ip" = "$SERVER_HOST" ]; then
                echo -e "Status: ${GREEN}Successfully bound to ${SERVER_HOST}${NC} "
            else
                echo -e "Status: ${YELLOW}Fallback binding (${actual_ip})${NC} "
            fi
        fi
    else
        echo -e "${RED}Server is OFFLINE${NC} "
        echo -e "Expected binding: ${SERVER_HOST}:${SERVER_PORT} "
    fi
}

# Function to display real-time dashboard
show_dashboard() {
    while true; do
        display_header
        
        # Server Status
        echo -e "${WHITE}SERVER STATUS:${NC} "
        local server_status=$(check_server_status && echo "ONLINE" || echo "OFFLINE")
        echo -e "Status: $server_status "
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
        show_processes
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
    "apis")
        monitor_api_calls "$LOG_FILE" "$API_COUNT_FILE"
        ;;
    "help")
        echo "Usage: $0 [command] "
        echo ""
        echo "Commands:"
        echo "  dashboard  - Show real-time monitoring dashboard (default) "
        echo "  test      - Run comprehensive server test "
        echo "  server    - Show server binding information "
        echo "  status    - Check if server is running "
        echo "  apis      - Show API call statistics "
        echo "  help      - Show this help message "
        ;;
    *)
        echo "Unknown command: $1 "
        echo "Use '$0 help' for available commands "
        exit 1
        ;;
esac
