#!/bin/bash
# Simple server ping check script

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== CyberPWN Server Ping Check ==="
echo ""

# Function to check if server is up on specific IP
check_server() {
    local ip="$1"
    local port="$2"
    
    echo -n "Checking $ip:$port ... "
    
    # Ping the IP
    if ping -c 1 -W 2 "$ip" >/dev/null 2>&1; then
        # Ping successful, now check HTTP
        if curl -s -m 3 "http://$ip:$port/api/server/info" >/dev/null 2>&1; then
            echo -e "${GREEN}UP${NC}"
            return 0
        else
            echo -e "${YELLOW}PING OK, HTTP DOWN${NC}"
            return 1
        fi
    else
        echo -e "${RED}DOWN${NC}"
        return 2
    fi
}

# Check both IPs
check_server "192.168.1.118" "5000"
check_server "192.168.4.1" "5000"

echo ""
echo "Done."
