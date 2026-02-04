#!/usr/bin/env python3
import socket
import subprocess
import re

def get_ipv4_ips():
    """Get IPv4 addresses using ip command"""
    ipv4_ips = []
    
    try:
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'inet ' in line and not line.strip().startswith('127.'):
                    match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        ip = match.group(1)
                        if ip not in ipv4_ips:
                            ipv4_ips.append(ip)
    except Exception as e:
        print(f"Error running ip command: {e}")
    
    return ipv4_ips

def test_socket_method():
    """Test socket method to get IP"""
    try:
        hostname = socket.gethostname()
        print(f"Hostname: {hostname}")
        
        # Test socket.getaddrinfo
        try:
            for interface in socket.getaddrinfo(hostname, None):
                ip = interface[4][0]
                print(f"Socket found IP: {ip}")
        except Exception as e:
            print(f"Error with getaddrinfo: {e}")
        
        # Test external connection method
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            print(f"External connection method IP: {local_ip}")
        except Exception as e:
            print(f"Error with external connection: {e}")
            
    except Exception as e:
        print(f"Error in socket method: {e}")

if __name__ == "__main__":
    print("=== IP Detection Test ===")
    
    print("\n1. Testing ip command method:")
    ipv4_ips = get_ipv4_ips()
    print(f"IPv4 IPs found: {ipv4_ips}")
    
    print("\n2. Testing socket methods:")
    test_socket_method()
    
    print(f"\n3. Primary IP would be: {ipv4_ips[0] if ipv4_ips else '127.0.0.1'}")
