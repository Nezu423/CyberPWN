#!/usr/bin/env python3
"""
Simple Wardrive Log Parser - specifically for your JSON lines format
"""

import json
import sys

def parse_log_file(file_path):
    """Parse your specific log format"""
    all_ssids = set()
    open_networks = []
    encrypted_networks = []
    
    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    ssid = data.get('ssid')
                    if not ssid:
                        continue
                    
                    all_ssids.add(ssid)
                    
                    # Check if open using should_be_open field
                    is_open = data.get('should_be_open', False)
                    encryption = data.get('encryption', 'Unknown')
                    
                    network_info = {
                        'ssid': ssid,
                        'encryption': encryption,
                        'signal': data.get('signal'),
                        'channel': data.get('channel'),
                        'line': line_num
                    }
                    
                    if is_open:
                        open_networks.append(network_info)
                    else:
                        encrypted_networks.append(network_info)
                        
                except json.JSONDecodeError:
                    print(f"Line {line_num}: Invalid JSON - {line[:50]}...")
                    continue
                    
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        return
    
    # Print results
    print("=" * 60)
    print("SIMPLE WARDRIVE LOG PARSER")
    print("=" * 60)
    print()
    
    print(f"Total lines processed: {line_num}")
    print(f"Unique SSIDs found: {len(all_ssids)}")
    print(f"Open networks: {len(open_networks)}")
    print(f"Encrypted networks: {len(encrypted_networks)}")
    print()
    
    # All SSIDs
    print("=" * 60)
    print("ALL UNIQUE SSIDs:")
    print("=" * 60)
    for i, ssid in enumerate(sorted(all_ssids), 1):
        print(f"{i:3}. {ssid}")
    
    # Open networks
    if open_networks:
        print()
        print("=" * 60)
        print("OPEN NETWORKS (should_be_open = true):")
        print("=" * 60)
        for i, net in enumerate(open_networks, 1):
            signal = net.get('signal', 'N/A')
            channel = net.get('channel', 'N/A')
            print(f"{i:3}. {net['ssid']}")
            print(f"     Signal: {signal} dBm | Channel: {channel} | Line: {net['line']}")
    
    # Encrypted networks (first 10)
    if encrypted_networks:
        print()
        print("=" * 60)
        print(f"ENCRYPTED NETWORKS (showing first 10 of {len(encrypted_networks)}):")
        print("=" * 60)
        for i, net in enumerate(encrypted_networks[:10], 1):
            signal = net.get('signal', 'N/A')
            channel = net.get('channel', 'N/A')
            print(f"{i:3}. {net['ssid']} ({net['encryption']})")
            print(f"     Signal: {signal} dBm | Channel: {channel}")
    
    # Summary
    print()
    print("=" * 60)
    print("SUMMARY:")
    print("=" * 60)
    print(f"🎯 {len(open_networks)} networks are OPEN (no password required)")
    print(f"🔒 {len(encrypted_networks)} networks are ENCRYPTED")
    print(f"📡 Total unique networks: {len(all_ssids)}")
    
    # Save to files
    with open('all_ssids.txt', 'w') as f:
        for ssid in sorted(all_ssids):
            f.write(f"{ssid}\n")
    
    if open_networks:
        with open('open_networks.txt', 'w') as f:
            for net in open_networks:
                f.write(f"{net['ssid']}\n")
    
    print()
    print("Files saved:")
    print("- all_ssids.txt (all unique SSIDs)")
    if open_networks:
        print("- open_networks.txt (open networks only)")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python simple_log_parser.py <logfile>")
        sys.exit(1)
    
    parse_log_file(sys.argv[1])
