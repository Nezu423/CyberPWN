#!/usr/bin/env python3
"""
Simple Wardrive Log Parser - specifically for your JSON lines format
"""

import json
import sys

def parse_log_file(file_path):
    """Parse plain text log format"""
    all_ssids = set()
    open_networks = []
    encrypted_networks = []
    
    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                # Debug: Show each line being processed
                print(f"Line {line_num:3}: {line}")
                
                # Parse plain text format
                # Look for SSID patterns in plain text
                ssid = None
                
                # Try different patterns for SSID extraction
                if 'SSID:' in line:
                    # Format: SSID: NetworkName
                    parts = line.split('SSID:')
                    if len(parts) > 1:
                        ssid = parts[1].strip().strip('"\'')
                        print(f"  -> Found SSID with 'SSID:' pattern: '{ssid}'")
                elif 'ssid:' in line:
                    # Format: ssid: NetworkName
                    parts = line.split('ssid:')
                    if len(parts) > 1:
                        ssid = parts[1].strip().strip('"\'')
                        print(f"  -> Found SSID with 'ssid:' pattern: '{ssid}'")
                elif line.startswith('"') and line.endswith('"'):
                    # Format: "NetworkName"
                    ssid = line.strip('"\'')
                    print(f"  -> Found SSID in quotes: '{ssid}'")
                elif 'should_be_open' in line:
                    # Extract SSID from should_be_open lines
                    if 'ssid' in line:
                        # Extract ssid from the line
                        import re
                        ssid_match = re.search(r'ssid["\']?\s*[:=]\s*["\']([^"\']+)["\']', line)
                        if ssid_match:
                            ssid = ssid_match.group(1)
                            print(f"  -> Found SSID in should_be_open line: '{ssid}'")
                else:
                    # Try to extract from any line that looks like a network name
                    # Skip lines that are clearly not SSIDs
                    if not any(char in line for char in ['{', '}', '[', ']', ',', ':', '=', '(', ')']) and len(line) > 2:
                        if not line.isdigit() and not line.replace('-', '').replace('.', '').isdigit():
                            ssid = line.strip('"\'')
                            print(f"  -> Found SSID as plain text: '{ssid}'")
                
                if not ssid or len(ssid) < 2:
                    print(f"  -> No SSID found, skipping")
                    continue
                
                # Skip common non-SSID entries
                if ssid.lower() in ['unknown', 'n/a', 'none', 'hidden', 'ssid', 'network']:
                    print(f"  -> Skipping common non-SSID: '{ssid}'")
                    continue
                
                all_ssids.add(ssid)
                print(f"  -> Added SSID to list: '{ssid}'")
                
                # Check if open network
                is_open = False
                encryption = "Unknown"
                
                # Look for open indicators
                if 'should_be_open' in line and ('true' in line or 'True' in line):
                    is_open = True
                    encryption = "Open"
                    print(f"  -> Detected as OPEN (should_be_open=true)")
                elif 'open' in line.lower():
                    is_open = True
                    encryption = "Open"
                    print(f"  -> Detected as OPEN (contains 'open')")
                elif 'none' in line.lower() or 'no encryption' in line.lower():
                    is_open = True
                    encryption = "Open"
                    print(f"  -> Detected as OPEN (no encryption)")
                elif 'wpa' in line.lower():
                    encryption = "WPA"
                    is_open = False
                    print(f"  -> Detected as ENCRYPTED (WPA)")
                elif 'wep' in line.lower():
                    encryption = "WEP"
                    is_open = False
                    print(f"  -> Detected as ENCRYPTED (WEP)")
                else:
                    print(f"  -> Encryption unknown, defaulting to encrypted")
                
                # Extract signal strength
                signal = None
                import re
                signal_match = re.search(r'(-?\d+)\s*dBm', line)
                if signal_match:
                    signal = int(signal_match.group(1))
                    print(f"  -> Signal: {signal} dBm")
                
                # Extract channel
                channel = None
                channel_match = re.search(r'channel[:\s]+(\d+)', line, re.IGNORECASE)
                if channel_match:
                    channel = int(channel_match.group(1))
                    print(f"  -> Channel: {channel}")
                
                network_info = {
                    'ssid': ssid,
                    'encryption': encryption,
                    'signal': signal,
                    'channel': channel,
                    'line': line_num,
                    'raw_line': line
                }
                
                if is_open:
                    open_networks.append(network_info)
                    print(f"  -> Added to OPEN networks list")
                else:
                    encrypted_networks.append(network_info)
                    print(f"  -> Added to ENCRYPTED networks list")
                
                print()  # Empty line for readability
                        
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
        print("OPEN NETWORKS:")
        print("=" * 60)
        for i, net in enumerate(open_networks, 1):
            signal = net.get('signal', 'N/A')
            channel = net.get('channel', 'N/A')
            print(f"{i:3}. {net['ssid']}")
            print(f"     Signal: {signal} dBm | Channel: {channel} | Line: {net['line']}")
            if len(net['raw_line']) < 100:
                print(f"     Raw: {net['raw_line']}")
    
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
