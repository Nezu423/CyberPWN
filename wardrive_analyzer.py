#!/usr/bin/env python3
"""
Wardrive Log Analyzer
Parses wardrive logs and shows unique SSIDs and open networks
"""

import json
import re
import sys
import os
from collections import defaultdict
from datetime import datetime

def parse_wardrive_log(file_path):
    """Parse wardrive log file (JSON lines or text format)"""
    networks = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        print(f"DEBUG: Reading {len(lines)} lines from file")
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            # Debug: Show first few lines
            if line_num <= 5:
                print(f"DEBUG Line {line_num}: {line[:100]}...")
            
            # Try to parse each line as JSON (JSON lines format)
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    # Extract SSID from JSON
                    ssid = data.get('ssid') or data.get('SSID') or data.get('essid') or data.get('ESSID')
                    if ssid:
                        if line_num <= 5:
                            print(f"DEBUG: Found SSID in JSON: '{ssid}'")
                        
                        # Extract encryption from JSON
                        encryption = data.get('encryption', data.get('security', 'Unknown'))
                        if isinstance(encryption, list):
                            encryption = ', '.join(encryption)
                        
                        # Extract signal
                        signal = data.get('signal') or data.get('rssi') or data.get('RSSI') or data.get('level')
                        if isinstance(signal, (int, float)):
                            signal = int(signal)
                        elif isinstance(signal, str):
                            signal_match = re.search(r'(-?\d+)', signal)
                            if signal_match:
                                signal = int(signal_match.group(1))
                        
                        # Extract channel
                        channel = data.get('channel') or data.get('Channel')
                        if isinstance(channel, (int, float)):
                            channel = int(channel)
                        elif isinstance(channel, str):
                            channel_match = re.search(r'(\d+)', channel)
                            if channel_match:
                                channel = int(channel_match.group(1))
                        
                        networks.append({
                            'ssid': ssid,
                            'encryption': encryption,
                            'signal': signal,
                            'channel': channel,
                            'raw_line': line
                        })
                        continue
            except json.JSONDecodeError:
                if line_num <= 5:
                    print(f"DEBUG: Not JSON, trying text parsing")
                pass  # Not JSON, try text parsing
            
            # If not JSON, try text parsing
            # Multiple SSID extraction patterns
            ssid = None
            
            # Pattern 1: SSID: "NetworkName"
            ssid_match = re.search(r'SSID[:\s]+["\']?([^"\',\s]+)["\']?', line, re.IGNORECASE)
            if ssid_match:
                ssid = ssid_match.group(1)
                if line_num <= 5:
                    print(f"DEBUG: Found SSID with pattern 1: '{ssid}'")
            
            # Pattern 2: ESSID:"NetworkName" (iwconfig format)
            if not ssid:
                essid_match = re.search(r'ESSID[:\s]+["\']?([^"\']+)["\']?', line, re.IGNORECASE)
                if essid_match:
                    ssid = essid_match.group(1)
                    if line_num <= 5:
                        print(f"DEBUG: Found SSID with pattern 2: '{ssid}'")
            
            # Pattern 3: "NetworkName" (quoted SSID alone)
            if not ssid:
                quoted_match = re.search(r'^["\']([^"\']+)["\']$', line)
                if quoted_match:
                    ssid = quoted_match.group(1)
                    if line_num <= 5:
                        print(f"DEBUG: Found SSID with pattern 3: '{ssid}'")
            
            # Pattern 4: NetworkName (unquoted, just a word)
            if not ssid and len(line.split()) == 1 and len(line) > 2:
                # Single word that looks like a network name
                if not re.match(r'^[0-9\-\.]+$', line) and not line.startswith(('0x', '00:')):
                    ssid = line
                    if line_num <= 5:
                        print(f"DEBUG: Found SSID with pattern 4: '{ssid}'")
            
            # Pattern 5: JSON-like entries in text
            if not ssid:
                json_match = re.search(r'"ssid"[:\s]*["\']([^"\']+)["\']', line, re.IGNORECASE)
                if json_match:
                    ssid = json_match.group(1)
                    if line_num <= 5:
                        print(f"DEBUG: Found SSID with pattern 5: '{ssid}'")
            
            if line_num <= 5 and not ssid:
                print(f"DEBUG: No SSID found in line {line_num}")
            
            if not ssid:
                continue
            
            # Skip common non-SSID entries
            if ssid.lower() in ['unknown', '', 'n/a', 'null', 'none', 'hidden', 'ssid']:
                if line_num <= 5:
                    print(f"DEBUG: Skipping SSID: '{ssid}'")
                continue
            
            # Extract encryption info
            encryption = "Unknown"
            line_upper = line.upper()
            
            if any(word in line_upper for word in ['WEP', 'WEP-']):
                encryption = "WEP"
            elif any(word in line_upper for word in ['WPA2', 'WPA2-']):
                encryption = "WPA2"
            elif any(word in line_upper for word in ['WPA', 'WPA-']):
                encryption = "WPA"
            elif any(word in line_upper for word in ['OPEN', 'NONE', 'OPEN-NETWORK']):
                encryption = "Open"
            elif 'PSK' in line_upper:
                if 'WPA2' in line_upper:
                    encryption = "WPA2"
                elif 'WPA' in line_upper:
                    encryption = "WPA"
            
            # Extract signal strength
            signal = None
            signal_patterns = [
                r'(-?\d+)\s*dBm',
                r'Signal[:\s]+(-?\d+)',
                r'RSSI[:\s]+(-?\d+)',
                r'Level[:\s]+(-?\d+)'
            ]
            for pattern in signal_patterns:
                signal_match = re.search(pattern, line, re.IGNORECASE)
                if signal_match:
                    signal = int(signal_match.group(1))
                    break
            
            # Extract channel
            channel = None
            channel_patterns = [
                r'channel[:\s]+(\d+)',
                r'CH[:\s]+(\d+)',
                r'Frequency[:\s]+[\d.]+.*\(CH\s*(\d+)\)',
                r'(\d+)\s*GHz'  # Convert GHz to channel if needed
            ]
            for pattern in channel_patterns:
                channel_match = re.search(pattern, line, re.IGNORECASE)
                if channel_match:
                    channel = int(channel_match.group(1))
                    # Convert GHz to channel if needed
                    if channel > 100:  # Likely GHz frequency
                        if 2.4 <= channel/1000 <= 2.5:
                            channel = 6  # Default 2.4GHz channel
                        elif 5.0 <= channel/1000 <= 6.0:
                            channel = 36  # Default 5GHz channel
                    break
            
            networks.append({
                'ssid': ssid,
                'encryption': encryption,
                'signal': signal,
                'channel': channel,
                'raw_line': line
            })
                    
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        return []
    except Exception as e:
        print(f"Error parsing file: {e}")
        return []
    
    print(f"DEBUG: Total networks parsed: {len(networks)}")
    return networks

def analyze_networks(networks):
    """Analyze networks and categorize them"""
    unique_ssids = set()
    open_networks = []
    encrypted_networks = []
    channel_stats = defaultdict(int)
    encryption_stats = defaultdict(int)
    
    for network in networks:
        ssid = network.get('ssid', 'Unknown')
        encryption = network.get('encryption', 'Unknown')
        signal = network.get('signal')
        channel = network.get('channel')
        
        # Skip empty SSIDs
        if not ssid or ssid.lower() in ['unknown', '', 'n/a']:
            continue
            
        unique_ssids.add(ssid)
        
        # Categorize by encryption
        if encryption.lower() in ['open', 'none', '']:
            open_networks.append(network)
        else:
            encrypted_networks.append(network)
        
        # Statistics
        if channel:
            channel_stats[channel] += 1
        encryption_stats[encryption] += 1
    
    return {
        'unique_ssids': sorted(list(unique_ssids)),
        'open_networks': open_networks,
        'encrypted_networks': encrypted_networks,
        'channel_stats': dict(channel_stats),
        'encryption_stats': dict(encryption_stats),
        'total_networks': len(networks)
    }

def print_results(analysis):
    """Print analysis results"""
    print("=" * 60)
    print("WARDRIVE LOG ANALYSIS")
    print("=" * 60)
    
    print(f"\nTotal Networks Found: {analysis['total_networks']}")
    print(f"Unique SSIDs: {len(analysis['unique_ssids'])}")
    print(f"Open Networks: {len(analysis['open_networks'])}")
    print(f"Encrypted Networks: {len(analysis['encrypted_networks'])}")
    
    # Encryption breakdown
    print("\n" + "-" * 40)
    print("ENCRYPTION BREAKDOWN:")
    print("-" * 40)
    for enc_type, count in sorted(analysis['encryption_stats'].items()):
        print(f"{enc_type:12}: {count:3} networks")
    
    # Channel breakdown
    if analysis['channel_stats']:
        print("\n" + "-" * 40)
        print("CHANNEL BREAKDOWN:")
        print("-" * 40)
        for channel, count in sorted(analysis['channel_stats'].items()):
            print(f"Channel {channel:2}: {count:3} networks")
    
    # All unique SSIDs
    print("\n" + "=" * 60)
    print("ALL UNIQUE SSIDs:")
    print("=" * 60)
    for i, ssid in enumerate(analysis['unique_ssids'], 1):
        print(f"{i:3}. {ssid}")
    
    # Open networks (detailed)
    if analysis['open_networks']:
        print("\n" + "=" * 60)
        print("OPEN NETWORKS (No Password):")
        print("=" * 60)
        for i, network in enumerate(analysis['open_networks'], 1):
            ssid = network['ssid']
            signal = network.get('signal', 'N/A')
            channel = network.get('channel', 'N/A')
            signal_str = f"{signal} dBm" if signal != 'N/A' else 'N/A'
            print(f"{i:3}. {ssid:20} | Signal: {signal_str:6} | Channel: {channel}")
    
    # Statistics summary
    print("\n" + "=" * 60)
    print("SUMMARY:")
    print("=" * 60)
    total = analysis['total_networks']
    open_count = len(analysis['open_networks'])
    encrypted_count = len(analysis['encrypted_networks'])
    
    if total > 0:
        open_percent = (open_count / total) * 100
        encrypted_percent = (encrypted_count / total) * 100
        print(f"Open Networks:     {open_count:3} ({open_percent:5.1f}%)")
        print(f"Encrypted Networks: {encrypted_count:3} ({encrypted_percent:5.1f}%)")
        print(f"Total Networks:    {total:3}")
        
        if open_count > 0:
            print(f"\n🎯 {open_count} networks are vulnerable (no password!)")

def save_results(analysis, output_file):
    """Save results to a file"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("WARDRIVE LOG ANALYSIS\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write(f"Total Networks: {analysis['total_networks']}\n")
            f.write(f"Unique SSIDs: {len(analysis['unique_ssids'])}\n")
            f.write(f"Open Networks: {len(analysis['open_networks'])}\n")
            f.write(f"Encrypted Networks: {len(analysis['encrypted_networks'])}\n\n")
            
            f.write("ALL UNIQUE SSIDS:\n")
            f.write("-" * 40 + "\n")
            for ssid in analysis['unique_ssids']:
                f.write(f"{ssid}\n")
            
            if analysis['open_networks']:
                f.write("\nOPEN NETWORKS:\n")
                f.write("-" * 40 + "\n")
                for network in analysis['open_networks']:
                    f.write(f"{network['ssid']}\n")
        
        print(f"\nResults saved to: {output_file}")
    except Exception as e:
        print(f"Error saving results: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python wardrive_analyzer.py <logfile> [output_file] [--debug]")
        print("\nSupported formats:")
        print("  - JSON wardrive logs")
        print("  - Text logs with SSID information")
        print("\nExamples:")
        print("  python wardrive_analyzer.py wardrive.log")
        print("  python wardrive_analyzer.py wardrive.log results.txt")
        print("  python wardrive_analyzer.py wardrive.log --debug")
        sys.exit(1)
    
    log_file = sys.argv[1]
    output_file = None
    debug_mode = False
    
    # Parse arguments
    for arg in sys.argv[2:]:
        if arg == '--debug':
            debug_mode = True
        else:
            output_file = arg
    
    print(f"Analyzing wardrive log: {log_file}")
    
    # Parse the log file
    networks = parse_wardrive_log(log_file)
    
    if debug_mode:
        print(f"\nDEBUG: Found {len(networks)} raw network entries")
        print("DEBUG: First 5 entries:")
        for i, net in enumerate(networks[:5]):
            print(f"  {i+1}. SSID: '{net.get('ssid', 'N/A')}' | Enc: {net.get('encryption', 'N/A')}")
        print()
    
    if not networks:
        print("No networks found in the log file")
        print("Try using --debug to see parsing details")
        sys.exit(1)
    
    # Analyze the networks
    analysis = analyze_networks(networks)
    
    if debug_mode:
        print(f"DEBUG: {len(analysis['unique_ssids'])} unique SSIDs after filtering")
        print(f"DEBUG: {len(analysis['open_networks'])} open networks found")
        print()
    
    # Print results
    print_results(analysis)
    
    # Save to file if requested
    if output_file:
        save_results(analysis, output_file)

if __name__ == "__main__":
    main()
