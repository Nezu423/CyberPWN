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
    """Parse wardrive log file (JSON or text format)"""
    networks = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Try JSON format first
        try:
            data = json.loads(content)
            if isinstance(data, list):
                networks = data
            elif isinstance(data, dict) and 'networks' in data:
                networks = data['networks']
            elif isinstance(data, dict):
                networks = [data]
        except json.JSONDecodeError:
            # Try to parse as text/log format
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                # Look for SSID patterns
                ssid_match = re.search(r'SSID[:\s]+([^\s,]+)', line, re.IGNORECASE)
                if ssid_match:
                    ssid = ssid_match.group(1).strip('"\'')
                    
                    # Extract other info
                    encryption = "Unknown"
                    if "WEP" in line.upper():
                        encryption = "WEP"
                    elif "WPA" in line.upper():
                        encryption = "WPA"
                    elif "WPA2" in line.upper():
                        encryption = "WPA2"
                    elif "OPEN" in line.upper() or "NONE" in line.upper():
                        encryption = "Open"
                    
                    # Extract signal strength
                    signal = None
                    signal_match = re.search(r'(-?\d+)\s*dBm', line)
                    if signal_match:
                        signal = int(signal_match.group(1))
                    
                    # Extract channel
                    channel = None
                    channel_match = re.search(r'channel[:\s]+(\d+)', line, re.IGNORECASE)
                    if channel_match:
                        channel = int(channel_match.group(1))
                    
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
        print("Usage: python wardrive_analyzer.py <logfile> [output_file]")
        print("\nSupported formats:")
        print("  - JSON wardrive logs")
        print("  - Text logs with SSID information")
        print("\nExamples:")
        print("  python wardrive_analyzer.py wardrive.log")
        print("  python wardrive_analyzer.py wardrive.log results.txt")
        sys.exit(1)
    
    log_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"Analyzing wardrive log: {log_file}")
    
    # Parse the log file
    networks = parse_wardrive_log(log_file)
    
    if not networks:
        print("No networks found in the log file")
        sys.exit(1)
    
    # Analyze the networks
    analysis = analyze_networks(networks)
    
    # Print results
    print_results(analysis)
    
    # Save to file if requested
    if output_file:
        save_results(analysis, output_file)

if __name__ == "__main__":
    main()
