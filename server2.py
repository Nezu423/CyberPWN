import subprocess
import os
import sys
from flask import Flask, jsonify, request, render_template

# --- SETUP ---
base_dir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(base_dir, 'templates')
app = Flask(__name__, template_folder=template_dir)

# --- ROUTES ---
@app.route('/')
def home():
    return render_template('wifi.html')

@app.route('/<path:filename>')
def serve_page(filename):
    return render_template(filename)

# --- 1. CLEAN SSID SCANNER ---
@app.route('/api/scan_wifi')
def scan_wifi():
    try:
        cmd = "sudo nmcli -t -f SSID,SIGNAL,SECURITY dev wifi list"
        output = subprocess.check_output(cmd, shell=True).decode('utf-8')
        results = []
        seen = set()
        
        for line in output.split('\n'):
            if not line: continue
            parts = line.split(':')
            if len(parts) >= 2:
                ssid = parts[0]
                if not ssid or ssid in seen: continue
                seen.add(ssid)
                sec = "SECURE" if "WPA" in (parts[2] if len(parts)>2 else "") else "OPEN"
                results.append(f"{ssid[:12].ljust(12)} {parts[1]}% {sec}")

        return jsonify(results[:15])
    except Exception as e:
        return jsonify([f"ERROR: {str(e)}"])

# --- 2. VULN MONITOR (Port Scan) ---
@app.route('/api/nmap', strict_slashes=False)
def nmap_scan():
    try:
        my_ip_raw = subprocess.check_output("hostname -I", shell=True).decode('utf-8').strip()
        if not my_ip_raw: return jsonify(["ERROR: No Network"])
        my_ip = my_ip_raw.split(' ')[0]
        subnet = f"{'.'.join(my_ip.split('.')[:3])}.0/24"
        
        # Scan common danger ports
        cmd = f"sudo nmap -sS -p 21,23,445,3389,8080 --open -n {subnet} --exclude {my_ip}"
        output = subprocess.check_output(cmd, shell=True).decode('utf-8')
        
        clean_res = []
        clean_res.append(f"TARGET: {subnet}")
        current_ip = ""
        found_vuln = False
        
        for line in output.split('\n'):
            if "scan report" in line:
                current_ip = line.split("for ")[1]
            if "open" in line and "tcp" in line:
                found_vuln = True
                parts = line.split()
                port = parts[0].split('/')[0]
                service = parts[-1]
                clean_res.append(f"{current_ip} > {port} ({service})")

        if not found_vuln:
            clean_res.append("SECURE: No vulnerable ports found.")
            
        return jsonify(clean_res)

    except Exception as e:
        return jsonify([f"FAIL: {str(e)}"])

# --- 3. TRAFFIC INTERCEPTOR (NEW) ---
@app.route('/api/sniff')
def sniff_traffic():
    try:
        # Listen on ANY interface for 10 seconds.
        # Filter: Port 80 (HTTP), 21 (FTP), 23 (Telnet)
        # -n: No DNS resolution (faster)
        # -q: Quiet (less header noise)
        cmd = "sudo timeout 10 tcpdump -n -q -i any 'port 80 or port 21 or port 23' 2>&1"
        
        try:
            output = subprocess.check_output(cmd, shell=True).decode('utf-8')
        except subprocess.CalledProcessError as e:
            # timeout command exits with 124, which python considers an error. We catch it here.
            output = e.output.decode('utf-8')

        results = []
        unique_flows = set()

        for line in output.split('\n'):
            if "tcpdump" in line or not line: continue
            
            # Line format roughly: "IP 192.168.1.5.5543 > 1.1.1.1.80: tcp 0"
            parts = line.split(' ')
            if len(parts) > 4:
                try:
                    # Extract Source and Dest
                    src = parts[2]
                    dst = parts[4].rstrip(':')
                    
                    # Identify Protocol
                    proto = "UNK"
                    if ".80" in dst or ".80" in src: proto = "HTTP (CLEAR)"
                    elif ".21" in dst or ".21" in src: proto = "FTP (RISK)"
                    elif ".23" in dst or ".23" in src: proto = "TELNET (RISK)"
                    
                    # Create a unique key so we don't spam the log with the same packet
                    flow_key = f"{src}->{dst}"
                    if flow_key not in unique_flows:
                        unique_flows.add(flow_key)
                        results.append(f"[{proto}]\n{src} -> {dst}")
                except:
                    continue

        if not results:
            results.append("SECURE: No unencrypted traffic captured.")
        else:
            # Prepend a header
            results.insert(0, f"CAPTURED: {len(results)} FLOWS")

        return jsonify(results)

    except Exception as e:
        return jsonify([f"FAIL: {str(e)}"])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
