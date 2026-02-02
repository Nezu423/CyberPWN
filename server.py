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
    return render_template('wifi.html') # Serving the specific wifi file

@app.route('/<path:filename>')
def serve_page(filename):
    return render_template(filename)

# --- 1. CLEAN SSID SCANNER ---
@app.route('/api/scan_wifi')
def scan_wifi():
    try:
        # Scan for SSID, Signal, and Security
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
                
                # Check for WPA/WEP vs Open
                security_field = parts[2] if len(parts) > 2 else ""
                sec = "SECURE" if "WPA" in security_field or "RSN" in security_field else "OPEN"
                
                # Format: "Name (Signal%) [SEC]"
                results.append(f"{ssid[:12].ljust(12)} {parts[1]}% {sec}")

        return jsonify(results[:15])
    except Exception as e:
        return jsonify([f"ERROR: {str(e)}"])

# --- 2. VULNERABILITY MONITOR (High-Risk Ports) ---
@app.route('/api/nmap', strict_slashes=False)
def nmap_scan():
    try:
        # 1. Get Local Subnet
        # hostname -I usually returns "192.168.1.15 ..."
        my_ip_raw = subprocess.check_output("hostname -I", shell=True).decode('utf-8').strip()
        if not my_ip_raw: return jsonify(["ERROR: No Network"])
        
        my_ip = my_ip_raw.split(' ')[0]
        # Create subnet 192.168.1.0/24
        subnet = f"{'.'.join(my_ip.split('.')[:3])}.0/24"
        
        print(f"[LOG] Scanning Danger Ports on {subnet}")
        
        # 2. RUN STEALTH SCAN (-sS) ON DANGER PORTS
        # 21=FTP, 23=Telnet, 445=SMB(Windows), 3389=RDP, 8080=AltWeb
        # --open: Only show devices with these holes open
        cmd = f"sudo nmap -sS -p 21,23,445,3389,8080 --open -n {subnet} --exclude {my_ip}"
        
        output = subprocess.check_output(cmd, shell=True).decode('utf-8')
        
        # 3. Clean Output
        clean_res = []
        clean_res.append(f"TARGET: {subnet}")
        
        current_ip = ""
        found_vuln = False
        
        for line in output.split('\n'):
            # Detect IP Line
            if "scan report" in line:
                current_ip = line.split("for ")[1]
            
            # Detect Open Port Line
            if "open" in line and "tcp" in line:
                found_vuln = True
                # Line example: "445/tcp open  microsoft-ds"
                parts = line.split() # Splits by any whitespace
                port = parts[0].split('/')[0] # Get 445
                service = parts[-1] # Get service name (last item)
                
                clean_res.append(f"{current_ip} > {port} ({service})")

        if not found_vuln:
            clean_res.append("SECURE: No vulnerable ports found.")
            
        return jsonify(clean_res)

    except Exception as e:
        return jsonify([f"FAIL: {str(e)}"])

if __name__ == '__main__':
    # Listen on all interfaces
    app.run(host='0.0.0.0', port=5000)
