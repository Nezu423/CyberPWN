import subprocess
import os
import re
import hashlib
from datetime import timedelta

from flask import Flask, Response, jsonify, request, render_template, send_from_directory, abort, session, redirect

base_dir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(base_dir, 'templates')
app = Flask(__name__, template_folder=template_dir)

app.secret_key = hashlib.sha256((base_dir + ":" + "cyberpwn").encode()).hexdigest()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

PIN_SHA256 = hashlib.sha256("062823".encode()).hexdigest()

_UNAUTH_API_PATHS = {
    '/api/verify_pin',
}

_IFACE_RE: re.Pattern[str] = re.compile(r'^[a-zA-Z0-9_.:-]{1,20}$')


def _validate_iface_or_400(iface: str) -> str:
    iface = (iface or '').strip()
    if not _IFACE_RE.match(iface):
        abort(400)
    return iface


@app.before_request
def enforce_auth():
    path = request.path or ''
    if path.startswith('/api/'):
        if path in _UNAUTH_API_PATHS:
            return None
        if not session.get('auth'):
            return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return None

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
    return interfaces

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
            session['auth'] = True
            session.permanent = True
            return jsonify({"ok": True})
        else:
            return jsonify({"ok": False, "error": "Invalid PIN"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# --- Basic Routes ---
@app.route('/')
def home():
    if session.get('auth'):
        return redirect('/success.html')
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
    if filename != 'index.html' and not session.get('auth'):
        return redirect('/')
    template_path = os.path.join(app.template_folder, filename)
    if not os.path.exists(template_path):
        abort(404)
    return render_template(filename)

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
            bssid: str = bssid_match.group(1).upper() if bssid_match else ""
            
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

# --- Interface Management ---
@app.route('/api/interfaces/status')
def interfaces_status() -> Response:
    """Get status of all network interfaces."""
    try:
        interfaces = get_all_interfaces()
        return jsonify({
            'ok': True,
            'interfaces': interfaces,
        })

    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/interfaces/<iface>/up', methods=['POST'])
def interface_up(iface) -> Response:
    """Bring interface up."""
    try:
        iface = _validate_iface_or_400(iface)
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
        iface = _validate_iface_or_400(iface)
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

# --- Packet Sniffing (using tcpdump/tshark) ---
def beacon_sniff():
    """Capture and parse WiFi beacon frames to extract SSIDs."""
    try:
        r = run_capture("nmcli -t -f SSID,SIGNAL,CHAN,SECURITY dev wifi list 2>/dev/null", timeout=10)
        if r.get('returncode') != 0:
            return {'ok': False, 'error': 'nmcli scan failed', 'stdout': r.get('stdout', ''), 'stderr': r.get('stderr', '')}
        ssids = []
        seen = set()
        for line in (r.get('stdout') or '').split('\n'):
            if not line:
                continue
            parts = line.split(':')
            if not parts:
                continue
            ssid = (parts[0] or '').strip()
            if not ssid or ssid in seen:
                continue
            seen.add(ssid)
            ssids.append(ssid)
            if len(ssids) >= 20:
                break
        return {'ok': True, 'ssids': ssids, 'count': len(ssids), 'note': 'Managed-mode scan'}
    except Exception as e:
        return {
            'ok': False,
            'error': str(e),
            'cmd': cmd if 'cmd' in locals() else None,
            'stdout': result.get('stdout', '') if 'result' in locals() else '',
            'stderr': result.get('stderr', '') if 'result' in locals() else ''
        }

def channel_analyzer():
    """Analyze WiFi channels using iwlist."""
    try:
        cmd = "sudo iwlist wlan0 channel 2>/dev/null"
        result = run_capture(cmd, timeout=5)
        if result.get('returncode') != 0:
            return {'ok': False, 'error': 'iwlist failed - interface may not support channel scanning', 'cmd': cmd, 'stdout': result.get('stdout', ''), 'stderr': result.get('stderr', '')}
        lines = [l.strip() for l in result.get('stdout', '').splitlines() if l.strip()]
        return {'ok': True, 'channels': lines}
    except Exception as e:
        return {'ok': False, 'error': str(e), 'cmd': cmd if 'cmd' in locals() else None, 'stdout': result.get('stdout', '') if 'result' in locals() else '', 'stderr': result.get('stderr', '') if 'result' in locals() else ''}

# --- Sniffer API Routes ---
@app.route('/api/sniffer/beacon', methods=['POST'])
def sniffer_beacon() -> Response:
    return jsonify(beacon_sniff())

@app.route('/api/sniffer/channel_analyzer', methods=['POST'])
def sniffer_channel_analyzer() -> Response:
    return jsonify(channel_analyzer())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
