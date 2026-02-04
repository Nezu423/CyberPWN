import subprocess
import os
import re
import json
import time
import hashlib
import ipaddress
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta

from flask import Flask, Response, jsonify, request, render_template, send_from_directory, abort, session, redirect

base_dir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(base_dir, 'templates')
app = Flask(__name__, template_folder=template_dir)

_ARP_BASELINE_PATH = os.path.join(base_dir, 'arp_baseline.json')
try:
    if not os.access(base_dir, os.W_OK):
        _ARP_BASELINE_PATH = os.path.join('/tmp', 'cyberpwn_arp_baseline.json')
except Exception:
    _ARP_BASELINE_PATH = os.path.join('/tmp', 'cyberpwn_arp_baseline.json')

_KILLSWITCH_PATH = os.path.join(base_dir, 'killswitch.json')
try:
    if not os.access(base_dir, os.W_OK):
        _KILLSWITCH_PATH = os.path.join('/tmp', 'cyberpwn_killswitch.json')
except Exception:
    _KILLSWITCH_PATH = os.path.join('/tmp', 'cyberpwn_killswitch.json')

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


def _geteuid() -> int | None:
    try:
        fn = getattr(os, 'geteuid', None)
        if not callable(fn):
            return None
        return int(fn())
    except Exception:
        return None


def _cmd_exists(name: str) -> bool:
    name = (name or '').strip()
    if not name:
        return False
    r = run_capture(f"command -v {name}", timeout=2)
    if r.get('returncode') == 0 and (r.get('stdout') or '').strip():
        return True
    r2 = run_capture(f"which {name}", timeout=2)
    return bool(r2.get('returncode') == 0 and (r2.get('stdout') or '').strip())


def _has_ipv6_default_route() -> bool:
    try:
        r = run_capture("ip -6 route show default | head -1", timeout=2)
        return bool(r.get('returncode') == 0 and (r.get('stdout') or '').strip())
    except Exception:
        return False


def _run_root(cmd: str, timeout: int = 10) -> dict:
    cmd = (cmd or '').strip()
    if not cmd:
        return {'cmd': cmd, 'stdout': '', 'stderr': 'Empty command', 'returncode': -1, 'timeout': False}

    euid = _geteuid()
    if euid == 0:
        return run_capture(cmd, timeout=timeout)

    r = run_capture(f"sudo -n {cmd}", timeout=timeout)
    if r.get('returncode') == 0:
        return r

    r2 = run_capture(cmd, timeout=timeout)
    if r2.get('returncode') == 0:
        return r2
    return r


def _resolve_host_addrs(host: str) -> list[str]:
    host = (host or '').strip()
    if not host:
        return []
    addrs: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            sockaddr = info[4]
            if not sockaddr:
                continue
            ip = sockaddr[0]
            if ip and ip not in addrs:
                addrs.append(ip)
        return addrs
    except Exception:
        return []


def _is_private_or_local_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return bool(addr.is_private or addr.is_loopback or addr.is_link_local)
    except Exception:
        return False


def _require_private_target(host: str) -> tuple[bool, str, list[str]]:
    host = (host or '').strip()
    if not host:
        return False, 'Target host required', []

    if host.lower() in ('localhost',):
        return True, '', ['127.0.0.1']

    try:
        ipaddress.ip_address(host)
        ips = [host]
    except Exception:
        ips = _resolve_host_addrs(host)

    if not ips:
        return False, 'Could not resolve host', []

    private_ips: list[str] = []
    for ip in ips:
        if _is_private_or_local_ip(ip):
            private_ips.append(ip)
        else:
            return False, 'Target must be private LAN or localhost', ips[:4]

    return True, '', private_ips[:4]


def _get_default_gateway_ip() -> tuple[str | None, str | None]:
    r = run_capture("ip route | grep default | head -1", timeout=2)
    if r.get('returncode') != 0 or not (r.get('stdout') or '').strip():
        return None, 'No default gateway found'

    parts = (r.get('stdout') or '').strip().split()
    gw = None
    if 'via' in parts:
        idx = parts.index('via')
        if idx + 1 < len(parts):
            gw = parts[idx + 1].strip()
    else:
        if len(parts) >= 3:
            gw = parts[2].strip()
    if not gw:
        return None, 'Could not parse gateway'

    try:
        ipaddress.ip_address(gw)
    except Exception:
        return None, 'Invalid gateway address'
    return gw, None


def _prime_arp(ip: str) -> None:
    ip = (ip or '').strip()
    if not ip:
        return
    try:
        run_capture(f"ping -c 1 -W 1 {ip} >/dev/null 2>&1", timeout=2)
    except Exception:
        pass


def _get_proc_arp_mac(ip: str) -> str | None:
    ip = (ip or '').strip()
    if not ip:
        return None
    try:
        if not os.path.exists('/proc/net/arp'):
            return None
        with open('/proc/net/arp', 'r', encoding='utf-8', errors='replace') as f:
            lines = f.read().splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            if parts[0] != ip:
                continue
            mac = (parts[3] or '').strip()
            if re.match(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$", mac):
                return mac.lower()
        return None
    except Exception:
        return None


def _get_neighbor_mac(ip: str) -> tuple[str | None, str | None]:
    ip = (ip or '').strip()
    if not ip:
        return None, None
    mac = None

    iface = None

    r = run_capture(f"ip neigh show {ip} 2>/dev/null", timeout=2)
    out = (r.get('stdout') or '').strip()
    m = re.search(r"\bdev\s+(\S+)", out)
    if m:
        iface = m.group(1)
    m = re.search(r"\blladdr\s+([0-9A-Fa-f:]{17})", out)
    if m:
        mac = m.group(1).lower()

    if mac:
        return mac, iface

    r2 = run_capture(f"arp -n {ip} 2>/dev/null | head -1", timeout=2)
    out2 = (r2.get('stdout') or '').strip()
    m2 = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", out2)
    if m2:
        mac = m2.group(1).lower()

    if not mac:
        mac = _get_proc_arp_mac(ip)
    return mac, iface


def _arp_baseline_read() -> dict:
    try:
        if not os.path.exists(_ARP_BASELINE_PATH):
            return {}
        with open(_ARP_BASELINE_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _arp_baseline_write(data: dict) -> tuple[bool, str]:
    try:
        tmp = _ARP_BASELINE_PATH + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        os.replace(tmp, _ARP_BASELINE_PATH)
        return True, ''
    except Exception as e:
        return False, str(e)


def _ks_read() -> dict:
    try:
        if not os.path.exists(_KILLSWITCH_PATH):
            return {}
        with open(_KILLSWITCH_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _ks_write(data: dict) -> tuple[bool, str]:
    try:
        tmp = _KILLSWITCH_PATH + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        os.replace(tmp, _KILLSWITCH_PATH)
        return True, ''
    except Exception as e:
        return False, str(e)


def _ks_chain_v4() -> str:
    return 'CYBERPWN_KS'


def _ks_chain_v6() -> str:
    return 'CYBERPWN6_KS'


def _ks_applied_v4() -> bool:
    ch = _ks_chain_v4()
    if not _cmd_exists('iptables'):
        return False
    r = _run_root(f"iptables -C OUTPUT -j {ch}", timeout=3)
    return bool(r.get('returncode') == 0)


def _ks_applied_v6() -> bool:
    ch = _ks_chain_v6()
    if not _cmd_exists('ip6tables'):
        return False
    r = _run_root(f"ip6tables -C OUTPUT -j {ch}", timeout=3)
    return bool(r.get('returncode') == 0)


def _ks_apply_v4() -> tuple[bool, str]:
    ch = _ks_chain_v4()
    if not _cmd_exists('iptables'):
        return False, 'iptables not found'

    _run_root(f"iptables -N {ch}", timeout=3)
    _run_root(f"iptables -F {ch}", timeout=3)

    allow = [
        '127.0.0.0/8',
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '169.254.0.0/16',
        '224.0.0.0/4',
    ]
    for cidr in allow:
        _run_root(f"iptables -A {ch} -d {cidr} -j RETURN", timeout=3)
    _run_root(f"iptables -A {ch} -j DROP", timeout=3)

    if not _ks_applied_v4():
        r = _run_root(f"iptables -I OUTPUT 1 -j {ch}", timeout=3)
        if r.get('returncode') != 0:
            return False, (r.get('stderr') or r.get('stdout') or 'iptables insert failed')
    return True, ''


def _ks_apply_v6() -> tuple[bool, str]:
    ch = _ks_chain_v6()
    if not _cmd_exists('ip6tables'):
        return True, 'ip6tables not found (skipping v6)'

    _run_root(f"ip6tables -N {ch}", timeout=3)
    _run_root(f"ip6tables -F {ch}", timeout=3)

    allow = [
        '::1/128',
        'fe80::/10',
        'fc00::/7',
    ]
    for cidr in allow:
        _run_root(f"ip6tables -A {ch} -d {cidr} -j RETURN", timeout=3)
    _run_root(f"ip6tables -A {ch} -j DROP", timeout=3)

    if not _ks_applied_v6():
        r = _run_root(f"ip6tables -I OUTPUT 1 -j {ch}", timeout=3)
        if r.get('returncode') != 0:
            return False, (r.get('stderr') or r.get('stdout') or 'ip6tables insert failed')
    return True, ''


def _ks_apply() -> tuple[bool, dict]:
    ok4, err4 = _ks_apply_v4()
    ok6, err6 = _ks_apply_v6()
    ipv6_default = _has_ipv6_default_route()
    ipv6_disabled = False
    ipv6_disable_err = ''

    if ipv6_default and (not _cmd_exists('ip6tables')):
        if not _cmd_exists('sysctl'):
            ok6 = False
            err6 = 'IPv6 default route present but ip6tables not found; sysctl not available to disable IPv6'
        else:
            prev_all = (run_capture('sysctl -n net.ipv6.conf.all.disable_ipv6', timeout=2).get('stdout') or '').strip()
            prev_def = (run_capture('sysctl -n net.ipv6.conf.default.disable_ipv6', timeout=2).get('stdout') or '').strip()
            r1 = _run_root('sysctl -w net.ipv6.conf.all.disable_ipv6=1', timeout=3)
            r2 = _run_root('sysctl -w net.ipv6.conf.default.disable_ipv6=1', timeout=3)
            if r1.get('returncode') == 0 and r2.get('returncode') == 0:
                ipv6_disabled = True
                cur = _ks_read()
                cur['ipv6_disabled'] = True
                cur['ipv6_prev_all'] = prev_all
                cur['ipv6_prev_default'] = prev_def
                _ks_write(cur)
            else:
                ipv6_disable_err = (r1.get('stderr') or r1.get('stdout') or '').strip()
                if not ipv6_disable_err:
                    ipv6_disable_err = (r2.get('stderr') or r2.get('stdout') or '').strip()
                ok6 = False
                err6 = 'IPv6 default route present but ip6tables not found; failed to disable IPv6 via sysctl'

    return bool(ok4 and ok6), {
        'v4_ok': ok4,
        'v4_err': err4,
        'v6_ok': ok6,
        'v6_err': err6,
        'ipv6_default_route': ipv6_default,
        'ipv6_disabled': ipv6_disabled,
        'ipv6_disable_err': ipv6_disable_err,
    }


def _ks_disable() -> tuple[bool, dict]:
    ch4 = _ks_chain_v4()
    ch6 = _ks_chain_v6()


    if _cmd_exists('iptables'):
        _run_root(f"iptables -D OUTPUT -j {ch4}", timeout=3)
        _run_root(f"iptables -F {ch4}", timeout=3)
        _run_root(f"iptables -X {ch4}", timeout=3)

    if _cmd_exists('ip6tables'):
        _run_root(f"ip6tables -D OUTPUT -j {ch6}", timeout=3)
        _run_root(f"ip6tables -F {ch6}", timeout=3)
        _run_root(f"ip6tables -X {ch6}", timeout=3)

    ipv6_restored = False
    ipv6_restore_err = ''
    ks = _ks_read()
    if ks.get('ipv6_disabled') and _cmd_exists('sysctl'):
        prev_all = str(ks.get('ipv6_prev_all') or '0').strip()
        prev_def = str(ks.get('ipv6_prev_default') or '0').strip()
        if prev_all not in ('0', '1'):
            prev_all = '0'
        if prev_def not in ('0', '1'):
            prev_def = '0'
        r1 = _run_root(f"sysctl -w net.ipv6.conf.all.disable_ipv6={prev_all}", timeout=3)
        r2 = _run_root(f"sysctl -w net.ipv6.conf.default.disable_ipv6={prev_def}", timeout=3)
        if r1.get('returncode') == 0 and r2.get('returncode') == 0:
            ipv6_restored = True
            ks['ipv6_disabled'] = False
            _ks_write(ks)
        else:
            ipv6_restore_err = (r1.get('stderr') or r1.get('stdout') or '').strip()
            if not ipv6_restore_err:
                ipv6_restore_err = (r2.get('stderr') or r2.get('stdout') or '').strip()

    return True, {
        'v4_applied': _ks_applied_v4(),
        'v6_applied': _ks_applied_v6(),
        'ipv6_restored': ipv6_restored,
        'ipv6_restore_err': ipv6_restore_err,
    }


@app.route('/api/killswitch', methods=['POST'])
def api_killswitch() -> Response:
    try:
        data = request.get_json(force=True, silent=True) or {}
        action = (data.get('action') or '').strip().lower()
        if action not in ('enable', 'disable', 'status', 'set_auto'):
            return jsonify({'ok': False, 'error': 'Invalid action'}), 400

        if action == 'enable':
            ok, details = _ks_apply()
            if not ok:
                return jsonify({'ok': False, 'error': details}), 500
            cur = _ks_read()
            cur['enabled'] = True
            cur['auto'] = bool(cur.get('auto', False))
            _ks_write(cur)
            return jsonify({'ok': True, 'enabled': True, 'details': details})

        if action == 'disable':
            ok, details = _ks_disable()
            if not ok:
                return jsonify({'ok': False, 'error': details}), 500
            cur = _ks_read()
            cur['enabled'] = False
            cur['auto'] = bool(cur.get('auto', False))
            _ks_write(cur)
            return jsonify({'ok': True, 'enabled': False, 'details': details})

        if action == 'set_auto':
            auto_val = data.get('auto')
            auto = bool(auto_val) if isinstance(auto_val, bool) else (str(auto_val).lower() in ('true', '1', 'yes', 'on'))
            current = _ks_read()
            current['auto'] = auto
            _ks_write(current)
            return jsonify({'ok': True, 'auto': auto})

        if action == 'status':
            ks_data = _ks_read()
            enabled = ks_data.get('enabled', False)
            auto = ks_data.get('auto', False)
            v4_applied = _ks_applied_v4()
            v6_applied = _ks_applied_v6()
            sudo_n = run_capture('sudo -n true', timeout=2)
            return jsonify({
                'ok': True,
                'enabled': enabled,
                'auto': auto,
                'v4_applied': v4_applied,
                'v6_applied': v6_applied,
                'diag': {
                    'euid': _geteuid(),
                    'sudo_n_ok': bool(sudo_n.get('returncode') == 0),
                    'sudo_n_err': (sudo_n.get('stderr') or sudo_n.get('stdout') or '').strip()[:200],
                    'iptables_exists': _cmd_exists('iptables'),
                    'ip6tables_exists': _cmd_exists('ip6tables'),
                    'ipv6_default_route': _has_ipv6_default_route(),
                    'ipv6_disabled': bool(ks_data.get('ipv6_disabled')),
                }
            })

        return jsonify({'ok': False, 'error': 'Unhandled action'}), 400
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/url_sniffer', methods=['POST'])
def api_url_sniffer() -> Response:
    try:
        data = request.get_json(force=True, silent=True) or {}
        raw_url = (data.get('url') or '').strip()
        if not raw_url:
            return jsonify({'ok': False, 'error': 'URL required'}), 400
        if '://' not in raw_url:
            raw_url = 'http://' + raw_url

        parts = urllib.parse.urlsplit(raw_url)
        if parts.scheme not in ('http', 'https'):
            return jsonify({'ok': False, 'error': 'Only http/https supported'}), 400
        if not parts.hostname:
            return jsonify({'ok': False, 'error': 'Invalid URL'}), 400

        ok, err, resolved = _require_private_target(parts.hostname)
        if not ok:
            return jsonify({'ok': False, 'error': err, 'resolved': resolved}), 400

        base = urllib.parse.urlunsplit((parts.scheme, parts.netloc, '', '', ''))
        timeout_s = 3
        max_checks = 40
        ctx = ssl._create_unverified_context()

        seed_paths = [
                # --- Exact Files (High Value) ---
            '/robots.txt',
            '/sitemap.xml',
            '/.env',
            '/.env.example',
            '/config.php',
            '/web.config',
            '/docker-compose.yml',
            '/package.json',
            '/server.js',
            '/app.py',
            '/settings.py',
            '/database.yml',
            '/.git/HEAD',
            '/.git/config',
            '/.ssh/id_rsa',
            '/backup.zip',
            '/backup.sql',
            '/dump.sql',
            '/users.sql',
            '/error.log',
            '/access.log',
            '/phpinfo.php',

            # --- Specific Endpoints (No trailing slash) ---
            '/admin',
            '/administrator',
            '/login',
            '/register',
            '/dashboard',
            '/cpanel',
            '/whm',
            '/phpmyadmin',
            '/metrics',
            '/health',
            '/status',
            '/api',
            '/swagger',
            '/graphql',
            '/shell',
            '/console',
            '/update',
            '/install',
            '/setup',

            # --- API & Docs Specifics ---
            '/swagger-ui.html',
            '/swagger.json',
            '/api/v1',
            '/api/v2',
            '/api/docs',

            # --- Framework Specifics ---
            '/actuator/env',
            '/actuator/heapdump',
            '/.well-known/security.txt',
            '/.well-known/apple-app-site-association'
        ]

        extra_paths: list[str] = []
        try:
            r = urllib.request.urlopen(base + '/robots.txt', timeout=timeout_s, context=ctx)
            body = (r.read(4096) or b'').decode('utf-8', errors='replace')
            for line in body.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.lower().startswith('disallow:'):
                    p = line.split(':', 1)[1].strip()
                    if p and p.startswith('/') and p not in extra_paths:
                        extra_paths.append(p)
                        if len(extra_paths) >= 20:
                            break
        except Exception:
            pass

        paths: list[str] = []
        for p in seed_paths + extra_paths:
            if p not in paths:
                paths.append(p)
            if len(paths) >= max_checks:
                break

        results = []
        for p in paths:
            target = base + p
            status = None
            found = False
            location = None

            try:
                req = urllib.request.Request(target)
                req.get_method = lambda: 'HEAD'
                resp = urllib.request.urlopen(req, timeout=timeout_s, context=ctx)
                status = int(resp.getcode() or 0)
                location = resp.headers.get('Location')
            except urllib.error.HTTPError as he:
                status = int(getattr(he, 'code', 0) or 0)
                location = he.headers.get('Location') if getattr(he, 'headers', None) else None
                if status == 405:
                    try:
                        resp2 = urllib.request.urlopen(target, timeout=timeout_s, context=ctx)
                        status = int(resp2.getcode() or 0)
                        location = resp2.headers.get('Location')
                        resp2.read(256)
                    except urllib.error.HTTPError as he2:
                        status = int(getattr(he2, 'code', 0) or 0)
                        location = he2.headers.get('Location') if getattr(he2, 'headers', None) else None
                    except Exception:
                        pass
            except Exception:
                status = None

            if status is not None:
                if 200 <= status < 400 or status in (401, 403):
                    found = True

            results.append({
                'path': p,
                'url': target,
                'status': status,
                'found': found,
                'location': location,
            })

        found_only = [r for r in results if r.get('found')]
        return jsonify({
            'ok': True,
            'base': base,
            'resolved': resolved,
            'checked': len(results),
            'found': found_only,
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/port_audit', methods=['POST'])
def api_port_audit() -> Response:
    try:
        data = request.get_json(force=True, silent=True) or {}
        host = (data.get('host') or '').strip()
        if not host:
            return jsonify({'ok': False, 'error': 'Host required'}), 400

        ok, err, resolved = _require_private_target(host)
        if not ok:
            return jsonify({'ok': False, 'error': err, 'resolved': resolved}), 400

        ports = [
            (22, 'SSH'),
            (23, 'TELNET'),
            (21, 'FTP'),
            (80, 'HTTP'),
            (443, 'HTTPS'),
            (445, 'SMB'),
            (3389, 'RDP'),
            (5900, 'VNC'),
        ]

        timeout_s = 0.8
        ips = resolved or _resolve_host_addrs(host)
        if not ips:
            ips = [host]
        ips = ips[:2]

        results = []
        for port, label in ports:
            state = 'closed'
            used_ip = ips[0]
            for ip in ips:
                used_ip = ip
                try:
                    fam = socket.AF_INET6 if ':' in ip else socket.AF_INET
                    s = socket.socket(fam, socket.SOCK_STREAM)
                    s.settimeout(timeout_s)
                    rc = s.connect_ex((ip, int(port)))
                    s.close()
                    if rc == 0:
                        state = 'open'
                        break
                except socket.timeout:
                    state = 'timeout'
                except Exception:
                    state = 'error'
            results.append({'port': port, 'service': label, 'state': state, 'ip': used_ip})

        return jsonify({'ok': True, 'host': host, 'resolved': ips, 'results': results})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


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
        mac_match = re.search(r"link/ether\s+([0-9a-f:]+)", result.get('stdout', ''), re.I)
        if mac_match:
            status['mac'] = mac_match.group(1).upper()
        # Get IP address
        result = run_capture(f"ip addr show {iface} 2>/dev/null | grep 'inet '", timeout=2)
        if result.get('returncode') == 0:
            ip_match = re.search(r"inet\s+([0-9.]+)", result.get('stdout', ''))
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


@app.route('/api/interfaces/status', methods=['GET'])
def api_interfaces_status() -> Response:
    try:
        return jsonify({'ok': True, 'interfaces': get_all_interfaces()})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/interfaces/<iface>/up', methods=['POST'])
def api_iface_up(iface: str) -> Response:
    try:
        iface = _validate_iface_or_400(iface)
        r = _run_root(f"ip link set dev {iface} up", timeout=4)
        if r.get('returncode') != 0:
            return jsonify({'ok': False, 'error': (r.get('stderr') or r.get('stdout') or 'Failed'), 'cmd': r.get('cmd')}), 500
        return jsonify({'ok': True, 'iface': iface})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/interfaces/<iface>/down', methods=['POST'])
def api_iface_down(iface: str) -> Response:
    try:
        iface = _validate_iface_or_400(iface)
        r = _run_root(f"ip link set dev {iface} down", timeout=4)
        if r.get('returncode') != 0:
            return jsonify({'ok': False, 'error': (r.get('stderr') or r.get('stdout') or 'Failed'), 'cmd': r.get('cmd')}), 500
        return jsonify({'ok': True, 'iface': iface})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/scan_wifi_list', methods=['GET'])
def api_scan_wifi_list() -> Response:
    try:
        if not _cmd_exists('nmcli'):
            return jsonify({'ok': False, 'error': 'nmcli not found'}), 500

        r = run_capture("nmcli -t --separator '|' -f SSID,SIGNAL dev wifi list", timeout=10)
        if r.get('returncode') != 0:
            return jsonify({'ok': False, 'error': 'nmcli scan failed', 'stdout': r.get('stdout', ''), 'stderr': r.get('stderr', '')}), 500

        out = (r.get('stdout') or '').splitlines()
        nets = []
        for line in out:
            line = (line or '').strip()
            if not line:
                continue
            parts = line.split('|')
            ssid = (parts[0] or '').strip() if len(parts) > 0 else ''
            sig = (parts[1] or '').strip() if len(parts) > 1 else ''
            try:
                sig_i = int(sig)
            except Exception:
                sig_i = None
            nets.append({'ssid': ssid, 'signal': sig_i})
            if len(nets) >= 12:
                break

        return jsonify(nets)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


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
    if filename in ('wifi.html', 'network.html'):
        abort(404)
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


@app.route('/api/arp_spoof/status')
def api_arp_spoof_status() -> Response:
    try:
        gw, err = _get_default_gateway_ip()
        if not gw:
            return jsonify({'ok': False, 'error': err or 'Gateway not found'}), 400
        _prime_arp(gw)
        mac, iface = _get_neighbor_mac(gw)

        baseline = _arp_baseline_read()
        base_ip = (baseline.get('gateway_ip') or '').strip() if isinstance(baseline, dict) else ''
        base_mac = (baseline.get('gateway_mac') or '').strip().lower() if isinstance(baseline, dict) else ''

        mismatch = False
        status = 'unknown'
        if not base_mac:
            status = 'no_baseline'
        else:
            status = 'ok'
            if base_ip and base_ip != gw:
                status = 'alert'
                mismatch = True
            if mac and base_mac and mac.lower() != base_mac.lower():
                status = 'alert'
                mismatch = True

        return jsonify({
            'ok': True,
            'gateway_ip': gw,
            'gateway_mac': mac,
            'gateway_iface': iface,
            'baseline_path': _ARP_BASELINE_PATH,
            'baseline_ip': base_ip or None,
            'baseline_mac': base_mac or None,
            'status': status,
            'mismatch': mismatch,
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/arp_spoof/baseline/set', methods=['POST'])
def api_arp_spoof_baseline_set() -> Response:
    try:
        gw, err = _get_default_gateway_ip()
        if not gw:
            return jsonify({'ok': False, 'error': err or 'Gateway not found'}), 400

        _prime_arp(gw)
        mac = None
        iface = None
        tries = 0
        while tries < 4 and not mac:
            mac, iface = _get_neighbor_mac(gw)
            if mac:
                break
            _prime_arp(gw)
            time.sleep(0.25)
            tries += 1

        if not mac:
            neigh = run_capture(f"ip neigh show {gw} 2>/dev/null", timeout=2)
            arp = run_capture(f"arp -n {gw} 2>/dev/null | head -2", timeout=2)
            proc_mac = _get_proc_arp_mac(gw)
            return jsonify({
                'ok': False,
                'error': 'Could not read gateway MAC (try again after some traffic)',
                'gateway_ip': gw,
                'baseline_path': _ARP_BASELINE_PATH,
                'debug': {
                    'ip_neigh': (neigh.get('stdout') or neigh.get('stderr') or '').strip()[:300],
                    'arp': (arp.get('stdout') or arp.get('stderr') or '').strip()[:300],
                    'proc_arp_mac': proc_mac,
                }
            }), 400

        data = {
            'gateway_ip': gw,
            'gateway_mac': mac,
            'gateway_iface': iface,
            'set_at': int(time.time()),
        }
        ok_w, err_w = _arp_baseline_write(data)
        if not ok_w:
            return jsonify({'ok': False, 'error': 'Failed to write baseline', 'baseline_path': _ARP_BASELINE_PATH, 'debug': {'write_error': err_w}}), 500
        return jsonify({'ok': True, 'baseline': data, 'baseline_path': _ARP_BASELINE_PATH})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/arp_spoof/baseline/clear', methods=['POST'])
def api_arp_spoof_baseline_clear() -> Response:
    try:
        try:
            if os.path.exists(_ARP_BASELINE_PATH):
                os.remove(_ARP_BASELINE_PATH)
        except Exception:
            ok_w, err_w = _arp_baseline_write({})
            if not ok_w:
                return jsonify({'ok': False, 'error': 'Failed to clear baseline', 'baseline_path': _ARP_BASELINE_PATH, 'debug': {'write_error': err_w}}), 500
        return jsonify({'ok': True, 'baseline_path': _ARP_BASELINE_PATH})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/arp_spoof/watch', methods=['GET'])
def api_arp_spoof_watch() -> Response:
    try:
        baseline = _arp_baseline_read()
        gw, err = _get_default_gateway_ip()
        if not gw:
            return jsonify({'ok': False, 'error': err or 'Gateway not found'}), 400

        base_mac = (baseline.get('gateway_mac') or '').strip().lower() if isinstance(baseline, dict) else ''
        iface = (baseline.get('gateway_iface') or '').strip() if isinstance(baseline, dict) else ''

        try:
            seconds = int((request.args.get('seconds') or '3').strip())
        except Exception:
            seconds = 3
        if seconds < 1:
            seconds = 1
        if seconds > 6:
            seconds = 6

        _prime_arp(gw)

        if not _cmd_exists('tcpdump'):
            return jsonify({'ok': False, 'error': 'tcpdump not found', 'debug': {'tcpdump_exists': False}}), 500
        if not _cmd_exists('timeout'):
            return jsonify({'ok': False, 'error': 'timeout not found', 'debug': {'timeout_exists': False}}), 500

        if iface:
            cmd = f"timeout {seconds}s tcpdump -n -e -l -i {iface} arp"
        else:
            cmd = f"timeout {seconds}s tcpdump -n -e -l -i any arp"

        cap = _run_root(cmd, timeout=seconds + 4)
        out = (cap.get('stdout') or '').splitlines()
        err = (cap.get('stderr') or '').splitlines()

        reply_re = re.compile(r"\bReply\s+(\d+\.\d+\.\d+\.\d+)\s+is-at\s+([0-9A-Fa-f:]{17})\b")
        seen_macs = []
        seen_set = set()
        for line in out:
            m = reply_re.search(line)
            if not m:
                continue
            ip = m.group(1)
            mac = (m.group(2) or '').lower()
            if ip != gw:
                continue
            if mac and mac not in seen_set:
                seen_set.add(mac)
                seen_macs.append(mac)

        alert = False
        reason = None
        if base_mac:
            for mac in seen_macs:
                if mac != base_mac:
                    alert = True
                    reason = 'Observed ARP reply claiming gateway IP from unexpected MAC'
                    break
        else:
            if len(seen_macs) > 1:
                alert = True
                reason = 'Observed multiple MACs claiming gateway IP'

        ks_applied = False
        ks_auto = False
        if alert:
            ks_data = _ks_read()
            ks_auto = ks_data.get('auto', False)
            if ks_auto and not _ks_applied_v4():
                ok, _ = _ks_apply()
                ks_applied = ok

        return jsonify({
            'ok': True,
            'gateway_ip': gw,
            'baseline_mac': base_mac or None,
            'iface': iface or None,
            'seconds': seconds,
            'seen_macs': seen_macs,
            'alert': alert,
            'reason': reason,
            'ks_auto': ks_auto,
            'ks_applied': ks_applied,
            'diag': {
                'euid': _geteuid(),
                'tcpdump_exists': _cmd_exists('tcpdump'),
                'timeout_exists': _cmd_exists('timeout'),
            },
            'sample': out[:20],
            'stderr': err[:20],
            'cmd': cmd,
            'rc': cap.get('returncode'),
        })
    except Exception as e:
        return jsonify({'error': str(e)})


# --- Packet Sniffing (using tcpdump/tshark) ---
def beacon_sniff():
    """Capture and parse WiFi beacon frames to extract SSIDs."""
    try:
        note = ''
        last_err = {'stdout': '', 'stderr': ''}

        cmds = [
            
            "nmcli -t -f SSID,BSSID,SIGNAL,CHAN,SECURITY dev wifi list",
        ]
        r = None
        for cmd in cmds:
            rr = run_capture(cmd, timeout=10)
            last_err = {'stdout': rr.get('stdout', ''), 'stderr': rr.get('stderr', '')}
            if rr.get('returncode') == 0 and (rr.get('stdout') or '').strip():
                r = rr
                note = 'Managed-mode scan'
                break

        has_bssid = True
        if r is None:
            has_bssid = False
            rr = run_capture("nmcli -t -f SSID,SIGNAL,CHAN,SECURITY dev wifi list", timeout=10)
            last_err = {'stdout': rr.get('stdout', ''), 'stderr': rr.get('stderr', '')}
            if rr.get('returncode') != 0:
                return {'ok': False, 'error': 'nmcli scan failed', 'stdout': rr.get('stdout', ''), 'stderr': rr.get('stderr', '')}
            if not (rr.get('stdout') or '').strip():
                return {'ok': False, 'error': 'nmcli returned no results', 'stdout': rr.get('stdout', ''), 'stderr': rr.get('stderr', '')}
            r = rr
            note = 'Managed-mode scan (no BSSID)'

        aps = []
        ssids = []
        seen_key = set()

        bssid_re = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")

        for line in (r.get('stdout') or '').split('\n'):
            line = (line or '').strip()
            if not line:
                continue

            ssid = ''
            bssid = ''
            signal = ''
            chan = ''
            sec = ''

            if has_bssid:
                if '|' in line:
                    parts = line.split('|')
                    if len(parts) < 2:
                        continue
                    ssid = (parts[0] or '').strip()
                    bssid = (parts[1] or '').strip().lower()
                    signal = (parts[2] or '').strip() if len(parts) > 2 else ''
                    chan = (parts[3] or '').strip() if len(parts) > 3 else ''
                    sec = (parts[4] or '').strip() if len(parts) > 4 else ''
                    if len(parts) > 5:
                        sec = ('|'.join(parts[4:]) or '').strip()
                else:
                    m = bssid_re.search(line)
                    if not m:
                        continue
                    bssid = (m.group(1) or '').strip().lower()
                    ssid = (line[:m.start()] or '').rstrip(':').strip()
                    tail = (line[m.end():] or '')
                    if tail.startswith(':'):
                        tail = tail[1:]
                    tail_parts = tail.split(':')
                    signal = (tail_parts[0] or '').strip() if len(tail_parts) > 0 else ''
                    chan = (tail_parts[1] or '').strip() if len(tail_parts) > 1 else ''
                    sec = (':'.join(tail_parts[2:]) or '').strip() if len(tail_parts) > 2 else ''

                if not re.match(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$", bssid or ''):
                    continue
            else:
                if '|' in line:
                    parts = line.split('|')
                else:
                    parts = line.split(':')
                if len(parts) < 1:
                    continue
                ssid = (parts[0] or '').strip()
                signal = (parts[1] or '').strip() if len(parts) > 1 else ''
                chan = (parts[2] or '').strip() if len(parts) > 2 else ''
                sec = (':'.join(parts[3:]) or '').strip() if len(parts) > 3 else ''
                bssid = None

            sig_i = None
            try:
                sig_i = int(signal)
            except Exception:
                sig_i = None
            rssi = None
            if sig_i is not None:
                if sig_i < 0:
                    sig_i = 0
                if sig_i > 100:
                    sig_i = 100
                rssi = int((sig_i / 2) - 100)

            key = (bssid or '') + '|' + (ssid or '')
            if key in seen_key:
                continue
            seen_key.add(key)

            aps.append({
                'ssid': ssid,
                'bssid': bssid,
                'signal': sig_i,
                'rssi': rssi,
                'channel': chan,
                'security': sec,
            })

            if ssid and ssid not in ssids:
                ssids.append(ssid)
            if len(aps) >= 20:
                break

        return {
            'ok': True,
            'ssids': ssids,
            'count': len(aps),
            'aps': aps,
            'note': note,
            'diag': {
                'has_bssid': has_bssid,
                'stderr': (last_err.get('stderr') or '')[:300],
            }
        }
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
 