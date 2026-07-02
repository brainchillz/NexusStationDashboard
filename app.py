#!/usr/bin/env python3
import os
import re
import json
import time
import hmac
import socket
import hashlib
import secrets
import shutil
import threading
import subprocess
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, jsonify, request, session, send_from_directory, g, Response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Dashboard version. Surfaced via /api/version and /api/me so a cluster
# controller can detect API/version skew across enrolled nodes.
APP_VERSION = '1.2.0'


def env_bool(name, default):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.lower() in ('1', 'true', 'yes', 'on')


# ─── TLS configuration ────────────────────────────────────────────────
# The dashboard serves HTTPS by default with a self-signed certificate it
# generates on first run. To use your own certificate, either drop your PEM
# files at the paths below (replacing the self-signed ones) or point
# DASHBOARD_TLS_CERT / DASHBOARD_TLS_KEY at them — or upload them from the
# Settings page in the UI. Set DASHBOARD_TLS=0 to serve plain HTTP (e.g. when a
# reverse proxy terminates TLS in front of the app).
TLS_ENABLED = env_bool('DASHBOARD_TLS', True)
# The listen port. Resolved here (not just in __main__) so request handlers can
# build self-referential URLs (e.g. the network handoff link to the new IP).
DASHBOARD_PORT = int(os.environ.get('DASHBOARD_PORT', 8443 if TLS_ENABLED else 8080))
TLS_DIR = os.environ.get('DASHBOARD_TLS_DIR', os.path.join(APP_DIR, 'certs'))
TLS_CERT = os.environ.get('DASHBOARD_TLS_CERT', os.path.join(TLS_DIR, 'dashboard.crt'))
TLS_KEY = os.environ.get('DASHBOARD_TLS_KEY', os.path.join(TLS_DIR, 'dashboard.key'))

# Session cookies are signed with secret_key (set at startup from the auth
# file). Harden the cookie: HttpOnly stops JS theft, SameSite=Lax stops the
# cookie riding along on cross-site POST/DELETE (CSRF mitigation), and Secure
# (default on whenever TLS is enabled) keeps the cookie off plaintext HTTP.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=env_bool('DASHBOARD_COOKIE_SECURE', TLS_ENABLED),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)


def run(args, input_data=None, no_sudo=False):
    """Run a command given as an argument list (NO shell).

    Passing a list and shell=False means user-supplied values can never be
    interpreted by a shell, which closes off command injection. ``sudo -n``
    is used so a missing/incorrect sudoers rule fails immediately instead of
    blocking on a password prompt.
    """
    if isinstance(args, str):
        # Only fixed, trusted command strings should be passed as strings.
        args = args.split()
    if not no_sudo:
        args = ['sudo', '-n'] + list(args)
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=120, input=input_data)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return '', 'Command timed out', -1
    except FileNotFoundError:
        return '', 'Command not found', -1


def run_safe(args, input_data=None):
    out, err, rc = run(args, input_data=input_data)
    return {'success': rc == 0, 'stdout': out, 'stderr': err, 'returncode': rc}


def err(message, code=400):
    return jsonify({'success': False, 'error': message}), code


def _size_to_bytes(s):
    """Parse a binary size string ('64.0MiB', '18.2TiB') to bytes."""
    m = re.match(r'^([\d.]+)\s*([KMGTP]?)i?B?$', (s or '').strip())
    if not m:
        return 0
    units = {'': 1, 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4, 'P': 1024**5}
    return int(float(m.group(1)) * units.get(m.group(2), 1))


def _human_bytes(n):
    n = float(n or 0)
    for u in ('B', 'K', 'M', 'G', 'T', 'P'):
        if n < 1024 or u == 'P':
            return f'{int(n)}B' if u == 'B' else f'{n:.1f}{u}'
        n /= 1024


# SMART health is expensive (one smartctl per disk), so cache the aggregate
# pass/fail for the dashboard summary rather than recompute it every refresh.
_smart_cache = {'ts': 0.0, 'ok': None}


def _smart_health_ok():
    now = time.time()
    if _smart_cache['ts'] and now - _smart_cache['ts'] < 300:
        return _smart_cache['ok']
    ok = True
    out, _, _ = run(['lsblk', '-J', '-o', 'NAME,TYPE'])
    try:
        for d in json.loads(out).get('blockdevices', []):
            if (d.get('type') or '') != 'disk':
                continue
            so, _, _ = run(['smartctl', '-H', '-j', f"/dev/{d['name']}"])
            try:
                st = json.loads(so).get('smart_status') or {}
            except json.JSONDecodeError:
                continue
            if 'passed' in st and not st['passed']:
                ok = False
    except json.JSONDecodeError:
        ok = None
    _smart_cache['ts'], _smart_cache['ok'] = now, ok
    return ok


# ─── Authentication ───────────────────────────────────────────────────
# Single-file admin tool: credentials and the session secret live in a 0600
# JSON file owned by the dashboard user. No database, in keeping with the
# project's footprint.

AUTH_FILE = os.environ.get(
    'DASHBOARD_AUTH_FILE',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'auth.json'),
)
RE_USERNAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')
MIN_PASSWORD_LEN = 8

# Append-only audit trail (who did what, when, from where). The app is
# root-equivalent and multi-user, so every state-changing request is recorded.
AUDIT_FILE = os.environ.get('DASHBOARD_AUDIT_FILE', os.path.join(APP_DIR, 'audit.log'))
AUDIT_METHODS = {'POST', 'PUT', 'DELETE', 'PATCH'}
_audit_lock = threading.Lock()

# Compared against when a username is unknown, so a missing user costs the
# same time as a wrong password (no user enumeration via timing).
_DUMMY_HASH = generate_password_hash('storage-dashboard-dummy')

# In-memory brute-force throttle, keyed by client IP.
_LOGIN_FAILS = {}
LOCKOUT_MAX = 5
LOCKOUT_WINDOW = 300  # seconds

# Endpoints reachable without a session. Everything else requires login.
# `metrics` is public so a Prometheus scraper can reach it; it has its own
# optional token gate (DASHBOARD_METRICS_TOKEN).
PUBLIC_ENDPOINTS = {'api_login', 'api_me', 'index', 'static', 'metrics',
                    'network_handoff', 'web_manifest'}


def write_json_atomic(path, data, mode=0o600):
    """Write JSON to ``path`` atomically: serialize into a temp file in the same
    directory, fsync it, then os.replace() over the target (an atomic rename on
    POSIX). A crash or full disk mid-write leaves the *original* file intact
    rather than a truncated one — critical for auth.json, where a corrupt
    credentials file would lock everyone out of the dashboard."""
    tmp = '%s.tmp.%d' % (path, os.getpid())
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def load_config():
    try:
        with open(AUTH_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_config(cfg):
    write_json_atomic(AUTH_FILE, cfg, 0o600)


# A user record is {password, role, smb}. Legacy entries were a bare hash string
# (a single admin) — treat those as role=admin for back-compat.
def _users():
    return load_config().get('users', {})

def _user_hash(rec):
    return rec if isinstance(rec, str) else (rec or {}).get('password', '')

def _user_role(rec):
    return 'admin' if isinstance(rec, str) else (rec or {}).get('role', 'admin')

def _count_admins(users):
    return sum(1 for r in users.values() if _user_role(r) == 'admin')

def _is_admin():
    # Identity (session user or API token) is resolved in require_login.
    return getattr(g, 'identity_role', None) == 'admin'


# ─── API tokens (for automation; bearer auth, no session cookie) ───────
# A token is a high-entropy secret shown once at creation; only its SHA-256 is
# stored. Each token carries a role (admin/readonly) and is enforced by the same
# before_request RBAC check as session users.
TOKEN_PREFIX = 'sd_'


def _tokens():
    return load_config().get('tokens', [])


def _hash_token(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


def _bearer_token():
    """Extract a presented API token from the request, if any."""
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:].strip()
    return (request.headers.get('X-API-Token') or '').strip()


def _resolve_token(secret):
    """Return the matching token record (constant-time compare), or None."""
    if not secret or not secret.startswith(TOKEN_PREFIX):
        return None
    h = _hash_token(secret)
    for rec in _tokens():
        if hmac.compare_digest(rec.get('hash', ''), h):
            return rec
    return None


def _touch_token(rec):
    """Record last-used at day granularity (bounds writes to once/day/token)."""
    today = datetime.now().strftime('%Y-%m-%d')
    if rec.get('last_used') == today:
        return
    cfg = load_config()
    for t in cfg.get('tokens', []):
        if t.get('id') == rec.get('id'):
            t['last_used'] = today
            save_config(cfg)
            return


def _resolve_identity():
    """Resolve the caller to (name, role) from the session cookie or an API
    token. Returns (None, None) if unauthenticated."""
    user = session.get('user')
    if user:
        return user, _user_role(_users().get(user))
    rec = _resolve_token(_bearer_token())
    if rec:
        _touch_token(rec)
        return 'token:' + rec.get('name', '?'), rec.get('role', 'readonly')
    return None, None


def ensure_bootstrap():
    """Ensure a session secret and at least one user exist. Returns the config."""
    cfg = load_config()
    changed = False
    if not cfg.get('secret_key'):
        cfg['secret_key'] = secrets.token_hex(32)
        changed = True
    if not cfg.get('users'):
        pw = os.environ.get('DASHBOARD_ADMIN_PASSWORD')
        generated = not pw
        if not pw:
            pw = secrets.token_urlsafe(12)
        cfg.setdefault('users', {})['admin'] = {'password': generate_password_hash(pw),
                                                'role': 'admin', 'smb': False,
                                                'must_change': True}
        changed = True
        if generated:
            print('=' * 64, flush=True)
            print('Storage Dashboard: created initial admin account', flush=True)
            print('  username: admin', flush=True)
            print(f'  password: {pw}', flush=True)
            print('  Change it from the UI, or: python app.py set-password admin', flush=True)
            print('=' * 64, flush=True)
    if changed:
        save_config(cfg)
    return cfg


# Mutating endpoints a non-admin (read-only) account is still allowed to call.
RBAC_EXEMPT = {'api_logout', 'change_password'}


@app.before_request
def require_login():
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    name, role = _resolve_identity()
    if not name:
        return jsonify({'success': False, 'error': 'Authentication required'}), 401
    g.identity_name = name
    g.identity_role = role
    # Role check: read-only identities may view (GET) but not change anything.
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH') and request.endpoint not in RBAC_EXEMPT:
        if role != 'admin':
            return jsonify({'success': False, 'error': 'Read-only account: action not permitted'}), 403
    return None


def audit(user, ip, method, path, target, status):
    """Append one JSON line to the audit log. Best-effort: auditing must never
    break a request, so all errors are swallowed."""
    try:
        entry = {
            'ts': datetime.now().astimezone().isoformat(timespec='seconds'),
            'user': user or '-',
            'ip': ip or '-',
            'method': method,
            'path': path,
            'target': target or {},
            'status': status,
            'result': 'ok' if 200 <= status < 300 else
                      ('denied' if status in (401, 403, 429) else 'error'),
        }
        line = json.dumps(entry, separators=(',', ':'), default=str)
        with _audit_lock:
            fd = os.open(AUDIT_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, 'a') as f:
                f.write(line + '\n')
    except Exception:
        pass


@app.after_request
def _audit_request(response):
    """Single choke point: record every state-changing request (and login
    attempts) regardless of which endpoint handled it. Runs even when
    require_login short-circuits, so denied (401/403/429) attempts are logged
    too. GETs are reads and intentionally not audited (too noisy)."""
    try:
        if request.method in AUDIT_METHODS and request.endpoint != 'static':
            # Prefer the resolved identity (session user or 'token:<name>'); on a
            # failed login fall back to the attempted username stashed by api_login.
            user = (session.get('user') or getattr(g, 'identity_name', None)
                    or getattr(g, 'audit_user', None))
            audit(user, request.remote_addr, request.method,
                  request.path, request.view_args, response.status_code)
    except Exception:
        pass
    return response


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    ip = request.remote_addr or '?'
    g.audit_user = username or '-'  # attribute the attempt even if it fails

    cnt, first = _LOGIN_FAILS.get(ip, (0, 0))
    now = time.time()
    if now - first > LOCKOUT_WINDOW:
        cnt, first = 0, now
    if cnt >= LOCKOUT_MAX:
        return jsonify({'success': False, 'error': 'Too many attempts; try again later'}), 429

    rec = load_config().get('users', {}).get(username)
    if rec and check_password_hash(_user_hash(rec), password):
        _LOGIN_FAILS.pop(ip, None)
        session.clear()
        session['user'] = username
        session.permanent = True
        return jsonify({'success': True, 'user': username, 'role': _user_role(rec),
                        'must_change': bool(isinstance(rec, dict) and rec.get('must_change')),
                        'fqdn': socket.getfqdn()})

    check_password_hash(_DUMMY_HASH, password)  # equalize timing for unknown users
    _LOGIN_FAILS[ip] = (cnt + 1, first or now)
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})


@app.route('/api/me')
def api_me():
    # Resolve via session cookie OR API token so a cluster controller can probe
    # a node with its bearer token (Test-connection at enroll). api_me is a
    # PUBLIC_ENDPOINT, so it must resolve identity itself (require_login, which
    # sets g.identity_*, is skipped for public endpoints).
    name, role = _resolve_identity()
    if not name:
        return jsonify({'authenticated': False}), 401
    # Token identities ('token:<name>') have no user record / must_change flag.
    rec = _users().get(name) if not str(name).startswith('token:') else None
    return jsonify({'authenticated': True, 'user': name, 'role': role,
                    'must_change': bool(isinstance(rec, dict) and rec.get('must_change')),
                    'fqdn': socket.getfqdn(),
                    'version': APP_VERSION,
                    'capabilities': _enabled_module_ids()})


@app.route('/api/version')
def api_version():
    """Dashboard version + identity, for controller version-skew detection.
    Authenticated (not public) — a node only reveals its version to a caller
    holding a valid session or token."""
    return jsonify({'version': APP_VERSION, 'fqdn': socket.getfqdn()})


@app.route('/api/account/password', methods=['POST'])
def change_password():
    data = request.get_json() or {}
    old = data.get('old_password') or ''
    new = data.get('new_password') or ''
    user = session.get('user')  # session-only; not applicable to API tokens
    if not user:
        return err('Only an interactive session can change a password', 401)
    cfg = load_config()
    rec = cfg.get('users', {}).get(user)
    if not rec or not check_password_hash(_user_hash(rec), old):
        return err('Current password is incorrect')
    if len(new) < MIN_PASSWORD_LEN:
        return err(f'New password must be at least {MIN_PASSWORD_LEN} characters')
    if isinstance(rec, str):
        rec = {'password': '', 'role': 'admin', 'smb': False}
    rec['password'] = generate_password_hash(new)
    rec.pop('must_change', None)  # first-run forced change satisfied
    cfg['users'][user] = rec
    save_config(cfg)
    return jsonify({'success': True})


# ─── Dashboard user management (admin only) ──────────────────────────

@app.route('/api/users')
def users_list():
    if not _is_admin():
        return err('Administrator access required', 403)
    return jsonify([{'username': n, 'role': _user_role(r),
                     'smb': bool(r.get('smb')) if isinstance(r, dict) else False}
                    for n, r in _users().items()])


@app.route('/api/audit')
def audit_list():
    """Recent audit entries (admin only), newest first."""
    if not _is_admin():
        return err('Administrator access required', 403)
    try:
        limit = max(1, min(int(request.args.get('limit', 200)), 2000))
    except (TypeError, ValueError):
        limit = 200
    entries = []
    try:
        with open(AUDIT_FILE) as f:
            for line in f.readlines()[-limit:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    entries.reverse()
    return jsonify({'entries': entries, 'count': len(entries)})


@app.route('/api/users', methods=['POST'])
def users_create():
    if not _is_admin():
        return err('Administrator access required', 403)
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    role = data.get('role', 'readonly')
    smb = bool(data.get('smb'))
    if not RE_USER.match(username):
        return err('Invalid username')
    if role not in ('admin', 'readonly'):
        return err('Invalid role')
    if not password:
        return err('Password required')
    cfg = load_config()
    cfg.setdefault('users', {})[username] = {'password': generate_password_hash(password),
                                             'role': role, 'smb': smb}
    save_config(cfg)
    if smb:  # mirror to a Samba account with the same name/password
        run(['useradd', '-M', '-s', '/usr/sbin/nologin', username])
        run(['smbpasswd', '-a', '-s', username], input_data=f'{password}\n{password}\n')
    return jsonify({'success': True})


@app.route('/api/users/<username>/role', methods=['POST'])
def users_set_role(username):
    if not _is_admin():
        return err('Administrator access required', 403)
    role = (request.get_json() or {}).get('role')
    if role not in ('admin', 'readonly'):
        return err('Invalid role')
    cfg = load_config()
    users = cfg.get('users', {})
    if username not in users:
        return err('No such user', 404)
    if role != 'admin' and _user_role(users[username]) == 'admin' and _count_admins(users) <= 1:
        return err('Cannot demote the last administrator', 409)
    rec = users[username] if isinstance(users[username], dict) else {'password': users[username], 'smb': False}
    rec['role'] = role
    users[username] = rec
    save_config(cfg)
    return jsonify({'success': True})


@app.route('/api/users/<username>/password', methods=['POST'])
def users_set_password(username):
    if not _is_admin():
        return err('Administrator access required', 403)
    password = (request.get_json() or {}).get('password') or ''
    if not password:
        return err('Password required')
    cfg = load_config()
    users = cfg.get('users', {})
    if username not in users:
        return err('No such user', 404)
    rec = users[username] if isinstance(users[username], dict) else {'role': 'admin', 'smb': False}
    rec['password'] = generate_password_hash(password)
    users[username] = rec
    save_config(cfg)
    if rec.get('smb'):
        run(['smbpasswd', '-s', username], input_data=f'{password}\n{password}\n')
    return jsonify({'success': True})


@app.route('/api/users/<username>', methods=['DELETE'])
def users_delete(username):
    if not _is_admin():
        return err('Administrator access required', 403)
    cfg = load_config()
    users = cfg.get('users', {})
    if username not in users:
        return err('No such user', 404)
    if username == session.get('user'):
        return err('Cannot delete your own account', 409)
    if _user_role(users[username]) == 'admin' and _count_admins(users) <= 1:
        return err('Cannot delete the last administrator', 409)
    was_smb = isinstance(users[username], dict) and users[username].get('smb')
    del users[username]
    save_config(cfg)
    if was_smb:
        run(['smbpasswd', '-x', username])
    return jsonify({'success': True})


# ─── API token management (admin only) ───────────────────────────────

@app.route('/api/tokens')
def tokens_list():
    if not _is_admin():
        return err('Administrator access required', 403)
    return jsonify([{'id': t['id'], 'name': t.get('name', ''), 'role': t.get('role', 'readonly'),
                     'created': t.get('created', ''), 'last_used': t.get('last_used', '')}
                    for t in _tokens()])


@app.route('/api/tokens', methods=['POST'])
def tokens_create():
    if not _is_admin():
        return err('Administrator access required', 403)
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    role = data.get('role', 'readonly')
    if not RE_USER.match(name):
        return err('Invalid token name')
    if role not in ('admin', 'readonly'):
        return err('Invalid role')
    secret = TOKEN_PREFIX + secrets.token_urlsafe(32)
    rec = {'id': 'tok-' + secrets.token_hex(6), 'name': name, 'role': role,
           'hash': _hash_token(secret), 'created': datetime.now().strftime('%Y-%m-%d'),
           'last_used': ''}
    cfg = load_config()
    cfg.setdefault('tokens', []).append(rec)
    save_config(cfg)
    # The secret is returned exactly once — only its SHA-256 is stored.
    return jsonify({'success': True, 'id': rec['id'], 'name': name, 'role': role, 'token': secret})


@app.route('/api/tokens/<tid>', methods=['DELETE'])
def tokens_delete(tid):
    if not _is_admin():
        return err('Administrator access required', 403)
    cfg = load_config()
    before = len(cfg.get('tokens', []))
    cfg['tokens'] = [t for t in cfg.get('tokens', []) if t.get('id') != tid]
    if len(cfg.get('tokens', [])) == before:
        return err('No such token', 404)
    save_config(cfg)
    return jsonify({'success': True})


# ─── Input validation ─────────────────────────────────────────────────
# Argument-list execution stops shell injection. These additional checks
# stop argument injection (values that look like flags) and config-file
# injection (newlines used to inject extra /etc/exports or smb.conf lines).

RE_POOL    = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')
RE_DATASET = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_./-]*$')
RE_SNAP    = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_./-]*@[a-zA-Z0-9][a-zA-Z0-9_.:-]*$')
RE_PROP    = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.:-]*$')
RE_IQN     = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._:-]*$')
RE_BSNAME  = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')
RE_CHAP    = re.compile(r'^[A-Za-z0-9._:+-]{1,64}$')
RE_PATH    = re.compile(r'^/[^\x00\n\r]*$')
RE_DISK    = re.compile(r'^/?[a-zA-Z0-9][a-zA-Z0-9_./-]*$')
# Pool member identifiers as shown by `zpool status` (bare names, /dev paths,
# and /dev/disk/by-id/... which can contain ':').
RE_DEVICE  = re.compile(r'^/?[A-Za-z0-9][A-Za-z0-9_./:-]*$')
VDEV_ADD_ROLES = {'', 'mirror', 'raidz', 'raidz1', 'raidz2', 'raidz3', 'spare', 'cache', 'log'}
RE_SIZE    = re.compile(r'^[0-9]+[KkMmGgTt]?[Bb]?$')
RE_NUM     = re.compile(r'^[0-9]+$')
RE_IP      = re.compile(r'^[0-9a-fA-F:.]+$')
RE_HOST    = re.compile(r'^[a-zA-Z0-9_.:*/-]+$')
RE_NFSOPTS = re.compile(r'^[a-zA-Z0-9_,=.-]+$')
RE_SHARE   = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')
RE_USER    = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')
RE_USERS   = re.compile(r'^[a-zA-Z0-9_,. @-]+$')
RE_GROUP   = re.compile(r'^[a-z_][a-z0-9_-]*$')
RE_ACL     = re.compile(r'^[A-Za-z0-9_,.@ +-]*$')   # user / @group access lists
RE_HOSTS   = re.compile(r'^[A-Za-z0-9_,.: /-]*$')    # hosts allow/deny (IPs, subnets, names)
RE_MASK    = re.compile(r'^[0-7]{3,4}$')
RE_SERVICE = re.compile(r'^[a-zA-Z0-9@._-]+$')
RE_DEVNAME = re.compile(r'^[a-zA-Z0-9]+$')  # bare block-device name, e.g. sda / nvme0n1
RE_COMMENT = re.compile(r'^[^\n\r]*$')
VDEV_TYPES = {'', 'mirror', 'raidz', 'raidz1', 'raidz2', 'raidz3'}

# Plain-disk format & mount (a standard disk → partition → filesystem → mount).
# Filesystems the dashboard will create on a disk. Anything not here is refused.
MOUNT_FSTYPES = {'ext4', 'xfs', 'vfat', 'exfat'}
# Optional filesystem label (passed to mkfs); keep it conservative. \Z (not $)
# so a trailing newline can't sneak through — $ matches before a final '\n'.
RE_FSLABEL = re.compile(r'^[A-Za-z0-9_.-]{1,32}\Z')
# A leaf mount-point name (the dir created under a fixed base); no '/', no '..'.
RE_MOUNTNAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]*\Z')
# Where the dashboard is allowed to mount disks. A fixed allowlist keeps the
# mount target away from system paths (/, /etc, ...). The wrapper re-checks this.
MOUNT_BASES = ('/mnt', '/media')
# A filesystem UUID as reported by blkid/lsblk (ext/xfs hex-dash, vfat 8-char).
RE_UUID = re.compile(r'^[A-Za-z0-9-]{1,64}\Z')
# fstypes that are members of another subsystem and must never be offered as a
# plain mountable filesystem (they belong to ZFS/LVM/MD/swap).
NON_MOUNTABLE_FSTYPES = {'zfs_member', 'LVM2_member', 'linux_raid_member', 'swap'}


# llama.cpp inference server — managed like a system service (status/control via
# the shared service endpoints) plus its own page for model + CLI-arg editing.
LLAMA_SERVICE = 'llama-server'
LLAMA_CONF = os.environ.get('DASHBOARD_LLAMA_CONF', '/etc/llama.conf')
LLAMA_MODELS_DIR = os.environ.get('DASHBOARD_LLAMA_MODELS_DIR', '/usr/share/models')
LLAMA_DEFAULT_BIN = os.environ.get('DASHBOARD_LLAMA_BIN', '/usr/local/llama.cpp/llama-server')
LLAMA_URL = os.environ.get('DASHBOARD_LLAMA_URL', 'http://localhost:8080')

# ─── Platform detection (Debian/Ubuntu vs RHEL/Rocky) ─────────────────
# All OS coupling (service unit names, package names, the package manager) is
# driven from per-family tables keyed off this, rather than `if rhel` scattered
# through the code. Detect once from /etc/os-release.
def _platform_from_osrelease(text):
    """Pure parser: given /etc/os-release contents, return
    {family: 'debian'|'rhel', id, version}. Defaults to 'debian' when unknown."""
    data = {}
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        data[k.strip()] = v.strip().strip('"').strip("'")
    osid = (data.get('ID') or '').lower()
    like = set((data.get('ID_LIKE') or '').lower().split())
    rhel_ids = {'rhel', 'centos', 'rocky', 'almalinux', 'fedora'}
    debian_ids = {'debian', 'ubuntu'}
    if osid in rhel_ids or (rhel_ids & like):
        family = 'rhel'
    elif osid in debian_ids or (debian_ids & like):
        family = 'debian'
    else:
        family = 'debian'  # safe default — Ubuntu is the historical target
    return {'family': family, 'id': osid, 'version': data.get('VERSION_ID', '')}


def detect_platform(path='/etc/os-release'):
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        text = ''
    return _platform_from_osrelease(text)


PLATFORM = detect_platform()
FAMILY = PLATFORM['family']

# Per-family file paths / commands that differ between Debian and RHEL.
# mdadm.conf lives in /etc/mdadm/ on Debian but directly in /etc/ on RHEL; the
# initramfs is rebuilt with update-initramfs on Debian, dracut on RHEL.
if FAMILY == 'rhel':
    MDADM_CONF = '/etc/mdadm.conf'
    INITRAMFS_UPDATE = ['dracut', '-f']
else:
    MDADM_CONF = '/etc/mdadm/mdadm.conf'
    INITRAMFS_UPDATE = ['update-initramfs', '-u']

SYSTEM_SERVICES = {
    'zfs': {'name': 'ZFS', 'service': 'zfs.target', 'pkg': 'zfsutils-linux', 'binary': '/usr/sbin/zpool'},
    'iscsi': {'name': 'iSCSI Target', 'service': 'target', 'pkg': 'targetcli-fb', 'binary': '/usr/bin/targetcli'},
    'nfs': {'name': 'NFS Server', 'service': 'nfs-server', 'pkg': 'nfs-kernel-server', 'binary': '/usr/sbin/nfsdclnts'},
    'smb': {'name': 'Samba', 'service': 'smbd', 'pkg': 'samba', 'binary': '/usr/sbin/smbd'},
    # No apt package (pkg=None) and never raises health alerts (alert=False) —
    # llama-server is frequently stopped on purpose / absent on storage hosts.
    'llamacpp': {'name': 'llama.cpp', 'service': LLAMA_SERVICE, 'pkg': None,
                 'binary': LLAMA_DEFAULT_BIN, 'alert': False},
}

# Per-family overrides for the services whose systemd unit and/or package name
# differ from the Debian/Ubuntu defaults above. RHEL/Rocky: Samba's unit is
# `smb` (not `smbd`), NFS ships in `nfs-utils`, iSCSI in `targetcli`, ZFS from
# the OpenZFS repo's `zfs` package. The `nfs-server` and `target` unit names are
# already correct on both families.
SERVICE_OVERRIDES = {
    'rhel': {
        'zfs':   {'pkg': 'zfs'},
        'iscsi': {'pkg': 'targetcli'},
        'nfs':   {'pkg': 'nfs-utils'},
        'smb':   {'service': 'smb', 'pkg': 'samba'},
    },
}
for _key, _ov in SERVICE_OVERRIDES.get(FAMILY, {}).items():
    if _key in SYSTEM_SERVICES:
        SYSTEM_SERVICES[_key].update(_ov)


def _unit_present(unit):
    """True if a systemd unit file exists in any standard location."""
    name = unit if ('.' in unit) else unit + '.service'
    return (Path(f'/etc/systemd/system/{name}').exists() or
            Path(f'/usr/lib/systemd/system/{name}').exists() or
            Path(f'/lib/systemd/system/{name}').exists())


def resolve_service(service):
    """Map a service key to its systemd unit, validating arbitrary input."""
    if service in SYSTEM_SERVICES:
        return SYSTEM_SERVICES[service]['service']
    return service if RE_SERVICE.match(service or '') else None

# ─── System ───────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('templates', 'index.html')


@app.route('/manifest.webmanifest')
def web_manifest():
    """PWA manifest so the dashboard can be installed / added to a home screen and
    open standalone. No service worker (a live control panel must not serve stale
    cached state); this is install-to-home-screen only."""
    return jsonify({
        'name': 'Nexus Dashboard',
        'short_name': 'Nexus',
        'description': 'Single-host storage & AI management dashboard',
        'start_url': '/',
        'scope': '/',
        'display': 'standalone',
        'orientation': 'any',
        'background_color': '#0f1419',
        'theme_color': '#1a1f2e',
        'icons': [],
    })

@app.route('/api/status')
def api_status():
    services = {}
    for key, svc in SYSTEM_SERVICES.items():
        r = run(['systemctl', 'is-active', svc['service']])
        e = run(['systemctl', 'is-enabled', svc['service']])
        services[key] = {
            'name': svc['name'],
            'active': r[0].strip() if r[0] else 'inactive',
            'enabled': e[0].strip() if e[0] else 'disabled',
            'installed': Path(svc['binary']).exists() or _unit_present(svc['service'])
        }
    return jsonify(services)

# Pool fill level (percent) at which a capacity alert fires.
ALERT_FULL_PCT = 90

# Pseudo / virtual / read-only filesystem types that are never "full" in a way
# worth alerting on (and zfs, which is covered by the dedicated pool alert).
ALERT_SKIP_FSTYPES = {
    'tmpfs', 'devtmpfs', 'squashfs', 'overlay', 'iso9660', 'proc', 'sysfs',
    'cgroup', 'cgroup2', 'devpts', 'mqueue', 'debugfs', 'tracefs', 'fusectl',
    'configfs', 'pstore', 'bpf', 'autofs', 'ramfs', 'efivarfs', 'securityfs',
    'binfmt_misc', 'hugetlbfs', 'nsfs', 'zfs',
}


def _df_use_pct(blocks, bfree, bavail):
    """Filesystem use% the way df reports it (accounts for root-reserved blocks)."""
    used = blocks - bfree
    denom = used + bavail
    return round(used * 100 / denom) if denom > 0 else 0


def _real_mounts(proc_mounts_text):
    """[(mountpoint, fstype, options)] for real, non-pseudo filesystems."""
    out, seen = [], set()
    for line in proc_mounts_text.split('\n'):
        parts = line.split()
        if len(parts) < 4:
            continue
        _dev, mnt, fstype, opts = parts[0], parts[1], parts[2], parts[3]
        if fstype in ALERT_SKIP_FSTYPES or not mnt.startswith('/'):
            continue
        mnt = mnt.replace('\\040', ' ')   # /proc/mounts octal-escapes spaces
        if mnt in seen:
            continue
        seen.add(mnt)
        out.append((mnt, fstype, opts.split(',')))
    return out


def _fs_alerts():
    """Real filesystems at or above the fill threshold (covers LVM/plain mounts)."""
    try:
        with open('/proc/mounts') as f:
            text = f.read()
    except OSError:
        return []
    alerts = []
    for mnt, _fstype, opts in _real_mounts(text):
        if 'ro' in opts:               # read-only (e.g. snap, image) can't fill
            continue
        try:
            st = os.statvfs(mnt)
        except OSError:
            continue
        if st.f_blocks <= 0:
            continue
        pct = _df_use_pct(st.f_blocks, st.f_bfree, st.f_bavail)
        if pct >= ALERT_FULL_PCT:
            alerts.append({'key': 'fs_full:' + mnt,
                           'message': f'Filesystem {mnt} is {pct}% full'})
    return alerts


def _lvm_alerts():
    """LVM volume groups with a missing PV (a failed/removed disk).

    Capacity is intentionally NOT measured here: a fully-allocated VG is the
    normal default (the Ubuntu installer assigns 100% of the VG to the root LV),
    so "VG % allocated" cries wolf. Running-out-of-space shows up as the
    filesystem filling, which `_fs_alerts` catches."""
    alerts = []
    for g in _lvm_report('vgs', 'vg_name,vg_missing_pv_count'):
        name = g.get('vg_name')
        if not name:
            continue
        try:
            missing = int(g.get('vg_missing_pv_count', 0) or 0)
        except (TypeError, ValueError):
            continue
        if missing > 0:
            alerts.append({'key': 'lvm_pv:' + name,
                           'message': f'LVM volume group {name} has {missing} missing PV(s)'})
    return alerts


def _parse_mdstat(text):
    """Parse /proc/mdstat into [{name, degraded}]. Degraded if the array has a
    failed/missing member ('_' in the [UU] map, fewer active than total, or (F))."""
    arrays, cur = [], None
    for line in text.split('\n'):
        m = re.match(r'^(md\d+)\s*:', line)
        if m:
            cur = {'name': m.group(1), 'degraded': '(F)' in line}
            arrays.append(cur)
        elif cur is not None:
            mm = re.search(r'\[(\d+)/(\d+)\]\s*\[([U_]+)\]', line)
            if mm:
                total, active = int(mm.group(1)), int(mm.group(2))
                if active < total or '_' in mm.group(3):
                    cur['degraded'] = True
    return arrays


def _md_alerts():
    """MD RAID arrays running degraded (failed/missing member disk)."""
    try:
        with open('/proc/mdstat') as f:
            text = f.read()
    except OSError:
        return []
    return [{'key': 'md_degraded:' + a['name'],
             'message': f"MD RAID array {a['name']} is degraded"}
            for a in _parse_mdstat(text) if a['degraded']]


def _compute_alerts():
    """The single source of truth for health alerts — used by both the dashboard
    summary and the background notifier. Returns [{key, message}] where `key` is
    stable per condition (so the notifier can de-duplicate)."""
    alerts = []
    disabled_modules = load_disabled_modules()
    for key, svc in SYSTEM_SERVICES.items():
        if not svc.get('alert', True):
            continue
        # A feature turned off on the Modules page is intentional — not an issue.
        if key in disabled_modules:
            continue
        active = (run(['systemctl', 'is-active', svc['service']])[0] or '').strip() or 'inactive'
        if active != 'active':
            # A unit intentionally disabled/masked at boot is also intentional.
            enabled = (run(['systemctl', 'is-enabled', svc['service']])[0] or '').strip()
            if enabled in ('disabled', 'masked'):
                continue
            alerts.append({'key': 'service:' + key, 'message': f"{svc['name']} service is {active}"})
    zout, _, zrc = run(['zpool', 'list', '-Hp', '-o', 'name,size,alloc,free,health'])
    if zrc == 0:
        for line in zout.strip().split('\n'):
            p = line.split('\t')
            if len(p) >= 5 and p[0]:
                if p[4] != 'ONLINE':
                    alerts.append({'key': 'zfs_health:' + p[0],
                                   'message': f"ZFS pool {p[0]} is {p[4]}"})
                size, alloc = int(p[1]), int(p[2])
                pctp = round(alloc / size * 100) if size else 0
                if pctp >= ALERT_FULL_PCT:
                    alerts.append({'key': 'zfs_full:' + p[0],
                                   'message': f"ZFS pool {p[0]} is {pctp}% full"})
    if _smart_health_ok() is False:
        alerts.append({'key': 'smart', 'message': 'A disk reports SMART failure'})
    # LVM and MD alerts follow their module toggles (off = intentional).
    if 'lvm' not in disabled_modules:
        alerts.extend(_lvm_alerts())
    if 'mdraid' not in disabled_modules:
        alerts.extend(_md_alerts())
    # Filesystem-full is a general operational risk — always checked.
    alerts.extend(_fs_alerts())
    # A scheduled task whose last run failed.
    alerts.extend(_task_alerts())
    return alerts


@app.route('/api/summary')
def api_summary():
    """Aggregated overview for the dashboard front page (one call)."""
    services = {}
    # A module turned off on the Modules page hides its card and suppresses its
    # alerts; hide its service line on the front page too (the dedicated Services
    # page still lists everything for management). Service keys are module ids.
    disabled = load_disabled_modules()
    for key, svc in SYSTEM_SERVICES.items():
        if key in disabled:
            continue
        active = (run(['systemctl', 'is-active', svc['service']])[0] or '').strip() or 'inactive'
        enabled = (run(['systemctl', 'is-enabled', svc['service']])[0] or '').strip() or 'disabled'
        services[key] = {'name': svc['name'], 'active': active, 'enabled': enabled}

    # System
    try:
        with open('/proc/uptime') as f:
            uptime_days = round(float(f.read().split()[0]) / 86400, 1)
    except (OSError, ValueError):
        uptime_days = 0
    ip4 = '-'
    try:
        for itf in json.loads(run(['ip', '-j', 'addr', 'show'])[0] or '[]'):
            for a in itf.get('addr_info', []):
                if a.get('family') == 'inet' and a.get('local') != '127.0.0.1':
                    ip4 = a['local']
                    break
    except json.JSONDecodeError:
        pass
    system = {'hostname': socket.gethostname(), 'uptime_days': uptime_days, 'ip': ip4}

    # ZFS
    pools = size = alloc = 0
    online = True
    zout, _, zrc = run(['zpool', 'list', '-Hp', '-o', 'name,size,alloc,free,health'])
    if zrc == 0:
        for line in zout.strip().split('\n'):
            p = line.split('\t')
            if len(p) >= 5 and p[0]:
                pools += 1
                size += int(p[1]); alloc += int(p[2])
                if p[4] != 'ONLINE':
                    online = False
    pct = round(alloc / size * 100) if size else 0
    scanning = 'in progress' in (run(['zpool', 'status'])[0] or '')
    zfs = {'pools': pools, 'online': online, 'used': _human_bytes(alloc),
           'size': _human_bytes(size), 'pct': pct, 'scanning': scanning}

    # iSCSI
    iout = run(['targetcli', '/iscsi', 'ls'])[0] or ''
    bs = parse_backstores(run(['targetcli', '/backstores', 'ls'])[0] or '')
    sess = [l for l in (run(['/usr/local/sbin/storage-dashboard-iscsi-sessions'])[0] or '').split('\n') if l.strip()]
    iscsi = {
        'targets': len(parse_targets(iout)),
        'luns': sum(int(x) for x in re.findall(r'\[LUNs: (\d+)\]', iout)),
        'backstores': len(bs),
        'provisioned': _human_bytes(sum(_size_to_bytes(b.get('size', '')) for b in bs)),
        'sessions': len(sess),
    }

    # NFS
    mounts = [l for l in (run(['showmount', '-a', '--no-headers'], no_sudo=True)[0] or '').split('\n') if l.strip()]
    nfs = {'exports': len(parse_exports()), 'clients': len(mounts)}

    # SMB
    users = [l for l in (run(['pdbedit', '-L'])[0] or '').split('\n') if l.strip()]
    conns = [l for l in (run(['smbstatus', '-b'])[0] or '').split('\n') if re.match(r'^\d+\s', l.strip())]
    share_count = len([n for n in smbconf_parse() if n.lower() not in ('global', 'homes')])
    smb = {'shares': share_count, 'users': len(users), 'connections': len(conns)}

    # Disks
    total = free = 0
    try:
        defined_md, pmap = _mdadm_conf_arrays(), _zpool_disk_map()
        for d in json.loads(run(['lsblk', '-J', '-o', 'NAME,TYPE,FSTYPE,MOUNTPOINT'])[0] or '{}').get('blockdevices', []):
            if (d.get('type') or '') == 'disk':
                total += 1
                if disk_usage(d, pmap, defined_md) == 'Free':
                    free += 1
    except json.JSONDecodeError:
        pass
    smart_ok = _smart_health_ok()
    disks = {'total': total, 'free': free, 'smart_ok': smart_ok}

    alerts = [a['message'] for a in _compute_alerts()]
    return jsonify({'system': system, 'services': services, 'zfs': zfs, 'iscsi': iscsi,
                    'nfs': nfs, 'smb': smb, 'disks': disks, 'alerts': alerts})


# ─── System resources (CPU / memory / load / uptime) ──────────────────
# All read from /proc — no sudo, no external tools. The parsers below are pure
# (text in, numbers out) so they are unit-tested.

def _parse_meminfo(text):
    """/proc/meminfo -> {key: bytes}. meminfo reports kB; convert to bytes."""
    out = {}
    for line in text.split('\n'):
        m = re.match(r'^(\w+):\s+(\d+)(?:\s+kB)?', line)
        if m:
            out[m.group(1)] = int(m.group(2)) * 1024
    return out


def _parse_loadavg(text):
    """/proc/loadavg -> (load1, load5, load15) as floats."""
    parts = text.split()
    try:
        return float(parts[0]), float(parts[1]), float(parts[2])
    except (IndexError, ValueError):
        return 0.0, 0.0, 0.0


def _parse_cpu_stat(text):
    """First 'cpu ' aggregate line of /proc/stat -> (idle_jiffies, total_jiffies).
    idle counts idle+iowait."""
    for line in text.split('\n'):
        if line.startswith('cpu '):
            vals = [int(x) for x in line.split()[1:]]
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
            return idle, sum(vals)
    return 0, 0


def _cpu_percent(prev, cur):
    """Busy % between two (idle, total) /proc/stat samples."""
    didle = cur[0] - prev[0]
    dtotal = cur[1] - prev[1]
    if dtotal <= 0:
        return 0.0
    return round((1 - didle / dtotal) * 100, 1)


def _cpu_usage():
    try:
        with open('/proc/stat') as f:
            a = _parse_cpu_stat(f.read())
        time.sleep(0.1)
        with open('/proc/stat') as f:
            b = _parse_cpu_stat(f.read())
        return _cpu_percent(a, b)
    except OSError:
        return 0.0


def _system_resources():
    try:
        with open('/proc/uptime') as f:
            uptime = int(float(f.read().split()[0]))
    except (OSError, ValueError):
        uptime = 0
    try:
        with open('/proc/loadavg') as f:
            l1, l5, l15 = _parse_loadavg(f.read())
    except OSError:
        l1 = l5 = l15 = 0.0
    try:
        with open('/proc/meminfo') as f:
            mem = _parse_meminfo(f.read())
    except OSError:
        mem = {}
    total = mem.get('MemTotal', 0)
    avail = mem.get('MemAvailable', 0)
    swap_total = mem.get('SwapTotal', 0)
    swap_free = mem.get('SwapFree', 0)
    return {
        'uptime_seconds': uptime,
        'load': {'1': l1, '5': l5, '15': l15},
        'cpus': os.cpu_count() or 1,
        'cpu_pct': _cpu_usage(),
        'memory': {'total': total, 'available': avail, 'used': max(0, total - avail),
                   'pct': round((total - avail) / total * 100, 1) if total else 0},
        'swap': {'total': swap_total, 'used': max(0, swap_total - swap_free),
                 'pct': round((swap_total - swap_free) / swap_total * 100, 1) if swap_total else 0},
    }


@app.route('/api/system/resources')
def system_resources():
    return jsonify(_system_resources())


# ─── Time-series history (bounded, on-disk) ───────────────────────────
# A tiny SQLite ring buffer sampled by the storage-dashboard-history timer. Disk
# is HARD-bounded: raw 5-min points kept a short window, folded to one row/day
# for long trends; auto_vacuum reclaims space; a size backstop prunes if it ever
# exceeds a cap. Only allowlisted metrics with small labels (pool/disk/gpu/mount)
# are stored, so cardinality can't explode. See docs/plans/01-history-store.md.
HISTORY_DB = os.environ.get('DASHBOARD_HISTORY_DB', os.path.join(APP_DIR, 'history.db'))
HISTORY_TIMER = 'storage-dashboard-history.timer'
HISTORY_RAW_DAYS = int(os.environ.get('DASHBOARD_HISTORY_RAW_DAYS', 3))
HISTORY_DAILY_DAYS = int(os.environ.get('DASHBOARD_HISTORY_DAILY_DAYS', 400))
HISTORY_MAX_MB = int(os.environ.get('DASHBOARD_HISTORY_MAX_MB', 64))
# Allowlisted metrics. gpu_*/llama_tokens_total are pre-listed so features 02/06c
# can write them without touching this set. Labels are bounded names.
HISTORY_METRICS = {
    'cpu_pct', 'mem_pct', 'load1', 'pool_alloc', 'pool_size',
    'arc_size', 'arc_hit_ratio', 'gpu_util', 'gpu_mem_pct', 'gpu_temp',
    'llama_tokens_total',
}
RE_HISTORY_LABEL = re.compile(r'^[A-Za-z0-9 ._:/-]{0,64}$')


def _history_conn():
    first = not os.path.exists(HISTORY_DB)
    conn = sqlite3.connect(HISTORY_DB, timeout=5, isolation_level=None)  # autocommit
    if first:
        conn.execute('PRAGMA auto_vacuum=FULL')   # must precede table creation
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute("CREATE TABLE IF NOT EXISTS samples("
                 "ts INTEGER NOT NULL, metric TEXT NOT NULL, "
                 "label TEXT NOT NULL DEFAULT '', value REAL)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_samples ON samples(metric,label,ts)")
    conn.execute("CREATE TABLE IF NOT EXISTS daily("
                 "day TEXT NOT NULL, metric TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', "
                 "avg REAL, min REAL, max REAL, last REAL, PRIMARY KEY(day,metric,label))")
    conn.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
    return conn


def _history_record(rows):
    """rows: iterable of (metric, label, value). One shared timestamp. Best-effort
    — never raise into a caller (history must not break a request or a tick)."""
    try:
        ts = int(time.time())
        clean = [(ts, m, (l or ''), float(v)) for (m, l, v) in rows
                 if m in HISTORY_METRICS and v is not None]
        if not clean:
            return
        conn = _history_conn()
        try:
            conn.executemany('INSERT INTO samples(ts,metric,label,value) VALUES(?,?,?,?)', clean)
        finally:
            conn.close()
    except Exception:
        pass


def _history_query(metric, label, since_ts):
    conn = _history_conn()
    try:
        cur = conn.execute('SELECT ts,value FROM samples WHERE metric=? AND label=? AND ts>=? '
                           'ORDER BY ts', (metric, label or '', since_ts))
        return [[r[0], r[1]] for r in cur.fetchall()]
    finally:
        conn.close()


def _history_query_daily(metric, label, days):
    conn = _history_conn()
    try:
        cur = conn.execute('SELECT day,avg,min,max,last FROM daily WHERE metric=? AND label=? '
                           'ORDER BY day DESC LIMIT ?', (metric, label or '', days))
        rows = [{'day': r[0], 'avg': r[1], 'min': r[2], 'max': r[3], 'last': r[4]}
                for r in cur.fetchall()]
        return rows[::-1]
    finally:
        conn.close()


def _history_prune_raw():
    conn = _history_conn()
    try:
        conn.execute('DELETE FROM samples WHERE ts < ?', (int(time.time()) - HISTORY_RAW_DAYS * 86400,))
    finally:
        conn.close()


def _history_maybe_rollup():
    """Once per day: fold whole prior days of raw into `daily`, prune old daily,
    VACUUM to release disk. Idempotent (upsert), gated by a meta marker."""
    today = datetime.now().strftime('%Y-%m-%d')
    conn = _history_conn()
    try:
        cur = conn.execute("SELECT v FROM meta WHERE k='last_rollup'")
        row = cur.fetchone()
        if row and row[0] == today:
            return
        conn.execute(
            "INSERT INTO daily(day,metric,label,avg,min,max,last) "
            "SELECT date(ts,'unixepoch','localtime') AS d, metric, label, "
            "  AVG(value), MIN(value), MAX(value), "
            "  (SELECT value FROM samples s2 WHERE s2.metric=samples.metric "
            "     AND s2.label=samples.label "
            "     AND date(s2.ts,'unixepoch','localtime')"
            "         =date(samples.ts,'unixepoch','localtime') "
            "   ORDER BY s2.ts DESC LIMIT 1) "
            "FROM samples WHERE date(ts,'unixepoch','localtime') < ? "
            "GROUP BY d, metric, label "
            "ON CONFLICT(day,metric,label) DO UPDATE SET "
            "  avg=excluded.avg, min=excluded.min, max=excluded.max, last=excluded.last",
            (today,))
        day_cut = (datetime.now() - timedelta(days=HISTORY_DAILY_DAYS)).strftime('%Y-%m-%d')
        conn.execute('DELETE FROM daily WHERE day < ?', (day_cut,))
        conn.execute('DELETE FROM samples WHERE ts < ?', (int(time.time()) - HISTORY_RAW_DAYS * 86400,))
        conn.execute("INSERT INTO meta(k,v) VALUES('last_rollup',?) "
                     "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (today,))
        conn.execute('VACUUM')
    finally:
        conn.close()


def _history_size_backstop():
    """Last-resort bound: if the db somehow exceeds the cap, aggressively drop the
    oldest raw and VACUUM. Returns MB after the check."""
    try:
        mb = os.path.getsize(HISTORY_DB) / (1024 * 1024)
        if mb > HISTORY_MAX_MB:
            conn = _history_conn()
            try:
                conn.execute('DELETE FROM samples WHERE ts < ?', (int(time.time()) - 86400,))
                conn.execute('VACUUM')
            finally:
                conn.close()
            print(f'history: size cap hit ({mb:.0f}MB > {HISTORY_MAX_MB}MB) — pruned', flush=True)
        return mb
    except OSError:
        return 0


def _num(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def _gpu_history_samples():
    """Per-GPU util/mem/temp for the history sampler (feature 02). Empty when no
    GPU tooling is present, so history stays a no-op on GPU-less hosts."""
    rows = []
    for gp in _gpu_snapshot().get('gpus', []):
        idx = gp.get('index')
        lbl = 'gpu%d' % idx if idx is not None else 'gpu'
        if gp.get('util') is not None:
            rows.append(('gpu_util', lbl, gp['util']))
        if gp.get('mem_pct') is not None:
            rows.append(('gpu_mem_pct', lbl, gp['mem_pct']))
        if gp.get('temp') is not None:
            rows.append(('gpu_temp', lbl, gp['temp']))
    return rows


def _llama_tokens_total():
    """llama-server's cumulative tokens_predicted_total counter, or None if the
    server isn't up / the module is off. Cheap: one short HTTP GET, no sudo."""
    if 'llamacpp' in load_disabled_modules():
        return None
    import urllib.request
    try:
        with urllib.request.urlopen(LLAMA_URL.rstrip('/') + '/metrics', timeout=3) as r:
            text = r.read().decode()
    except Exception:
        return None
    for m in re.finditer(r'^(\w[\w:]*)\s+([0-9.eE+-]+)\s*$', text, re.M):
        name = m.group(1)
        if name.split(':', 1)[-1] == 'tokens_predicted_total':
            try:
                return float(m.group(2))
            except ValueError:
                return None
    return None


def _llama_history_samples():
    """Persist the cumulative predicted-token counter (feature 06c). The sparkline
    derives tokens/sec from the slope, so a raw counter is what we store. A restart
    resets the counter; that produces one downward step the UI can ignore."""
    tot = _llama_tokens_total()
    return [('llama_tokens_total', '', tot)] if tot is not None else []


def _history_sample():
    """Gather the current allowlisted metrics as (metric, label, value) tuples.
    Cheap sources only (/proc + `zpool list -Hp` + arcstats). 02/06c append more."""
    rows = []
    try:
        r = _system_resources()
        rows.append(('cpu_pct', '', r.get('cpu_pct')))
        rows.append(('mem_pct', '', (r.get('memory') or {}).get('pct')))
        rows.append(('load1', '', (r.get('load') or {}).get('1')))
    except Exception:
        pass
    try:
        out, _, _ = run(['zpool', 'list', '-Hp', '-o', 'name,size,alloc'])
        for line in out.strip().split('\n'):
            if '\t' not in line:
                continue
            parts = line.split('\t')
            name = parts[0]
            rows.append(('pool_size', name, _num(parts[1]) if len(parts) > 1 else None))
            rows.append(('pool_alloc', name, _num(parts[2]) if len(parts) > 2 else None))
    except Exception:
        pass
    try:
        with open('/proc/spl/kstat/zfs/arcstats') as f:
            s = _arc_summary(_parse_arcstats(f.read()))
        rows.append(('arc_size', '', s.get('size')))
        if s.get('hit_ratio') is not None:
            rows.append(('arc_hit_ratio', '', s.get('hit_ratio')))
    except Exception:
        pass
    try:
        rows.extend(_gpu_history_samples())   # feature 02 (no-op if absent)
    except Exception:
        pass
    try:
        rows.extend(_llama_history_samples())  # feature 06c (no-op if absent)
    except Exception:
        pass
    return rows


def _history_forecast_slope(points):
    """Least-squares slope (value units per second) over [[ts,value],...].
    Returns None if fewer than 3 points or the fit is degenerate."""
    pts = [(float(t), float(v)) for t, v in points if v is not None]
    n = len(pts)
    if n < 3:
        return None
    mx = sum(p[0] for p in pts) / n
    my = sum(p[1] for p in pts) / n
    denom = sum((p[0] - mx) ** 2 for p in pts)
    if denom == 0:
        return None
    return sum((p[0] - mx) * (p[1] - my) for p in pts) / denom


@app.route('/api/history')
def history_get():
    metric = request.args.get('metric', '')
    label = request.args.get('label', '')
    if metric not in HISTORY_METRICS:
        return err('Unknown metric')
    if label and not RE_HISTORY_LABEL.match(label):
        return err('Invalid label')
    if request.args.get('res') == 'daily':
        days = max(1, min(_num(request.args.get('days')) or 90, HISTORY_DAILY_DAYS))
        return jsonify({'metric': metric, 'label': label, 'resolution': 'daily',
                        'points': _history_query_daily(metric, label, days)})
    max_since = HISTORY_RAW_DAYS * 86400
    since = min(_num(request.args.get('since')) or max_since, max_since)
    return jsonify({'metric': metric, 'label': label, 'resolution': 'raw',
                    'points': _history_query(metric, label, int(time.time()) - since)})


@app.route('/api/history/forecast')
def history_forecast():
    """'full in ~N days' for a pool from its alloc trend (daily, else raw)."""
    label = request.args.get('label', '')
    if not label or not RE_POOL.match(label):
        return err('Invalid pool')
    daily = _history_query_daily('pool_alloc', label, 90)
    pts = [[datetime.strptime(d['day'], '%Y-%m-%d').timestamp(), d['last']]
           for d in daily if d['last'] is not None]
    if len(pts) < 3:
        pts = _history_query('pool_alloc', label, int(time.time()) - HISTORY_RAW_DAYS * 86400)
    slope = _history_forecast_slope(pts)   # bytes/sec
    out, _, _ = run(['zpool', 'list', '-Hp', '-o', 'size,alloc', label])
    parts = out.strip().split('\t')
    size = _num(parts[0]) if len(parts) > 0 else None
    cur = _num(parts[1]) if len(parts) > 1 else None
    rate_day = int(slope * 86400) if slope else 0
    days_to_full = None
    if slope and slope > 0 and size and cur is not None and size > cur:
        days_to_full = round((size - cur) / (slope * 86400), 1)
    return jsonify({'pool': label, 'fill_rate_bytes_per_day': rate_day,
                    'days_to_full': days_to_full})


def cli_history_tick():
    _history_record(_history_sample())
    _history_prune_raw()
    _history_maybe_rollup()
    _history_size_backstop()
    return 0


# ─── GPU monitoring (feature 02) ──────────────────────────────────────
# Read-only telemetry from nvidia-smi (NVIDIA) or rocm-smi (AMD/ROCm). Both are
# cheap; a short cache still keeps a busy dashboard from polling every refresh.
# No sudo needed (query tools work unprivileged); no config, no state.
_gpu_cache = {'ts': 0.0, 'data': None}


def _gpu_vendor():
    """Which GPU query tool is installed (nvidia wins if somehow both), or None."""
    if shutil.which('nvidia-smi'):
        return 'nvidia'
    if shutil.which('rocm-smi'):
        return 'amd'
    return None


def _gpu_float(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _parse_nvidia_smi(csv_text):
    """Parse `nvidia-smi --query-gpu=... --format=csv,noheader,nounits`.
    Columns: index,name,util,mem_used(MiB),mem_total(MiB),temp(C),power(W)."""
    gpus = []
    for line in (csv_text or '').strip().splitlines():
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 7:
            continue
        used = _gpu_float(parts[3])
        total = _gpu_float(parts[4])
        mem_pct = round(used / total * 100, 1) if (used is not None and total) else None
        gpus.append({
            'index': _num(parts[0]),
            'name': parts[1] or 'GPU',
            'vendor': 'nvidia',
            'util': _gpu_float(parts[2]),
            'mem_used': int(used * 1024 * 1024) if used is not None else None,
            'mem_total': int(total * 1024 * 1024) if total is not None else None,
            'mem_pct': mem_pct,
            'temp': _gpu_float(parts[5]),
            'power': _gpu_float(parts[6]),
        })
    return gpus


def _parse_rocm_smi(json_text):
    """Parse `rocm-smi ... --json` ({"card0": {..metrics..}, ...})."""
    try:
        data = json.loads(json_text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    gpus = []
    for card in sorted(data):
        d = data[card]
        if not isinstance(d, dict):
            continue
        m = re.search(r'(\d+)', card)
        used = _gpu_float(d.get('VRAM Total Used Memory (B)'))
        total = _gpu_float(d.get('VRAM Total Memory (B)'))
        mem_pct = _gpu_float(d.get('GPU Memory Allocated (VRAM%)'))
        if mem_pct is None and used is not None and total:
            mem_pct = round(used / total * 100, 1)
        name = d.get('Card Series')
        if not name or name == 'N/A':
            name = d.get('Card SKU')
        if not name or name == 'N/A':
            name = d.get('Card Model')
        gfx = d.get('GFX Version')
        if not name or name == 'N/A':
            name = gfx or 'AMD GPU'
        elif gfx and gfx != 'N/A':
            name = '%s (%s)' % (name, gfx)
        gpus.append({
            'index': int(m.group(1)) if m else None,
            'name': name,
            'vendor': 'amd',
            'util': _gpu_float(d.get('GPU use (%)')),
            'mem_used': int(used) if used is not None else None,
            'mem_total': int(total) if total is not None else None,
            'mem_pct': mem_pct,
            'temp': _gpu_float(d.get('Temperature (Sensor junction) (C)')
                               or d.get('Temperature (Sensor edge) (C)')),
            'power': _gpu_float(d.get('Average Graphics Package Power (W)')
                               or d.get('Current Socket Graphics Package Power (W)')),
        })
    return gpus


def _gpu_snapshot(force=False):
    """Current GPU telemetry: {available, vendor, gpus:[...]}. Cached ~8s."""
    now = time.time()
    if not force and _gpu_cache['ts'] and now - _gpu_cache['ts'] < 8:
        return _gpu_cache['data']
    vendor = _gpu_vendor()
    gpus = []
    try:
        if vendor == 'nvidia':
            out, _, _ = run(['nvidia-smi',
                             '--query-gpu=index,name,utilization.gpu,memory.used,'
                             'memory.total,temperature.gpu,power.draw',
                             '--format=csv,noheader,nounits'], no_sudo=True)
            gpus = _parse_nvidia_smi(out)
        elif vendor == 'amd':
            out, _, _ = run(['rocm-smi', '--showproductname', '--showuse',
                             '--showmemuse', '--showtemp', '--showpower',
                             '--showmeminfo', 'vram', '--json'], no_sudo=True)
            gpus = _parse_rocm_smi(out)
    except Exception:
        gpus = []
    data = {'available': bool(gpus), 'vendor': vendor, 'gpus': gpus}
    _gpu_cache['ts'], _gpu_cache['data'] = now, data
    return data


@app.route('/api/gpu')
def gpu_get():
    return jsonify(_gpu_snapshot())


# ─── Prometheus metrics ───────────────────────────────────────────────
# Public endpoint (a scraper can't use the session cookie). If
# DASHBOARD_METRICS_TOKEN is set it is required (?token= or Bearer); otherwise
# open, as is conventional for node_exporter-style endpoints on a trusted LAN.
METRICS_TOKEN = os.environ.get('DASHBOARD_METRICS_TOKEN', '')


def _prom_escape(v):
    return str(v).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')


def _prom_num(v):
    return ('%g' % v) if isinstance(v, float) else str(int(v))


def _render_metrics(families):
    """families: list of (name, help, type, [(labels_str, value), ...]) -> text."""
    out = []
    for name, htext, mtype, samples in families:
        if not samples:
            continue
        out.append('# HELP %s %s' % (name, htext))
        out.append('# TYPE %s %s' % (name, mtype))
        for labels, value in samples:
            out.append('%s%s %s' % (name, labels, _prom_num(value)))
    return '\n'.join(out) + '\n'


def _metrics_families():
    res = _system_resources()
    mem, sw = res['memory'], res['swap']
    fams = [
        ('storagedash_up', 'Dashboard is up', 'gauge', [('', 1)]),
        ('storagedash_uptime_seconds', 'Host uptime in seconds', 'gauge', [('', res['uptime_seconds'])]),
        ('storagedash_load1', '1-minute load average', 'gauge', [('', res['load']['1'])]),
        ('storagedash_load5', '5-minute load average', 'gauge', [('', res['load']['5'])]),
        ('storagedash_load15', '15-minute load average', 'gauge', [('', res['load']['15'])]),
        ('storagedash_cpu_count', 'Logical CPU count', 'gauge', [('', res['cpus'])]),
        ('storagedash_cpu_usage_percent', 'CPU busy percent', 'gauge', [('', res['cpu_pct'])]),
        ('storagedash_memory_total_bytes', 'Total RAM', 'gauge', [('', mem['total'])]),
        ('storagedash_memory_available_bytes', 'Available RAM', 'gauge', [('', mem['available'])]),
        ('storagedash_memory_used_bytes', 'Used RAM', 'gauge', [('', mem['used'])]),
        ('storagedash_swap_total_bytes', 'Total swap', 'gauge', [('', sw['total'])]),
        ('storagedash_swap_used_bytes', 'Used swap', 'gauge', [('', sw['used'])]),
    ]

    # ZFS pools (cheap: one zpool list -Hp).
    size_s, alloc_s, free_s, health_s = [], [], [], []
    zout, _, zrc = run(['zpool', 'list', '-Hp', '-o', 'name,size,alloc,free,health'])
    if zrc == 0:
        for line in zout.strip().split('\n'):
            p = line.split('\t')
            if len(p) >= 5 and p[0]:
                lbl = '{pool="%s"}' % _prom_escape(p[0])
                size_s.append((lbl, int(p[1])))
                alloc_s.append((lbl, int(p[2])))
                free_s.append((lbl, int(p[3])))
                health_s.append((lbl, 1 if p[4] == 'ONLINE' else 0))
    fams += [
        ('storagedash_zfs_pool_size_bytes', 'ZFS pool total size', 'gauge', size_s),
        ('storagedash_zfs_pool_alloc_bytes', 'ZFS pool allocated', 'gauge', alloc_s),
        ('storagedash_zfs_pool_free_bytes', 'ZFS pool free', 'gauge', free_s),
        ('storagedash_zfs_pool_healthy', 'ZFS pool ONLINE (1) or not (0)', 'gauge', health_s),
    ]

    # Service up/down (cheap systemctl is-active per service).
    svc_s = []
    for key, svc in SYSTEM_SERVICES.items():
        active = (run(['systemctl', 'is-active', svc['service']])[0] or '').strip()
        svc_s.append(('{service="%s"}' % _prom_escape(key), 1 if active == 'active' else 0))
    fams.append(('storagedash_service_up', 'systemd service active (1) or not (0)', 'gauge', svc_s))

    # Share/export counts (file reads, cheap) and SMART (cached).
    fams.append(('storagedash_nfs_exports', 'Configured NFS exports', 'gauge',
                 [('', len(parse_exports()))]))
    fams.append(('storagedash_smb_shares', 'Configured SMB shares', 'gauge',
                 [('', len([n for n in smbconf_parse() if n.lower() not in ('global', 'homes')]))]))
    smart_ok = _smart_health_ok()
    if smart_ok is not None:
        fams.append(('storagedash_disk_smart_ok', 'All disks pass SMART (1) or a failure (0)',
                     'gauge', [('', 1 if smart_ok else 0)]))
    return fams


@app.route('/metrics')
def metrics():
    if METRICS_TOKEN:
        tok = request.args.get('token', '')
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            tok = auth[7:]
        if tok != METRICS_TOKEN:
            return Response('unauthorized\n', status=401, mimetype='text/plain')
    return Response(_render_metrics(_metrics_families()),
                    mimetype='text/plain; version=0.0.4; charset=utf-8')


BOOT_MOUNTS = {'/', '/boot', '/boot/efi', '/boot/efi/', '[SWAP]'}


def _walk(node):
    yield node
    for c in (node.get('children') or []):
        yield from _walk(c)


def _mdadm_conf_arrays():
    """Names of md arrays declared in mdadm.conf (treated as 'defined')."""
    names = set()
    try:
        with open(MDADM_CONF) as f:
            for line in f:
                if line.strip().upper().startswith('ARRAY') and len(line.split()) >= 2:
                    names.add(os.path.basename(line.split()[1]))
    except FileNotFoundError:
        pass
    return names


def _zfs_active_member(node, pool_map):
    """True if any part of this disk belongs to a currently-imported pool. A
    `zfs_member` signature alone is NOT enough — `zpool destroy`/export leaves the
    label behind, so we only trust live membership (from `zpool status`)."""
    return any(n.get('name') in pool_map for n in _walk(node))


def disk_wipe_status(node, defined_md, pool_map):
    """Decide whether a whole disk may be wiped, and why not if not. Protects
    boot/system disks, mounted disks, *live* ZFS/LVM members, and disks in an
    active or defined RAID array. A disk held only by a *stale* signature — an
    auto-assembled md not in mdadm.conf, or a `zfs_member` label from a
    destroyed/exported pool — stays wipeable (md devices to stop are recorded)."""
    nodes = list(_walk(node))
    mounts = [n.get('mountpoint') for n in nodes if n.get('mountpoint')]
    fstypes = [n.get('fstype') for n in nodes if n.get('fstype')]
    if any(m in BOOT_MOUNTS for m in mounts):
        return {'wipeable': False, 'reason': 'system/boot disk'}
    if 'zfs_member' in fstypes and _zfs_active_member(node, pool_map):
        return {'wipeable': False, 'reason': 'ZFS pool member'}
    if 'LVM2_member' in fstypes:
        return {'wipeable': False, 'reason': 'LVM member'}
    md_stale = []
    for md in [n for n in nodes if (n.get('type') or '') == 'md' or (n.get('type') or '').startswith('raid')]:
        sub = list(_walk(md))
        in_use = any(s.get('mountpoint') for s in sub) or \
                 any(s.get('fstype') in ('zfs_member', 'LVM2_member') for s in sub)
        if in_use or md.get('name') in defined_md:
            return {'wipeable': False, 'reason': 'active RAID array member'}
        md_stale.append(md.get('name'))
    if mounts:
        return {'wipeable': False, 'reason': 'mounted'}
    return {'wipeable': True, 'reason': None, 'md_stop': md_stale}


def _zpool_disk_map():
    """Map device basenames (as `zpool status` reports them) to their pool."""
    out, _, _ = run(['zpool', 'status', '-LP'])
    mapping = {}
    pool = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith('pool:'):
            pool = s.split(':', 1)[1].strip()
        elif pool and s.startswith('/dev/'):
            mapping[os.path.basename(s.split()[0])] = pool
    return mapping


# Identify pool members by stable /dev/disk/by-id links (serial/WWN based) rather
# than kernel names (nvme0n1, sda), which can be reordered across reboots and make
# ZFS report a healthy pool as DEGRADED. This is the OpenZFS-recommended scheme.
BY_ID_DIR = '/dev/disk/by-id'


def _by_id_rank(link):
    """Preference key for choosing among several by-id links for one disk.
    Lower sorts first: descriptive serial-bearing ids beat bare wwn-; longer
    (more specific) names win ties. Used only to pick a canonical link."""
    if link.startswith(('nvme-', 'ata-', 'scsi-')) and not link.startswith('nvme-eui.'):
        prio = 0
    elif link.startswith('wwn-') or link.startswith('nvme-eui.'):
        prio = 1
    else:
        prio = 2
    return (prio, -len(link), link)


def _disk_by_id_map(by_id_dir=BY_ID_DIR):
    """Map kernel basename (e.g. 'nvme0n1', 'sda') -> preferred stable
    '/dev/disk/by-id/<link>' path. Reads the symlinks directly (world-readable,
    no sudo); partition links (containing '-part') are skipped so only whole-disk
    identifiers are returned."""
    candidates = {}
    try:
        names = os.listdir(by_id_dir)
    except OSError:
        return {}
    for link in names:
        if '-part' in link:
            continue
        full = os.path.join(by_id_dir, link)
        try:
            target = os.path.basename(os.readlink(full))
        except OSError:
            continue
        candidates.setdefault(target, []).append(link)
    return {dev: os.path.join(by_id_dir, sorted(links, key=_by_id_rank)[0])
            for dev, links in candidates.items()}


def _resolve_stable_dev(dev, by_id_map):
    """Resolve a member identifier (bare name, /dev/X, or an existing by-id path)
    to its stable by-id path. Falls back to the original when no by-id link
    exists (loopback-file scratch pools, virtio disks without a serial) so those
    keep working. Returns (resolved, used_stable)."""
    d = (dev or '').strip()
    if d.startswith(BY_ID_DIR + '/'):
        return d, True
    base = os.path.basename(d)
    stable = by_id_map.get(base)
    if stable:
        return stable, True
    return d, False


# Classify a pool-member path (as `zpool status -P` reports it, WITHOUT -L so
# symlinks are kept) into stable / kernel / other.
RE_KERNEL_DEV = re.compile(r'^/dev/(sd|nvme|vd|hd|xvd|mmcblk|dm-|md)[0-9a-z]')


def _classify_member_path(path):
    if path.startswith(BY_ID_DIR + '/'):
        return 'stable'
    if RE_KERNEL_DEV.match(path):
        return 'kernel'
    return 'other'   # file vdev, /dev/disk/by-{path,uuid}, etc. — not flagged


def _pool_uses_kernel_names(name):
    """True if any leaf vdev of `name` is referenced by a kernel device node
    (and is thus reorder-unstable). Uses `zpool status -P` (full paths) WITHOUT
    -L so stored by-id symlinks are not resolved back to kernel names."""
    out, _, _ = run(['zpool', 'status', '-P', name])
    for line in (out or '').splitlines():
        tok = line.strip().split()
        if tok and tok[0].startswith('/') and _classify_member_path(tok[0]) == 'kernel':
            return True
    return False


def disk_usage(node, pool_map, defined_md):
    """A short human label of what a whole disk is being used for."""
    nodes = list(_walk(node))
    mounts = [n.get('mountpoint') for n in nodes if n.get('mountpoint')]
    fstypes = [n.get('fstype') for n in nodes if n.get('fstype')]
    if any(m in BOOT_MOUNTS for m in mounts):
        return 'System / boot'
    if 'zfs_member' in fstypes:
        for n in nodes:
            if n.get('name') in pool_map:
                return f'ZFS pool: {pool_map[n["name"]]}'
        return 'ZFS member (stale)'
    if 'LVM2_member' in fstypes:
        return 'LVM member'
    md_nodes = [n for n in nodes if (n.get('type') or '') == 'md' or (n.get('type') or '').startswith('raid')]
    for md in md_nodes:
        sub = list(_walk(md))
        if any(s.get('mountpoint') for s in sub) or \
           any(s.get('fstype') in ('zfs_member', 'LVM2_member') for s in sub) or \
           md.get('name') in defined_md:
            return f'RAID: {md.get("name")}'
    if md_nodes or 'linux_raid_member' in fstypes:
        return 'RAID member (stale)'
    if mounts:
        return f'Mounted: {mounts[0]}'
    return 'Free'


@app.route('/api/disks')
def api_disks():
    out, _, _ = run(['lsblk', '-J', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL,SERIAL,TRAN'])
    try:
        data = json.loads(out) if out.strip() else {'blockdevices': []}
    except json.JSONDecodeError:
        data = {'blockdevices': []}
    devices = data.get('blockdevices', [])
    defined_md = _mdadm_conf_arrays()
    pool_map = _zpool_disk_map()
    by_id_map = _disk_by_id_map()
    for d in devices:
        if (d.get('type') or '') == 'disk':
            st = disk_wipe_status(d, defined_md, pool_map)
            d['wipeable'] = st['wipeable']
            d['wipe_reason'] = st.get('reason')
            d['md_stop'] = st.get('md_stop', [])
            d['usage'] = disk_usage(d, pool_map, defined_md)
            d['by_id'] = by_id_map.get(d.get('name'))
    out2, _, _ = run(['lsscsi', '-t'])
    return jsonify({'devices': devices, 'scsi_info': out2})

@app.route('/api/disks/<dev>/smart')
def disk_smart(dev):
    """SMART health for a single block device, normalized across ATA and NVMe.
    smartctl's exit code is a bitmask (non-zero != failure), so we always parse
    the JSON it emits rather than gating on the return code."""
    if not RE_DEVNAME.match(dev):
        return err('Invalid device')
    out, e, _ = run(['smartctl', '-H', '-A', '-i', '-j', f'/dev/{dev}'])
    try:
        data = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        return jsonify({'device': dev, 'available': False, 'error': e or 'no SMART data'})

    status = data.get('smart_status') or {}
    info = {
        'device': dev,
        'available': bool(data),
        'model': data.get('model_name'),
        'serial': data.get('serial_number'),
        'firmware': data.get('firmware_version'),
        'rotation_rate': data.get('rotation_rate'),
        'capacity': (data.get('user_capacity') or {}).get('bytes'),
        'health': ('PASSED' if status['passed'] else 'FAILED') if 'passed' in status else 'unknown',
        'temperature_c': (data.get('temperature') or {}).get('current'),
        'power_on_hours': (data.get('power_on_time') or {}).get('hours'),
    }

    # ATA attributes of interest
    attrs = {}
    for a in ((data.get('ata_smart_attributes') or {}).get('table') or []):
        attrs[a.get('name')] = (a.get('raw') or {}).get('value')
    if attrs:
        info['reallocated'] = attrs.get('Reallocated_Sector_Ct')
        info['pending'] = attrs.get('Current_Pending_Sector')
        info['uncorrectable'] = attrs.get('Offline_Uncorrectable')

    # NVMe health log
    nvme = data.get('nvme_smart_health_information_log')
    if nvme:
        info['power_on_hours'] = info['power_on_hours'] or nvme.get('power_on_hours')
        info['temperature_c'] = info['temperature_c'] or nvme.get('temperature')
        info['media_errors'] = nvme.get('media_errors')
        info['percentage_used'] = nvme.get('percentage_used')
        info['critical_warning'] = nvme.get('critical_warning')

    msgs = [m.get('string') for m in ((data.get('smartctl') or {}).get('messages') or [])]
    if msgs:
        info['messages'] = msgs
    return jsonify(info)

@app.route('/api/disks/<dev>/wipe', methods=['POST'])
def disk_wipe(dev):
    """Wipe a disk back to a blank state: stop any stale md array holding it,
    zero RAID superblocks, remove all signatures, and clear the partition table.
    Eligibility is re-checked server-side here — the client is never trusted."""
    if not RE_DEVNAME.match(dev):
        return err('Invalid device')
    out, _, _ = run(['lsblk', '-J', '-o', 'NAME,TYPE,FSTYPE,MOUNTPOINT', f'/dev/{dev}'])
    try:
        tree = json.loads(out).get('blockdevices', []) if out.strip() else []
    except json.JSONDecodeError:
        tree = []
    if not tree:
        return err('Device not found', 404)
    node = tree[0]
    if (node.get('type') or '') != 'disk':
        return err('Not a whole disk')
    status = disk_wipe_status(node, _mdadm_conf_arrays(), _zpool_disk_map())
    if not status['wipeable']:
        return err(f'Refusing to wipe: {status["reason"]}', 409)

    target = f'/dev/{dev}'
    parts = ['/dev/' + n.get('name') for n in _walk(node) if (n.get('type') or '') == 'part']
    steps = []

    # 1. Stop any stale assembled md array holding this disk.
    for md in status.get('md_stop', []):
        if RE_DEVNAME.match(md or ''):
            steps.append({'step': f'stop md {md}', **run_safe(['mdadm', '--stop', f'/dev/{md}'])})
    # 2. Clear stale ZFS labels (front + back) and RAID superblocks on members +
    #    whole disk, then signatures (ignore "no label/superblock" failures).
    for m in parts:
        run(['zpool', 'labelclear', '-f', m])
        run(['mdadm', '--zero-superblock', m])
        run_safe(['wipefs', '-a', m])
    run(['zpool', 'labelclear', '-f', target])
    run(['mdadm', '--zero-superblock', target])
    # 3. Remove remaining signatures and clear the partition table.
    steps.append({'step': 'wipefs', **run_safe(['wipefs', '-a', target])})
    steps.append({'step': 'zap partition table', **run_safe(['sgdisk', '--zap-all', target])})
    run(['partprobe', target])

    ok = all(s.get('success', True) for s in steps)
    return jsonify({'success': ok, 'steps': steps})

# ─── Disk locate (identify a physical drive) ──────────────────────────
# Best-effort enclosure locate LED (ledctl, SES/SGPIO) PLUS read-only I/O so the
# drive's activity light flashes on any hardware. Read-only -> safe on any disk,
# including in-use pool members (the usual reason you want to find a drive).

_locate_jobs = {}
_locate_lock = threading.Lock()


def _locate_worker(dev, seconds, stop):
    run(['ledctl', f'locate=/dev/{dev}'])  # best effort; no-op if unsupported
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not stop.is_set():
        # Root-owned read-only helper (O_DIRECT) -> real device reads so the
        # activity LED flashes; the pause between bursts makes it blink.
        run(['/usr/local/sbin/storage-dashboard-locate-read', dev])
        stop.wait(0.3)
    run(['ledctl', f'locate_off=/dev/{dev}'])
    with _locate_lock:
        if _locate_jobs.get(dev) is stop:
            del _locate_jobs[dev]


def _locate_stop(dev):
    with _locate_lock:
        ev = _locate_jobs.pop(dev, None)
    if ev:
        ev.set()


@app.route('/api/disks/<dev>/locate', methods=['POST'])
def disk_locate(dev):
    if not RE_DEVNAME.match(dev):
        return err('Invalid device')
    if not os.path.exists(f'/dev/{dev}'):
        return err('Device not found', 404)
    data = request.get_json(silent=True) or {}
    if data.get('stop'):
        _locate_stop(dev)
        run(['ledctl', f'locate_off=/dev/{dev}'])
        return jsonify({'success': True, 'stopped': True})
    try:
        seconds = max(3, min(120, int(data.get('seconds', 20))))
    except (TypeError, ValueError):
        seconds = 20
    _locate_stop(dev)  # restart any existing job
    stop = threading.Event()
    with _locate_lock:
        _locate_jobs[dev] = stop
    threading.Thread(target=_locate_worker, args=(dev, seconds, stop), daemon=True).start()
    return jsonify({'success': True, 'seconds': seconds,
                    'message': f'Locating {dev} for {seconds}s — drive activity light '
                               f'(and enclosure locate LED if supported).'})

# ─── Plain-disk format & mount ────────────────────────────────────────
# Everyday "format this disk and mount it" workflow for standard filesystems
# (incl. a just-plugged-in USB drive). All the dangerous primitives — mount,
# umount, and /etc/fstab edits — go through the root-owned wrapper
# `storage-dashboard-mount`, which is the trust boundary: it confines mount
# points to MOUNT_BASES, forces a safe fstab option set, and validates fstab
# before committing. Formatting reuses already-granted tools (wipefs/sgdisk/
# partprobe/mkfs.*). Eligibility is always re-checked server-side.

MOUNT_HELPER = '/usr/local/sbin/storage-dashboard-mount'
FSTAB_PATH = '/etc/fstab'
FSTAB_MARK_BEGIN = '# >>> storage-dashboard managed >>>'
FSTAB_MARK_END = '# <<< storage-dashboard managed <<<'

# mkfs invocation per filesystem: command, force flag, label flag, and the
# GPT partition type code (Linux filesystem vs Microsoft basic data).
MKFS_CFG = {
    'ext4':  {'cmd': 'mkfs.ext4',  'force': '-F', 'label': '-L', 'labelmax': 16, 'ptype': '8300'},
    'xfs':   {'cmd': 'mkfs.xfs',   'force': '-f', 'label': '-L', 'labelmax': 12, 'ptype': '8300'},
    'vfat':  {'cmd': 'mkfs.vfat',  'force': None, 'label': '-n', 'labelmax': 11, 'ptype': '0700'},
    'exfat': {'cmd': 'mkfs.exfat', 'force': None, 'label': '-L', 'labelmax': 15, 'ptype': '0700'},
}


def _part1_name(dev):
    """Kernel name of partition 1 on a whole disk: sdb→sdb1, nvme0n1→nvme0n1p1."""
    return f'{dev}p1' if dev[-1:].isdigit() else f'{dev}1'


def _managed_fstab_uuids(path=FSTAB_PATH):
    """UUIDs the dashboard added to /etc/fstab (inside its managed block).
    fstab is world-readable, so no sudo is needed to read it."""
    uuids = set()
    try:
        lines = open(path).read().splitlines()
    except OSError:
        return uuids
    inblock = False
    for ln in lines:
        s = ln.strip()
        if s == FSTAB_MARK_BEGIN:
            inblock = True
        elif s == FSTAB_MARK_END:
            inblock = False
        elif inblock and s.startswith('UUID='):
            uuids.add(s.split()[0][len('UUID='):])
    return uuids


def _list_filesystems():
    """Plain mountable filesystems (partitions or whole-disk), including USB.
    Excludes ZFS/LVM/MD/swap members (those belong to other subsystems)."""
    out, _, _ = run(['lsblk', '-J', '-o',
                     'NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,UUID,TRAN,MODEL'])
    try:
        devices = json.loads(out).get('blockdevices', []) if out.strip() else []
    except json.JSONDecodeError:
        devices = []
    managed = _managed_fstab_uuids()
    fs = []
    for top in devices:
        for n in _walk(top):
            fstype = n.get('fstype')
            if not fstype or fstype in NON_MOUNTABLE_FSTYPES:
                continue
            if (n.get('type') or '') not in ('part', 'disk'):
                continue
            mnt = n.get('mountpoint') or ''
            system = mnt in BOOT_MOUNTS or any(
                mnt == b or mnt.startswith(b + '/') for b in ('/', '/boot', '/usr', '/var', '/etc'))
            # A non-system mount that isn't under our bases (e.g. mounted by
            # hand elsewhere) is shown but treated as not-ours to unmount.
            ours = any(mnt == b or mnt.startswith(b + '/') for b in MOUNT_BASES)
            fs.append({
                'name': n.get('name'), 'size': n.get('size'), 'fstype': fstype,
                'label': n.get('label'), 'uuid': n.get('uuid'),
                'tran': n.get('tran'), 'model': (n.get('model') or '').strip(),
                'mountpoint': mnt or None, 'mounted': bool(mnt),
                'system': system, 'unmountable': bool(mnt) and not system and ours,
                'fstab': bool(n.get('uuid') and n.get('uuid') in managed),
            })
    return fs


@app.route('/api/disks/<dev>/format', methods=['POST'])
def disk_format(dev):
    """Initialize a Free disk: GPT label + one whole-disk partition + mkfs.
    Refuses any disk that is in use (re-checked here, client never trusted)."""
    if not RE_DEVNAME.match(dev):
        return err('Invalid device')
    data = request.get_json(silent=True) or {}
    fstype = (data.get('fstype') or '').lower()
    if fstype not in MOUNT_FSTYPES:
        return err('Unsupported filesystem type')
    label = data.get('label') or ''
    if label and not RE_FSLABEL.match(label):
        return err('Invalid label (letters, digits, . _ - ; max 32)')

    out, _, _ = run(['lsblk', '-J', '-o', 'NAME,TYPE,FSTYPE,MOUNTPOINT', f'/dev/{dev}'])
    try:
        tree = json.loads(out).get('blockdevices', []) if out.strip() else []
    except json.JSONDecodeError:
        tree = []
    if not tree:
        return err('Device not found', 404)
    node = tree[0]
    if (node.get('type') or '') != 'disk':
        return err('Not a whole disk')
    status = disk_wipe_status(node, _mdadm_conf_arrays(), _zpool_disk_map())
    if not status['wipeable']:
        return err(f'Refusing to format: {status["reason"]}', 409)

    cfg = MKFS_CFG[fstype]
    target = f'/dev/{dev}'
    steps = []
    # Clear any stale signatures / labels, then lay down a fresh GPT + 1 part.
    for m in ['/dev/' + n.get('name') for n in _walk(node) if (n.get('type') or '') == 'part']:
        run(['wipefs', '-a', m])
    steps.append({'step': 'wipe signatures', **run_safe(['wipefs', '-a', target])})
    steps.append({'step': 'new GPT label', **run_safe(['sgdisk', '-Z', target])})
    steps.append({'step': 'create partition',
                  **run_safe(['sgdisk', '-n', '1:0:0', '-t', f'1:{cfg["ptype"]}', target])})
    run(['partprobe', target])

    part = _part1_name(dev)
    pdev = f'/dev/{part}'
    for _ in range(20):  # give udev a moment to create the partition node
        if os.path.exists(pdev):
            break
        time.sleep(0.15)
    if not os.path.exists(pdev):
        return jsonify({'success': False, 'error': 'Partition did not appear after partitioning',
                        'steps': steps}), 500

    mkfs = [cfg['cmd']]
    if cfg['force']:
        mkfs.append(cfg['force'])
    if label:
        lbl = label[:cfg['labelmax']]
        if fstype == 'vfat':
            lbl = lbl.upper()
        mkfs += [cfg['label'], lbl]
    mkfs.append(pdev)
    steps.append({'step': f'mkfs.{fstype}', **run_safe(mkfs)})

    # Let udev catch up so the new filesystem's UUID/fstype are populated before
    # we read them back (and before the UI re-lists filesystems).
    run(['udevadm', 'settle'], no_sudo=True)
    uuid = ''
    for _ in range(20):
        uuid = run(['lsblk', '-no', 'UUID', pdev], no_sudo=True)[0].strip()
        if uuid:
            break
        time.sleep(0.15)
    ok = all(s.get('success', True) for s in steps)
    return jsonify({'success': ok, 'steps': steps, 'partition': part, 'uuid': uuid})


@app.route('/api/filesystems')
def api_filesystems():
    return jsonify({'filesystems': _list_filesystems(), 'bases': list(MOUNT_BASES)})


def _lookup_fs(part):
    """(node-dict, error-response) for a partition/disk that holds a plain fs."""
    out, _, _ = run(['lsblk', '-J', '-o', 'NAME,TYPE,FSTYPE,UUID,MOUNTPOINT', f'/dev/{part}'])
    try:
        tree = json.loads(out).get('blockdevices', []) if out.strip() else []
    except json.JSONDecodeError:
        tree = []
    if not tree:
        return None, err('Device not found', 404)
    n = tree[0]
    fstype = n.get('fstype')
    if not fstype or fstype in NON_MOUNTABLE_FSTYPES:
        return None, err('Not a mountable filesystem (it belongs to ZFS/LVM/RAID/swap)', 409)
    return n, None


@app.route('/api/filesystems/<part>/mount', methods=['POST'])
def fs_mount(part):
    if not RE_DEVNAME.match(part):
        return err('Invalid device')
    data = request.get_json(silent=True) or {}
    name = data.get('name') or part
    if not RE_MOUNTNAME.match(name):
        return err('Invalid mount-point name (letters, digits, . _ -)')
    base = data.get('base') or MOUNT_BASES[0]
    if base not in MOUNT_BASES:
        return err('Invalid mount base')
    n, e = _lookup_fs(part)
    if e:
        return e
    if n.get('mountpoint'):
        return err(f'Already mounted at {n["mountpoint"]}', 409)
    res = run_safe([MOUNT_HELPER, 'mount', part, name, base])
    if not res['success']:
        return jsonify({'success': False, 'error': res['stderr'].strip() or 'mount failed',
                        'detail': res}), 500
    fstab = bool(data.get('fstab'))
    fstab_res = None
    if fstab:
        uuid = n.get('uuid')
        if not uuid:
            fstab_res = {'success': False, 'stderr': 'no filesystem UUID; cannot persist'}
        else:
            fstab_res = run_safe([MOUNT_HELPER, 'fstab-add', uuid, f'{base}/{name}', n.get('fstype')])
    return jsonify({'success': True, 'mountpoint': f'{base}/{name}',
                    'fstab': (fstab_res['success'] if fstab_res else False),
                    'fstab_detail': fstab_res})


@app.route('/api/filesystems/<part>/unmount', methods=['POST'])
def fs_unmount(part):
    if not RE_DEVNAME.match(part):
        return err('Invalid device')
    data = request.get_json(silent=True) or {}
    n, e = _lookup_fs(part)
    if e:
        return e
    mnt = n.get('mountpoint')
    if not mnt:
        return err('Not mounted', 409)
    if not any(mnt == b or mnt.startswith(b + '/') for b in MOUNT_BASES):
        return err('Refusing to unmount: not a dashboard-managed mount point', 409)
    res = run_safe([MOUNT_HELPER, 'umount', part])
    if not res['success']:
        return jsonify({'success': False, 'error': res['stderr'].strip() or 'unmount failed',
                        'detail': res}), 500
    fstab_res = None
    if data.get('remove_fstab') and n.get('uuid'):
        fstab_res = run_safe([MOUNT_HELPER, 'fstab-remove', n.get('uuid')])
    return jsonify({'success': True, 'fstab_removed': (fstab_res['success'] if fstab_res else False),
                    'fstab_detail': fstab_res})


@app.route('/api/logs/<service>')
def api_logs(service):
    svc = resolve_service(service)
    if not svc:
        return err('Invalid service')
    out, _, rc = run(['journalctl', '-u', svc, '--no-pager', '-n', '100', '--output=short-unix'])
    if rc != 0 or not out.strip():
        out = out or 'No logs available'
    return jsonify({'logs': out})


# ─── Log viewer (feature 08) ──────────────────────────────────────────
# A journald browser over a CURATED set of units (this app, the system services,
# and the dashboard-managed task units) — never an arbitrary unit from the client,
# and the grep filter is allowlisted so it can't become a journalctl flag.
LOG_PRIORITIES = {'0', '1', '2', '3', '4', '5', '6', '7'}
RE_LOG_GREP = re.compile(r'^[\w .:@/=,+-]{0,120}$')


def _own_unit():
    """This process's own systemd unit (the unit name varies by deployment, e.g.
    storage-dashboard vs a custom name). Falls back sanely when not run by systemd."""
    try:
        with open('/proc/self/cgroup') as f:
            m = re.search(r'/([A-Za-z0-9@._-]+\.service)', f.read())
        if m:
            return m.group(1)
    except OSError:
        pass
    return 'storage-dashboard.service'


def _log_sources():
    srcs = [{'id': 'dashboard', 'label': 'Dashboard (this app)', 'unit': _own_unit()}]
    for key, svc in SYSTEM_SERVICES.items():
        srcs.append({'id': 'svc:' + key, 'label': svc['name'], 'unit': svc['service']})
    for t in MANAGED_TASKS:
        srcs.append({'id': 'task:' + t['id'], 'label': t['label'] + ' (task)', 'unit': t['service']})
    return srcs


def _log_unit_for(source):
    return next((s['unit'] for s in _log_sources() if s['id'] == source), None)


@app.route('/api/logs/sources')
def logs_sources():
    return jsonify({'sources': _log_sources()})


@app.route('/api/logs/query')
def logs_query():
    """Filtered journald tail for one curated source. Read-only."""
    unit = _log_unit_for(request.args.get('source', ''))
    if not unit:
        return err('Unknown log source', 404)
    try:
        lines = max(10, min(int(request.args.get('lines', 200)), 2000))
    except (TypeError, ValueError):
        lines = 200
    args = ['journalctl', '-u', unit, '--no-pager', '-n', str(lines), '--output=short-iso']
    pri = request.args.get('priority', '')
    if pri:
        if pri not in LOG_PRIORITIES:
            return err('Invalid priority')
        args.append('--priority=' + pri)
    grep = (request.args.get('grep') or '').strip()
    if grep:
        if not RE_LOG_GREP.match(grep):
            return err('Invalid filter (allowed: letters, digits, space . : @ / = , + -)')
        # '=' form + a separate flag keeps a leading '-' in the pattern from being
        # read as an option; case-insensitive for convenience.
        args += ['--grep=' + grep, '--case-sensitive=no']
    out, _, rc = run(args)
    if rc != 0 and not out.strip():
        out = out or 'No logs available'
    return jsonify({'unit': unit, 'logs': out or 'No matching log entries'})

# ─── Service Control ──────────────────────────────────────────────────

def systemctl_cmd(action, service):
    return run_safe(['systemctl', action, service])

def _service_action(action, service):
    svc = resolve_service(service)
    if not svc:
        return err('Invalid service')
    return jsonify(systemctl_cmd(action, svc))

@app.route('/api/service/<service>/start', methods=['POST'])
def service_start(service):
    return _service_action('start', service)

@app.route('/api/service/<service>/stop', methods=['POST'])
def service_stop(service):
    return _service_action('stop', service)

@app.route('/api/service/<service>/restart', methods=['POST'])
def service_restart(service):
    return _service_action('restart', service)

@app.route('/api/service/<service>/enable', methods=['POST'])
def service_enable(service):
    return _service_action('enable', service)

@app.route('/api/service/<service>/disable', methods=['POST'])
def service_disable(service):
    return _service_action('disable', service)

# ─── ZFS Pool Management ─────────────────────────────────────────────

def parse_zpool_status(output):
    pools = {}
    current_pool = None
    for line in output.split('\n'):
        if line.startswith('  pool:'):
            current_pool = line.split('pool:')[1].strip()
            pools[current_pool] = {'config': [], 'errors': ''}
        elif line.startswith(' state:') and current_pool:
            pools[current_pool]['state'] = line.split('state:')[1].strip()
        elif line.startswith('  scan:') and current_pool:
            pools[current_pool]['scan'] = line.split('scan:')[1].strip()
        elif line.startswith('config:') and current_pool:
            pass
        elif current_pool and ('ONLINE' in line or 'DEGRADED' in line or 'FAULTED' in line or 'OFFLINE' in line or 'UNAVAIL' in line or 'REMOVED' in line):
            pools[current_pool]['config'].append(line.strip())
        elif line.startswith('errors:') and current_pool:
            pools[current_pool]['errors'] = line.split('errors:')[1].strip()
    return pools

@app.route('/api/zfs/pools')
def zfs_pools():
    out, e, rc = run(['zpool', 'list', '-Ho', 'name,size,alloc,free,cap,frag,dedup,health,altroot'])
    if rc != 0:
        return jsonify({'pools': [], 'raw_output': e})
    pools = []
    for line in out.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split('\t')
        if len(parts) >= 8:
            pools.append({
                'name': parts[0], 'size': parts[1], 'alloc': parts[2],
                'free': parts[3], 'cap': parts[4], 'frag': parts[5],
                'dedup': parts[6], 'health': parts[7], 'altroot': parts[8],
            })
    return jsonify(pools)

@app.route('/api/zfs/pools/detail')
def zfs_pools_detail():
    out, _, _ = run(['zpool', 'status'])
    pools = {}
    if out:
        pools = parse_zpool_status(out)
    # Flag pools whose members are referenced by reorder-unstable kernel names so
    # the UI can offer to "stabilize" them (re-import by /dev/disk/by-id).
    for pname, pdata in pools.items():
        pdata['unstable'] = _pool_uses_kernel_names(pname)
    return jsonify(pools)


def _parse_arcstats(text):
    """Parse /proc/spl/kstat/zfs/arcstats ('name  type  value' columns) into a
    flat {name: int}. Pure — unit-tested without ZFS present."""
    stats = {}
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2].lstrip('-').isdigit():
            stats[parts[0]] = int(parts[2])
    return stats


def _arc_summary(stats):
    """Derive the headline ARC/L2ARC figures from raw arcstats."""
    hits, misses = stats.get('hits', 0), stats.get('misses', 0)
    total = hits + misses
    l2_size = stats.get('l2_size', 0)
    return {
        'size': stats.get('size', 0),
        'c_max': stats.get('c_max', 0),
        'c_min': stats.get('c_min', 0),
        'hits': hits, 'misses': misses,
        'hit_ratio': round(hits / total * 100, 1) if total else None,
        'l2_present': l2_size > 0,
        'l2_size': l2_size,
        'l2_hits': stats.get('l2_hits', 0),
        'l2_misses': stats.get('l2_misses', 0),
    }


@app.route('/api/zfs/arc')
def zfs_arc():
    """ARC/L2ARC stats from /proc (no sudo). ARC is present on any host with ZFS
    loaded regardless of cache devices; l2_present stays false until an L2ARC
    (cache vdev) exists."""
    try:
        with open('/proc/spl/kstat/zfs/arcstats') as f:
            stats = _parse_arcstats(f.read())
    except OSError:
        return jsonify({'available': False})
    return jsonify({'available': True, **_arc_summary(stats)})


@app.route('/api/zfs/pools/<name>/scrub', methods=['POST'])
def zfs_pool_scrub(name):
    if not RE_POOL.match(name):
        return err('Invalid pool name')
    action = (request.get_json(silent=True) or {}).get('action', 'start')
    if action == 'start':
        return jsonify(run_safe(['zpool', 'scrub', name]))
    if action == 'stop':
        return jsonify(run_safe(['zpool', 'scrub', '-s', name]))
    return err('Invalid scrub action')

@app.route('/api/zfs/pools/<name>/trim', methods=['POST'])
def zfs_pool_trim(name):
    """SSD TRIM: reclaim unused blocks. Errors on vdevs that don't support it are
    surfaced from stderr rather than swallowed."""
    if not RE_POOL.match(name):
        return err('Invalid pool name')
    action = (request.get_json(silent=True) or {}).get('action', 'start')
    if action == 'start':
        return jsonify(run_safe(['zpool', 'trim', name]))
    if action == 'cancel':
        return jsonify(run_safe(['zpool', 'trim', '-c', name]))
    return err('Invalid trim action')

@app.route('/api/zfs/pools/<name>/autotrim', methods=['POST'])
def zfs_pool_autotrim(name):
    if not RE_POOL.match(name):
        return err('Invalid pool name')
    enabled = bool((request.get_json(silent=True) or {}).get('enabled'))
    return jsonify(run_safe(['zpool', 'set', 'autotrim=' + ('on' if enabled else 'off'), name]))

@app.route('/api/zfs/pools/<name>/device', methods=['POST'])
def zfs_pool_device(name):
    """Per-device operations: offline / online / detach a member, replace a
    member with a new device, or remove a device. `detach` splits a mirror
    member; `remove` pulls a cache (L2ARC) / log (SLOG) / spare device (and, on
    modern OpenZFS, evacuates a top-level data vdev)."""
    if not RE_POOL.match(name):
        return err('Invalid pool name')
    data = request.get_json() or {}
    action = data.get('action', '')
    device = (data.get('device') or '').strip()
    if action not in ('replace', 'offline', 'online', 'detach', 'remove'):
        return err('Invalid device action')
    if not device or not RE_DEVICE.match(device):
        return err('Invalid device')
    if action == 'replace':
        new_device = (data.get('new_device') or '').strip()
        if not new_device or not RE_DEVICE.match(new_device):
            return err('Invalid replacement device')
        # Bring the replacement in by its stable by-id path so it survives reboots.
        new_device, _ = _resolve_stable_dev(new_device, _disk_by_id_map())
        return jsonify(run_safe(['zpool', 'replace', name, device, new_device]))
    return jsonify(run_safe(['zpool', action, name, device]))

def _zfs_disk_usable(dev):
    """Whether a device may back a new pool/vdev. `zpool create/add` use -f, so
    the server must reject in-use disks itself (the client is never trusted): a
    real block device must be free — not mounted/boot, nor a ZFS/RAID/LVM/swap
    member (a stale label counts as in-use; wipe it first). A path lsblk doesn't
    recognise as a block device (e.g. a file vdev) is allowed — it can't clobber
    other storage."""
    if not RE_DISK.match(dev):
        return False
    out, _, _ = run(['lsblk', '-J', '-o', 'NAME,FSTYPE,MOUNTPOINT', dev])
    try:
        nodes = json.loads(out).get('blockdevices', [])
    except json.JSONDecodeError:
        nodes = []
    if not nodes:
        return True   # not a block device (file vdev) — no risk to other storage
    for n in nodes:
        for x in _walk(n):
            if x.get('mountpoint'):
                return False
            if x.get('fstype') in ('zfs_member', 'linux_raid_member', 'LVM2_member', 'swap'):
                return False
    return True


@app.route('/api/zfs/pools/<name>/vdev', methods=['POST'])
def zfs_pool_add_vdev(name):
    """Add a vdev to a pool: extra data vdev (optionally mirror/raidz), or a
    spare / cache (L2ARC) / log (SLOG) device."""
    if not RE_POOL.match(name):
        return err('Invalid pool name')
    data = request.get_json() or {}
    role = data.get('role', '')
    disks = data.get('disks', [])
    if role not in VDEV_ADD_ROLES:
        return err('Invalid vdev role')
    if not disks:
        return err('No disks specified')
    for d in disks:
        if not RE_DEVICE.match(d):
            return err(f'Invalid disk: {d}')
        if not _zfs_disk_usable(d):
            return err(f'Disk {d} is in use (mounted/boot or a pool/RAID/LVM member) — refusing', 409)
    by_id_map = _disk_by_id_map()
    disks = [_resolve_stable_dev(d, by_id_map)[0] for d in disks]
    cmd = ['zpool', 'add', '-f', name]
    if role:
        cmd.append(role)
    cmd.extend(disks)
    return jsonify(run_safe(cmd))

# Section keywords that precede a vdev group in `zpool create` ('' = data vdev).
VDEV_ROLES = {'', 'log', 'cache', 'spare'}


def _normalize_vdev_spec(data):
    """Return (groups, error). Each group is {role, type, disks}. Accepts the
    structured `vdevs` list AND the legacy {vdev_type, disks} single-group form."""
    if isinstance(data.get('vdevs'), list):
        groups = []
        for g in data['vdevs']:
            if not isinstance(g, dict):
                return None, 'Invalid vdev group'
            groups.append({'role': (g.get('role') or '').strip(),
                           'type': (g.get('type') or '').strip(),
                           'disks': g.get('disks') or []})
        return groups, None
    return [{'role': '', 'type': (data.get('vdev_type') or '').strip(),
             'disks': data.get('disks') or []}], None


def _pool_vdev_args(groups):
    """Turn normalized {role,type,disks} groups (disks already resolved) into the
    `zpool create` argument tail. Pure — raises ValueError on an invalid spec."""
    args = []
    for g in groups:
        role, vtype, disks = g['role'], g['type'], g['disks']
        if role not in VDEV_ROLES:
            raise ValueError(f'Invalid vdev role: {role}')
        if vtype not in VDEV_TYPES:
            raise ValueError(f'Invalid vdev type: {vtype}')
        if not disks:
            raise ValueError('A vdev group has no disks')
        if role in ('cache', 'spare') and vtype:
            raise ValueError(f'{role} devices cannot be {vtype}')
        if role:
            args.append(role)
        if vtype:
            args.append(vtype)
        args.extend(disks)
    return args


@app.route('/api/zfs/pools', methods=['POST'])
def zfs_pool_create():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name or not RE_POOL.match(name):
        return err('Invalid pool name')
    groups, e = _normalize_vdev_spec(data)
    if e:
        return err(e)
    if not any(g['disks'] for g in groups):
        return err('No disks specified')
    # Validate + resolve every disk to its stable /dev/disk/by-id path so the pool
    # won't go DEGRADED if kernel device names get reordered across a reboot.
    by_id_map = _disk_by_id_map()
    for g in groups:
        resolved = []
        for d in g['disks']:
            if not RE_DISK.match(d):
                return err(f'Invalid disk: {d}')
            if not _zfs_disk_usable(d):
                return err(f'Disk {d} is in use (mounted/boot or a pool/RAID/LVM member) — refusing', 409)
            resolved.append(_resolve_stable_dev(d, by_id_map)[0])
        g['disks'] = resolved
    try:
        vargs = _pool_vdev_args(groups)
    except ValueError as ve:
        return err(str(ve))
    return jsonify(run_safe(['zpool', 'create', '-f', name] + vargs))

@app.route('/api/zfs/pools/<name>', methods=['DELETE'])
def zfs_pool_destroy(name):
    if not RE_POOL.match(name):
        return err('Invalid pool name')
    return jsonify(run_safe(['zpool', 'destroy', '-f', name]))


def _parse_importable(text):
    """Parse `zpool import` (scan) output into a list of importable pools."""
    pools, cur = [], None
    for raw in (text or '').split('\n'):
        line = raw.strip()
        if line.startswith('pool:'):
            if cur:
                pools.append(cur)
            cur = {'name': line.split(':', 1)[1].strip(), 'id': '', 'state': '', 'action': ''}
        elif cur is None:
            continue
        elif line.startswith('id:'):
            cur['id'] = line.split(':', 1)[1].strip()
        elif line.startswith('state:'):
            cur['state'] = line.split(':', 1)[1].strip()
        elif line.startswith('status:'):
            cur['action'] = line.split(':', 1)[1].strip()
    if cur:
        pools.append(cur)
    return pools


@app.route('/api/zfs/pools/importable')
def zfs_pools_importable():
    """Pools present on attached devices but not currently imported."""
    out, _, _ = run(['zpool', 'import'])
    return jsonify(_parse_importable(out))


@app.route('/api/zfs/pools/import', methods=['POST'])
def zfs_pool_import():
    data = request.get_json() or {}
    ident = (data.get('name') or data.get('id') or '').strip()  # pool name or numeric id
    new_name = (data.get('new_name') or '').strip()
    altroot = (data.get('altroot') or '').strip()
    # Accept either a pool name or an all-digit pool id.
    if not (RE_POOL.match(ident) or RE_NUM.match(ident)):
        return err('Invalid pool name or id')
    if new_name and not RE_POOL.match(new_name):
        return err('Invalid new pool name')
    if altroot and not RE_PATH.match(altroot):
        return err('Invalid altroot path')
    cmd = ['zpool', 'import']
    if data.get('force'):
        cmd.append('-f')
    if altroot:
        cmd += ['-R', altroot]
    cmd.append(ident)
    if new_name:
        cmd.append(new_name)
    return jsonify(run_safe(cmd))


@app.route('/api/zfs/pools/<name>/export', methods=['POST'])
def zfs_pool_export(name):
    if not RE_POOL.match(name):
        return err('Invalid pool name')
    # Never export a pool that backs the running system (a dataset mounted at /
    # or another critical path) — that would wedge the host.
    out, _, _ = run(['zfs', 'list', '-r', '-H', '-o', 'mountpoint', name])
    mounts = {m.strip() for m in out.split('\n') if m.strip()}
    if mounts & {'/', '/boot', '/usr', '/var'}:
        return err('Refusing to export: this pool backs the running system', 409)
    cmd = ['zpool', 'export']
    if (request.get_json(silent=True) or {}).get('force'):
        cmd.append('-f')
    cmd.append(name)
    return jsonify(run_safe(cmd))


@app.route('/api/zfs/pools/<name>/stabilize', methods=['POST'])
def zfs_pool_stabilize(name):
    """Rewrite a pool's member paths to stable /dev/disk/by-id links by exporting
    and re-importing with `-d /dev/disk/by-id`. Fixes pools that go DEGRADED when
    kernel device names (nvme0n1, sda) get reordered across reboots. The pool is
    briefly offline during the export/import."""
    if not RE_POOL.match(name):
        return err('Invalid pool name')
    # Same guard as export: never take the pool backing the running system offline.
    out, _, _ = run(['zfs', 'list', '-r', '-H', '-o', 'mountpoint', name])
    mounts = {m.strip() for m in out.split('\n') if m.strip()}
    if mounts & {'/', '/boot', '/usr', '/var'}:
        return err('Refusing to stabilize: this pool backs the running system', 409)
    steps = []
    exp = run_safe(['zpool', 'export', name])
    steps.append({'step': 'export', **exp})
    if not exp['success']:
        # Export failed (pool busy) — abort before touching anything else.
        return jsonify({'steps': steps, 'success': False,
                        'error': 'Export failed (pool in use?); pool left imported.'})
    imp = run_safe(['zpool', 'import', '-d', BY_ID_DIR, name])
    steps.append({'step': 'import (by-id)', **imp})
    if not imp['success']:
        # Recover: re-import normally so we don't leave the pool exported.
        steps.append({'step': 'recover import', **run_safe(['zpool', 'import', name])})
        return jsonify({'steps': steps, 'success': False,
                        'error': 'Re-import by-id failed; pool re-imported with previous paths.'})
    return jsonify({'steps': steps, 'success': True})

@app.route('/api/zfs/pools/<name>/datasets')
def zfs_datasets(name):
    if not RE_POOL.match(name):
        return err('Invalid pool name')
    out, _, _ = run(['zfs', 'list', '-r', '-H', '-o',
                     'name,used,available,referenced,mountpoint,compression,quota,reservation,type,encryption,keystatus', name])
    datasets = []
    for line in out.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split('\t')
        if len(parts) >= 4:
            datasets.append({
                'name': parts[0], 'used': parts[1], 'available': parts[2],
                'referenced': parts[3], 'mountpoint': parts[4],
                'compression': parts[5] if len(parts) > 5 else '-',
                'quota': parts[6] if len(parts) > 6 else '-',
                'reservation': parts[7] if len(parts) > 7 else '-',
                'type': parts[8] if len(parts) > 8 else 'filesystem',
                'encryption': parts[9] if len(parts) > 9 else 'off',
                'keystatus': parts[10] if len(parts) > 10 else '-',
            })
    return jsonify(datasets)

# Native ZFS encryption is set only at dataset creation. Algorithms + key formats
# are allowlisted; the passphrase is fed on stdin (keylocation=prompt) so it never
# reaches the process command line or the audit log.
ZFS_ENC_ALGOS = {'on', 'aes-256-gcm', 'aes-192-gcm', 'aes-128-gcm',
                 'aes-256-ccm', 'aes-192-ccm', 'aes-128-ccm'}
ZFS_KEYFORMATS = {'passphrase', 'hex', 'raw'}


@app.route('/api/zfs/datasets', methods=['POST'])
def zfs_dataset_create():
    data = request.get_json()
    name = data.get('name', '').strip()
    properties = data.get('properties', {})
    volsize = (data.get('volsize') or '').strip()
    if not name or not RE_DATASET.match(name):
        return err('Invalid dataset name')
    cmd = ['zfs', 'create']
    if volsize:
        # A ZVOL (block volume) - usable as an iSCSI block backstore.
        if not RE_SIZE.match(volsize):
            return err('Invalid volume size')
        cmd += ['-V', volsize]
    # Optional native encryption (creation-time only).
    input_data = None
    enc = (data.get('encryption') or '').strip()
    if enc:
        if enc not in ZFS_ENC_ALGOS:
            return err('Invalid encryption algorithm')
        keyformat = (data.get('keyformat') or 'passphrase').strip()
        if keyformat != 'passphrase':
            return err('Only the passphrase key format is supported from the UI')
        passphrase = data.get('passphrase') or ''
        if len(passphrase) < 8:
            return err('Encryption passphrase must be at least 8 characters')
        cmd += ['-o', f'encryption={enc}', '-o', 'keyformat=passphrase',
                '-o', 'keylocation=prompt']
        # `zfs create` reads the passphrase from stdin and asks to confirm it.
        input_data = passphrase + '\n' + passphrase + '\n'
    for k, v in properties.items():
        if v:
            if not RE_PROP.match(k):
                return err(f'Invalid property name: {k}')
            cmd.extend(['-o', f'{k}={v}'])
    cmd.append(name)
    return jsonify(run_safe(cmd, input_data=input_data))

@app.route('/api/zfs/datasets/all')
def zfs_datasets_all():
    """Every snapshot target: pool roots, datasets, and volumes (for pickers)."""
    out, _, _ = run(['zfs', 'list', '-H', '-o', 'name,type', '-t', 'filesystem,volume'])
    items = []
    for line in out.strip().split('\n'):
        if '\t' in line:
            name, dtype = line.split('\t')[:2]
            items.append({'name': name, 'type': dtype, 'is_pool': '/' not in name})
    return jsonify(items)

@app.route('/api/zfs/zvols')
def zfs_zvols():
    """List ZFS volumes (ZVOLs) usable as iSCSI block backstores."""
    out, _, _ = run(['zfs', 'list', '-H', '-t', 'volume', '-o', 'name,volsize'])
    vols = []
    for line in out.strip().split('\n'):
        if '\t' in line:
            name, volsize = line.split('\t')[:2]
            vols.append({'name': name, 'volsize': volsize, 'path': f'/dev/zvol/{name}'})
    return jsonify(vols)

@app.route('/api/zfs/datasets/rename', methods=['POST'])
def zfs_dataset_rename():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    new_name = (data.get('new_name') or '').strip()
    if not RE_DATASET.match(name) or not RE_DATASET.match(new_name):
        return err('Invalid dataset name')
    return jsonify(run_safe(['zfs', 'rename', name, new_name]))

@app.route('/api/zfs/datasets/<path:name>', methods=['DELETE'])
def zfs_dataset_destroy(name):
    if not RE_DATASET.match(name):
        return err('Invalid dataset name')
    return jsonify(run_safe(['zfs', 'destroy', '-r', name]))


# ─── Encryption key management (passphrase always via stdin, never argv) ──
@app.route('/api/zfs/datasets/<path:name>/key/load', methods=['POST'])
def zfs_key_load(name):
    if not RE_DATASET.match(name):
        return err('Invalid dataset name')
    passphrase = (request.get_json() or {}).get('passphrase') or ''
    if not passphrase:
        return err('Passphrase required')
    return jsonify(run_safe(['zfs', 'load-key', name], input_data=passphrase + '\n'))


@app.route('/api/zfs/datasets/<path:name>/key/unload', methods=['POST'])
def zfs_key_unload(name):
    if not RE_DATASET.match(name):
        return err('Invalid dataset name')
    return jsonify(run_safe(['zfs', 'unload-key', name]))


@app.route('/api/zfs/datasets/<path:name>/key/change', methods=['POST'])
def zfs_key_change(name):
    if not RE_DATASET.match(name):
        return err('Invalid dataset name')
    passphrase = (request.get_json() or {}).get('passphrase') or ''
    if len(passphrase) < 8:
        return err('New passphrase must be at least 8 characters')
    return jsonify(run_safe(['zfs', 'change-key', name],
                            input_data=passphrase + '\n' + passphrase + '\n'))

@app.route('/api/zfs/snapshots')
def zfs_snapshots():
    pool = request.args.get('pool', '')
    # `written` = space unique to this snapshot since the previous one; `used` =
    # space freed if ONLY this snapshot is destroyed (not additive across snaps).
    cols = 'name,used,written,referenced,creation'
    cmd = ['zfs', 'list', '-H', '-t', 'snapshot', '-o', cols]
    if pool:
        if not RE_POOL.match(pool):
            return err('Invalid pool name')
        cmd = ['zfs', 'list', '-H', '-r', '-t', 'snapshot', '-o', cols, pool]
    out, _, _ = run(cmd)
    snapshots = []
    for line in out.strip().split('\n'):
        if not line.strip() or '\t' not in line:
            continue
        parts = line.split('\t')
        if len(parts) >= 5:
            snapshots.append({
                'name': parts[0], 'used': parts[1], 'written': parts[2],
                'referenced': parts[3], 'creation': parts[4],
            })
    return jsonify(snapshots)

@app.route('/api/zfs/snapshots', methods=['POST'])
def zfs_snapshot_create():
    data = request.get_json()
    dataset = data.get('dataset', '').strip()
    snap_name = data.get('snap_name', '').strip()
    if not dataset or not RE_DATASET.match(dataset):
        return err('Invalid dataset')
    if not snap_name:
        snap_name = f'snap-{int(time.time())}'
    full_name = f'{dataset}@{snap_name}'
    if not RE_SNAP.match(full_name):
        return err('Invalid snapshot name')
    cmd = ['zfs', 'snapshot']
    if data.get('recursive'):
        cmd.append('-r')
    cmd.append(full_name)
    return jsonify(run_safe(cmd))

@app.route('/api/zfs/snapshots/clone', methods=['POST'])
def zfs_snapshot_clone():
    data = request.get_json() or {}
    snapshot = (data.get('snapshot') or '').strip()
    target = (data.get('target') or '').strip()
    if not RE_SNAP.match(snapshot):
        return err('Invalid snapshot')
    if not RE_DATASET.match(target):
        return err('Invalid target dataset name')
    return jsonify(run_safe(['zfs', 'clone', snapshot, target]))

@app.route('/api/zfs/snapshots/rollback', methods=['POST'])
def zfs_snapshot_rollback():
    data = request.get_json()
    snap = data.get('snapshot', '').strip()
    if not snap or not RE_SNAP.match(snap):
        return err('Invalid snapshot')
    return jsonify(run_safe(['zfs', 'rollback', '-r', snap]))

@app.route('/api/zfs/snapshots/<path:name>', methods=['DELETE'])
def zfs_snapshot_destroy(name):
    if not RE_SNAP.match(name):
        return err('Invalid snapshot')
    return jsonify(run_safe(['zfs', 'destroy', '-r', name]))


# zfs diff change-type codes -> human labels.
_DIFF_KIND = {'+': 'added', '-': 'removed', 'M': 'modified', 'R': 'renamed'}


@app.route('/api/zfs/snapshots/diff')
def zfs_snapshot_diff():
    """Differences between a snapshot and a later snapshot (or the live dataset).
    `to` may be another snapshot of the same dataset, or the dataset itself."""
    frm = (request.args.get('from') or '').strip()
    to = (request.args.get('to') or '').strip()
    if not RE_SNAP.match(frm):
        return err('Invalid "from" snapshot')
    if to and not (RE_SNAP.match(to) or RE_DATASET.match(to)):
        return err('Invalid "to" snapshot/dataset')
    cmd = ['zfs', 'diff', '-H', '-F', frm]
    if to:
        cmd.append(to)
    out, errtxt, rc = run(cmd)
    if rc != 0:
        return jsonify({'success': False, 'error': (errtxt or 'zfs diff failed').strip()[:200]}), 400
    changes = []
    for line in out.split('\n'):
        if not line.strip():
            continue
        parts = line.split('\t')
        if len(parts) < 3:
            continue
        change, ftype, path = parts[0], parts[1], parts[2]
        entry = {'change': _DIFF_KIND.get(change, change), 'ftype': ftype, 'path': path}
        if change == 'R' and len(parts) >= 4:
            entry['path_to'] = parts[3]
        changes.append(entry)
    return jsonify({'success': True, 'changes': changes, 'count': len(changes)})


# Root-owned helper that resolves & confines snapshot/live paths and does the
# actual read/copy as root (snapshot dirs and live datasets aren't readable by
# the unprivileged dashboard user). It enforces its own confinement, so it is
# the security boundary — see install.sh. Not writable by `dashboard`.
SNAP_FS_HELPER = '/usr/local/sbin/storage-dashboard-snap-fs'


def _split_snap(snap):
    """Validate a dataset@snapshot string and return (dataset, snapname)."""
    if not RE_SNAP.match(snap) or '@' not in snap:
        return None, None
    dataset, snapname = snap.split('@', 1)
    return dataset, snapname


def _valid_relpath(p):
    # Relative, no NUL/newline, no traversal segments. (The helper re-confines
    # via realpath regardless; this is a cheap first gate.)
    if p in ('', '.'):
        return True
    if p.startswith('/') or '\x00' in p or '\n' in p or '\r' in p:
        return False
    return '..' not in p.split('/')


@app.route('/api/zfs/snapshots/<path:snap>/browse')
def zfs_snapshot_browse(snap):
    dataset, snapname = _split_snap(snap)
    if not dataset:
        return err('Invalid snapshot')
    relpath = request.args.get('path', '')
    if not _valid_relpath(relpath):
        return err('Invalid path')
    out, errtxt, rc = run([SNAP_FS_HELPER, 'browse', dataset, snapname, relpath])
    if rc != 0:
        return err((errtxt or 'browse failed').strip()[:200], 400)
    try:
        return jsonify(json.loads(out))
    except json.JSONDecodeError:
        return err('Could not read snapshot directory', 500)


@app.route('/api/zfs/snapshots/<path:snap>/restore', methods=['POST'])
def zfs_snapshot_restore(snap):
    dataset, snapname = _split_snap(snap)
    if not dataset:
        return err('Invalid snapshot')
    data = request.get_json() or {}
    relpath = (data.get('path') or '').strip()
    mode = data.get('mode', 'copy')  # 'copy' (beside original, never clobbers) | 'inplace'
    if not relpath or not _valid_relpath(relpath):
        return err('Invalid path')
    if mode not in ('copy', 'inplace'):
        return err('Invalid restore mode')
    out, errtxt, rc = run([SNAP_FS_HELPER, 'restore', dataset, snapname, relpath, mode])
    if rc != 0:
        return err((errtxt or 'restore failed').strip()[:200], 400)
    try:
        return jsonify(json.loads(out))
    except json.JSONDecodeError:
        return jsonify({'success': True})

@app.route('/api/zfs/pools/<name>/properties')
def zfs_pool_properties(name):
    if not RE_POOL.match(name):
        return err('Invalid pool name')
    out, _, _ = run(['zpool', 'get', 'all', name])
    props = {}
    for line in out.strip().split('\n')[1:]:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 3:
            props[parts[1]] = parts[2]
    return jsonify(props)

@app.route('/api/zfs/datasets/<path:name>/properties')
def zfs_dataset_properties(name):
    if not RE_DATASET.match(name):
        return err('Invalid dataset name')
    out, _, _ = run(['zfs', 'get', 'all', name])
    props = {}
    for line in out.strip().split('\n')[1:]:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 3:
            props[parts[1]] = parts[2]
    return jsonify(props)

@app.route('/api/zfs/datasets/<path:name>/properties', methods=['PUT'])
def zfs_dataset_set_property(name):
    data = request.get_json()
    prop = data.get('property', '').strip()
    value = data.get('value', '').strip()
    if not RE_DATASET.match(name):
        return err('Invalid dataset name')
    if not prop or not RE_PROP.match(prop):
        return err('Invalid property')
    return jsonify(run_safe(['zfs', 'set', f'{prop}={value}', name]))

# ─── iSCSI Target Management ─────────────────────────────────────────

def targetcli(*cmd_args):
    return run_safe(['targetcli', *cmd_args])


def tmutate(*cmd_args):
    """Run a mutating targetcli command and persist the config on success. LIO
    config is in-memory until `saveconfig`, so without this a `target.service`
    restart loses everything."""
    r = run_safe(['targetcli', *cmd_args])
    if r['success']:
        run(['targetcli', 'saveconfig'])
    return r


def parse_tpg(output):
    """Parse `targetcli /iscsi/<iqn>/tpg1 ls` into luns / acls / portals. Items
    sit exactly one tree level (2 columns) below their section header, which
    excludes nested entries like mapped_lunN."""
    res = {'luns': [], 'acls': [], 'portals': []}
    section = None
    base_col = None
    for line in output.split('\n'):
        idx = line.find('o- ')
        if idx == -1:
            continue
        rest = line[idx + 3:].strip()
        name = rest.split()[0] if rest else ''
        low = name.lower()
        if low in ('luns', 'acls', 'portals'):
            section, base_col = low, idx
            continue
        if not section or base_col is None or idx != base_col + 2:
            continue
        if section == 'luns':
            bs = rest[rest.find('[') + 1:rest.find(']')] if '[' in rest and ']' in rest else ''
            res['luns'].append({'lun': name, 'backstore': bs})
        elif section == 'acls':
            res['acls'].append({'initiator': name})
        elif section == 'portals':
            if name.startswith('['):  # IPv6 e.g. [::0]:3260
                ip, port = name[1:name.rfind(']')], name[name.rfind(':') + 1:]
            else:
                ip, port = name.rsplit(':', 1) if ':' in name else (name, '')
            res['portals'].append({'ip': ip, 'port': port, 'portal': name})
    return res


def parse_targets(output):
    """Extract target IQNs from `targetcli /iscsi ls`. Target rows are the only
    ones tagged with [TPGs:], which avoids picking up ACL initiator IQNs."""
    targets = []
    for line in output.split('\n'):
        if '[TPGs:' not in line:
            continue
        idx = line.find('o- ')
        if idx == -1:
            continue
        rest = line[idx + 3:].strip().split()
        if rest and rest[0].startswith('iqn'):
            targets.append(rest[0])
    return targets


def parse_backstores(output):
    """Extract backstore objects from `targetcli /backstores ls` with size and
    in-use status. Each object sits exactly one tree level (2 columns) below its
    type header, which distinguishes it from nested alua entries. The bracket
    looks like: [/path (64.0MiB) write-back activated]."""
    backstores = []
    types = {'block', 'fileio', 'pscsi', 'ramdisk'}
    base_col = None
    cur_type = None
    for line in output.split('\n'):
        idx = line.find('o- ')
        if idx == -1:
            continue
        rest = line[idx + 3:].strip()
        name = rest.split()[0] if rest else ''
        if name in types:
            cur_type, base_col = name, idx
        elif cur_type and base_col is not None and idx == base_col + 2:
            bracket = rest[rest.find('[') + 1:rest.rfind(']')] if '[' in rest and ']' in rest else ''
            size = ''
            m = re.search(r'\(([\d.]+\s*[KMGTP]?i?B)\)', bracket)
            if m:
                size = m.group(1)
            backstores.append({
                'type': cur_type, 'name': name, 'size': size,
                'in_use': 'activated' in bracket and 'deactivated' not in bracket,
            })
    return backstores

@app.route('/api/iscsi/status')
def iscsi_status():
    out, _, rc = run(['targetcli', '/iscsi', 'ls'])
    if rc != 0:
        out = 'NO CONFIG'
    out2, _, rc2 = run(['targetcli', '/backstores', 'ls'])
    if rc2 != 0:
        out2 = 'NO CONFIG'
    return jsonify({'targets': out, 'backstores': out2})

@app.route('/api/iscsi/targets')
def iscsi_targets():
    out, _, rc = run(['targetcli', '/iscsi', 'ls'])
    if rc != 0:
        return jsonify({'targets': [], 'raw': ''})
    return jsonify({'targets': parse_targets(out), 'raw': out})

def _set_shared_mode(iqn):
    # Any initiator may connect and read/write the shared LUNs - the usual
    # default for clustered hypervisor storage (Proxmox / VMware).
    return tmutate(f'/iscsi/{iqn}/tpg1', 'set', 'attribute',
                   'generate_node_acls=1', 'demo_mode_write_protect=0', 'cache_dynamic_acls=1')


def _set_restricted_mode(iqn):
    # Only explicitly-added initiator ACLs may connect (optionally with CHAP).
    return tmutate(f'/iscsi/{iqn}/tpg1', 'set', 'attribute', 'generate_node_acls=0')


@app.route('/api/iscsi/targets', methods=['POST'])
def iscsi_target_create():
    data = request.get_json()
    iqn = data.get('iqn', '').strip()
    access_mode = data.get('access_mode', 'shared')
    if not iqn or not RE_IQN.match(iqn):
        return err('Invalid IQN')
    if access_mode not in ('shared', 'restricted'):
        return err('Invalid access mode')
    r = tmutate('/iscsi', 'create', iqn)
    if not r['success']:
        return jsonify(r)
    _set_shared_mode(iqn) if access_mode == 'shared' else _set_restricted_mode(iqn)
    return jsonify(r)

@app.route('/api/iscsi/targets/<path:iqn>', methods=['DELETE'])
def iscsi_target_destroy(iqn):
    if not RE_IQN.match(iqn):
        return err('Invalid IQN')
    return jsonify(tmutate('/iscsi', 'delete', iqn))

@app.route('/api/iscsi/targets/<path:iqn>', methods=['GET'])
def iscsi_target_detail(iqn):
    if not RE_IQN.match(iqn):
        return err('Invalid IQN')
    out, _, rc = run(['targetcli', f'/iscsi/{iqn}/tpg1', 'ls'])
    if rc != 0:
        return err('Target not found', 404)
    detail = parse_tpg(out)
    attr_out, _, _ = run(['targetcli', f'/iscsi/{iqn}/tpg1', 'get', 'attribute',
                          'generate_node_acls', 'demo_mode_write_protect', 'authentication'])
    attrs = dict(t.split('=', 1) for t in attr_out.split() if '=' in t)
    detail['attributes'] = attrs
    detail['shared'] = attrs.get('generate_node_acls') == '1'
    detail['auth'] = attrs.get('authentication') == '1'
    detail['raw'] = out
    return jsonify(detail)

@app.route('/api/iscsi/targets/<path:iqn>/mode', methods=['POST'])
def iscsi_target_mode(iqn):
    if not RE_IQN.match(iqn):
        return err('Invalid IQN')
    mode = (request.get_json() or {}).get('mode', '')
    if mode == 'shared':
        return jsonify(_set_shared_mode(iqn))
    if mode == 'restricted':
        return jsonify(_set_restricted_mode(iqn))
    return err('Invalid access mode')

@app.route('/api/iscsi/backstores')
def iscsi_backstores():
    out, _, _ = run(['targetcli', '/backstores', 'ls'])
    return jsonify({'backstores': parse_backstores(out), 'raw': out})

@app.route('/api/iscsi/backstores', methods=['POST'])
def iscsi_backstore_create():
    data = request.get_json()
    btype = data.get('type', 'fileio')
    name = data.get('name', '').strip()
    path = data.get('path', '').strip()
    size = str(data.get('size', '')).strip()
    if not name or not RE_BSNAME.match(name):
        return err('Invalid backstore name')
    if btype not in ('fileio', 'block'):
        return err(f'Unknown backstore type: {btype}')
    if not path or not RE_PATH.match(path):
        return err('Invalid path')
    if btype == 'fileio':
        cmd = ['/backstores/fileio', 'create', name, path]
        if size:
            if not RE_SIZE.match(size):
                return err('Invalid size')
            cmd.append(size)
    else:  # block
        cmd = ['/backstores/block', 'create', name, path]
    return jsonify(tmutate(*cmd))

@app.route('/api/iscsi/backstores/<btype>/<name>', methods=['DELETE'])
def iscsi_backstore_delete(btype, name):
    if btype not in ('fileio', 'block'):
        return err('Unknown backstore type')
    if not RE_BSNAME.match(name):
        return err('Invalid backstore name')
    return jsonify(tmutate(f'/backstores/{btype}', 'delete', name))

@app.route('/api/iscsi/luns', methods=['POST'])
def iscsi_lun_create():
    data = request.get_json()
    iqn = data.get('iqn', '').strip()
    backstore_type = data.get('backstore_type', 'fileio')
    backstore_name = data.get('backstore_name', '').strip()
    lun_id = str(data.get('lun_id', '')).strip()
    if not iqn or not RE_IQN.match(iqn):
        return err('Invalid IQN')
    if backstore_type not in ('fileio', 'block'):
        return err('Unknown backstore type')
    if not backstore_name or not RE_BSNAME.match(backstore_name):
        return err('Invalid backstore name')
    cmd = [f'/iscsi/{iqn}/tpg1/luns', 'create', f'/backstores/{backstore_type}/{backstore_name}']
    if lun_id:
        if not RE_NUM.match(lun_id):
            return err('Invalid LUN id')
        cmd.append(lun_id)
    return jsonify(tmutate(*cmd))

@app.route('/api/iscsi/luns/delete', methods=['POST'])
def iscsi_lun_delete():
    data = request.get_json() or {}
    iqn = data.get('iqn', '').strip()
    lun = data.get('lun', '').strip()
    if not RE_IQN.match(iqn):
        return err('Invalid target IQN')
    if not re.match(r'^lun[0-9]+$', lun):
        return err('Invalid LUN')
    return jsonify(tmutate(f'/iscsi/{iqn}/tpg1/luns', 'delete', lun))

@app.route('/api/iscsi/acls', methods=['POST'])
def iscsi_acl_create():
    data = request.get_json()
    iqn = data.get('iqn', '').strip()
    initiator_iqn = data.get('initiator_iqn', '').strip()
    if not iqn or not RE_IQN.match(iqn):
        return err('Invalid target IQN')
    if not initiator_iqn or not RE_IQN.match(initiator_iqn):
        return err('Invalid initiator IQN')
    return jsonify(tmutate(f'/iscsi/{iqn}/tpg1/acls', 'create', initiator_iqn))

@app.route('/api/iscsi/acls/delete', methods=['POST'])
def iscsi_acl_delete():
    data = request.get_json() or {}
    iqn = data.get('iqn', '').strip()
    initiator_iqn = data.get('initiator_iqn', '').strip()
    if not RE_IQN.match(iqn) or not RE_IQN.match(initiator_iqn):
        return err('Invalid IQN')
    return jsonify(tmutate(f'/iscsi/{iqn}/tpg1/acls', 'delete', initiator_iqn))

@app.route('/api/iscsi/acls/chap', methods=['POST'])
def iscsi_acl_chap():
    data = request.get_json() or {}
    iqn = data.get('iqn', '').strip()
    initiator_iqn = data.get('initiator_iqn', '').strip()
    if not RE_IQN.match(iqn) or not RE_IQN.match(initiator_iqn):
        return err('Invalid IQN')
    acl = f'/iscsi/{iqn}/tpg1/acls/{initiator_iqn}'
    if data.get('clear'):
        tmutate(acl, 'set', 'auth', 'userid=', 'password=')
        return jsonify({'success': True})
    userid = (data.get('userid') or '').strip()
    password = (data.get('password') or '').strip()
    if not RE_CHAP.match(userid) or not RE_CHAP.match(password):
        return err('Invalid CHAP userid/password (use letters, digits, . _ : + -)')
    tmutate(f'/iscsi/{iqn}/tpg1', 'set', 'attribute', 'authentication=1')
    return jsonify(tmutate(acl, 'set', 'auth', f'userid={userid}', f'password={password}'))

@app.route('/api/iscsi/portals', methods=['POST'])
def iscsi_portal_create():
    data = request.get_json()
    iqn = data.get('iqn', '').strip()
    ip = str(data.get('ip', '0.0.0.0')).strip()
    port = str(data.get('port', '3260')).strip()
    if not iqn or not RE_IQN.match(iqn):
        return err('Invalid IQN')
    if not RE_IP.match(ip):
        return err('Invalid IP address')
    if not RE_NUM.match(port):
        return err('Invalid port')
    return jsonify(tmutate(f'/iscsi/{iqn}/tpg1/portals', 'create', ip, port))

@app.route('/api/iscsi/portals/delete', methods=['POST'])
def iscsi_portal_delete():
    data = request.get_json() or {}
    iqn = data.get('iqn', '').strip()
    ip = str(data.get('ip', '')).strip()
    port = str(data.get('port', '')).strip()
    if not RE_IQN.match(iqn):
        return err('Invalid IQN')
    if not RE_IP.match(ip) or not RE_NUM.match(port):
        return err('Invalid portal')
    return jsonify(tmutate(f'/iscsi/{iqn}/tpg1/portals', 'delete', ip, port))

@app.route('/api/iscsi/sessions')
def iscsi_sessions():
    # targetcli's `sessions` doesn't report demo-mode dynamic sessions, so read
    # connected initiators from configfs via a root-owned helper.
    out, _, _ = run(['/usr/local/sbin/storage-dashboard-iscsi-sessions'])
    sessions = []
    for line in out.strip().split('\n'):
        parts = line.split('\t')
        if len(parts) >= 2:
            sessions.append({'target': parts[0], 'initiator': parts[1],
                             'type': parts[2] if len(parts) > 2 else ''})
    return jsonify({'sessions': sessions})

@app.route('/api/iscsi/saveconfig', methods=['POST'])
def iscsi_saveconfig():
    return jsonify(targetcli('saveconfig'))

# ─── NFS Export Management ───────────────────────────────────────────

EXPORTS_FILE = '/etc/exports'

def parse_exports(filepath=EXPORTS_FILE):
    exports = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if re.match(r'^\s*/\S', line):
                    parts = line.split()
                    path = parts[0]
                    clients = []
                    for p in parts[1:]:
                        client_parts = p.split('(')
                        if len(client_parts) == 2:
                            clients.append({
                                'host': client_parts[0],
                                'options': client_parts[1].rstrip(')')
                            })
                    exports.append({'path': path, 'clients': clients, 'raw': line})
    except FileNotFoundError:
        pass
    return exports

@app.route('/api/nfs/exports')
def nfs_exports():
    exports = parse_exports()
    return jsonify(exports)

@app.route('/api/nfs/exports', methods=['POST'])
def nfs_export_create():
    data = request.get_json()
    path = data.get('path', '').strip()
    clients = data.get('clients', [])
    if not path or not RE_PATH.match(path):
        return err('Invalid export path')

    client_entries = []
    for c in clients:
        host = (c.get('host') or '*').strip()
        opts = (c.get('options') or 'rw,sync,no_subtree_check,no_root_squash').strip()
        if not RE_HOST.match(host):
            return err(f'Invalid client/host: {host}')
        if not RE_NFSOPTS.match(opts):
            return err(f'Invalid export options: {opts}')
        client_entries.append(f'{host}({opts})')
    if not client_entries:
        client_entries.append('*(rw,sync,no_subtree_check,no_root_squash)')

    lines = []
    try:
        with open(EXPORTS_FILE) as f:
            lines = f.readlines()
    except FileNotFoundError:
        pass

    export_line = f'{path}\t{" ".join(client_entries)}\n'
    # Match an existing export of the exact same path (first whitespace token).
    replaced = False
    for i, l in enumerate(lines):
        toks = l.split()
        if toks and not l.lstrip().startswith('#') and toks[0] == path:
            lines[i] = export_line
            replaced = True
    if not replaced:
        if lines and not lines[-1].endswith('\n'):
            lines[-1] += '\n'
        lines.append(export_line)

    r1 = run_safe(['tee', EXPORTS_FILE], input_data=''.join(lines))
    if not r1['success']:
        return jsonify(r1)
    run_safe(['mkdir', '-p', '--', path])
    return jsonify(run_safe(['exportfs', '-ra']))

@app.route('/api/nfs/exports/<path:export_path>', methods=['DELETE'])
def nfs_export_delete(export_path):
    if not RE_PATH.match('/' + export_path.lstrip('/')):
        return err('Invalid export path')
    norm = '/' + export_path.lstrip('/')
    try:
        with open(EXPORTS_FILE) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return err('No exports file')
    new_lines = []
    for l in lines:
        toks = l.split()
        # Drop only the export line whose path token matches exactly.
        if toks and not l.lstrip().startswith('#') and toks[0] == norm:
            continue
        new_lines.append(l)
    r = run_safe(['tee', EXPORTS_FILE], input_data=''.join(new_lines))
    if not r['success']:
        return jsonify(r)
    # Best-effort: drop the export directory if it is now empty. rmdir can only
    # remove empty directories, so this never deletes a user's data.
    run_safe(['rmdir', norm])
    return jsonify(run_safe(['exportfs', '-ra']))

@app.route('/api/nfs/exportfs')
def nfs_exportfs_status():
    out, _, _ = run(['exportfs', '-v'])
    return jsonify({'exports': out})

@app.route('/api/nfs/clients')
def nfs_clients():
    # showmount queries rpc.mountd over RPC; it doesn't need root.
    out, _, _ = run(['showmount', '-a', '--no-headers'], no_sudo=True)
    return jsonify({'clients': out.strip()})

# ─── SMB Share Management ────────────────────────────────────────────

SMBCONF_FILE = '/etc/samba/smb.conf'

DEFAULT_GLOBAL = {'workgroup': 'WORKGROUP', 'server string': '%h server (Samba)',
                  'security': 'user', 'map to guest': 'bad user', 'dns proxy': 'no'}


def smbconf_parse():
    """Round-trip parse: {section: {key: value}} preserving order (lowercased
    keys). Comments/blank lines are dropped on rewrite."""
    sections = {}
    cur = None
    try:
        with open(SMBCONF_FILE) as f:
            for line in f:
                s = line.strip()
                if not s or s[0] in '#;':
                    continue
                if s.startswith('[') and s.endswith(']'):
                    cur = s[1:-1]
                    sections.setdefault(cur, {})
                elif cur is not None and '=' in s:
                    k, v = s.split('=', 1)
                    sections[cur][k.strip().lower()] = v.strip()
    except FileNotFoundError:
        pass
    if 'global' not in sections:
        sections = {'global': dict(DEFAULT_GLOBAL), **sections}
    return sections


def smbconf_render(sections):
    out = []
    for sec, kv in sections.items():
        out.append(f'[{sec}]')
        for k, v in kv.items():
            out.append(f'   {k} = {v}')
        out.append('')
    return '\n'.join(out) + '\n'


def smbconf_apply(sections):
    """Validate with testparm, then write + reload Samba. Never applies a config
    testparm rejects."""
    content = smbconf_render(sections)
    tmp = os.path.join(APP_DIR, '.smb.conf.check')
    try:
        with open(tmp, 'w') as f:
            f.write(content)
        _, e, rc = run(['testparm', '-s', tmp], no_sudo=True)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    if rc != 0:
        return {'success': False, 'error': 'Rejected by testparm: ' + e.strip()[-300:]}
    r = run_safe(['tee', SMBCONF_FILE], input_data=content)
    if not r['success']:
        return r
    return run_safe(['systemctl', 'reload-or-restart', SYSTEM_SERVICES['smb']['service']])


def _yn(v, default='no'):
    if isinstance(v, bool):
        return 'yes' if v else 'no'
    return 'yes' if str(v).lower() in ('yes', 'true', '1', 'on') else ('no' if v not in (None, '') else default)


@app.route('/api/smb/shares')
def smb_shares():
    sections = smbconf_parse()
    shares = []
    for name, kv in sections.items():
        if name.lower() in ('global', 'homes'):
            continue
        objs = kv.get('vfs objects', '')
        shares.append({
            'name': name,
            'path': kv.get('path', ''),
            'comment': kv.get('comment', ''),
            'read_only': kv.get('read only', 'yes'),
            'browseable': kv.get('browseable', 'yes'),
            'guest_ok': kv.get('guest ok', 'no'),
            'available': kv.get('available', 'yes'),
            'valid_users': kv.get('valid users', ''),
            'write_list': kv.get('write list', ''),
            'read_list': kv.get('read list', ''),
            'admin_users': kv.get('admin users', ''),
            'hosts_allow': kv.get('hosts allow', ''),
            'hosts_deny': kv.get('hosts deny', ''),
            'force_user': kv.get('force user', ''),
            'force_group': kv.get('force group', ''),
            'create_mask': kv.get('create mask', ''),
            'directory_mask': kv.get('directory mask', ''),
            'vfs': {'recycle': 'recycle' in objs, 'shadow_copy': 'shadow_copy2' in objs,
                    'time_machine': 'fruit' in objs, 'audit': 'full_audit' in objs},
        })
    return jsonify(shares)


@app.route('/api/smb/shares', methods=['POST'])
def smb_share_save():
    """Create or update a share (upsert by name)."""
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    path = (data.get('path') or '').strip()
    if not RE_SHARE.match(name) or name.lower() in ('global', 'homes'):
        return err('Invalid share name')
    if not RE_PATH.match(path):
        return err('Invalid path')

    def acl(field):
        v = (data.get(field) or '').strip()
        if v and not RE_ACL.match(v):
            raise ValueError(field)
        return v

    try:
        valid_users, write_list, read_list, admin_users = (acl('valid_users'), acl('write_list'),
                                                            acl('read_list'), acl('admin_users'))
        force_user, force_group = acl('force_user'), acl('force_group')
    except ValueError as ex:
        return err(f'Invalid value for {ex}')
    hosts_allow = (data.get('hosts_allow') or '').strip()
    hosts_deny = (data.get('hosts_deny') or '').strip()
    if (hosts_allow and not RE_HOSTS.match(hosts_allow)) or (hosts_deny and not RE_HOSTS.match(hosts_deny)):
        return err('Invalid hosts allow/deny')
    cmask = (data.get('create_mask') or '').strip()
    dmask = (data.get('directory_mask') or '').strip()
    if (cmask and not RE_MASK.match(cmask)) or (dmask and not RE_MASK.match(dmask)):
        return err('Invalid mask')
    comment = (data.get('comment') or '').strip()
    if not RE_COMMENT.match(comment):
        return err('Invalid comment')

    kv = {}
    if comment:
        kv['comment'] = comment
    kv['path'] = path
    kv['browseable'] = _yn(data.get('browseable', 'yes'))
    kv['read only'] = _yn(data.get('read_only', 'no'))
    kv['guest ok'] = _yn(data.get('guest_ok', 'no'))
    if not _yn(data.get('available', 'yes')) == 'yes':
        kv['available'] = 'no'
    for key, val in (('valid users', valid_users), ('write list', write_list), ('read list', read_list),
                     ('admin users', admin_users), ('hosts allow', hosts_allow), ('hosts deny', hosts_deny),
                     ('force user', force_user), ('force group', force_group),
                     ('create mask', cmask), ('directory mask', dmask)):
        if val:
            kv[key] = val

    # VFS modules
    vfs = data.get('vfs') or {}
    objects, extra = [], {}
    if vfs.get('time_machine'):
        objects += ['catia', 'fruit', 'streams_xattr']
        extra.update({'fruit:time machine': 'yes', 'fruit:metadata': 'stream'})
    if vfs.get('recycle'):
        objects.append('recycle')
        extra.update({'recycle:repository': '.recycle/%U', 'recycle:keeptree': 'yes', 'recycle:versions': 'yes'})
    if vfs.get('shadow_copy'):
        objects.append('shadow_copy2')
        extra.update({'shadow:snapdir': '.zfs/snapshot', 'shadow:sort': 'desc', 'shadow:localtime': 'yes',
                      'shadow:snapprefix': r'autosnap_\(hourly\|daily\|weekly\|monthly\)',
                      'shadow:delimiter': '_', 'shadow:format': '%Y-%m-%d_%H%M%S'})
    if vfs.get('audit'):
        objects.append('full_audit')
        extra.update({'full_audit:prefix': '%u|%I|%S', 'full_audit:success': 'mkdir rename unlink rmdir pwrite',
                      'full_audit:failure': 'none', 'full_audit:facility': 'local5', 'full_audit:priority': 'notice'})
    if objects:
        kv['vfs objects'] = ' '.join(objects)
        kv.update(extra)

    run_safe(['mkdir', '-p', '--', path])
    run_safe(['chmod', '2775', '--', path])
    sections = smbconf_parse()
    sections[name] = kv
    return jsonify(smbconf_apply(sections))


@app.route('/api/smb/shares/<name>', methods=['DELETE'])
def smb_share_delete(name):
    if not RE_SHARE.match(name):
        return err('Invalid share name')
    sections = smbconf_parse()
    if name in sections:
        del sections[name]
    return jsonify(smbconf_apply(sections))


@app.route('/api/smb/shares/<name>/toggle', methods=['POST'])
def smb_share_toggle(name):
    if not RE_SHARE.match(name):
        return err('Invalid share name')
    sections = smbconf_parse()
    if name not in sections:
        return err('No such share', 404)
    if sections[name].get('available', 'yes') == 'no':
        sections[name].pop('available', None)  # available
    else:
        sections[name]['available'] = 'no'
    return jsonify(smbconf_apply(sections))

@app.route('/api/smb/status')
def smb_status():
    out, _, _ = run(['smbstatus', '--json'])
    try:
        d = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        d = {}
    sessions = []
    for s in (d.get('sessions') or {}).values():
        enc = s.get('encryption')
        sessions.append({
            'username': s.get('username', ''),
            'machine': s.get('remote_machine') or s.get('hostname', ''),
            'dialect': s.get('session_dialect', ''),
            'encryption': enc.get('cipher', '-') if isinstance(enc, dict) else (enc or '-'),
        })
    tcons = [{'share': t.get('service', ''), 'machine': t.get('machine', '')}
             for t in (d.get('tcons') or {}).values()]
    return jsonify({'sessions': sessions, 'tcons': tcons, 'open_files': len(d.get('open_files') or {})})

# ─── SMB global settings ─────────────────────────────────────────────

SMB_GLOBAL_KEYS = ['workgroup', 'server string', 'server min protocol',
                   'map to guest', 'smb encrypt', 'server signing']


@app.route('/api/smb/global')
def smb_global_get():
    g = smbconf_parse().get('global', {})
    return jsonify({k: g.get(k, '') for k in SMB_GLOBAL_KEYS})

@app.route('/api/smb/global', methods=['POST'])
def smb_global_set():
    data = request.get_json() or {}
    workgroup = (data.get('workgroup') or '').strip()
    server_string = (data.get('server string') or '').strip()
    minproto = (data.get('server min protocol') or '').strip()
    mtg = (data.get('map to guest') or '').strip()
    enc = (data.get('smb encrypt') or '').strip()
    sign = (data.get('server signing') or '').strip()
    if workgroup and not re.match(r'^[A-Za-z0-9_-]{1,15}$', workgroup):
        return err('Invalid workgroup')
    if not RE_COMMENT.match(server_string):
        return err('Invalid server string')
    if minproto not in ('', 'NT1', 'SMB2', 'SMB3'):
        return err('Invalid min protocol')
    if mtg not in ('', 'Never', 'Bad User', 'Bad Password'):
        return err('Invalid map to guest')
    if enc not in ('', 'off', 'desired', 'required', 'auto', 'enabled'):
        return err('Invalid smb encrypt')
    if sign not in ('', 'auto', 'mandatory', 'disabled', 'default'):
        return err('Invalid server signing')
    sections = smbconf_parse()
    g = sections.setdefault('global', {})
    for k, v in (('workgroup', workgroup), ('server string', server_string),
                 ('server min protocol', minproto), ('map to guest', mtg),
                 ('smb encrypt', enc), ('server signing', sign)):
        if v:
            g[k] = v
        else:
            g.pop(k, None)  # empty = leave at Samba default (remove the key)
    return jsonify(smbconf_apply(sections))

@app.route('/api/smb/users', methods=['POST'])
def smb_user_create():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    if not username or not RE_USER.match(username):
        return err('Invalid username')
    if not password:
        return err('Password required')
    run(['useradd', '-M', '-s', '/usr/sbin/nologin', username])
    out, e, rc = run(['smbpasswd', '-a', '-s', username], input_data=f'{password}\n{password}\n')
    return jsonify({'success': rc == 0, 'stdout': out, 'stderr': e})

@app.route('/api/smb/users/<username>', methods=['DELETE'])
def smb_user_delete(username):
    if not RE_USER.match(username):
        return err('Invalid username')
    return jsonify(run_safe(['smbpasswd', '-x', username]))

@app.route('/api/smb/users')
def smb_users_list():
    """SMB users with enabled/disabled state (from pdbedit account flags)."""
    out, _, _ = run(['pdbedit', '-Lw'])
    users = []
    for line in out.strip().split('\n'):
        parts = line.split(':')
        if len(parts) >= 5 and parts[0]:
            flags = parts[4].strip('[] ')
            users.append({'username': parts[0], 'enabled': 'D' not in flags})
    return jsonify(users)

@app.route('/api/smb/users/<username>/password', methods=['POST'])
def smb_user_password(username):
    if not RE_USER.match(username):
        return err('Invalid username')
    password = (request.get_json() or {}).get('password') or ''
    if not password:
        return err('Password required')
    out, e, rc = run(['smbpasswd', '-s', username], input_data=f'{password}\n{password}\n')
    return jsonify({'success': rc == 0, 'stdout': out, 'stderr': e})

@app.route('/api/smb/users/<username>/enable', methods=['POST'])
def smb_user_enable(username):
    if not RE_USER.match(username):
        return err('Invalid username')
    return jsonify(run_safe(['smbpasswd', '-e', username]))

@app.route('/api/smb/users/<username>/disable', methods=['POST'])
def smb_user_disable(username):
    if not RE_USER.match(username):
        return err('Invalid username')
    return jsonify(run_safe(['smbpasswd', '-d', username]))

# ─── SMB groups (for group-based share access) ───────────────────────

@app.route('/api/smb/groups')
def smb_groups_list():
    out, _, _ = run(['getent', 'group'], no_sudo=True)
    groups = []
    for line in out.strip().split('\n'):
        parts = line.split(':')
        if len(parts) >= 4 and parts[2].isdigit() and 1000 <= int(parts[2]) < 65534:
            members = [m for m in parts[3].split(',') if m]
            groups.append({'name': parts[0], 'gid': int(parts[2]), 'members': members})
    return jsonify(groups)

@app.route('/api/smb/groups', methods=['POST'])
def smb_group_create():
    name = ((request.get_json() or {}).get('name') or '').strip()
    if not RE_GROUP.match(name):
        return err('Invalid group name')
    return jsonify(run_safe(['groupadd', name]))

@app.route('/api/smb/groups/<name>', methods=['DELETE'])
def smb_group_delete(name):
    if not RE_GROUP.match(name):
        return err('Invalid group name')
    return jsonify(run_safe(['groupdel', name]))

@app.route('/api/smb/groups/<name>/members', methods=['POST'])
def smb_group_member(name):
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    action = data.get('action', 'add')
    if not RE_GROUP.match(name) or not RE_USER.match(username):
        return err('Invalid group or username')
    if action == 'add':
        return jsonify(run_safe(['gpasswd', '-a', username, name]))
    if action == 'remove':
        return jsonify(run_safe(['gpasswd', '-d', username, name]))
    return err('Invalid action')

# ─── SMB home directories ([homes] special share) ────────────────────

HOMES_BLOCK = (
    '\n[homes]\n'
    '   comment = Home Directories\n'
    '   browseable = no\n'
    '   read only = no\n'
    '   valid users = %S\n'
    '   create mask = 0700\n'
    '   directory mask = 0700\n'
)


def _smb_has_homes():
    try:
        with open(SMBCONF_FILE) as f:
            return any(l.strip().lower() == '[homes]' for l in f)
    except FileNotFoundError:
        return False


def _smb_remove_section(content, name):
    """Return smb.conf content with the named [section] removed."""
    out, skip = [], False
    for line in content.split('\n'):
        s = line.strip()
        if s.startswith('[') and s.endswith(']'):
            skip = (s[1:-1].lower() == name.lower())
        if not skip:
            out.append(line)
    return '\n'.join(out)


@app.route('/api/smb/homes')
def smb_homes_get():
    return jsonify({'enabled': _smb_has_homes()})

@app.route('/api/smb/homes', methods=['POST'])
def smb_homes_set():
    enabled = bool((request.get_json() or {}).get('enabled'))
    try:
        with open(SMBCONF_FILE) as f:
            content = f.read()
    except FileNotFoundError:
        content = '[global]\n   workgroup = WORKGROUP\n   security = user\n'
    has = _smb_has_homes()
    if enabled and not has:
        content = content.rstrip('\n') + '\n' + HOMES_BLOCK
    elif not enabled and has:
        content = _smb_remove_section(content, 'homes')
    else:
        return jsonify({'success': True, 'enabled': enabled})
    r = run_safe(['tee', SMBCONF_FILE], input_data=content)
    if r['success']:
        run(['testparm', '-s'])
        r = run_safe(['systemctl', 'restart', SYSTEM_SERVICES['smb']['service']])
    r['enabled'] = enabled
    return jsonify(r)


# ─── Installation Check ───────────────────────────────────────────────

def _pkg_installed(pkg):
    """Whether a system package is installed, using the platform's package
    manager (dpkg on Debian/Ubuntu, rpm on RHEL/Rocky)."""
    if FAMILY == 'rhel':
        return run(['rpm', '-q', pkg], no_sudo=True)[2] == 0
    return 'installed' in run(['dpkg-query', '-W', "-f=${Status}", pkg])[0]


@app.route('/api/install/status')
def install_status():
    results = {}
    for key, svc in SYSTEM_SERVICES.items():
        pkg = svc.get('pkg')
        if pkg:
            results[key] = {'package': pkg, 'installed': _pkg_installed(pkg)}
        else:
            # Not apt-managed (e.g. llama.cpp): presence = unit file or binary.
            installed = _unit_present(svc['service']) or Path(svc.get('binary') or '').exists()
            results[key] = {'package': svc.get('binary') or '—', 'installed': installed}
    return jsonify(results)

# Package installation is intentionally not exposed over the API. Packages are
# provisioned at install time by install-prerequisites.sh; granting the
# network-facing service passwordless apt-get would be a root-escalation path.


# ─── TLS certificate management ───────────────────────────────────────

def _openssl(args, input_data=None):
    # openssl only ever touches the dashboard-owned certs dir, so it never
    # needs root - always run it without sudo.
    return run(['openssl', *args], input_data=input_data, no_sudo=True)


def generate_self_signed(cert_path=TLS_CERT, key_path=TLS_KEY):
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    cn = socket.gethostname() or 'storage-dashboard'
    _, e, rc = _openssl([
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', key_path, '-out', cert_path,
        '-days', '3650', '-subj', f'/CN={cn}',
    ])
    if rc == 0:
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
    return rc == 0, e


def ensure_tls_cert():
    """Ensure a usable cert+key exist. Generate a self-signed pair only when
    BOTH are missing - never overwrite a certificate the operator supplied."""
    have_cert, have_key = os.path.exists(TLS_CERT), os.path.exists(TLS_KEY)
    if have_cert and have_key:
        return
    if have_cert or have_key:
        raise RuntimeError(f'TLS cert/key mismatch: one of {TLS_CERT} / {TLS_KEY} is missing')
    ok, e = generate_self_signed()
    if not ok:
        raise RuntimeError(f'Failed to generate self-signed certificate: {e}')


def cert_info(cert_path=TLS_CERT):
    if not os.path.exists(cert_path):
        return {'present': False}
    out, _, rc = _openssl(['x509', '-in', cert_path, '-noout', '-subject', '-issuer', '-enddate'])
    if rc != 0:
        return {'present': True, 'error': 'unreadable certificate'}
    info = {'present': True, 'path': cert_path}
    for line in out.splitlines():
        if line.startswith('subject='):
            info['subject'] = line[8:].strip()
        elif line.startswith('issuer='):
            info['issuer'] = line[7:].strip()
        elif line.startswith('notAfter='):
            info['expires'] = line[9:].strip()
    info['self_signed'] = 'subject' in info and info.get('subject') == info.get('issuer')
    return info


@app.route('/api/tls/info')
def tls_info():
    info = cert_info()
    info['tls_enabled'] = TLS_ENABLED
    return jsonify(info)


@app.route('/api/tls/regenerate', methods=['POST'])
def tls_regenerate():
    ok, e = generate_self_signed()
    if not ok:
        return err(f'Failed to generate certificate: {e}', 500)
    return jsonify({'success': True, 'restart_required': True})


@app.route('/api/tls/cert', methods=['POST'])
def tls_upload_cert():
    data = request.get_json() or {}
    cert_pem = (data.get('cert') or '').strip()
    key_pem = (data.get('key') or '').strip()
    if 'BEGIN CERTIFICATE' not in cert_pem:
        return err('Certificate must be PEM (-----BEGIN CERTIFICATE-----)')
    if 'PRIVATE KEY' not in key_pem:
        return err('Key must be a PEM private key')
    if len(cert_pem) > 100_000 or len(key_pem) > 100_000:
        return err('Certificate or key too large')

    os.makedirs(os.path.dirname(TLS_CERT), exist_ok=True)
    os.makedirs(os.path.dirname(TLS_KEY), exist_ok=True)
    tmp_cert, tmp_key = TLS_CERT + '.upload', TLS_KEY + '.upload'
    try:
        with open(tmp_cert, 'w') as f:
            f.write(cert_pem + '\n')
        fd = os.open(tmp_key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(key_pem + '\n')

        if _openssl(['x509', '-in', tmp_cert, '-noout'])[2] != 0:
            return err('Invalid certificate')
        if _openssl(['pkey', '-in', tmp_key, '-noout'])[2] != 0:
            return err('Invalid private key')
        cert_pub = _openssl(['x509', '-in', tmp_cert, '-noout', '-pubkey'])[0]
        key_pub = _openssl(['pkey', '-in', tmp_key, '-pubout'])[0]
        if not cert_pub.strip() or cert_pub.strip() != key_pub.strip():
            return err('Certificate and private key do not match')

        os.replace(tmp_cert, TLS_CERT)
        os.replace(tmp_key, TLS_KEY)
        os.chmod(TLS_KEY, 0o600)
    finally:
        for p in (tmp_cert, tmp_key):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass
    return jsonify({'success': True, 'restart_required': True})


# ─── ZFS replication (send/receive over SSH) ──────────────────────────
# Push model: this host streams a dataset's snapshots to a remote ZFS host over
# SSH. The dashboard owns a dedicated SSH keypair (its public half is installed
# on the receiving host's authorized_keys). `zfs send` is piped into
# `ssh host sudo zfs recv` via Popen chaining — never a shell — preserving the
# shell=False guarantee. The first run sends a full replication stream; later
# runs send an incremental from the latest snapshot common to both sides.

REPLICATION_FILE = os.environ.get('DASHBOARD_REPLICATION_FILE', os.path.join(APP_DIR, 'replication.json'))
REPL_KEY = os.environ.get('DASHBOARD_REPL_KEY', os.path.join(APP_DIR, 'replication_key'))
REPL_KNOWN_HOSTS = os.path.join(APP_DIR, 'replication_known_hosts')
REPL_TIMER = 'storage-dashboard-replicate.timer'
RE_HOSTNAME = re.compile(r'^[a-zA-Z0-9_.-]+$')


def load_replication():
    try:
        with open(REPLICATION_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {'jobs': []}


def save_replication(cfg):
    write_json_atomic(REPLICATION_FILE, cfg, 0o600)


def ensure_repl_key():
    """Generate the dedicated replication keypair on first use. Returns the
    public key text (to install on the remote), or '' on failure."""
    if not os.path.exists(REPL_KEY):
        run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-q', '-f', REPL_KEY,
             '-C', 'storage-dashboard-replication'], no_sudo=True)
    try:
        with open(REPL_KEY + '.pub') as f:
            return f.read().strip()
    except FileNotFoundError:
        return ''


def _ssh_base(host, user, port):
    return ['ssh', '-i', REPL_KEY, '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'UserKnownHostsFile=' + REPL_KNOWN_HOSTS,
            '-o', 'ConnectTimeout=10', '-p', str(port),
            '%s@%s' % (user, host)]


def _valid_endpoint(host, user, port):
    if not (RE_HOSTNAME.match(host or '') or RE_IP.match(host or '')):
        return 'Invalid host'
    if not RE_USERNAME.match(user or ''):
        return 'Invalid remote user'
    try:
        p = int(port)
        if not (1 <= p <= 65535):
            return 'Invalid port'
    except (TypeError, ValueError):
        return 'Invalid port'
    return None


def _local_snaps(dataset):
    out, _, _ = run(['zfs', 'list', '-H', '-o', 'name', '-t', 'snapshot',
                     '-s', 'creation', '-d', '1', dataset])
    return [l.split('@', 1)[1] for l in out.split('\n') if '@' in l]


def _remote_snaps(job):
    """Snapshot short-names of the target on the remote, or None if the target
    dataset does not exist there yet (i.e. an initial replication is needed)."""
    cmd = _ssh_base(job['host'], job['user'], job.get('port', 22)) + \
        ['sudo', '-n', 'zfs', 'list', '-H', '-o', 'name', '-t', 'snapshot', '-d', '1', job['target']]
    out, _, rc = run(cmd, no_sudo=True)
    if rc != 0:
        return None
    return [l.split('@', 1)[1] for l in out.split('\n') if '@' in l]


def _pipe_send_recv(send_cmd, recv_cmd):
    """Run `send_cmd | recv_cmd` connecting pipes in Python (no shell). Returns
    (ok, error_text)."""
    try:
        sp = subprocess.Popen(send_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rp = subprocess.Popen(recv_cmd, stdin=sp.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sp.stdout.close()  # let `send` get SIGPIPE if `recv` dies
        _, rerr = rp.communicate()
        sp.wait()
        serr = sp.stderr.read()
        sp.stderr.close()
    except OSError as e:
        return False, str(e)
    if sp.returncode == 0 and rp.returncode == 0:
        return True, ''
    msg = (serr.decode(errors='replace') + ' ' + rerr.decode(errors='replace')).strip()
    return False, msg[:300] or 'replication failed'


def replicate_job(job):
    """Replicate one job's source dataset to its remote target. Returns a result
    dict with ok/message/error and the snapshot transferred."""
    source, target = job['source'], job['target']
    local = _local_snaps(source)
    if not local:
        return {'ok': False, 'error': 'No snapshots on %s — create or schedule one first' % source}
    latest = local[-1]
    remote = _remote_snaps(job)
    send = ['sudo', '-n', 'zfs', 'send']
    if remote is None:
        # Initial replication: full stream up to the latest snapshot.
        if job.get('recursive'):
            send.append('-R')
        send.append('%s@%s' % (source, latest))
        kind = 'full'
    else:
        common = [s for s in local if s in remote]
        if not common:
            return {'ok': False, 'error': 'Target exists but shares no snapshot with the source. '
                    'Destroy the remote target to re-seed, or pick a fresh target.'}
        base = common[-1]
        if base == latest:
            return {'ok': True, 'nochange': True, 'snapshot': latest,
                    'message': 'Already up to date at @%s' % latest}
        if job.get('recursive'):
            send.append('-R')
        send += ['-I', '%s@%s' % (source, base), '%s@%s' % (source, latest)]
        kind = 'incremental'
    recv = _ssh_base(job['host'], job['user'], job.get('port', 22)) + \
        ['sudo', '-n', 'zfs', 'recv', '-F', target]
    ok, errtxt = _pipe_send_recv(send, recv)
    return {'ok': ok, 'snapshot': latest, 'kind': kind, 'error': errtxt}


def sync_replicate_timer():
    """Enable the replication timer iff at least one enabled job exists."""
    active = any(j.get('enabled') for j in load_replication().get('jobs', []))
    action = 'enable' if active else 'disable'
    run(['systemctl', '--now', action, REPL_TIMER])


@app.route('/api/zfs/replication')
def replication_list():
    cfg = load_replication()
    active = (run(['systemctl', 'is-active', REPL_TIMER])[0] or '').strip() == 'active'
    return jsonify({'jobs': cfg.get('jobs', []), 'pubkey': ensure_repl_key(),
                    'timer_active': active})


@app.route('/api/zfs/replication', methods=['POST'])
def replication_save():
    data = request.get_json() or {}
    source = (data.get('source') or '').strip()
    target = (data.get('target') or '').strip()
    host = (data.get('host') or '').strip()
    user = (data.get('user') or '').strip()
    port = data.get('port', 22)
    if not RE_DATASET.match(source):
        return err('Invalid source dataset')
    if not RE_DATASET.match(target):
        return err('Invalid target dataset')
    bad = _valid_endpoint(host, user, port)
    if bad:
        return err(bad)
    job = {
        'id': (data.get('id') or 'repl-%d' % int(time.time() * 1000)),
        'source': source, 'target': target, 'host': host, 'user': user,
        'port': int(port), 'recursive': bool(data.get('recursive')),
        'enabled': bool(data.get('enabled', True)),
    }
    cfg = load_replication()
    prev = next((j for j in cfg['jobs'] if j.get('id') == job['id']), None)
    if prev:  # preserve run history on edit
        for k in ('last_run', 'last_status', 'last_error', 'last_snapshot'):
            if k in prev:
                job[k] = prev[k]
    cfg['jobs'] = [j for j in cfg['jobs'] if j.get('id') != job['id']]
    cfg['jobs'].append(job)
    save_replication(cfg)
    sync_replicate_timer()
    return jsonify({'success': True, 'id': job['id']})


@app.route('/api/zfs/replication/<job_id>', methods=['DELETE'])
def replication_delete(job_id):
    cfg = load_replication()
    cfg['jobs'] = [j for j in cfg['jobs'] if j.get('id') != job_id]
    save_replication(cfg)
    sync_replicate_timer()
    return jsonify({'success': True})


@app.route('/api/zfs/replication/test', methods=['POST'])
def replication_test():
    data = request.get_json() or {}
    host = (data.get('host') or '').strip()
    user = (data.get('user') or '').strip()
    port = data.get('port', 22)
    bad = _valid_endpoint(host, user, port)
    if bad:
        return err(bad)
    ensure_repl_key()
    cmd = _ssh_base(host, user, port) + ['sudo', '-n', 'zfs', 'version']
    out, errtxt, rc = run(cmd, no_sudo=True)
    if rc != 0:
        return jsonify({'success': False,
                        'error': (errtxt or 'SSH/zfs check failed').strip()[:300]})
    return jsonify({'success': True, 'remote_zfs': out.strip().split('\n')[0]})


@app.route('/api/zfs/replication/<job_id>/run', methods=['POST'])
def replication_run(job_id):
    cfg = load_replication()
    job = next((j for j in cfg['jobs'] if j.get('id') == job_id), None)
    if not job:
        return err('No such replication job', 404)
    res = replicate_job(job)
    job['last_run'] = datetime.now().isoformat(timespec='seconds')
    job['last_status'] = 'ok' if res['ok'] else 'error'
    job['last_error'] = '' if res['ok'] else res.get('error', '')
    if res.get('snapshot'):
        job['last_snapshot'] = res['snapshot']
    save_replication(cfg)
    return jsonify({'success': res['ok'], **res})


@app.route('/api/zfs/replication/key/regenerate', methods=['POST'])
def replication_key_regenerate():
    for p in (REPL_KEY, REPL_KEY + '.pub'):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    return jsonify({'success': True, 'pubkey': ensure_repl_key()})


def cli_replicate_tick():
    """Invoked by the systemd timer: run every enabled replication job."""
    cfg = load_replication()
    changed = False
    for job in cfg.get('jobs', []):
        if not job.get('enabled'):
            continue
        res = replicate_job(job)
        job['last_run'] = datetime.now().isoformat(timespec='seconds')
        job['last_status'] = 'ok' if res['ok'] else 'error'
        job['last_error'] = '' if res['ok'] else res.get('error', '')
        if res.get('snapshot'):
            job['last_snapshot'] = res['snapshot']
        changed = True
        print('replicate %s -> %s@%s:%s : %s' % (
            job['source'], job['user'], job['host'], job['target'],
            job['last_status']), flush=True)
    if changed:
        save_replication(cfg)


# ─── Alerting / notifications (email + webhook) ───────────────────────
# A background tick computes the current health alerts (the single source,
# _compute_alerts) and notifies on NEW conditions only (de-duplicated against
# saved state), plus a RESOLVED notice when one clears. Email via smtplib and
# webhook via urllib — both stdlib, no new dependencies or sudo.
NOTIFICATIONS_FILE = os.environ.get('DASHBOARD_NOTIFICATIONS_FILE',
                                    os.path.join(APP_DIR, 'notifications.json'))
ALERTS_TIMER = 'storage-dashboard-alerts.timer'
PW_MASK = '********'
RE_EMAIL = re.compile(r'^[^@\s,]+@[^@\s,]+\.[^@\s,]+$')


def load_notifications():
    try:
        with open(NOTIFICATIONS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {'email': {}, 'webhook': {}, 'state': {}}


def save_notifications(cfg):
    write_json_atomic(NOTIFICATIONS_FILE, cfg, 0o600)


def _notifications_enabled(cfg):
    return bool(cfg.get('email', {}).get('enabled') or cfg.get('webhook', {}).get('enabled'))


def _send_email(ec, subject, body):
    import smtplib
    from email.message import EmailMessage
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = ec.get('from') or ec.get('username') or 'storage-dashboard'
    msg['To'] = ec.get('to', '')
    msg.set_content(body)
    host, port = ec.get('host', ''), int(ec.get('port') or 587)
    sec = ec.get('security', 'starttls')
    if sec == 'ssl':
        s = smtplib.SMTP_SSL(host, port, timeout=15)
    else:
        s = smtplib.SMTP(host, port, timeout=15)
        if sec == 'starttls':
            s.starttls()
    try:
        if ec.get('username'):
            s.login(ec['username'], ec.get('password', ''))
        s.send_message(msg)
    finally:
        s.quit()


def _send_webhook(url, payload):
    import urllib.request
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method='POST',
                                 headers={'Content-Type': 'application/json',
                                          'User-Agent': 'storage-dashboard'})
    urllib.request.urlopen(req, timeout=15).read()


def _notify(cfg, kind, message):
    """Deliver one notification to every enabled channel. Returns list of
    (channel, ok, error)."""
    host = socket.gethostname()
    subject = '[%s] Storage %s: %s' % (host, kind, message[:90])
    body = '%s: %s\n\nHost: %s\nTime: %s\n' % (
        kind, message, socket.getfqdn(), datetime.now().astimezone().isoformat(timespec='seconds'))
    results = []
    ec = cfg.get('email', {})
    if ec.get('enabled'):
        try:
            _send_email(ec, subject, body)
            results.append(('email', True, ''))
        except Exception as e:
            results.append(('email', False, str(e)[:200]))
    wc = cfg.get('webhook', {})
    if wc.get('enabled') and wc.get('url'):
        try:
            # Send only {"text": ...} — Google Chat and Slack both render it, and
            # Google Chat rejects payloads with any unknown fields (400).
            _send_webhook(wc['url'], {'text': '[%s] %s: %s' % (host, kind, message)})
            results.append(('webhook', True, ''))
        except Exception as e:
            results.append(('webhook', False, str(e)[:200]))
    return results


def sync_alerts_timer():
    action = 'enable' if _notifications_enabled(load_notifications()) else 'disable'
    run(['systemctl', '--now', action, ALERTS_TIMER])


def cli_alerts_tick():
    """Invoked by the timer: notify on new/cleared alerts, then persist state."""
    cfg = load_notifications()
    current = {a['key']: a['message'] for a in _compute_alerts()}
    state = cfg.get('state', {})
    if _notifications_enabled(cfg):
        for k, msg in current.items():
            if k not in state:
                _notify(cfg, 'ALERT', msg)
        for k, msg in state.items():
            if k not in current:
                _notify(cfg, 'RESOLVED', msg)
    cfg['state'] = current  # always refresh so enable/disable stays clean
    save_notifications(cfg)


def _validate_notifications(data):
    """Return (clean_config_fragment, error). Does not touch state/password merge."""
    email = data.get('email', {}) or {}
    web = data.get('webhook', {}) or {}
    if email.get('enabled'):
        if not (RE_HOSTNAME.match(email.get('host', '')) or RE_IP.match(email.get('host', ''))):
            return None, 'Invalid SMTP host'
        try:
            if not (1 <= int(email.get('port') or 0) <= 65535):
                return None, 'Invalid SMTP port'
        except (TypeError, ValueError):
            return None, 'Invalid SMTP port'
        if email.get('security', 'starttls') not in ('none', 'starttls', 'ssl'):
            return None, 'Invalid SMTP security'
        if not RE_EMAIL.match(email.get('to', '')):
            return None, 'Invalid recipient address'
        if email.get('from') and not RE_EMAIL.match(email['from']):
            return None, 'Invalid sender address'
    if web.get('enabled') and not re.match(r'^https?://', web.get('url', '')):
        return None, 'Webhook URL must start with http:// or https://'
    return {'email': email, 'webhook': web}, None


@app.route('/api/notifications')
def notifications_get():
    cfg = load_notifications()
    email = dict(cfg.get('email', {}))
    if email.get('password'):
        email['password'] = PW_MASK   # never expose the stored password
    return jsonify({'email': email, 'webhook': cfg.get('webhook', {}),
                    'active_alerts': cfg.get('state', {}),
                    'timer_active': (run(['systemctl', 'is-active', ALERTS_TIMER])[0] or '').strip() == 'active'})


@app.route('/api/notifications', methods=['POST'])
def notifications_save():
    data = request.get_json() or {}
    clean, errmsg = _validate_notifications(data)
    if errmsg:
        return err(errmsg)
    cfg = load_notifications()
    # Preserve the stored SMTP password when the client sends the mask or blank.
    newpw = clean['email'].get('password', '')
    if newpw in (PW_MASK, ''):
        clean['email']['password'] = cfg.get('email', {}).get('password', '')
    cfg['email'] = clean['email']
    cfg['webhook'] = clean['webhook']
    save_notifications(cfg)
    sync_alerts_timer()
    return jsonify({'success': True})


@app.route('/api/notifications/test', methods=['POST'])
def notifications_test():
    cfg = load_notifications()
    if not _notifications_enabled(cfg):
        return err('Enable and save email and/or webhook first')
    results = _notify(cfg, 'TEST', 'This is a test notification from the storage dashboard.')
    ok = all(r[1] for r in results) and bool(results)
    return jsonify({'success': ok,
                    'results': [{'channel': c, 'ok': o, 'error': e} for c, o, e in results]})


# ─── Scheduled maintenance (scrubs + SMART self-tests) ────────────────
# Opt-in, same timer pattern as auto-snapshots: a tick runs due scrubs and SMART
# self-tests. Uses already-granted binaries (zpool, smartctl) — no new sudoers.
MAINTENANCE_FILE = os.environ.get('DASHBOARD_MAINTENANCE_FILE',
                                  os.path.join(APP_DIR, 'maintenance.json'))
MAINT_TIMER = 'storage-dashboard-maintenance.timer'
MAINT_INTERVALS = {'daily': timedelta(days=1), 'weekly': timedelta(days=7),
                   'monthly': timedelta(days=30)}


def load_maintenance():
    try:
        with open(MAINTENANCE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {'scrubs': [], 'smart': []}


def save_maintenance(cfg):
    write_json_atomic(MAINTENANCE_FILE, cfg, 0o644)


def _maint_due(last_run, freq):
    iv = MAINT_INTERVALS.get(freq)
    if not iv:
        return False
    if not last_run:
        return True
    try:
        return datetime.now() - datetime.fromisoformat(last_run) >= iv
    except ValueError:
        return True


def sync_maintenance_timer():
    cfg = load_maintenance()
    active = bool(cfg.get('scrubs') or cfg.get('smart'))
    run(['systemctl', '--now', 'enable' if active else 'disable', MAINT_TIMER])


def cli_maintenance_tick():
    """Invoked by the timer: start due scrubs and SMART self-tests."""
    cfg = load_maintenance()
    now = datetime.now().isoformat(timespec='seconds')
    changed = False
    for s in cfg.get('scrubs', []):
        if _maint_due(s.get('last_run'), s.get('freq', 'monthly')):
            run(['zpool', 'scrub', s['pool']])
            s['last_run'] = now
            changed = True
            print('maintenance: scrub %s' % s['pool'], flush=True)
    for s in cfg.get('smart', []):
        if _maint_due(s.get('last_run'), s.get('freq', 'weekly')):
            run(['smartctl', '-t', s.get('type', 'short'), '/dev/' + s['device']])
            s['last_run'] = now
            changed = True
            print('maintenance: smart %s %s' % (s.get('type', 'short'), s['device']), flush=True)
    if changed:
        save_maintenance(cfg)


@app.route('/api/maintenance')
def maintenance_get():
    cfg = load_maintenance()
    return jsonify({'scrubs': cfg.get('scrubs', []), 'smart': cfg.get('smart', []),
                    'timer_active': (run(['systemctl', 'is-active', MAINT_TIMER])[0] or '').strip() == 'active'})


@app.route('/api/maintenance', methods=['POST'])
def maintenance_save():
    data = request.get_json() or {}
    scrubs, smart = [], []
    for s in data.get('scrubs', []):
        pool = (s.get('pool') or '').strip()
        freq = s.get('freq', 'monthly')
        if not RE_POOL.match(pool):
            return err(f'Invalid pool: {pool}')
        if freq not in ('weekly', 'monthly'):
            return err('Scrub frequency must be weekly or monthly')
        scrubs.append({'pool': pool, 'freq': freq, 'last_run': s.get('last_run', '')})
    for s in data.get('smart', []):
        dev = (s.get('device') or '').strip()
        ttype = s.get('type', 'short')
        freq = s.get('freq', 'weekly')
        if not RE_DEVNAME.match(dev):
            return err(f'Invalid device: {dev}')
        if ttype not in ('short', 'long'):
            return err('SMART test type must be short or long')
        if freq not in ('daily', 'weekly', 'monthly'):
            return err('SMART frequency must be daily, weekly or monthly')
        smart.append({'device': dev, 'type': ttype, 'freq': freq, 'last_run': s.get('last_run', '')})
    save_maintenance({'scrubs': scrubs, 'smart': smart})
    sync_maintenance_timer()
    return jsonify({'success': True})


@app.route('/api/maintenance/smart-test', methods=['POST'])
def maintenance_smart_test():
    """Kick off a SMART self-test now (independent of any schedule)."""
    data = request.get_json() or {}
    dev = (data.get('device') or '').strip()
    ttype = data.get('type', 'short')
    if not RE_DEVNAME.match(dev):
        return err('Invalid device')
    if ttype not in ('short', 'long'):
        return err('Invalid test type')
    return jsonify(run_safe(['smartctl', '-t', ttype, '/dev/' + dev]))


# ─── Scheduled tasks (feature 04) ─────────────────────────────────────
# A read-only console over the systemd timers the dashboard manages, plus a
# "run now" trigger. Status/last-run/next-run/last-result come straight from
# systemctl (no new state file). A failed last run of an armed timer raises an
# alert through the normal _compute_alerts path.
MANAGED_TASKS = [
    {'id': 'autosnap', 'label': 'Auto-Snapshots',
     'timer': 'storage-dashboard-autosnap.timer', 'service': 'storage-dashboard-autosnap.service',
     'desc': 'Take & prune scheduled ZFS snapshots'},
    {'id': 'replicate', 'label': 'Replication',
     'timer': 'storage-dashboard-replicate.timer', 'service': 'storage-dashboard-replicate.service',
     'desc': 'Send ZFS replication jobs to remote hosts'},
    {'id': 'alerts', 'label': 'Health Alerts',
     'timer': 'storage-dashboard-alerts.timer', 'service': 'storage-dashboard-alerts.service',
     'desc': 'Evaluate health and send notifications'},
    {'id': 'maintenance', 'label': 'Maintenance',
     'timer': 'storage-dashboard-maintenance.timer', 'service': 'storage-dashboard-maintenance.service',
     'desc': 'Run due scrubs and SMART self-tests'},
    {'id': 'history', 'label': 'Metrics History',
     'timer': 'storage-dashboard-history.timer', 'service': 'storage-dashboard-history.service',
     'desc': 'Sample metrics into the history store'},
]
TASK_IDS = {t['id'] for t in MANAGED_TASKS}


def _systemctl_show(unit, props):
    """Return {prop: value} from `systemctl show`. Best-effort ({} on error)."""
    args = ['systemctl', 'show', unit, '--no-pager']
    for p in props:
        args += ['-p', p]
    out, _, rc = run(args)
    d = {}
    if rc == 0:
        for line in out.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                d[k] = v
    return d


def _usec_to_epoch(v):
    """systemd *USec property (microseconds) -> unix seconds, or None if 0/empty."""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n // 1_000_000 if n > 0 else None


def _task_status(t):
    tinfo = _systemctl_show(t['timer'], ['ActiveState', 'LastTriggerUSec', 'NextElapseUSecRealtime'])
    sinfo = _systemctl_show(t['service'], ['Result', 'ExecMainStatus', 'ActiveState'])
    last = _usec_to_epoch(tinfo.get('LastTriggerUSec'))
    try:
        code = int(sinfo.get('ExecMainStatus') or -1)
    except ValueError:
        code = -1
    result = sinfo.get('Result') or 'unknown'
    running = sinfo.get('ActiveState') == 'active'
    return {
        'id': t['id'], 'label': t['label'], 'desc': t['desc'], 'timer': t['timer'],
        'timer_active': tinfo.get('ActiveState') == 'active',
        'running': running,
        'last_run': last,
        'next_run': _usec_to_epoch(tinfo.get('NextElapseUSecRealtime')),
        'last_result': result,
        'exit_code': code,
        # ok is None until the task has actually run at least once.
        'ok': (result == 'success') if last is not None else None,
    }


def _task_alerts():
    """Alert on an armed timer whose most recent run failed."""
    out = []
    for t in MANAGED_TASKS:
        s = _task_status(t)
        if s['timer_active'] and s['ok'] is False:
            out.append({'key': 'task:' + t['id'],
                        'message': f"Scheduled task '{t['label']}' last run failed ({s['last_result']})"})
    return out


@app.route('/api/tasks')
def tasks_get():
    return jsonify({'tasks': [_task_status(t) for t in MANAGED_TASKS]})


@app.route('/api/tasks/<tid>/run', methods=['POST'])
def task_run(tid):
    if tid not in TASK_IDS:
        return err('Unknown task', 404)
    t = next(x for x in MANAGED_TASKS if x['id'] == tid)
    r = run_safe(['systemctl', 'start', t['service']])
    if not r['success']:
        return err(r.get('stderr') or 'Failed to start task', 500)
    return jsonify({'success': True})


# ─── Feature modules (nav visibility) ─────────────────────────────────
# Admins can hide whole feature areas from the left-hand navigation. This is a
# cosmetic/organizational toggle (it does not stop services or block the API) —
# the underlying endpoints keep working, so disabling a module never risks data.
# State is a single global list of disabled module ids in modules.json; a module
# is enabled unless explicitly listed as disabled (so new modules default on).
MODULES_FILE = os.environ.get('DASHBOARD_MODULES_FILE',
                              os.path.join(APP_DIR, 'modules.json'))
MODULES = [
    {'id': 'disks',       'label': 'Disks',          'category': 'Storage MGMT'},
    {'id': 'zfs',         'label': 'ZFS Pools',      'category': 'Storage MGMT'},
    {'id': 'lvm',         'label': 'LVM',            'category': 'Storage MGMT'},
    {'id': 'mdraid',      'label': 'MD RAID',        'category': 'Storage MGMT'},
    {'id': 'schedules',   'label': 'Auto-Snapshots', 'category': 'Storage MGMT'},
    {'id': 'replication', 'label': 'Replication',    'category': 'Storage MGMT'},
    {'id': 'maintenance', 'label': 'Maintenance',    'category': 'Storage MGMT'},
    {'id': 'iscsi',       'label': 'iSCSI Targets',  'category': 'Sharing'},
    {'id': 'nfs',         'label': 'NFS Exports',    'category': 'Sharing'},
    {'id': 'smb',         'label': 'SMB/CIFS',       'category': 'Sharing'},
    {'id': 'llamacpp',    'label': 'LLama.cpp',      'category': 'AI Tools'},
    {'id': 'gpu',         'label': 'GPU',            'category': 'AI Tools'},
]
MODULE_IDS = {m['id'] for m in MODULES}


def load_disabled_modules():
    try:
        with open(MODULES_FILE) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return set()
    # Keep only ids we still recognize (a removed module shouldn't linger).
    return {m for m in data.get('disabled', []) if m in MODULE_IDS}


def _enabled_module_ids():
    """Enabled module ids — the node's advertised capabilities. Consumed by a
    cluster controller (via /api/me) for per-node capability discovery and
    node-type auto-classification."""
    disabled = load_disabled_modules()
    return [m['id'] for m in MODULES if m['id'] not in disabled]


@app.route('/api/modules')
def modules_get():
    disabled = load_disabled_modules()
    return jsonify({'modules': [
        {**m, 'enabled': m['id'] not in disabled} for m in MODULES
    ]})


@app.route('/api/modules', methods=['POST'])
def modules_save():
    """Enable/disable modules. Accepts a single {id, enabled} toggle or a full
    {modules: {id: bool}} map. Admin-only (enforced centrally by require_login)."""
    data = request.get_json() or {}
    disabled = load_disabled_modules()
    if 'id' in data:
        updates = {data.get('id'): bool(data.get('enabled'))}
    elif isinstance(data.get('modules'), dict):
        updates = data['modules']
    else:
        return err('Nothing to update')
    for mid, enabled in updates.items():
        if mid not in MODULE_IDS:
            return err(f'Unknown module: {mid}')
        if enabled:
            disabled.discard(mid)
        else:
            disabled.add(mid)
    write_json_atomic(MODULES_FILE, {'disabled': sorted(disabled)}, 0o644)
    return jsonify({'success': True})


# ─── llama.cpp management ─────────────────────────────────────────────
# Recreate the llama-switcher capability in this dashboard's paradigm. Service
# control (start/stop/restart/enable/disable) flows through the shared service
# endpoints (llama-server is registered in SYSTEM_SERVICES). Model + CLI-arg
# changes are written to /etc/llama.conf (LLAMA_BIN / LLAMA_MODEL / LLAMA_OPTS),
# which a static unit's wrapper sources — so no daemon-reload and no unit edits.
# Every value is validated before it reaches the file (config-file injection) or
# the eventual command line (argument injection), and the write goes through the
# pinned `tee /etc/llama.conf` sudoers grant — never open()+write() to /etc.
RE_LLAMA_FLAG = re.compile(r'^-{1,2}[A-Za-z0-9][A-Za-z0-9-]*$')
RE_LLAMA_VALUE = re.compile(r'^[A-Za-z0-9_./:,@=+-]*$')  # no spaces/quotes/newlines

# llama-server flags that take no value (presence-only) — used only to split an
# existing LLAMA_OPTS string into flag/value pairs for the editor.
LLAMA_BOOL_FLAGS = frozenset({
    '--verbose', '-v', '--log-disable', '--log-colors', '--log-verbose', '--offline',
    '--escape', '--no-escape', '--ignore-eos', '--perf', '--no-perf', '--flash-attn', '-fa',
    '--mlock', '--no-mmap', '--mmap', '--no-host', '--repack', '--no-repack',
    '--kv-offload', '-kvo', '--no-kv-offload', '-nkvo', '--direct-io', '-dio', '--no-direct-io', '-ndio',
    '--op-offload', '--no-op-offload', '--cpu-moe', '-cmoe',
    '--reuse-port', '--metrics', '--props', '--slots', '--no-slots',
    '--embedding', '--embeddings', '--rerank', '--reranking', '--jinja', '--no-jinja',
    '--cont-batching', '-cb', '--no-cont-batching', '-nocb', '--cache-prompt', '--no-cache-prompt',
    '--context-shift', '--no-context-shift', '--warmup', '--no-warmup', '--spm-infill',
    '--no-mmproj', '--mmproj-offload', '--no-mmproj-offload', '--kv-unified', '-kvu',
    '--no-webui', '--webui', '--check-tensors',
})


def _llama_read_conf():
    """Parse /etc/llama.conf into {bin, model, opts}; -m stripped from opts."""
    conf = {'bin': LLAMA_DEFAULT_BIN, 'model': '', 'opts': ''}
    try:
        with open(LLAMA_CONF) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, val = line.partition('=')
                val = val.strip().strip('"').strip("'")
                if key == 'LLAMA_BIN':
                    conf['bin'] = val
                elif key == 'LLAMA_MODEL':
                    conf['model'] = val
                elif key == 'LLAMA_OPTS':
                    conf['opts'] = val
    except OSError:
        pass
    conf['opts'] = re.sub(r'(^|\s)-m\s+\S+', ' ', conf['opts']).strip()
    return conf


def _llama_write_conf(conf):
    """Render and write /etc/llama.conf via the pinned tee grant.

    Returns (out, err, rc) — use run() (tuple), not run_safe() (dict)."""
    content = (f'LLAMA_BIN={conf["bin"]}\n'
               f'LLAMA_MODEL={conf["model"]}\n'
               f'LLAMA_OPTS="{conf["opts"]}"\n')
    return run(['tee', LLAMA_CONF], input_data=content)


def _llama_models():
    """All *.gguf under the models dir (excluding mmproj-* projector files)."""
    models = []
    try:
        for root, _dirs, files in os.walk(LLAMA_MODELS_DIR):
            for f in files:
                if f.endswith('.gguf') and not f.startswith('mmproj-'):
                    full = os.path.join(root, f)
                    models.append({'path': full, 'name': os.path.relpath(full, LLAMA_MODELS_DIR)})
    except OSError:
        pass
    return sorted(models, key=lambda m: m['name'])


def _llama_valid_model(path):
    """A model must be a .gguf that resolves inside the models dir and exists."""
    if not path or not RE_PATH.match(path) or not path.endswith('.gguf'):
        return False
    real = os.path.realpath(path)
    root = os.path.realpath(LLAMA_MODELS_DIR)
    return (real == root or real.startswith(root + os.sep)) and os.path.isfile(real)


def _llama_parse_opts(opts):
    """Split an opts string into [{flag, value}] pairs (mirrors the editor)."""
    tokens = opts.split()
    args, i = [], 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith('-'):
            if '=' in tok:
                f, v = tok.split('=', 1)
                args.append({'flag': f, 'value': v}); i += 1; continue
            if tok in LLAMA_BOOL_FLAGS:
                args.append({'flag': tok, 'value': ''}); i += 1; continue
            if i + 1 < len(tokens) and not tokens[i + 1].startswith('-'):
                args.append({'flag': tok, 'value': tokens[i + 1]}); i += 2
            else:
                args.append({'flag': tok, 'value': ''}); i += 1
        else:
            i += 1  # stray bare token (shouldn't happen) — skip
    return args


def _llama_format_opts(args):
    parts = []
    for a in args:
        flag = (a.get('flag') or '').strip()
        val = (a.get('value') or '').strip()
        if not flag:
            continue
        parts.append(f'{flag} {val}' if val else flag)
    return ' '.join(parts)


def _llama_configured():
    return os.path.exists(LLAMA_CONF) or _unit_present(LLAMA_SERVICE)


def _llama_apply_restart():
    """Restart llama-server only if it is currently running (apply in place)."""
    if (run(['systemctl', 'is-active', LLAMA_SERVICE])[0] or '').strip() == 'active':
        run(['systemctl', 'restart', LLAMA_SERVICE])
        return True
    return False


@app.route('/api/llama')
def llama_get():
    conf = _llama_read_conf()
    active = (run(['systemctl', 'is-active', LLAMA_SERVICE])[0] or '').strip() or 'inactive'
    enabled = (run(['systemctl', 'is-enabled', LLAMA_SERVICE])[0] or '').strip() or 'disabled'
    return jsonify({
        'configured': _llama_configured(),
        'service': {'active': active, 'enabled': enabled},
        'bin': conf['bin'],
        'model': conf['model'],
        'models_dir': LLAMA_MODELS_DIR,
        'models': _llama_models(),
        'args': _llama_parse_opts(conf['opts']),
    })


@app.route('/api/llama/model', methods=['PUT'])
def llama_set_model():
    data = request.get_json() or {}
    model = (data.get('model') or '').strip()
    if not _llama_valid_model(model):
        return err('Invalid or unknown model path')
    conf = _llama_read_conf()
    conf['model'] = model
    _, e, rc = _llama_write_conf(conf)
    if rc != 0:
        return err(e or 'Failed to write llama config', 500)
    return jsonify({'success': True, 'restarted': _llama_apply_restart()})


def _llama_clean_args(raw):
    """Validate a raw [{flag, value}] list (shared by the live config and
    presets). Returns (clean_list, error_message_or_None). Drops empty flags and
    the -m/--model flag (managed separately by the Model card)."""
    if not isinstance(raw, list):
        return None, 'args must be a list'
    clean = []
    for a in raw:
        if not isinstance(a, dict):
            return None, 'Each arg must be an object'
        flag = (a.get('flag') or '').strip()
        val = (a.get('value') or '').strip()
        if not flag:
            continue
        if flag in ('-m', '--model'):
            continue
        if not RE_LLAMA_FLAG.match(flag):
            return None, f'Invalid flag: {flag}'
        if val and not RE_LLAMA_VALUE.match(val):
            return None, f'Invalid value for {flag}'
        clean.append({'flag': flag, 'value': val})
    return clean, None


@app.route('/api/llama/args', methods=['PUT'])
def llama_set_args():
    data = request.get_json() or {}
    clean, e = _llama_clean_args(data.get('args'))
    if e:
        return err(e)
    conf = _llama_read_conf()
    conf['opts'] = _llama_format_opts(clean)
    _, we, rc = _llama_write_conf(conf)
    if rc != 0:
        return err(we or 'Failed to write llama config', 500)
    return jsonify({'success': True, 'restarted': _llama_apply_restart(), 'args': clean})


# Named profiles — save a model + a set of CLI args under a name and apply the
# pair to the live server in one click. State in llama_presets.json (atomic,
# gitignored). Back-compat: early presets stored args only (a bare list); those
# normalize to {model:'', args:[...]}.
RE_LLAMA_PRESET = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$')
LLAMA_PRESETS_FILE = os.environ.get('DASHBOARD_LLAMA_PRESETS_FILE',
                                    os.path.join(APP_DIR, 'llama_presets.json'))


def _norm_preset(v):
    """Normalize a stored preset to {model, args}. Accepts the legacy bare-list
    (args-only) shape and the current {model, args} dict shape."""
    if isinstance(v, list):
        return {'model': '', 'args': v}
    if isinstance(v, dict):
        args = v.get('args')
        return {'model': v.get('model') or '', 'args': args if isinstance(args, list) else []}
    return {'model': '', 'args': []}


def _load_llama_presets():
    try:
        with open(LLAMA_PRESETS_FILE) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: _norm_preset(v) for k, v in data.items()}


@app.route('/api/llama/presets')
def llama_presets_get():
    presets = _load_llama_presets()
    return jsonify({'presets': [{'name': k, 'model': v['model'], 'args': v['args']}
                                for k, v in sorted(presets.items())]})


@app.route('/api/llama/presets', methods=['POST'])
def llama_presets_save():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not RE_LLAMA_PRESET.match(name):
        return err('Invalid preset name (letters, numbers, space, _ . - ; max 64)')
    # A profile may pin a model (optional). Validate it the same way the Model
    # card does — must resolve inside the models dir and exist.
    model = (data.get('model') or '').strip()
    if model and not _llama_valid_model(model):
        return err('Invalid or unknown model path')
    clean, e = _llama_clean_args(data.get('args'))
    if e:
        return err(e)
    presets = _load_llama_presets()
    presets[name] = {'model': model, 'args': clean}
    write_json_atomic(LLAMA_PRESETS_FILE, presets, 0o600)
    return jsonify({'success': True, 'name': name})


@app.route('/api/llama/presets/<name>/apply', methods=['POST'])
def llama_presets_apply(name):
    """Apply a saved profile to the live config: write its model (if any) AND its
    args in one /etc/llama.conf rewrite, then restart if running."""
    presets = _load_llama_presets()
    if name not in presets:
        return err('No such preset', 404)
    p = presets[name]
    conf = _llama_read_conf()
    if p['model']:
        if not _llama_valid_model(p['model']):
            return err('Preset model no longer exists: ' + p['model'], 409)
        conf['model'] = p['model']
    conf['opts'] = _llama_format_opts(p['args'])
    _, we, rc = _llama_write_conf(conf)
    if rc != 0:
        return err(we or 'Failed to write llama config', 500)
    return jsonify({'success': True, 'restarted': _llama_apply_restart(),
                    'model': conf['model'], 'args': p['args']})


@app.route('/api/llama/presets/<name>', methods=['DELETE'])
def llama_presets_delete(name):
    presets = _load_llama_presets()
    if name not in presets:
        return err('No such preset', 404)
    del presets[name]
    write_json_atomic(LLAMA_PRESETS_FILE, presets, 0o600)
    return jsonify({'success': True})


# ─── Model download (Hugging Face GGUF pull) ──────────────────────────
# Writing into the root-owned models dir is done by the root-owned wrapper
# storage-dashboard-model-fetch (the trust boundary — it re-validates repo +
# filename, confines output to the models dir, and atomically renames the
# finished file into place). The pull runs in a background thread (one at a time)
# because a multi-GB fetch never fits run()'s 120s window; live progress is read
# by statting the .partial file the wrapper writes.
MODEL_FETCH_HELPER = '/usr/local/sbin/storage-dashboard-model-fetch'
RE_HF_REPO = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$')
RE_HF_FILE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*\.gguf$')

# Job state lives in a file, not memory, so it's consistent across gunicorn
# workers (a status poll may land on a different worker than the one that ran the
# POST / owns the download thread). The .partial byte progress is read straight
# from the filesystem, which is worker-agnostic anyway.
MODEL_JOB_FILE = os.environ.get('DASHBOARD_MODEL_JOB_FILE',
                                os.path.join(APP_DIR, 'model_job.json'))
_model_job_lock = threading.Lock()


def _load_model_job():
    try:
        with open(MODEL_JOB_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {'state': 'idle'}


def _save_model_job(job):
    write_json_atomic(MODEL_JOB_FILE, job, 0o600)


def _hf_resolve_url(repo, filename):
    return 'https://huggingface.co/%s/resolve/main/%s' % (repo, filename)


def _model_fetch_run(repo, filename, token):
    """Thread body: run the wrapper (blocking) and record the outcome to file."""
    out, e, rc = run([MODEL_FETCH_HELPER, repo, filename],
                     input_data=(token + '\n') if token else None)
    with _model_job_lock:
        job = _load_model_job()
        if job.get('filename') != filename:
            return  # superseded by a newer job
        if rc == 0:
            job.update(state='done', finished=time.time())
        else:
            job.update(state='error', finished=time.time(),
                       error=(e or out or 'download failed').strip()[-300:])
        _save_model_job(job)


@app.route('/api/llama/models/pull', methods=['POST'])
def llama_model_pull():
    data = request.get_json() or {}
    repo = (data.get('repo') or '').strip()
    filename = (data.get('filename') or '').strip()
    token = (data.get('token') or '').strip()
    if not RE_HF_REPO.match(repo):
        return err('Invalid repo id (expected e.g. TheBloke/Model-GGUF)')
    if not RE_HF_FILE.match(filename):
        return err('Invalid filename (must be a .gguf, no path separators)')
    dest = os.path.join(LLAMA_MODELS_DIR, filename)
    if os.path.exists(dest):
        return err('A model with that filename already exists', 409)
    with _model_job_lock:
        if _load_model_job().get('state') == 'downloading':
            return err('A download is already in progress', 409)
    # Best-effort total size + existence check via HEAD (unknown -> 0 = no % bar).
    total = 0
    try:
        import urllib.request
        req = urllib.request.Request(_hf_resolve_url(repo, filename), method='HEAD')
        if token:
            req.add_header('Authorization', 'Bearer ' + token)
        with urllib.request.urlopen(req, timeout=10) as r:
            total = int(r.headers.get('Content-Length') or 0)
    except Exception as ex:
        return err('Cannot reach that model on Hugging Face: ' + str(ex)[-200:], 502)
    with _model_job_lock:
        _save_model_job({'state': 'downloading', 'repo': repo, 'filename': filename,
                         'total': total, 'started': time.time()})
    threading.Thread(target=_model_fetch_run, args=(repo, filename, token),
                     daemon=True).start()
    return jsonify({'success': True, 'total': total})


@app.route('/api/llama/models/pull/status')
def llama_model_pull_status():
    job = _load_model_job()
    # Live byte progress: stat the .partial (created by the wrapper as root; the
    # models dir is world-traversable so we can read its size).
    if job.get('state') == 'downloading' and job.get('filename'):
        part = os.path.join(LLAMA_MODELS_DIR, job['filename'] + '.partial')
        try:
            job['downloaded'] = os.path.getsize(part)
        except OSError:
            job['downloaded'] = 0
    return jsonify(job)


# Lightweight in-memory tokens/sec: derived from the tokens_predicted_total
# counter between successive /health polls. No persistence — a real trend lands
# with the history store (plan 01). A counter that decreases means llama-server
# restarted (model switch), so that interval is skipped.
_llama_rate = {'ts': 0.0, 'tokens': None}


def _llama_derive_rate(result):
    tot = (result.get('metrics') or {}).get('tokens_predicted_total')
    if not isinstance(tot, (int, float)):
        return
    now = time.time()
    prev_t, prev_n = _llama_rate['ts'], _llama_rate['tokens']
    if prev_n is not None and prev_t and now > prev_t and tot >= prev_n:
        result['tokens_per_sec'] = round((tot - prev_n) / (now - prev_t), 1)
    _llama_rate['ts'], _llama_rate['tokens'] = now, tot


@app.route('/api/llama/health')
def llama_health():
    """Proxy llama-server's /health + /metrics (no sudo) for the dashboard card."""
    import urllib.request
    base = LLAMA_URL.rstrip('/')
    result = {'ok': False, 'status': 'unknown', 'metrics': {}}
    try:
        with urllib.request.urlopen(base + '/health', timeout=3) as r:
            data = json.loads(r.read().decode())
            result['ok'] = True
            result['status'] = data.get('status', 'ok')
    except Exception as ex:
        result['error'] = str(ex)
    try:
        with urllib.request.urlopen(base + '/metrics', timeout=3) as r:
            text = r.read().decode()
            metrics = {}
            for m in re.finditer(r'^(\w[\w:]*)\s+([0-9.eE+-]+)\s*$', text, re.M):
                name, val = m.group(1), m.group(2)
                short = name.split(':', 1)[-1] if ':' in name else name
                try:
                    metrics[short] = float(val) if ('.' in val or 'e' in val.lower()) else int(val)
                except ValueError:
                    pass
            result['metrics'] = metrics
    except Exception:
        pass
    _llama_derive_rate(result)
    return jsonify(result)


# ─── Network configuration (netplan) ──────────────────────────────────
# The dashboard owns a single netplan file (90-storage-dashboard.yaml), rendered
# from an app-owned JSON config (the source of truth). Changing an interface IP
# is the one operation that can sever the admin's own connection, so it uses a
# **dual-IP, two-step** flow instead of replace-and-race:
#
#   1. Apply  — the new address is ADDED alongside the old one (networkd holds
#      both), keeping the old gateway/DNS active. The admin's current session is
#      never touched, so lockout is impossible during verification. A janitor
#      timer removes the new address after PENDING_WINDOW if nothing is finalized.
#   2. Finalize — once the admin reaches the dashboard on the new address (a
#      handoff token logs them straight in there), the old address is dropped and
#      the gateway/DNS switched. A short FINALIZE_WINDOW timer rolls all the way
#      back to the previous config unless the new-address page heartbeat-confirms,
#      covering the only residual risk (a bad gateway at the final commit).
#
# The privileged write + `netplan generate` + `netplan apply` happen in a
# root-owned helper.
NETPLAN_HELPER = '/usr/local/sbin/storage-dashboard-netplan'
NETCONF_FILE = os.environ.get('DASHBOARD_NETCONF_FILE', os.path.join(APP_DIR, 'network_config.json'))
HOSTS_FILE = os.environ.get('DASHBOARD_HOSTS_FILE', '/etc/hosts')
PENDING_WINDOW = 600   # seconds the un-finalized new address lingers before auto-cleanup
FINALIZE_WINDOW = 90   # seconds to heartbeat-confirm a finalize before it rolls back
DHCP_LEASE_WAIT = 15   # seconds to wait for a DHCP lease so we can report the new IP

RE_HOST_LABEL = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')
RE_DOMAIN = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
                       r'[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')
RE_IFACE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')

# The pending network change (None when idle). 'phase' is 'dual' (new address
# added, awaiting finalize) or 'finalizing' (committed, awaiting heartbeat).
_net_pending = {'phase': None, 'token': None, 'timer': None, 'prev': None,
                'target': None, 'dual': None, 'iface': None, 'desc': None,
                'new_addr': '', 'new_url': ''}
_net_lock = threading.Lock()

# Single-use, short-lived handoff tokens that let the new-address origin mint a
# session without re-typing credentials (session cookies are per-host). Stored
# by SHA-256; minted only by an authenticated admin apply; bound to that user.
HANDOFF_TTL = 120  # seconds
_net_handoffs = {}  # token_hash -> {user, role, exp, used}
_handoff_fails = {}  # ip -> (count, first_ts) brute-force throttle for the public endpoint


def _valid_ipv4(s):
    parts = (s or '').split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
    return True


def _valid_cidr(s):
    ip, sep, prefix = (s or '').partition('/')
    return bool(sep) and _valid_ipv4(ip) and prefix.isdigit() and 0 <= int(prefix) <= 32


def load_netconf():
    try:
        with open(NETCONF_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {'ethernets': {}, 'bridges': {}}


def save_netconf(conf):
    write_json_atomic(NETCONF_FILE, conf, 0o600)


def render_netplan(conf):
    """Render the app's network config to netplan YAML (values are pre-validated,
    so no escaping is needed)."""
    lines = ['network:', '  version: 2', '  renderer: networkd']

    def emit(name, spec, indent):
        pad = ' ' * indent
        p2 = ' ' * (indent + 2)
        lines.append('%s%s:' % (pad, name))
        if spec.get('interfaces'):
            lines.append('%sinterfaces: [%s]' % (p2, ', '.join(spec['interfaces'])))
        # dhcp4 and a list of static addresses are emitted independently:
        # networkd happily holds both at once (DHCP lease + extra static IPs),
        # which is exactly what the dual-IP transition phase relies on.
        lines.append('%sdhcp4: %s' % (p2, 'true' if spec.get('dhcp4') else 'false'))
        addrs = spec.get('addresses', [])
        if addrs:
            lines.append('%saddresses:' % p2)
            for a in addrs:
                lines.append('%s  - %s' % (p2, a))
        if spec.get('gateway'):
            lines.append('%sroutes:' % p2)
            lines.append('%s  - to: default' % p2)
            lines.append('%s    via: %s' % (p2, spec['gateway']))
        if spec.get('nameservers'):
            lines.append('%snameservers:' % p2)
            lines.append('%s  addresses: [%s]' % (p2, ', '.join(spec['nameservers'])))

    eth = conf.get('ethernets', {})
    if eth:
        lines.append('  ethernets:')
        for n, s in eth.items():
            emit(n, s, 4)
    br = conf.get('bridges', {})
    if br:
        lines.append('  bridges:')
        for n, s in br.items():
            emit(n, s, 4)
    return '\n'.join(lines) + '\n'


def _netplan_apply_yaml(yaml_text):
    """Hand the YAML to the root-owned helper: write + `netplan generate` +
    `netplan apply`. On a generate failure the helper restores the prior file and
    returns non-zero (so connectivity is never changed by a bad config)."""
    return run([NETPLAN_HELPER, 'apply'], input_data=yaml_text)


def _iface_spec(conf, iface):
    """The spec for `iface` from either ethernets or bridges (empty if absent)."""
    return (conf.get('ethernets', {}).get(iface)
            or conf.get('bridges', {}).get(iface) or {})


def _addr_host(cidr):
    """'192.168.1.50/24' -> '192.168.1.50'."""
    return (cidr or '').split('/')[0]


def _net_live_spec(iface):
    """The interface's actual current state (addresses/dhcp/gateway) from live
    `ip` data — the fallback when the dashboard has no managed spec yet, so the
    dual phase still preserves the real current IP."""
    for i in _net_interfaces():
        if i['name'] == iface:
            return {'dhcp4': bool(i.get('dhcp')),
                    'addresses': list(i.get('addresses', [])),
                    'gateway': i.get('gateway', '')}
    return {}


def _net_union_spec(prev_spec, target_spec, live_spec=None):
    """Build the transitional 'dual' spec: the new address(es) added on top of
    the old one(s), keeping the OLD gateway/DNS active so routing doesn't switch
    until finalize. `prev_spec` is the dashboard-managed config (may be falsy on
    first configure); `live_spec` reflects the interface's real current state and
    is the fallback. Pure function (unit-tested)."""
    old = prev_spec or live_spec or {}
    target_spec = target_spec or {}
    # Only carry the old *static* addresses forward. If the old side was DHCP, its
    # address comes from the lease and dhcp4 below re-acquires it — re-listing it
    # as static would duplicate the lease.
    old_addrs = [] if old.get('dhcp4') else list(old.get('addresses', []))
    merged, seen = [], set()
    for a in old_addrs + list(target_spec.get('addresses', [])):
        if a and a not in seen:
            seen.add(a)
            merged.append(a)
    dual = {'dhcp4': bool(old.get('dhcp4') or target_spec.get('dhcp4'))}
    if target_spec.get('interfaces') is not None:
        dual['interfaces'] = target_spec['interfaces']
    elif old.get('interfaces'):
        dual['interfaces'] = old['interfaces']
    if merged:
        dual['addresses'] = merged
    # Keep the OLD gateway/DNS during the dual phase, but only when the dual spec
    # is purely static — if DHCP is on it supplies its own default route, and
    # adding a manual one would create a duplicate/ambiguous default route.
    if not dual['dhcp4']:
        if old.get('gateway'):
            dual['gateway'] = old['gateway']
        if old.get('nameservers'):
            dual['nameservers'] = old['nameservers']
    return dual


def _net_resolve_new_addr(iface, target_spec, prev_conf):
    """The address the admin should browse to after applying. For a static
    target that's the configured IP; for DHCP we wait briefly for a lease and
    return the new dynamic address (one not already present in the old config)."""
    static = target_spec.get('addresses') or []
    if static:
        return _addr_host(static[0])
    if not target_spec.get('dhcp4'):
        return ''
    known = {_addr_host(a) for a in _iface_spec(prev_conf, iface).get('addresses', [])}
    deadline = time.time() + DHCP_LEASE_WAIT
    while time.time() < deadline:
        out, _, _ = run(['ip', '-j', 'addr', 'show', iface])
        try:
            links = json.loads(out or '[]')
        except json.JSONDecodeError:
            links = []
        for l in links:
            for a in l.get('addr_info', []):
                if (a.get('family') == 'inet' and a.get('dynamic')
                        and a.get('local') and a['local'] not in known):
                    return a['local']
        time.sleep(1)
    return ''


def _mint_handoff():
    """Issue a single-use handoff secret for the *current admin session*, so the
    new-address origin can mint a session without re-typing credentials. Only one
    is valid at a time (cleared whenever a change starts/ends)."""
    user = session.get('user')
    if not user or _user_role(_users().get(user)) != 'admin':
        return ''
    secret = secrets.token_urlsafe(32)
    _net_handoffs.clear()
    _net_handoffs[_hash_token(secret)] = {'user': user, 'role': 'admin',
                                          'exp': time.time() + HANDOFF_TTL, 'used': False}
    return secret


def _consume_handoff(secret):
    """Validate + burn a handoff secret (constant-time). Valid only if unused,
    unexpired, AND a network change is still pending."""
    if not secret:
        return None
    h = _hash_token(secret)
    now = time.time()
    match = None
    for kh in list(_net_handoffs.keys()):
        rec = _net_handoffs[kh]
        if rec.get('used') or rec.get('exp', 0) < now:
            _net_handoffs.pop(kh, None)
            continue
        if hmac.compare_digest(kh, h):
            match = rec
            _net_handoffs.pop(kh, None)  # single-use
    if not match or not _net_pending['phase']:
        return None
    return match


def _net_clear_timer():
    if _net_pending.get('timer'):
        _net_pending['timer'].cancel()


def _net_clear_pending():
    _net_pending.update({'phase': None, 'token': None, 'timer': None, 'prev': None,
                         'target': None, 'dual': None, 'iface': None, 'desc': None,
                         'new_addr': '', 'new_url': ''})
    _net_handoffs.clear()


def _net_timeout_revert(token, expect_phase):
    """Timer callback: restore the previous (working) config. For 'dual' this
    removes the un-finalized new address; for 'finalizing' it rolls back a
    finalize that was never heartbeat-confirmed. Either way the admin keeps/
    regains a working connection — lockout is impossible."""
    with _net_lock:
        if _net_pending['token'] != token or _net_pending['phase'] != expect_phase:
            return  # superseded, finalized, confirmed, or already reverted
        prev = _net_pending['prev']
        _netplan_apply_yaml(render_netplan(prev))
        save_netconf(prev)
        _net_clear_pending()
    print('network: %s' % ('removed un-finalized address (dual-phase timeout)'
                           if expect_phase == 'dual'
                           else 'finalize not confirmed — rolled back'), flush=True)


def _net_apply(target_conf, dual_conf, iface, desc):
    """Enter the dual phase: apply `dual_conf` (new address ADDED alongside the
    old one, old gateway/DNS kept), arm the cleanup janitor, and return where to
    go to finalize. The clean `target_conf` is committed later by finalize.
    Returns a jsonify-able dict."""
    with _net_lock:
        prev = load_netconf()
        out, errtxt, rc = _netplan_apply_yaml(render_netplan(dual_conf))
        if rc != 0:
            return {'success': False, 'error': (errtxt or out or 'netplan rejected the config').strip()[:300]}
        save_netconf(dual_conf)
        _net_clear_timer()
        token = secrets.token_hex(8)
        timer = threading.Timer(PENDING_WINDOW, _net_timeout_revert, args=[token, 'dual'])
        timer.daemon = True
        _net_pending.update({'phase': 'dual', 'token': token, 'timer': timer,
                             'prev': prev, 'target': target_conf, 'dual': dual_conf,
                             'iface': iface, 'desc': desc, 'new_addr': '', 'new_url': ''})
        timer.start()
    # Resolve the new address outside the lock (a DHCP lease wait can take a few
    # seconds) and mint the handoff link for it.
    new_addr = _net_resolve_new_addr(iface, _iface_spec(target_conf, iface), prev)
    new_url = ''
    if new_addr:
        secret = _mint_handoff()
        scheme = 'https' if TLS_ENABLED else 'http'
        new_url = '%s://%s:%d/?nethandoff=%s' % (scheme, new_addr, DASHBOARD_PORT, secret)
    with _net_lock:
        if _net_pending['token'] == token:
            _net_pending['new_addr'] = new_addr
            _net_pending['new_url'] = new_url
    return {'success': True, 'pending': True, 'phase': 'dual', 'token': token,
            'new_addr': new_addr, 'new_url': new_url, 'window': PENDING_WINDOW, 'desc': desc}


def _net_dns():
    servers = []
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                if line.startswith('nameserver'):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except OSError:
        pass
    return servers


def _net_interfaces():
    out, _, _ = run(['ip', '-j', 'addr', 'show'])
    try:
        links = json.loads(out or '[]')
    except json.JSONDecodeError:
        links = []
    # Map each interface to its default-route gateway (so the Configure dialog
    # can pre-fill the current gateway).
    gwmap = {}
    rout, _, _ = run(['ip', '-j', 'route', 'show', 'default'])
    try:
        for r in json.loads(rout or '[]'):
            if r.get('dst') == 'default' and r.get('dev') and r.get('gateway'):
                gwmap.setdefault(r['dev'], r['gateway'])
    except json.JSONDecodeError:
        pass
    ifaces = []
    for l in links:
        name = l.get('ifname', '')
        if name == 'lo':
            continue
        kind = (l.get('linkinfo', {}) or {}).get('info_kind', '')
        inet = [a for a in l.get('addr_info', []) if a.get('family') == 'inet']
        addrs = ['%s/%s' % (a.get('local', ''), a.get('prefixlen', '')) for a in inet]
        # A DHCP-assigned address carries dynamic=true (kernel sets it from the
        # lease); a static address does not. This tells us the current mode
        # without parsing the existing netplan.
        dhcp = any(a.get('dynamic') for a in inet)
        ifaces.append({'name': name, 'type': 'bridge' if kind == 'bridge' else 'ethernet',
                       'state': (l.get('operstate') or '').lower(), 'mac': l.get('address', ''),
                       'addresses': addrs, 'dhcp': dhcp, 'gateway': gwmap.get(name, '')})
    return ifaces


def _net_gateway():
    out, _, _ = run(['ip', '-j', 'route', 'show', 'default'])
    try:
        for r in json.loads(out or '[]'):
            if r.get('dst') == 'default' and r.get('gateway'):
                return r['gateway']
    except json.JSONDecodeError:
        pass
    return ''


@app.route('/api/network')
def network_get():
    fqdn = socket.getfqdn()
    host = socket.gethostname()
    domain = fqdn[len(host) + 1:] if fqdn.startswith(host + '.') else ''
    with _net_lock:
        pending = None
        if _net_pending['phase']:
            pending = {'phase': _net_pending['phase'], 'token': _net_pending['token'],
                       'desc': _net_pending['desc'], 'new_addr': _net_pending['new_addr'],
                       'new_url': _net_pending['new_url'],
                       'window': PENDING_WINDOW if _net_pending['phase'] == 'dual' else FINALIZE_WINDOW}
    return jsonify({
        'hostname': host, 'domain': domain, 'fqdn': fqdn,
        'interfaces': _net_interfaces(), 'gateway': _net_gateway(), 'dns': _net_dns(),
        'config': load_netconf(), 'pending': pending,
    })


@app.route('/api/network/hostname', methods=['POST'])
def network_hostname():
    data = request.get_json() or {}
    host = (data.get('hostname') or '').strip()
    domain = (data.get('domain') or '').strip()
    if not RE_HOST_LABEL.match(host):
        return err('Invalid hostname')
    if domain and not RE_DOMAIN.match(domain):
        return err('Invalid domain')
    r = run_safe(['hostnamectl', 'set-hostname', host])
    if not r['success']:
        return jsonify(r)
    # Maintain the 127.0.1.1 FQDN line in /etc/hosts (world-readable; rewrite via tee).
    fqdn = '%s.%s' % (host, domain) if domain else host
    try:
        with open(HOSTS_FILE) as f:
            lines = [ln.rstrip('\n') for ln in f]
    except OSError:
        lines = []
    lines = [ln for ln in lines if not ln.split('#', 1)[0].strip().startswith('127.0.1.1')]
    # insert after the 127.0.0.1 line if present, else at top
    newline = '127.0.1.1\t%s %s' % (fqdn, host) if domain else '127.0.1.1\t%s' % host
    out = []
    inserted = False
    for ln in lines:
        out.append(ln)
        if not inserted and ln.split('#', 1)[0].strip().startswith('127.0.0.1'):
            out.append(newline)
            inserted = True
    if not inserted:
        out.insert(0, newline)
    run(['tee', HOSTS_FILE], input_data='\n'.join(out) + '\n')
    return jsonify({'success': True, 'fqdn': fqdn})


def _build_static_spec(data, base):
    """Validate the static-IP fields and attach them to `base`: one or MORE CIDR
    addresses (so a single interface can intentionally hold several IPs), one
    optional default gateway, and optional DNS. Accepts `addresses` (a list) or
    the legacy single `address`. Returns (spec, None) on success, else
    (None, error_response)."""
    raw = data.get('addresses')
    if raw is None:
        raw = [data.get('address')]
    if not isinstance(raw, list):
        raw = [raw]
    addrs = []
    for a in raw:
        a = (a or '').strip()
        if not a:
            continue
        if not _valid_cidr(a):
            return None, err('Address must be CIDR, e.g. 192.168.1.50/24')
        if a not in addrs:           # de-dupe, preserve order
            addrs.append(a)
    if not addrs:
        return None, err('At least one static address (CIDR) is required')
    base['addresses'] = addrs
    gw = (data.get('gateway') or '').strip()
    if gw:
        if not _valid_ipv4(gw):
            return None, err('Invalid gateway')
        base['gateway'] = gw          # one default gateway, regardless of address count
    dns = [d.strip() for d in (data.get('nameservers') or []) if d.strip()]
    for d in dns:
        if not _valid_ipv4(d):
            return None, err('Invalid nameserver: %s' % d)
    if dns:
        base['nameservers'] = dns
    return base, None


@app.route('/api/network/interface', methods=['POST'])
def network_interface():
    data = request.get_json() or {}
    iface = (data.get('iface') or '').strip()
    mode = data.get('mode', 'dhcp')
    if not RE_IFACE.match(iface):
        return err('Invalid interface name')
    if mode not in ('dhcp', 'static'):
        return err('Invalid mode')
    spec = {'dhcp4': mode == 'dhcp'}
    if mode == 'static':
        spec, e = _build_static_spec(data, spec)
        if e:
            return e
    conf = load_netconf()
    prev_spec = conf.get('ethernets', {}).get(iface)
    target_conf = json.loads(json.dumps(conf))
    target_conf.setdefault('ethernets', {})[iface] = spec
    # Dual: keep the interface's current address and add the new one, so the
    # admin's existing connection is never dropped during verification.
    dual_conf = json.loads(json.dumps(conf))
    dual_conf.setdefault('ethernets', {})[iface] = _net_union_spec(
        prev_spec, spec, _net_live_spec(iface))
    return jsonify(_net_apply(target_conf, dual_conf, iface,
                              'interface %s → %s' % (iface, mode)))


@app.route('/api/network/bridge', methods=['POST'])
def network_bridge():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    members = [m.strip() for m in (data.get('interfaces') or []) if m.strip()]
    mode = data.get('mode', 'dhcp')
    if not RE_IFACE.match(name):
        return err('Invalid bridge name')
    for m in members:
        if not RE_IFACE.match(m):
            return err('Invalid member interface: %s' % m)
    if mode not in ('dhcp', 'static'):
        return err('Invalid mode')
    spec = {'dhcp4': mode == 'dhcp', 'interfaces': members}
    if mode == 'static':
        spec, e = _build_static_spec(data, spec)
        if e:
            return e
    conf = load_netconf()
    target_conf = json.loads(json.dumps(conf))
    target_conf.setdefault('bridges', {})[name] = spec
    # Member NICs join the bridge with no IP of their own.
    for m in members:
        target_conf.setdefault('ethernets', {})[m] = {'dhcp4': False}
    # A bridge can't be dual-IP'd — enslaving a member NIC removes its address —
    # so the change applies in full and is protected by the finalize/janitor net
    # (and the handoff link) rather than a non-disruptive dual phase.
    return jsonify(_net_apply(target_conf, target_conf, name,
                              'bridge %s (%s)' % (name, ', '.join(members) or 'no members')))


@app.route('/api/network/finalize', methods=['POST'])
def network_finalize():
    """Commit the dual phase: apply the clean target config (drops the old
    address, switches gateway/DNS) and arm the short heartbeat-confirm net."""
    token = (request.get_json() or {}).get('token')
    with _net_lock:
        if _net_pending['phase'] != 'dual':
            return err('No pending change to finalize', 409)
        if token != _net_pending['token']:
            return err('Stale token; a newer change is pending', 409)
        target = _net_pending['target']
        out, errtxt, rc = _netplan_apply_yaml(render_netplan(target))
        if rc != 0:
            return err((errtxt or out or 'netplan rejected the config').strip()[:300])
        save_netconf(target)
        _net_clear_timer()
        ctoken = secrets.token_hex(8)
        timer = threading.Timer(FINALIZE_WINDOW, _net_timeout_revert, args=[ctoken, 'finalizing'])
        timer.daemon = True
        _net_pending.update({'phase': 'finalizing', 'token': ctoken, 'timer': timer})
        timer.start()
    return jsonify({'success': True, 'phase': 'finalizing', 'confirm_token': ctoken,
                    'window': FINALIZE_WINDOW})


@app.route('/api/network/confirm', methods=['POST'])
def network_confirm():
    """Heartbeat from the new-address page after finalize: cancels the rollback
    net, locking in the committed config."""
    token = (request.get_json() or {}).get('token')
    with _net_lock:
        if _net_pending['phase'] != 'finalizing':
            return jsonify({'success': True, 'note': 'nothing to confirm'})
        if token != _net_pending['token']:
            return err('Stale confirmation token; a newer change is pending', 409)
        _net_clear_timer()
        _net_clear_pending()
    return jsonify({'success': True})


@app.route('/api/network/revert', methods=['POST'])
def network_revert_now():
    """Roll back to the previous working config immediately (either phase)."""
    with _net_lock:
        if not _net_pending['phase']:
            return jsonify({'success': True, 'note': 'nothing to revert'})
        prev = _net_pending['prev']
        _netplan_apply_yaml(render_netplan(prev))
        save_netconf(prev)
        _net_clear_timer()
        _net_clear_pending()
    return jsonify({'success': True})


@app.route('/api/network/handoff', methods=['POST'])
def network_handoff():
    """PUBLIC: exchange a single-use handoff secret (minted by the admin's apply)
    for a session on this origin. Lets the new-address page log in without
    re-typing credentials (session cookies are per-host). High-entropy,
    single-use, 120s, valid only while a change is pending — plus a per-IP
    throttle on this unauthenticated endpoint."""
    ip = request.remote_addr or '?'
    cnt, first = _handoff_fails.get(ip, (0, 0))
    now = time.time()
    if now - first > LOCKOUT_WINDOW:
        cnt, first = 0, now
    if cnt >= LOCKOUT_MAX:
        return jsonify({'success': False, 'error': 'Too many attempts; try again later'}), 429
    secret = (request.get_json(silent=True) or {}).get('token') or ''
    with _net_lock:
        rec = _consume_handoff(secret)
    if not rec:
        _handoff_fails[ip] = (cnt + 1, first or now)
        return jsonify({'success': False, 'error': 'Invalid or expired handoff'}), 401
    _handoff_fails.pop(ip, None)
    g.audit_user = rec['user']
    session.clear()
    session['user'] = rec['user']
    session.permanent = True
    return jsonify({'success': True, 'user': rec['user'], 'role': rec['role'],
                    'fqdn': socket.getfqdn()})


# ─── Automatic snapshot schedules ─────────────────────────────────────
# Opt-in only: nothing is snapshotted or pruned unless the user has created an
# *enabled* schedule. The systemd timer is enabled only while at least one
# enabled schedule exists, and pruning only ever touches autosnap_<freq>_*
# snapshots of scheduled datasets (never manual snapshots).

SCHEDULES_FILE = os.environ.get('DASHBOARD_SCHEDULES_FILE', os.path.join(APP_DIR, 'schedules.json'))
AUTOSNAP_TIMER = 'storage-dashboard-autosnap.timer'
FREQS = ['hourly', 'daily', 'weekly', 'monthly']
FREQ_INTERVAL = {'hourly': timedelta(hours=1), 'daily': timedelta(days=1),
                 'weekly': timedelta(days=7), 'monthly': timedelta(days=30)}


def load_schedules():
    try:
        with open(SCHEDULES_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {'schedules': []}


def save_schedules(cfg):
    write_json_atomic(SCHEDULES_FILE, cfg, 0o644)


def sync_autosnap_timer():
    """Enable the timer iff at least one enabled schedule needs it; disable
    otherwise. This is the master on/off — driven only by the user's schedules."""
    cfg = load_schedules()
    active = any(s.get('enabled') and any(int(s.get('keep', {}).get(fr, 0)) > 0 for fr in FREQS)
                 for s in cfg.get('schedules', []))
    if active:
        run(['systemctl', 'enable', '--now', AUTOSNAP_TIMER])
    else:
        run(['systemctl', 'disable', '--now', AUTOSNAP_TIMER])
    return active


def autosnap_prune(dataset, freq, keep, recursive):
    """Destroy autosnap_<freq>_* snapshots of this dataset beyond the keep count.
    Only ever removes snapshots created by this feature."""
    out, _, _ = run(['zfs', 'list', '-H', '-d', '1', '-t', 'snapshot', '-o', 'name', '-s', 'creation', dataset])
    prefix = f'@autosnap_{freq}_'
    matching = [l for l in out.strip().split('\n') if prefix in l]
    to_delete = matching[:-keep] if keep > 0 and len(matching) > keep else []
    pruned = 0
    for snap in to_delete:
        cmd = ['zfs', 'destroy'] + (['-r'] if recursive else []) + [snap]
        if run_safe(cmd)['success']:
            pruned += 1
    return pruned


def autosnap_one(sched, freq):
    dataset = sched['dataset']
    keep = int(sched.get('keep', {}).get(freq, 0))
    stamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    name = f'{dataset}@autosnap_{freq}_{stamp}'
    cmd = ['zfs', 'snapshot'] + (['-r'] if sched.get('recursive') else []) + [name]
    r = run_safe(cmd)
    pruned = autosnap_prune(dataset, freq, keep, sched.get('recursive')) if r['success'] else 0
    return {'freq': freq, 'snapshot': name, 'ok': r['success'], 'error': r['stderr'][:160], 'pruned': pruned}


@app.route('/api/snapshots/schedules')
def snap_schedules_list():
    active = (run(['systemctl', 'is-active', AUTOSNAP_TIMER])[0] or '').strip() == 'active'
    return jsonify({'schedules': load_schedules().get('schedules', []), 'timer_active': active})


@app.route('/api/snapshots/schedules', methods=['POST'])
def snap_schedule_save():
    data = request.get_json() or {}
    dataset = (data.get('dataset') or '').strip()
    if not RE_DATASET.match(dataset):
        return err('Invalid dataset/pool')
    keep = {}
    for fr in FREQS:
        try:
            keep[fr] = max(0, min(10000, int(data.get('keep', {}).get(fr, 0))))
        except (TypeError, ValueError):
            keep[fr] = 0
    sched = {'dataset': dataset, 'recursive': bool(data.get('recursive')),
             'enabled': bool(data.get('enabled', True)), 'keep': keep, 'last_run': {}}
    cfg = load_schedules()
    prev = next((s for s in cfg['schedules'] if s.get('dataset') == dataset), None)
    if prev:
        sched['last_run'] = prev.get('last_run', {})  # preserve run history on edit
    cfg['schedules'] = [s for s in cfg['schedules'] if s.get('dataset') != dataset]
    cfg['schedules'].append(sched)
    save_schedules(cfg)
    sync_autosnap_timer()
    return jsonify({'success': True})


@app.route('/api/snapshots/schedules/<path:dataset>', methods=['DELETE'])
def snap_schedule_delete(dataset):
    if not RE_DATASET.match(dataset):
        return err('Invalid dataset')
    cfg = load_schedules()
    cfg['schedules'] = [s for s in cfg['schedules'] if s.get('dataset') != dataset]
    save_schedules(cfg)
    sync_autosnap_timer()
    # Existing autosnap snapshots are intentionally left in place on delete.
    return jsonify({'success': True})


@app.route('/api/snapshots/schedules/<path:dataset>/run', methods=['POST'])
def snap_schedule_run(dataset):
    if not RE_DATASET.match(dataset):
        return err('Invalid dataset')
    cfg = load_schedules()
    sched = next((s for s in cfg['schedules'] if s.get('dataset') == dataset), None)
    if not sched:
        return err('No such schedule', 404)
    results = [autosnap_one(sched, fr) for fr in FREQS if int(sched.get('keep', {}).get(fr, 0)) > 0]
    now = datetime.now().isoformat()
    sched.setdefault('last_run', {})
    for r in results:
        sched['last_run'][r['freq']] = now
    save_schedules(cfg)
    return jsonify({'success': all(r['ok'] for r in results), 'results': results})


def cli_autosnap_tick():
    """Invoked by the systemd timer. Snapshots+prunes each enabled schedule's
    frequencies that are due (based on last_run)."""
    cfg = load_schedules()
    now = datetime.now()
    changed = False
    for s in cfg.get('schedules', []):
        if not s.get('enabled'):
            continue
        lr = s.setdefault('last_run', {})
        for fr in FREQS:
            if int(s.get('keep', {}).get(fr, 0)) <= 0:
                continue
            last = lr.get(fr)
            due = True
            if last:
                try:
                    due = (now - datetime.fromisoformat(last)) >= FREQ_INTERVAL[fr]
                except ValueError:
                    due = True
            if due:
                autosnap_one(s, fr)
                lr[fr] = now.isoformat()
                changed = True
    if changed:
        save_schedules(cfg)
    return 0


# ─── LVM (PV / VG / LV) management ───────────────────────────────────
# Safety: destructive ops are refused on anything backing a mounted filesystem
# (protects the boot/root LVM). New PVs are only created on free devices.

RE_LVM = re.compile(r'^[a-zA-Z0-9+_.][a-zA-Z0-9+_.-]*$')        # vg / lv names
RE_LVSIZE = re.compile(r'^\+?[0-9]+(\.[0-9]+)?[KkMmGgTtPp]?$')  # -L sizes (and +N to extend)
RE_LVPCT = re.compile(r'^[0-9]{1,3}%(FREE|VG)$')               # -l percentages


def _lvm_report(tool, fields):
    out, _, _ = run([tool, '--reportformat', 'json', '--units', 'b', '--nosuffix', '-o', fields])
    try:
        rep = json.loads(out).get('report', [])
    except json.JSONDecodeError:
        return []
    key = {'pvs': 'pv', 'vgs': 'vg', 'lvs': 'lv'}[tool]
    return rep[0].get(key, []) if rep else []


def _lv_mountpoint(path):
    return run(['findmnt', '-n', '-o', 'TARGET', path], no_sudo=True)[0].strip() if path else ''


def _lvm_mounted():
    """Sets of VGs and 'vg/lv' that currently back a mounted filesystem."""
    prot_vgs, prot_lvs = set(), set()
    for l in _lvm_report('lvs', 'lv_name,vg_name,lv_path'):
        if _lv_mountpoint(l.get('lv_path', '')):
            prot_vgs.add(l['vg_name'])
            prot_lvs.add(f"{l['vg_name']}/{l['lv_name']}")
    return prot_vgs, prot_lvs


def _standalone_pvs():
    """PV names that exist but are not yet in any VG."""
    return {p['pv_name'] for p in _lvm_report('pvs', 'pv_name,vg_name') if not p.get('vg_name')}


def _device_free_for_pv(dev):
    if not RE_DEVICE.match(dev):
        return False
    out, _, _ = run(['lsblk', '-J', '-o', 'NAME,TYPE,FSTYPE,MOUNTPOINT', dev])
    try:
        nodes = json.loads(out).get('blockdevices', [])
    except json.JSONDecodeError:
        return False
    if not nodes:
        return False
    for n in nodes:
        for x in _walk(n):
            if x.get('mountpoint') or x.get('mountpoint') in BOOT_MOUNTS:
                return False
            if x.get('fstype') in ('zfs_member', 'linux_raid_member', 'LVM2_member', 'swap'):
                return False
    return True


@app.route('/api/lvm')
def lvm_overview():
    prot_vgs, _ = _lvm_mounted()
    lvs = []
    for l in _lvm_report('lvs', 'lv_name,vg_name,lv_size,lv_path,lv_attr'):
        mnt = _lv_mountpoint(l.get('lv_path', ''))
        lvs.append({'name': l['lv_name'], 'vg': l['vg_name'], 'size': _human_bytes(int(l['lv_size'])),
                    'path': l.get('lv_path', ''), 'mountpoint': mnt, 'protected': bool(mnt)})
    pvs = [{'name': p['pv_name'], 'vg': p.get('vg_name', ''),
            'size': _human_bytes(int(p['pv_size'])), 'free': _human_bytes(int(p['pv_free'])),
            'protected': p.get('vg_name') in prot_vgs}
           for p in _lvm_report('pvs', 'pv_name,vg_name,pv_size,pv_free')]
    vgs = [{'name': g['vg_name'], 'pv_count': int(g['pv_count']), 'lv_count': int(g['lv_count']),
            'size': _human_bytes(int(g['vg_size'])), 'free': _human_bytes(int(g['vg_free'])),
            'protected': g['vg_name'] in prot_vgs}
           for g in _lvm_report('vgs', 'vg_name,pv_count,lv_count,vg_size,vg_free')]
    return jsonify({'pvs': pvs, 'vgs': vgs, 'lvs': lvs})


# ── Physical volumes ──
@app.route('/api/lvm/pv', methods=['POST'])
def lvm_pv_create():
    dev = (request.get_json() or {}).get('device', '').strip()
    if not _device_free_for_pv(dev):
        return err('Device is not a free block device')
    return jsonify(run_safe(['pvcreate', dev]))

@app.route('/api/lvm/pv/resize', methods=['POST'])
def lvm_pv_resize():
    dev = (request.get_json() or {}).get('device', '').strip()
    if not RE_DEVICE.match(dev):
        return err('Invalid device')
    return jsonify(run_safe(['pvresize', dev]))

@app.route('/api/lvm/pv/move', methods=['POST'])
def lvm_pv_move():
    data = request.get_json() or {}
    src = (data.get('source') or '').strip()
    dest = (data.get('dest') or '').strip()
    if not RE_DEVICE.match(src) or (dest and not RE_DEVICE.match(dest)):
        return err('Invalid device')
    prot_vgs, _ = _lvm_mounted()
    src_vg = next((p.get('vg_name') for p in _lvm_report('pvs', 'pv_name,vg_name') if p['pv_name'] == src), None)
    if src_vg in prot_vgs:
        return err('Refusing to move data off a PV in a mounted volume group', 409)
    return jsonify(run_safe(['pvmove'] + ([src, dest] if dest else [src])))

@app.route('/api/lvm/pv/remove', methods=['POST'])
def lvm_pv_remove():
    dev = (request.get_json() or {}).get('device', '').strip()
    if not RE_DEVICE.match(dev):
        return err('Invalid device')
    in_vg = next((p.get('vg_name') for p in _lvm_report('pvs', 'pv_name,vg_name') if p['pv_name'] == dev), '')
    if in_vg:
        return err(f'PV is in volume group "{in_vg}" — remove it from the VG first', 409)
    return jsonify(run_safe(['pvremove', dev]))


# ── Volume groups ──
@app.route('/api/lvm/vg', methods=['POST'])
def lvm_vg_create():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    devices = data.get('devices', [])
    if not RE_LVM.match(name):
        return err('Invalid VG name')
    standalone = _standalone_pvs()
    for d in devices:
        if not RE_DEVICE.match(d) or d not in standalone:
            return err(f'{d} is not an unused physical volume')
    if not devices:
        return err('Select at least one physical volume')
    return jsonify(run_safe(['vgcreate', name] + devices))

@app.route('/api/lvm/vg/<name>/extend', methods=['POST'])
def lvm_vg_extend(name):
    dev = (request.get_json() or {}).get('device', '').strip()
    if not RE_LVM.match(name):
        return err('Invalid VG name')
    if dev not in _standalone_pvs():
        return err('Device is not an unused physical volume')
    return jsonify(run_safe(['vgextend', name, dev]))

@app.route('/api/lvm/vg/<name>/reduce', methods=['POST'])
def lvm_vg_reduce(name):
    dev = (request.get_json() or {}).get('device', '').strip()
    if not RE_LVM.match(name) or not RE_DEVICE.match(dev):
        return err('Invalid VG or device')
    prot_vgs, _ = _lvm_mounted()
    if name in prot_vgs:
        return err('Refusing to alter a mounted volume group', 409)
    return jsonify(run_safe(['vgreduce', name, dev]))

@app.route('/api/lvm/vg/<name>', methods=['DELETE'])
def lvm_vg_remove(name):
    if not RE_LVM.match(name):
        return err('Invalid VG name')
    prot_vgs, _ = _lvm_mounted()
    if name in prot_vgs:
        return err('Refusing to remove a volume group with mounted volumes', 409)
    return jsonify(run_safe(['vgremove', name]))  # no -f: refuses if LVs still exist


# ── Logical volumes ──
@app.route('/api/lvm/lv', methods=['POST'])
def lvm_lv_create():
    data = request.get_json() or {}
    vg = (data.get('vg') or '').strip()
    name = (data.get('name') or '').strip()
    size = (data.get('size') or '').strip()
    fstype = (data.get('fstype') or '').strip()
    if not RE_LVM.match(vg) or not RE_LVM.match(name):
        return err('Invalid VG or LV name')
    if RE_LVPCT.match(size):
        cmd = ['lvcreate', '-l', size, '-n', name, vg]
    elif RE_LVSIZE.match(size):
        cmd = ['lvcreate', '-L', size, '-n', name, vg]
    else:
        return err('Invalid size (e.g. 10G or 100%FREE)')
    if fstype and fstype not in ('ext4', 'xfs'):
        return err('Unsupported filesystem')
    r = run_safe(cmd)
    if r['success'] and fstype:
        opt = '-F' if fstype == 'ext4' else '-f'
        run_safe([f'mkfs.{fstype}', opt, f'/dev/{vg}/{name}'])
    return jsonify(r)

@app.route('/api/lvm/lv/<vg>/<name>/extend', methods=['POST'])
def lvm_lv_extend(vg, name):
    data = request.get_json() or {}
    size = (data.get('size') or '').strip()
    if not RE_LVM.match(vg) or not RE_LVM.match(name):
        return err('Invalid VG or LV name')
    if RE_LVPCT.match(size):
        cmd = ['lvextend', '-l', size]
    elif RE_LVSIZE.match(size):
        cmd = ['lvextend', '-L', size]
    else:
        return err('Invalid size (e.g. +10G, 50G, or 100%FREE)')
    if data.get('resize_fs'):
        cmd.append('-r')  # grow the filesystem too
    cmd.append(f'{vg}/{name}')
    return jsonify(run_safe(cmd))  # extend (grow) only — never shrinks

@app.route('/api/lvm/lv/<vg>/<name>', methods=['DELETE'])
def lvm_lv_remove(vg, name):
    if not RE_LVM.match(vg) or not RE_LVM.match(name):
        return err('Invalid VG or LV name')
    _, prot_lvs = _lvm_mounted()
    if f'{vg}/{name}' in prot_lvs:
        return err('Refusing to remove a mounted logical volume', 409)
    return jsonify(run_safe(['lvremove', '-y', f'{vg}/{name}']))


# ─── MD RAID (mdadm) management ──────────────────────────────────────
# Members can only be FREE disks; arrays backing a mounted FS / pool / LVM are
# protected from stop/delete. Created arrays are persisted to mdadm.conf.

RE_MDDEV = re.compile(r'^md\d+$')
RE_MDNAME = re.compile(r'^[a-zA-Z0-9_.-]+$')
MD_MIN_DEVICES = {'0': 2, '1': 2, '5': 3, '6': 4, '10': 2}


def _md_list_devs():
    devs = []
    try:
        with open('/proc/mdstat') as f:
            for line in f:
                m = re.match(r'^(md\d+)\s*:', line)
                if m:
                    devs.append(m.group(1))
    except FileNotFoundError:
        pass
    return devs


def parse_mdadm_detail(out):
    info = {'level': '', 'size': '', 'state': '', 'raid_devices': '', 'active': '',
            'failed': '', 'spare': '', 'sync': '', 'devices': []}
    keymap = {'Raid Level': 'level', 'Array Size': 'size', 'State': 'state',
              'Raid Devices': 'raid_devices', 'Active Devices': 'active',
              'Failed Devices': 'failed', 'Spare Devices': 'spare'}
    for line in out.split('\n'):
        s = line.strip()
        if ':' in s:
            k, v = s.split(':', 1)
            k, v = k.strip(), v.strip()
            if k in keymap:
                info[keymap[k]] = v.split('(')[0].strip() if k == 'Array Size' else v
            elif k in ('Rebuild Status', 'Resync Status', 'Check Status'):
                info['sync'] = f'{k.split()[0]}: {v}'
        parts = s.split()
        if len(parts) >= 5 and parts[0].isdigit() and parts[-1].startswith('/dev/'):
            info['devices'].append({'number': parts[0], 'state': ' '.join(parts[4:-1]), 'device': parts[-1]})
    return info


def _md_protected(dev):
    out, _, _ = run(['lsblk', '-J', '-o', 'NAME,FSTYPE,MOUNTPOINT', f'/dev/{dev}'])
    try:
        nodes = json.loads(out).get('blockdevices', [])
    except json.JSONDecodeError:
        return False
    for n in nodes:
        for x in _walk(n):
            if x.get('mountpoint') or x.get('fstype') in ('zfs_member', 'LVM2_member', 'swap'):
                return True
    return False


def _md_sync_conf(persist=True):
    """Rebuild the ARRAY lines in mdadm.conf from the live arrays (best effort)."""
    scan = run(['mdadm', '--detail', '--scan'])[0]
    array_lines = [l.strip() for l in scan.split('\n') if l.strip().startswith('ARRAY')]
    try:
        with open(MDADM_CONF) as f:
            kept = [l for l in f.read().split('\n') if not l.strip().startswith('ARRAY')]
    except FileNotFoundError:
        kept = []
    content = '\n'.join(kept).rstrip('\n') + '\n' + '\n'.join(array_lines) + '\n'
    run_safe(['tee', MDADM_CONF], input_data=content)
    if persist:
        run(INITRAMFS_UPDATE)  # best effort; for boot-time assembly


@app.route('/api/mdadm/arrays')
def mdadm_arrays():
    arrays = []
    for dev in _md_list_devs():
        info = parse_mdadm_detail(run(['mdadm', '--detail', f'/dev/{dev}'])[0])
        info['device'] = dev
        info['protected'] = _md_protected(dev)
        arrays.append(info)
    return jsonify({'arrays': arrays})


@app.route('/api/mdadm/arrays', methods=['POST'])
def mdadm_create():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    level = str(data.get('level', '1')).strip()
    devices = data.get('devices', [])
    spares = data.get('spares', [])
    persist = data.get('persist', True)
    if not RE_MDNAME.match(name):
        return err('Invalid array name')
    if level not in MD_MIN_DEVICES:
        return err('Invalid RAID level')
    for d in list(devices) + list(spares):
        if not _device_free_for_pv(d):
            return err(f'{d} is not a free disk')
    if len(devices) < MD_MIN_DEVICES[level]:
        return err(f'RAID{level} needs at least {MD_MIN_DEVICES[level]} devices')
    # Ensure the RAID personality is loaded (this host boots with none).
    run(['modprobe', {'0': 'raid0', '1': 'raid1', '5': 'raid456', '6': 'raid456', '10': 'raid10'}[level]])
    cmd = ['mdadm', '--create', f'/dev/md/{name}', '--run', f'--level={level}',
           f'--raid-devices={len(devices)}']
    if spares:
        cmd.append(f'--spare-devices={len(spares)}')
    cmd += list(devices) + list(spares)
    r = run_safe(cmd, input_data='y\n')
    if r['success']:
        _md_sync_conf(persist)
    return jsonify(r)


@app.route('/api/mdadm/arrays/<dev>')
def mdadm_detail(dev):
    if not RE_MDDEV.match(dev):
        return err('Invalid array')
    info = parse_mdadm_detail(run(['mdadm', '--detail', f'/dev/{dev}'])[0])
    info['device'] = dev
    return jsonify(info)


@app.route('/api/mdadm/arrays/<dev>/device', methods=['POST'])
def mdadm_device(dev):
    if not RE_MDDEV.match(dev):
        return err('Invalid array')
    data = request.get_json() or {}
    action = data.get('action')
    device = (data.get('device') or '').strip()
    if action not in ('add', 'remove', 'fail'):
        return err('Invalid action')
    if not RE_DEVICE.match(device):
        return err('Invalid device')
    if action == 'add' and not _device_free_for_pv(device):
        return err('Device is not free (wipe it first to re-add)')
    flag = {'add': '--add', 'remove': '--remove', 'fail': '--fail'}[action]
    r = run_safe(['mdadm', '--manage', f'/dev/{dev}', flag, device])
    if r['success'] and action in ('add', 'remove'):
        _md_sync_conf(persist=False)
    return jsonify(r)


@app.route('/api/mdadm/arrays/<dev>/stop', methods=['POST'])
def mdadm_stop(dev):
    if not RE_MDDEV.match(dev):
        return err('Invalid array')
    if _md_protected(dev):
        return err('Refusing to stop an array that is in use', 409)
    return jsonify(run_safe(['mdadm', '--stop', f'/dev/{dev}']))


@app.route('/api/mdadm/assemble', methods=['POST'])
def mdadm_assemble():
    return jsonify(run_safe(['mdadm', '--assemble', '--scan']))


@app.route('/api/mdadm/arrays/<dev>', methods=['DELETE'])
def mdadm_delete(dev):
    if not RE_MDDEV.match(dev):
        return err('Invalid array')
    if _md_protected(dev):
        return err('Refusing to delete an array that is in use', 409)
    members = [d['device'] for d in parse_mdadm_detail(run(['mdadm', '--detail', f'/dev/{dev}'])[0])['devices']]
    run_safe(['mdadm', '--stop', f'/dev/{dev}'])
    for m in members:
        if RE_DEVICE.match(m):
            run(['mdadm', '--zero-superblock', m])
    _md_sync_conf()
    return jsonify({'success': True})


# ─── Network Info ─────────────────────────────────────────────────────

@app.route('/api/network')
def api_network():
    out, _, rc = run(['ip', '-j', 'addr', 'show'])
    if rc != 0:
        out, _, _ = run(['ip', 'addr', 'show'])
        return jsonify({'interfaces': [], 'raw': out})
    try:
        data = json.loads(out) if out.strip() else []
    except json.JSONDecodeError:
        data = []
    return jsonify({'interfaces': data})


def cli_set_password(argv):
    import getpass
    user = argv[2] if len(argv) > 2 else 'admin'
    if not RE_USERNAME.match(user):
        print('Invalid username')
        return 1
    pw = os.environ.get('DASHBOARD_ADMIN_PASSWORD')
    if not pw:
        pw = getpass.getpass(f'New password for {user}: ')
        if pw != getpass.getpass('Confirm password: '):
            print('Passwords do not match')
            return 1
    if len(pw) < MIN_PASSWORD_LEN:
        print(f'Password must be at least {MIN_PASSWORD_LEN} characters')
        return 1
    cfg = ensure_bootstrap()
    users = cfg.setdefault('users', {})
    rec = users[user] if isinstance(users.get(user), dict) else {'role': 'admin', 'smb': False}
    rec['password'] = generate_password_hash(pw)
    users[user] = rec
    save_config(cfg)
    print(f'Password updated for {user}')
    return 0


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'set-password':
        sys.exit(cli_set_password(sys.argv))
    if len(sys.argv) > 1 and sys.argv[1] == 'autosnap-tick':
        sys.exit(cli_autosnap_tick())
    if len(sys.argv) > 1 and sys.argv[1] == 'replicate-tick':
        sys.exit(cli_replicate_tick())
    if len(sys.argv) > 1 and sys.argv[1] == 'alerts-tick':
        sys.exit(cli_alerts_tick())
    if len(sys.argv) > 1 and sys.argv[1] == 'maintenance-tick':
        sys.exit(cli_maintenance_tick())
    if len(sys.argv) > 1 and sys.argv[1] == 'history-tick':
        sys.exit(cli_history_tick())
    app.secret_key = ensure_bootstrap()['secret_key']
    ssl_context = None
    if TLS_ENABLED:
        ensure_tls_cert()
        ssl_context = (TLS_CERT, TLS_KEY)
    app.run(host='0.0.0.0', port=DASHBOARD_PORT, ssl_context=ssl_context, debug=False)
