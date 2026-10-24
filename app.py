"""
CyberWatch IDS — Flask Backend
Run:  python app.py
API base: http://localhost:5000/api
"""

import os, re, json, math
from datetime import datetime, timedelta, timezone
from functools import wraps

from dotenv import load_dotenv
load_dotenv()  # Load .env BEFORE importing Config so env vars are ready

from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt as pyjwt

from config import Config

# ─────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)
CORS(app, origins=Config.CORS_ORIGINS, supports_credentials=True)
db = SQLAlchemy(app)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# ══════════════════════════════════════════════════════════════
#  MODELS
# ══════════════════════════════════════════════════════════════

class User(db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.Enum('admin','analyst','viewer'), default='analyst')
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    last_login    = db.Column(db.DateTime)
    is_active     = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {'id': self.id, 'username': self.username,
                'role': self.role, 'created_at': str(self.created_at)}


class Report(db.Model):
    __tablename__ = 'reports'
    id               = db.Column(db.Integer, primary_key=True)
    report_id        = db.Column(db.String(40), unique=True, nullable=False)
    file_name        = db.Column(db.String(255), nullable=False)
    uploaded_by      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    total_lines      = db.Column(db.Integer, default=0)
    total_parsed     = db.Column(db.Integer, default=0)
    critical_count   = db.Column(db.Integer, default=0)
    suspicious_count = db.Column(db.Integer, default=0)
    clean_count      = db.Column(db.Integer, default=0)
    unique_ips       = db.Column(db.Integer, default=0)
    risk_score       = db.Column(db.Integer, default=0)
    risk_label       = db.Column(db.Enum('LOW','MEDIUM','HIGH','CRITICAL'), default='LOW')
    findings_json    = db.Column(db.JSON)
    status_codes_json= db.Column(db.JSON)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'report_id': self.report_id,
            'file_name': self.file_name, 'uploaded_by': self.uploaded_by,
            'total_lines': self.total_lines, 'total_parsed': self.total_parsed,
            'critical_count': self.critical_count, 'suspicious_count': self.suspicious_count,
            'clean_count': self.clean_count, 'unique_ips': self.unique_ips,
            'risk_score': self.risk_score, 'risk_label': self.risk_label,
            'findings': self.findings_json or [],
            'status_codes': self.status_codes_json or {},
            'created_at': str(self.created_at),
        }


class Alert(db.Model):
    __tablename__ = 'alerts'
    id          = db.Column(db.Integer, primary_key=True)
    alert_id    = db.Column(db.String(10), unique=True, nullable=False)
    type        = db.Column(db.Enum('critical','warning','info'), nullable=False)
    category    = db.Column(db.String(30), nullable=False)
    title       = db.Column(db.String(255), nullable=False)
    source_ip   = db.Column(db.String(45))
    detail      = db.Column(db.Text)
    alert_time  = db.Column(db.String(10))
    module      = db.Column(db.String(60))
    log_file    = db.Column(db.String(80))
    rule_id     = db.Column(db.String(20))
    attempts    = db.Column(db.Integer, default=0)
    port        = db.Column(db.Integer, default=0)
    status      = db.Column(db.Enum('active','blocked','watchlist','mitigated','flagged','resolved'), default='active')
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    resolved_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id, 'alert_id': self.alert_id,
            'type': self.type, 'category': self.category,
            'title': self.title, 'source': self.source_ip,
            'detail': self.detail, 'time': self.alert_time,
            'module': self.module, 'file': self.log_file,
            'rule': self.rule_id, 'attempts': self.attempts,
            'port': self.port, 'status': self.status,
            'created_at': str(self.created_at),
        }


class LogFile(db.Model):
    __tablename__ = 'log_files'
    id          = db.Column(db.Integer, primary_key=True)
    file_name   = db.Column(db.String(255), nullable=False)
    file_size   = db.Column(db.BigInteger, default=0)
    file_path   = db.Column(db.String(500))
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    total_lines = db.Column(db.Integer, default=0)
    threat_count= db.Column(db.Integer, default=0)
    report_id   = db.Column(db.Integer, db.ForeignKey('reports.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'file_name': self.file_name,
            'file_size': self.file_size, 'uploaded_by': self.uploaded_by,
            'total_lines': self.total_lines, 'threat_count': self.threat_count,
            'uploaded_at': str(self.uploaded_at),
        }


class LogEntry(db.Model):
    __tablename__ = 'log_entries'
    id          = db.Column(db.Integer, primary_key=True)
    log_file_id = db.Column(db.Integer, db.ForeignKey('log_files.id', ondelete='CASCADE'))
    entry_ts    = db.Column(db.DateTime)
    ip_address  = db.Column(db.String(45))
    method      = db.Column(db.String(10))
    path        = db.Column(db.String(1000))
    status_code = db.Column(db.SmallInteger)
    flag        = db.Column(db.Enum('CLEAN','SUSPICIOUS','CRITICAL'), default='CLEAN')
    raw_line    = db.Column(db.Text)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'log_file_id': self.log_file_id,
            'ts': str(self.entry_ts), 'ip': self.ip_address,
            'method': self.method, 'path': self.path,
            'status': self.status_code, 'flag': self.flag,
        }


class IPBlocklist(db.Model):
    __tablename__ = 'ip_blocklist'
    id           = db.Column(db.Integer, primary_key=True)
    ip_address   = db.Column(db.String(45), unique=True, nullable=False)
    country      = db.Column(db.String(60))
    threat_level = db.Column(db.Integer, default=0)
    attempts     = db.Column(db.Integer, default=0)
    status       = db.Column(db.Enum('BLOCKED','WATCHLIST','ALLOWED'), default='BLOCKED')
    reason       = db.Column(db.Text)
    added_by     = db.Column(db.Integer, db.ForeignKey('users.id'))
    added_at     = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes        = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id, 'ip': self.ip_address,
            'country': self.country, 'threat_level': self.threat_level,
            'attempts': self.attempts, 'status': self.status,
            'reason': self.reason, 'added_at': str(self.added_at),
        }


class LiveLog(db.Model):
    __tablename__ = 'live_logs'
    id      = db.Column(db.Integer, primary_key=True)
    level   = db.Column(db.Enum('CRIT','WARN','INFO','OK'), nullable=False)
    source  = db.Column(db.String(50))
    message = db.Column(db.Text)
    host_ip = db.Column(db.String(45))
    ts      = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'level': self.level,
            'src': self.source, 'msg': self.message,
            'ip': self.host_ip,
            'time': self.ts.strftime('%H:%M') if self.ts else '',
        }


# ══════════════════════════════════════════════════════════════
#  JWT HELPERS
# ══════════════════════════════════════════════════════════════

def create_token(user_id, role, refresh=False):
    delta = (timedelta(days=Config.JWT_REFRESH_TOKEN_EXPIRES_DAYS)
             if refresh else
             timedelta(minutes=Config.JWT_ACCESS_TOKEN_EXPIRES_MINUTES))
    payload = {
        'sub': user_id,
        'role': role,
        'type': 'refresh' if refresh else 'access',
        'exp': datetime.now(timezone.utc) + delta,
        'iat': datetime.now(timezone.utc),
    }
    return pyjwt.encode(payload, Config.JWT_SECRET_KEY, algorithm='HS256')


def decode_token(token):
    return pyjwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])


def jwt_required(roles=None):
    """Decorator — validates Bearer token, injects g.current_user."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get('Authorization', '')
            if not auth.startswith('Bearer '):
                return jsonify({'error': 'Missing or invalid Authorization header'}), 401
            token = auth.split(' ', 1)[1]
            try:
                data = decode_token(token)
            except pyjwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except pyjwt.InvalidTokenError as e:
                return jsonify({'error': f'Invalid token: {e}'}), 401
            if data.get('type') != 'access':
                return jsonify({'error': 'Refresh token cannot access this endpoint'}), 401
            user = db.session.get(User, data['sub'])
            if not user or not user.is_active:
                return jsonify({'error': 'User not found or inactive'}), 401
            if roles and user.role not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            g.current_user = user
            return f(*args, **kwargs)
        return wrapper
    return decorator


def ok(data=None, status=200, **kwargs):
    payload = {'success': True}
    if data is not None:
        payload['data'] = data
    payload.update(kwargs)
    return jsonify(payload), status


def err(msg, status=400):
    return jsonify({'success': False, 'error': msg}), status


# ══════════════════════════════════════════════════════════════
#  THREAT RULES  (mirror of frontend THREAT_RULES)
# ══════════════════════════════════════════════════════════════

THREAT_RULES = [
    {'id': 'BF-001',   'name': 'Brute Force Attack',
     'severity': 'CRITICAL',
     'pattern': re.compile(r'fail(ed)?\s*(password|login|auth)|invalid\s*(user|pass|credential)|authentication\s*fail', re.I),
     'solutions': [
         'Block the offending IP via iptables: iptables -A INPUT -s <IP> -j DROP',
         'Enable account lockout after 5 failed attempts (pam_faillock).',
         'Deploy fail2ban to auto-ban IPs exceeding the threshold.',
         'Enforce MFA on all SSH/admin endpoints.',
         'Disable root SSH login: PermitRootLogin no in sshd_config.',
         'Use SSH key-based auth and disable password auth.',
     ]},
    {'id': 'SQLI-001', 'name': 'SQL Injection Attempt',
     'severity': 'CRITICAL',
     'pattern': re.compile(r"UNION\s+SELECT|SELECT\s+.*FROM|DROP\s+TABLE|INSERT\s+INTO|'\s*OR\s*'?1'?\s*=\s*'?1|--\s*$|;\s*DROP|EXEC\s*\(", re.I),
     'solutions': [
         'Use parameterized queries / prepared statements — never concatenate user input.',
         'Deploy a WAF with SQLi ruleset (ModSecurity, Cloudflare WAF).',
         'Validate and whitelist all input on the server side.',
         'Apply least privilege to DB accounts — never use root for the web app.',
         'Enable DB query logging to audit suspicious queries.',
         'Run regular DAST scans (OWASP ZAP, Burp Suite).',
     ]},
    {'id': 'SCAN-001', 'name': 'Port Scan / Reconnaissance',
     'severity': 'WARNING',
     'pattern': re.compile(r'port\s*scan|nmap|masscan|\d+\s+ports?\s+(scanned|in\s+\d)|SYN\s+scan|TCP\s+connect\s+scan', re.I),
     'solutions': [
         'Block the scanning IP at the perimeter firewall immediately.',
         'Use iptables recent module to auto-block rapid port scanners.',
         'Disable or close all non-essential open ports.',
         'Deploy Snort/Suricata with port scan detection signatures.',
         'Consider a honeypot (Cowrie, OpenCanary) to detect scanners.',
     ]},
    {'id': 'PRIV-001', 'name': 'Privilege Escalation',
     'severity': 'CRITICAL',
     'pattern': re.compile(r'sudo|su\s+-|privilege\s*escal|NOPASSWD|setuid|chmod\s+[0-9]*[47][0-9]*\s+\/|\/etc\/sudoers', re.I),
     'solutions': [
         'Audit /etc/sudoers and remove unnecessary NOPASSWD entries.',
         'Apply principle of least privilege to all user accounts.',
         'Enable auditd to log all privilege escalation events.',
         'Restrict shell access for service accounts (/usr/sbin/nologin).',
     ]},
    {'id': 'XSS-001',  'name': 'Cross-Site Scripting (XSS)',
     'severity': 'WARNING',
     'pattern': re.compile(r'<script[\s>]|javascript:|on(load|click|error|mouseover)\s*=|alert\s*\(|document\.cookie', re.I),
     'solutions': [
         'Encode all user-supplied output (HTML/JS/URL encode).',
         'Implement a strong Content-Security-Policy header.',
         'Use HTTPOnly and Secure flags on session cookies.',
         'Use modern frameworks that auto-escape output (React, Vue).',
     ]},
    {'id': 'DIR-001',  'name': 'Directory Traversal',
     'severity': 'WARNING',
     'pattern': re.compile(r'\.\.[/\\]|\.\.%2[fF]|%2e%2e%2f|/etc/passwd|/etc/shadow|/proc/self', re.I),
     'solutions': [
         'Validate file paths — resolve canonical path and verify it starts within the allowed dir.',
         'Configure the web server to deny requests containing "../".',
         'Run the web app as a low-privilege user with chroot/containers.',
         'Use a WAF rule to block path traversal patterns.',
     ]},
    {'id': 'DOS-001',  'name': 'Denial of Service / Flood',
     'severity': 'CRITICAL',
     'pattern': re.compile(r'SYN\s+flood|DDoS|DoS|UDP\s+flood|\d{4,}\s+(packet|request)s?\s+(per\s+second|in\s+\d+\s*s)|connection\s*flood', re.I),
     'solutions': [
         'Enable SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1',
         'Use rate-limiting at the firewall.',
         'Deploy a CDN with DDoS protection (Cloudflare, AWS Shield).',
         'Enable Anycast network diffusion to distribute attack traffic.',
     ]},
    {'id': 'MAL-001',  'name': 'Malware / C2 Communication',
     'severity': 'CRITICAL',
     'pattern': re.compile(r'malware|c2|command.and.control|botnet|backdoor|trojan|reverse\s+shell|nc\s+-e|bash\s+-i|/dev/tcp', re.I),
     'solutions': [
         'Isolate the affected host from the network immediately.',
         'Run a full malware scan (ClamAV, commercial AV).',
         'Capture network traffic for forensic analysis.',
         'Block C2 domain/IP at DNS level and firewall.',
         'Consider reimaging the compromised host.',
     ]},
    {'id': 'AUTH-001', 'name': 'Unauthorized Access Attempt',
     'severity': 'WARNING',
     'pattern': re.compile(r'unauthorized|403\s+forbidden|access\s+denied|permission\s+denied|not\s+authorized|invalid\s+token', re.I),
     'solutions': [
         'Audit IAM policies and file permissions.',
         'Implement rate-limiting on authentication endpoints.',
         'Enable JWT/session token expiry and rotation.',
         'Enable CAPTCHA on login forms.',
     ]},
    {'id': 'DATA-001', 'name': 'Suspicious Data Exfiltration',
     'severity': 'WARNING',
     'pattern': re.compile(r'exfil|large\s+(upload|transfer|outbound)|\d+\s*(MB|GB)\s*(upload|sent|transfer)|unusual\s+outbound', re.I),
     'solutions': [
         'Block the destination IP and investigate the source host.',
         'Enable DLP policies to alert on large file transfers.',
         'Monitor outbound traffic baselines — alert on deviations.',
         'Restrict outbound connections to whitelisted IPs only.',
     ]},
    {'id': 'LFI-001',  'name': 'Local File Inclusion (LFI)',
     'severity': 'WARNING',
     'pattern': re.compile(r"include\s*\(?['\"]?\s*\.\.|php://input|php://filter|expect://|data://text/plain", re.I),
     'solutions': [
         'Never use user input directly in include/require statements.',
         'Whitelist allowed filenames only.',
         'Disable allow_url_include and allow_url_fopen in php.ini.',
         'Move sensitive configuration files outside the web root.',
     ]},
]


def analyze_log_content(raw_content: str):
    """Run threat rules against raw log text. Returns findings + stats."""
    raw_lines = [l for l in raw_content.split('\n') if l.strip()]
    rule_hits = {}
    findings  = []

    for line in raw_lines:
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        ip = ip_match.group(1) if ip_match else None
        for rule in THREAT_RULES:
            if rule['pattern'].search(line):
                rid = rule['id']
                if rid not in rule_hits:
                    rule_hits[rid] = {'rule_id': rid, 'rule_name': rule['name'],
                                      'severity': rule['severity'],
                                      'solutions': rule['solutions'],
                                      'matched_count': 0, 'ips': set(),
                                      'sample_lines': []}
                    findings.append(rule_hits[rid])
                rule_hits[rid]['matched_count'] += 1
                if ip:
                    rule_hits[rid]['ips'].add(ip)
                if len(rule_hits[rid]['sample_lines']) < 3:
                    rule_hits[rid]['sample_lines'].append(line[:200])

    # Convert sets to lists for JSON serialisation
    for f in findings:
        f['ips'] = list(f['ips'])

    critical_findings = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    other_findings    = len(findings) - critical_findings
    risk_score = min(100, critical_findings * 20 + other_findings * 8)
    risk_label = ('CRITICAL' if risk_score >= 80 else
                  'HIGH'     if risk_score >= 50 else
                  'MEDIUM'   if risk_score >= 25 else 'LOW')
    return findings, risk_score, risk_label


def parse_log_lines(lines):
    """Parse raw log lines into structured entries."""
    entries = []
    for i, line in enumerate(lines[:200]):   # cap at 200 rows per upload
        ip_m      = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        method_m  = re.search(r'\b(GET|POST|PUT|DELETE|PATCH)\b', line)
        status_m  = re.search(r'\b([2345]\d{2})\b', line)
        path_m    = re.search(r'(\/[^\s"]*)', line)

        ip     = ip_m.group(1)     if ip_m     else '127.0.0.1'
        method = method_m.group(1) if method_m else 'GET'
        status = int(status_m.group(1)) if status_m else 200
        path   = path_m.group(1)[:200] if path_m else '/unknown'

        is_sql   = bool(re.search(r"UNION|SELECT|DROP|INSERT|'--|OR 1=1", line, re.I))
        is_brute = bool(re.search(r'fail|invalid|denied|unauthorized', line, re.I))
        flag = 'CRITICAL' if (is_sql or is_brute) else ('SUSPICIOUS' if i % 7 == 0 else 'CLEAN')

        sc = (status // 100) * 100
        entries.append({
            'ip': ip, 'method': method, 'path': path,
            'status': status, 'status_class': f'{sc // 100}xx',
            'flag': flag, 'raw': line[:500],
        })
    return entries


def allowed_file(filename):
    return ('.' in filename and
            filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS'])


# ══════════════════════════════════════════════════════════════
#  ROUTES — AUTH
# ══════════════════════════════════════════════════════════════

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return err('Username and password required')

    user = User.query.filter_by(username=username, is_active=True).first()
    if not user or not user.check_password(password):
        return err('Invalid credentials', 401)

    user.last_login = datetime.utcnow()
    db.session.commit()

    access  = create_token(user.id, user.role)
    refresh = create_token(user.id, user.role, refresh=True)
    return ok({'access_token': access, 'refresh_token': refresh,
               'user': user.to_dict()})


@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    data = request.get_json(silent=True) or {}
    token = data.get('refresh_token', '')
    try:
        payload = decode_token(token)
    except pyjwt.ExpiredSignatureError:
        return err('Refresh token expired — please log in again', 401)
    except pyjwt.InvalidTokenError:
        return err('Invalid refresh token', 401)
    if payload.get('type') != 'refresh':
        return err('Not a refresh token', 401)
    user = db.session.get(User, payload['sub'])
    if not user or not user.is_active:
        return err('User not found', 401)
    new_access = create_token(user.id, user.role)
    return ok({'access_token': new_access})


@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def me():
    return ok(g.current_user.to_dict())


@app.route('/api/auth/change-password', methods=['POST'])
@jwt_required()
def change_password():
    data = request.get_json(silent=True) or {}
    old_pw = data.get('old_password', '')
    new_pw = data.get('new_password', '')
    if not old_pw or not new_pw:
        return err('old_password and new_password required')
    if not g.current_user.check_password(old_pw):
        return err('Current password incorrect', 403)
    if len(new_pw) < 8:
        return err('New password must be at least 8 characters')
    g.current_user.set_password(new_pw)
    db.session.commit()
    return ok(message='Password changed successfully')


# ══════════════════════════════════════════════════════════════
#  ROUTES — DASHBOARD
# ══════════════════════════════════════════════════════════════

@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def dashboard_stats():
    active_threats   = Alert.query.filter(Alert.type == 'critical',
                                          Alert.status.in_(['active','flagged','watchlist'])).count()
    alerts_today     = Alert.query.filter(Alert.created_at >= datetime.utcnow().date()).count()
    blocked_ips      = IPBlocklist.query.filter_by(status='BLOCKED').count()
    total_reports    = Report.query.count()
    critical_alerts  = Alert.query.filter_by(type='critical').count()
    warning_alerts   = Alert.query.filter_by(type='warning').count()
    info_alerts      = Alert.query.filter_by(type='info').count()
    return ok({
        'active_threats':  active_threats,
        'alerts_today':    alerts_today,
        'blocked_ips':     blocked_ips,
        'total_reports':   total_reports,
        'critical_alerts': critical_alerts,
        'warning_alerts':  warning_alerts,
        'info_alerts':     info_alerts,
    })


@app.route('/api/dashboard/live-logs', methods=['GET'])
@jwt_required()
def live_logs():
    limit = min(int(request.args.get('limit', 20)), 100)
    logs  = LiveLog.query.order_by(LiveLog.ts.desc()).limit(limit).all()
    return ok([l.to_dict() for l in logs])


# ══════════════════════════════════════════════════════════════
#  ROUTES — ALERTS
# ══════════════════════════════════════════════════════════════

@app.route('/api/alerts', methods=['GET'])
@jwt_required()
def get_alerts():
    q = Alert.query
    if t := request.args.get('type'):
        q = q.filter_by(type=t)
    if c := request.args.get('category'):
        q = q.filter_by(category=c)
    if s := request.args.get('status'):
        q = q.filter_by(status=s)
    page  = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 50)), 200)
    total = q.count()
    items = q.order_by(Alert.created_at.desc()).offset((page-1)*limit).limit(limit).all()
    return ok([a.to_dict() for a in items], total=total, page=page, limit=limit)


@app.route('/api/alerts/<string:alert_id>', methods=['GET'])
@jwt_required()
def get_alert(alert_id):
    alert = Alert.query.filter_by(alert_id=alert_id).first_or_404()
    return ok(alert.to_dict())


@app.route('/api/alerts/<string:alert_id>/resolve', methods=['POST'])
@jwt_required()
def resolve_alert(alert_id):
    alert = Alert.query.filter_by(alert_id=alert_id).first_or_404()
    alert.status      = 'resolved'
    alert.resolved_by = g.current_user.id
    alert.resolved_at = datetime.utcnow()
    db.session.commit()
    return ok(alert.to_dict(), message='Alert resolved')


@app.route('/api/alerts/<string:alert_id>/status', methods=['PATCH'])
@jwt_required()
def update_alert_status(alert_id):
    alert  = Alert.query.filter_by(alert_id=alert_id).first_or_404()
    data   = request.get_json(silent=True) or {}
    status = data.get('status')
    valid  = {'active','blocked','watchlist','mitigated','flagged','resolved'}
    if status not in valid:
        return err(f'status must be one of {valid}')
    alert.status = status
    db.session.commit()
    return ok(alert.to_dict())


@app.route('/api/alerts/stats/categories', methods=['GET'])
@jwt_required()
def alert_category_stats():
    from sqlalchemy import func
    rows = (db.session.query(Alert.category, Alert.type, func.count(Alert.id))
            .group_by(Alert.category, Alert.type).all())
    result = {}
    for cat, typ, cnt in rows:
        result.setdefault(cat, {'critical':0,'warning':0,'info':0,'total':0})
        result[cat][typ] += cnt
        result[cat]['total'] += cnt
    return ok(result)


# ══════════════════════════════════════════════════════════════
#  ROUTES — LOG UPLOAD & ANALYSIS
# ══════════════════════════════════════════════════════════════

@app.route('/api/logs/upload', methods=['POST'])
@jwt_required()
def upload_log():
    if 'file' not in request.files:
        return err('No file part in request')
    file = request.files['file']
    if file.filename == '':
        return err('No file selected')
    if not allowed_file(file.filename):
        return err('File type not allowed. Use: .log .txt .csv .json')

    filename  = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    file_size = os.path.getsize(file_path)

    # Read and parse
    try:
        with open(file_path, 'r', errors='replace') as fh:
            raw_content = fh.read()
    except Exception as e:
        return err(f'Could not read file: {e}')

    raw_lines = [l for l in raw_content.split('\n') if l.strip()]
    entries   = parse_log_lines(raw_lines)

    # Save LogFile record
    lf = LogFile(
        file_name   = filename,
        file_size   = file_size,
        file_path   = file_path,
        uploaded_by = g.current_user.id,
        total_lines = len(raw_lines),
        threat_count= sum(1 for e in entries if e['flag'] == 'CRITICAL'),
    )
    db.session.add(lf)
    db.session.flush()

    # Bulk-insert log entries
    for e in entries:
        le = LogEntry(
            log_file_id = lf.id,
            ip_address  = e['ip'],
            method      = e['method'],
            path        = e['path'],
            status_code = e['status'],
            flag        = e['flag'],
            raw_line    = e['raw'],
        )
        db.session.add(le)

    db.session.commit()
    return ok({
        'log_file_id': lf.id,
        'file_name':   filename,
        'total_lines': len(raw_lines),
        'entries':     len(entries),
        'threats':     lf.threat_count,
        'parsed':      entries[:50],     # return first 50 for preview
    }, status=201)


@app.route('/api/logs/<int:log_file_id>/analyze', methods=['POST'])
@jwt_required()
def analyze_log(log_file_id):
    lf = db.session.get(LogFile, log_file_id)
    if not lf:
        return err('Log file not found', 404)

    try:
        with open(lf.file_path, 'r', errors='replace') as fh:
            raw_content = fh.read()
    except Exception as e:
        return err(f'Cannot read stored file: {e}')

    findings, risk_score, risk_label = analyze_log_content(raw_content)

    all_ips    = list({e.ip_address for e in LogEntry.query.filter_by(log_file_id=lf.id).all() if e.ip_address})
    crit_count = LogEntry.query.filter_by(log_file_id=lf.id, flag='CRITICAL').count()
    susp_count = LogEntry.query.filter_by(log_file_id=lf.id, flag='SUSPICIOUS').count()
    clean_cnt  = LogEntry.query.filter_by(log_file_id=lf.id, flag='CLEAN').count()

    # Status code distribution
    from sqlalchemy import func
    sc_rows = (db.session.query(LogEntry.status_code, func.count(LogEntry.id))
               .filter_by(log_file_id=lf.id)
               .group_by(LogEntry.status_code).all())
    status_codes = {str(row[0]): row[1] for row in sc_rows}

    # Build report ID
    import hashlib, time
    report_id = 'RPT-' + hashlib.md5(f"{lf.id}{time.time()}".encode()).hexdigest()[:8].upper()

    # Save report
    report = Report(
        report_id        = report_id,
        file_name        = lf.file_name,
        uploaded_by      = g.current_user.id,
        total_lines      = lf.total_lines,
        total_parsed     = LogEntry.query.filter_by(log_file_id=lf.id).count(),
        critical_count   = crit_count,
        suspicious_count = susp_count,
        clean_count      = clean_cnt,
        unique_ips       = len(all_ips),
        risk_score       = risk_score,
        risk_label       = risk_label,
        findings_json    = findings,
        status_codes_json= status_codes,
    )
    db.session.add(report)
    db.session.flush()
    lf.report_id = report.id
    db.session.commit()

    return ok(report.to_dict(), status=201)


@app.route('/api/logs', methods=['GET'])
@jwt_required()
def list_logs():
    page  = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 20)), 100)
    q     = LogFile.query.order_by(LogFile.uploaded_at.desc())
    total = q.count()
    items = q.offset((page-1)*limit).limit(limit).all()
    return ok([l.to_dict() for l in items], total=total, page=page)


@app.route('/api/logs/<int:log_file_id>/entries', methods=['GET'])
@jwt_required()
def log_entries(log_file_id):
    flag  = request.args.get('flag')
    page  = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 50)), 500)
    q     = LogEntry.query.filter_by(log_file_id=log_file_id)
    if flag:
        q = q.filter_by(flag=flag)
    total = q.count()
    items = q.order_by(LogEntry.id).offset((page-1)*limit).limit(limit).all()
    return ok([e.to_dict() for e in items], total=total)


# ══════════════════════════════════════════════════════════════
#  ROUTES — REPORTS
# ══════════════════════════════════════════════════════════════

@app.route('/api/reports', methods=['GET'])
@jwt_required()
def list_reports():
    page  = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 20)), 100)
    q     = Report.query.order_by(Report.created_at.desc())
    total = q.count()
    items = q.offset((page-1)*limit).limit(limit).all()
    return ok([r.to_dict() for r in items], total=total, page=page)


@app.route('/api/reports/<string:report_id>', methods=['GET'])
@jwt_required()
def get_report(report_id):
    report = Report.query.filter_by(report_id=report_id).first_or_404()
    return ok(report.to_dict())


@app.route('/api/reports/<string:report_id>', methods=['DELETE'])
@jwt_required(roles=['admin'])
def delete_report(report_id):
    report = Report.query.filter_by(report_id=report_id).first_or_404()
    db.session.delete(report)
    db.session.commit()
    return ok(message=f'Report {report_id} deleted')


# ══════════════════════════════════════════════════════════════
#  ROUTES — IP BLOCKLIST
# ══════════════════════════════════════════════════════════════

@app.route('/api/network/ips', methods=['GET'])
@jwt_required()
def list_ips():
    status = request.args.get('status')
    q      = IPBlocklist.query
    if status:
        q = q.filter_by(status=status.upper())
    items = q.order_by(IPBlocklist.threat_level.desc()).all()
    return ok([ip.to_dict() for ip in items], total=len(items))


@app.route('/api/network/ips', methods=['POST'])
@jwt_required()
def add_ip():
    data = request.get_json(silent=True) or {}
    ip   = data.get('ip', '').strip()
    if not ip:
        return err('ip is required')
    # Basic IPv4 validation
    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
        return err('Invalid IPv4 address format')

    existing = IPBlocklist.query.filter_by(ip_address=ip).first()
    if existing:
        # Update status instead
        existing.status       = data.get('status', 'BLOCKED').upper()
        existing.reason       = data.get('reason', existing.reason)
        existing.threat_level = data.get('threat_level', existing.threat_level)
        db.session.commit()
        return ok(existing.to_dict(), message='IP record updated')

    entry = IPBlocklist(
        ip_address   = ip,
        country      = data.get('country', 'Unknown'),
        threat_level = int(data.get('threat_level', 80)),
        attempts     = int(data.get('attempts', 0)),
        status       = data.get('status', 'BLOCKED').upper(),
        reason       = data.get('reason', 'Manually blocked'),
        added_by     = g.current_user.id,
        notes        = data.get('notes', ''),
    )
    db.session.add(entry)
    db.session.commit()
    return ok(entry.to_dict(), status=201, message=f'IP {ip} added to blocklist')


@app.route('/api/network/ips/<string:ip_addr>/unblock', methods=['POST'])
@jwt_required()
def unblock_ip(ip_addr):
    entry = IPBlocklist.query.filter_by(ip_address=ip_addr).first_or_404()
    entry.status = 'ALLOWED'
    db.session.commit()
    return ok(entry.to_dict(), message=f'{ip_addr} removed from blocklist')


@app.route('/api/network/ips/<string:ip_addr>', methods=['DELETE'])
@jwt_required(roles=['admin'])
def delete_ip(ip_addr):
    entry = IPBlocklist.query.filter_by(ip_address=ip_addr).first_or_404()
    db.session.delete(entry)
    db.session.commit()
    return ok(message=f'{ip_addr} deleted from blocklist')


@app.route('/api/network/ips/<string:ip_addr>/status', methods=['PATCH'])
@jwt_required()
def update_ip_status(ip_addr):
    entry  = IPBlocklist.query.filter_by(ip_address=ip_addr).first_or_404()
    data   = request.get_json(silent=True) or {}
    status = data.get('status', '').upper()
    if status not in {'BLOCKED','WATCHLIST','ALLOWED'}:
        return err('status must be BLOCKED, WATCHLIST, or ALLOWED')
    entry.status = status
    db.session.commit()
    return ok(entry.to_dict())


# ══════════════════════════════════════════════════════════════
#  ROUTES — USERS (admin only)
# ══════════════════════════════════════════════════════════════

@app.route('/api/users', methods=['GET'])
@jwt_required(roles=['admin'])
def list_users():
    users = User.query.filter_by(is_active=True).all()
    return ok([u.to_dict() for u in users])


@app.route('/api/users', methods=['POST'])
@jwt_required(roles=['admin'])
def create_user():
    data     = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role     = data.get('role', 'analyst')
    if not username or not password:
        return err('username and password required')
    if User.query.filter_by(username=username).first():
        return err('Username already exists')
    if role not in {'admin','analyst','viewer'}:
        return err('role must be admin, analyst, or viewer')
    u = User(username=username, role=role)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    return ok(u.to_dict(), status=201)


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@jwt_required(roles=['admin'])
def deactivate_user(user_id):
    if user_id == g.current_user.id:
        return err('Cannot deactivate your own account')
    user = db.session.get(User, user_id)
    if not user:
        return err('User not found', 404)
    user.is_active = False
    db.session.commit()
    return ok(message=f'User {user.username} deactivated')


# ══════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════════

@app.route('/api/health', methods=['GET'])
def health():
    try:
        db.session.execute(db.text('SELECT 1'))
        db_ok = True
    except Exception:
        db_ok = False
    return jsonify({'status': 'ok' if db_ok else 'degraded',
                    'database': 'connected' if db_ok else 'error',
                    'version': '2.0.0'})


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print(f'[CyberWatch] Connecting to MySQL at {Config.MYSQL_HOST}:{Config.MYSQL_PORT} '
          f'as {Config.MYSQL_USER}@{Config.MYSQL_DB}')
    try:
        with app.app_context():
            db.create_all()
            # Create default admin if missing
            if not User.query.filter_by(username='admin').first():
                admin = User(username='admin', role='admin')
                admin.set_password('cyber123')
                db.session.add(admin)
                db.session.commit()
                print('[CyberWatch] Default admin user created (admin / cyber123)')
            print('[CyberWatch] MySQL connected successfully!')
    except Exception as e:
        print('\n' + '='*60)
        print('[CyberWatch] MYSQL CONNECTION FAILED!')
        print(f'Error: {e}')
        print()
        print('Fix: Open .env file and check MYSQL_PASSWORD is correct.')
        print(f'     Current password set: {Config.MYSQL_PASSWORD[:2]}***')
        print('     Then restart: python app.py')
        print('='*60 + '\n')
        raise SystemExit(1)
    app.run(host='0.0.0.0', port=5000, debug=True)
