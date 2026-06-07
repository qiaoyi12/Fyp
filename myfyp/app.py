from flask import Flask, render_template, request, session, redirect, url_for
from functools import wraps

import os

app = Flask(__name__,
    template_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend'),
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend'),
    static_url_path='/static'
)
app.secret_key = 'ids_secret_key_change_in_production'

# ─── This was the original route — kept intact ────────────────────────────────
@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ─── Auth Decorators (FED) ────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# ─── Auth Routes (FED) ────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role     = request.form.get('role')

        # NOTE TO TEAM: Replace this with real DB validation
        # when BED peer's authentication is ready
        valid_users = {
            'analyst': {'password': 'analyst123', 'role': 'analyst'},
            'admin':   {'password': 'admin123',   'role': 'admin'},
        }
        user = valid_users.get(username)
        if user and user['password'] == password and user['role'] == role:
            session['user'] = username
            session['role'] = role
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username, password or role.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ─── Page Routes (FED) ────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    # NOTE TO TEAM: Replace mock data with real API calls
    # when BED/AI peers' endpoints are ready
    metrics = {
        'logs_processed': '48,291',
        'high_count': 7,
        'medium_count': 23,
        'low_count': 142,
        'model_accuracy': '96.4%',
        'response_time': '142ms',
        'uptime': '99.8%'
    }
    alerts = get_alerts_data()
    high_alerts = [a for a in alerts if a['severity'] == 'high']
    threat_distribution = [
        {'type': 'SQL Injection', 'pct': 31, 'colour': '#E74C3C'},
        {'type': 'Brute Force',   'pct': 24, 'colour': '#F39C12'},
        {'type': 'Port Scan',     'pct': 20, 'colour': '#3D8EFF'},
        {'type': 'Malware',       'pct': 15, 'colour': '#A07EFF'},
        {'type': 'Other',         'pct': 10, 'colour': '#1DB954'},
    ]
    return render_template('dashboard.html',
        metrics=metrics,
        high_alerts=high_alerts,
        threat_distribution=threat_distribution,
        user=session['user'],
        role=session['role']
    )

@app.route('/alerts')
@login_required
def alert_feed():
    alerts = get_alerts_data()
    severity = request.args.get('severity', 'all')
    if severity != 'all':
        alerts = [a for a in alerts if a['severity'] == severity]
    return render_template('alert_feed.html',
        alerts=alerts,
        severity=severity,
        user=session['user'],
        role=session['role']
    )

@app.route('/alerts/<int:alert_id>')
@login_required
def threat_detail(alert_id):
    alert = get_alert_detail(alert_id)
    return render_template('threat_detail.html',
        alert=alert,
        user=session['user'],
        role=session['role']
    )

@app.route('/logs')
@login_required
def log_viewer():
    logs = get_logs_data()
    search = request.args.get('search', '')
    filter_type = request.args.get('filter', 'all')
    if search:
        logs = [l for l in logs if search.lower() in l['source'].lower()
                or search.lower() in l['type'].lower()]
    if filter_type == 'flagged':
        logs = [l for l in logs if l['flagged']]
    elif filter_type == 'normal':
        logs = [l for l in logs if not l['flagged']]
    return render_template('log_viewer.html',
        logs=logs,
        search=search,
        filter_type=filter_type,
        user=session['user'],
        role=session['role']
    )

@app.route('/upload', methods=['GET', 'POST'])
@admin_required
def upload():
    message = None
    error = None
    if request.method == 'POST':
        if 'file' not in request.files:
            error = 'No file selected.'
        else:
            file = request.files['file']
            allowed = {'csv', 'log', 'json', 'pcap'}
            ext = file.filename.rsplit('.', 1)[-1].lower()
            if ext not in allowed:
                error = f'Unsupported format: .{ext}. Allowed: .csv .log .json .pcap'
            else:
                # NOTE TO TEAM: Forward file to BED peer for processing
                message = f'{file.filename} uploaded and queued for processing.'
    history = [
        {'name': 'network_logs_apr27.csv', 'status': 'success', 'detail': 'Processed · 12,440 entries'},
        {'name': 'auth_logs_apr26.log',    'status': 'success', 'detail': 'Processed · 8,112 entries'},
        {'name': 'firewall_dump.exe',       'status': 'error',   'detail': 'Failed · Unsupported format'},
    ]
    return render_template('upload.html',
        message=message,
        error=error,
        history=history,
        user=session['user'],
        role=session['role']
    )

@app.route('/metrics')
@admin_required
def model_metrics():
    # NOTE TO TEAM: Replace with real model metrics from AI peer
    metrics = {
        'accuracy': 96.4,
        'precision': 94.1,
        'recall': 91.8,
        'f1_score': 92.9,
        'weekly': [91, 93, 94, 92, 95, 96, 96],
        'days': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        'confusion': {
            'tp': 4821, 'fp': 287,
            'fn': 421,  'tn': 43291
        }
    }
    return render_template('model_metrics.html',
        metrics=metrics,
        user=session['user'],
        role=session['role']
    )

# ─── Mock Data (FED — replace with BED API calls when ready) ──────────────────
def get_alerts_data():
    return [
        {'id': 1, 'severity': 'high',   'description': 'SQL Injection Attempt — prod-db-01',  'source': '192.168.4.207', 'time': '14:17'},
        {'id': 2, 'severity': 'high',   'description': 'SSH Brute Force Attack Detected',      'source': '10.0.4.88',     'time': '13:52'},
        {'id': 3, 'severity': 'high',   'description': 'Lateral Port Scan — /24 Subnet',       'source': '172.16.0.44',   'time': '13:41'},
        {'id': 4, 'severity': 'medium', 'description': 'Unusual Outbound Data Transfer',        'source': '10.0.1.33',     'time': '13:20'},
        {'id': 5, 'severity': 'medium', 'description': 'Repeated Authentication Failures ×47', 'source': '192.168.1.12',  'time': '12:58'},
        {'id': 6, 'severity': 'medium', 'description': 'Privilege Escalation — sudo abuse',    'source': '10.0.2.7',      'time': '12:30'},
        {'id': 7, 'severity': 'low',    'description': 'Deprecated TLS 1.0 Handshake',         'source': '10.0.5.2',      'time': '11:45'},
        {'id': 8, 'severity': 'low',    'description': 'DNS Lookup Anomaly — unusual pattern', 'source': '192.168.3.9',   'time': '11:12'},
    ]

def get_alert_detail(alert_id):
    return {
        'id': alert_id,
        'severity': 'high',
        'description': 'SQL Injection Attempt Detected',
        'source': '192.168.4.207',
        'destination': 'prod-db-01 / Port 3306',
        'timestamp': '2026-04-28 14:17:03 SGT',
        'type': 'SQL Injection · SQLI-07',
        'confidence': 94,
        'raw_log': '[2026-04-28 14:17:03] WARN auth-service: Unusual query pattern detected\nPOST /api/users/login HTTP/1.1\nPayload: username=\' OR \'1\'=\'1\'; DROP TABLE users;--\nResponse: 403 Forbidden · WAF rule SQLI-07\nSession: 0xFA2C19 · Duration: 0.34s',
        'action': 'Block source IP 192.168.4.207 at firewall level immediately. Escalate to Tier 2 analyst for forensic review of session 0xFA2C19. Audit all requests from this host in the past 24 hours.'
    }

def get_logs_data():
    return [
        {'timestamp': '14:17:03', 'source': '192.168.4.207', 'destination': '10.0.1.15:3306', 'type': 'SQL Injection',     'protocol': 'TCP/HTTP', 'severity': 'high',   'flagged': True},
        {'timestamp': '14:15:22', 'source': '10.0.1.44',     'destination': '10.0.1.1:443',   'type': 'HTTPS Auth',        'protocol': 'TCP/TLS',  'severity': 'normal', 'flagged': False},
        {'timestamp': '14:12:08', 'source': '10.0.4.88',     'destination': '10.0.1.22:22',   'type': 'SSH Brute Force',   'protocol': 'TCP/SSH',  'severity': 'high',   'flagged': True},
        {'timestamp': '14:09:55', 'source': '10.0.2.3',      'destination': '8.8.8.8:53',     'type': 'DNS Query',         'protocol': 'UDP/DNS',  'severity': 'normal', 'flagged': False},
        {'timestamp': '14:07:31', 'source': '172.16.0.44',   'destination': '10.0.0.0/24',    'type': 'Port Scan',         'protocol': 'TCP/ICMP', 'severity': 'high',   'flagged': True},
        {'timestamp': '14:05:14', 'source': '10.0.1.10',     'destination': '10.0.1.15:80',   'type': 'HTTP GET',          'protocol': 'TCP/HTTP', 'severity': 'normal', 'flagged': False},
        {'timestamp': '14:03:02', 'source': '10.0.1.33',     'destination': '104.21.0.0:443', 'type': 'Unusual Egress',    'protocol': 'TCP/TLS',  'severity': 'medium', 'flagged': True},
        {'timestamp': '14:00:47', 'source': '10.0.5.2',      'destination': '10.0.1.15:443',  'type': 'TLS 1.0 Handshake', 'protocol': 'TCP/TLS',  'severity': 'low',    'flagged': True},
    ]

if __name__ == '__main__':
    app.run(debug=True)