# ─── Analyst Agent Routes (FED) ───────────────────────────────────────────────
# Flask blueprint for the Analyst Agent feature.
# Connects the agenticAI/analyst_agent.py logic to the web interface.
# Author: FED role
# NOTE TO TEAM: Do not modify this file — it is owned by the FED role.

from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
from agenticAI.analyst_agent import generate_incident_report

analyst_bp = Blueprint('analyst', __name__)

# ─── Auth decorator ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session and 'user' not in session:
            return redirect(url_for('pages.login'))
        return f(*args, **kwargs)
    return decorated

# ─── Report page ──────────────────────────────────────────────────────────────
@analyst_bp.route('/report/<int:alert_id>')
@login_required
def report(alert_id):
    # NOTE TO TEAM: Replace get_mock_alert() with real DB query when ready
    alert = get_mock_alert(alert_id)
    all_alerts = get_mock_alerts()

    related_alerts = [
        a for a in all_alerts
        if a['source'] == alert['source'] and a['id'] != alert_id
    ]

    return render_template('report.html',
        alert=alert,
        related_alerts=related_alerts,
        user=session.get('user', session.get('username', 'Analyst')),
        role=session.get('role', 'analyst')
    )

# ─── Generate report endpoint ─────────────────────────────────────────────────
@analyst_bp.route('/report/<int:alert_id>/generate', methods=['POST'])
@login_required
def generate_report(alert_id):
    try:
        # NOTE TO TEAM: Replace with real DB query when BED is ready
        alert      = get_mock_alert(alert_id)
        all_alerts = get_mock_alerts()

        report_content, related_alerts = generate_incident_report(alert, all_alerts)
        return jsonify({'report': report_content, 'error': None})

    except Exception as e:
        return jsonify({'report': None, 'error': str(e)}), 500

# ─── Submit report endpoint ───────────────────────────────────────────────────
@analyst_bp.route('/report/<int:alert_id>/submit', methods=['POST'])
@login_required
def submit_report(alert_id):
    data           = request.get_json()
    report_content = data.get('report', '')

    report = IncidentReport(
        alert_id=alert_id,
        analyst_id=session['user_id'],
        content=report_content,
    )
    db.session.add(report)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'Report for Alert #{alert_id} submitted to admin successfully.'
    })
# ─── Mock data (FED placeholder — replace with BED DB queries) ────────────────
def get_mock_alerts():
    return [
        {'id': 1,  'severity': 'high',   'description': 'SQL Injection Attempt — prod-db-01',  'source': '192.168.4.207', 'time': '14:17', 'type': 'SQL Injection',        'date': '2026-04-28'},
        {'id': 2,  'severity': 'high',   'description': 'SSH Brute Force Attack Detected',      'source': '10.0.4.88',     'time': '13:52', 'type': 'Brute Force',          'date': '2026-04-28'},
        {'id': 3,  'severity': 'high',   'description': 'Lateral Port Scan — /24 Subnet',       'source': '172.16.0.44',   'time': '13:41', 'type': 'Port Scan',            'date': '2026-04-28'},
        {'id': 4,  'severity': 'medium', 'description': 'Unusual Outbound Data Transfer',        'source': '10.0.1.33',     'time': '13:20', 'type': 'Data Exfiltration',    'date': '2026-04-28'},
        {'id': 5,  'severity': 'medium', 'description': 'Repeated Authentication Failures ×47', 'source': '192.168.1.12',  'time': '12:58', 'type': 'Brute Force',          'date': '2026-04-28'},
        {'id': 6,  'severity': 'medium', 'description': 'Privilege Escalation — sudo abuse',    'source': '10.0.2.7',      'time': '12:30', 'type': 'Privilege Escalation', 'date': '2026-04-28'},
        {'id': 7,  'severity': 'low',    'description': 'Deprecated TLS 1.0 Handshake',         'source': '10.0.5.2',      'time': '11:45', 'type': 'Misconfiguration',     'date': '2026-04-27'},
        {'id': 8,  'severity': 'low',    'description': 'DNS Lookup Anomaly — unusual pattern', 'source': '192.168.3.9',   'time': '11:12', 'type': 'DNS Anomaly',          'date': '2026-04-27'},
        {'id': 9,  'severity': 'high',   'description': 'Malware Beacon Detected',               'source': '10.0.3.15',     'time': '10:44', 'type': 'Malware',              'date': '2026-04-27'},
        {'id': 10, 'severity': 'medium', 'description': 'Suspicious Login — unusual location',  'source': '10.0.1.99',     'time': '10:20', 'type': 'Brute Force',          'date': '2026-04-26'},
        {'id': 11, 'severity': 'high',   'description': 'Ransomware Activity Detected',          'source': '10.0.2.44',     'time': '09:55', 'type': 'Malware',              'date': '2026-04-26'},
        {'id': 12, 'severity': 'low',    'description': 'Unencrypted HTTP Traffic',              'source': '10.0.4.12',     'time': '09:30', 'type': 'Misconfiguration',     'date': '2026-04-25'},
    ]

def get_mock_alert(alert_id):
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