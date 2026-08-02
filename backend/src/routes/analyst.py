# ─── Analyst Agent Routes (FED) ───────────────────────────────────────────────
# Flask blueprint for the Analyst Agent feature.
# Uses real Alert and AlertDetail data from the database.
# Author: FED role
# NOTE TO TEAM: Do not modify this file — it is owned by the FED role.

from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
from agenticAI.analyst_agent import generate_incident_report
from backend.src.database.db import db
from backend.src.database.models import Alert, AlertDetail, IncidentReport, User

analyst_bp = Blueprint('analyst', __name__)

# ─── Auth decorator ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('pages.login'))
        return f(*args, **kwargs)
    return decorated

# ─── Helper — convert real Alert DB object to dict for the agent ───────────────
def alert_to_dict(alert):
    # Handle both real Alert DB objects and plain dicts
    if isinstance(alert, dict):
        return alert

    return {
        'id':          alert.id,
        'description': f"{alert.prediction} detected on port {alert.dest_port}",
        'severity':    alert.severity,
        'source':      alert.source_ip or 'Unknown',
        'destination': f"{alert.dest_ip}:{alert.dest_port}" if alert.dest_ip else f"Port {alert.dest_port}",
        'timestamp':   alert.created_at.strftime('%Y-%m-%d %H:%M:%S SGT'),
        'type':        alert.prediction,
        'confidence':  round(float(alert.confidence), 1) if alert.confidence else 0,
        'time':        alert.created_at.strftime('%H:%M'),
        'date':        alert.created_at.strftime('%Y-%m-%d'),
        'raw_log': (
            f"[{alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}] "
            f"Alert ID: {alert.id} | "
            f"Prediction: {alert.prediction} | "
            f"Severity: {alert.severity.upper()} | "
            f"Source IP: {alert.source_ip or 'Unknown'} | "
            f"Dest IP: {alert.dest_ip or 'Unknown'} | "
            f"Dest Port: {alert.dest_port} | "
            f"Confidence: {round(float(alert.confidence), 1) if alert.confidence else 0}% | "
            f"Flow Packets/s: {alert.flow_pkts_s} | "
            f"XGB Vote: {alert.xgb_vote} | "
            f"RF Vote: {alert.rf_vote} | "
            f"Tag: {alert.tag}"
        ),
        'action': (
            f"Investigate {alert.prediction} from {alert.source_ip or 'Unknown'}. "
            f"Check port {alert.dest_port} activity and review related alerts from this IP."
        )
    }

# ─── Report page ──────────────────────────────────────────────────────────────
@analyst_bp.route('/report/<int:alert_id>')
@login_required
def report(alert_id):
    # ── Get real alert from DB ─────────────────────────────────────────────────
    alert = Alert.query.get_or_404(alert_id)

    # ── Cross-reference — find other alerts from same source IP ───────────────
    related_alerts = []
    if alert.source_ip:
        related_alerts = (
            Alert.query
            .filter(Alert.source_ip == alert.source_ip, Alert.id != alert_id)
            .order_by(Alert.created_at.desc())
            .limit(5)
            .all()
        )

    alert_dict   = alert_to_dict(alert)
    related_list = [alert_to_dict(a) for a in related_alerts]

    return render_template('report.html',
        alert=alert_dict,
        related_alerts=related_list,
        user=session.get('user', 'Analyst'),
        role=session.get('role', 'analyst')
    )

# ─── Generate report endpoint ─────────────────────────────────────────────────
@analyst_bp.route('/report/<int:alert_id>/generate', methods=['POST'])
@login_required
def generate_report(alert_id):
    try:
        # ── Get real alert from DB ─────────────────────────────────────────────
        alert = Alert.query.get_or_404(alert_id)

        # ── Cross-reference — find other alerts from same source IP ───────────
        related_alerts = []
        if alert.source_ip:
            related_alerts = (
                Alert.query
                .filter(Alert.source_ip == alert.source_ip, Alert.id != alert_id)
                .order_by(Alert.created_at.desc())
                .limit(5)
                .all()
            )

        alert_dict   = alert_to_dict(alert)
        related_list = [alert_to_dict(a) for a in related_alerts]

        # ── Generate report using OpenAI ───────────────────────────────────────
        report_content, _ = generate_incident_report(alert_dict, related_list)
        return jsonify({'report': report_content, 'error': None})

    except Exception as e:
        import traceback
        print('=== ANALYST AGENT ERROR ===')
        print(traceback.format_exc())
        print('===========================')
        return jsonify({'report': None, 'error': str(e)}), 500

# ─── Submit report — saves to IncidentReport table ────────────────────────────
@analyst_bp.route('/report/<int:alert_id>/submit', methods=['POST'])
@login_required
def submit_report(alert_id):
    try:
        data           = request.get_json()
        report_content = data.get('report', '')

        if not report_content.strip():
            return jsonify({'success': False, 'error': 'Report content is empty.'}), 400

        # ── Save to IncidentReport table ───────────────────────────────────────
        new_report = IncidentReport(
            alert_id   = alert_id,
            analyst_id = session['user_id'],
            content    = report_content
        )
        db.session.add(new_report)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Report for Alert #{alert_id} saved and submitted to admin successfully.'
        })

    except Exception as e:
        db.session.rollback()
        import traceback
        print('=== SUBMIT REPORT ERROR ===')
        print(traceback.format_exc())
        print('===========================')
        return jsonify({'success': False, 'error': str(e)}), 500