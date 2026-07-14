# Handles uploaded data, analysis, alerts, logs, and report summary.
import json
import time
from datetime import timedelta, datetime
from backend.src.database.models import Alert, AlertDetail, AnalysisResult, UploadedFile, IPBlacklist, AnalysisAssignment, User
from backend.src.database.db import db
from backend.src.ml.preprocess import preprocess_csv
from backend.src.ml.predict import predict, get_summary, estimate_model_metrics

SEVERITY_RANK = {'normal': 0, 'medium': 1, 'high': 2}


# ── ASSIGNMENT HELPER ─────────────────────────────────────────
def _get_assigned_analysis_ids(user_id, role):
    """Returns list of analysis_ids assigned to this user, based on role."""
    if role == 'analyst':
        assignments = AnalysisAssignment.query.filter_by(analyst_id=user_id).all()
    elif role == 'manager':
        assignments = AnalysisAssignment.query.filter_by(manager_id=user_id).all()
    else:
        return []
    return [a.analysis_id for a in assignments]


def has_no_assignments(user_id, role):
    if role not in ('analyst', 'manager'):
        return False
    return len(_get_assigned_analysis_ids(user_id, role)) == 0


def _alert_query(user_id, role):
    if role in ('analyst', 'manager'):
        analysis_ids = _get_assigned_analysis_ids(user_id, role)
        if not analysis_ids:
            return Alert.query.filter_by(id=None)
        return Alert.query.filter(Alert.analysis_id.in_(analysis_ids))
    return Alert.query.filter_by(user_id=user_id)


def _analysis_query(user_id, role):
    if role in ('analyst', 'manager'):
        analysis_ids = _get_assigned_analysis_ids(user_id, role)
        if not analysis_ids:
            return AnalysisResult.query.filter_by(id=None)
        return AnalysisResult.query.filter(AnalysisResult.id.in_(analysis_ids))
    return AnalysisResult.query.filter_by(user_id=user_id)


# ── DASHBOARD ─────────────────────────────────────────────────
def get_dashboard_data(user_id, role, attack_type='all'):
    query = _alert_query(user_id, role)
    if attack_type == 'all':
        query = query.filter_by(severity='high')
    else:
        query = query.filter_by(prediction=attack_type)

    high_alerts = query.order_by(Alert.created_at.desc()).limit(3).all()
    high_alerts = [a.to_dict() for a in high_alerts]

    latest = _analysis_query(user_id, role)\
        .order_by(AnalysisResult.analysed_at.desc()).first()

    if not latest:
        return high_alerts, [], _empty_metrics()

    threat_distribution = [
        {'type': 'BENIGN',      'pct': round(latest.benign      / latest.total_rows * 100, 1) if latest.total_rows else 0, 'count': latest.benign,      'colour': '#1DB954'},
        {'type': 'Web Attack',  'pct': round(latest.web_attack  / latest.total_rows * 100, 1) if latest.total_rows else 0, 'count': latest.web_attack,  'colour': '#E74C3C'},
        {'type': 'Bot/Patator', 'pct': round(latest.bot         / latest.total_rows * 100, 1) if latest.total_rows else 0, 'count': latest.bot,         'colour': '#FF6B6B'},
        {'type': 'DDoS',        'pct': round(latest.ddos        / latest.total_rows * 100, 1) if latest.total_rows else 0, 'count': latest.ddos,        'colour': '#3D8EFF'},
        {'type': 'DoS',         'pct': round(latest.dos         / latest.total_rows * 100, 1) if latest.total_rows else 0, 'count': latest.dos,         'colour': '#F39C12'},
        {'type': 'Rare/Others', 'pct': round(latest.rare        / latest.total_rows * 100, 1) if latest.total_rows else 0, 'count': latest.rare,        'colour': '#FFD93D'},
        {'type': 'PortScan',    'pct': round(latest.portscan    / latest.total_rows * 100, 1) if latest.total_rows else 0, 'count': latest.portscan,    'colour': '#A07EFF'},
    ]
    metrics = {
        'logs_processed': f'{latest.total_rows:,}',
        'high_count':     latest.high_count,
        'medium_count':   latest.medium_count,
        'low_count':      latest.normal_count,
        'model_accuracy': 'N/A',
        'response_time':  'N/A',
        'uptime':         '99.8%',
        'total_threat_types': sum(1 for item in threat_distribution if item['pct'] > 0),
    }
    return high_alerts, threat_distribution, metrics


def _empty_metrics():
    return {
        'logs_processed': '0', 'high_count': 0, 'medium_count': 0, 'low_count': 0,
        'model_accuracy': 'N/A', 'response_time': 'N/A', 'uptime': '99.8%',
        'total_threat_types': 0,
    }


# ── ANALYSIS ──────────────────────────────────────────────────
def _estimate_model_metrics(results):
    return estimate_model_metrics(results)


def _resolve_uploads(file_ids, user_id):
    if isinstance(file_ids, (int, str)):
        file_ids = [file_ids]
    elif file_ids is None:
        file_ids = []
    else:
        file_ids = [item for item in file_ids if item is not None]

    normalized_ids = []
    for raw_id in file_ids:
        try:
            normalized_ids.append(int(raw_id))
        except (TypeError, ValueError):
            continue

    if not normalized_ids:
        return None

    uploads = UploadedFile.query.filter(
        UploadedFile.user_id == user_id,
        UploadedFile.id.in_(normalized_ids)
    ).order_by(UploadedFile.uploaded_at.asc()).all()

    if not uploads or len(uploads) != len(set(normalized_ids)):
        return None

    return uploads

def run_analysis(file_ids, user_id):
    uploads = _resolve_uploads(file_ids, user_id)
    if not uploads:
        return None, 'File not found.', None

    start_time = time.time()

    processed_files = []
    combined_results = []
    global_row = 0

    for upload in uploads:
        X, error = preprocess_csv(upload.filepath)
        if error:
            return None, error, None

        results = predict(X)
        for result in results:
            enriched = dict(result)
            enriched['source_upload_id'] = upload.id
            enriched['source_row'] = int(result['row'])
            enriched['row'] = global_row
            combined_results.append(enriched)
            global_row += 1

        processed_files.append((upload, X))

    metrics = _estimate_model_metrics(combined_results)
    elapsed_seconds = round(time.time() - start_time, 2)
    metrics['response_time_seconds'] = elapsed_seconds
    summary = get_summary(combined_results)
    by_label, by_sev = summary['by_label'], summary['by_severity']

    record = AnalysisResult(
        file_id=uploads[0].id, user_id=user_id, total_rows=len(combined_results),
        benign=by_label['BENIGN'], web_attack=by_label['Web Attack'],
        dos=by_label['DoS'], ddos=by_label['DDoS'], portscan=by_label['PortScan'],
        bot=by_label['Bot/Patator'], rare=by_label['Rare/Others'],
        high_count=by_sev['high'], medium_count=by_sev['medium'], normal_count=by_sev['normal'],
        file_ids=json.dumps([u.id for u in uploads]),
    )
    db.session.add(record)
    db.session.commit()

    # Group ALL predictions by type, including BENIGN
    by_type = {}
    for r in combined_results:
        if r['prediction'] not in by_type:
            by_type[r['prediction']] = []
        by_type[r['prediction']].append(r)

    # IP stats — across all rows (now includes BENIGN too)
    ip_counts = {}
    for r in [row for rows in by_type.values() for row in rows]:
        row_idx = r['row']
        source_ip = f'10.0.{(row_idx // 254) % 255}.{(row_idx % 254) + 1}'
        if source_ip not in ip_counts:
            ip_counts[source_ip] = {'ip': source_ip, 'count': 0, 'types': {}, 'max_severity': 'normal'}
        entry = ip_counts[source_ip]
        entry['count'] += 1
        entry['types'][r['prediction']] = entry['types'].get(r['prediction'], 0) + 1
        if SEVERITY_RANK.get(r['severity'], 0) > SEVERITY_RANK.get(entry['max_severity'], 0):
            entry['max_severity'] = r['severity']

    record.ip_stats = json.dumps(list(ip_counts.values()))
    db.session.commit()

    TICKETS_PER_TYPE_MAX = 80  # cap per type, including BENIGN

    selected = []
    for label, rows in by_type.items():
        # ascending confidence — least confident (most uncertain) predictions first,
        # since those need analyst review most
        selected.extend(sorted(rows, key=lambda x: x['confidence'])[:TICKETS_PER_TYPE_MAX])

    frame_lookup = {upload.id: X for upload, X in processed_files}
    for r in selected:
        row_data = frame_lookup[r['source_upload_id']].iloc[r['source_row']]
        row_idx = r['row']
        source_ip = f'10.0.{(row_idx // 254) % 255}.{(row_idx % 254) + 1}'

        severity = 'normal' if r['prediction'] == 'BENIGN' else r['severity']

        alert = Alert(
            analysis_id=record.id,
            user_id=user_id,
            row_index=row_idx,
            prediction=r['prediction'],
            severity=severity,
            confidence=r['confidence'],
            xgb_vote=r['xgb_vote'],
            rf_vote=r['rf_vote'],
            dest_port=int(row_data['Destination Port']),
            flow_duration=round(float(row_data['Flow Duration']), 2),
            flow_pkts_s=round(float(row_data['Flow Packets/s']), 2),
            source_ip=source_ip,
        )
        db.session.add(alert)
        db.session.flush()  # generates alert.id

        detail = AlertDetail(
            alert_id=alert.id,
            flow_duration=round(float(row_data['Flow Duration']), 2),
            flow_bytes_s=round(float(row_data['Flow Bytes/s']), 2),
            flow_packets_s=round(float(row_data['Flow Packets/s']), 2),
            total_fwd_packets=int(row_data['Total Fwd Packets']),
            total_backward_packets=int(row_data['Total Backward Packets']),
            packet_length_mean=round(float(row_data['Packet Length Mean']), 2),
            average_packet_size=round(float(row_data['Average Packet Size']), 2),
            syn_flag_count=int(row_data['SYN Flag Count']),
            ack_flag_count=int(row_data['ACK Flag Count']),
            psh_flag_count=int(row_data['PSH Flag Count']),
            init_win_bytes_forward=int(row_data['Init_Win_bytes_forward']),
            init_win_bytes_backward=int(row_data['Init_Win_bytes_backward']),
        )
        db.session.add(detail)

    db.session.commit()  # single commit for the whole batch

    return record, None, metrics


# ── ALERTS ────────────────────────────────────────────────────
def get_alert_feed(user_id, role, severity, attack_type):
    query = _alert_query(user_id, role).order_by(Alert.created_at.desc())
    if severity != 'all':
        query = query.filter_by(severity=severity)
    if attack_type != 'all':
        query = query.filter_by(prediction=attack_type)
    return [a.to_dict() for a in query.limit(100).all()]

def get_alert_detail(user_id, role, alert_id):
    alert = _alert_query(user_id, role).filter_by(id=alert_id).first()

    if not alert:
        return None

    return {
        "alert": alert,
        "detail": alert.detail
    }

def update_alert_tag(alert_id, tag):
    alert = Alert.query.get(alert_id)

    if alert:
        alert.tag = tag
        db.session.commit()

def update_alert_remarks(alert_id, remarks):
    alert = Alert.query.get(alert_id)
    if alert:
        alert.remarks = remarks
        db.session.commit()


# ── LOGS ──────────────────────────────────────────────────────
def get_logs(user_id, role, filter_type):
    query = _alert_query(user_id, role)
    if filter_type == 'flagged':
        query = query.filter(Alert.severity.in_(['high', 'medium']))
    elif filter_type == 'normal':
        query = query.filter_by(severity='normal')

    total = query.count()
    alerts = query.order_by(Alert.created_at.desc()).limit(500).all()

    logs = [{
        'timestamp':   a.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'source':      a.source_ip or '—',
        'destination': f'192.168.1.1:{a.dest_port}' if a.dest_port else '—',
        'type':        a.prediction,
        'protocol':    'TCP',
        'severity':    a.severity,
        'flagged':     a.severity in ('high', 'medium'),
    } for a in alerts]

    return logs, total


# ── UPLOAD HISTORY ────────────────────────────────────────────
def get_upload_history(user_id, limit=10):
    uploads = UploadedFile.query.filter_by(user_id=user_id) \
        .order_by(UploadedFile.uploaded_at.desc()).limit(limit).all()
    return [{
        'id': u.id, 'name': u.filename,
        'status': 'success' if u.is_valid else 'error',
        'detail': f'Processed · {u.row_count} rows'
    } for u in uploads]


# ── REPORT ANALYSIS ───────────────────────────────────────────
def get_report_data(user_id, role, date_from=None, date_to=None, top_n=5):
    query = _analysis_query(user_id, role)
    if date_from:
        query = query.filter(AnalysisResult.analysed_at >= date_from)
    if date_to:
        query = query.filter(AnalysisResult.analysed_at < date_to + timedelta(days=1))

    analyses = query.all()
    blacklisted_ips = {b.ip_address for b in IPBlacklist.query.all()}

    by_ip = {}
    total_alerts = 0
    for analysis in analyses:
        if not analysis.ip_stats:
            continue
        for entry in json.loads(analysis.ip_stats):
            ip = entry['ip']
            total_alerts += entry['count']
            if ip not in by_ip:
                by_ip[ip] = {'ip': ip, 'count': 0, 'types': {}, 'max_severity': 'normal'}
            agg = by_ip[ip]
            agg['count'] += entry['count']
            for t, c in entry['types'].items():
                agg['types'][t] = agg['types'].get(t, 0) + c
            if SEVERITY_RANK.get(entry['max_severity'], 0) > SEVERITY_RANK.get(agg['max_severity'], 0):
                agg['max_severity'] = entry['max_severity']

    top_ips = []
    for ip, entry in by_ip.items():
        top_type = max(entry['types'], key=entry['types'].get)
        top_ips.append({
            'ip': ip, 'count': entry['count'], 'top_attack_type': top_type,
            'severity': entry['max_severity'], 'is_blacklisted': ip in blacklisted_ips,
        })
    top_ips.sort(key=lambda x: x['count'], reverse=True)

    return {
        'top_ips': top_ips[:top_n],
        'total_alerts': total_alerts,
        'total_unique_ips': len(by_ip),
    }


# ── BLACKLIST ─────────────────────────────────────────────────
def get_blacklist(user_id=None):
    return [b.to_dict() for b in IPBlacklist.query.order_by(IPBlacklist.added_at.desc()).all()]


def add_blacklist_ip(ip_address, reason, added_by_user_id):
    existing = IPBlacklist.query.filter_by(ip_address=ip_address).first()
    if existing:
        return {'success': False, 'error': 'IP already in blacklist'}
    entry = IPBlacklist(ip_address=ip_address, reason=reason, added_by=added_by_user_id)
    db.session.add(entry)
    db.session.commit()
    return {'success': True}


def remove_blacklist_ip(entry_id):
    entry = IPBlacklist.query.get(entry_id)
    if entry:
        db.session.delete(entry)
        db.session.commit()


def remove_blacklist_ip_by_address(ip_address):
    entry = IPBlacklist.query.filter_by(ip_address=ip_address).first()
    if entry:
        db.session.delete(entry)
        db.session.commit()


# ── ASSIGN ────────────────────────────────────────────────
def get_analyses_for_assignment(admin_user_id):
    """All analysis runs this admin has done, with current assignment status."""
    analyses = AnalysisResult.query.filter_by(user_id=admin_user_id)\
        .order_by(AnalysisResult.analysed_at.desc()).all()
    result = []
    for a in analyses:
        file = UploadedFile.query.get(a.file_id)
        assignments = AnalysisAssignment.query.filter_by(analysis_id=a.id).all()

        assigned_to = [
            {'id': assign.analyst.id, 'username': assign.analyst.username, 'analyst_id': assign.analyst_id}
            for assign in assignments
            if assign.analyst_id is not None
        ]
        assigned_managers = [
            {'id': assign.manager.id, 'username': assign.manager.username, 'manager_id': assign.manager_id}
            for assign in assignments
            if assign.manager_id is not None
        ]

        result.append({
            'id':                  a.id,
            'filename':            file.filename if file else 'Unknown',
            'analysed_at':         a.analysed_at.strftime('%Y-%m-%d %H:%M'),
            'total_rows':          a.total_rows,
            'high_count':          a.high_count,
            'medium_count':        a.medium_count,
            'assigned_to':         assigned_to,
            'is_assigned':         len(assigned_to) > 0,
            'assigned_managers':   assigned_managers,
            'is_assigned_manager': len(assigned_managers) > 0,
        })
    return result

def get_all_analysts():
    """All SOC Analyst accounts for the assignment n."""
    analysts = User.query.filter_by(role='analyst').all()
    return [{'id': u.id, 'username': u.username} for u in analysts]

def get_all_managers():
    """All it manager accounts for the assignment ."""
    managers = User.query.filter_by(role='manager').all()
    return [{'id': u.id, 'username': u.username} for u in managers]


def assign_to_manager(analysis_id, manager_id, assigned_by):
    """
    Admin assigns an analysis to a manager.
    Adds a new AnalysisAssignment row for this manager if one doesn't already exist.
    """
    existing_ids = {
        a.manager_id for a in
        AnalysisAssignment.query.filter_by(analysis_id=analysis_id).all()
        if a.manager_id is not None
    }
    if manager_id not in existing_ids:
        db.session.add(AnalysisAssignment(
            analysis_id=analysis_id,
            manager_id=manager_id,
            assigned_by=assigned_by,
        ))
    db.session.commit()

def remove_assignment_manager(analysis_id, manager_id):
    entry = AnalysisAssignment.query.filter_by(
        analysis_id=analysis_id, manager_id=manager_id
    ).first()
    if entry:
        db.session.delete(entry)
        db.session.commit()


# to be changed
# def assign_analysis(analysis_id, analyst_ids, assigned_by):
#     existing_ids = {
#         a.analyst_id for a in 
#         AnalysisAssignment.query.filter_by(analysis_id=analysis_id).all()
#     }
#     for analyst_id in analyst_ids:
#         if analyst_id not in existing_ids:
#             db.session.add(AnalysisAssignment(
#                 analysis_id=analysis_id,
#                 analyst_id=analyst_id,
#                 assigned_by=assigned_by,
#             ))
#     db.session.commit()

# def remove_assignment(analysis_id, analyst_id):
#     entry = AnalysisAssignment.query.filter_by(
#         analysis_id=analysis_id, analyst_id=analyst_id
#     ).first()
#     if entry:
#         db.session.delete(entry)
#         db.session.commit()

# insights page
from datetime import datetime, timedelta
import json

def get_attack_overview(user_id, role, days=7):
    since = datetime.utcnow() - timedelta(days=days)
    prev_since = since - timedelta(days=days)

    # pull from AnalysisResult — this has the REAL totals, not the sampled ticket subset
    results = _analysis_query(user_id, role)\
        .filter(AnalysisResult.analysed_at >= since)\
        .order_by(AnalysisResult.analysed_at.asc()).all()

    prev_results = _analysis_query(user_id, role)\
        .filter(AnalysisResult.analysed_at >= prev_since,
                AnalysisResult.analysed_at < since).all()

    volume_by_day = {}
    severity_by_day = {}
    type_totals = {
        'BENIGN': 0, 'Web Attack': 0, 'DoS': 0, 'DDoS': 0,
        'PortScan': 0, 'Bot/Patator': 0, 'Rare/Others': 0
    }
    ip_totals = {}

    for r in results:
        day_key = r.analysed_at.strftime('%Y-%m-%d')

        volume_by_day[day_key] = volume_by_day.get(day_key, 0) + r.total_rows

        sev_bucket = severity_by_day.setdefault(day_key, {'high': 0, 'medium': 0, 'normal': 0})
        sev_bucket['high'] += r.high_count
        sev_bucket['medium'] += r.medium_count
        sev_bucket['normal'] += r.normal_count

        type_totals['BENIGN'] += r.benign
        type_totals['Web Attack'] += r.web_attack
        type_totals['DoS'] += r.dos
        type_totals['DDoS'] += r.ddos
        type_totals['PortScan'] += r.portscan
        type_totals['Bot/Patator'] += r.bot
        type_totals['Rare/Others'] += r.rare

        # aggregate IP stats across all analyses in this period
        if r.ip_stats:
            for entry in json.loads(r.ip_stats):
                ip = entry['ip']
                if ip not in ip_totals:
                    ip_totals[ip] = {'ip': ip, 'count': 0, 'max_severity': 'normal'}
                ip_totals[ip]['count'] += entry['count']
                if SEVERITY_RANK.get(entry['max_severity'], 0) > SEVERITY_RANK.get(ip_totals[ip]['max_severity'], 0):
                    ip_totals[ip]['max_severity'] = entry['max_severity']

    day_labels = [(since + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(days + 1)]

    volume_trend = [{'date': d, 'count': volume_by_day.get(d, 0)} for d in day_labels]
    severity_trend = [{'date': d, **severity_by_day.get(d, {'high': 0, 'medium': 0, 'normal': 0})} for d in day_labels]

    attack_only = {k: v for k, v in type_totals.items() if k != 'BENIGN'}
    top_attack_type = max(attack_only, key=attack_only.get) if any(attack_only.values()) else 'None'

    top_ips = sorted(ip_totals.values(), key=lambda x: x['count'], reverse=True)[:5]

    total_this_period = sum(volume_by_day.values())
    total_prev_period = sum(r.total_rows for r in prev_results)

    if total_prev_period > 0:
        pct_change = round(((total_this_period - total_prev_period) / total_prev_period) * 100, 1)
    else:
        pct_change = None

    return {
        'total_alerts': total_this_period,
        'volume_trend': volume_trend,
        'severity_trend': severity_trend,
        'top_attack_type': top_attack_type,
        'type_totals': type_totals,
        'top_ips': top_ips,
        'pct_change': pct_change,
        'analyses_in_period': results,
    }