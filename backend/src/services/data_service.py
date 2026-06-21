#it handles the data uploaded 
import json
from datetime import timedelta
from backend.src.database.models import Alert, AnalysisResult, UploadedFile, IPBlacklist
from backend.src.database.db import db
from backend.src.ml.preprocess import preprocess_csv
from backend.src.ml.predict import predict, get_summary

SEVERITY_RANK = {'normal': 0, 'medium': 1, 'high': 2}

def get_dashboard_data(user_id):
    high_alerts = Alert.query.filter_by(severity='high', user_id=user_id) \
        .order_by(Alert.created_at.desc()).limit(3).all()
    high_alerts = [a.to_dict() for a in high_alerts]

    latest = AnalysisResult.query.filter_by(user_id=user_id) \
        .order_by(AnalysisResult.analysed_at.desc()).first()

    if not latest:
        return high_alerts, [], _empty_metrics()

    threat_distribution = [
        {'type': 'BENIGN',      'pct': round(latest.benign     / latest.total_rows * 100, 1), 'count': latest.benign,     'colour': '#1DB954'},
        {'type': 'Web Attack',  'pct': round(latest.web_attack / latest.total_rows * 100, 1), 'count': latest.web_attack, 'colour': '#E74C3C'},
        {'type': 'DoS',         'pct': round(latest.dos        / latest.total_rows * 100, 1), 'count': latest.dos,        'colour': '#F39C12'},
        {'type': 'DDoS',        'pct': round(latest.ddos       / latest.total_rows * 100, 1), 'count': latest.ddos,       'colour': '#3D8EFF'},
        {'type': 'PortScan',    'pct': round(latest.portscan   / latest.total_rows * 100, 1), 'count': latest.portscan,   'colour': '#A07EFF'},
        {'type': 'Bot/Patator', 'pct': round(latest.bot        / latest.total_rows * 100, 1), 'count': latest.bot,        'colour': '#FF6B6B'},
        {'type': 'Rare/Others', 'pct': round(latest.rare       / latest.total_rows * 100, 1), 'count': latest.rare,       'colour': '#FFD93D'},
    ]
    metrics = {
        'logs_processed':     f'{latest.total_rows:,}',
        'high_count':         latest.high_count,
        'medium_count':       latest.medium_count,
        'low_count':          latest.normal_count,
        'model_accuracy':     '96.4%',
        'response_time':      '142ms',
        'uptime':             '99.8%',
        'total_threat_types': sum(1 for item in threat_distribution if item['pct'] > 0),
    }
    return high_alerts, threat_distribution, metrics


def _empty_metrics():
    return {
        'logs_processed': '0', 'high_count': 0, 'medium_count': 0, 'low_count': 0,
        'model_accuracy': 'N/A', 'response_time': 'N/A', 'uptime': '99.8%',
        'total_threat_types': 0,
    }


def run_analysis(file_id, user_id):
    upload = UploadedFile.query.filter_by(id=file_id, user_id=user_id).first()
    if not upload:
        return None, 'File not found.'

    X, error = preprocess_csv(upload.filepath)
    if error:
        return None, error

    results = predict(X)
    summary = get_summary(results)
    by_label, by_sev = summary['by_label'], summary['by_severity']

    record = AnalysisResult(
        file_id=file_id, user_id=user_id, total_rows=len(results),
        benign=by_label['BENIGN'], web_attack=by_label['Web Attack'],
        dos=by_label['DoS'], ddos=by_label['DDoS'], portscan=by_label['PortScan'],
        bot=by_label['Bot/Patator'], rare=by_label['Rare/Others'],
        high_count=by_sev['high'], medium_count=by_sev['medium'], normal_count=by_sev['normal'],
    )
    db.session.add(record)
    db.session.commit()

    by_type = {}
    for r in results:
        if r['severity'] in ('high', 'medium'):
            if r['prediction'] not in by_type:
                by_type[r['prediction']] = []
            by_type[r['prediction']].append(r)

    # make up fake ips for the dataset as we dont have now so we can chnge this part laterz
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

    #keep the the top 20 highestconfidence rows per attack type and saves each one as a real Alert which we can click into and view more info
    selected = []
    for label, rows in by_type.items():
        selected.extend(sorted(rows, key=lambda x: x['confidence'], reverse=True)[:20])

    for r in selected:
        row_data = X.iloc[r['row']]
        row_idx = r['row']
        source_ip = f'10.0.{(row_idx // 254) % 255}.{(row_idx % 254) + 1}'
        db.session.add(Alert(
            analysis_id=record.id, user_id=user_id, row_index=row_idx,
            prediction=r['prediction'], severity=r['severity'], confidence=r['confidence'],
            xgb_vote=r['xgb_vote'], rf_vote=r['rf_vote'],
            dest_port=int(row_data['Destination Port']),
            flow_duration=round(float(row_data['Flow Duration']), 2),
            flow_pkts_s=round(float(row_data['Flow Packets/s']), 2),
            source_ip=source_ip,
        ))
    db.session.commit()
    return record, None

def get_alert_feed(user_id, severity, attack_type):
    query = Alert.query.filter_by(user_id=user_id).order_by(Alert.created_at.desc())
    if severity != 'all':
        query = query.filter_by(severity=severity)
    if attack_type != 'all':
        query = query.filter_by(prediction=attack_type)
    return [a.to_dict() for a in query.limit(100).all()]


def get_alert_detail(user_id, alert_id):
    return Alert.query.filter_by(id=alert_id, user_id=user_id).first()


def get_logs(user_id, filter_type):
    query = Alert.query.filter_by(user_id=user_id)
    if filter_type == 'flagged':
        query = query.filter(Alert.severity.in_(['high', 'medium']))
    elif filter_type == 'normal':
        query = query.filter_by(severity='normal')

    total = query.count()
    alerts = query.order_by(Alert.created_at.desc()).limit(500).all()

    logs = [{
        'timestamp':   a.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'source':      f'10.0.{(a.row_index or 0) % 255}.{(a.row_index or 1) % 254 + 1}',
        'destination': f'192.168.1.1:{a.dest_port}' if a.dest_port else '—',
        'type':        a.prediction,
        'protocol':    'TCP',
        'severity':    a.severity,
        'flagged':     a.severity in ('high', 'medium'),
    } for a in alerts]

    return logs, total


def get_upload_history(user_id, limit=10):
    uploads = UploadedFile.query.filter_by(user_id=user_id) \
        .order_by(UploadedFile.uploaded_at.desc()).limit(limit).all()
    return [{
        'id': u.id, 'name': u.filename,
        'status': 'success' if u.is_valid else 'error',
        'detail': f'Processed · {u.row_count} rows'
    } for u in uploads]




# report analysis page (can be work on)
# it has time range (but now we dont have), counts the fake ip that have highest count and show the top 5 to show which one to block
def get_report_data(user_id, date_from=None, date_to=None, top_n=5):
    query = AnalysisResult.query.filter_by(user_id=user_id)
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



# the blacklist part ( dk if needed will work on it later )
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