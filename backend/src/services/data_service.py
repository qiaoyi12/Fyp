# Handles all the backend logic data
import json
import time
import pandas as pd
from datetime import timedelta, datetime
from sqlalchemy import or_
from backend.src.database.models import Alert, AlertDetail, AnalysisResult, UploadedFile, IPBlacklist, AnalysisAssignment, User, TrafficLog, IncidentReport
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
    if role == 'analyst':
        has_analysis_level = len(_get_assigned_analysis_ids(user_id, role)) > 0
        has_ticket_level = Alert.query.filter_by(assigned_analyst_id=user_id).first() is not None
        return not (has_analysis_level or has_ticket_level)
    if role == 'manager':
        return len(_get_assigned_analysis_ids(user_id, role)) == 0
    return False


def _alert_query(user_id, role):
    if role == 'analyst':
        analysis_ids = _get_assigned_analysis_ids(user_id, role)
        conditions = [Alert.assigned_analyst_id == user_id]
        if analysis_ids:
            conditions.append(Alert.analysis_id.in_(analysis_ids))
        return Alert.query.filter(or_(*conditions))
    if role == 'manager':
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
        'model_accuracy': f"{latest.model_accuracy}%" if latest.model_accuracy is not None else 'N/A',
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

# ── TRAFFICLOGS ──────────────────────────────────────────────────
# used for query for top attacking IPS
def _traffic_log_query(user_id, role):
    if role in ('analyst', 'manager'):
        analysis_ids = _get_assigned_analysis_ids(user_id, role)
        if not analysis_ids:
            return TrafficLog.query.filter_by(id=None)
        return TrafficLog.query.filter(TrafficLog.analysis_id.in_(analysis_ids))
    return TrafficLog.query.filter_by(user_id=user_id)

def get_traffic_log_count_by_ip(user_id, role, ip):
    return _traffic_log_query(user_id, role).filter_by(source_ip=ip).count()

# to make sure that all the traffic is stored in the db
def _bulk_insert_traffic_logs(record, combined_results, frame_lookup, user_id):
    """Persist a lightweight record of every processed row (not just the capped alert subset)."""
    df = pd.DataFrame(combined_results)

    traffic_log_rows = []
    for upload_id, group in df.groupby('source_upload_id'):
        X_frame, raw_frame = frame_lookup[upload_id]
        idx = group['source_row'].values

        src_ips   = raw_frame['Src IP'].values[idx]
        dst_ips   = raw_frame['Dst IP'].values[idx]
        dst_ports = X_frame['Dst Port'].values[idx]

        row_indices = group['row'].values
        predictions = group['prediction'].values
        severities  = group['severity'].values
        confidences = group['confidence'].values

        for i in range(len(group)):
            pred = predictions[i]
            traffic_log_rows.append({
                'analysis_id': record.id,
                'user_id': user_id,
                'row_index': int(row_indices[i]),
                'source_ip': str(src_ips[i]),
                'dest_ip': str(dst_ips[i]),
                'dest_port': int(dst_ports[i]),
                'prediction': pred,
                'severity': 'normal' if pred == 'BENIGN' else severities[i],
                'confidence': float(confidences[i]),
            })

    # Insert in chunks 
    CHUNK = 20000
    for i in range(0, len(traffic_log_rows), CHUNK):
        db.session.bulk_insert_mappings(TrafficLog, traffic_log_rows[i:i+CHUNK])
    db.session.commit()
    

# the main analysis that run the whole csv file 
def run_analysis(file_ids, user_id):
    uploads = _resolve_uploads(file_ids, user_id)
    if not uploads:
        return None, 'File not found.', None

    start_time = time.time()

    processed_files = []
    combined_results = []
    global_row = 0

    for upload in uploads:
        t0 = time.time()                                              
        X, error = preprocess_csv(upload.filepath)
        print(f"[TIMING] preprocess_csv: {time.time()-t0:.2f}s")       
        if error:
            return None, error, None

        t0 = time.time()                                              
        raw_df = pd.read_csv(upload.filepath)
        raw_df.columns = raw_df.columns.str.strip()
        print(f"[TIMING] read_csv raw_df: {time.time()-t0:.2f}s")      

        t0 = time.time()                                              
        results = predict(X)
        print(f"[TIMING] predict: {time.time()-t0:.2f}s")              

        for result in results:
            enriched = dict(result)
            enriched['source_upload_id'] = upload.id
            enriched['source_row'] = int(result['row'])
            enriched['row'] = global_row
            combined_results.append(enriched)
            global_row += 1

        processed_files.append((upload, X, raw_df))

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
        model_accuracy=metrics.get('accuracy'),
    )
    db.session.add(record)
    db.session.commit()

    frame_lookup = {upload.id: (X, raw_df) for upload, X, raw_df in processed_files}

    by_type = {}
    for r in combined_results:
        if r['prediction'] not in by_type:
            by_type[r['prediction']] = []
        by_type[r['prediction']].append(r)

    t0 = time.time()
    ip_counts = {}
    flat_rows = [row for rows in by_type.values() for row in rows]
    flat_df = pd.DataFrame(flat_rows)

    for upload_id, group in flat_df.groupby('source_upload_id'):
        _, raw_frame = frame_lookup[upload_id]
        idx = group['source_row'].values
        ips = raw_frame['Src IP'].values[idx]

        for ip, pred, sev in zip(ips, group['prediction'].values, group['severity'].values):
            ip = str(ip)
            if ip not in ip_counts:
                ip_counts[ip] = {'ip': ip, 'count': 0, 'types': {}, 'max_severity': 'normal'}
            entry = ip_counts[ip]
            entry['count'] += 1
            entry['types'][pred] = entry['types'].get(pred, 0) + 1
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(entry['max_severity'], 0):
                entry['max_severity'] = sev
    print(f"[TIMING] ip_counts loop: {time.time()-t0:.2f}s")

    record.ip_stats = json.dumps(list(ip_counts.values()))
    db.session.commit()

    t0 = time.time()                                                   # ADD
    _bulk_insert_traffic_logs(record, combined_results, frame_lookup, user_id)
    print(f"[TIMING] bulk_insert_traffic_logs: {time.time()-t0:.2f}s")  # ADD

    TICKETS_PER_TYPE_MAX = 80

    selected = []
    for label, rows in by_type.items():
        selected.extend(sorted(rows, key=lambda x: x['confidence'])[:TICKETS_PER_TYPE_MAX])
    selected.sort(key=lambda x: x['row'])

    t0 = time.time()                                                   # ADD
    for ticket_no, r in enumerate(selected, start=1):
        X_frame, raw_frame = frame_lookup[r['source_upload_id']]
        row_data = X_frame.iloc[r['source_row']]
        raw_row = raw_frame.iloc[r['source_row']]
        row_idx = r['row']
        source_ip = str(raw_row.get('Src IP', 'Unknown'))

        severity = 'normal' if r['prediction'] == 'BENIGN' else r['severity']

        alert = Alert(
            analysis_id=record.id,
            user_id=user_id,
            row_index=row_idx,
            ticket_id=ticket_no,
            prediction=r['prediction'],
            severity=severity,
            confidence=r['confidence'],
            xgb_vote=r['xgb_vote'],
            rf_vote=r['rf_vote'],
            dest_port=int(row_data['Dst Port']),
            flow_bytes_s=round(float(raw_row.get('Flow Bytes/s', 0)), 2),
            source_ip=source_ip,
            dest_ip=str(raw_row.get('Dst IP', 'Unknown')),
        )
        db.session.add(alert)
        db.session.flush()

        detail = AlertDetail(
                alert_id=alert.id,
                flow_bytes_s=round(float(row_data['Flow Bytes/s']), 2),
                total_fwd_packets=int(raw_row.get('Total Fwd Packets', 0)),
                total_backward_packets=int(row_data['Total Bwd packets']),
                packet_length_mean=round(float(row_data['Packet Length Mean']), 2),
                average_packet_size=round(float(row_data['Average Packet Size']), 2),
                syn_flag_count=int(raw_row.get('SYN Flag Count', 0)),
                ack_flag_count=int(row_data['ACK Flag Count']),
                psh_flag_count=int(row_data['PSH Flag Count']),
                init_win_bytes_forward=int(row_data['FWD Init Win Bytes']),
                init_win_bytes_backward=int(row_data['Bwd Init Win Bytes']),
                packet_length_max=round(float(row_data['Packet Length Max']), 2),
                packet_length_std=round(float(row_data['Packet Length Std']), 2),
                bwd_iat_max=round(float(row_data['Bwd IAT Max']), 2),
            )
        db.session.add(detail)
    print(f"[TIMING] alert+detail insert loop: {time.time()-t0:.2f}s")  # ADD

    db.session.commit()

    from agenticAI.assignment_agent import run_assignment_for_batch  # local import avoids circular import
    run_assignment_for_batch(record.id)

    return record, None, metrics

# ── ALERTS ────────────────────────────────────────────────────
def get_alert_feed(user_id, role, severity, attack_type, sort='confidence_desc', ip=None):
    query = _alert_query(user_id, role)
    query = query.filter(Alert.tag != 'Resolved')

    if severity != 'all':
        query = query.filter_by(severity=severity)
    if attack_type != 'all':
        query = query.filter_by(prediction=attack_type)
    if ip:
        query = query.filter_by(source_ip=ip)

    if sort == 'confidence_desc':
        query = query.order_by(Alert.confidence.desc())
    elif sort == 'confidence_asc':
        query = query.order_by(Alert.confidence.asc())
    elif sort == 'newest':
        query = query.order_by(Alert.created_at.desc())
    elif sort == 'oldest':
        query = query.order_by(Alert.created_at.asc())
    else:
        query = query.order_by(Alert.confidence.desc())

    return [a.to_dict() for a in query.limit(100).all()]

def get_alert_detail(user_id, role, alert_id):
    alert = _alert_query(user_id, role).filter_by(id=alert_id).first()

    if not alert:
        return None

    return {
        "alert": alert,
        "detail": alert.detail
    }

RESOLVED_TAG = 'Resolved'
TICKETS_PER_STAFF_CAP = 5
SEVERITY_RANK = {'high': 0, 'medium': 1, 'normal': 2}


def get_open_ticket_count(analyst_id):
    """
    Number of tickets currently assigned to this analyst that are NOT
    yet resolved. This defines their "open workload" - the cap of 5 is
    now an ongoing 'max 5 open at once' limit, not a one-time batch cap.
    """
    return Alert.query.filter(
        Alert.assigned_analyst_id == analyst_id,
        Alert.tag != RESOLVED_TAG,
    ).count()


def get_unassigned_ticket_pool():
    """
    Every unassigned ticket system-wide, sorted with 'Needs Action'
    tagged tickets first (manually flagged as urgent), then by
    severity (high first), then oldest first.
    """
    tickets = Alert.query.filter_by(assigned_analyst_id=None).all()
    tickets.sort(key=lambda a: (
        0 if a.tag == 'Needs Action' else 1,
        SEVERITY_RANK.get(a.severity, 99),
        a.created_at,
    ))
    return tickets


def replenish_analyst(analyst_id):
    """
    Called right after an analyst resolves a ticket. Fills their freed-up
    capacity (up to TICKETS_PER_STAFF_CAP open tickets total) from the
    system-wide unassigned pool, oldest/highest-severity first.

    Deliberately rule-based, no LLM call: the decision here (oldest,
    highest-severity ticket first) is unambiguous, so there's no benefit
    to an agent call - only added latency and cost. The agent is reserved
    for the initial batch routing decision, where genuine judgment
    (severity vs seniority tradeoffs) is actually needed.
    """
    open_count = get_open_ticket_count(analyst_id)
    free_slots = TICKETS_PER_STAFF_CAP - open_count
    if free_slots <= 0:
        return {"replenished_count": 0}

    pool = get_unassigned_ticket_pool()
    to_assign = pool[:free_slots]

    # imported here (not at top of file) to avoid a circular import - this
    # module is part of the backend package, and assignment_tools needs
    # models from that same package
    from agenticAI.assignment_tools import assign_ticket  # pylint: disable=import-outside-toplevel

    replenished_count = 0
    for ticket in to_assign:
        outcome = assign_ticket(
            ticket_id=ticket.id,
            staff_id=analyst_id,
            reason=(
                f"Auto-assigned to fill freed capacity: {ticket.severity} severity "
                f"{ticket.prediction} ticket, oldest unassigned in the system-wide queue."
            ),
        )
        if outcome["success"]:
            replenished_count += 1

    return {"replenished_count": replenished_count}


def _assign_single_ticket(alert):
    """
    Assigns one specific ticket to an eligible analyst, following the
    same severity/seniority rule as the batch fallback in
    distribution_plan.py: senior analysts only receive high-severity
    tickets, and seniors are filled to capacity before a junior can
    receive a high-severity ticket (emergency overflow).
    """
    analysts = User.query.filter_by(role='analyst').all()
    if not analysts:
        return

    from agenticAI.assignment_tools import assign_ticket

    is_high = alert.severity == 'high'
    seniors = [a for a in analysts if a.level == 'senior']
    juniors = [a for a in analysts if a.level != 'senior']

    def has_capacity(analyst):
        return get_open_ticket_count(analyst.id) < TICKETS_PER_STAFF_CAP

    if is_high:
        # seniors first, most free capacity first
        candidates = sorted([a for a in seniors if has_capacity(a)],
                             key=lambda a: get_open_ticket_count(a.id))
        if not candidates:
            # emergency overflow: only if every senior is fully at capacity
            seniors_full = all(not has_capacity(a) for a in seniors) if seniors else True
            if seniors_full:
                candidates = sorted([a for a in juniors if has_capacity(a)],
                                     key=lambda a: get_open_ticket_count(a.id))
    else:
        # medium/normal severity goes ONLY to juniors, never seniors
        candidates = sorted([a for a in juniors if has_capacity(a)],
                             key=lambda a: get_open_ticket_count(a.id))

    if not candidates:
        return  # nobody eligible right now - stays unassigned until capacity frees up

    chosen = candidates[0]
    assign_ticket(
        ticket_id=alert.id,
        staff_id=chosen.id,
        reason=(
            f"Auto-assigned on 'Needs Action' tag: routed to {chosen.username} "
            f"({chosen.level} analyst) based on {alert.severity} severity {alert.prediction} activity."
        ),
    )


def update_alert_tag(alert_id, tag):
    alert = Alert.query.get(alert_id)

    if alert:
        alert.tag = tag
        db.session.commit()

        if tag == 'Resolved' and alert.assigned_analyst_id:
            replenish_analyst(alert.assigned_analyst_id)

        elif tag == 'Needs Action' and not alert.assigned_analyst_id:
            _assign_single_ticket(alert)

def update_alert_remarks(alert_id, remarks):
    alert = Alert.query.get(alert_id)
    if alert:
        alert.remarks = remarks
        db.session.commit()



# ── LOGS ──────────────────────────────────────────────────────
def get_logs(user_id, role, filter_type, search='', page=1, per_page=80):
    if not search:
        # mirror what's already in Alert Feed
        query = _alert_query(user_id, role)
        if filter_type == 'flagged':
            query = query.filter(Alert.severity.in_(['high', 'medium']))
        elif filter_type == 'normal':
            query = query.filter_by(severity='normal')

        total = query.count()
        alerts_page = query.order_by(Alert.created_at.desc()) \
            .offset((page - 1) * per_page).limit(per_page).all()

        logs = [{
            'id':          a.id,
            'timestamp':   a.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'source':      a.source_ip or '—',
            'destination': a.dest_ip or '—',
            'type':        a.prediction,
            'protocol':    'TCP',
            'severity':    a.severity,
            'flagged':     a.severity in ('high', 'medium'),
            'alert_id':    a.id,   # already a real alert, always show "View Alert"
            'ticket_id':   a.ticket_id,
        } for a in alerts_page]

        return logs, total

    else:
        # search the FULL traffic log, not just existing alerts
        query = _traffic_log_query(user_id, role)
        if filter_type == 'flagged':
            query = query.filter(TrafficLog.severity.in_(['high', 'medium']))
        elif filter_type == 'normal':
            query = query.filter_by(severity='normal')

        query = query.filter(
            db.or_(
                TrafficLog.source_ip.ilike(f'%{search}%'),
                TrafficLog.dest_ip.ilike(f'%{search}%'),
                TrafficLog.prediction.ilike(f'%{search}%'),
            )
        )

        total = query.count()
        logs_page = query.order_by(TrafficLog.created_at.desc()) \
            .offset((page - 1) * per_page).limit(per_page).all()

        logs = []
        for log in logs_page:
            log_dict = log.to_dict()
            existing_alert = Alert.query.filter_by(
                analysis_id=log.analysis_id,
                row_index=log.row_index
            ).first()
            log_dict['alert_id']  = existing_alert.id if existing_alert else None
            log_dict['ticket_id'] = existing_alert.ticket_id if existing_alert else None  # ADD THIS LINE
            logs.append(log_dict)

        return logs, total



# to create alert if needed 
def create_alert_from_traffic_log(traffic_log):
    """Escalate a TrafficLog row into a full Alert with detail, computed on demand."""
    existing = Alert.query.filter_by(
        analysis_id=traffic_log.analysis_id,
        row_index=traffic_log.row_index
    ).first()
    if existing:
        return existing

    analysis = AnalysisResult.query.get(traffic_log.analysis_id)
    upload = UploadedFile.query.get(analysis.file_id)

    X, error = preprocess_csv(upload.filepath)
    raw_df = pd.read_csv(upload.filepath)
    raw_df.columns = raw_df.columns.str.strip()

    row_data = X.iloc[traffic_log.row_index]
    raw_row = raw_df.iloc[traffic_log.row_index]

    result = predict(X.iloc[[traffic_log.row_index]])[0]

    max_ticket = db.session.query(db.func.max(Alert.ticket_id)) \
        .filter_by(analysis_id=traffic_log.analysis_id).scalar() or 0

    alert = Alert(
        analysis_id=traffic_log.analysis_id,
        user_id=traffic_log.user_id,
        row_index=traffic_log.row_index,
        ticket_id=max_ticket + 1,
        prediction=result['prediction'],
        severity=result['severity'],
        confidence=result['confidence'],
        xgb_vote=result['xgb_vote'],
        rf_vote=result['rf_vote'],
        dest_port=int(row_data['Dst Port']),
        dest_ip=str(raw_row.get('Dst IP', 'Unknown')),
        source_ip=str(raw_row.get('Src IP', 'Unknown')),
        # CHNAGE THIS
        flow_bytes_s=round(float(raw_row.get('Flow Bytes/s', 0)), 2),
    )
    
    db.session.add(alert)
    db.session.flush()   # generates alert.id

    detail = AlertDetail(
        alert_id=alert.id,
        flow_bytes_s=round(float(row_data['Flow Bytes/s']), 2),
        total_fwd_packets=int(raw_row.get('Total Length of Fwd Packets', 0)),
        total_backward_packets=int(row_data['Total Bwd packets']),
        packet_length_mean=round(float(row_data['Packet Length Mean']), 2),
        average_packet_size=round(float(row_data['Average Packet Size']), 2),
        syn_flag_count=int(raw_row.get('SYN Flag Count', 0)),
        ack_flag_count=int(row_data['ACK Flag Count']),
        psh_flag_count=int(row_data['PSH Flag Count']),
        init_win_bytes_forward=int(row_data['FWD Init Win Bytes']),
        init_win_bytes_backward=int(row_data['Bwd Init Win Bytes']),
        packet_length_max=round(float(row_data['Packet Length Max']), 2),
        packet_length_std=round(float(row_data['Packet Length Std']), 2),
        bwd_iat_max=round(float(row_data['Bwd IAT Max']), 2),
    )
    db.session.add(detail)
    db.session.commit() 

    return alert
    
# ── UPLOAD HISTORY ────────────────────────────────────────────
def get_upload_history(user_id, limit=10):
    uploads = UploadedFile.query.filter_by(user_id=user_id) \
        .order_by(UploadedFile.uploaded_at.desc()).limit(limit).all()
    return [{
        'id': u.id, 'name': u.filename,
        'status': 'success' if u.is_valid else 'error',
        'detail': f'Processed · {u.row_count} rows'
    } for u in uploads]

SEVERITY_MAP = {
    'BENIGN':      'normal',
    'Web Attack':  'high',
    'DoS':         'high',
    'DDoS':        'high',
    'PortScan':    'medium',
    'Bot/Patator': 'high',
    'Rare/Others': 'medium'
}
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
            'severity': SEVERITY_MAP.get(top_type, 'normal'), 'is_blacklisted': ip in blacklisted_ips,
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

def get_analyses_for_manager_assignment(manager_id):
    """
    Analyses that have been assigned to this manager (by an admin), with
    current per-analyst assignment status - used by the manager's
    'assign to analyst' page.
    """
    analysis_ids = _get_assigned_analysis_ids(manager_id, 'manager')
    if not analysis_ids:
        return []

    analyses = AnalysisResult.query.filter(AnalysisResult.id.in_(analysis_ids))\
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

        result.append({
            'id':           a.id,
            'filename':     file.filename if file else 'Unknown',
            'analysed_at':  a.analysed_at.strftime('%Y-%m-%d %H:%M'),
            'total_rows':   a.total_rows,
            'high_count':   a.high_count,
            'medium_count': a.medium_count,
            'assigned_to':  assigned_to,
            'is_assigned':  len(assigned_to) > 0,
        })
    return result


def assign_to_analyst(analysis_id, analyst_id, assigned_by):
    """
    Manager assigns an analysis to an analyst.
    Adds a new AnalysisAssignment row for this analyst if one doesn't already exist.
      Only allowed if this analysis is actually assigned to this manager -
    prevents a manager from assigning analyses they don't own just by
    guessing an analysis_id. Returns False if the ownership check fails.
    """
    owned_ids = _get_assigned_analysis_ids(assigned_by, 'manager')
    if analysis_id not in owned_ids:
        return False

    existing_ids = {
        a.analyst_id for a in
        AnalysisAssignment.query.filter_by(analysis_id=analysis_id).all()
        if a.analyst_id is not None
    }
    if analyst_id not in existing_ids:
        db.session.add(AnalysisAssignment(
            analysis_id=analysis_id,
            analyst_id=analyst_id,
            assigned_by=assigned_by,
        ))
    db.session.commit()
    return True


def remove_assignment_manager(analysis_id, manager_id):
    entry = AnalysisAssignment.query.filter_by(
        analysis_id=analysis_id, manager_id=manager_id
    ).first()
    if entry:
        db.session.delete(entry)

        # cascade path 1: clear AI-agent per-ticket assignments on Alert rows
        Alert.query.filter_by(analysis_id=analysis_id).update({
            'assigned_analyst_id': None,
            'assignment_source': None,
            'assignment_reason': None,
            'assigned_at': None,
        })

        # cascade path 2: remove manual manager->analyst AnalysisAssignment rows,
        # since _alert_query() grants analyst visibility through this table too
        AnalysisAssignment.query.filter_by(
            analysis_id=analysis_id
        ).filter(AnalysisAssignment.analyst_id.isnot(None)).delete()

        db.session.commit()

def remove_assignment_analyst(analysis_id, analyst_id, manager_id):
    owned_ids = _get_assigned_analysis_ids(manager_id, 'manager')
    if analysis_id not in owned_ids:
        return False

    entry = AnalysisAssignment.query.filter_by(
        analysis_id=analysis_id, analyst_id=analyst_id
    ).first()
    if entry:
        db.session.delete(entry)

        Alert.query.filter_by(
            analysis_id=analysis_id,
            assigned_analyst_id=analyst_id,
            assignment_source='manual',
        ).update({
            'assigned_analyst_id': None,
            'assignment_source': None,
            'assignment_reason': None,
            'assigned_at': None,
        })

        db.session.commit()
    return True

def trigger_auto_assignment(analysis_id, manager_id):
    """
    Manager-triggered AI auto-assignment for one specific analysis.
    Only runs if this analysis is actually assigned to this manager -
    prevents a manager from triggering assignment on analyses they
    don't own just by guessing an analysis_id.

    Returns the same dict shape as run_assignment_for_batch(), or an
    {"error": ...} dict if the permission check fails.
    """
    owned_ids = _get_assigned_analysis_ids(manager_id, 'manager')
    if analysis_id not in owned_ids:
        return {"error": "This analysis is not assigned to you."}

    # imported here (not at top of file) to avoid a circular import - this
    # module is part of the backend package, and assignment_agent needs
    # models from that same package
    from agenticAI.assignment_agent import run_assignment_for_batch  # pylint: disable=import-outside-toplevel
    return run_assignment_for_batch(analysis_id)


def get_all_analysts():
    """All SOC Analyst accounts for the assignment n."""
    analysts = User.query.filter_by(role='analyst').all()
    return [{'id': u.id, 'username': u.username, 'level': u.level} for u in analysts]

def get_all_managers():
    """All it manager accounts for the assignment ."""
    managers = User.query.filter_by(role='manager').all()
    return [{'id': u.id, 'username': u.username} for u in managers]


def update_analyst_level(analyst_id, level):
    """
    Admin sets an analyst's seniority tier ('junior' or 'senior'), used by
    the AI assignment agent to route higher-severity tickets to senior
    analysts. Returns True if updated, False if the account isn't an analyst.
    """
    if level not in ('junior', 'senior'):
        return False
    analyst = User.query.filter_by(id=analyst_id, role='analyst').first()
    if not analyst:
        return False
    analyst.level = level
    db.session.commit()
    return True


def assign_to_manager(analysis_id, manager_id, assigned_by):
    """
    Admin assigns an analysis to a manager.
    Adds a new AnalysisAssignment row for this manager if one doesn't already exist.
    
    Automatically triggers the AI ticket-assignment agent right after -
    this is the point the analysis first becomes "owned" by a manager,
    so tickets get distributed to analysts immediately, no manual click needed.
    """
    existing_ids = {
        a.manager_id for a in
        AnalysisAssignment.query.filter_by(analysis_id=analysis_id).all()
        if a.manager_id is not None
    }
    is_new_assignment = manager_id not in existing_ids
    if is_new_assignment:
        db.session.add(AnalysisAssignment(
            analysis_id=analysis_id,
            manager_id=manager_id,
            assigned_by=assigned_by,
        ))
    db.session.commit()

    if is_new_assignment:
        # imported here (not at top of file) to avoid a circular import - this
        # module is part of the backend package, and assignment_agent needs
        # models from that same package
        from agenticAI.assignment_agent import run_assignment_for_batch  # pylint: disable=import-outside-toplevel
        run_assignment_for_batch(analysis_id)



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

    day_labels = [(since + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(1, days + 1)]

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

# for resolved tickets 
# ── RESOLVED TICKETS ──────────────────────────────────────────
def get_resolved_tickets(user_id, role, severity='all', attack_type='all', sort='newest'):
    query = _alert_query(user_id, role).filter_by(tag='Resolved')

    if severity != 'all':
        query = query.filter_by(severity=severity)
    if attack_type != 'all':
        query = query.filter_by(prediction=attack_type)

    if sort == 'confidence_desc':
        query = query.order_by(Alert.confidence.desc())
    elif sort == 'confidence_asc':
        query = query.order_by(Alert.confidence.asc())
    elif sort == 'oldest':
        query = query.order_by(Alert.created_at.asc())
    else:
        query = query.order_by(Alert.created_at.desc())

    alerts = query.limit(100).all()
    return [a.to_dict() for a in alerts]


# for the incident report
# ── INCIDENT REPORTS (ADMIN VIEW) ──────────────────────────────
def get_all_incident_reports():
    reports = IncidentReport.query.order_by(IncidentReport.submitted_at.desc()).all()
    result = []
    for r in reports:
        analyst = User.query.get(r.analyst_id)
        d = r.to_dict()
        d['submitted_by'] = f"{analyst.username}({analyst.role})" if analyst else "Unknown"
        result.append(d)
    return result