# it handles the routing on the web pages, connect the frontend with the backend

from flask import Blueprint, render_template, request, session, redirect, url_for
from functools import wraps
from backend.src.database.models import User, TrafficLog
from backend.src.database.db import db  
from backend.src.services import data_service
from backend.src.routes.upload import save_upload
from datetime import datetime
from flask import flash
from collections import defaultdict
from datetime import datetime, timedelta

# Tracks failed attempts per IP
login_attempts = defaultdict(list)

MAX_ATTEMPTS = 5
WINDOW_MINUTES = 1

pages_bp = Blueprint('pages', __name__)

def _parse_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except ValueError:
        return None


# for credentials
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('pages.login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('pages.login'))
        if session.get('role') != 'admin': 
            return redirect(url_for('pages.dashboard'))
        return f(*args, **kwargs)
    return decorated


# for manager role required check if working
def manager_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('pages.login'))
        if session.get('role') != 'manager':
            return redirect(url_for('pages.dashboard'))
        return f(*args, **kwargs)
    return decorated



# for login and register credentials
@pages_bp.route('/register', methods=['GET', 'POST'])
def register():
    error = success = None
    if request.method == 'POST':
        username = request.form.get('username')
        email    = request.form.get('email')
        password = request.form.get('password')
        confirm  = request.form.get('confirm_password')
        role     = request.form.get('role', 'SOC Analyst')

        if not username or not email or not password:
            error = 'All fields are required.'
        elif not (3 <= len(username) <= 20):
            error = 'Username must be between 3 and 20 characters.'
        elif not username.isalnum():
            error = 'Username must contain only letters and numbers.'
        elif not (8 <= len(password) <= 72):
            error = 'Password must be between 8 and 72 characters.'
        elif password != confirm:
            error = 'Passwords do not match.'
        elif User.query.filter_by(username=username).first():
            error = 'Username already exists.'
        elif User.query.filter_by(email=email).first():
            error = 'Email already registered.'
        else:
            user = User(username=username, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            success = f'Account created for {username}. You can now log in.'

    return render_template('register.html', error=error, success=success)


@pages_bp.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('pages.dashboard'))
    return redirect(url_for('pages.login'))


@pages_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        ip = request.remote_addr
        now = datetime.now()

        # 1. Clean out old attempts outside the window
        login_attempts[ip] = [t for t in login_attempts[ip] if now - t < timedelta(minutes=WINDOW_MINUTES)]

        # 2. Check lockout BEFORE checking credentials
        if len(login_attempts[ip]) >= MAX_ATTEMPTS:
            error = 'Too many failed attempts. Please try again later.'
            return render_template('login.html', error=error)

        username = request.form.get('username')
        password = request.form.get('password')
        role     = request.form.get('role')

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            error = 'Invalid username or password.'
            login_attempts[ip].append(now)   # 3. record the failure
        elif user.role != role:
            error = f'This account is not registered as {role}.'
            login_attempts[ip].append(now)
        else:
            login_attempts[ip].clear()       # 4. reset on success
            session['user']    = user.username
            session['role']    = user.role
            session['user_id'] = user.id
            return redirect(url_for('pages.dashboard'))

    return render_template('login.html', error=error)

@pages_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('pages.login'))


# admin required is only for soc analysts
@pages_bp.route('/analyse', methods=['POST'])
@admin_required
def analyse_selected_files():
    file_ids = request.form.getlist('file_ids')

    if not file_ids:
        return redirect(url_for('pages.upload'))

    record, error, metrics = data_service.run_analysis(file_ids, session['user_id'])

    if error:
        return redirect(url_for('pages.upload'))

    session['last_model_metrics'] = metrics or {}

    flash("Analysis completed successfully!")

    return redirect(url_for('pages.dashboard'))


# for analyse of csv files for admin
@pages_bp.route('/analyse/<int:file_id>', methods=['POST'])
@admin_required
def analyse_file(file_id):
    record, error, metrics = data_service.run_analysis([file_id], session['user_id'])
    if error:
        return redirect(url_for('pages.upload'))
    session['last_model_metrics'] = metrics or {}
    return redirect(url_for('pages.dashboard'))

# for dashboard
@pages_bp.route('/dashboard')
@login_required
def dashboard():
    attack_type = request.args.get('type', 'all')
    

    high_alerts, threat_distribution, metrics = data_service.get_dashboard_data(
        session['user_id'], session['role'], attack_type
    )
    if session.get('last_model_metrics'):
        metrics['model_accuracy'] = f"{session['last_model_metrics'].get('accuracy', 0)}%"
        response_seconds = session['last_model_metrics'].get('response_time_seconds')
        metrics['response_time'] = f"{response_seconds}s" if response_seconds is not None else 'N/A'
    no_assignments = data_service.has_no_assignments(session['user_id'], session['role'])
    return render_template('dashboard.html',
        metrics=metrics, high_alerts=high_alerts,
        threat_distribution=threat_distribution,
        no_assignments=no_assignments,
        attack_type=attack_type,
        user=session['user'], role=session['role'])

@pages_bp.route('/alerts')
@login_required
def alert_feed():
    severity = request.args.get('severity', 'all')
    attack_type = request.args.get('type', 'all')
    sort = request.args.get('sort', 'newest')
    ip = request.args.get('ip', None)

    alerts = data_service.get_alert_feed(
        session['user_id'], session['role'], severity, attack_type, sort, ip=ip
    )

    traffic_log_count = None                                         
    if ip:                                                            
        traffic_log_count = data_service.get_traffic_log_count_by_ip( 
            session['user_id'], session['role'], ip)                  

    no_assignments = data_service.has_no_assignments(session['user_id'], session['role'])
    return render_template('alert_feed.html',
        alerts=alerts, severity=severity, attack_type=attack_type, sort=sort,
        ip=ip, traffic_log_count=traffic_log_count,               
        no_assignments=no_assignments,
        user=session['user'], role=session['role'])


@pages_bp.route('/alerts/<int:alert_id>')
@login_required
def threat_detail(alert_id):

    result = data_service.get_alert_detail(
        session['user_id'],
        session['role'],
        alert_id
    )

    if not result:
        return redirect(url_for('pages.alert_feed'))

    return render_template(
        "threat_detail.html",
        alert=result["alert"],
        detail=result["detail"],
        user=session["user"],
        role=session["role"]
    )


from flask import request
# alert tag status and remarks update
@pages_bp.route('/alerts/<int:alert_id>/tag', methods=['POST'])
@login_required
def update_alert_tag(alert_id):
    tag = request.form.get("tag")

    data_service.update_alert_tag(alert_id, tag)

    return redirect(request.referrer or url_for('pages.alert_feed'))

@pages_bp.route('/alerts/<int:alert_id>/remarks', methods=['POST'])
@login_required
def update_alert_remarks(alert_id):
    remarks = request.form.get('remarks', '')
    data_service.update_alert_remarks(alert_id, remarks)
    return redirect(request.referrer or url_for('pages.alert_feed'))


# logs section
@pages_bp.route('/logs')
@login_required
def logs():
    filter_type = request.args.get('filter', 'all')
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    logs_data, total = data_service.get_logs(
        session['user_id'], session['role'], filter_type, search=search, page=page
    )
    no_assignments = data_service.has_no_assignments(session['user_id'], session['role'])
    return render_template('log_viewer.html',
        logs=logs_data, total=total, filter_type=filter_type, search=search,
        no_assignments=no_assignments,
        user=session['user'], role=session['role'])

@pages_bp.route('/logs/<int:log_id>/analyze', methods=['POST'])
@login_required
def request_log_detail(log_id):
    traffic_log = TrafficLog.query.get_or_404(log_id)
    alert = data_service.create_alert_from_traffic_log(traffic_log)
    return redirect(url_for('pages.threat_detail', alert_id=alert.id))

# route to upload of csv files for admin
@pages_bp.route('/upload', methods=['GET', 'POST'])
@admin_required
def upload():
    message = error = None
    if request.method == 'POST':
        result = save_upload(request.files, user_id=session['user_id'])
        if result['success']:
            message = result['message']
        else:
            error = result['error']
    history = data_service.get_upload_history(session['user_id'])
    return render_template('upload.html',
        message=message, error=error, history=history,
        user=session['user'], role=session['role'])



# assignment section for admin to assign analysis to analysts and managers
@pages_bp.route('/assign-manager', methods=['GET'])
@admin_required
def assign_manager():
    analyses = data_service.get_analyses_for_assignment(session['user_id'])
    managers = data_service.get_all_managers()
    message = request.args.get('message')
    error = request.args.get('error')
    return render_template('assignManager.html',
        analyses=analyses, managers=managers,
        message=message, error=error,
        active_page='assign_manager', user=session['user'], role=session['role'])


@pages_bp.route('/assign-manager', methods=['POST'])
@admin_required
def assign_manager_submit():
    analysis_id = request.form.get('analysis_id')
    manager_id = request.form.get('manager_id')
    if not analysis_id or not manager_id:
        return redirect(url_for('pages.assign_manager', error='Please select an analysis and a manager.'))
    data_service.assign_to_manager(
        analysis_id=int(analysis_id),
        manager_id=int(manager_id),
        assigned_by=session['user_id']
    )
    return redirect(url_for('pages.assign_manager', message='Analysis successfully assigned to manager.'))


@pages_bp.route('/assign-manager/remove', methods=['POST'])
@admin_required
def unassign_manager():
    analysis_id = request.form.get('analysis_id')
    manager_id = request.form.get('manager_id')
    if analysis_id and manager_id:
        data_service.remove_assignment_manager(int(analysis_id), int(manager_id))
    return redirect(url_for('pages.assign_manager'))

# admin screen to set each analyst's seniority level (junior/senior),
# used by the AI assignment agent to route high-severity tickets to seniors
@pages_bp.route('/manage-analysts', methods=['GET'])
@admin_required
def manage_analysts():
    analysts = data_service.get_all_analysts()
    message = request.args.get('message')
    error = request.args.get('error')
    return render_template('manageAnalysts.html',
        analysts=analysts,
        message=message, error=error,
        active_page='manage_analysts', user=session['user'], role=session['role'])


@pages_bp.route('/manage-analysts/level', methods=['POST'])
@admin_required
def manage_analysts_set_level():
    analyst_id = request.form.get('analyst_id')
    level = request.form.get('level')
    if not analyst_id or level not in ('junior', 'senior'):
        return redirect(url_for('pages.manage_analysts', error='Please select a valid analyst and level.'))
    updated = data_service.update_analyst_level(int(analyst_id), level)
    if not updated:
        return redirect(url_for('pages.manage_analysts', error='Could not update that analyst.'))
    return redirect(url_for('pages.manage_analysts', message='Analyst level updated.'))


# for manager page assignment 
@pages_bp.route('/assign-analyst', methods=['GET'])
@login_required
@manager_required
def assign_analyst():
    analyses = data_service.get_analyses_for_manager_assignment(session['user_id'])
    analysts = data_service.get_all_analysts()
    message = request.args.get('message')
    error = request.args.get('error')
    return render_template('assignAnalyst.html',
        analyses=analyses, analysts=analysts,
        message=message, error=error,
        active_page='assign_analyst', user=session['user'], role=session['role'])


@pages_bp.route('/assign-analyst', methods=['POST'])
@manager_required
def assign_analyst_submit():
    analysis_id = request.form.get('analysis_id')
    analyst_ids = request.form.getlist('analyst_ids')
    if not analysis_id or not analyst_ids:
        return redirect(url_for('pages.assign_analyst', error='Please select an analysis and at least one analyst.'))
    for analyst_id in analyst_ids:
        ok = data_service.assign_to_analyst(
            analysis_id=int(analysis_id),
            analyst_id=int(analyst_id),
            assigned_by=session['user_id']
        )
        if not ok:
            return redirect(url_for('pages.assign_analyst', error='This analysis is not assigned to you.'))
    return redirect(url_for('pages.assign_analyst', message='Analysis successfully assigned to analyst(s).'))



@pages_bp.route('/assign-analyst/remove', methods=['POST'])
@manager_required
def unassign_analyst():
    analysis_id = request.form.get('analysis_id')
    analyst_id = request.form.get('analyst_id')
    if analysis_id and analyst_id:
        data_service.remove_assignment_analyst(int(analysis_id), int(analyst_id), manager_id=session['user_id'])
    return redirect(url_for('pages.assign_analyst'))



@pages_bp.route('/assign-analyst/auto', methods=['POST'])
@login_required
@manager_required
def auto_assign_analyst():
    analysis_id = request.form.get('analysis_id')
    if not analysis_id:
        return redirect(url_for('pages.assign_analyst', error='Please select an analysis first.'))

    result = data_service.trigger_auto_assignment(int(analysis_id), session['user_id'])

    if 'error' in result:
        return redirect(url_for('pages.assign_analyst', error=result['error']))

    return redirect(url_for('pages.assign_analyst', message=result['agent_summary']))


# top attacking IPs section for admin to view the top attacking IPs
@pages_bp.route('/attackingIPS')
@login_required
def attacking_ips():
    date_from = _parse_date(request.args.get('from'))
    date_to = _parse_date(request.args.get('to'))

    attacking_ips = data_service.get_report_data(
        session['user_id'],
        session['role'],
        date_from=date_from,
        date_to=date_to
    )

    no_assignments = data_service.has_no_assignments(
        session['user_id'],
        session['role']
    )

    return render_template(
        'attacking_ips.html',
        attacking_ips=attacking_ips,
        no_assignments=no_assignments,
        date_from=request.args.get('from', ''),
        date_to=request.args.get('to', ''),
        active_page='attackingIPS',
        user=session['user'],
        role=session['role']
    )

# blacklist section for admin
@pages_bp.route('/blacklist/add', methods=['POST'])
@admin_required
def blacklist_add():
    ip_address = request.form.get('ip_address', '').strip()
    reason = request.form.get('reason', '').strip()
    if ip_address:
        data_service.add_blacklist_ip(ip_address, reason, session['user_id'])
    return redirect(url_for('pages.attacking_ips'))


@pages_bp.route('/blacklist/remove/<int:entry_id>', methods=['POST'])
@admin_required
def blacklist_remove(entry_id):
    data_service.remove_blacklist_ip(entry_id)
    return redirect(url_for('pages.attacking_ips'))


@pages_bp.route('/blacklist/remove_by_ip', methods=['POST'])
@admin_required
def blacklist_remove_by_ip():
    ip_address = request.form.get('ip_address', '').strip()
    if ip_address:
        data_service.remove_blacklist_ip_by_address(ip_address)
    return redirect(url_for('pages.attacking_ips'))

# resolved page 
@pages_bp.route('/resolved')
@login_required
def resolved_tickets():
    severity = request.args.get('severity', 'all')
    attack_type = request.args.get('type', 'all')
    sort = request.args.get('sort', 'newest')

    tickets = data_service.get_resolved_tickets(
        session['user_id'], session['role'], severity, attack_type, sort
    )

    return render_template(
        'resolved.html',
        alerts=tickets,
        severity=severity,
        attack_type=attack_type,
        sort=sort,
        user=session['user'], role=session['role']
    )



# insights page for admin to view the insights of the analysis
@pages_bp.route('/insights')
@login_required
@admin_required   
def attack_overview():
    data = data_service.get_attack_overview(session['user_id'], session['role'], days=7)
    return render_template('insights.html',
        overview=data,
        user=session['user'], role=session['role'])

# incident report page only availble to the admin
# pages.py
@pages_bp.route('/incident-reports')
@login_required
@admin_required
def incident_reports():
    reports = data_service.get_all_incident_reports()
    return render_template('incident_reports.html', 
        reports=reports, user=session['user'], role=session['role'])