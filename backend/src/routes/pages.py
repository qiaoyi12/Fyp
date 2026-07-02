# it handles the routing on the web pages, connect the frontend with the backend

from flask import Blueprint, render_template, request, session, redirect, url_for
from functools import wraps
from backend.src.database.models import User
from backend.src.database.db import db  
from backend.src.services import data_service
from backend.src.routes.upload import save_upload
from datetime import datetime

pages_bp = Blueprint('pages', __name__)

def _parse_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except ValueError:
        return None

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
        if session.get('role') != 'admin':  # change this to 'IT Administrator' later
            return redirect(url_for('pages.dashboard'))
        return f(*args, **kwargs)
    return decorated


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
        username = request.form.get('username')
        password = request.form.get('password')
        role     = request.form.get('role')

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            error = 'Invalid username or password.'
        elif user.role != role:
            error = f'This account is not registered as {role}.'
        else:
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
    # not sure later check
    record, error, metrics = data_service.run_analysis(file_ids, session['user_id'])
    if error:
        return redirect(url_for('pages.upload'))
    session['last_model_metrics'] = metrics or {}
    return redirect(url_for('pages.dashboard'))


@pages_bp.route('/analyse/<int:file_id>', methods=['POST'])
@admin_required
def analyse_file(file_id):
    record, error, metrics = data_service.run_analysis([file_id], session['user_id'])
    if error:
        return redirect(url_for('pages.upload'))
    session['last_model_metrics'] = metrics or {}
    return redirect(url_for('pages.dashboard'))


@pages_bp.route('/dashboard')
@login_required
def dashboard():
    # SOC Analysts only see data from analyses assigned to them
    high_alerts, threat_distribution, metrics = data_service.get_dashboard_data(
        session['user_id'], session['role']
    )
    if session.get('last_model_metrics'):
        metrics['model_accuracy'] = f"{session['last_model_metrics'].get('accuracy', 0)}%"
        metrics['response_time'] = f"{session['last_model_metrics'].get('precision', 0)}%"
    return render_template('dashboard.html',
        metrics=metrics, high_alerts=high_alerts,
        threat_distribution=threat_distribution,
        user=session['user'], role=session['role'])


@pages_bp.route('/alerts')
@login_required
def alert_feed():
    severity = request.args.get('severity', 'all')
    attack_type = request.args.get('type', 'all')
    alerts = data_service.get_alert_feed(
        session['user_id'], session['role'], severity, attack_type
    )
    return render_template('alert_feed.html',
        alerts=alerts, severity=severity, attack_type=attack_type,
        user=session['user'], role=session['role'])


@pages_bp.route('/alerts/<int:alert_id>')
@login_required
def threat_detail(alert_id):
    alert = data_service.get_alert_detail(session['user_id'], session['role'], alert_id)
    if not alert:
        return redirect(url_for('pages.alert_feed'))
    return render_template('threat_detail.html',
        alert=alert.to_dict(), user=session['user'], role=session['role'])


@pages_bp.route('/logs')
@login_required
def logs():
    filter_type = request.args.get('filter', 'all')
    search = request.args.get('search', '')
    logs_data, total = data_service.get_logs(
        session['user_id'], session['role'], filter_type
    )
    return render_template('log_viewer.html',
        logs=logs_data, total=total, filter_type=filter_type, search=search,
        user=session['user'], role=session['role'])


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


@pages_bp.route('/metrics')
@admin_required
def model_metrics():
    metrics = session.get('last_model_metrics', {})
    if not metrics:
        metrics = {'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0, 'f1_score': 0.0}
    payload = {
        'accuracy':  metrics.get('accuracy', 0.0),
        'precision': metrics.get('precision', 0.0),
        'recall':    metrics.get('recall', 0.0),
        'f1_score':  metrics.get('f1_score', 0.0),
        # change this part is for plceholder now
        'weekly': [
            int(metrics.get('accuracy', 0.0)),
            int(metrics.get('accuracy', 0.0)) + 1,
            int(metrics.get('accuracy', 0.0)) + 2,
            int(metrics.get('accuracy', 0.0)) + 1,
            int(metrics.get('accuracy', 0.0)) + 3,
            int(metrics.get('accuracy', 0.0)) + 2,
            int(metrics.get('accuracy', 0.0)) + 4,
        ],
        'days': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        'confusion': {'tp': 4821, 'fp': 287, 'fn': 421, 'tn': 43291}
    }
    return render_template('model_metrics.html',
        metrics=payload, user=session['user'], role=session['role'])


@pages_bp.route('/assign', methods=['GET'])
@admin_required
def assign():
    analyses = data_service.get_analyses_for_assignment(session['user_id'])
    analysts = data_service.get_all_analysts()
    message = request.args.get('message')
    error = request.args.get('error')
    return render_template('assign.html',
        analyses=analyses, analysts=analysts,
        message=message, error=error,
        active_page='assign', user=session['user'], role=session['role'])


@pages_bp.route('/assign', methods=['POST'])
@admin_required
def assign_submit():
    analysis_id = request.form.get('analysis_id')
    analyst_ids = request.form.getlist('analyst_ids')
    if not analysis_id or not analyst_ids:
        return redirect(url_for('pages.assign', error='Please select an analysis and at least one analyst.'))
    data_service.assign_analysis(
        analysis_id=int(analysis_id),
        analyst_ids=[int(i) for i in analyst_ids],
        assigned_by=session['user_id']
    )
    return redirect(url_for('pages.assign', message='Analysis successfully assigned.'))

@pages_bp.route('/assign/remove', methods=['POST'])
@admin_required
def unassign():
    analysis_id = request.form.get('analysis_id')
    analyst_id = request.form.get('analyst_id')
    if analysis_id and analyst_id:
        data_service.remove_assignment(int(analysis_id), int(analyst_id))
    return redirect(url_for('pages.assign'))


@pages_bp.route('/report')
@login_required
def report_analysis():
    date_from = _parse_date(request.args.get('from'))
    date_to = _parse_date(request.args.get('to'))
    report = data_service.get_report_data(
        session['user_id'], session['role'],
        date_from=date_from, date_to=date_to
    )
    return render_template('report_analysis.html',
        report=report,
        date_from=request.args.get('from', ''), date_to=request.args.get('to', ''),
        active_page='report', user=session['user'], role=session['role'])


@pages_bp.route('/blacklist/add', methods=['POST'])
@admin_required
def blacklist_add():
    ip_address = request.form.get('ip_address', '').strip()
    reason = request.form.get('reason', '').strip()
    if ip_address:
        data_service.add_blacklist_ip(ip_address, reason, session['user_id'])
    return redirect(url_for('pages.report_analysis'))


@pages_bp.route('/blacklist/remove/<int:entry_id>', methods=['POST'])
@admin_required
def blacklist_remove(entry_id):
    data_service.remove_blacklist_ip(entry_id)
    return redirect(url_for('pages.report_analysis'))


@pages_bp.route('/blacklist/remove_by_ip', methods=['POST'])
@admin_required
def blacklist_remove_by_ip():
    ip_address = request.form.get('ip_address', '').strip()
    if ip_address:
        data_service.remove_blacklist_ip_by_address(ip_address)
    return redirect(url_for('pages.report_analysis'))