# For database columns and tables
from datetime import datetime
from .db import db ,bcrypt

# for database tables

# user table
class User(db.Model):
    __tablename__ = 'users'

    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(80), unique=True, nullable=False)
    email      = db.Column(db.String(120), unique=True, nullable=False)

    # secure password storage
    password_hash = db.Column(db.String(255), nullable=False)

    # roles (to identify whether it is SOC Analyst or It Administrator)
    role       = db.Column(db.String(30), nullable=False, default='SOC Analyst')

    # analyst seniority tier ('junior' or 'senior'), used to route
    # higher-severity tickets to more senior analysts. Only meaningful
    # for role='analyst', but kept on the base table since there's no
    # per-role subclassing here.
    level      = db.Column(db.String(20), nullable=False, default='junior')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # for users to upload more than 1 file
    uploads = db.relationship('UploadedFile', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'level': self.level,
            'created_at': self.created_at.isoformat()
        }
    

# file table
class UploadedFile(db.Model):
    __tablename__ = 'uploaded_files'

    id          = db.Column(db.Integer, primary_key=True)
    filename    = db.Column(db.String(255), nullable=False)
    filepath    = db.Column(db.String(500), nullable=False)
    row_count   = db.Column(db.Integer)
    is_valid    = db.Column(db.Boolean, default=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def to_dict(self):
        return {
            'id':          self.id,
            'filename':    self.filename,
            'row_count':   self.row_count,
            'is_valid':    self.is_valid,
            'uploaded_at': self.uploaded_at.isoformat(),
            'user_id':     self.user_id
        }


# for uploaded files dashboard
class AnalysisResult(db.Model):
    __tablename__ = 'analysis_results'

    id          = db.Column(db.Integer, primary_key=True)
    file_id     = db.Column(db.Integer, db.ForeignKey('uploaded_files.id'), nullable=False)
    file_ids    = db.Column(db.Text)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    total_rows  = db.Column(db.Integer, default=0)
    high_count  = db.Column(db.Integer, default=0)
    medium_count= db.Column(db.Integer, default=0)
    normal_count= db.Column(db.Integer, default=0)
    benign      = db.Column(db.Integer, default=0)
    web_attack  = db.Column(db.Integer, default=0)
    dos         = db.Column(db.Integer, default=0)
    ddos        = db.Column(db.Integer, default=0)
    portscan    = db.Column(db.Integer, default=0)
    bot         = db.Column(db.Integer, default=0)
    rare        = db.Column(db.Integer, default=0)
    analysed_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_stats = db.Column(db.Text)  # JSON-encoded per-IP attack counts for the full upload

    assignments = db.relationship('AnalysisAssignment', backref='analysis', lazy=True)


# links an analysis run to the SOC Analyst it was assigned to 
class AnalysisAssignment(db.Model):
    __tablename__ = 'analysis_assignments'

    id          = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analysis_results.id'), nullable=False)
    analyst_id  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    manager_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  
    assigned_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'analysis_id': self.analysis_id,
            'analyst_id': self.analyst_id,
            'manager_id': self.manager_id,
            'assigned_by': self.assigned_by,
            'assigned_at': self.assigned_at.strftime('%Y-%m-%d %H:%M'),
        }

    analyst = db.relationship('User', foreign_keys=[analyst_id])
    manager = db.relationship('User', foreign_keys=[manager_id])
    

# for the alerts feed page
class Alert(db.Model):
    xgb_vote = db.Column(db.String(50))
    rf_vote  = db.Column(db.String(50))
    __tablename__ = 'alerts'

    id             = db.Column(db.Integer, primary_key=True)
    analysis_id    = db.Column(db.Integer, db.ForeignKey('analysis_results.id'), nullable=False)
    user_id        = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    row_index      = db.Column(db.Integer)
    ticket_id      = db.Column(db.Integer)
    # prediction of attack
    prediction     = db.Column(db.String(50))
    severity       = db.Column(db.String(20))
    confidence     = db.Column(db.Float)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    # for packet info feature
    dest_port      = db.Column(db.Integer)
    flow_duration  = db.Column(db.Float)
    flow_pkts_s    = db.Column(db.Float)
    source_ip      = db.Column(db.String(45))
    dest_ip        = db.Column(db.String(45))
    tag = db.Column(db.String(30), default="Unreviewed")
    remarks        = db.Column(db.Text, default='')

    # per-ticket assignment (separate from AnalysisAssignment, which assigns
    # a whole analysis run to a manager - this assigns one alert to one analyst)
    assigned_analyst_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    assignment_source   = db.Column(db.String(20), nullable=True)   # 'agent' or 'manual'
    assignment_reason   = db.Column(db.Text, nullable=True)
    assigned_at         = db.Column(db.DateTime, nullable=True)

    assigned_analyst = db.relationship('User', foreign_keys=[assigned_analyst_id])

    detail = db.relationship(
        "AlertDetail",
        backref="alert",
        uselist=False,
        cascade="all, delete-orphan"
    )

    def to_dict(self):
        reason = {
            'PortScan':    f'Port probing on port {self.dest_port} · {self.flow_pkts_s} pkts/s',
            'DoS':         f'Flood traffic · {self.flow_pkts_s} pkts/s over {self.flow_duration}ms',
            'DDoS':        f'Distributed flood · {self.flow_pkts_s} pkts/s',
            'Web Attack':  f'Malicious payload on port {self.dest_port}',
            'Bot/Patator': f'Automated attack on port {self.dest_port} · {self.flow_pkts_s} pkts/s',
            'Rare/Others': f'Anomalous flow on port {self.dest_port}',
            'BENIGN':      'Normal traffic'
        }.get(self.prediction, 'Unknown pattern')

        return {
            'id':          self.id,
            'ticket'    :  self.ticket_id,
            'prediction':  self.prediction,
            'severity':    self.severity,
            'confidence':  self.confidence,
            'time':        self.created_at.strftime('%H:%M'),
            'created_at':  self.created_at.isoformat(),
            'dest_port':   self.dest_port,
            'flow_pkts_s': self.flow_pkts_s,
            'source_ip':   self.source_ip,
            'dest_ip':     self.dest_ip,
            'reason':      reason,
            'row_index':   self.row_index,
            'xgb_vote':    self.xgb_vote,
            'rf_vote':     self.rf_vote,
            'consensus':   '✓ Consensus' if self.xgb_vote == self.rf_vote else '⚠ Conflict',
            'tag':         self.tag,
            'remarks':     self.remarks or ''
        }
    
#alert details model
class AlertDetail(db.Model):
    __tablename__ = "alert_details"

    id = db.Column(db.Integer, primary_key=True)

    alert_id = db.Column(
        db.Integer,
        db.ForeignKey("alerts.id"),
        nullable=False,
        unique=True
    )

    flow_bytes_s = db.Column(db.Float)

    total_backward_packets = db.Column(db.Integer)

    packet_length_mean = db.Column(db.Float)
    average_packet_size = db.Column(db.Float)

    ack_flag_count = db.Column(db.Integer)
    psh_flag_count = db.Column(db.Integer)

    init_win_bytes_forward = db.Column(db.Integer)
    init_win_bytes_backward = db.Column(db.Integer)

    packet_length_max = db.Column(db.Float)
    packet_length_std = db.Column(db.Float)
    bwd_iat_max = db.Column(db.Float)

# top attacking source ip addresses the IT Admin maintains alerts from these IPs
# get flagged as a blacklist match in the Report Analysis page.
class IPBlacklist(db.Model):
    __tablename__ = 'ip_blacklist'

    id          = db.Column(db.Integer, primary_key=True)
    ip_address  = db.Column(db.String(45), unique=True, nullable=False)
    reason      = db.Column(db.String(255))
    added_by    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    added_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            # use this for time now as we dont have the exact time stamp
            'added_at': self.added_at.strftime('%Y-%m-%d %H:%M'),
        }

# for all traffic logs saved 
class TrafficLog(db.Model):
    __tablename__ = 'traffic_logs'

    id            = db.Column(db.Integer, primary_key=True)
    analysis_id   = db.Column(db.Integer, db.ForeignKey('analysis_results.id'), nullable=False)
    user_id       = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    row_index     = db.Column(db.Integer)
    source_ip     = db.Column(db.String(45))
    dest_ip       = db.Column(db.String(45))
    dest_port     = db.Column(db.Integer)
    prediction    = db.Column(db.String(50))
    severity      = db.Column(db.String(20))
    confidence    = db.Column(db.Float)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':          self.id,
            'timestamp':   self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'source':      self.source_ip or '—',
            'destination': f'{self.dest_ip}:{self.dest_port}' if self.dest_ip and self.dest_port else '—',
            'type':        self.prediction,
            'protocol':    'TCP',
            'severity':    self.severity,
            'flagged':     self.severity in ('high', 'medium'),
        }