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

# for the alerts feed page
class Alert(db.Model):
    __tablename__ = 'alerts'

    id             = db.Column(db.Integer, primary_key=True)
    analysis_id    = db.Column(db.Integer, db.ForeignKey('analysis_results.id'), nullable=False)
    user_id        = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    row_index      = db.Column(db.Integer)
    # prediction of attack
    prediction     = db.Column(db.String(50))
    severity       = db.Column(db.String(20))
    confidence     = db.Column(db.Float)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':         self.id,
            'prediction': self.prediction,
            'severity':   self.severity,
            'confidence': self.confidence,
            'time':       self.created_at.strftime('%H:%M'),
        }