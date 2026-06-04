from datetime import datetime
from .db import db


class User(db.Model):
    __tablename__ = 'users'

    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(80),  unique=True, nullable=False)
    email      = db.Column(db.String(120), unique=True, nullable=False)
    password   = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # one user can have many uploads
    uploads = db.relationship('UploadedFile', backref='owner', lazy=True)

    def to_dict(self):
        return {
            'id':         self.id,
            'username':   self.username,
            'email':      self.email,
            'created_at': self.created_at.isoformat()
        }


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
