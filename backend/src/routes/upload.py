import os
import pandas as pd
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from backend.src.database.db import db
from backend.src.database.models import UploadedFile

upload_bp = Blueprint('upload', __name__)

ALLOWED_EXTENSIONS = {'csv'}

REQUIRED_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Label'
]


# ── Shared helper — used by both API and pages route ──────────
def save_upload(files, user_id):
    """
    Handles file validation, saving, and DB record creation.
    Returns dict: { success, message, error, file_id, row_count }
    """
    if 'file' not in files:
        return {'success': False, 'error': 'No file in request'}

    file = files['file']

    if file.filename == '':
        return {'success': False, 'error': 'No file selected'}

    ext = file.filename.rsplit('.', 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return {'success': False, 'error': f'Only .csv files allowed, got .{ext}'}

    filename = secure_filename(file.filename)
    upload_folder = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)

    # Validate CSV
    try:
        df = pd.read_csv(filepath, nrows=5)
        df.columns = df.columns.str.strip()

        if df.empty:
            os.remove(filepath)
            return {'success': False, 'error': 'CSV file is empty'}

        missing_cols = [c for c in REQUIRED_COLUMNS if c not in df.columns]
        if missing_cols:
            os.remove(filepath)
            return {'success': False, 'error': f'Missing columns: {missing_cols}'}

        # Get full row count
        full_df = pd.read_csv(filepath)
        full_df.columns = full_df.columns.str.strip()
        row_count = len(full_df)

    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return {'success': False, 'error': f'Failed to read CSV: {str(e)}'}

    # Save to DB
    try:
        record = UploadedFile(
            filename=filename,
            filepath=filepath,
            row_count=row_count,
            is_valid=True,
            user_id=user_id
        )
        db.session.add(record)
        db.session.commit()
    except Exception as e:
        return {'success': False, 'error': f'DB error: {str(e)}'}

    return {
        'success': True,
        'message': f'{filename} uploaded · {row_count} rows saved',
        'file_id': record.id,
        'row_count': row_count
    }


# ── REST API endpoint (for future use) ────────────────────────
@upload_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_csv():
    user_id = get_jwt_identity()
    result = save_upload(request.files, user_id)

    if not result['success']:
        return jsonify({'error': result['error']}), 422

    return jsonify({
        'message':   result['message'],
        'file_id':   result['file_id'],
        'row_count': result['row_count']
    }), 200


# ── Get all uploads for current user ──────────────────────────
@upload_bp.route('/uploads', methods=['GET'])
@jwt_required()
def get_uploads():
    user_id = get_jwt_identity()
    uploads = UploadedFile.query.filter_by(user_id=user_id).order_by(
        UploadedFile.uploaded_at.desc()
    ).all()
    return jsonify({'uploads': [u.to_dict() for u in uploads]}), 200