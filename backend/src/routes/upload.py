# File handling for uploading one or many CSV files.
import os
import pandas as pd
from flask import Blueprint, request, jsonify, current_app, session
from werkzeug.utils import secure_filename
from backend.src.database.db import db
from backend.src.database.models import UploadedFile

from functools import wraps


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated


upload_bp = Blueprint('upload', __name__)

ALLOWED_EXTENSIONS = {'csv'}

REQUIRED_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Fwd Packet Length Mean',
    'Bwd Packet Length Mean', 'Fwd Packets/s', 'Bwd Packets/s',
    'SYN Flag Count', 'ACK Flag Count', 'PSH Flag Count',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward'
]


# Shared helper used by both API and page routes.
def save_upload(files, user_id):
    if hasattr(files, 'getlist'):
        file_items = files.getlist('files') or files.getlist('file')
    else:
        file_items = []

    if not file_items and isinstance(files, dict):
        if 'files' in files:
            file_items = files['files'] if isinstance(files['files'], list) else [files['files']]
        elif 'file' in files:
            file_items = [files['file']]

    if not file_items:
        return {'success': False, 'error': 'No file in request'}

    upload_folder = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)

    saved_records = []
    errors = []

    for file in file_items:
        if not hasattr(file, 'filename') or file.filename == '':
            continue

        ext = file.filename.rsplit('.', 1)[-1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            errors.append(f'Only .csv files allowed, got .{ext}')
            continue

        filename = secure_filename(file.filename)
        filepath = os.path.join(upload_folder, filename)
        if os.path.exists(filepath):
            base, ext_name = os.path.splitext(filename)
            filepath = os.path.join(upload_folder, f'{base}_{len(saved_records) + 1}{ext_name}')

        file.save(filepath)

        try:
            df = pd.read_csv(filepath, nrows=5)
            df.columns = df.columns.str.strip()

            if df.empty:
                os.remove(filepath)
                errors.append(f'{file.filename} is empty')
                continue

            missing_cols = [c for c in REQUIRED_COLUMNS if c not in df.columns]
            if missing_cols:
                os.remove(filepath)
                errors.append(f'{file.filename} is missing columns: {missing_cols}')
                continue

            full_df = pd.read_csv(filepath)
            full_df.columns = full_df.columns.str.strip()
            row_count = len(full_df)
        except Exception as e:
            if os.path.exists(filepath):
                os.remove(filepath)
            errors.append(f'{file.filename} failed: {str(e)}')
            continue

        try:
            record = UploadedFile(
                filename=os.path.basename(filepath),
                filepath=filepath,
                row_count=row_count,
                is_valid=True,
                user_id=user_id
            )
            db.session.add(record)
            db.session.commit()
            saved_records.append(record)
        except Exception as e:
            errors.append(f'{file.filename} DB error: {str(e)}')

    if not saved_records:
        return {'success': False, 'error': errors[0] if errors else 'No valid files uploaded'}

    message = f'Uploaded {len(saved_records)} file(s)'
    if errors:
        message += f' · {len(errors)} skipped'

    return {
        'success': True,
        'message': message,
        'results': saved_records,
        'row_count': sum(r.row_count or 0 for r in saved_records),
    }


@upload_bp.route('/upload', methods=['POST'])
@login_required
def upload_csv():
    user_id = session['user_id']
    result = save_upload(request.files, user_id)

    if not result['success']:
        return jsonify({'error': result['error']}), 422

    return jsonify({
        'message': result['message'],
        'files': [r.id for r in result.get('results', [])],
        'row_count': result['row_count'],
    }), 200


@upload_bp.route('/uploads', methods=['GET'])
@login_required
def get_uploads():
    user_id = session['user_id']
    uploads = UploadedFile.query.filter_by(user_id=user_id).order_by(
        UploadedFile.uploaded_at.desc()
    ).all()
    return jsonify({'uploads': [u.to_dict() for u in uploads]}), 200