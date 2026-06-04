import os
import pandas as pd
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from ..database.db import db
from ..database.models import UploadedFile

upload_bp = Blueprint('upload', __name__)

ALLOWED_EXTENSIONS = {'csv'}

# ── Minimum required columns from CIC-IDS-2017 ───────────────
# These are the core feature columns your model was trained on.
# Add or remove based on your actual trained model's feature list.
REQUIRED_COLUMNS = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Bwd Packet Length Mean',
    'Bwd Packet Length Std',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    'Label'
]


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_csv(filepath):
    """
    Validates the uploaded CSV file.
    Returns (is_valid: bool, message: str, row_count: int)
    """
    try:
        # Read just the header + a few rows to check quickly
        df = pd.read_csv(filepath, nrows=5)
    except Exception as e:
        return False, f'Cannot read CSV file: {str(e)}', 0

    # Strip whitespace from column names (CIC-IDS-2017 has leading spaces)
    df.columns = df.columns.str.strip()

    # Check for empty file
    if df.empty:
        return False, 'CSV file is empty', 0

    # Check required columns
    missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing_cols:
        return False, f'Missing required columns: {missing_cols}', 0

    # Get actual row count from full file
    try:
        full_df = pd.read_csv(filepath)
        full_df.columns = full_df.columns.str.strip()
        row_count = len(full_df)
    except Exception as e:
        return False, f'Error reading full CSV: {str(e)}', 0

    if row_count == 0:
        return False, 'CSV has no data rows', 0

    return True, f'Valid CSV with {row_count} rows', row_count


# ── Upload endpoint ───────────────────────────────────────────
@upload_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_csv():
    user_id = get_jwt_identity()

    # Check file exists in request
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Only .csv files are allowed'}), 400

    # Save file
    filename = secure_filename(file.filename)
    upload_folder = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)

    # Validate CSV
    is_valid, message, row_count = validate_csv(filepath)

    if not is_valid:
        os.remove(filepath)  # delete bad file
        return jsonify({'error': message}), 422

    # Save upload record to DB
    record = UploadedFile(
        filename=filename,
        filepath=filepath,
        row_count=row_count,
        is_valid=True,
        user_id=user_id
    )
    db.session.add(record)
    db.session.commit()

    return jsonify({
        'message':   message,
        'filename':  filename,
        'row_count': row_count,
        'file_id':   record.id
    }), 200


# ── Get all uploads for current user ─────────────────────────
@upload_bp.route('/uploads', methods=['GET'])
@jwt_required()
def get_uploads():
    user_id = get_jwt_identity()
    uploads = UploadedFile.query.filter_by(user_id=user_id).order_by(
        UploadedFile.uploaded_at.desc()
    ).all()

    return jsonify({
        'uploads': [u.to_dict() for u in uploads]
    }), 200
