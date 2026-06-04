from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..database.models import UploadedFile

analysis_bp = Blueprint('analysis', __name__)


# ── Placeholder: will call predict.py once model is ready ─────
@analysis_bp.route('/analyse/<int:file_id>', methods=['POST'])
@jwt_required()
def analyse(file_id):
    user_id = get_jwt_identity()

    upload = UploadedFile.query.filter_by(id=file_id, user_id=user_id).first()
    if not upload:
        return jsonify({'error': 'File not found or not yours'}), 404

    # TODO: call predict.py here once XGBoost model is integrated
    return jsonify({
        'message': f'Analysis for file {upload.filename} will run here',
        'file_id': file_id
    }), 200
