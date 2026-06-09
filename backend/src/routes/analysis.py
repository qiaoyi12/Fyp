from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from backend.src.database.db import db
from backend.src.database.models import UploadedFile
from backend.src.ml.preprocess import preprocess_csv
from backend.src.ml.predict import predict, get_summary

analysis_bp = Blueprint('analysis', __name__)


@analysis_bp.route('/analyse/<int:file_id>', methods=['POST'])
@jwt_required()
def analyse(file_id):
    user_id = get_jwt_identity()

    upload = UploadedFile.query.filter_by(id=file_id, user_id=user_id).first()
    if not upload:
        return jsonify({'error': 'File not found'}), 404

    # Preprocess
    X, error = preprocess_csv(upload.filepath)
    if error:
        return jsonify({'error': error}), 422

    # Predict
    results = predict(X)
    summary = get_summary(results)
     # DEBUG — remove after testing
    print("=== ANALYSIS DEBUG ===")
    print("Total rows:", len(results))
    print("Summary:", summary)
    print("First 5 predictions:", results[:5])
    print("======================")

    return jsonify({
        'file_id':     file_id,
        'filename':    upload.filename,
        'total_rows':  len(results),
        'summary':     summary,
        'predictions': results[:100]  # cap response at 100 rows
    }), 200

