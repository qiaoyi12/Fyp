
from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from backend.src.database.db import db
from backend.src.database.models import UploadedFile, AnalysisResult, Alert
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

    X, error = preprocess_csv(upload.filepath)
    if error:
        return jsonify({'error': error}), 422

    results = predict(X)
    summary = get_summary(results)

    by_label = summary['by_label']
    by_sev   = summary['by_severity']
    record = AnalysisResult(
        file_id      = file_id,
        user_id      = user_id,
        total_rows   = len(results),
        benign       = by_label['BENIGN'],
        web_attack   = by_label['Web Attack'],
        dos          = by_label['DoS'],
        ddos         = by_label['DDoS'],
        portscan     = by_label['PortScan'],
        bot          = by_label['Bot/Patator'],
        rare         = by_label['Rare/Others'],
        high_count   = by_sev['high'],
        medium_count = by_sev['medium'],
        normal_count = by_sev['normal'],
    )
    db.session.add(record)
    db.session.commit()

    # Save top 100 high/medium alerts by confidence
    # Save top 50 high + top 50 medium alerts by confidence
    high_alerts   = sorted([r for r in results if r['severity'] == 'high'],   key=lambda x: x['confidence'], reverse=True)[:50]
    medium_alerts = sorted([r for r in results if r['severity'] == 'medium'], key=lambda x: x['confidence'], reverse=True)[:50]

    for r in high_alerts + medium_alerts:
        alert = Alert(
            analysis_id = record.id,
            user_id     = user_id,
            row_index   = r['row'],
            prediction  = r['prediction'],
            severity    = r['severity'],
            confidence  = r['confidence'],
        )
        db.session.add(alert)

    db.session.commit()

    return jsonify({
        'file_id':     file_id,
        'filename':    upload.filename,
        'total_rows':  len(results),
        'summary':     summary,
        'predictions': results[:100]
    }), 200