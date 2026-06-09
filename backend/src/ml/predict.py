# 

import os
import pickle
import numpy as np

LABEL_MAP = {
    0: 'BENIGN',
    1: 'Web Attack',
    2: 'DoS',
    3: 'DDoS',
    4: 'PortScan',
    5: 'Bot/Patator',
    6: 'Rare/Others'
}

SEVERITY_MAP = {
    'BENIGN':      'normal',
    'Web Attack':  'high',
    'DoS':         'high',
    'DDoS':        'high',
    'PortScan':    'medium',
    'Bot/Patator': 'high',
    'Rare/Others': 'medium'
}

# Absolute path to models
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
XGB_PATH     = os.path.join(PROJECT_ROOT, 'dataset', 'zann_dataset', 'xgboost_model.pkl')
# RF_PATH      = os.path.join(PROJECT_ROOT, 'dataset', 'zann_dataset', 'random_forest_model.pkl')




# Load once at startup
with open(XGB_PATH, 'rb') as f:
    xgb_model = pickle.load(f)

# RF disabled until teammate fixes the pkl
# rf_model = None


def predict(X):
    xgb_proba   = xgb_model.predict_proba(X)
    predictions = np.argmax(xgb_proba, axis=1)
    confidence  = np.max(xgb_proba, axis=1)

    results = []
    for i, pred in enumerate(predictions):
        label    = LABEL_MAP[int(pred)]
        severity = SEVERITY_MAP[label]
        results.append({
            'row':        i,
            'prediction': label,
            'severity':   severity,
            'confidence': round(float(confidence[i]) * 100, 2),
            'xgb_vote':   label,
            'rf_vote':    'N/A (model pending)',
        })

    return results


def get_summary(results):
    """
    Summarises prediction results into counts per label and severity.
    """
    summary = {label: 0 for label in LABEL_MAP.values()}
    severity_counts = {'normal': 0, 'medium': 0, 'high': 0}

    for r in results:
        summary[r['prediction']] += 1
        severity_counts[r['severity']] += 1

    return {'by_label': summary, 'by_severity': severity_counts}