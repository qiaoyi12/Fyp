# this is used to import the ml model and come out with the dashboard threat type result
import os
import joblib
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

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
XGB_PATH     = os.path.join(PROJECT_ROOT, 'dataset', 'zann_dataset', 'xgboost_model.pkl')
RF_PATH = os.path.join(PROJECT_ROOT, 'dataset', 'zann_dataset', 'random_forest_model.pkl')
SCALER_PATH  = os.path.join(PROJECT_ROOT, 'dataset', 'zann_dataset', 'scaler.pkl')

# to load the ml and scalar model
xgb_model = joblib.load(XGB_PATH)
rf_model = joblib.load(RF_PATH)
scaler     = joblib.load(SCALER_PATH)


# x is noted as preprocess csv file and use xgb model to predict every row
def predict(X):
    X_scaled = scaler.transform(X)

    # XGBoost predictions
    xgb_proba   = xgb_model.predict_proba(X_scaled)
    xgb_preds   = np.argmax(xgb_proba, axis=1)
    xgb_conf    = np.max(xgb_proba, axis=1)

    # Random Forest predictions
    rf_proba    = rf_model.predict_proba(X_scaled)
    rf_preds    = np.argmax(rf_proba, axis=1)

# loop 
    results = []
    for i in range(len(xgb_preds)):
        xgb_label = LABEL_MAP[int(xgb_preds[i])]
        rf_label  = LABEL_MAP[int(rf_preds[i])]

        # Majority vote if both agree use that, else trust XGBoost
        if xgb_label == rf_label:
            final_label = xgb_label
        else:
            final_label = xgb_label  # XGB tiebreak

        severity = SEVERITY_MAP[final_label]

        results.append({
            'row':        i,
            'prediction': final_label,
            'severity':   severity,
            'confidence': round(float(xgb_conf[i]) * 100, 2),
            'xgb_vote':   xgb_label,
            'rf_vote':    rf_label,
        })

    return results


# loop to count the numbers for severity and prediction
def get_summary(results):
    summary = {label: 0 for label in LABEL_MAP.values()}
    severity_counts = {'normal': 0, 'medium': 0, 'high': 0}

    for r in results:
        summary[r['prediction']] += 1
        severity_counts[r['severity']] += 1

    return {'by_label': summary, 'by_severity': severity_counts}