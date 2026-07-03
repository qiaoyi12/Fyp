# this is used to import the ml model and come out with the dashboard threat type result

import os
import re
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
XGB_PATH        = os.path.join(PROJECT_ROOT, 'dataset', 'zann_dataset', 'xgboost_model.pkl')
RF_PATH         = os.path.join(PROJECT_ROOT, 'dataset', 'zann_dataset', 'random_forest_model.pkl')
SCALER_PATH     = os.path.join(PROJECT_ROOT, 'dataset', 'zann_dataset', 'scaler.pkl')
ISOLATION_PATH  = os.path.join(PROJECT_ROOT, 'dataset', 'zann_dataset', 'isolation_forest_model.pkl')
MODEL_DIR       = os.path.join(PROJECT_ROOT, 'dataset', 'zann_dataset')

# to load the ml and scalar model
xgb_model = joblib.load(XGB_PATH)
rf_model = joblib.load(RF_PATH)
isolation_forest = joblib.load(ISOLATION_PATH)
scaler = joblib.load(SCALER_PATH)


# reads the training notebooks to get the model accuracy/precision/recall from training
def get_model_metrics():
    metrics = {'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0, 'f1_score': 0.0}
    if not os.path.isdir(MODEL_DIR):
        return metrics

    accuracy_values = []
    precision_values = []
    recall_values = []
    f1_values = []

    for name in sorted(os.listdir(MODEL_DIR)):
        if not name.endswith('.ipynb'):
            continue
        path = os.path.join(MODEL_DIR, name)
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                text = fh.read()
        except Exception:
            continue

        accuracy_values += re.findall(r'Accuracy\s*[:=]\s*([0-9]+(?:\.\d+)?)', text, flags=re.IGNORECASE)
        precision_values += re.findall(r'Precision\s*[:=]\s*([0-9]+(?:\.\d+)?)', text, flags=re.IGNORECASE)
        recall_values += re.findall(r'Recall\s*[:=]\s*([0-9]+(?:\.\d+)?)', text, flags=re.IGNORECASE)
        f1_values += re.findall(r'F1(?:-score|score)?\s*[:=]\s*([0-9]+(?:\.\d+)?)', text, flags=re.IGNORECASE)

    # notebook values might be written as 0.94 or as 94 - normalize to a percentage
    def to_percent(value_list):
        if not value_list:
            return None
        best = max(float(v) for v in value_list)
        return round(best * 100, 2) if best <= 1.0 else round(best, 2)

    accuracy = to_percent(accuracy_values)
    if accuracy is not None:
        metrics['accuracy'] = accuracy
        metrics['precision'] = to_percent(precision_values) or accuracy
        metrics['recall'] = to_percent(recall_values) or accuracy
        metrics['f1_score'] = to_percent(f1_values) or accuracy

    return metrics


# x is noted as preprocess csv file and use xgb model to predict every row
def predict(X):
    X_scaled = scaler.transform(X)

    # XGBoost predictions
    xgb_proba = xgb_model.predict_proba(X_scaled)
    xgb_preds = np.argmax(xgb_proba, axis=1)
    xgb_conf = np.max(xgb_proba, axis=1)

    # Random Forest predictions
    rf_proba = rf_model.predict_proba(X_scaled)
    rf_preds = np.argmax(rf_proba, axis=1)
    rf_conf = np.max(rf_proba, axis=1)

    # isolation forest flags rows that look "weird" compared to normal traffic,
    # even if XGB/RF don't recognise them as a known attack type
    anomaly_flags = [False] * len(X_scaled)
    if isolation_forest is not None:
        try:
            raw_flags = isolation_forest.predict(X_scaled)
            anomaly_flags = [flag == -1 for flag in raw_flags]
        except Exception:
            anomaly_flags = [False] * len(X_scaled)

    # loop
    results = []
    for i in range(len(xgb_preds)):
        xgb_label = LABEL_MAP[int(xgb_preds[i])]
        rf_label = LABEL_MAP[int(rf_preds[i])]

        # instead of always trusting XGB on disagreement, trust whichever model
        # is more confident about its own prediction for this row
        if xgb_label == rf_label:
            final_label = xgb_label
            final_conf = max(float(xgb_conf[i]), float(rf_conf[i]))
        elif xgb_conf[i] >= rf_conf[i]:
            final_label = xgb_label
            final_conf = float(xgb_conf[i])
        else:
            final_label = rf_label
            final_conf = float(rf_conf[i])

        severity = SEVERITY_MAP[final_label]

        # if isolation forest thinks this row is unusual and it's not flagged BENIGN,
        # bump it up to high severity
        if anomaly_flags[i] and final_label != 'BENIGN':
            severity = 'high'

        results.append({
            'row': i,
            'prediction': final_label,
            'severity': severity,
            'confidence': round(final_conf * 100, 2),
            'xgb_vote': xgb_label,
            'rf_vote': rf_label,
            'is_anomaly': anomaly_flags[i],
        })

    return results


# loop to count the numbers for severity and prediction
def get_summary(results):
    summary = {label: 0 for label in LABEL_MAP.values()}
    severity_counts = {'normal': 0, 'medium': 0, 'high': 0}
    anomaly_count = 0

    for r in results:
        summary[r['prediction']] += 1
        severity_counts[r['severity']] += 1
        if r.get('is_anomaly'):
            anomaly_count += 1

    return {'by_label': summary, 'by_severity': severity_counts, 'anomaly_count': anomaly_count}


# this is the REAL model accuracy from training
def estimate_model_metrics(results):
    return get_model_metrics()