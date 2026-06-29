# Clean and format uploaded CSV data so it matches the ML model input shape.
import json
import os
import pandas as pd
import numpy as np

# These are the numeric columns the trained models expect as input.
SELECTED_FEATURES = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
    'Fwd IAT Mean', 'Bwd IAT Mean', 'Packet Length Mean', 'Packet Length Std',
    'Destination Port', 'Average Packet Size', 'Fwd Packet Length Mean',
    'Bwd Packet Length Mean', 'Fwd Packets/s', 'Bwd Packets/s',
    'SYN Flag Count', 'ACK Flag Count', 'PSH Flag Count',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward'
]

TRAINING_STATS_PATH = os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'dataset', 'zann_dataset', 'training_stats.json'
)


def _load_training_stats():
    # Load training-set summary statistics so new uploads can be cleaned in a
    # consistent, model-aligned way when such a file is available.
    if not os.path.exists(TRAINING_STATS_PATH):
        return {}
    try:
        with open(TRAINING_STATS_PATH, 'r', encoding='utf-8') as fh:
            payload = json.load(fh) or {}
        if not isinstance(payload, dict):
            return {}

        medians = payload.get('medians', {}) if isinstance(payload.get('medians', {}), dict) else {}
        means = payload.get('means', {}) if isinstance(payload.get('means', {}), dict) else {}
        stds = payload.get('stds', {}) if isinstance(payload.get('stds', {}), dict) else {}
        lower_bounds = payload.get('lower_bounds', {}) if isinstance(payload.get('lower_bounds', {}), dict) else {}
        upper_bounds = payload.get('upper_bounds', {}) if isinstance(payload.get('upper_bounds', {}), dict) else {}

        return {
            'medians': medians,
            'means': means,
            'stds': stds,
            'lower_bounds': lower_bounds,
            'upper_bounds': upper_bounds,
        }
    except Exception:
        return {}


def _fill_missing_values(X, training_stats=None):
    # Work on a copy so the original data frame is not modified in place.
    X = X.copy()
    # Convert infinite values to missing values so they can be handled safely.
    X.replace([np.inf, -np.inf], np.nan, inplace=True)

    stats = training_stats or {}
    medians = stats.get('medians', {}) if isinstance(stats, dict) else {}
    means = stats.get('means', {}) if isinstance(stats, dict) else {}
    lower_bounds = stats.get('lower_bounds', {}) if isinstance(stats, dict) else {}
    upper_bounds = stats.get('upper_bounds', {}) if isinstance(stats, dict) else {}

    for col in SELECTED_FEATURES:
        if col not in X.columns:
            continue

        # Convert each selected feature to numeric and treat bad values as NaN.
        X[col] = pd.to_numeric(X[col], errors='coerce')

        # Prefer training-set medians when available, then the training mean,
        # and finally a robust fallback based on the current column.
        if col in medians and pd.notna(medians[col]):
            fill_value = medians[col]
        elif col in means and pd.notna(means[col]):
            fill_value = means[col]
        else:
            fill_value = X[col].median()

        X[col] = X[col].fillna(fill_value)

        # Clip extreme values using training bounds when available; otherwise use
        # a robust IQR-based range derived from the current data.
        lower = lower_bounds.get(col) if isinstance(lower_bounds, dict) else None
        upper = upper_bounds.get(col) if isinstance(upper_bounds, dict) else None

        if lower is None or upper is None:
            q1 = X[col].quantile(0.25)
            q3 = X[col].quantile(0.75)
            iqr = q3 - q1
            if pd.notna(iqr) and iqr > 0:
                lower = q1 - 1.5 * iqr
                upper = q3 + 1.5 * iqr

        if lower is not None and pd.notna(lower):
            X[col] = X[col].clip(lower=float(lower))
        if upper is not None and pd.notna(upper):
            X[col] = X[col].clip(upper=float(upper))

    return X.astype(float)


# Read a user-uploaded CSV, keep only the model features, and clean the data.
def preprocess_csv(filepath, training_stats=None):
    try:
        df = pd.read_csv(filepath)
    except Exception as e:
        return None, f'Cannot read CSV: {str(e)}'

    # Trim whitespace from column names so feature matching is more robust.
    df.columns = df.columns.str.strip()

    missing = [f for f in SELECTED_FEATURES if f not in df.columns]
    if missing:
        return None, f'Missing columns: {missing}'

    # Keep only the columns the model was trained on and normalize the header
    # to the exact feature names expected by the model.
    X = df[SELECTED_FEATURES].copy()
    if training_stats is None:
        training_stats = _load_training_stats()

    # Clean missing values, extreme values, and bad numeric entries before prediction.
    X = _fill_missing_values(X, training_stats=training_stats)
    return X, None