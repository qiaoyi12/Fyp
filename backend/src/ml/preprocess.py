import pandas as pd
import numpy as np


SELECTED_FEATURES = [
    'Packet Length Mean', 'Average Packet Size', 'Bwd Packet Length Max',
    'Bwd Segment Size Avg', 'Packet Length Max', 'Bwd Header Length',
    'Fwd Packet Length Max', 'Bwd Packet Length Mean', 'Dst Port',
    'Total Length of Bwd Packet', 'Packet Length Std', 'Fwd PSH Flags',
    'Fwd Header Length', 'ECE Flag Count', 'Fwd Segment Size Avg',
    'Fwd Seg Size Min', 'Bwd Init Win Bytes', 'Bwd PSH Flags',
    'Subflow Bwd Bytes', 'PSH Flag Count', 'Flow Bytes/s',
    'Packet Length Variance', 'Total Length of Fwd Packet', 'CWR Flag Count',
    'Bwd IAT Max', 'FWD Init Win Bytes', 'Fwd Packet Length Std',
    'Total Bwd packets', 'ACK Flag Count', 'Fwd Act Data Pkts',
]


# ============================================================
# METADATA
# Not used by ML models, but useful for frontend/dashboard
# ============================================================
METADATA_COLUMNS = [
    'Timestamp',
    'Flow ID',
    'Src IP',
    'Dst IP',
    'Src Port',
]

def preprocess_csv(filepath):

    try:
        df = pd.read_csv(filepath)
    except Exception as e:
        return None, f'Cannot read CSV: {str(e)}'

    # Remove extra whitespace
    df.columns = df.columns.str.strip()

    # Check all required features exist
    missing = [f for f in SELECTED_FEATURES if f not in df.columns]
    if missing:
        return None, f'Missing columns: {missing}'

    # Keep only the features used by the model
    X = df[SELECTED_FEATURES].copy()

    # Convert all values to numbers
    X = X.apply(pd.to_numeric, errors='coerce')

    # Replace infinite values with NaN
    X.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Fill missing values using the column median
    X.fillna(X.median(), inplace=True)

    return X, None
