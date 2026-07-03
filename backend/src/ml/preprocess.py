import pandas as pd
import numpy as np

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