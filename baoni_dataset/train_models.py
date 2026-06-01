"""
train_models.py

Usage:
  python train_models.py --mode binary
  python train_models.py --mode multiclass

This script loads dataset/train.csv and dataset/test.csv, creates a stratified
train/test split, trains RandomForest, LogisticRegression, XGBoost and
IsolationForest, evaluates them, compares results, and saves the best model
and label mapping for use in a Flask-based IDS.

Outputs:
  - best_model.pkl
  - scaler.pkl (if used)
  - label_mapping.json
  - model_comparison.csv

"""
import argparse
import json
import os
from collections import Counter

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight
import xgboost as xgb


def detect_label_column(df: pd.DataFrame):
    for candidate in ("label", "Label", "CLASS", "class", "attack", "target"):
        if candidate in df.columns:
            return candidate
    return df.columns[-1]


def load_and_split(train_path, test_path, mode='binary', random_state=42, max_samples=None):
    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)
    df = pd.concat([df_train, df_test], ignore_index=True)

    label_col = detect_label_column(df)
    y = df[label_col]
    if mode == 'binary':
        y = y.apply(lambda x: 0 if x == 0 else 1)

    if max_samples is not None and len(df) > max_samples:
        print(f"Sampling {max_samples} rows from {len(df)} total rows to speed up training.")
        if y.value_counts().min() >= 2:
            sss_sample = StratifiedShuffleSplit(n_splits=1, train_size=max_samples, random_state=random_state)
            sample_idx, _ = next(sss_sample.split(df, y))
            df = df.iloc[sample_idx].reset_index(drop=True)
            y = y.iloc[sample_idx].reset_index(drop=True)
        else:
            print("Rare classes present; using random sampling instead of stratified sampling.")
            df = df.sample(n=max_samples, random_state=random_state).reset_index(drop=True)
            y = df[label_col]
            if mode == 'binary':
                y = y.apply(lambda x: 0 if x == 0 else 1)

    X = df.drop(columns=[label_col])

    # compute test_size so we preserve original proportions
    total = len(df)
    test_size = len(df_test) / len(pd.concat([df_train, df_test], ignore_index=True))

    sss = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    for train_idx, test_idx in sss.split(X, y):
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

    return X_train.reset_index(drop=True), X_test.reset_index(drop=True), y_train.reset_index(drop=True), y_test.reset_index(drop=True), label_col


def get_class_weights(y):
    classes = np.unique(y)
    weights = compute_class_weight(class_weight='balanced', classes=classes, y=y)
    return dict(zip(classes, weights))


def evaluate_binary(y_true, y_pred):
    return {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision': precision_score(y_true, y_pred),
        'recall': recall_score(y_true, y_pred),
        'f1': f1_score(y_true, y_pred),
        'confusion_matrix': confusion_matrix(y_true, y_pred).tolist()
    }


def evaluate_multiclass(y_true, y_pred):
    return {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision_macro': precision_score(y_true, y_pred, average='macro', zero_division=0),
        'recall_macro': recall_score(y_true, y_pred, average='macro', zero_division=0),
        'f1_macro': f1_score(y_true, y_pred, average='macro', zero_division=0),
        'confusion_matrix': confusion_matrix(y_true, y_pred).tolist()
    }


def train_and_evaluate(X_train, y_train, X_test, y_test, mode='binary', output_dir='.', random_state=42):
    os.makedirs(output_dir, exist_ok=True)

    results = []

    # Preprocessing: ensure only numeric features are used (drop non-numeric)
    numeric_cols = X_train.select_dtypes(include=[np.number]).columns.tolist()
    non_numeric = [c for c in X_train.columns if c not in numeric_cols]
    if non_numeric:
        print(f"Dropping non-numeric features: {non_numeric}")
        X_train = X_train[numeric_cols].copy()
        X_test = X_test[numeric_cols].copy()

    # Preprocessing: scaler for LR (and IsolationForest)
    scaler = StandardScaler()
    scaler.fit(X_train)

    X_train_scaled = scaler.transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    class_weights = get_class_weights(y_train)

    # 1) Random Forest
    print('Training RandomForest...')
    if mode == 'binary':
        rf = RandomForestClassifier(n_estimators=50, max_depth=12, class_weight='balanced', n_jobs=-1, random_state=random_state)
    else:
        rf = RandomForestClassifier(n_estimators=50, max_depth=12, class_weight='balanced', n_jobs=-1, random_state=random_state)
    rf.fit(X_train, y_train)
    y_pred_rf = rf.predict(X_test)
    metrics_rf = evaluate_binary(y_test, y_pred_rf) if mode == 'binary' else evaluate_multiclass(y_test, y_pred_rf)
    results.append(('RandomForest', metrics_rf, rf))

    # 2) Logistic Regression (needs scaling)
    print('Training LogisticRegression...')
    if mode == 'binary':
        lr = LogisticRegression(class_weight='balanced', max_iter=2000, tol=1e-3, solver='saga', random_state=random_state)
    else:
        lr = LogisticRegression(class_weight='balanced', multi_class='multinomial', max_iter=2000, tol=1e-3, solver='saga', random_state=random_state)
    lr.fit(X_train_scaled, y_train)
    y_pred_lr = lr.predict(X_test_scaled)
    metrics_lr = evaluate_binary(y_test, y_pred_lr) if mode == 'binary' else evaluate_multiclass(y_test, y_pred_lr)
    results.append(('LogisticRegression', metrics_lr, (lr, scaler)))

    # 3) XGBoost
    print('Training XGBoost...')
    if mode == 'binary':
        # compute scale_pos_weight = neg/pos
        y_vals = np.array(y_train)
        pos = np.sum(y_vals == 1)
        neg = np.sum(y_vals == 0)
        scale_pos_weight = (neg / pos) if pos > 0 else 1.0
        xgb_clf = xgb.XGBClassifier(eval_metric='logloss', scale_pos_weight=scale_pos_weight, random_state=random_state, n_jobs=-1, n_estimators=50, max_depth=6, tree_method='hist', verbosity=1)
        xgb_clf.fit(X_train, y_train)
    else:
        xgb_clf = xgb.XGBClassifier(objective='multi:softprob', num_class=len(np.unique(y_train)), random_state=random_state, n_jobs=-1, n_estimators=50, max_depth=6, tree_method='hist', verbosity=1)
        # pass sample_weight computed from class_weights
        sample_weight = np.array([class_weights[l] for l in y_train])
        xgb_clf.fit(X_train, y_train, sample_weight=sample_weight)
    y_pred_xgb = xgb_clf.predict(X_test)
    metrics_xgb = evaluate_binary(y_test, y_pred_xgb) if mode == 'binary' else evaluate_multiclass(y_test, y_pred_xgb)
    results.append(('XGBoost', metrics_xgb, xgb_clf))

    # 4) Isolation Forest -> used as anomaly detector (binary: BENIGN vs ATTACK)
    print('Training IsolationForest...')
    # We'll train IF on benign samples only
    try:
        benign_label = 0 if (0 in set(y_train)) else min(set(y_train))
        X_benign = X_train[y_train == benign_label]
        if len(X_benign) < 10:
            raise ValueError('Not enough benign samples for IsolationForest')
        if_clf = IsolationForest(n_estimators=50, contamination='auto', random_state=random_state)
        if_clf.fit(X_benign)

        # predict: -1 anomaly (attack), 1 normal (benign)
        preds = if_clf.predict(X_test)
        # map to 0 benign, 1 attack
        y_pred_if = np.where(preds == 1, benign_label, 1)
        # If multiclass, convert y_test to binary (benign vs attack) for IF evaluation
        if mode == 'binary':
            metrics_if = evaluate_binary(y_test, y_pred_if)
        else:
            # make binary mapping for ground truth
            y_test_bin = np.where(y_test == benign_label, benign_label, 1)
            metrics_if = evaluate_binary(y_test_bin, y_pred_if)
    except Exception as e:
        metrics_if = {'error': str(e)}
        if_clf = None
    results.append(('IsolationForest', metrics_if, if_clf))

    # Save comparison table
    rows = []
    for name, metrics, _ in results:
        if 'f1_macro' in metrics:
            f1 = metrics.get('f1_macro')
        else:
            f1 = metrics.get('f1')
        rows.append({'model': name, 'f1': f1, 'metrics': json.dumps(metrics)})
    df_comp = pd.DataFrame(rows).sort_values('f1', ascending=False)
    comp_path = os.path.join(output_dir, 'model_comparison.csv')
    df_comp.to_csv(comp_path, index=False)

    # Choose best model (by f1 / f1_macro)
    best_row = df_comp.iloc[0]
    best_name = best_row['model']
    best_model = None
    for name, metrics, model in results:
        if name == best_name:
            best_model = model
            break

    # Save best model and artifacts
    if isinstance(best_model, tuple):
        # logistic stored as (model, scaler)
        joblib.dump(best_model[0], os.path.join(output_dir, 'best_model.pkl'))
        joblib.dump(best_model[1], os.path.join(output_dir, 'scaler.pkl'))
    else:
        if best_model is not None:
            joblib.dump(best_model, os.path.join(output_dir, 'best_model.pkl'))
            # save global scaler
            joblib.dump(scaler, os.path.join(output_dir, 'scaler.pkl'))

    # Save label mapping
    classes = np.unique(y_train)
    mapping = {str(i): int(c) for i, c in enumerate(classes)}
    # also provide reverse mapping
    rev_map = {int(c): str(i) for i, c in enumerate(classes)}
    with open(os.path.join(output_dir, 'label_mapping.json'), 'w') as f:
        json.dump({'classes': classes.tolist(), 'mapping': mapping, 'reverse_mapping': rev_map}, f)

    return results, comp_path, os.path.join(output_dir, 'best_model.pkl')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['binary', 'multiclass'], default='binary')
    parser.add_argument('--train', default='dataset/train.csv')
    parser.add_argument('--test', default='dataset/test.csv')
    parser.add_argument('--out', default='artifacts')
    parser.add_argument('--max-samples', type=int, default=200000,
                        help='Maximum number of combined rows to use for training and evaluation')
    args = parser.parse_args()

    X_train, X_test, y_train, y_test, label_col = load_and_split(args.train, args.test, mode=args.mode, max_samples=args.max_samples)

    # If binary mode, labels are already mapped to 0/1 during splitting
    if args.mode == 'binary':
        y_train = y_train.astype(int)
        y_test = y_test.astype(int)

    print(f"Training mode: {args.mode}")
    print(f"Label column detected: {label_col}")
    print("Class distribution (train):", Counter(y_train))

    results, comp_path, best_model_path = train_and_evaluate(X_train, y_train, X_test, y_test, mode=args.mode, output_dir=args.out)

    print("Model comparison saved to:", comp_path)
    print("Best model saved to:", best_model_path)


if __name__ == '__main__':
    main()
