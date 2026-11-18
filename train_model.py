"""
WAF ML Anomaly Detector Training Pipeline.

Trains Random Forest, Logistic Regression, and Isolation Forest models on HTTP
traffic features, performs stratified evaluation, and saves the serialized
model bundle (model.joblib) for runtime proxy inspection.
"""

import argparse
import os
import sys
import time
from datetime import datetime
from typing import Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler

# Handle path resolution whether run as module or script
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
WAF_ROOT = os.path.dirname(CURRENT_DIR)
PROJECT_ROOT = os.path.dirname(WAF_ROOT)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from waf.ml.dataset import build_dataset
from waf.ml.feature_extractor import FEATURE_NAMES, FeatureExtractor


def prepare_dataset(num_samples: int = 5000) -> Tuple[np.ndarray, np.ndarray, list, FeatureExtractor]:
    """
    Generate dataset and extract feature vectors.
    """
    print(f"[*] Generating {num_samples} labeled HTTP requests (benign vs malicious)...")
    raw_dataset = build_dataset(num_samples=num_samples, benign_ratio=0.5)

    extractor = FeatureExtractor()
    print("[*] Extracting multi-dimensional feature vectors...")

    feature_matrix = []
    labels = []
    attack_types = []

    for item in raw_dataset:
        vec = extractor.extract_vector(item)
        feature_matrix.append(vec)
        labels.append(item["label"])
        attack_types.append(item["attack_type"])

    X = np.array(feature_matrix, dtype=np.float32)
    y = np.array(labels, dtype=np.int32)

    print(f"[+] Feature matrix shape: {X.shape} | Labels shape: {y.shape}")
    print(f"    - Benign samples: {int(np.sum(y == 0))}")
    print(f"    - Malicious samples: {int(np.sum(y == 1))}")
    return X, y, attack_types, extractor


def train_and_evaluate(X: np.ndarray, y: np.ndarray, attack_types: list) -> Dict:
    """
    Train and compare Random Forest, Logistic Regression, and Isolation Forest.
    """
    X_train, X_test, y_train, y_test, types_train, types_test = train_test_split(
        X, y, attack_types, test_size=0.25, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("\n" + "=" * 60)
    print(" 1. TRAINING RANDOM FOREST CLASSIFIER (Primary Supervised Model)")
    print("=" * 60)
    t0 = time.time()
    rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    train_time_rf = time.time() - t0

    # Predictions & metrics
    y_pred_rf = rf.predict(X_test)
    y_prob_rf = rf.predict_proba(X_test)[:, 1]

    acc_rf = accuracy_score(y_test, y_pred_rf)
    prec_rf = precision_score(y_test, y_pred_rf)
    rec_rf = recall_score(y_test, y_pred_rf)
    f1_rf = f1_score(y_test, y_pred_rf)
    auc_rf = roc_auc_score(y_test, y_prob_rf)
    cm_rf = confusion_matrix(y_test, y_pred_rf)
    tn, fp, fn, tp = cm_rf.ravel()
    fpr_rf = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"Random Forest fit completed in {train_time_rf:.3f}s")
    print(f"Accuracy:  {acc_rf * 100:.2f}%")
    print(f"Precision: {prec_rf * 100:.2f}% (Attacks identified correctly)")
    print(f"Recall:    {rec_rf * 100:.2f}% (Coverage of all attacks)")
    print(f"F1-Score:  {f1_rf:.4f}")
    print(f"ROC-AUC:   {auc_rf:.4f}")
    print(f"False Positive Rate (FPR): {fpr_rf * 100:.2f}%")
    print(f"Confusion Matrix: [TN={tn}, FP={fp}, FN={fn}, TP={tp}]")

    print("\n" + "=" * 60)
    print(" 2. TRAINING LOGISTIC REGRESSION (Baseline Comparison)")
    print("=" * 60)
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_train_scaled, y_train)
    y_pred_lr = lr.predict(X_test_scaled)
    acc_lr = accuracy_score(y_test, y_pred_lr)
    f1_lr = f1_score(y_test, y_pred_lr)
    print(f"Logistic Regression Accuracy: {acc_lr * 100:.2f}% | F1: {f1_lr:.4f}")

    print("\n" + "=" * 60)
    print(" 3. TRAINING ISOLATION FOREST (Unsupervised Outlier Detector)")
    print("=" * 60)
    # Train Isolation Forest on benign samples
    X_train_benign = X_train_scaled[y_train == 0]
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X_train_benign)
    # Isolation Forest returns 1 for inlier (benign), -1 for outlier (anomaly)
    iso_pred = iso_forest.predict(X_test_scaled)
    iso_pred_binary = (iso_pred == -1).astype(int)
    iso_f1 = f1_score(y_test, iso_pred_binary)
    print(f"Isolation Forest Anomaly F1-Score: {iso_f1:.4f}")

    # Feature importances from Random Forest
    importances = rf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("\n" + "=" * 60)
    print(" TOP 10 MOST INFLUENTIAL ML FEATURES")
    print("=" * 60)
    for rank, idx in enumerate(sorted_idx[:10], start=1):
        print(f"  {rank:2d}. {FEATURE_NAMES[idx]:<28} : {importances[idx]:.4f}")

    # Latency benchmark
    t_start = time.perf_counter()
    _ = rf.predict_proba(X_test[:500])
    avg_latency_ms = ((time.perf_counter() - t_start) / 500) * 1000.0
    print(f"\n[+] Average inference latency: {avg_latency_ms:.4f} ms per request")

    results = {
        "rf_model": rf,
        "scaler": scaler,
        "iso_forest": iso_forest,
        "metrics": {
            "accuracy": float(acc_rf),
            "precision": float(prec_rf),
            "recall": float(rec_rf),
            "f1_score": float(f1_rf),
            "roc_auc": float(auc_rf),
            "fpr": float(fpr_rf),
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp)
            },
            "avg_latency_ms": float(avg_latency_ms),
            "logistic_regression_f1": float(f1_lr),
            "isolation_forest_f1": float(iso_f1),
        },
        "feature_importances": {
            FEATURE_NAMES[i]: float(importances[i]) for i in sorted_idx
        }
    }
    return results


def save_model_artifact(bundle: Dict, output_path: str):
    """
    Saves the serialized model bundle to disk.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    payload = {
        "model": bundle["rf_model"],
        "scaler": bundle["scaler"],
        "isolation_forest": bundle["iso_forest"],
        "feature_names": FEATURE_NAMES,
        "threshold": 0.50,
        "metrics": bundle["metrics"],
        "feature_importances": bundle["feature_importances"],
        "created_at": datetime.now().isoformat(),
        "model_version": "1.0.0",
        "description": "WAF ML Anomaly Detector Random Forest + Isolation Forest Bundle"
    }
    joblib.dump(payload, output_path, compress=3)
    print(f"\n[OK] Successfully serialized trained model bundle to: {output_path}")
    print(f"    Bundle file size: {os.path.getsize(output_path) / 1024:.2f} KB")


def main():
    parser = argparse.ArgumentParser(description="Train WAF ML Anomaly Detection Model")
    parser.add_argument("--samples", type=int, default=5000, help="Number of training samples to synthesize")
    parser.add_argument("--output", type=str, default=os.path.join(CURRENT_DIR, "model.joblib"), help="Path to save model.joblib")
    args = parser.parse_args()

    X, y, attack_types, _ = prepare_dataset(num_samples=args.samples)
    results = train_and_evaluate(X, y, attack_types)
    save_model_artifact(results, args.output)


if __name__ == "__main__":
    main()
