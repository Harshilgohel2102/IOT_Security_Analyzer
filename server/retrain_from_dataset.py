from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split
from joblib import dump

from app.ml_engine import FEATURE_COLUMNS
from generate_training_dataset import generate_dataset


def main() -> int:
    parser = argparse.ArgumentParser(description="Retrain the risk classifier and anomaly detector from a CSV dataset.")
    parser.add_argument("--csv", type=Path, default=Path("data/iot_training_dataset.csv"), help="Path to the training dataset CSV file")
    parser.add_argument("--generate", action="store_true", help="Generate synthetic dataset before training")
    parser.add_argument("--rows", type=int, default=200_000, help="Number of rows to generate when --generate is used")
    args = parser.parse_args()

    csv_path = args.csv
    if args.generate:
        print(f"Generating synthetic dataset: {csv_path} ({args.rows} rows)")
        generate_dataset(csv_path, args.rows)

    if not csv_path.exists():
        print(f"Dataset not found: {csv_path}")
        return 1

    df = pd.read_csv(csv_path)
    required = set(FEATURE_COLUMNS + ["label"])
    missing = required - set(df.columns)
    if missing:
        print("Missing columns:", ", ".join(sorted(missing)))
        return 1

    X = df[FEATURE_COLUMNS]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    classifier = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
    )
    classifier.fit(X_train, y_train)
    preds = classifier.predict(X_test)

    anomaly = IsolationForest(n_estimators=250, contamination=0.12, random_state=42)
    anomaly.fit(X[y.isin(["LOW", "MEDIUM"])])

    model_dir = Path("app/models")
    model_dir.mkdir(parents=True, exist_ok=True)
    dump(classifier, model_dir / "risk_classifier.joblib")
    dump(anomaly, model_dir / "anomaly_detector.joblib")
    print({
        "rows": len(df),
        "accuracy": round(float(accuracy_score(y_test, preds)), 4),
        "weighted_f1": round(float(f1_score(y_test, preds, average="weighted")), 4),
        "saved_to": str(model_dir.resolve()),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
