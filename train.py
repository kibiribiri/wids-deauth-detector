#!/usr/bin/env python3
"""
Train and evaluate the WIDS classifier on the prepared WPA3 deauth windows.

The train/test split is by time and comes from prepare_data.py, so the test
windows are later traffic the model has never seen.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier

from features import FEATURES


def make_model(kind: str):
    if kind == "dt":
        clf = DecisionTreeClassifier(max_depth=6, class_weight="balanced", random_state=42)
    else:
        clf = RandomForestClassifier(
            n_estimators=300,
            max_depth=10,
            min_samples_leaf=2,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        )
    return Pipeline([("imputer", SimpleImputer(strategy="median")), ("clf", clf)])


def evaluate(name, model, X_test, y_test, out_dir: Path):
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    cm = confusion_matrix(y_test, pred, labels=[0, 1])
    report = classification_report(
        y_test,
        pred,
        labels=[0, 1],
        target_names=["normal", "deauth_flood"],
        output_dict=True,
        zero_division=0,
    )
    metrics = {
        "model": name,
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred, zero_division=0),
        "recall": recall_score(y_test, pred, zero_division=0),
        "f1": f1_score(y_test, pred, zero_division=0),
        "confusion_matrix": cm.tolist(),  # [[TN, FP], [FN, TP]]
        "classification_report": report,
    }

    fig, ax = plt.subplots(figsize=(4.8, 3.9), dpi=220)
    ConfusionMatrixDisplay(cm, display_labels=["Normal", "Deauth flood"]).plot(
        ax=ax, cmap="Blues", colorbar=False, values_format="d"
    )
    ax.set_title("Held-out confusion matrix", fontsize=12)
    fig.tight_layout()
    slug = name.lower().replace(" ", "_")
    fig.savefig(out_dir / f"confusion_matrix_{slug}.png")
    plt.close(fig)

    print(f"\n=== {name} ===")
    print(
        f"accuracy={metrics['accuracy']:.4f}  precision={metrics['precision']:.4f}  "
        f"recall={metrics['recall']:.4f}  f1={metrics['f1']:.4f}"
    )
    print(classification_report(y_test, pred, target_names=["normal", "deauth_flood"], zero_division=0))
    print("confusion matrix [[TN, FP], [FN, TP]] =", cm.tolist())
    return metrics, proba, pred


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, default=Path("data/wpa3_windows.csv"))
    ap.add_argument("--out", type=Path, default=Path("results"))
    ap.add_argument("--models", type=Path, default=Path("models"))
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    args.models.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.data)
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        raise SystemExit(f"Missing feature columns: {missing}")

    train = df[df["split"] == "train"].reset_index(drop=True)
    test = df[df["split"] == "test"].reset_index(drop=True)
    if train.empty or test.empty:
        raise SystemExit("Train or test split is empty; rerun prepare_data.py.")

    print(f"Dataset: {len(df)} windows, {int(df['label'].sum())} attack "
          f"({100 * df['label'].mean():.1f}%), {df['mac'].nunique()} MACs")
    print(f"Train: {len(train)} windows, {int(train['label'].sum())} attack")
    print(f"Test : {len(test)} windows, {int(test['label'].sum())} attack")

    all_metrics = []
    models = {}
    preds = {}
    for kind, name in (("dt", "Decision Tree"), ("rf", "Random Forest")):
        model = make_model(kind)
        model.fit(train[FEATURES], train["label"])
        models[kind] = model
        metrics, proba, pred = evaluate(name, model, test[FEATURES], test["label"], args.out)
        all_metrics.append(metrics)
        preds[kind] = (proba, pred)

    rf = models["rf"]
    importances = rf.named_steps["clf"].feature_importances_
    order = np.argsort(importances)[::-1][:12]
    fig, ax = plt.subplots(figsize=(6.2, 4.6), dpi=220)
    ax.barh(
        [FEATURES[i] for i in order][::-1],
        importances[order][::-1],
        color="#2b6cb0",
    )
    ax.set_xlabel("Importance", fontsize=12)
    ax.tick_params(labelsize=11)
    ax.set_title("Random Forest feature importance (top 12)", fontsize=13)
    fig.tight_layout()
    fig.savefig(args.out / "feature_importance.png")
    plt.close(fig)

    joblib.dump(rf, args.models / "wids_rf.joblib")
    (args.models / "metadata.json").write_text(
        json.dumps(
            {
                "features": FEATURES,
                "window_seconds": 1.0,
                "positive_class": "deauth_flood",
                "test_accuracy": all_metrics[1]["accuracy"],
                "train_rows": len(train),
                "test_rows": len(test),
            },
            indent=2,
        )
    )

    # Keep the scored test windows for inspection / the poster.
    scored = test[["mac", "window_start", "label", *FEATURES]].copy()
    scored["score"] = preds["rf"][0]
    scored["prediction"] = preds["rf"][1]
    scored.to_csv(args.out / "test_predictions.csv", index=False)

    summary = {
        "dataset": {
            "windows": len(df),
            "attack_windows": int(df["label"].sum()),
            "normal_windows": int((df["label"] == 0).sum()),
            "macs": int(df["mac"].nunique()),
            "train_windows": len(train),
            "test_windows": len(test),
        },
        "models": all_metrics,
        "top_features": [
            {"feature": FEATURES[i], "importance": float(importances[i])}
            for i in order[:10]
        ],
    }
    (args.out / "metrics.json").write_text(json.dumps(summary, indent=2))
    print(f"\nSaved model -> {args.models / 'wids_rf.joblib'}")
    print(f"Saved metrics/plots -> {args.out}/")


if __name__ == "__main__":
    main()
