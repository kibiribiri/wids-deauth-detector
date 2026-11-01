#!/usr/bin/env python3
"""
WIDS runtime: replay an 802.11 capture, score each MAC/second with the trained
Random Forest, and raise a deauthentication-flood alert.

This is detection only (WIDS).  Alerts are printed and appended to
results/alerts.csv; no frames are transmitted and no device is blocked.

Examples:
    python detect.py --pcap data/demo_normal.pcap
    python detect.py --pcap data/demo_attack.pcap
    python detect.py --pcap data/raw/wpa3_deauth.pcap
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime
from pathlib import Path

import joblib
import pandas as pd

from features import FEATURES, extract_features_from_pcap


def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def episodes(df: pd.DataFrame, proba, threshold: float, max_gap: float = 2.0):
    """Collapse consecutive positive windows per MAC into alert episodes."""
    scored = df.copy()
    scored["score"] = proba
    scored["pred"] = (scored["score"] >= threshold).astype(int)
    scored = scored.sort_values(["mac", "window_start"])

    alerts = []
    for mac, group in scored.groupby("mac"):
        current = None
        for row in group.itertuples(index=False):
            if row.pred:
                if current is None or row.window_start - current["end"] > max_gap:
                    if current:
                        alerts.append(current)
                    current = {
                        "mac": mac,
                        "start": row.window_start,
                        "end": row.window_start + 1.0,
                        "peak_score": row.score,
                        "peak_deauth": row.n_deauth,
                        "frames": row.n_frames,
                        "rssi": row.mean_rssi,
                    }
                else:
                    current["end"] = row.window_start + 1.0
                    current["peak_score"] = max(current["peak_score"], row.score)
                    current["peak_deauth"] = max(current["peak_deauth"], row.n_deauth)
                    current["frames"] = max(current["frames"], row.n_frames)
            else:
                if current:
                    alerts.append(current)
                    current = None
        if current:
            alerts.append(current)
    return sorted(alerts, key=lambda a: a["start"])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap", type=Path, required=True)
    ap.add_argument("--model", type=Path, default=Path("models/wids_rf.joblib"))
    ap.add_argument("--out", type=Path, default=Path("results"))
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--min-deauth", type=int, default=20,
                    help="minimum peak deauth frames/s for a flood alert")
    ap.add_argument("--min-duration", type=float, default=2.0,
                    help="minimum episode duration in seconds")
    args = ap.parse_args()

    if not args.model.exists():
        raise SystemExit(f"Model not found: {args.model}. Run train.py first.")
    model = joblib.load(args.model)
    meta = json.loads((args.model.parent / "metadata.json").read_text())
    if meta.get("features") != FEATURES:
        raise SystemExit("Feature list mismatch between model metadata and features.py")

    print(f"Reading {args.pcap} ...")
    df = extract_features_from_pcap(args.pcap)
    if df.empty:
        raise SystemExit("No 802.11 frames found.")
    proba = model.predict_proba(df[FEATURES])[:, 1]
    alerts = episodes(df, proba, args.threshold)
    alerts = [
        a for a in alerts
        if a["peak_deauth"] >= args.min_deauth
        and (a["end"] - a["start"]) >= args.min_duration
    ]

    args.out.mkdir(parents=True, exist_ok=True)
    scored_path = args.out / f"scored_{args.pcap.stem}.csv"
    scored = df.copy()
    scored["score"] = proba
    scored.to_csv(scored_path, index=False)

    log_path = args.out / "alerts.csv"
    new_log = not log_path.exists()
    with open(log_path, "a", newline="") as f:
        writer = csv.writer(f)
        if new_log:
            writer.writerow(["time", "mac", "duration_s", "peak_deauth_per_s", "frames_per_s", "rssi", "score", "source"])
        for a in alerts:
            writer.writerow([
                fmt_time(a["start"]), a["mac"], round(a["end"] - a["start"], 1),
                a["peak_deauth"], a["frames"], f"{a['rssi']:.1f}", f"{a['peak_score']:.3f}",
                args.pcap.name,
            ])

    if not alerts:
        print(f"No deauthentication-flood episodes detected in {len(df)} MAC/windows.")
        print(f"Scored windows -> {scored_path}")
        return 0

    print(f"\n{len(alerts)} deauthentication-flood episode(s) detected "
          f"(threshold={args.threshold:.2f}):\n")
    for i, a in enumerate(alerts, 1):
        print(
            f"[ALERT {i}] {fmt_time(a['start'])} - {fmt_time(a['end'])[11:]}  "
            f"MAC {a['mac']}  deauth={a['peak_deauth']}/s  "
            f"frames={a['frames']}/s  RSSI={a['rssi']:.0f} dBm  "
            f"score={a['peak_score']:.2f}"
        )
    print(f"\nLogged to {log_path}")
    print(f"Scored windows -> {scored_path}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
