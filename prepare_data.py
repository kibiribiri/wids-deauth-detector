#!/usr/bin/env python3
"""
Prepare the WPA3 deauthentication capture for training and demonstration.

Input (already downloaded into data/raw/):
  wpa3_deauth.pcap  - raw 802.11 capture (normal traffic + deauth flood)
  wpa3_deauth.csv   - Wireshark packet export with a per-frame Label column

The dataset is the "Deauthentication attack" capture from:
  Halbouni, Ong & Leow, WPA3 Attacks Dataset (2026), Mendeley Data,
  DOI 10.17632/cxx5t5nw7z.3, CC BY 4.0.

Output:
  data/wpa3_windows.csv - per-(second, MAC) features + label + split
  data/demo_normal.pcap - first 60 s (normal only)
  data/demo_attack.pcap - 60 s around the start of the flood
  data/dataset_summary.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import numpy as np
import pandas as pd

from features import FEATURES, extract_features_from_pcap


def cut_excerpt(src: Path, dst: Path, start: float, stop: float):
    """Cut a time range out of a pcap with editcap (fast)."""
    subprocess.run(
        ["editcap", "-A", str(start), "-B", str(stop), str(src), str(dst)],
        check=True,
        capture_output=True,
        text=True,
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--raw", type=Path, default=Path("data/raw"))
    ap.add_argument("--out", type=Path, default=Path("data"))
    args = ap.parse_args()

    pcap = args.raw / "wpa3_deauth.pcap"
    labels_csv = args.raw / "wpa3_deauth.csv"
    if not pcap.exists() or not labels_csv.exists():
        raise SystemExit(
            "Missing data/raw/wpa3_deauth.pcap or .csv.\n"
            "Download the Deauthentication capture from the WPA3 Attacks Dataset "
            "(DOI 10.17632/cxx5t5nw7z.3) and place both files in data/raw/."
        )

    args.out.mkdir(parents=True, exist_ok=True)

    print("Reading frame labels ...")
    labels = pd.read_csv(
        labels_csv,
        usecols=["frame.number", "frame.time_epoch", "Label"],
        dtype={"frame.number": "int64", "frame.time_epoch": "float64", "Label": "string"},
    ).rename(
        columns={"frame.number": "frame_number", "frame.time_epoch": "ts", "Label": "label"}
    )
    labels["is_attack"] = labels["label"].eq("Deauth").astype(int)
    print(labels["label"].value_counts().to_string())

    attack_times = labels.loc[labels["is_attack"] == 1, "ts"]
    attack_start = float(attack_times.min())
    attack_end = float(attack_times.max())
    print(f"Attack interval: {attack_start:.0f} - {attack_end:.0f} "
          f"({attack_end - attack_start:.0f} s)")

    print("Extracting per-second, per-MAC features with tshark ...")
    windows = extract_features_from_pcap(
        pcap, frame_labels=labels[["frame_number", "is_attack"]]
    )
    if windows.empty:
        raise SystemExit("Feature extraction returned no rows.")

    # Time-based split: train on the earlier part of the capture, test on the
    # later part.  The attack starts before the cutoff and continues after it,
    # so both splits contain normal and attack windows.
    cutoff = attack_start + 0.7 * (attack_end - attack_start)
    windows["split"] = np.where(windows["window_start"] < cutoff, "train", "test")

    for split, part in windows.groupby("split"):
        print(
            f"{split}: {len(part):5d} windows, "
            f"{int(part['label'].sum()):4d} attack, "
            f"{part['mac'].nunique():3d} MACs"
        )
    if windows.groupby("split")["label"].nunique().min() < 2:
        raise SystemExit("Split does not contain both classes; adjust the cutoff.")

    out_csv = args.out / "wpa3_windows.csv"
    windows.to_csv(out_csv, index=False)
    print(f"Wrote {out_csv} ({len(windows)} rows)")

    # Demo excerpts (attack starts at attack_start).
    demo_normal = args.out / "demo_normal.pcap"
    demo_attack = args.out / "demo_attack.pcap"
    first_ts = float(labels["ts"].min())
    cut_excerpt(pcap, demo_normal, first_ts, first_ts + 60)
    cut_excerpt(pcap, demo_attack, attack_start - 5, attack_start + 55)
    print(f"Wrote {demo_normal} and {demo_attack}")

    summary = {
        "source": {
            "dataset": "WPA3 Attacks Dataset - Deauthentication attack",
            "doi": "10.17632/cxx5t5nw7z.3",
            "license": "CC BY 4.0",
            "pcap": pcap.name,
            "pcap_frames": int(labels.shape[0]),
        },
        "attack_interval": [attack_start, attack_end],
        "split_cutoff": cutoff,
        "windows": int(len(windows)),
        "attack_windows": int(windows["label"].sum()),
        "normal_windows": int((windows["label"] == 0).sum()),
        "macs": int(windows["mac"].nunique()),
        "splits": {
            k: {
                "windows": int(len(v)),
                "attack": int(v["label"].sum()),
                "normal": int((v["label"] == 0).sum()),
            }
            for k, v in windows.groupby("split")
        },
        "features": FEATURES,
    }
    (args.out / "dataset_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"Wrote {args.out / 'dataset_summary.json'}")


if __name__ == "__main__":
    main()
