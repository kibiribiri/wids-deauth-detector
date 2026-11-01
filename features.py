"""
Feature extraction for the WIDS prototype.

Two backends produce the same per-(second, transmitter MAC) feature rows:

* ``extract_features_from_pcap`` uses tshark + pandas.  This is the fast path
  used for training and offline replay of a capture.
* ``extract_features`` uses scapy on an iterable of packets.  This is the path
  a live monitor-mode interface would use.

Only behavioural features are used.  MAC addresses and timestamps are kept as
metadata, never as model inputs.
"""

from __future__ import annotations

import io
import math
import shutil
import subprocess
from collections import defaultdict

import numpy as np
import pandas as pd
from scapy.all import Dot11, Dot11Deauth, Dot11Disas, RadioTap

FEATURES = [
    "n_frames",
    "frames_per_sec",
    "n_deauth",
    "n_disassoc",
    "n_auth",
    "n_assoc",
    "n_beacon",
    "n_probe",
    "n_data",
    "n_mgmt",
    "n_ctrl",
    "mean_rssi",
    "std_rssi",
    "mean_len",
    "unique_dst",
    "dst_diversity",
    "broadcast_ratio",
    "deauth_ratio",
    "disassoc_ratio",
    "mgmt_ratio",
    "retry_ratio",
    "unique_reason_codes",
]

TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "wlan.sa",
    "wlan.da",
    "wlan.fc.type",
    "wlan.fc.subtype",
    "wlan.fc.retry",
    "radiotap.dbm_antsignal",
    "frame.len",
    "wlan.fixed.reason_code",
]

TSHARK_COLUMNS = [
    "frame_number",
    "ts",
    "sa",
    "da",
    "ftype",
    "subtype",
    "retry",
    "rssi",
    "length",
    "reason",
]


def _finalise_ratios(df: pd.DataFrame) -> pd.DataFrame:
    n = df["n_frames"].replace(0, np.nan)
    df["frames_per_sec"] = df["n_frames"].astype(float)
    df["dst_diversity"] = df["unique_dst"] / n
    df["broadcast_ratio"] = df["broadcast_count"] / n
    df["deauth_ratio"] = df["n_deauth"] / n
    df["disassoc_ratio"] = df["n_disassoc"] / n
    df["mgmt_ratio"] = df["n_mgmt"] / n
    df["retry_ratio"] = df["retry_count"] / n
    return df


def _aggregate(frame_df: pd.DataFrame, window: float) -> pd.DataFrame:
    """Aggregate a normalised frame table into (window, MAC) feature rows."""
    if frame_df.empty:
        return pd.DataFrame(columns=["mac", "window_start", *FEATURES])

    df = frame_df.dropna(subset=["ts", "sa"]).copy()
    df["sa"] = df["sa"].str.lower()
    df["da"] = df["da"].fillna("").str.lower()
    df["window_start"] = (np.floor(df["ts"] / window) * window).astype(np.int64)

    df["is_deauth"] = df["subtype"].eq(12)
    df["is_disassoc"] = df["subtype"].eq(10)
    df["is_auth"] = df["subtype"].eq(11)
    df["is_assoc"] = df["subtype"].eq(0) & df["ftype"].eq(0)
    df["is_beacon"] = df["subtype"].eq(8)
    df["is_probe"] = df["subtype"].isin([4, 5])
    df["is_data"] = df["ftype"].eq(2)
    df["is_mgmt"] = df["ftype"].eq(0)
    df["is_ctrl"] = df["ftype"].eq(1)
    df["is_broadcast"] = df["da"].eq("ff:ff:ff:ff:ff:ff")
    df["is_retry"] = df["retry"].eq(1)

    g = df.groupby(["window_start", "sa"], sort=False)
    out = pd.DataFrame(
        {
            "n_frames": g.size(),
            "n_deauth": g["is_deauth"].sum(),
            "n_disassoc": g["is_disassoc"].sum(),
            "n_auth": g["is_auth"].sum(),
            "n_assoc": g["is_assoc"].sum(),
            "n_beacon": g["is_beacon"].sum(),
            "n_probe": g["is_probe"].sum(),
            "n_data": g["is_data"].sum(),
            "n_mgmt": g["is_mgmt"].sum(),
            "n_ctrl": g["is_ctrl"].sum(),
            "mean_rssi": g["rssi"].mean(),
            "std_rssi": g["rssi"].std(ddof=0),
            "mean_len": g["length"].mean(),
            "unique_dst": g["da"].nunique(),
            "broadcast_count": g["is_broadcast"].sum(),
            "retry_count": g["is_retry"].sum(),
            "unique_reason_codes": g["reason"].nunique(),
        }
    ).reset_index()

    out["std_rssi"] = out["std_rssi"].fillna(0.0)
    out = _finalise_ratios(out)
    out = out.rename(columns={"sa": "mac"})
    out = out[["mac", "window_start", *FEATURES]]

    if "is_attack" in df.columns:
        attack = (
            df.groupby(["window_start", "sa"], sort=False)["is_attack"]
            .sum()
            .rename("n_attack_frames")
            .reset_index()
            .rename(columns={"sa": "mac"})
        )
        out = out.merge(attack, on=["mac", "window_start"], how="left")
        out["n_attack_frames"] = out["n_attack_frames"].fillna(0).astype(int)
        out["label"] = (out["n_attack_frames"] > 0).astype(int)

    return out.sort_values(["window_start", "mac"]).reset_index(drop=True)


def extract_features_from_pcap(path, frame_labels: pd.DataFrame | None = None, window: float = 1.0):
    """
    Fast PCAP feature extraction through tshark.

    ``frame_labels`` is an optional DataFrame with columns ``frame_number`` and
    ``is_attack`` (bool/int).  When supplied, each window receives a ``label``
    (1 if any labelled attack frame falls in it) and ``n_attack_frames``.
    """
    if shutil.which("tshark") is None:
        raise RuntimeError("tshark is required. Install wireshark/tshark.")

    cmd = [
        "tshark",
        "-r", str(path),
        "-n",
        "-T", "fields",
        "-E", "separator=/t",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]
    for field in TSHARK_FIELDS:
        cmd += ["-e", field]

    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    raw = proc.stdout
    if not raw.strip():
        return pd.DataFrame(columns=["mac", "window_start", *FEATURES])

    frames = pd.read_csv(
        io.StringIO(raw),
        sep="\t",
        names=TSHARK_COLUMNS,
        dtype=str,
        keep_default_na=False,
        na_values=[""],
    )
    for col in ["frame_number", "ts", "ftype", "subtype", "retry", "rssi", "length", "reason"]:
        frames[col] = pd.to_numeric(frames[col], errors="coerce")
    frames["ts"] = frames["ts"].astype(float)

    if frame_labels is not None:
        labels = frame_labels.copy()
        labels["frame_number"] = labels["frame_number"].astype(int)
        labels["is_attack"] = labels["is_attack"].astype(int)
        frames = frames.merge(
            labels[["frame_number", "is_attack"]], on="frame_number", how="left"
        )
        frames["is_attack"] = frames["is_attack"].fillna(0).astype(int)

    return _aggregate(frames, window)


# ---------------------------------------------------------------------------
# scapy backend (live capture path)
# ---------------------------------------------------------------------------

def _rssi(pkt):
    if pkt.haslayer(RadioTap):
        val = pkt[RadioTap].dBm_AntSignal
        if val is not None:
            return float(val)
    return None


def _new_bucket():
    return {
        "n_frames": 0,
        "n_deauth": 0,
        "n_disassoc": 0,
        "n_auth": 0,
        "n_assoc": 0,
        "n_beacon": 0,
        "n_probe": 0,
        "n_data": 0,
        "n_mgmt": 0,
        "n_ctrl": 0,
        "rssi": [],
        "lengths": [],
        "dst": set(),
        "broadcast": 0,
        "retries": 0,
        "reasons": set(),
    }


def _accumulate(bucket, pkt, length):
    if not pkt.haslayer(Dot11):
        return
    dot11 = pkt[Dot11]
    ftype, subtype = int(dot11.type), int(dot11.subtype)
    bucket["n_frames"] += 1
    bucket["lengths"].append(length)

    if dot11.FCfield & 0x8:
        bucket["retries"] += 1

    dst = (dot11.addr1 or "").lower()
    if dst:
        bucket["dst"].add(dst)
        if dst == "ff:ff:ff:ff:ff:ff":
            bucket["broadcast"] += 1

    rssi = _rssi(pkt)
    if rssi is not None:
        bucket["rssi"].append(rssi)

    if ftype == 0:
        bucket["n_mgmt"] += 1
        if subtype == 0:
            bucket["n_assoc"] += 1
        elif subtype in (4, 5):
            bucket["n_probe"] += 1
        elif subtype == 8:
            bucket["n_beacon"] += 1
        elif subtype == 11:
            bucket["n_auth"] += 1
    elif ftype == 1:
        bucket["n_ctrl"] += 1
    elif ftype == 2:
        bucket["n_data"] += 1

    if pkt.haslayer(Dot11Deauth) or subtype == 12:
        bucket["n_deauth"] += 1
        if pkt.haslayer(Dot11Deauth):
            bucket["reasons"].add(int(pkt[Dot11Deauth].reason))
    if pkt.haslayer(Dot11Disas) or subtype == 10:
        bucket["n_disassoc"] += 1
        if pkt.haslayer(Dot11Disas):
            bucket["reasons"].add(int(pkt[Dot11Disas].reason))


def _finalise(key, bucket):
    n = bucket["n_frames"]
    rssi = bucket["rssi"]
    lengths = bucket["lengths"]
    dst = bucket["dst"]
    return {
        "mac": key[1],
        "window_start": key[0],
        "n_frames": n,
        "frames_per_sec": float(n),
        "n_deauth": bucket["n_deauth"],
        "n_disassoc": bucket["n_disassoc"],
        "n_auth": bucket["n_auth"],
        "n_assoc": bucket["n_assoc"],
        "n_beacon": bucket["n_beacon"],
        "n_probe": bucket["n_probe"],
        "n_data": bucket["n_data"],
        "n_mgmt": bucket["n_mgmt"],
        "n_ctrl": bucket["n_ctrl"],
        "mean_rssi": sum(rssi) / len(rssi) if rssi else float("nan"),
        "std_rssi": (
            math.sqrt(sum((x - sum(rssi) / len(rssi)) ** 2 for x in rssi) / len(rssi))
            if len(rssi) > 1 else 0.0
        ),
        "mean_len": sum(lengths) / len(lengths) if lengths else 0.0,
        "unique_dst": len(dst),
        "dst_diversity": len(dst) / n if n else 0.0,
        "broadcast_ratio": bucket["broadcast"] / n if n else 0.0,
        "deauth_ratio": bucket["n_deauth"] / n if n else 0.0,
        "disassoc_ratio": bucket["n_disassoc"] / n if n else 0.0,
        "mgmt_ratio": bucket["n_mgmt"] / n if n else 0.0,
        "retry_ratio": bucket["retries"] / n if n else 0.0,
        "unique_reason_codes": len(bucket["reasons"]),
    }


def extract_features(packet_iter, window: float = 1.0):
    """Live/scapy backend.  packet_iter yields (timestamp, scapy_packet)."""
    buckets = {}
    for ts, pkt in packet_iter:
        if not pkt.haslayer(Dot11):
            continue
        tx = (pkt[Dot11].addr2 or "").lower()
        if not tx:
            continue
        wstart = math.floor(ts / window) * window
        key = (round(wstart, 3), tx)
        bucket = buckets.get(key)
        if bucket is None:
            bucket = buckets[key] = _new_bucket()
        _accumulate(bucket, pkt, len(pkt))

    df = pd.DataFrame([_finalise(k, b) for k, b in buckets.items()])
    if df.empty:
        return df
    return df.sort_values(["window_start", "mac"]).reset_index(drop=True)
