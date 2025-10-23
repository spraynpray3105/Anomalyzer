#!/usr/bin/env python3
"""
-----------------------------------------------------
Collects real packets from the NIC, aggregates them into short windows,
then trains two tiny models and saves ONLY model artifacts.

Models:
  1) 1D "size": robust baseline on median-absolute-deviation of per-window median packet length
  2) 2D Isolation Forest on (log1p(total_bytes), log1p(size_median))

Data definition per window (default 1 second):
  - total_bytes  := sum of packet lengths within the window
  - size         := median packet length within the window

Requirements:
  pip install scapy pandas numpy scikit-learn joblib

Run examples (requires sudo/admin for capture):
  sudo python anomalyzer_trainer.py --iface wlan0 --collect_seconds 60 --bpf "ip or ip6"
  sudo python anomalyzer_trainer.py --iface en0   --collect_seconds 45

Artifacts saved to ./artifacts_simple/ :
  - size_baseline.json
  - scaler.json
  - if_bytes_size.joblib
"""

import argparse
import json
import os
import time
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
import joblib

# scapy import (needs root/administrator permissions to sniff)
from scapy.all import sniff

# -----------------------------
# Utilities
# -----------------------------

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def log1p_safe(x: np.ndarray) -> np.ndarray:
    return np.log1p(np.clip(x.astype(float), a_min=0.0, a_max=None))

def mad_std(x: np.ndarray) -> float:
    med = np.median(x)
    mad = np.median(np.abs(x - med))
    val = 1.4826 * mad
    return float(val if val > 1e-9 else 1e-6)

# -----------------------------
# Live capture and aggregation
# -----------------------------

def capture_packets(iface: str, seconds: int, bpf: str | None, promisc: bool = True):
    """
    Capture packets for a fixed duration using scapy.sniff.
    Returns a list of tuples: (timestamp_sec_float, packet_len_bytes)
    """
    pkt_rows: list[tuple[float, int]] = []

    def _cb(pkt):
        try:
            pkt_rows.append((float(pkt.time), int(len(pkt))))
        except Exception:
            pass  # ignore any odd packets

    sniff_kwargs = dict(
        iface=iface,
        prn=_cb,
        store=False,
        timeout=seconds,
        promisc=promisc,
    )
    if bpf:
        sniff_kwargs["filter"] = bpf

    sniff(**sniff_kwargs)
    return pkt_rows

def aggregate_windows(pkt_rows: list[tuple[float, int]], window_sec: int) -> pd.DataFrame:
    """
    Turn per-packet rows into per-window aggregates:
      total_bytes = sum(length)
      size        = median(length)
    """
    if not pkt_rows:
        raise RuntimeError("No packets captured. Check interface name, permissions, or BPF filter.")
    # Build DataFrame with datetime index
    ts = pd.to_datetime([r[0] for r in pkt_rows], unit="s")
    lens = [r[1] for r in pkt_rows]
    dfp = pd.DataFrame({"len": lens}, index=ts).sort_index()
    # Resample into fixed windows
    agg = pd.DataFrame()
    agg["total_bytes"] = dfp["len"].resample(f"{window_sec}S").sum().fillna(0).astype(float)
    agg["size"] = dfp["len"].resample(f"{window_sec}S").median().fillna(0).astype(float)
    # Drop initial empty rows (if any)
    agg = agg[agg["total_bytes"].notna()]
    if len(agg) < 10:
        raise RuntimeError("Too few windows after aggregation; try increasing collect_seconds or window size.")
    # Reset index to simple range for training simplicity
    agg = agg.reset_index(drop=True)
    return agg

# -----------------------------
# Minimal training routine
# -----------------------------

@dataclass
class Config:
    outdir: str = "artifacts_simple"
    baseline_frac: float = 0.7
    if_estimators: int = 200
    if_max_samples: int = 512

def train_and_save_models(df: pd.DataFrame, cfg: Config) -> None:
    """
    Train two tiny models and save only artifacts:
      (1) 1D size baseline: median + MAD of size_log (log1p(size) scaled)
      (2) 2D Isolation Forest on (bytes_log, size_log), with RobustScaler
    """
    ensure_dir(cfg.outdir)

    for col in ["total_bytes", "size"]:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")
    if len(df) < 30:
        raise ValueError("Need at least ~30 windows of data for baseline.")

    # Split baseline vs the rest
    n = len(df)
    n_base = max(20, int(n * cfg.baseline_frac))
    df_base = df.iloc[:n_base]

    # Stabilize skew + scale on baseline
    X = pd.DataFrame({
        "bytes_log": log1p_safe(df["total_bytes"].values),
        "size_log":  log1p_safe(df["size"].values),
    })
    scaler = RobustScaler().fit(X.iloc[:n_base])
    Xs = pd.DataFrame(scaler.transform(X), columns=X.columns, index=df.index)

    # 1D size baseline
    size_base = Xs["size_log"].values[:n_base]
    size_median = float(np.median(size_base))
    size_madstd = float(mad_std(size_base))

    # 2D Isolation Forest
    X_base_2d = Xs.iloc[:n_base][["bytes_log","size_log"]].values
    if_model = IsolationForest(
        n_estimators=cfg.if_estimators,
        max_samples=min(cfg.if_max_samples, len(X_base_2d)),
        contamination="auto",
        random_state=42,
        bootstrap=False,
    ).fit(X_base_2d)

    # Save artifacts ONLY
    with open(os.path.join(cfg.outdir, "scaler.json"), "w") as f:
        json.dump({
            "center_": scaler.center_.tolist(),
            "scale_": scaler.scale_.tolist(),
            "feature_names": ["bytes_log","size_log"],
        }, f, indent=2)

    with open(os.path.join(cfg.outdir, "size_baseline.json"), "w") as f:
        json.dump({"median": size_median, "mad_std": size_madstd}, f, indent=2)

    joblib.dump(if_model, os.path.join(cfg.outdir, "if_bytes_size.joblib"))

    print("[OK] Artifacts saved to:", cfg.outdir)
    print("  - scaler.json")
    print("  - size_baseline.json")
    print("  - if_bytes_size.joblib")

# -----------------------------
# CLI
# -----------------------------

def main():
    ap = argparse.ArgumentParser(description="Anomalyzer Wi‑Fi live-capture trainer (no CSV outputs).")
    ap.add_argument("--iface", required=True, help="Wi‑Fi interface (e.g., wlan0, en0). Requires sudo/admin.")
    ap.add_argument("--collect_seconds", type=int, default=60, help="Capture duration in seconds.")
    ap.add_argument("--window_sec", type=int, default=1, help="Aggregation window in seconds.")
    ap.add_argument("--bpf", default="ip or ip6", help="Optional BPF filter (default captures IP traffic).")
    ap.add_argument("--outdir", default="artifacts_simple", help="Directory to save artifacts.")
    ap.add_argument("--baseline_frac", type=float, default=0.7, help="Fraction of windows used as baseline.")
    args = ap.parse_args()

    # Capture real packets
    print(f"[INFO] Capturing on iface={args.iface} for {args.collect_seconds}s (BPF: {args.bpf})...")
    pkt_rows = capture_packets(iface=args.iface, seconds=args.collect_seconds, bpf=args.bpf, promisc=True)
    print(f"[INFO] Captured {len(pkt_rows)} packets. Aggregating into {args.window_sec}s windows...")

    df = aggregate_windows(pkt_rows, window_sec=args.window_sec)
    df = df[["total_bytes","size"]]

    # Train & save artifacts
    cfg = Config(outdir=args.outdir, baseline_frac=args.baseline_frac)
    train_and_save_models(df, cfg)

if __name__ == "__main__":
    main()
