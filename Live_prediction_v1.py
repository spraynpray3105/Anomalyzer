"""
Anomalyzer - Lightweight Anomaly Detection System
--------------------------------------------------

Author: Elijah Martin
Project: Anomalyzer
Repository: https://github.com/spraynpray3105/Anomalyzer
Website: https://anomalyzer.wordpress.com
License: Anomalyzer Open GPL-Compatible License with Attribution (AOGPL-Attribution) v1.0

Description:
    This script/module is part of the Anomalyzer project, a lightweight,
    deployable system for network anomaly detection aimed at small and 
    medium businesses. The goal is to provide an easy-to-deploy, baseline-aware
    monitoring system that adapts to local network traffic patterns while 
    conforming to industry standards.

Usage:
    - Import as a module or run as a standalone script.
    - Analyze network flows (PCAP, NetFlow, CSV).
    - Monitor anomalies in real-time or generate reports.
    
Attribution:
    Any derivative work or redistribution of this code must credit:
    "Original work created by Elijah Martin, Anomalyzer 2025."

Notes:
    - This code is licensed under the AOGPL-Attribution license.
    - Redistribution under GPLv3 or later is allowed.
    - Proprietary redistribution or commercial use outside GPL requires
      written permission from Elijah Martin.
"""

import os
import csv
import time
import joblib
import argparse
import numpy as np
import pandas as pd
from datetime import datetime
from tqdm import tqdm
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from scapy.all import sniff, IP, TCP, UDP

# ==============================
# CONFIGURATION
# ==============================
MODEL_PATH = "model.joblib"
SCALER_PATH = "scaler.joblib"
BASELINE_PATH = "baseline_data.csv"
ANOMALY_LOG_PATH = "anomalies_log.csv"

BASELINE_FLOW_COUNT = 3000        # How many flows to capture for baseline
TRAIN_SAMPLE_MIN_PACKETS = 5      # Minimum packets per flow before processing
ANOMALY_THRESHOLD = -0.25         # IsolationForest decision_function threshold
NUMERIC_FEATS = ["duration", "src_bytes", "dst_bytes", "count", "srv_count", "same_srv_rate", "service"]

# ==============================
# ANOMALY LOGGING
# ==============================
def process_anomaly(flow_features, score):
    """Log detected anomalies to CSV and print to console."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": timestamp,
        "duration": flow_features[0],
        "src_bytes": flow_features[1],
        "dst_bytes": flow_features[2],
        "count": flow_features[3],
        "srv_count": flow_features[4],
        "same_srv_rate": flow_features[5],
        "service": flow_features[6],
        "anomaly_score": round(score, 4),
    }

    # CLI output
    print(f"!!!  [{timestamp}] Anomaly Detected → Score={score:.4f}")
    print(f"   Features: {entry}")

    # Save to CSV
    file_exists = os.path.isfile(ANOMALY_LOG_PATH)
    with open(ANOMALY_LOG_PATH, mode="a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=entry.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(entry)

# ==============================
# BASELINE COLLECTION
# ==============================
def collect_baseline(interface):
    """Capture live traffic to create a baseline dataset."""
    print(f"\n---> Collecting baseline for {BASELINE_FLOW_COUNT} flows on {interface}...\n")

    baseline_data = []
    flows = {}
    pbar = tqdm(total=BASELINE_FLOW_COUNT, desc="Collecting baseline", unit="flow")

    def process_packet(pkt):
        """Process packets and extract flow features for baseline."""
        try:
            if IP in pkt:
                # Extract network identifiers
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
                dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                key = (src, dst, sport, dport, proto)

                # Track flow state
                flow = flows.setdefault(
                    key,
                    {
                        "start": time.time(),
                        "src_bytes": 0,
                        "dst_bytes": 0,
                        "num_packets": 0,
                        "count": 0,
                        "srv_count": 0,
                        "same_srv_rate": 0,
                        "service": dport,
                    },
                )

                # Update flow stats
                flow["num_packets"] += 1
                flow["src_bytes"] += len(pkt)
                flow["dst_bytes"] += len(pkt)
                flow["duration"] = time.time() - flow["start"]
                flow["count"] += 1

                # Record flow once it has enough packets
                if flow["num_packets"] >= TRAIN_SAMPLE_MIN_PACKETS:
                    baseline_data.append([
                        flow["duration"],
                        flow["src_bytes"],
                        flow["dst_bytes"],
                        flow["count"],
                        flow["srv_count"],
                        flow["same_srv_rate"],
                        flow["service"],
                    ])
                    pbar.update(1)
                    del flows[key]

                    # Stop collecting once baseline is reached
                    if len(baseline_data) >= BASELINE_FLOW_COUNT:
                        raise KeyboardInterrupt
        except Exception:
            pass

    try:
        sniff(iface=interface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        pbar.close()
        if len(baseline_data) == 0:
            print("!!! No baseline data collected. Returning empty DataFrame.")
            return pd.DataFrame(columns=NUMERIC_FEATS)
        else:
            print(f"\n---> Baseline collection complete: {len(baseline_data)} flows.\n")
            df = pd.DataFrame(baseline_data, columns=NUMERIC_FEATS)
            return df

# ==============================
# TRAINING
# ==============================
def train_model(df):
    """Train IsolationForest model using baseline data."""
    print("---> Training model on baseline data...")
    if df is None or df.empty:
        raise ValueError("!!! No valid data provided for training. Baseline may be empty.")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df[NUMERIC_FEATS])

    model = IsolationForest(n_estimators=150, contamination=0.01, random_state=42)
    model.fit(X_scaled)

    # Save trained model and scaler
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    df.to_csv(BASELINE_PATH, index=False)

    print("---> Model and scaler saved.\n")
    return model, scaler

# ==============================
# LIVE MONITORING
# ==============================
def live_monitor(model, scaler, interface):
    """Continuously monitor live network traffic and detect anomalies."""
    print(f"\n---> Monitoring live traffic on {interface} (Press Ctrl+C to stop)...\n")
    flows = {}

    def extract_features(flow):
        return [
            flow["duration"],
            flow["src_bytes"],
            flow["dst_bytes"],
            flow["count"],
            flow["srv_count"],
            flow["same_srv_rate"],
            flow["service"],
        ]

    def process_packet(pkt):
        try:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
                dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                key = (src, dst, sport, dport, proto)

                flow = flows.setdefault(
                    key,
                    {
                        "start": time.time(),
                        "src_bytes": 0,
                        "dst_bytes": 0,
                        "num_packets": 0,
                        "count": 0,
                        "srv_count": 0,
                        "same_srv_rate": 0,
                        "service": dport,
                    },
                )

                flow["num_packets"] += 1
                flow["src_bytes"] += len(pkt)
                flow["dst_bytes"] += len(pkt)
                flow["duration"] = time.time() - flow["start"]
                flow["count"] += 1

                if flow["num_packets"] >= TRAIN_SAMPLE_MIN_PACKETS:
                    features_df = pd.DataFrame([extract_features(flow)], columns=NUMERIC_FEATS)
                    X_scaled = scaler.transform(features_df)
                    score = model.decision_function(X_scaled)[0]

                    if score < ANOMALY_THRESHOLD:
                        process_anomaly(features.flatten().tolist(), score)

                    del flows[key]
        except Exception as e:
            print(f"[PROCESS PACKET ERROR] {e}")

    sniff(iface=interface, prn=process_packet, store=False)

# ==============================
# UTILITY: NETWORK INTERFACE
# ==============================
def get_active_interface():
    """Automatically detect an active network interface (Windows-compatible)."""
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        for iface in interfaces:
            if "Wi-Fi" in iface["name"] or "Ethernet" in iface["name"]:
                return iface["name"]
        return interfaces[0]["name"]
    except Exception:
        return "Wi-Fi"

# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live Anomaly Detection Framework")
    parser.add_argument("--collect", action="store_true", help="Collect new baseline data and retrain model")
    parser.add_argument("--flowcount", type=int, default=3000, help="Specify the number of flows to collect")
    args = parser.parse_args()

    # Set the value of BASELINE_FLOW_COUNT to what was passed under --flowcount
    if args.flowcount != 0 and args.flowcount is not None:
        BASELINE_FLOW_COUNT = args.flowcount

    #interface = get_active_interface()
    interface = "Wi-Fi"  # Hard-coded for testing purposes - remove for production.
    print(f"---> Using interface: {interface}")

    # ==============================
    # COLLECT MODE
    # ==============================
    if args.collect:
        new_df = collect_baseline(interface)

        if os.path.exists(BASELINE_PATH):
            old_df = pd.read_csv(BASELINE_PATH)
            combined_df = pd.concat([old_df, new_df], ignore_index=True)
            print(f"---> Combined baseline size: {len(combined_df)}")
        else:
            combined_df = new_df

        model, scaler = train_model(combined_df)

    # ==============================
    # NORMAL MONITORING MODE
    # ==============================
    else:
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            print("---> Loading existing model and scaler...")
            model = joblib.load(MODEL_PATH)
            scaler = joblib.load(SCALER_PATH)
        else:
            print("!!! No existing model/scaler found. Please run with '--collect' first to create them.")
            sys.exit(1)

    # Start monitoring (only if model/scaler available)
    live_monitor(model, scaler, interface)

