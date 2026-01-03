#!/usr/bin/env python3
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


BASE_DIR = Path("/home/smotaali/BGP_Traffic_Generation/RIPE/RIPE_INCIDENTS")

# Which labels should be treated as "attack" classes
ATTACK_LABELS = ["prefix_hijacking", "path_manipulation", "dos_attack"]

# Minimum number of windows needed to attempt refinement for a given class
MIN_CLASS_SAMPLES = 50


def refine_labels_in_features_csv(features_path: Path):
    print(f"[+] Refining labels in {features_path}")
    df = pd.read_csv(features_path)

    if "label" not in df.columns:
        print(f"    [!] No 'label' column in {features_path}, skipping.")
        return

    # Preserve original rule-based label
    if "label_rule" not in df.columns:
        df.rename(columns={"label": "label_rule"}, inplace=True)
    else:
        # if label_rule already exists, keep it and ignore current 'label'
        df.drop(columns=["label"], inplace=True)

    # Initialize refined label as a copy of rule-based label
    df["label_refined"] = df["label_rule"]

    # Identify feature columns: all numeric ones, excluding metadata
    meta_cols = {"Incident", "window_start", "window_end", "label_rule", "label_refined"}
    candidate_cols = [c for c in df.columns if c not in meta_cols]

    # Keep only numeric columns for the model
    feature_cols = df[candidate_cols].select_dtypes(include=[np.number]).columns.tolist()
    if not feature_cols:
        print(f"    [!] No numeric feature columns found, skipping.")
        return

    print(f"    Using {len(feature_cols)} feature columns for refinement.")

    # Work per attack label
    for attack_label in ATTACK_LABELS:
        mask = df["label_rule"] == attack_label
        sub = df[mask].copy()
        n = len(sub)
        if n < MIN_CLASS_SAMPLES:
            print(f"    [-] Label '{attack_label}': only {n} samples, skipping refinement.")
            continue

        print(f"    [*] Refining label '{attack_label}' on {n} windows...")

        X = sub[feature_cols].values
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Isolation Forest: we mark a small fraction as "likely mislabelled"
        iso = IsolationForest(
            n_estimators=200,
            contamination=0.1,   # 10% of windows in this class considered inconsistent
            random_state=42,
            n_jobs=-1
        )
        preds = iso.fit_predict(X_scaled)   # 1 = inlier, -1 = outlier
        sub["iforest_pred"] = preds

        # Policy:
        # - inliers (1): keep attack_label
        # - outliers (-1): downgrade to 'normal_refined'
        sub["label_refined_local"] = attack_label
        sub.loc[sub["iforest_pred"] == -1, "label_refined_local"] = "normal_refined"

        # Write back into main df
        df.loc[mask, "label_refined"] = sub["label_refined_local"].values

        downgraded = (sub["label_refined_local"] == "normal_refined").sum()
        print(f"      -> downgraded {downgraded}/{n} windows to 'normal_refined'")

    # Save refined file next to original
    out_path = features_path.with_name(features_path.stem.replace("_features", "_features_refined") + ".csv")
    df.to_csv(out_path, index=False)
    print(f"[+] Wrote refined labels to {out_path}\n")


def process_all_incidents(base_dir: Path):
    for incident_dir in base_dir.iterdir():
        if not incident_dir.is_dir():
            continue

        # Look for one *_labeled_features.csv in this folder
        for features_csv in incident_dir.glob("*_labeled_features.csv"):
            # Skip if refined file already exists
            refined_csv = features_csv.with_name(features_csv.stem.replace("_features", "_features_refined") + ".csv")
            #if refined_csv.exists():
            #    print(f"[=] Skipping {features_csv} (refined file already exists).")
            #    continue

            refine_labels_in_features_csv(features_csv)


if __name__ == "__main__":
    process_all_incidents(BASE_DIR)
