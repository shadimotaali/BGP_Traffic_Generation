#!/usr/bin/env python3
"""
Diagnostic script to identify why feature extraction only processes 33% of data
"""

import pandas as pd
import numpy as np
from collections import Counter

def diagnose_csv(csv_file):
    """Diagnose issues with CSV data for feature extraction"""

    print("=" * 70)
    print("CSV DIAGNOSTIC REPORT")
    print("=" * 70)

    # Read CSV
    print(f"\n[1] Reading CSV: {csv_file}")
    try:
        df = pd.read_csv(csv_file)
        print(f"    ✅ Successfully read {len(df)} rows")
    except Exception as e:
        print(f"    ❌ Error reading CSV: {e}")
        return

    # Check columns
    print(f"\n[2] Columns in CSV:")
    for col in df.columns:
        print(f"    - {col}")

    # Check Entry_Type distribution
    print(f"\n[3] Entry_Type distribution:")
    if 'Entry_Type' in df.columns:
        entry_types = df['Entry_Type'].value_counts()
        for entry_type, count in entry_types.items():
            pct = count / len(df) * 100
            print(f"    - {entry_type}: {count} ({pct:.1f}%)")

        # Check which types feature extraction will process
        announcements = df[df['Entry_Type'] == 'A']
        withdrawals = df[df['Entry_Type'].isin(['W', 'WITHDRAW_MP_UNREACH_NLRI_AFI2'])]
        other = df[~df['Entry_Type'].isin(['A', 'W', 'WITHDRAW_MP_UNREACH_NLRI_AFI2'])]

        print(f"\n    Feature extraction will process:")
        print(f"    - Announcements (A): {len(announcements)} ({len(announcements)/len(df)*100:.1f}%)")
        print(f"    - Withdrawals (W): {len(withdrawals)} ({len(withdrawals)/len(df)*100:.1f}%)")
        print(f"    - Other (IGNORED): {len(other)} ({len(other)/len(df)*100:.1f}%)")

        if len(other) > 0:
            print(f"\n    ⚠️  WARNING: {len(other)} rows have unrecognized Entry_Type!")
            print(f"    Unrecognized types: {other['Entry_Type'].unique().tolist()}")
    else:
        print("    ❌ 'Entry_Type' column not found!")

    # Check Time/Timestamp column
    print(f"\n[4] Timestamp analysis:")
    time_col = None
    if 'Time' in df.columns:
        time_col = 'Time'
    elif 'Timestamp' in df.columns:
        time_col = 'Timestamp'

    if time_col:
        print(f"    Using column: {time_col}")

        # Check for parsing issues
        try:
            df['parsed_time'] = pd.to_datetime(df[time_col])
            valid_times = df['parsed_time'].notna().sum()
            invalid_times = df['parsed_time'].isna().sum()
            print(f"    - Valid timestamps: {valid_times} ({valid_times/len(df)*100:.1f}%)")
            print(f"    - Invalid timestamps: {invalid_times} ({invalid_times/len(df)*100:.1f}%)")

            if valid_times > 0:
                print(f"    - Time range: {df['parsed_time'].min()} to {df['parsed_time'].max()}")
                duration = (df['parsed_time'].max() - df['parsed_time'].min()).total_seconds()
                print(f"    - Duration: {duration:.1f} seconds ({duration/60:.2f} minutes)")
        except Exception as e:
            print(f"    ❌ Error parsing timestamps: {e}")
            print(f"    Sample values: {df[time_col].head(5).tolist()}")
    else:
        print("    ❌ No 'Time' or 'Timestamp' column found!")

    # Check Label column
    print(f"\n[5] Label distribution:")
    if 'Label' in df.columns:
        labels = df['Label'].value_counts()
        for label, count in labels.items():
            pct = count / len(df) * 100
            print(f"    - {label}: {count} ({pct:.1f}%)")
    else:
        print("    ⚠️  'Label' column not found (will use 'unknown')")

    # Check for empty/null values in key columns
    print(f"\n[6] Null/empty value check:")
    key_cols = ['Entry_Type', 'Prefix', 'Peer_IP', 'AS_Path']
    for col in key_cols:
        if col in df.columns:
            null_count = df[col].isna().sum()
            empty_count = (df[col] == '').sum() if df[col].dtype == 'object' else 0
            total_missing = null_count + empty_count
            if total_missing > 0:
                print(f"    ⚠️  {col}: {total_missing} missing values ({total_missing/len(df)*100:.1f}%)")
            else:
                print(f"    ✅ {col}: No missing values")
        else:
            print(f"    ❌ {col}: Column not found!")

    # Simulate windowing
    print(f"\n[7] Window simulation (1s windows):")
    if time_col and 'parsed_time' in df.columns:
        df_valid = df[df['parsed_time'].notna()].copy()
        df_valid.set_index('parsed_time', inplace=True)

        grouped = df_valid.groupby(pd.Grouper(freq='1s'))
        non_empty_windows = sum(1 for _, g in grouped if not g.empty)
        total_windows = len(grouped)

        print(f"    - Total windows: {total_windows}")
        print(f"    - Non-empty windows: {non_empty_windows}")
        print(f"    - Empty windows: {total_windows - non_empty_windows}")

        # Check rows per window
        rows_per_window = [len(g) for _, g in grouped if not g.empty]
        if rows_per_window:
            print(f"    - Avg rows/window: {np.mean(rows_per_window):.1f}")
            print(f"    - Max rows/window: {max(rows_per_window)}")
            print(f"    - Min rows/window: {min(rows_per_window)}")

    # Summary
    print(f"\n" + "=" * 70)
    print("DIAGNOSIS SUMMARY")
    print("=" * 70)

    if 'Entry_Type' in df.columns:
        ann_pct = len(df[df['Entry_Type'] == 'A']) / len(df) * 100
        if ann_pct < 50:
            print(f"⚠️  Only {ann_pct:.1f}% of rows are announcements (Entry_Type='A')")
            print("   This might explain why only ~33% of data is being 'processed'")
            print("   (Withdrawals are counted but don't contribute to most features)")

    print("\nRECOMMENDATIONS:")
    print("1. Ensure all BGP UPDATE packets have Entry_Type='A' or 'W'")
    print("2. Check that timestamps are in a parseable format")
    print("3. The feature extraction processes ALL rows, but most features")
    print("   are computed from announcements only (this is correct behavior)")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        csv_file = sys.argv[1]
    else:
        # Default paths to check
        possible_files = [
            "./pcaps/mixed_bgp_traffic_enhanced.csv",
            "./pcaps/bgp_v6_correlated.csv",
            "./results/extracted_features.csv",
        ]
        csv_file = None
        for f in possible_files:
            import os
            if os.path.exists(f):
                csv_file = f
                break

        if not csv_file:
            print("Usage: python diagnose_feature_extraction.py <csv_file>")
            print("No default CSV file found.")
            sys.exit(1)

    diagnose_csv(csv_file)
