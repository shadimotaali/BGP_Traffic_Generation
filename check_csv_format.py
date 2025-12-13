#!/usr/bin/env python3
"""
Quick diagnostic to check CSV format
Run this on your machine: python3 check_csv_format.py
"""
import csv
from collections import Counter

# Change this to your CSV file path
CSV_FILE = "/home/smotaali/BGP_Traffic_Generation/results/bgp_updates_analysis_20251213_185355.csv"

print(f"Checking: {CSV_FILE}")
print("=" * 70)

with open(CSV_FILE, 'r') as f:
    reader = csv.reader(f)
    header = next(reader)

    print(f"\n[1] COLUMNS ({len(header)}):")
    for i, col in enumerate(header):
        print(f"    {i}: '{col}'")

    # Count all rows and type values
    type_counts = Counter()
    total_rows = 0

    # Reset and read all
    f.seek(0)
    next(csv.reader(f))  # skip header again

    for row in csv.reader(f):
        total_rows += 1
        # Check column index 2 (usually Subtype/Entry_Type)
        if len(row) > 2:
            type_counts[row[2]] += 1

    print(f"\n[2] TOTAL ROWS: {total_rows}")

    print(f"\n[3] VALUES in column index 2 ('{header[2]}'):")
    for val, count in type_counts.most_common():
        pct = count / total_rows * 100
        marker = "✅" if val in ['A', 'W', 'ANNOUNCE', 'WITHDRAW'] else "❓"
        print(f"    {marker} '{val}': {count} ({pct:.1f}%)")

    # Check what feature extraction expects vs what's in CSV
    print("\n" + "=" * 70)
    print("[4] DIAGNOSIS:")
    print("=" * 70)

    expected_announce = ['A', 'ANNOUNCE']
    expected_withdraw = ['W', 'WITHDRAW', 'WITHDRAWAL']

    found_announce = [v for v in type_counts.keys() if v in expected_announce]
    found_withdraw = [v for v in type_counts.keys() if v in expected_withdraw]

    if found_announce:
        print(f"    ✅ Announcements found as: {found_announce}")
    else:
        print(f"    ❌ No announcement type found! Expected one of: {expected_announce}")
        print(f"       Actual values: {list(type_counts.keys())}")

    if found_withdraw:
        print(f"    ✅ Withdrawals found as: {found_withdraw}")
    else:
        print(f"    ❌ No withdrawal type found! Expected one of: {expected_withdraw}")

    # Calculate percentages
    announce_count = sum(type_counts.get(v, 0) for v in expected_announce)
    withdraw_count = sum(type_counts.get(v, 0) for v in expected_withdraw)
    other_count = total_rows - announce_count - withdraw_count

    print(f"\n    Summary:")
    print(f"    - Announcements: {announce_count} ({announce_count/total_rows*100:.1f}%)")
    print(f"    - Withdrawals: {withdraw_count} ({withdraw_count/total_rows*100:.1f}%)")
    if other_count > 0:
        print(f"    - Other/Unknown: {other_count} ({other_count/total_rows*100:.1f}%)")
