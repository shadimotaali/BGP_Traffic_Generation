#!/usr/bin/env python3
"""
Unified BGP Feature Extraction Script

This script extracts consistent features from BGP update data for both:
- Normal traffic data (from RIPE RRC collectors)
- Anomaly/Incident data (from labeled incident datasets)

Supports multiple input formats:
- Format A: Entry_Type column with 'A'/'W' values (incident data from bgpdump)
- Format B: Subtype column with 'ANNOUNCE'/'WITHDRAW' values (normal data)

Features extracted (27 total):
- Volume: announcements, withdrawals, nlri_ann, dups
- Origin: origin_0 (IGP), origin_2 (INCOMPLETE), origin_changes
- Implicit Withdrawals: imp_wd, imp_wd_spath, imp_wd_dpath
- AS Path: as_path_max, unique_as_path_max
- Edit Distance: edit_distance_avg, edit_distance_max, edit_distance_dict_0-6,
                 edit_distance_unique_dict_0-1
- Rare AS: number_rare_ases, rare_ases_avg
- Stability: nadas, flaps

Author: BGP Traffic Generation Project
"""

import pandas as pd
import numpy as np
from collections import defaultdict, Counter
from pathlib import Path
from datetime import datetime
import argparse
import sys

# =============================================================================
# CONFIGURATION
# =============================================================================

WINDOW_SIZE = '1s'  # Time window for feature aggregation
LABEL_STRATEGY = 'majority'  # Options: 'majority', 'conservative', 'weighted'
RARE_AS_THRESHOLD = 3  # ASNs appearing less than this are considered "rare"

# Entry type mappings for different formats
ANNOUNCE_TYPES = ['A', 'ANNOUNCE']
WITHDRAW_TYPES = ['W', 'WITHDRAW', 'WITHDRAW_MP_UNREACH_NLRI_AFI2']


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def calculate_edit_distance(as_path1, as_path2):
    """
    Calculate Levenshtein edit distance between two AS paths.

    Parameters:
    -----------
    as_path1, as_path2 : str, int, or list
        AS paths to compare

    Returns:
    --------
    int : Edit distance between the two paths
    """
    if not as_path1 or not as_path2:
        return 0

    # Convert to list of integers
    def path_to_list(path):
        if isinstance(path, int):
            return [path]
        if isinstance(path, list):
            return path
        if isinstance(path, str):
            # Remove AS_SET brackets and split
            path = path.replace('{', '').replace('}', '')
            return [int(a) for a in path.split() if a.isdigit()]
        return []

    list1 = path_to_list(as_path1)
    list2 = path_to_list(as_path2)

    if not list1 or not list2:
        return 0

    m, n = len(list1), len(list2)

    # Dynamic programming matrix
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if list1[i-1] == list2[j-1]:
                dp[i][j] = dp[i-1][j-1]
            else:
                dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])

    return dp[m][n]


def get_path_length(as_path):
    """
    Get the length of an AS path.

    Parameters:
    -----------
    as_path : str, int, or None
        AS path to measure

    Returns:
    --------
    int : Number of ASNs in the path
    """
    if pd.isnull(as_path) or as_path == '':
        return 0
    if isinstance(as_path, int):
        return 1
    if isinstance(as_path, str):
        as_path = as_path.replace('{', '').replace('}', '')
        return len([a for a in as_path.split() if a.isdigit()])
    return 0


def attributes_are_same(row1, row2, attrs=None):
    """
    Check if BGP attributes are the same between two announcements.

    Parameters:
    -----------
    row1, row2 : pd.Series
        Two BGP announcement rows to compare
    attrs : list, optional
        List of attribute names to compare

    Returns:
    --------
    bool : True if all attributes are the same
    """
    if attrs is None:
        attrs = ['AS_Path', 'Origin', 'Next_Hop', 'MED', 'Local_Pref', 'Communities']

    for attr in attrs:
        if attr in row1.index and attr in row2.index:
            v1, v2 = row1[attr], row2[attr]
            # Both NaN = same
            if pd.isna(v1) and pd.isna(v2):
                continue
            # One NaN, one not = different
            if pd.isna(v1) or pd.isna(v2):
                return False
            # Direct comparison
            if v1 != v2:
                return False
    return True


def calculate_nadas_and_flaps(df_window, entry_type_col='Entry_Type'):
    """
    Calculate NADAS and FLAPS using proper state-based tracking.

    NADAS (Network Anomaly Detection and Analysis Score):
        Re-announcement after withdrawal with DIFFERENT attributes

    FLAPS:
        Re-announcement after withdrawal with SAME attributes

    Parameters:
    -----------
    df_window : pd.DataFrame
        DataFrame with BGP updates for a time window
    entry_type_col : str
        Column name containing entry type ('A'/'W' or 'ANNOUNCE'/'WITHDRAW')

    Returns:
    --------
    tuple : (nadas_count, flap_count)
    """
    nadas_count = 0
    flap_count = 0

    # Define withdrawal types
    withdrawal_types = ['W', 'WITHDRAW', 'WITHDRAW_MP_UNREACH_NLRI_AFI2']
    announce_types = ['A', 'ANNOUNCE']

    # Sort by timestamp
    df_sorted = df_window.sort_values('Timestamp')

    # Track state per (prefix, peer) pair
    prefix_state = {}

    for _, row in df_sorted.iterrows():
        key = (row.get('Prefix', ''), row.get('Peer_IP', ''))
        entry_type = row.get(entry_type_col, '')

        is_announce = entry_type in announce_types
        is_withdraw = entry_type in withdrawal_types

        if is_announce:
            if key in prefix_state and prefix_state[key].get('withdrawn', False):
                # This is a re-announcement after withdrawal
                last_ann = prefix_state[key].get('last_ann')
                if last_ann is not None:
                    if attributes_are_same(last_ann, row):
                        flap_count += 1  # Same attributes = FLAP
                    else:
                        nadas_count += 1  # Different attributes = NADAS
                else:
                    nadas_count += 1  # No previous announcement to compare
                prefix_state[key]['withdrawn'] = False

            # Update state
            prefix_state.setdefault(key, {})
            prefix_state[key]['last_ann'] = row
            prefix_state[key]['withdrawn'] = False

        elif is_withdraw:
            if key in prefix_state:
                prefix_state[key]['withdrawn'] = True
            else:
                prefix_state[key] = {'last_ann': None, 'withdrawn': True}

    return nadas_count, flap_count


# =============================================================================
# MAIN FEATURE EXTRACTION FUNCTION
# =============================================================================

def extract_features(df_window, entry_type_col='Entry_Type'):
    """
    Extract all BGP features from a time window.

    Parameters:
    -----------
    df_window : pd.DataFrame
        DataFrame with BGP updates for a single time window
    entry_type_col : str
        Column name containing entry type

    Returns:
    --------
    dict : Dictionary of extracted features
    """
    features = {}

    # Define entry types
    announce_types = ['A', 'ANNOUNCE']
    withdrawal_types = ['W', 'WITHDRAW', 'WITHDRAW_MP_UNREACH_NLRI_AFI2']

    # Separate announcements and withdrawals
    announcements = df_window[df_window[entry_type_col].isin(announce_types)]
    withdrawals = df_window[df_window[entry_type_col].isin(withdrawal_types)]

    # -------------------------------------------------------------------------
    # 1-3. VOLUME FEATURES
    # -------------------------------------------------------------------------
    features['announcements'] = len(announcements)
    features['withdrawals'] = len(withdrawals)
    features['nlri_ann'] = announcements['Prefix'].nunique() if not announcements.empty else 0

    # -------------------------------------------------------------------------
    # 4. DUPLICATES
    # Same prefix announced with identical attributes
    # -------------------------------------------------------------------------
    if not announcements.empty:
        dup_cols = ['Peer_IP', 'Peer_ASN', 'Prefix', 'AS_Path', 'Origin',
                    'Next_Hop', 'MED', 'Local_Pref', 'Communities']
        dup_cols = [c for c in dup_cols if c in announcements.columns]

        if dup_cols:
            counts = announcements.groupby(dup_cols, dropna=False).size()
            features['dups'] = sum(c - 1 for c in counts if c > 1)
        else:
            features['dups'] = 0
    else:
        features['dups'] = 0

    # -------------------------------------------------------------------------
    # 5-7. ORIGIN ATTRIBUTES
    # -------------------------------------------------------------------------
    if not announcements.empty and 'Origin' in announcements.columns:
        origin_counts = announcements['Origin'].value_counts()
        features['origin_0'] = origin_counts.get('IGP', 0)
        features['origin_2'] = origin_counts.get('INCOMPLETE', 0)

        # Origin changes: prefixes with multiple unique origins
        unique_origins = announcements.groupby('Prefix')['Origin'].nunique()
        features['origin_changes'] = (unique_origins > 1).sum()
    else:
        features['origin_0'] = 0
        features['origin_2'] = 0
        features['origin_changes'] = 0

    # -------------------------------------------------------------------------
    # 8-10. IMPLICIT WITHDRAWALS
    # When same prefix is re-announced with different attributes
    # -------------------------------------------------------------------------
    imp_wd = 0
    imp_wd_spath = 0  # Same AS path, different other attributes
    imp_wd_dpath = 0  # Different AS path
    edit_distances = []
    edit_distance_dict = defaultdict(list)

    attrs_to_check = ['AS_Path', 'Origin', 'Next_Hop', 'MED', 'Local_Pref', 'Communities']
    attrs_available = [a for a in attrs_to_check if a in announcements.columns]

    if not announcements.empty and len(attrs_available) > 0:
        for (prefix, peer), grp in announcements.groupby(['Prefix', 'Peer_IP']):
            if len(grp) < 2:
                continue

            grp = grp.sort_values('Timestamp')
            prev = None

            for _, row in grp.iterrows():
                if prev is not None:
                    # Check if any attribute changed
                    changed = False
                    as_path_changed = False

                    for attr in attrs_available:
                        pv, cv = prev.get(attr), row.get(attr)
                        pv_nan, cv_nan = pd.isna(pv), pd.isna(cv)

                        if pv_nan and cv_nan:
                            continue
                        if pv_nan or cv_nan or pv != cv:
                            changed = True
                            if attr == 'AS_Path':
                                as_path_changed = True

                    if changed:
                        imp_wd += 1
                        if as_path_changed:
                            imp_wd_dpath += 1
                            # Calculate edit distance
                            d = calculate_edit_distance(
                                prev.get('AS_Path', ''),
                                row.get('AS_Path', '')
                            )
                            edit_distances.append(d)
                            edit_distance_dict[prefix].append(d)
                        else:
                            imp_wd_spath += 1

                prev = row

    features['imp_wd'] = imp_wd
    features['imp_wd_spath'] = imp_wd_spath
    features['imp_wd_dpath'] = imp_wd_dpath

    # -------------------------------------------------------------------------
    # 11-12. AS PATH METRICS
    # -------------------------------------------------------------------------
    if not announcements.empty and 'AS_Path' in announcements.columns:
        valid_paths = announcements[
            announcements['AS_Path'].notna() &
            (announcements['AS_Path'] != '')
        ]

        if not valid_paths.empty:
            # Maximum AS path length
            lengths = valid_paths['AS_Path'].apply(get_path_length)
            features['as_path_max'] = int(lengths.max()) if not lengths.empty else 0

            # Maximum unique paths per prefix
            unique_paths = valid_paths.groupby('Prefix')['AS_Path'].nunique()
            features['unique_as_path_max'] = int(unique_paths.max()) if not unique_paths.empty else 0
        else:
            features['as_path_max'] = 0
            features['unique_as_path_max'] = 0
    else:
        features['as_path_max'] = 0
        features['unique_as_path_max'] = 0

    # -------------------------------------------------------------------------
    # 13-21. EDIT DISTANCE FEATURES
    # -------------------------------------------------------------------------
    if edit_distances:
        features['edit_distance_avg'] = float(np.mean(edit_distances))
        features['edit_distance_max'] = int(max(edit_distances))

        # Distribution of edit distances (0-6)
        dist_counter = Counter(edit_distances)
        for i in range(7):
            features[f'edit_distance_dict_{i}'] = dist_counter.get(i, 0)

        # Unique edit distances per prefix (0-1)
        unique_ed = defaultdict(int)
        for prefix, dists in edit_distance_dict.items():
            for d in set(dists):
                unique_ed[d] += 1

        for i in range(2):
            features[f'edit_distance_unique_dict_{i}'] = unique_ed.get(i, 0)
    else:
        features['edit_distance_avg'] = 0.0
        features['edit_distance_max'] = 0
        for i in range(7):
            features[f'edit_distance_dict_{i}'] = 0
        for i in range(2):
            features[f'edit_distance_unique_dict_{i}'] = 0

    # -------------------------------------------------------------------------
    # 22-23. RARE AS FEATURES
    # -------------------------------------------------------------------------
    if not announcements.empty and 'AS_Path' in announcements.columns:
        all_asns = []

        for as_path in announcements['AS_Path']:
            if pd.isnull(as_path) or as_path == '':
                continue

            path_str = str(as_path).replace('{', '').replace('}', '')
            all_asns.extend([a for a in path_str.split() if a.isdigit()])

        if all_asns:
            asn_counts = Counter(all_asns)
            rare_asns = [a for a, c in asn_counts.items() if c < RARE_AS_THRESHOLD]

            features['number_rare_ases'] = len(rare_asns)
            features['rare_ases_avg'] = len(rare_asns) / len(all_asns)
        else:
            features['number_rare_ases'] = 0
            features['rare_ases_avg'] = 0.0
    else:
        features['number_rare_ases'] = 0
        features['rare_ases_avg'] = 0.0

    # -------------------------------------------------------------------------
    # 24-25. NADAS AND FLAPS (State-based)
    # -------------------------------------------------------------------------
    nadas, flaps = calculate_nadas_and_flaps(df_window, entry_type_col)
    features['nadas'] = nadas
    features['flaps'] = flaps

    # -------------------------------------------------------------------------
    # LABEL AGGREGATION
    # -------------------------------------------------------------------------
    if 'Label' in df_window.columns:
        labels = df_window['Label'].value_counts()
        if not labels.empty:
            if LABEL_STRATEGY == 'majority':
                features['label'] = labels.idxmax()
            elif LABEL_STRATEGY == 'conservative':
                # If any non-normal, use that
                abnormal = [l for l in labels.index if l != 'normal']
                features['label'] = abnormal[0] if abnormal else 'normal'
            elif LABEL_STRATEGY == 'weighted':
                total = labels.sum()
                abnormal_weight = sum(c for l, c in labels.items() if l != 'normal') / total
                if abnormal_weight > 0.4:
                    abnormal = [l for l in labels.index if l != 'normal']
                    features['label'] = abnormal[0] if abnormal else 'normal'
                else:
                    features['label'] = 'normal'
            else:
                features['label'] = labels.idxmax()
        else:
            features['label'] = 'unknown'
    else:
        features['label'] = 'unknown'

    # Keep incident name if present
    if 'Incident' in df_window.columns:
        features['Incident'] = df_window['Incident'].iloc[0]

    return features


# =============================================================================
# DATA PROCESSING FUNCTIONS
# =============================================================================

def standardize_dataframe(df):
    """
    Standardize DataFrame column names and types for consistent processing.

    Parameters:
    -----------
    df : pd.DataFrame
        Raw BGP data

    Returns:
    --------
    pd.DataFrame : Standardized DataFrame
    str : Entry type column name
    """
    df = df.copy()

    # Standardize timestamp
    if 'Timestamp' not in df.columns:
        if 'Time' in df.columns:
            df['Timestamp'] = pd.to_datetime(df['Time'])
        else:
            raise ValueError("No timestamp column found (expected 'Time' or 'Timestamp')")
    else:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])

    # Standardize column names
    column_mapping = {
        'Peer_AS': 'Peer_ASN',
        'Origin_AS': 'Origin',
        'Community': 'Communities',
        'Subtype': 'Entry_Type'
    }

    for old_name, new_name in column_mapping.items():
        if old_name in df.columns and new_name not in df.columns:
            df.rename(columns={old_name: new_name}, inplace=True)

    # Determine entry type column
    entry_type_col = 'Entry_Type'

    # Map entry types if needed (ANNOUNCE/WITHDRAW -> A/W or vice versa)
    if entry_type_col in df.columns:
        # Check what format we have
        unique_types = df[entry_type_col].unique()

        # If using ANNOUNCE/WITHDRAW format, map to A/W
        if 'ANNOUNCE' in unique_types:
            type_map = {
                'ANNOUNCE': 'A',
                'WITHDRAW': 'W',
                'WITHDRAW_MP_UNREACH_NLRI_AFI2': 'W'
            }
            df[entry_type_col] = df[entry_type_col].map(lambda x: type_map.get(x, x))

    return df, entry_type_col


def process_single_file(input_path, output_path, window_size=WINDOW_SIZE):
    """
    Process a single BGP data file and extract features.

    Parameters:
    -----------
    input_path : Path
        Path to input CSV file
    output_path : Path
        Path to output features CSV file
    window_size : str
        Time window size (e.g., '1s', '30s', '5min')
    """
    print(f"\n[+] Processing: {input_path}")

    # Read data
    df = pd.read_csv(input_path, low_memory=False)
    print(f"    Loaded {len(df):,} records")

    # Standardize
    df, entry_type_col = standardize_dataframe(df)

    # Sort by timestamp
    df = df.sort_values('Timestamp')

    # Get time range
    start_time = df['Timestamp'].min()
    end_time = df['Timestamp'].max()
    print(f"    Time range: {start_time} to {end_time}")

    # Set index for grouping
    df.set_index('Timestamp', inplace=True)

    # Extract features per window
    features_list = []
    window_count = 0

    for window_start, window_df in df.groupby(pd.Grouper(freq=window_size)):
        if window_df.empty:
            continue

        # Reset index for processing
        window_df = window_df.reset_index()

        # Extract features
        features = extract_features(window_df, entry_type_col)

        if features:
            window_end = window_start + pd.Timedelta(window_size)
            features['window_start'] = window_start
            features['window_end'] = window_end
            features_list.append(features)
            window_count += 1

            if window_count % 1000 == 0:
                print(f"    Processed {window_count} windows...")

    print(f"    Total windows: {window_count}")

    # Save features
    if features_list:
        features_df = pd.DataFrame(features_list)

        # Ensure consistent column order
        ordered_cols = [
            'announcements', 'withdrawals', 'nlri_ann', 'dups',
            'origin_0', 'origin_2', 'origin_changes',
            'imp_wd', 'imp_wd_spath', 'imp_wd_dpath',
            'as_path_max', 'unique_as_path_max',
            'edit_distance_avg', 'edit_distance_max',
            'edit_distance_dict_0', 'edit_distance_dict_1', 'edit_distance_dict_2',
            'edit_distance_dict_3', 'edit_distance_dict_4', 'edit_distance_dict_5',
            'edit_distance_dict_6',
            'edit_distance_unique_dict_0', 'edit_distance_unique_dict_1',
            'number_rare_ases', 'rare_ases_avg',
            'nadas', 'flaps',
            'label', 'Incident', 'window_start', 'window_end'
        ]

        # Only include columns that exist
        final_cols = [c for c in ordered_cols if c in features_df.columns]
        # Add any extra columns not in the ordered list
        extra_cols = [c for c in features_df.columns if c not in final_cols]
        final_cols.extend(extra_cols)

        features_df = features_df[final_cols]
        features_df.to_csv(output_path, index=False)
        print(f"[+] Saved features to: {output_path}")
        print(f"    Shape: {features_df.shape}")

        return features_df
    else:
        print(f"[!] No features extracted from {input_path}")
        return None


def process_incident_directory(base_dir, skip_existing=True):
    """
    Process all incident directories and extract features.

    Parameters:
    -----------
    base_dir : Path
        Base directory containing incident subdirectories
    skip_existing : bool
        Whether to skip files that already have features extracted
    """
    base_dir = Path(base_dir)

    print("="*70)
    print("PROCESSING INCIDENT DATA")
    print("="*70)

    processed = 0
    skipped = 0

    for incident_dir in sorted(base_dir.iterdir()):
        if not incident_dir.is_dir():
            continue

        # Find labeled CSV files
        for csv_path in incident_dir.glob("*_labeled.csv"):
            out_path = incident_dir / (csv_path.stem + "_features.csv")

            if skip_existing and out_path.exists():
                print(f"[~] Skipping (exists): {out_path.name}")
                skipped += 1
                continue

            process_single_file(csv_path, out_path)
            processed += 1

    print("\n" + "="*70)
    print(f"COMPLETE: Processed {processed}, Skipped {skipped}")
    print("="*70)


def process_normal_data(input_file, output_file):
    """
    Process normal BGP traffic data and extract features.

    Parameters:
    -----------
    input_file : str or Path
        Path to input CSV file
    output_file : str or Path
        Path to output features CSV file
    """
    print("="*70)
    print("PROCESSING NORMAL TRAFFIC DATA")
    print("="*70)

    process_single_file(Path(input_file), Path(output_file))


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Unified BGP Feature Extraction',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process incident data
  python unified_feature_extraction.py --incidents /path/to/RIPE_INCIDENTS

  # Process normal traffic data
  python unified_feature_extraction.py --normal /path/to/input.csv --output /path/to/output.csv

  # Process single file
  python unified_feature_extraction.py --file /path/to/input.csv --output /path/to/output.csv

  # Change window size
  python unified_feature_extraction.py --file input.csv --output output.csv --window 30s
        """
    )

    parser.add_argument('--incidents', type=str,
                        help='Base directory containing incident subdirectories')
    parser.add_argument('--normal', type=str,
                        help='Path to normal traffic CSV file')
    parser.add_argument('--file', type=str,
                        help='Path to a single CSV file to process')
    parser.add_argument('--output', type=str,
                        help='Output file path (required for --normal and --file)')
    parser.add_argument('--window', type=str, default=WINDOW_SIZE,
                        help=f'Time window size (default: {WINDOW_SIZE})')
    parser.add_argument('--no-skip', action='store_true',
                        help='Do not skip existing feature files')

    args = parser.parse_args()

    # Update global window size
    global WINDOW_SIZE
    WINDOW_SIZE = args.window

    if args.incidents:
        process_incident_directory(args.incidents, skip_existing=not args.no_skip)
    elif args.normal:
        if not args.output:
            print("Error: --output required with --normal")
            sys.exit(1)
        process_normal_data(args.normal, args.output)
    elif args.file:
        if not args.output:
            print("Error: --output required with --file")
            sys.exit(1)
        process_single_file(Path(args.file), Path(args.output))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
