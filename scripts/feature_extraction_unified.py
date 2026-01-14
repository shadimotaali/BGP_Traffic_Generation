#!/usr/bin/env python3
"""
Unified BGP Feature Extraction Code

This script extracts time-window based features from BGP update data.
Works with both incident (RIPE) data and normal traffic data.

Features extracted match the standard BGP anomaly detection feature set.
"""

import pandas as pd
import numpy as np
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Configuration
WINDOW_SIZE = '1s'
LABEL_STRATEGY = 'majority'  # Options: 'majority', 'conservative', 'weighted'


def calculate_edit_distance(as_path1, as_path2) -> int:
    """
    Calculate Levenshtein edit distance between two AS paths.

    Args:
        as_path1: First AS path (string, int, or list)
        as_path2: Second AS path (string, int, or list)

    Returns:
        Edit distance as integer
    """
    if not as_path1 or not as_path2:
        return 0

    # Normalize to list of integers
    path1 = _normalize_as_path(as_path1)
    path2 = _normalize_as_path(as_path2)

    if not path1 or not path2:
        return 0

    m, n = len(path1), len(path2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if path1[i-1] == path2[j-1]:
                dp[i][j] = dp[i-1][j-1]
            else:
                dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])

    return dp[m][n]


def _normalize_as_path(as_path) -> List[int]:
    """Convert AS path to list of integers."""
    if isinstance(as_path, int):
        return [as_path]

    if isinstance(as_path, list):
        return [int(x) for x in as_path if str(x).isdigit()]

    if isinstance(as_path, str):
        # Remove AS_SET brackets
        as_path = as_path.replace('{', '').replace('}', '')
        return [int(asn) for asn in as_path.split() if asn.isdigit()]

    return []


def get_path_length(as_path) -> int:
    """Get the length of an AS path."""
    if pd.isnull(as_path) or as_path == '':
        return 0
    return len(_normalize_as_path(as_path))


def attributes_are_same(row1: pd.Series, row2: pd.Series) -> bool:
    """
    Compare BGP attributes between two announcements.

    Returns True if all comparable attributes are the same.
    """
    attrs_to_compare = ['AS_Path', 'Origin', 'Next_Hop', 'MED', 'Local_Pref', 'Communities']

    for attr in attrs_to_compare:
        if attr not in row1.index or attr not in row2.index:
            continue

        val1, val2 = row1[attr], row2[attr]

        # Both NaN → same
        if pd.isna(val1) and pd.isna(val2):
            continue
        # One NaN, one not → different
        if pd.isna(val1) or pd.isna(val2):
            return False
        # Compare values
        if val1 != val2:
            return False

    return True


def calculate_nadas_and_flaps(df_window: pd.DataFrame) -> Tuple[int, int]:
    """
    Calculate NADAS and FLAPS from BGP update sequence.

    NADAS: Withdrawal followed by Announcement with DIFFERENT attributes
    FLAP: Withdrawal followed by Announcement with SAME attributes

    Args:
        df_window: DataFrame with BGP updates in a time window

    Returns:
        Tuple of (nadas_count, flap_count)
    """
    nadas_count = 0
    flap_count = 0

    withdrawal_types = ['WITHDRAW', 'WITHDRAW_MP_UNREACH_NLRI_AFI2']

    # Sort by timestamp
    df_sorted = df_window.sort_values('Timestamp')

    # Track state per (prefix, peer)
    # State: {'withdrawn': bool, 'last_ann': row or None}
    prefix_state: Dict[Tuple, Dict] = {}

    for _, row in df_sorted.iterrows():
        key = (row['Prefix'], row['Peer_IP'])

        if row['Subtype'] == 'ANNOUNCE':
            # Check if this prefix was previously withdrawn
            if key in prefix_state and prefix_state[key].get('withdrawn', False):
                last_ann = prefix_state[key].get('last_ann')

                if last_ann is not None:
                    if attributes_are_same(last_ann, row):
                        flap_count += 1
                    else:
                        nadas_count += 1
                else:
                    # No previous announcement to compare → count as NADAS
                    nadas_count += 1

            # Update state
            if key not in prefix_state:
                prefix_state[key] = {}
            prefix_state[key]['last_ann'] = row
            prefix_state[key]['withdrawn'] = False

        elif row['Subtype'] in withdrawal_types:
            # Mark prefix as withdrawn
            if key not in prefix_state:
                prefix_state[key] = {'last_ann': None}
            prefix_state[key]['withdrawn'] = True

    return nadas_count, flap_count


def extract_features(df_window: pd.DataFrame) -> Dict:
    """
    Extract BGP features from a time window.

    Args:
        df_window: DataFrame containing BGP updates within a time window

    Returns:
        Dictionary of feature name → value
    """
    features = {}

    # Separate announcements and withdrawals
    announcements = df_window[df_window['Subtype'] == 'ANNOUNCE']
    withdrawal_types = ['WITHDRAW', 'WITHDRAW_MP_UNREACH_NLRI_AFI2']
    withdrawals = df_window[df_window['Subtype'].isin(withdrawal_types)]

    # =================================================================
    # BASIC COUNTS
    # =================================================================
    features['announcements'] = len(announcements)
    features['withdrawals'] = len(withdrawals)

    # NLRI_ANN: Number of unique prefixes announced (NOT total announcements)
    features['nlri_ann'] = announcements['Prefix'].nunique()

    # =================================================================
    # DUPLICATES
    # =================================================================
    if not announcements.empty:
        dup_cols = ['Peer_IP', 'Peer_ASN', 'Prefix', 'AS_Path', 'Origin',
                    'Next_Hop', 'MED', 'Local_Pref', 'Communities']
        dup_cols = [c for c in dup_cols if c in announcements.columns]

        announcement_counts = announcements.groupby(dup_cols).size()
        features['dups'] = sum(count - 1 for count in announcement_counts if count > 1)
    else:
        features['dups'] = 0

    # =================================================================
    # ORIGIN ATTRIBUTES
    # =================================================================
    if not announcements.empty and 'Origin' in announcements.columns:
        origin_counts = announcements['Origin'].value_counts()
        features['origin_0'] = origin_counts.get('IGP', 0)
        features['origin_2'] = origin_counts.get('INCOMPLETE', 0)

        # Origin changes: prefixes announced with multiple different origins
        unique_prefix_origins = announcements.groupby('Prefix')['Origin'].nunique()
        features['origin_changes'] = (unique_prefix_origins > 1).sum()
    else:
        features['origin_0'] = 0
        features['origin_2'] = 0
        features['origin_changes'] = 0

    # =================================================================
    # IMPLICIT WITHDRAWALS (correct implementation)
    # An implicit withdrawal occurs when a prefix is re-announced with
    # different attributes (replacing the previous announcement)
    # =================================================================
    imp_wd_count = 0
    imp_wd_spath_count = 0  # Same AS_Path, other attrs changed
    imp_wd_dpath_count = 0  # Different AS_Path

    edit_distances = []
    edit_distance_dict = defaultdict(list)

    attrs_to_compare = ['AS_Path', 'Origin', 'Next_Hop', 'MED', 'Local_Pref', 'Communities']

    if not announcements.empty:
        available_attrs = [c for c in attrs_to_compare if c in announcements.columns]

        for (prefix, peer), group in announcements.groupby(['Prefix', 'Peer_IP']):
            if len(group) < 2:
                continue

            sorted_group = group.sort_values('Timestamp')
            prev_row = None

            for _, row in sorted_group.iterrows():
                if prev_row is not None:
                    attributes_changed = False
                    as_path_changed = False

                    for attr in available_attrs:
                        prev_val = prev_row.get(attr)
                        curr_val = row.get(attr)

                        prev_nan = pd.isna(prev_val)
                        curr_nan = pd.isna(curr_val)

                        if prev_nan and curr_nan:
                            continue
                        if prev_nan or curr_nan or prev_val != curr_val:
                            attributes_changed = True
                            if attr == 'AS_Path':
                                as_path_changed = True

                    if attributes_changed:
                        imp_wd_count += 1

                        if as_path_changed:
                            imp_wd_dpath_count += 1

                            # Calculate edit distance for AS_Path changes
                            prev_path = prev_row.get('AS_Path', '')
                            curr_path = row.get('AS_Path', '')
                            dist = calculate_edit_distance(prev_path, curr_path)
                            if dist is not None:
                                edit_distances.append(dist)
                                edit_distance_dict[prefix].append(dist)
                        else:
                            imp_wd_spath_count += 1

                prev_row = row

    features['imp_wd'] = imp_wd_count
    features['imp_wd_spath'] = imp_wd_spath_count
    features['imp_wd_dpath'] = imp_wd_dpath_count

    # =================================================================
    # AS PATH METRICS
    # =================================================================
    if not announcements.empty and 'AS_Path' in announcements.columns:
        valid_paths = announcements[
            announcements['AS_Path'].notna() & (announcements['AS_Path'] != '')
        ]

        if not valid_paths.empty:
            path_lengths = valid_paths['AS_Path'].apply(get_path_length)
            features['as_path_max'] = path_lengths.max() if not path_lengths.empty else 0

            unique_paths_per_prefix = valid_paths.groupby('Prefix')['AS_Path'].nunique()
            features['unique_as_path_max'] = unique_paths_per_prefix.max() if not unique_paths_per_prefix.empty else 0
        else:
            features['as_path_max'] = 0
            features['unique_as_path_max'] = 0
    else:
        features['as_path_max'] = 0
        features['unique_as_path_max'] = 0

    # =================================================================
    # EDIT DISTANCE FEATURES
    # =================================================================
    if edit_distances:
        features['edit_distance_avg'] = float(np.mean(edit_distances))
        features['edit_distance_max'] = max(edit_distances)

        # Distribution of edit distances (0-6)
        ed_counter = Counter(edit_distances)
        for i in range(7):
            features[f'edit_distance_dict_{i}'] = ed_counter.get(i, 0)

        # Unique edit distances per prefix
        unique_ed = {}
        for prefix, dists in edit_distance_dict.items():
            for d in set(dists):
                unique_ed[d] = unique_ed.get(d, 0) + 1

        for i in range(2):
            features[f'edit_distance_unique_dict_{i}'] = unique_ed.get(i, 0)
    else:
        features['edit_distance_avg'] = 0
        features['edit_distance_max'] = 0
        for i in range(7):
            features[f'edit_distance_dict_{i}'] = 0
        for i in range(2):
            features[f'edit_distance_unique_dict_{i}'] = 0

    # =================================================================
    # RARE AS FEATURES
    # =================================================================
    if not announcements.empty and 'AS_Path' in announcements.columns:
        all_asns = []

        for as_path in announcements['AS_Path']:
            if pd.isnull(as_path) or as_path == '':
                continue
            all_asns.extend([str(asn) for asn in _normalize_as_path(as_path)])

        if all_asns:
            asn_counts = Counter(all_asns)
            rare_threshold = 3
            rare_asns = [asn for asn, count in asn_counts.items() if count < rare_threshold]

            features['number_rare_ases'] = len(rare_asns)
            features['rare_ases_avg'] = len(rare_asns) / len(all_asns)
        else:
            features['number_rare_ases'] = 0
            features['rare_ases_avg'] = 0
    else:
        features['number_rare_ases'] = 0
        features['rare_ases_avg'] = 0

    # =================================================================
    # NADAS AND FLAPS (correct implementation)
    # =================================================================
    nadas_count, flap_count = calculate_nadas_and_flaps(df_window)
    features['nadas'] = nadas_count
    features['flaps'] = flap_count

    # =================================================================
    # LABEL AGGREGATION
    # =================================================================
    if 'Label' in df_window.columns:
        labels = df_window['Label'].value_counts()
        if not labels.empty:
            if LABEL_STRATEGY == 'majority':
                features['label'] = labels.idxmax()
            elif LABEL_STRATEGY == 'conservative':
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


def process_file(input_csv: Path, output_csv: Path,
                 schema_type: str = 'auto') -> Optional[pd.DataFrame]:
    """
    Process a single BGP data file and extract features.

    Args:
        input_csv: Path to input CSV file
        output_csv: Path to output features CSV
        schema_type: 'ripe' for RIPE incident data, 'standard' for generated data,
                     'auto' to detect automatically

    Returns:
        DataFrame with extracted features, or None if no features extracted
    """
    print(f"[+] Reading {input_csv}")
    df = pd.read_csv(input_csv, low_memory=False)

    # Auto-detect schema type
    if schema_type == 'auto':
        if 'Time' in df.columns and 'Entry_Type' in df.columns:
            schema_type = 'ripe'
        else:
            schema_type = 'standard'

    # Schema mapping for RIPE data
    if schema_type == 'ripe':
        df['Timestamp'] = pd.to_datetime(df['Time'])

        def map_subtype(entry_type):
            if entry_type == 'A':
                return 'ANNOUNCE'
            elif entry_type == 'W':
                return 'WITHDRAW'
            return 'UNKNOWN'

        df['Subtype'] = df['Entry_Type'].apply(map_subtype)

        # Column renames
        if 'Peer_AS' in df.columns:
            df.rename(columns={'Peer_AS': 'Peer_ASN'}, inplace=True)
        if 'Origin_AS' in df.columns:
            df.rename(columns={'Origin_AS': 'Origin'}, inplace=True)
        if 'Community' in df.columns:
            df.rename(columns={'Community': 'Communities'}, inplace=True)
    else:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])

    # Sort and set index
    df = df.sort_values('Timestamp')
    df.set_index('Timestamp', inplace=True)

    # Process windows
    features_list = []
    count = 0

    for window_start, window_df in df.groupby(pd.Grouper(freq=WINDOW_SIZE)):
        if window_df.empty:
            continue

        w = window_df.reset_index()
        f = extract_features(w)

        if f:
            window_end = window_start + pd.Timedelta(WINDOW_SIZE)
            f['window_start'] = window_start
            f['window_end'] = window_end
            features_list.append(f)
            count += 1

            if count % 1000 == 0:
                print(f"  Processed {count} windows...")

    if not features_list:
        print(f"[!] No features extracted from {input_csv}")
        return None

    out_df = pd.DataFrame(features_list)
    out_df.to_csv(output_csv, index=False)
    print(f"[+] Wrote {len(out_df)} windows to {output_csv}")

    # Print diagnostics
    print(f"    Diagnostics: withdrawals={out_df['withdrawals'].sum()}, "
          f"flaps={out_df['flaps'].sum()}, nadas={out_df['nadas'].sum()}, "
          f"imp_wd={out_df['imp_wd'].sum()}")

    return out_df


def process_all_incidents(base_dir: Path):
    """Process all incident directories under base_dir."""
    for incident_dir in base_dir.iterdir():
        if not incident_dir.is_dir():
            continue

        for csv_path in incident_dir.glob("*_labeled.csv"):
            out_path = incident_dir / (csv_path.stem + "_features.csv")

            # Skip if features already exist (uncomment to enable)
            # if out_path.exists():
            #     print(f"[+] Skipping (already exists): {out_path}")
            #     continue

            process_file(csv_path, out_path, schema_type='ripe')


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  Process single file:  python feature_extraction_unified.py <input.csv> [output.csv]")
        print("  Process incidents:    python feature_extraction_unified.py --incidents <base_dir>")
        sys.exit(1)

    if sys.argv[1] == '--incidents':
        base_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("./RIPE/RIPE_INCIDENTS")
        process_all_incidents(base_dir)
    else:
        input_path = Path(sys.argv[1])
        output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else input_path.with_suffix('_features.csv')
        process_file(input_path, output_path)
