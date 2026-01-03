#!/usr/bin/env python3
"""
BGP Anomaly Discovery for Unlabeled RIPE Data

When you have RIPE data but DON'T KNOW if it's truly normal or contains anomalies,
this script helps you discover the structure of your data using multiple
unsupervised methods and consensus-based labeling.

The approach:
1. Use multiple anomaly detection methods (ensemble approach)
2. Find natural clusters in the data
3. Calculate consensus scores - samples flagged by multiple methods are more suspicious
4. Cross-reference with known BGP incident databases (optional)
5. Generate confidence-based labels: "likely_normal", "likely_anomaly", "uncertain"

This is the RIGHT approach when you don't have ground truth labels.

Author: BGP Traffic Generation Project
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
from sklearn.covariance import EllipticEnvelope
from scipy import stats
import warnings
from datetime import datetime
from collections import Counter
import json

warnings.filterwarnings('ignore')


class BGPAnomalyDiscovery:
    """
    Discover anomalies in unlabeled BGP data using ensemble of unsupervised methods.

    This is designed for the scenario where you have RIPE data but don't know
    if it's truly "normal" or contains attacks/anomalies.
    """

    def __init__(self,
                 contamination_estimate: float = 0.1,
                 n_methods: int = 4,
                 consensus_threshold: float = 0.5,
                 random_state: int = 42):
        """
        Initialize the anomaly discovery system.

        Args:
            contamination_estimate: Rough estimate of anomaly percentage (0.1 = 10%)
            n_methods: Number of methods that must agree for high confidence
            consensus_threshold: Fraction of methods that must agree to flag as anomaly
            random_state: Random seed for reproducibility
        """
        self.contamination = contamination_estimate
        self.n_methods = n_methods
        self.consensus_threshold = consensus_threshold
        self.random_state = random_state

        self.scaler = RobustScaler()  # Robust to outliers
        self.feature_cols = None
        self.results = {}

    def _identify_feature_columns(self, df: pd.DataFrame) -> list:
        """Identify numeric feature columns, excluding metadata."""
        meta_cols = {
            'incident', 'window_start', 'window_end', 'timestamp', 'time',
            'label', 'label_rule', 'label_refined', 'label_discovered',
            'cluster', 'anomaly_score', 'source', 'collector'
        }

        candidate_cols = [c for c in df.columns if c.lower() not in {m.lower() for m in meta_cols}]
        feature_cols = df[candidate_cols].select_dtypes(include=[np.number]).columns.tolist()

        return feature_cols

    def _statistical_outliers(self, X: np.ndarray) -> np.ndarray:
        """
        Detect outliers using statistical methods (Z-score and IQR).

        Returns array of anomaly scores (higher = more anomalous)
        """
        n_samples, n_features = X.shape
        outlier_scores = np.zeros(n_samples)

        for i in range(n_features):
            col = X[:, i]

            # Z-score method
            z_scores = np.abs(stats.zscore(col, nan_policy='omit'))
            z_outliers = z_scores > 3  # More than 3 std deviations

            # IQR method
            Q1, Q3 = np.percentile(col[~np.isnan(col)], [25, 75])
            IQR = Q3 - Q1
            iqr_outliers = (col < Q1 - 1.5 * IQR) | (col > Q3 + 1.5 * IQR)

            # Combine scores
            outlier_scores += z_outliers.astype(float) + iqr_outliers.astype(float)

        # Normalize to 0-1
        outlier_scores = outlier_scores / (2 * n_features)

        return outlier_scores

    def discover_anomalies(self, df: pd.DataFrame, feature_cols: list = None) -> pd.DataFrame:
        """
        Run multiple anomaly detection methods and compute consensus.

        Args:
            df: DataFrame with BGP features (can be unlabeled)
            feature_cols: List of feature columns (auto-detected if None)

        Returns:
            DataFrame with anomaly detection results added
        """
        print("\n" + "=" * 80)
        print("BGP ANOMALY DISCOVERY - UNLABELED DATA ANALYSIS")
        print("=" * 80)

        df = df.copy()

        # Identify features
        self.feature_cols = feature_cols or self._identify_feature_columns(df)
        print(f"\n[+] Using {len(self.feature_cols)} features for analysis")

        # Prepare data
        X = df[self.feature_cols].values
        valid_mask = ~np.isnan(X).any(axis=1)
        X_valid = X[valid_mask]

        print(f"[+] Analyzing {len(X_valid)} samples ({(~valid_mask).sum()} excluded due to NaN)")

        # Scale data
        X_scaled = self.scaler.fit_transform(X_valid)

        # Initialize result columns
        df['iso_forest_score'] = np.nan
        df['iso_forest_anomaly'] = False
        df['lof_score'] = np.nan
        df['lof_anomaly'] = False
        df['statistical_score'] = np.nan
        df['statistical_anomaly'] = False
        df['elliptic_score'] = np.nan
        df['elliptic_anomaly'] = False
        df['dbscan_cluster'] = -1
        df['dbscan_anomaly'] = False
        df['anomaly_votes'] = 0
        df['consensus_score'] = 0.0
        df['discovered_label'] = 'unknown'

        n_methods = 5  # Total methods we're using

        # === Method 1: Isolation Forest ===
        print("\n[1/5] Running Isolation Forest...")
        iso = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        iso_scores = iso.fit_predict(X_scaled)
        iso_decision = iso.decision_function(X_scaled)

        df.loc[valid_mask, 'iso_forest_score'] = iso_decision
        df.loc[valid_mask, 'iso_forest_anomaly'] = (iso_scores == -1)
        print(f"    Found {(iso_scores == -1).sum()} anomalies ({(iso_scores == -1).mean()*100:.1f}%)")

        # === Method 2: Local Outlier Factor ===
        print("\n[2/5] Running Local Outlier Factor...")
        lof = LocalOutlierFactor(
            n_neighbors=20,
            contamination=self.contamination,
            novelty=False
        )
        lof_scores = lof.fit_predict(X_scaled)
        lof_decision = lof.negative_outlier_factor_

        df.loc[valid_mask, 'lof_score'] = lof_decision
        df.loc[valid_mask, 'lof_anomaly'] = (lof_scores == -1)
        print(f"    Found {(lof_scores == -1).sum()} anomalies ({(lof_scores == -1).mean()*100:.1f}%)")

        # === Method 3: Statistical Outliers ===
        print("\n[3/5] Running Statistical Analysis (Z-score + IQR)...")
        stat_scores = self._statistical_outliers(X_valid)
        stat_threshold = np.percentile(stat_scores, 100 * (1 - self.contamination))
        stat_anomalies = stat_scores > stat_threshold

        df.loc[valid_mask, 'statistical_score'] = stat_scores
        df.loc[valid_mask, 'statistical_anomaly'] = stat_anomalies
        print(f"    Found {stat_anomalies.sum()} anomalies ({stat_anomalies.mean()*100:.1f}%)")

        # === Method 4: Elliptic Envelope (Robust Covariance) ===
        print("\n[4/5] Running Elliptic Envelope...")
        try:
            ee = EllipticEnvelope(
                contamination=self.contamination,
                random_state=self.random_state
            )
            ee_scores = ee.fit_predict(X_scaled)
            ee_decision = ee.decision_function(X_scaled)

            df.loc[valid_mask, 'elliptic_score'] = ee_decision
            df.loc[valid_mask, 'elliptic_anomaly'] = (ee_scores == -1)
            print(f"    Found {(ee_scores == -1).sum()} anomalies ({(ee_scores == -1).mean()*100:.1f}%)")
        except Exception as e:
            print(f"    Skipped (error: {e})")
            n_methods -= 1

        # === Method 5: DBSCAN Clustering (noise points are anomalies) ===
        print("\n[5/5] Running DBSCAN Clustering...")
        # Use PCA for DBSCAN to handle high dimensionality
        pca = PCA(n_components=min(10, X_scaled.shape[1]))
        X_pca = pca.fit_transform(X_scaled)

        # Auto-tune eps using nearest neighbors
        from sklearn.neighbors import NearestNeighbors
        nn = NearestNeighbors(n_neighbors=5)
        nn.fit(X_pca)
        distances, _ = nn.kneighbors(X_pca)
        eps = np.percentile(distances[:, -1], 90)  # 90th percentile of 5-NN distances

        dbscan = DBSCAN(eps=eps, min_samples=5)
        dbscan_labels = dbscan.fit_predict(X_pca)

        df.loc[valid_mask, 'dbscan_cluster'] = dbscan_labels
        df.loc[valid_mask, 'dbscan_anomaly'] = (dbscan_labels == -1)  # -1 = noise
        n_noise = (dbscan_labels == -1).sum()
        n_clusters = len(set(dbscan_labels)) - (1 if -1 in dbscan_labels else 0)
        print(f"    Found {n_clusters} clusters and {n_noise} noise points ({n_noise/len(dbscan_labels)*100:.1f}%)")

        # === Compute Consensus ===
        print("\n[+] Computing consensus across methods...")

        anomaly_cols = ['iso_forest_anomaly', 'lof_anomaly', 'statistical_anomaly',
                        'elliptic_anomaly', 'dbscan_anomaly']

        # Count votes
        df['anomaly_votes'] = df[anomaly_cols].sum(axis=1)
        df['consensus_score'] = df['anomaly_votes'] / n_methods

        # Assign discovered labels based on consensus
        df.loc[df['consensus_score'] >= 0.8, 'discovered_label'] = 'high_confidence_anomaly'
        df.loc[(df['consensus_score'] >= 0.5) & (df['consensus_score'] < 0.8), 'discovered_label'] = 'likely_anomaly'
        df.loc[(df['consensus_score'] >= 0.2) & (df['consensus_score'] < 0.5), 'discovered_label'] = 'uncertain'
        df.loc[df['consensus_score'] < 0.2, 'discovered_label'] = 'likely_normal'

        # Store results
        self.results = {
            'total_samples': len(df),
            'valid_samples': valid_mask.sum(),
            'n_methods': n_methods,
            'contamination_estimate': self.contamination,
            'label_distribution': df['discovered_label'].value_counts().to_dict(),
            'consensus_stats': {
                'mean': df['consensus_score'].mean(),
                'std': df['consensus_score'].std(),
            },
            'per_method_anomaly_rate': {
                'isolation_forest': df['iso_forest_anomaly'].mean(),
                'local_outlier_factor': df['lof_anomaly'].mean(),
                'statistical': df['statistical_anomaly'].mean(),
                'elliptic_envelope': df['elliptic_anomaly'].mean(),
                'dbscan': df['dbscan_anomaly'].mean()
            }
        }

        return df

    def analyze_anomaly_characteristics(self, df: pd.DataFrame) -> dict:
        """
        Analyze what makes the detected anomalies different from normal samples.

        This helps you understand WHY certain samples are flagged.
        """
        print("\n[+] Analyzing anomaly characteristics...")

        # Split by discovered label
        normal_mask = df['discovered_label'] == 'likely_normal'
        anomaly_mask = df['discovered_label'].isin(['high_confidence_anomaly', 'likely_anomaly'])

        if normal_mask.sum() == 0 or anomaly_mask.sum() == 0:
            print("    Not enough samples in each category for comparison")
            return {}

        analysis = {
            'feature_differences': {},
            'most_discriminative_features': []
        }

        for col in self.feature_cols:
            normal_vals = df.loc[normal_mask, col].dropna()
            anomaly_vals = df.loc[anomaly_mask, col].dropna()

            if len(normal_vals) == 0 or len(anomaly_vals) == 0:
                continue

            # Statistical comparison
            normal_mean = normal_vals.mean()
            anomaly_mean = anomaly_vals.mean()

            # Effect size (Cohen's d)
            pooled_std = np.sqrt((normal_vals.std()**2 + anomaly_vals.std()**2) / 2)
            if pooled_std > 0:
                cohens_d = abs(anomaly_mean - normal_mean) / pooled_std
            else:
                cohens_d = 0

            analysis['feature_differences'][col] = {
                'normal_mean': normal_mean,
                'anomaly_mean': anomaly_mean,
                'difference': anomaly_mean - normal_mean,
                'effect_size': cohens_d
            }

        # Sort by effect size to find most discriminative features
        sorted_features = sorted(
            analysis['feature_differences'].items(),
            key=lambda x: x[1]['effect_size'],
            reverse=True
        )

        analysis['most_discriminative_features'] = [
            {'feature': f, 'effect_size': d['effect_size'], 'direction': 'higher' if d['difference'] > 0 else 'lower'}
            for f, d in sorted_features[:10]
        ]

        print("\n    Top discriminative features (anomalies vs normal):")
        for item in analysis['most_discriminative_features'][:5]:
            print(f"      - {item['feature']}: {item['direction']} in anomalies (effect size: {item['effect_size']:.2f})")

        return analysis

    def temporal_analysis(self, df: pd.DataFrame, time_col: str = 'window_start') -> dict:
        """
        Analyze if anomalies cluster in specific time periods.

        This can help identify if certain time windows correspond to known incidents.
        """
        print("\n[+] Performing temporal analysis...")

        if time_col not in df.columns:
            print(f"    No time column '{time_col}' found, skipping temporal analysis")
            return {}

        df_time = df.copy()
        df_time[time_col] = pd.to_datetime(df_time[time_col], errors='coerce')
        df_time = df_time.dropna(subset=[time_col])

        if len(df_time) == 0:
            print("    No valid timestamps found")
            return {}

        # Group by time periods
        df_time['hour'] = df_time[time_col].dt.hour
        df_time['day'] = df_time[time_col].dt.date

        # Find periods with high anomaly concentration
        anomaly_mask = df_time['discovered_label'].isin(['high_confidence_anomaly', 'likely_anomaly'])

        daily_stats = df_time.groupby('day').agg({
            'consensus_score': ['count', 'mean'],
            'discovered_label': lambda x: (x.isin(['high_confidence_anomaly', 'likely_anomaly'])).sum()
        }).reset_index()
        daily_stats.columns = ['day', 'total_samples', 'avg_anomaly_score', 'anomaly_count']
        daily_stats['anomaly_rate'] = daily_stats['anomaly_count'] / daily_stats['total_samples']

        # Find suspicious days (high anomaly rate)
        suspicious_days = daily_stats[daily_stats['anomaly_rate'] > 0.3].sort_values('anomaly_rate', ascending=False)

        analysis = {
            'daily_stats': daily_stats.to_dict('records'),
            'suspicious_periods': suspicious_days.head(10).to_dict('records'),
            'overall_temporal_pattern': {
                'start': str(df_time[time_col].min()),
                'end': str(df_time[time_col].max()),
                'total_days': (df_time[time_col].max() - df_time[time_col].min()).days
            }
        }

        if len(suspicious_days) > 0:
            print(f"\n    Found {len(suspicious_days)} days with high anomaly rates (>30%):")
            for _, row in suspicious_days.head(5).iterrows():
                print(f"      - {row['day']}: {row['anomaly_count']}/{row['total_samples']} anomalies ({row['anomaly_rate']*100:.1f}%)")

        return analysis

    def print_summary(self):
        """Print a summary of the discovery results."""
        if not self.results:
            print("No results available. Run discover_anomalies() first.")
            return

        r = self.results

        print("\n" + "=" * 80)
        print("ANOMALY DISCOVERY SUMMARY")
        print("=" * 80)

        print(f"\n📊 DATA OVERVIEW")
        print(f"   Total samples: {r['total_samples']}")
        print(f"   Valid samples: {r['valid_samples']}")
        print(f"   Methods used: {r['n_methods']}")
        print(f"   Contamination estimate: {r['contamination_estimate']*100:.1f}%")

        print(f"\n🏷️  DISCOVERED LABELS")
        total = sum(r['label_distribution'].values())
        for label, count in sorted(r['label_distribution'].items()):
            pct = count / total * 100
            emoji = "🟢" if 'normal' in label else "🔴" if 'anomaly' in label else "🟡"
            print(f"   {emoji} {label}: {count} ({pct:.1f}%)")

        print(f"\n📈 PER-METHOD ANOMALY RATES")
        for method, rate in r['per_method_anomaly_rate'].items():
            print(f"   - {method}: {rate*100:.1f}%")

        print(f"\n🎯 RECOMMENDATIONS")

        high_conf = r['label_distribution'].get('high_confidence_anomaly', 0)
        likely_anom = r['label_distribution'].get('likely_anomaly', 0)
        uncertain = r['label_distribution'].get('uncertain', 0)

        if high_conf > 0:
            print(f"   ⚠️  {high_conf} samples are HIGH CONFIDENCE anomalies - investigate these first!")

        if likely_anom > 0:
            print(f"   ⚡ {likely_anom} samples are LIKELY anomalies - review for potential incidents")

        if uncertain > 0:
            print(f"   ❓ {uncertain} samples are UNCERTAIN - may need domain expert review")

        likely_normal = r['label_distribution'].get('likely_normal', 0)
        print(f"   ✅ {likely_normal} samples appear to be NORMAL traffic")

        print("\n" + "=" * 80)


def discover_and_label(input_path: Path,
                        output_dir: Path = None,
                        contamination: float = 0.1) -> tuple:
    """
    Main function to discover anomalies in unlabeled RIPE data.

    Args:
        input_path: Path to features CSV file
        output_dir: Output directory (defaults to input directory)
        contamination: Estimated anomaly rate

    Returns:
        Tuple of (labeled_df, results_dict)
    """
    print(f"\n{'#' * 80}")
    print(f"# PROCESSING: {input_path}")
    print(f"{'#' * 80}")

    df = pd.read_csv(input_path)
    print(f"Loaded {len(df)} samples")

    # Initialize discoverer
    discoverer = BGPAnomalyDiscovery(
        contamination_estimate=contamination
    )

    # Run discovery
    labeled_df = discoverer.discover_anomalies(df)

    # Analyze characteristics
    char_analysis = discoverer.analyze_anomaly_characteristics(labeled_df)

    # Temporal analysis if time column exists
    temporal = discoverer.temporal_analysis(labeled_df)

    # Print summary
    discoverer.print_summary()

    # Save outputs
    output_dir = output_dir or input_path.parent

    # Save labeled data
    labeled_path = output_dir / f"{input_path.stem}_discovered.csv"
    labeled_df.to_csv(labeled_path, index=False)
    print(f"\n[+] Saved discovered labels to: {labeled_path}")

    # Save full report
    report = {
        'timestamp': datetime.now().isoformat(),
        'input_file': str(input_path),
        'discovery_results': discoverer.results,
        'characteristic_analysis': char_analysis,
        'temporal_analysis': temporal
    }

    report_path = output_dir / f"{input_path.stem}_discovery_report.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Saved report to: {report_path}")

    # Save just the anomalies for easier review
    anomaly_df = labeled_df[labeled_df['discovered_label'].isin(['high_confidence_anomaly', 'likely_anomaly'])]
    if len(anomaly_df) > 0:
        anomaly_path = output_dir / f"{input_path.stem}_anomalies.csv"
        anomaly_df.to_csv(anomaly_path, index=False)
        print(f"[+] Saved {len(anomaly_df)} anomalies to: {anomaly_path}")

    return labeled_df, report


def compare_with_existing_labels(df: pd.DataFrame, label_col: str = 'label') -> dict:
    """
    If you have some existing labels, compare them with discovered labels.

    This helps validate your existing labeling approach.
    """
    if label_col not in df.columns:
        return {}

    print("\n[+] Comparing discovered labels with existing labels...")

    comparison = {
        'agreement_matrix': {},
        'recommendations': []
    }

    # Create comparison
    for existing_label in df[label_col].unique():
        mask = df[label_col] == existing_label
        discovered_dist = df.loc[mask, 'discovered_label'].value_counts(normalize=True).to_dict()
        comparison['agreement_matrix'][existing_label] = discovered_dist

        # Generate recommendations
        anomaly_rate = discovered_dist.get('high_confidence_anomaly', 0) + discovered_dist.get('likely_anomaly', 0)
        normal_rate = discovered_dist.get('likely_normal', 0)

        if 'normal' in existing_label.lower() and anomaly_rate > 0.2:
            comparison['recommendations'].append(
                f"WARNING: {anomaly_rate*100:.1f}% of '{existing_label}' samples look anomalous!"
            )
        elif 'attack' in existing_label.lower() or 'hijack' in existing_label.lower():
            if normal_rate > 0.3:
                comparison['recommendations'].append(
                    f"WARNING: {normal_rate*100:.1f}% of '{existing_label}' samples look normal!"
                )

    print("\n    Label comparison matrix:")
    for existing, discovered in comparison['agreement_matrix'].items():
        print(f"\n    [{existing}]:")
        for d_label, pct in sorted(discovered.items(), key=lambda x: -x[1]):
            print(f"      → {d_label}: {pct*100:.1f}%")

    if comparison['recommendations']:
        print("\n    ⚠️  RECOMMENDATIONS:")
        for rec in comparison['recommendations']:
            print(f"      {rec}")

    return comparison


# CLI
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Discover anomalies in unlabeled BGP/RIPE data using ensemble methods"
    )
    parser.add_argument(
        "input",
        type=str,
        help="Path to features CSV file or directory"
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default=None,
        help="Output directory"
    )
    parser.add_argument(
        "--contamination", "-c",
        type=float,
        default=0.1,
        help="Estimated anomaly rate (default: 0.1 = 10%%)"
    )
    parser.add_argument(
        "--compare-labels",
        action="store_true",
        help="Compare with existing labels if present"
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir) if args.output_dir else None

    if input_path.is_file():
        labeled_df, report = discover_and_label(
            input_path,
            output_dir=output_dir,
            contamination=args.contamination
        )

        if args.compare_labels and 'label' in labeled_df.columns:
            compare_with_existing_labels(labeled_df)

    elif input_path.is_dir():
        for csv_file in sorted(input_path.glob("**/*features*.csv")):
            if '_discovered' in csv_file.name or '_anomalies' in csv_file.name:
                continue
            labeled_df, report = discover_and_label(
                csv_file,
                output_dir=output_dir,
                contamination=args.contamination
            )
    else:
        print(f"[!] Path not found: {input_path}")
