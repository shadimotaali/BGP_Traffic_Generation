#!/usr/bin/env python3
"""
BGP Label Validation using K-Means Clustering and Isolation Forest

This script validates the quality of BGP traffic labels by:
1. Using Isolation Forest trained on normal traffic to verify attack samples are truly anomalous
2. Using K-Means clustering to find natural data groupings and check label consistency
3. Cross-validating between both methods for high-confidence validation

The approach follows best practices from anomaly detection literature:
- Normal traffic is used as the reference baseline (not attack samples)
- Multiple unsupervised methods are combined for robust validation
- Labels are flagged for review rather than automatically changed

Author: BGP Traffic Generation Project
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score, calinski_harabasz_score
from sklearn.metrics import confusion_matrix, classification_report
from collections import Counter
import warnings
import json
from datetime import datetime

warnings.filterwarnings('ignore')


class BGPLabelValidator:
    """
    Validates BGP traffic labels using unsupervised learning methods.

    Methods:
    1. Isolation Forest: Trained on normal traffic to detect true anomalies
    2. K-Means Clustering: Groups similar samples to check label consistency
    3. Combined validation: Cross-validates both methods for confidence scoring
    """

    def __init__(self,
                 normal_label: str = "normal",
                 attack_labels: list = None,
                 n_clusters: int = None,
                 contamination: float = 0.05,
                 random_state: int = 42):
        """
        Initialize the validator.

        Args:
            normal_label: Label used for normal traffic
            attack_labels: List of attack label names
            n_clusters: Number of clusters for K-Means (auto-detected if None)
            contamination: Expected contamination in normal class (default 5%)
            random_state: Random seed for reproducibility
        """
        self.normal_label = normal_label
        self.attack_labels = attack_labels or ["prefix_hijacking", "path_manipulation", "dos_attack"]
        self.n_clusters = n_clusters
        self.contamination = contamination
        self.random_state = random_state

        self.scaler = StandardScaler()
        self.iso_forest = None
        self.kmeans = None
        self.pca = None
        self.feature_cols = None
        self.validation_results = {}

    def _identify_feature_columns(self, df: pd.DataFrame) -> list:
        """Identify numeric feature columns, excluding metadata."""
        meta_cols = {
            'Incident', 'window_start', 'window_end',
            'label', 'label_rule', 'label_refined', 'label_validated',
            'cluster', 'anomaly_score', 'validation_flag'
        }

        candidate_cols = [c for c in df.columns if c.lower() not in {m.lower() for m in meta_cols}]
        feature_cols = df[candidate_cols].select_dtypes(include=[np.number]).columns.tolist()

        return feature_cols

    def _optimal_clusters(self, X_scaled: np.ndarray, max_clusters: int = 10) -> int:
        """
        Determine optimal number of clusters using silhouette score.

        Args:
            X_scaled: Scaled feature matrix
            max_clusters: Maximum clusters to try

        Returns:
            Optimal number of clusters
        """
        n_samples = len(X_scaled)
        max_k = min(max_clusters, n_samples - 1, 10)

        if max_k < 2:
            return 2

        scores = []
        for k in range(2, max_k + 1):
            kmeans = KMeans(n_clusters=k, random_state=self.random_state, n_init=10)
            labels = kmeans.fit_predict(X_scaled)
            score = silhouette_score(X_scaled, labels)
            scores.append((k, score))

        # Find k with best silhouette score
        optimal_k = max(scores, key=lambda x: x[1])[0]
        print(f"    Optimal clusters determined: {optimal_k} (silhouette scores: {scores})")

        return optimal_k

    def fit_normal_baseline(self, df: pd.DataFrame, feature_cols: list = None) -> 'BGPLabelValidator':
        """
        Fit the Isolation Forest model on normal traffic samples.

        This establishes what "normal" behavior looks like, so we can
        later validate if attack-labeled samples are truly anomalous.

        Args:
            df: DataFrame with labeled data
            feature_cols: List of feature column names (auto-detected if None)

        Returns:
            self for method chaining
        """
        print("[+] Fitting normal baseline using Isolation Forest...")

        # Identify features
        self.feature_cols = feature_cols or self._identify_feature_columns(df)
        print(f"    Using {len(self.feature_cols)} features")

        # Get normal samples
        if 'label_rule' in df.columns:
            label_col = 'label_rule'
        elif 'label' in df.columns:
            label_col = 'label'
        else:
            raise ValueError("No label column found in DataFrame")

        normal_mask = df[label_col] == self.normal_label
        normal_samples = df[normal_mask][self.feature_cols].dropna()

        if len(normal_samples) < 50:
            raise ValueError(f"Not enough normal samples ({len(normal_samples)}). Need at least 50.")

        print(f"    Training on {len(normal_samples)} normal samples")

        # Fit scaler on normal data only
        X_normal = normal_samples.values
        self.scaler.fit(X_normal)
        X_normal_scaled = self.scaler.transform(X_normal)

        # Fit Isolation Forest on normal data
        # Low contamination since we expect normal data to be mostly clean
        self.iso_forest = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.iso_forest.fit(X_normal_scaled)

        # Store normal baseline stats for reporting
        self.normal_baseline_stats = {
            'n_samples': len(normal_samples),
            'feature_means': dict(zip(self.feature_cols, self.scaler.mean_)),
            'feature_stds': dict(zip(self.feature_cols, self.scaler.scale_))
        }

        print("    Normal baseline fitted successfully")
        return self

    def fit_kmeans_clusters(self, df: pd.DataFrame) -> 'BGPLabelValidator':
        """
        Fit K-Means clustering on all data to find natural groupings.

        Args:
            df: DataFrame with all samples

        Returns:
            self for method chaining
        """
        print("[+] Fitting K-Means clustering...")

        if self.feature_cols is None:
            self.feature_cols = self._identify_feature_columns(df)

        X = df[self.feature_cols].dropna().values
        X_scaled = self.scaler.transform(X)

        # Determine optimal clusters if not specified
        if self.n_clusters is None:
            # Use number of unique labels + 1 as starting point
            if 'label_rule' in df.columns:
                n_labels = df['label_rule'].nunique()
            else:
                n_labels = df['label'].nunique()

            # Try to find optimal, but use label count as fallback
            self.n_clusters = self._optimal_clusters(X_scaled, max_clusters=max(n_labels + 2, 5))

        print(f"    Using {self.n_clusters} clusters")

        # Fit K-Means
        self.kmeans = KMeans(
            n_clusters=self.n_clusters,
            random_state=self.random_state,
            n_init=10
        )
        self.kmeans.fit(X_scaled)

        # Calculate clustering quality metrics
        cluster_labels = self.kmeans.labels_
        self.clustering_stats = {
            'n_clusters': self.n_clusters,
            'silhouette_score': silhouette_score(X_scaled, cluster_labels),
            'calinski_harabasz_score': calinski_harabasz_score(X_scaled, cluster_labels),
            'cluster_sizes': dict(Counter(cluster_labels))
        }

        print(f"    Silhouette score: {self.clustering_stats['silhouette_score']:.4f}")
        print(f"    Calinski-Harabasz score: {self.clustering_stats['calinski_harabasz_score']:.2f}")

        return self

    def validate_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Validate labels using both Isolation Forest and K-Means.

        For each sample, we check:
        1. IF validation: Do attack samples look anomalous vs normal baseline?
        2. K-Means validation: Is the label consistent with cluster majority?
        3. Combined confidence: Do both methods agree?

        Args:
            df: DataFrame with labeled data

        Returns:
            DataFrame with validation columns added
        """
        print("\n[+] Validating labels...")

        if self.iso_forest is None:
            raise ValueError("Must call fit_normal_baseline() first")
        if self.kmeans is None:
            raise ValueError("Must call fit_kmeans_clusters() first")

        df = df.copy()

        # Get label column
        label_col = 'label_rule' if 'label_rule' in df.columns else 'label'

        # Get features and handle missing values
        X = df[self.feature_cols].values
        valid_mask = ~np.isnan(X).any(axis=1)
        X_valid = X[valid_mask]
        X_scaled = self.scaler.transform(X_valid)

        # Initialize validation columns
        df['anomaly_score'] = np.nan
        df['is_anomaly_vs_normal'] = np.nan
        df['cluster'] = -1
        df['cluster_dominant_label'] = ''
        df['label_matches_cluster'] = np.nan
        df['validation_flag'] = 'unknown'
        df['confidence_score'] = 0.0

        # === 1. Isolation Forest Validation ===
        print("    Running Isolation Forest validation...")

        # Get anomaly scores (negative = more anomalous)
        anomaly_scores = self.iso_forest.decision_function(X_scaled)
        anomaly_predictions = self.iso_forest.predict(X_scaled)  # 1=normal, -1=anomaly

        df.loc[valid_mask, 'anomaly_score'] = anomaly_scores
        df.loc[valid_mask, 'is_anomaly_vs_normal'] = (anomaly_predictions == -1)

        # === 2. K-Means Validation ===
        print("    Running K-Means cluster validation...")

        cluster_assignments = self.kmeans.predict(X_scaled)
        df.loc[valid_mask, 'cluster'] = cluster_assignments

        # Find dominant label for each cluster
        cluster_label_map = {}
        for cluster_id in range(self.n_clusters):
            cluster_mask = df['cluster'] == cluster_id
            if cluster_mask.sum() > 0:
                label_counts = df.loc[cluster_mask, label_col].value_counts()
                dominant_label = label_counts.idxmax()
                cluster_label_map[cluster_id] = {
                    'dominant_label': dominant_label,
                    'purity': label_counts.iloc[0] / label_counts.sum(),
                    'label_distribution': label_counts.to_dict()
                }

        self.cluster_label_map = cluster_label_map

        # Check if sample's label matches cluster's dominant label
        for cluster_id, info in cluster_label_map.items():
            cluster_mask = df['cluster'] == cluster_id
            df.loc[cluster_mask, 'cluster_dominant_label'] = info['dominant_label']
            df.loc[cluster_mask, 'label_matches_cluster'] = (
                df.loc[cluster_mask, label_col] == info['dominant_label']
            )

        # === 3. Combined Validation Logic ===
        print("    Computing combined validation flags...")

        for idx in df.index:
            if not valid_mask[df.index.get_loc(idx)]:
                continue

            label = df.loc[idx, label_col]
            is_anomaly = df.loc[idx, 'is_anomaly_vs_normal']
            matches_cluster = df.loc[idx, 'label_matches_cluster']
            anomaly_score = df.loc[idx, 'anomaly_score']

            # Validation logic based on label type
            if label == self.normal_label:
                # Normal samples should NOT be anomalous
                if is_anomaly:
                    if not matches_cluster:
                        df.loc[idx, 'validation_flag'] = 'SUSPECT_MISLABELED_NORMAL'
                        df.loc[idx, 'confidence_score'] = 0.9
                    else:
                        df.loc[idx, 'validation_flag'] = 'REVIEW_ANOMALOUS_NORMAL'
                        df.loc[idx, 'confidence_score'] = 0.6
                else:
                    if matches_cluster:
                        df.loc[idx, 'validation_flag'] = 'VALID'
                        df.loc[idx, 'confidence_score'] = 0.95
                    else:
                        df.loc[idx, 'validation_flag'] = 'REVIEW_CLUSTER_MISMATCH'
                        df.loc[idx, 'confidence_score'] = 0.7

            elif label in self.attack_labels:
                # Attack samples SHOULD be anomalous (different from normal)
                if is_anomaly:
                    if matches_cluster:
                        df.loc[idx, 'validation_flag'] = 'VALID'
                        df.loc[idx, 'confidence_score'] = 0.95
                    else:
                        # Anomalous but in wrong cluster - might be different attack type
                        df.loc[idx, 'validation_flag'] = 'REVIEW_CLUSTER_MISMATCH'
                        df.loc[idx, 'confidence_score'] = 0.7
                else:
                    # Labeled as attack but looks normal!
                    if not matches_cluster:
                        df.loc[idx, 'validation_flag'] = 'SUSPECT_FALSE_POSITIVE'
                        df.loc[idx, 'confidence_score'] = 0.85
                    else:
                        df.loc[idx, 'validation_flag'] = 'REVIEW_LOOKS_NORMAL'
                        df.loc[idx, 'confidence_score'] = 0.5
            else:
                df.loc[idx, 'validation_flag'] = 'UNKNOWN_LABEL'
                df.loc[idx, 'confidence_score'] = 0.0

        return df

    def generate_validation_report(self, df: pd.DataFrame) -> dict:
        """
        Generate a comprehensive validation report.

        Args:
            df: DataFrame with validation columns

        Returns:
            Dictionary containing validation metrics and statistics
        """
        print("\n[+] Generating validation report...")

        label_col = 'label_rule' if 'label_rule' in df.columns else 'label'

        report = {
            'timestamp': datetime.now().isoformat(),
            'total_samples': len(df),
            'feature_count': len(self.feature_cols),
            'features_used': self.feature_cols,

            # Overall validation summary
            'validation_summary': df['validation_flag'].value_counts().to_dict(),

            # Per-label validation
            'per_label_validation': {},

            # Clustering statistics
            'clustering': self.clustering_stats,
            'cluster_purity': {
                str(k): v for k, v in self.cluster_label_map.items()
            },

            # Isolation Forest statistics
            'isolation_forest': {
                'contamination': self.contamination,
                'anomaly_rate': (df['is_anomaly_vs_normal'] == True).mean()
            },

            # Flagged samples for review
            'samples_to_review': {
                'suspect_mislabeled': len(df[df['validation_flag'].str.contains('SUSPECT', na=False)]),
                'needs_review': len(df[df['validation_flag'].str.contains('REVIEW', na=False)])
            }
        }

        # Per-label breakdown
        for label in df[label_col].unique():
            label_mask = df[label_col] == label
            label_df = df[label_mask]

            report['per_label_validation'][label] = {
                'total': len(label_df),
                'valid': len(label_df[label_df['validation_flag'] == 'VALID']),
                'suspect': len(label_df[label_df['validation_flag'].str.contains('SUSPECT', na=False)]),
                'review': len(label_df[label_df['validation_flag'].str.contains('REVIEW', na=False)]),
                'validation_breakdown': label_df['validation_flag'].value_counts().to_dict(),
                'avg_anomaly_score': label_df['anomaly_score'].mean(),
                'anomaly_rate': (label_df['is_anomaly_vs_normal'] == True).mean(),
                'cluster_match_rate': label_df['label_matches_cluster'].mean()
            }

        # Confidence distribution
        report['confidence_distribution'] = {
            'mean': df['confidence_score'].mean(),
            'std': df['confidence_score'].std(),
            'high_confidence_rate': (df['confidence_score'] >= 0.8).mean(),
            'low_confidence_rate': (df['confidence_score'] < 0.5).mean()
        }

        self.validation_report = report
        return report

    def print_report(self, report: dict = None):
        """Print a formatted validation report."""
        report = report or self.validation_report

        print("\n" + "=" * 80)
        print("BGP LABEL VALIDATION REPORT")
        print("=" * 80)

        print(f"\n📊 OVERVIEW")
        print(f"   Total samples: {report['total_samples']}")
        print(f"   Features used: {report['feature_count']}")
        print(f"   Clusters found: {report['clustering']['n_clusters']}")
        print(f"   Silhouette score: {report['clustering']['silhouette_score']:.4f}")

        print(f"\n🔍 VALIDATION SUMMARY")
        for flag, count in sorted(report['validation_summary'].items()):
            pct = count / report['total_samples'] * 100
            emoji = "✅" if flag == "VALID" else "⚠️" if "REVIEW" in flag else "❌" if "SUSPECT" in flag else "❓"
            print(f"   {emoji} {flag}: {count} ({pct:.1f}%)")

        print(f"\n📋 PER-LABEL VALIDATION")
        for label, stats in report['per_label_validation'].items():
            valid_rate = stats['valid'] / stats['total'] * 100 if stats['total'] > 0 else 0
            print(f"\n   [{label.upper()}] ({stats['total']} samples)")
            print(f"      Valid: {stats['valid']} ({valid_rate:.1f}%)")
            print(f"      Suspect: {stats['suspect']}")
            print(f"      Needs review: {stats['review']}")
            print(f"      Avg anomaly score: {stats['avg_anomaly_score']:.4f}")
            print(f"      Anomaly rate: {stats['anomaly_rate']*100:.1f}%")
            print(f"      Cluster match rate: {stats['cluster_match_rate']*100:.1f}%")

        print(f"\n🎯 CONFIDENCE METRICS")
        print(f"   Mean confidence: {report['confidence_distribution']['mean']:.2f}")
        print(f"   High confidence (≥0.8): {report['confidence_distribution']['high_confidence_rate']*100:.1f}%")
        print(f"   Low confidence (<0.5): {report['confidence_distribution']['low_confidence_rate']*100:.1f}%")

        print(f"\n⚡ ACTION ITEMS")
        print(f"   Samples flagged as SUSPECT: {report['samples_to_review']['suspect_mislabeled']}")
        print(f"   Samples needing REVIEW: {report['samples_to_review']['needs_review']}")

        print("\n" + "=" * 80)

    def get_flagged_samples(self, df: pd.DataFrame, flag_type: str = 'SUSPECT') -> pd.DataFrame:
        """
        Get samples that are flagged for review.

        Args:
            df: DataFrame with validation columns
            flag_type: 'SUSPECT', 'REVIEW', or 'ALL'

        Returns:
            Filtered DataFrame
        """
        if flag_type == 'SUSPECT':
            return df[df['validation_flag'].str.contains('SUSPECT', na=False)]
        elif flag_type == 'REVIEW':
            return df[df['validation_flag'].str.contains('REVIEW', na=False)]
        elif flag_type == 'ALL':
            return df[df['validation_flag'] != 'VALID']
        else:
            return df[df['validation_flag'] == flag_type]


def validate_features_csv(features_path: Path,
                          output_dir: Path = None,
                          normal_label: str = "normal",
                          attack_labels: list = None) -> tuple:
    """
    Validate labels in a features CSV file.

    Args:
        features_path: Path to the features CSV
        output_dir: Directory to save outputs (defaults to same as input)
        normal_label: Label for normal traffic
        attack_labels: List of attack label names

    Returns:
        Tuple of (validated_df, report_dict)
    """
    print(f"\n{'='*80}")
    print(f"VALIDATING: {features_path}")
    print(f"{'='*80}")

    df = pd.read_csv(features_path)

    # Check for label column
    if 'label' not in df.columns and 'label_rule' not in df.columns:
        print(f"[!] No label column found, skipping.")
        return None, None

    # Initialize validator
    validator = BGPLabelValidator(
        normal_label=normal_label,
        attack_labels=attack_labels
    )

    try:
        # Fit and validate
        validator.fit_normal_baseline(df)
        validator.fit_kmeans_clusters(df)
        validated_df = validator.validate_labels(df)
        report = validator.generate_validation_report(validated_df)
        validator.print_report()

        # Save outputs
        output_dir = output_dir or features_path.parent

        # Save validated CSV
        validated_path = output_dir / f"{features_path.stem}_validated.csv"
        validated_df.to_csv(validated_path, index=False)
        print(f"\n[+] Saved validated data to: {validated_path}")

        # Save report JSON
        report_path = output_dir / f"{features_path.stem}_validation_report.json"
        with open(report_path, 'w') as f:
            # Convert numpy types for JSON serialization
            json.dump(report, f, indent=2, default=str)
        print(f"[+] Saved report to: {report_path}")

        # Save flagged samples separately
        flagged_df = validator.get_flagged_samples(validated_df, 'ALL')
        if len(flagged_df) > 0:
            flagged_path = output_dir / f"{features_path.stem}_flagged_samples.csv"
            flagged_df.to_csv(flagged_path, index=False)
            print(f"[+] Saved {len(flagged_df)} flagged samples to: {flagged_path}")

        return validated_df, report

    except Exception as e:
        print(f"[!] Error validating {features_path}: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def process_all_incidents(base_dir: Path,
                          normal_label: str = "normal",
                          attack_labels: list = None):
    """
    Process all incident directories and validate labels.

    Args:
        base_dir: Base directory containing incident folders
        normal_label: Label for normal traffic
        attack_labels: List of attack label names
    """
    print(f"\n[*] Scanning for feature files in: {base_dir}")

    attack_labels = attack_labels or ["prefix_hijacking", "path_manipulation", "dos_attack"]
    results = []

    for incident_dir in sorted(base_dir.iterdir()):
        if not incident_dir.is_dir():
            continue

        # Find feature files
        for features_csv in incident_dir.glob("*_labeled_features.csv"):
            validated_df, report = validate_features_csv(
                features_csv,
                normal_label=normal_label,
                attack_labels=attack_labels
            )

            if report:
                results.append({
                    'incident': incident_dir.name,
                    'file': features_csv.name,
                    'total': report['total_samples'],
                    'valid': report['validation_summary'].get('VALID', 0),
                    'suspect': report['samples_to_review']['suspect_mislabeled'],
                    'review': report['samples_to_review']['needs_review']
                })

    # Print summary
    if results:
        print("\n" + "=" * 80)
        print("VALIDATION SUMMARY ACROSS ALL INCIDENTS")
        print("=" * 80)

        summary_df = pd.DataFrame(results)
        print(summary_df.to_string(index=False))

        total_samples = summary_df['total'].sum()
        total_valid = summary_df['valid'].sum()
        total_suspect = summary_df['suspect'].sum()

        print(f"\nOverall: {total_valid}/{total_samples} samples validated ({total_valid/total_samples*100:.1f}%)")
        print(f"Total suspect samples: {total_suspect}")


# Example usage and CLI
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate BGP traffic labels using K-Means and Isolation Forest"
    )
    parser.add_argument(
        "input",
        type=str,
        help="Path to features CSV file or directory containing incident folders"
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default=None,
        help="Output directory for validated files (default: same as input)"
    )
    parser.add_argument(
        "--normal-label",
        type=str,
        default="normal",
        help="Label used for normal traffic (default: 'normal')"
    )
    parser.add_argument(
        "--attack-labels",
        type=str,
        nargs="+",
        default=["prefix_hijacking", "path_manipulation", "dos_attack"],
        help="Labels used for attack traffic"
    )
    parser.add_argument(
        "--n-clusters",
        type=int,
        default=None,
        help="Number of K-Means clusters (auto-detected if not specified)"
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Expected contamination rate in normal class (default: 0.05)"
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir) if args.output_dir else None

    if input_path.is_file():
        # Single file mode
        validate_features_csv(
            input_path,
            output_dir=output_dir,
            normal_label=args.normal_label,
            attack_labels=args.attack_labels
        )
    elif input_path.is_dir():
        # Check if it's a base directory with incidents or a single incident
        has_incidents = any(
            list(d.glob("*_labeled_features.csv"))
            for d in input_path.iterdir()
            if d.is_dir()
        )

        if has_incidents:
            process_all_incidents(
                input_path,
                normal_label=args.normal_label,
                attack_labels=args.attack_labels
            )
        else:
            # Single incident directory
            for features_csv in input_path.glob("*_labeled_features.csv"):
                validate_features_csv(
                    features_csv,
                    output_dir=output_dir,
                    normal_label=args.normal_label,
                    attack_labels=args.attack_labels
                )
    else:
        print(f"[!] Input path not found: {input_path}")
