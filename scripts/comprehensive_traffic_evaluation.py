#!/usr/bin/env python3
"""
Comprehensive Traffic Generation Evaluation Script
===================================================
Systematically compares all BGP traffic generation methods:
- SCAPY
- GAN-default (LSTM, TimeGAN, DoppelGanger)
- GAN-enhanced/tuned (LSTM, TimeGAN, DoppelGanger)
- SMOTE variants (normal, borderline, kmeans, adasyn)
- Hybrid (SMOTE + GAN)
- Copula

Evaluates against:
- Same dataset (rrc05): Training data evaluation
- Different dataset (rrc04): Generalization evaluation

Author: Generated for BGP Traffic Generation Project
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from scipy.stats import wasserstein_distance
from scipy.spatial.distance import mahalanobis
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.metrics import silhouette_score
from statsmodels.stats.multitest import multipletests
import warnings
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field, asdict
import pickle

warnings.filterwarnings('ignore')

# Set plotting style
plt.style.use('seaborn-v0_8-whitegrid')
sns.set_palette('husl')


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class EvaluationConfig:
    """Configuration for the comprehensive evaluation"""

    # Base paths
    results_base_path: str = "/home/smotaali/BGP_Traffic_Generation/results"
    output_base_path: str = "/home/smotaali/BGP_Traffic_Generation/results/comprehensive_evaluation"

    # Real datasets for comparison
    real_datasets: Dict[str, str] = field(default_factory=lambda: {
        'rrc05_same': '/home/smotaali/BGP_Traffic_Generation/results/final_label_results_HDBSCAN/rrc05_updates_20251216_extracted_discovered.csv',
        'rrc04_different': '/home/smotaali/BGP_Traffic_Generation/results/final_label_results_HDBSCAN/rrc04_updates_20251116_extracted_discovered.csv'
    })

    # Synthetic data paths - organized by method and comparison type
    # Structure: {method_name: {comparison_type: path}}
    synthetic_datasets: Dict[str, Dict[str, str]] = field(default_factory=lambda: {
        # SCAPY (only one version - direct generation)
        'SCAPY': {
            'generated': ''  # Path to SCAPY generated data
        },

        # GAN Default (trained on rrc05)
        'GAN_LSTM_default': {
            'same_rrc05': '',
            'diff_rrc04': ''
        },
        'GAN_TimeGAN_default': {
            'same_rrc05': '',
            'diff_rrc04': ''
        },
        'GAN_DoppelGanger_default': {
            'same_rrc05': '',
            'diff_rrc04': ''
        },

        # GAN Enhanced/Tuned
        'GAN_LSTM_enhanced': {
            'same_rrc05': '',
            'diff_rrc04': ''
        },
        'GAN_TimeGAN_enhanced': {
            'same_rrc05': '',
            'diff_rrc04': ''
        },
        'GAN_DoppelGanger_enhanced': {
            'same_rrc05': '',
            'diff_rrc04': ''
        },

        # SMOTE variants
        'SMOTE_normal': {
            'same_rrc05': '',
            'diff_rrc04': ''
        },
        'SMOTE_borderline': {
            'same_rrc05': '',
            'diff_rrc04': ''
        },
        'SMOTE_kmeans': {
            'same_rrc05': '',
            'diff_rrc04': ''
        },
        'SMOTE_adasyn': {
            'same_rrc05': '',
            'diff_rrc04': ''
        },

        # Hybrid (SMOTE + GAN)
        'Hybrid_SMOTE_GAN': {
            'same_rrc05': '',
            'diff_rrc04': ''
        },

        # Copula
        'Copula': {
            'same_rrc05': '',
            'diff_rrc04': ''
        }
    })

    # Evaluation parameters
    random_seed: int = 42
    alpha: float = 0.05  # Significance level

    # KS statistic thresholds
    ks_excellent_threshold: float = 0.05
    ks_good_threshold: float = 0.10
    ks_moderate_threshold: float = 0.15

    # Cohen's d cap
    cohens_d_cap: float = 10.0

    # Number of samples for t-SNE
    n_tsne_samples: int = 5000

    # PCA components
    n_pca_components: int = 10

    # Columns to exclude from analysis
    exclude_cols: List[str] = field(default_factory=lambda: [
        'timestamp', 'sequence_id', 'timestep', 'label', 'window_start', 'window_end',
        'discovered_label', 'generation_method', 'log_transform_used', 'bgp_constraints_enforced'
    ])

    # Feature importance weights for BGP semantics
    feature_importance_weights: Dict[str, float] = field(default_factory=lambda: {
        # Core routing activity (highest importance)
        'announcements_rate': 2.0,
        'withdrawals_rate': 2.0,
        'announcements_count': 2.0,
        'withdrawals_count': 2.0,

        # Instability indicators
        'flap_count': 1.8,
        'flap_rate': 1.8,

        # Path dynamics
        'edit_dist_mean': 1.5,
        'edit_dist_max': 1.5,
        'path_length_mean': 1.5,
        'path_length_max': 1.5,

        # Prefix activity
        'unique_prefixes': 1.3,
        'prefix_announcements': 1.3,

        # AS-path related
        'unique_origins': 1.2,
        'avg_as_path_length': 1.2,

        # Default for other features
        '_default': 1.0
    })

    # Top K worst features to highlight
    top_k_worst_features: int = 10


# =============================================================================
# DATA CLASSES FOR RESULTS
# =============================================================================

@dataclass
class FeatureMetrics:
    """Metrics for a single feature comparison"""
    feature: str
    ks_statistic: float
    ks_pvalue: float
    ks_adjusted_pvalue: float
    wasserstein_distance: float
    cohens_d: float
    cohens_d_interpretation: str
    similarity_level: str
    mw_statistic: float
    mw_pvalue: float
    mw_adjusted_pvalue: float
    syn_mean: float
    real_mean: float
    syn_std: float
    real_std: float
    mean_diff: float
    pct_diff: float
    importance_weight: float


@dataclass
class CorrelationMetrics:
    """Metrics for correlation structure comparison"""
    pearson_correlation: float
    spearman_correlation: float
    mean_abs_diff: float
    max_abs_diff: float
    median_abs_diff: float


@dataclass
class MultivariateMetrics:
    """Multivariate analysis metrics"""
    pca_centroid_distance: float
    pca_centroid_distance_2d: float
    mahalanobis_distance: float
    tsne_centroid_distance: float
    pca_explained_variance: List[float]
    silhouette_score: float


@dataclass
class OverallScores:
    """Overall similarity scores"""
    distribution_score_weighted: float
    distribution_score_unweighted: float
    correlation_score: float
    effect_size_score_weighted: float
    effect_size_score_unweighted: float
    wasserstein_score_weighted: float
    wasserstein_score_unweighted: float
    multivariate_score: float
    overall_score_weighted: float
    overall_score_unweighted: float


@dataclass
class MethodEvaluationResult:
    """Complete evaluation result for a single method"""
    method_name: str
    comparison_type: str  # 'same_rrc05' or 'diff_rrc04'
    n_synthetic: int
    n_real: int
    n_features: int
    feature_metrics: List[FeatureMetrics]
    correlation_metrics: CorrelationMetrics
    multivariate_metrics: MultivariateMetrics
    overall_scores: OverallScores
    problematic_features: Dict[str, List[str]]
    constant_features: Dict[str, List[str]]


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_upper_triangle(matrix: np.ndarray) -> np.ndarray:
    """Extract upper triangle elements from correlation matrix"""
    return matrix[np.triu_indices(len(matrix), k=1)]


def cohens_d(group1: pd.Series, group2: pd.Series, cap: float = 10.0) -> float:
    """Calculate Cohen's d effect size with capping"""
    n1, n2 = len(group1), len(group2)
    var1, var2 = group1.var(), group2.var()

    if n1 + n2 - 2 <= 0:
        return 0.0

    pooled_std = np.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2))

    if pooled_std == 0:
        if group1.mean() == group2.mean():
            return 0.0
        else:
            return cap if group1.mean() > group2.mean() else -cap

    d = (group1.mean() - group2.mean()) / pooled_std
    return np.clip(d, -cap, cap)


def interpret_cohens_d(d: float) -> str:
    """Interpret Cohen's d value"""
    abs_d = abs(d)
    if abs_d < 0.2:
        return 'Negligible'
    elif abs_d < 0.5:
        return 'Small'
    elif abs_d < 0.8:
        return 'Medium'
    else:
        return 'Large'


def interpret_ks_statistic(ks_stat: float, config: EvaluationConfig) -> str:
    """Interpret KS statistic threshold"""
    if ks_stat < config.ks_excellent_threshold:
        return 'Excellent'
    elif ks_stat < config.ks_good_threshold:
        return 'Good'
    elif ks_stat < config.ks_moderate_threshold:
        return 'Moderate'
    else:
        return 'Poor'


# =============================================================================
# MAIN EVALUATION CLASS
# =============================================================================

class ComprehensiveTrafficEvaluator:
    """Main class for comprehensive traffic generation evaluation"""

    def __init__(self, config: EvaluationConfig):
        self.config = config
        self.results: Dict[str, Dict[str, MethodEvaluationResult]] = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create output directory
        self.output_dir = Path(config.output_base_path) / self.timestamp
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Store real datasets
        self.real_data: Dict[str, pd.DataFrame] = {}

        print(f"Comprehensive Traffic Evaluator initialized")
        print(f"Output directory: {self.output_dir}")

    def load_real_datasets(self) -> None:
        """Load real datasets for comparison"""
        print("\n" + "=" * 60)
        print("Loading Real Datasets")
        print("=" * 60)

        for name, path in self.config.real_datasets.items():
            if os.path.exists(path):
                df = pd.read_csv(path)
                # Filter only normal traffic
                if 'discovered_label' in df.columns:
                    df = df[df['discovered_label'] == 'likely_normal'].copy()
                self.real_data[name] = df
                print(f"  Loaded {name}: {len(df)} samples")
            else:
                print(f"  [WARNING] File not found: {path}")

    def get_feature_columns(self, df: pd.DataFrame) -> List[str]:
        """Get feature columns excluding metadata"""
        return [col for col in df.columns if col not in self.config.exclude_cols]

    def evaluate_single_comparison(
        self,
        synthetic_df: pd.DataFrame,
        real_df: pd.DataFrame,
        method_name: str,
        comparison_type: str
    ) -> MethodEvaluationResult:
        """Evaluate a single synthetic vs real comparison"""

        print(f"\n  Evaluating {method_name} - {comparison_type}...")

        # Filter synthetic data (label == 'synthetic' or similar)
        if 'label' in synthetic_df.columns:
            syn_labels = synthetic_df['label'].unique()
            if 'synthetic' in syn_labels:
                synthetic_df = synthetic_df[synthetic_df['label'] == 'synthetic'].copy()

        # Get feature columns
        feature_cols = self.get_feature_columns(synthetic_df)
        feature_cols = [c for c in feature_cols if c in real_df.columns]

        # Sample equal amounts
        n_samples = min(len(synthetic_df), len(real_df))
        np.random.seed(self.config.random_seed)
        synthetic_sampled = synthetic_df.sample(n=n_samples, random_state=self.config.random_seed)
        real_sampled = real_df.sample(n=n_samples, random_state=self.config.random_seed)

        # Identify constant features
        constant_both = []
        constant_synthetic_only = []
        constant_real_only = []
        valid_features = []

        for col in feature_cols:
            syn_std = synthetic_sampled[col].std()
            real_std = real_sampled[col].std()

            if syn_std == 0 and real_std == 0:
                constant_both.append(col)
            elif syn_std == 0 and real_std > 0:
                constant_synthetic_only.append(col)
            elif syn_std > 0 and real_std == 0:
                constant_real_only.append(col)
            else:
                valid_features.append(col)

        # Calculate per-feature metrics
        feature_metrics_list = []
        ks_results = []
        mw_results = []
        effect_sizes = []

        for col in valid_features:
            syn_col = synthetic_sampled[col]
            real_col = real_sampled[col]

            # KS Test
            ks_stat, ks_pvalue = stats.ks_2samp(syn_col, real_col)

            # Wasserstein Distance (normalized)
            syn_normalized = (syn_col - syn_col.mean()) / (syn_col.std() + 1e-10)
            real_normalized = (real_col - real_col.mean()) / (real_col.std() + 1e-10)
            wd = wasserstein_distance(syn_normalized, real_normalized)

            # Mann-Whitney U test
            mw_stat, mw_pvalue = stats.mannwhitneyu(syn_col, real_col, alternative='two-sided')

            # Effect size
            d = cohens_d(syn_col, real_col, self.config.cohens_d_cap)
            d_interp = interpret_cohens_d(d)

            # Similarity level
            sim_level = interpret_ks_statistic(ks_stat, self.config)

            # Weight
            weight = self.config.feature_importance_weights.get(
                col, self.config.feature_importance_weights['_default']
            )

            # Mean difference
            syn_mean = syn_col.mean()
            real_mean = real_col.mean()
            mean_diff = abs(syn_mean - real_mean)
            pct_diff = (mean_diff / (abs(real_mean) + 1e-10)) * 100 if abs(real_mean) > 0.01 else 0

            ks_results.append(ks_pvalue)
            mw_results.append(mw_pvalue)

            feature_metrics_list.append({
                'feature': col,
                'ks_stat': ks_stat,
                'ks_pvalue': ks_pvalue,
                'wd': wd,
                'mw_stat': mw_stat,
                'mw_pvalue': mw_pvalue,
                'd': d,
                'd_interp': d_interp,
                'sim_level': sim_level,
                'syn_mean': syn_mean,
                'real_mean': real_mean,
                'syn_std': syn_col.std(),
                'real_std': real_col.std(),
                'mean_diff': mean_diff,
                'pct_diff': pct_diff,
                'weight': weight
            })

        # Apply FDR correction
        if ks_results:
            _, ks_adj_pvalues, _, _ = multipletests(ks_results, method='fdr_bh')
            _, mw_adj_pvalues, _, _ = multipletests(mw_results, method='fdr_bh')
        else:
            ks_adj_pvalues = []
            mw_adj_pvalues = []

        # Create FeatureMetrics objects
        feature_metrics = []
        for i, fm in enumerate(feature_metrics_list):
            feature_metrics.append(FeatureMetrics(
                feature=fm['feature'],
                ks_statistic=fm['ks_stat'],
                ks_pvalue=fm['ks_pvalue'],
                ks_adjusted_pvalue=ks_adj_pvalues[i] if i < len(ks_adj_pvalues) else fm['ks_pvalue'],
                wasserstein_distance=fm['wd'],
                cohens_d=fm['d'],
                cohens_d_interpretation=fm['d_interp'],
                similarity_level=fm['sim_level'],
                mw_statistic=fm['mw_stat'],
                mw_pvalue=fm['mw_pvalue'],
                mw_adjusted_pvalue=mw_adj_pvalues[i] if i < len(mw_adj_pvalues) else fm['mw_pvalue'],
                syn_mean=fm['syn_mean'],
                real_mean=fm['real_mean'],
                syn_std=fm['syn_std'],
                real_std=fm['real_std'],
                mean_diff=fm['mean_diff'],
                pct_diff=fm['pct_diff'],
                importance_weight=fm['weight']
            ))

        # Correlation structure analysis
        if len(valid_features) > 1:
            corr_syn = synthetic_sampled[valid_features].corr()
            corr_real = real_sampled[valid_features].corr()
            corr_diff = abs(corr_syn - corr_real)

            corr_syn_flat = get_upper_triangle(corr_syn.values)
            corr_real_flat = get_upper_triangle(corr_real.values)

            # Handle NaN values
            valid_mask = ~(np.isnan(corr_syn_flat) | np.isnan(corr_real_flat))
            if valid_mask.sum() > 0:
                pearson_corr, _ = stats.pearsonr(corr_syn_flat[valid_mask], corr_real_flat[valid_mask])
                spearman_corr, _ = stats.spearmanr(corr_syn_flat[valid_mask], corr_real_flat[valid_mask])
            else:
                pearson_corr = 0.0
                spearman_corr = 0.0

            correlation_metrics = CorrelationMetrics(
                pearson_correlation=pearson_corr,
                spearman_correlation=spearman_corr,
                mean_abs_diff=np.nanmean(corr_diff.values),
                max_abs_diff=np.nanmax(corr_diff.values),
                median_abs_diff=np.nanmedian(corr_diff.values)
            )
        else:
            correlation_metrics = CorrelationMetrics(0.0, 0.0, 0.0, 0.0, 0.0)

        # Multivariate analysis (PCA + t-SNE)
        multivariate_metrics = self._calculate_multivariate_metrics(
            synthetic_sampled[valid_features].values,
            real_sampled[valid_features].values
        )

        # Calculate overall scores
        overall_scores = self._calculate_overall_scores(
            feature_metrics, correlation_metrics, multivariate_metrics
        )

        # Identify problematic features
        problematic = {
            'large_effect': [fm.feature for fm in feature_metrics if fm.cohens_d_interpretation == 'Large'],
            'poor_ks': [fm.feature for fm in feature_metrics if fm.similarity_level == 'Poor'],
            'high_wasserstein': sorted(
                [(fm.feature, fm.wasserstein_distance) for fm in feature_metrics],
                key=lambda x: x[1], reverse=True
            )[:self.config.top_k_worst_features]
        }
        problematic['high_wasserstein'] = [f[0] for f in problematic['high_wasserstein']]

        constant_features = {
            'constant_both': constant_both,
            'constant_synthetic_only': constant_synthetic_only,
            'constant_real_only': constant_real_only
        }

        return MethodEvaluationResult(
            method_name=method_name,
            comparison_type=comparison_type,
            n_synthetic=n_samples,
            n_real=n_samples,
            n_features=len(valid_features),
            feature_metrics=feature_metrics,
            correlation_metrics=correlation_metrics,
            multivariate_metrics=multivariate_metrics,
            overall_scores=overall_scores,
            problematic_features=problematic,
            constant_features=constant_features
        )

    def _calculate_multivariate_metrics(
        self,
        X_synthetic: np.ndarray,
        X_real: np.ndarray
    ) -> MultivariateMetrics:
        """Calculate multivariate metrics (PCA, t-SNE)"""

        # Combine and scale
        X_combined = np.vstack([X_synthetic, X_real])
        labels = np.array([0] * len(X_synthetic) + [1] * len(X_real))

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_combined)

        # Split back
        X_syn_scaled = X_scaled[:len(X_synthetic)]
        X_real_scaled = X_scaled[len(X_synthetic):]

        # PCA
        n_components = min(self.config.n_pca_components, X_scaled.shape[1])
        pca = PCA(n_components=n_components)
        X_pca = pca.fit_transform(X_scaled)

        X_pca_syn = X_pca[:len(X_synthetic)]
        X_pca_real = X_pca[len(X_synthetic):]

        centroid_syn = X_pca_syn.mean(axis=0)
        centroid_real = X_pca_real.mean(axis=0)

        pca_centroid_distance = np.linalg.norm(centroid_syn - centroid_real)
        pca_centroid_distance_2d = np.linalg.norm(centroid_syn[:2] - centroid_real[:2])

        # Mahalanobis distance
        try:
            cov_pooled = (np.cov(X_pca_syn.T) + np.cov(X_pca_real.T)) / 2
            cov_inv = np.linalg.inv(cov_pooled)
            mahal_distance = mahalanobis(centroid_syn, centroid_real, cov_inv)
        except (np.linalg.LinAlgError, ValueError):
            mahal_distance = np.nan

        # Silhouette score (how well separated are the clusters?)
        try:
            sil_score = silhouette_score(X_pca[:, :2], labels)
        except:
            sil_score = np.nan

        # t-SNE (on subset for efficiency)
        n_tsne = min(self.config.n_tsne_samples, len(X_scaled))
        n_each = n_tsne // 2

        np.random.seed(self.config.random_seed)
        syn_idx = np.random.choice(len(X_synthetic), min(n_each, len(X_synthetic)), replace=False)
        real_idx = np.random.choice(len(X_real), min(n_each, len(X_real)), replace=False)

        X_tsne_subset = np.vstack([X_syn_scaled[syn_idx], X_real_scaled[real_idx]])

        if len(X_tsne_subset) > 10:
            try:
                tsne = TSNE(n_components=2, random_state=self.config.random_seed, perplexity=min(30, len(X_tsne_subset)-1))
                X_tsne = tsne.fit_transform(X_tsne_subset)

                n_syn_tsne = len(syn_idx)
                tsne_centroid_syn = X_tsne[:n_syn_tsne].mean(axis=0)
                tsne_centroid_real = X_tsne[n_syn_tsne:].mean(axis=0)
                tsne_centroid_distance = np.linalg.norm(tsne_centroid_syn - tsne_centroid_real)
            except:
                tsne_centroid_distance = np.nan
        else:
            tsne_centroid_distance = np.nan

        return MultivariateMetrics(
            pca_centroid_distance=pca_centroid_distance,
            pca_centroid_distance_2d=pca_centroid_distance_2d,
            mahalanobis_distance=mahal_distance,
            tsne_centroid_distance=tsne_centroid_distance,
            pca_explained_variance=pca.explained_variance_ratio_.tolist(),
            silhouette_score=sil_score
        )

    def _calculate_overall_scores(
        self,
        feature_metrics: List[FeatureMetrics],
        correlation_metrics: CorrelationMetrics,
        multivariate_metrics: MultivariateMetrics
    ) -> OverallScores:
        """Calculate overall similarity scores"""

        if not feature_metrics:
            return OverallScores(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        # Get weights
        total_weight = sum(fm.importance_weight for fm in feature_metrics)
        n_features = len(feature_metrics)

        # Distribution score (weighted)
        good_or_better_weighted = sum(
            fm.importance_weight for fm in feature_metrics
            if fm.similarity_level in ['Excellent', 'Good']
        )
        distribution_score_weighted = (good_or_better_weighted / total_weight) * 100

        # Distribution score (unweighted)
        good_or_better = sum(1 for fm in feature_metrics if fm.similarity_level in ['Excellent', 'Good'])
        distribution_score_unweighted = (good_or_better / n_features) * 100

        # Correlation score
        correlation_score = ((correlation_metrics.pearson_correlation + 1) / 2) * 100

        # Effect size score (weighted)
        effect_weights = {
            'Negligible': 4,
            'Small': 3,
            'Medium': 2,
            'Large': 1
        }
        effect_score_weighted = sum(
            effect_weights.get(fm.cohens_d_interpretation, 1) * fm.importance_weight
            for fm in feature_metrics
        ) / (4 * total_weight) * 100

        # Effect size score (unweighted)
        effect_score_unweighted = sum(
            effect_weights.get(fm.cohens_d_interpretation, 1)
            for fm in feature_metrics
        ) / (4 * n_features) * 100

        # Wasserstein score (inverse - lower is better)
        mean_wd = np.mean([fm.wasserstein_distance for fm in feature_metrics])
        wasserstein_score_unweighted = max(0, 100 - mean_wd * 50)

        weighted_wd = sum(
            fm.wasserstein_distance * fm.importance_weight for fm in feature_metrics
        ) / total_weight
        wasserstein_score_weighted = max(0, 100 - weighted_wd * 50)

        # Multivariate score (based on PCA centroid distance)
        # Normalize to 0-100 range (lower distance = higher score)
        pca_score = max(0, 100 - multivariate_metrics.pca_centroid_distance * 10)

        # Overall scores (weighted combination)
        overall_weighted = (
            distribution_score_weighted * 0.30 +
            correlation_score * 0.20 +
            effect_score_weighted * 0.25 +
            wasserstein_score_weighted * 0.15 +
            pca_score * 0.10
        )

        overall_unweighted = (
            distribution_score_unweighted * 0.30 +
            correlation_score * 0.20 +
            effect_score_unweighted * 0.25 +
            wasserstein_score_unweighted * 0.15 +
            pca_score * 0.10
        )

        return OverallScores(
            distribution_score_weighted=distribution_score_weighted,
            distribution_score_unweighted=distribution_score_unweighted,
            correlation_score=correlation_score,
            effect_size_score_weighted=effect_score_weighted,
            effect_size_score_unweighted=effect_score_unweighted,
            wasserstein_score_weighted=wasserstein_score_weighted,
            wasserstein_score_unweighted=wasserstein_score_unweighted,
            multivariate_score=pca_score,
            overall_score_weighted=overall_weighted,
            overall_score_unweighted=overall_unweighted
        )

    def evaluate_method(
        self,
        method_name: str,
        synthetic_paths: Dict[str, str]
    ) -> Dict[str, MethodEvaluationResult]:
        """Evaluate a single method against all comparison types"""

        print(f"\n{'='*60}")
        print(f"Evaluating Method: {method_name}")
        print(f"{'='*60}")

        results = {}

        for comp_type, syn_path in synthetic_paths.items():
            if not syn_path or not os.path.exists(syn_path):
                print(f"  [SKIP] {comp_type}: Path not found or empty")
                continue

            # Determine which real dataset to use
            if 'rrc05' in comp_type or 'same' in comp_type:
                real_key = 'rrc05_same'
            else:
                real_key = 'rrc04_different'

            if real_key not in self.real_data:
                print(f"  [SKIP] {comp_type}: Real data {real_key} not loaded")
                continue

            # Load synthetic data
            try:
                synthetic_df = pd.read_csv(syn_path)
                print(f"  Loaded synthetic data: {len(synthetic_df)} samples")
            except Exception as e:
                print(f"  [ERROR] Loading {syn_path}: {e}")
                continue

            # Evaluate
            result = self.evaluate_single_comparison(
                synthetic_df,
                self.real_data[real_key],
                method_name,
                comp_type
            )
            results[comp_type] = result

        return results

    def evaluate_all_methods(self) -> None:
        """Evaluate all configured methods"""

        print("\n" + "=" * 80)
        print("COMPREHENSIVE TRAFFIC GENERATION EVALUATION")
        print("=" * 80)

        # Load real datasets first
        self.load_real_datasets()

        # Evaluate each method
        for method_name, syn_paths in self.config.synthetic_datasets.items():
            self.results[method_name] = self.evaluate_method(method_name, syn_paths)

        print("\n" + "=" * 80)
        print("Evaluation Complete!")
        print("=" * 80)

    def generate_comparison_table(self) -> pd.DataFrame:
        """Generate a comparison table of all methods"""

        rows = []

        for method_name, method_results in self.results.items():
            for comp_type, result in method_results.items():
                rows.append({
                    'Method': method_name,
                    'Comparison': comp_type,
                    'N_Samples': result.n_synthetic,
                    'N_Features': result.n_features,
                    'Overall_Score_W': round(result.overall_scores.overall_score_weighted, 2),
                    'Overall_Score_UW': round(result.overall_scores.overall_score_unweighted, 2),
                    'Distribution_W': round(result.overall_scores.distribution_score_weighted, 2),
                    'Correlation': round(result.overall_scores.correlation_score, 2),
                    'Effect_Size_W': round(result.overall_scores.effect_size_score_weighted, 2),
                    'Wasserstein_W': round(result.overall_scores.wasserstein_score_weighted, 2),
                    'PCA_Score': round(result.overall_scores.multivariate_score, 2),
                    'N_Large_Effect': len(result.problematic_features['large_effect']),
                    'N_Poor_KS': len(result.problematic_features['poor_ks']),
                    'N_Const_Syn': len(result.constant_features['constant_synthetic_only'])
                })

        df = pd.DataFrame(rows)
        return df.sort_values('Overall_Score_W', ascending=False)

    def generate_feature_comparison_table(self) -> pd.DataFrame:
        """Generate detailed feature comparison across methods"""

        rows = []

        for method_name, method_results in self.results.items():
            for comp_type, result in method_results.items():
                for fm in result.feature_metrics:
                    rows.append({
                        'Method': method_name,
                        'Comparison': comp_type,
                        'Feature': fm.feature,
                        'KS_Statistic': fm.ks_statistic,
                        'Wasserstein': fm.wasserstein_distance,
                        'Cohens_d': fm.cohens_d,
                        'Effect_Interp': fm.cohens_d_interpretation,
                        'Similarity_Level': fm.similarity_level,
                        'Mean_Diff_Pct': fm.pct_diff,
                        'Weight': fm.importance_weight
                    })

        return pd.DataFrame(rows)

    def plot_overall_comparison(self, save_path: Optional[str] = None) -> None:
        """Plot overall comparison of all methods"""

        comparison_df = self.generate_comparison_table()

        if comparison_df.empty:
            print("No results to plot")
            return

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))

        # 1. Overall scores comparison
        ax1 = axes[0, 0]
        methods = comparison_df['Method'] + '\n(' + comparison_df['Comparison'] + ')'
        x = np.arange(len(methods))
        width = 0.35

        ax1.bar(x - width/2, comparison_df['Overall_Score_W'], width, label='Weighted', alpha=0.8, color='#3498db')
        ax1.bar(x + width/2, comparison_df['Overall_Score_UW'], width, label='Unweighted', alpha=0.8, color='#95a5a6')
        ax1.set_xlabel('Method')
        ax1.set_ylabel('Overall Score')
        ax1.set_title('Overall Similarity Scores by Method')
        ax1.set_xticks(x)
        ax1.set_xticklabels(methods, rotation=45, ha='right', fontsize=8)
        ax1.legend()
        ax1.set_ylim(0, 100)
        ax1.axhline(y=70, color='g', linestyle='--', alpha=0.5, label='Good threshold')

        # 2. Component scores heatmap
        ax2 = axes[0, 1]
        score_cols = ['Distribution_W', 'Correlation', 'Effect_Size_W', 'Wasserstein_W', 'PCA_Score']
        score_data = comparison_df[score_cols].values

        im = ax2.imshow(score_data, cmap='RdYlGn', aspect='auto', vmin=0, vmax=100)
        ax2.set_xticks(np.arange(len(score_cols)))
        ax2.set_xticklabels(score_cols, rotation=45, ha='right')
        ax2.set_yticks(np.arange(len(methods)))
        ax2.set_yticklabels(methods, fontsize=8)
        ax2.set_title('Component Scores Heatmap')
        plt.colorbar(im, ax=ax2, label='Score')

        # Add text annotations
        for i in range(len(methods)):
            for j in range(len(score_cols)):
                text = ax2.text(j, i, f'{score_data[i, j]:.0f}',
                               ha='center', va='center', fontsize=7)

        # 3. Issues count comparison
        ax3 = axes[1, 0]
        issue_cols = ['N_Large_Effect', 'N_Poor_KS', 'N_Const_Syn']
        issue_labels = ['Large Effect Size', 'Poor KS Score', 'Constant in Synthetic']

        x = np.arange(len(methods))
        width = 0.25

        for i, (col, label) in enumerate(zip(issue_cols, issue_labels)):
            ax3.bar(x + i * width, comparison_df[col], width, label=label, alpha=0.8)

        ax3.set_xlabel('Method')
        ax3.set_ylabel('Number of Features')
        ax3.set_title('Problematic Features Count')
        ax3.set_xticks(x + width)
        ax3.set_xticklabels(methods, rotation=45, ha='right', fontsize=8)
        ax3.legend(fontsize=8)

        # 4. Same vs Different dataset comparison
        ax4 = axes[1, 1]

        # Group by method and comparison type
        same_scores = []
        diff_scores = []
        method_names = []

        for method in comparison_df['Method'].unique():
            method_data = comparison_df[comparison_df['Method'] == method]
            same_data = method_data[method_data['Comparison'].str.contains('same|rrc05', case=False)]
            diff_data = method_data[method_data['Comparison'].str.contains('diff|rrc04', case=False)]

            if not same_data.empty and not diff_data.empty:
                same_scores.append(same_data['Overall_Score_W'].values[0])
                diff_scores.append(diff_data['Overall_Score_W'].values[0])
                method_names.append(method)

        if method_names:
            x = np.arange(len(method_names))
            ax4.bar(x - width/2, same_scores, width, label='Same Dataset (rrc05)', alpha=0.8, color='#2ecc71')
            ax4.bar(x + width/2, diff_scores, width, label='Different Dataset (rrc04)', alpha=0.8, color='#e74c3c')
            ax4.set_xlabel('Method')
            ax4.set_ylabel('Overall Score (Weighted)')
            ax4.set_title('Same vs Different Dataset Performance')
            ax4.set_xticks(x)
            ax4.set_xticklabels(method_names, rotation=45, ha='right', fontsize=8)
            ax4.legend()
            ax4.set_ylim(0, 100)
        else:
            ax4.text(0.5, 0.5, 'Not enough data for comparison', ha='center', va='center', transform=ax4.transAxes)
            ax4.set_title('Same vs Different Dataset Performance')

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            print(f"Saved: {save_path}")

        plt.show()

    def plot_method_radar(self, top_n: int = 8, save_path: Optional[str] = None) -> None:
        """Create radar chart comparing top methods"""

        comparison_df = self.generate_comparison_table()

        if comparison_df.empty or len(comparison_df) == 0:
            print("No results to plot")
            return

        # Get top N methods
        top_methods = comparison_df.head(top_n)

        # Metrics for radar chart
        metrics = ['Distribution_W', 'Correlation', 'Effect_Size_W', 'Wasserstein_W', 'PCA_Score']
        num_vars = len(metrics)

        # Create angles
        angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
        angles += angles[:1]

        fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(polar=True))

        colors = plt.cm.tab10(np.linspace(0, 1, len(top_methods)))

        for idx, (_, row) in enumerate(top_methods.iterrows()):
            values = row[metrics].values.flatten().tolist()
            values += values[:1]

            ax.plot(angles, values, 'o-', linewidth=2, label=f"{row['Method']}\n({row['Comparison']})", color=colors[idx])
            ax.fill(angles, values, alpha=0.1, color=colors[idx])

        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(metrics, fontsize=10)
        ax.set_ylim(0, 100)
        ax.set_title(f'Top {len(top_methods)} Methods Comparison', fontsize=14, fontweight='bold', pad=20)
        ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=8)

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            print(f"Saved: {save_path}")

        plt.show()

    def plot_feature_heatmap(self, metric: str = 'ks_statistic', save_path: Optional[str] = None) -> None:
        """Plot feature-wise comparison heatmap"""

        feature_df = self.generate_feature_comparison_table()

        if feature_df.empty:
            print("No feature data to plot")
            return

        # Map metric names
        metric_map = {
            'ks_statistic': 'KS_Statistic',
            'wasserstein': 'Wasserstein',
            'cohens_d': 'Cohens_d'
        }
        metric_col = metric_map.get(metric, metric)

        # Pivot for heatmap
        pivot_df = feature_df.pivot_table(
            index='Feature',
            columns=['Method', 'Comparison'],
            values=metric_col,
            aggfunc='mean'
        )

        if pivot_df.empty:
            print("No data for heatmap")
            return

        # Create heatmap
        fig, ax = plt.subplots(figsize=(max(12, len(pivot_df.columns) * 1.5), max(8, len(pivot_df) * 0.3)))

        cmap = 'RdYlGn_r' if metric in ['ks_statistic', 'wasserstein', 'cohens_d'] else 'RdYlGn'

        sns.heatmap(pivot_df, ax=ax, cmap=cmap, center=None, annot=True, fmt='.2f',
                    annot_kws={'size': 7}, cbar_kws={'label': metric_col})

        ax.set_title(f'Feature-wise {metric_col} Comparison Across Methods', fontsize=12, fontweight='bold')
        ax.set_xlabel('Method & Comparison')
        ax.set_ylabel('Feature')

        plt.xticks(rotation=45, ha='right', fontsize=8)
        plt.yticks(fontsize=8)
        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            print(f"Saved: {save_path}")

        plt.show()

    def generate_summary_report(self) -> str:
        """Generate text summary report"""

        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("COMPREHENSIVE TRAFFIC GENERATION EVALUATION REPORT")
        report_lines.append(f"Generated: {self.timestamp}")
        report_lines.append("=" * 80)

        comparison_df = self.generate_comparison_table()

        if comparison_df.empty:
            report_lines.append("\nNo evaluation results available.")
            return "\n".join(report_lines)

        # Best overall method
        report_lines.append("\n" + "-" * 40)
        report_lines.append("RANKING BY OVERALL SCORE (WEIGHTED)")
        report_lines.append("-" * 40)

        for i, (_, row) in enumerate(comparison_df.iterrows()):
            report_lines.append(
                f"{i+1}. {row['Method']} ({row['Comparison']}): {row['Overall_Score_W']:.2f}"
            )

        # Best for each category
        report_lines.append("\n" + "-" * 40)
        report_lines.append("BEST METHOD BY CATEGORY")
        report_lines.append("-" * 40)

        categories = {
            'Distribution Similarity': 'Distribution_W',
            'Correlation Structure': 'Correlation',
            'Effect Size': 'Effect_Size_W',
            'Wasserstein Distance': 'Wasserstein_W',
            'Multivariate (PCA)': 'PCA_Score'
        }

        for cat_name, col in categories.items():
            best_idx = comparison_df[col].idxmax()
            best_row = comparison_df.loc[best_idx]
            report_lines.append(
                f"  {cat_name}: {best_row['Method']} ({best_row['Comparison']}) - {best_row[col]:.2f}"
            )

        # Same vs Different dataset comparison
        report_lines.append("\n" + "-" * 40)
        report_lines.append("GENERALIZATION ANALYSIS (Same vs Different Dataset)")
        report_lines.append("-" * 40)

        for method in comparison_df['Method'].unique():
            method_data = comparison_df[comparison_df['Method'] == method]
            same_data = method_data[method_data['Comparison'].str.contains('same|rrc05', case=False)]
            diff_data = method_data[method_data['Comparison'].str.contains('diff|rrc04', case=False)]

            if not same_data.empty and not diff_data.empty:
                same_score = same_data['Overall_Score_W'].values[0]
                diff_score = diff_data['Overall_Score_W'].values[0]
                drop = same_score - diff_score
                report_lines.append(
                    f"  {method}: Same={same_score:.2f}, Diff={diff_score:.2f}, Drop={drop:.2f}"
                )

        # Detailed results per method
        report_lines.append("\n" + "=" * 80)
        report_lines.append("DETAILED RESULTS BY METHOD")
        report_lines.append("=" * 80)

        for method_name, method_results in self.results.items():
            report_lines.append(f"\n{'='*40}")
            report_lines.append(f"METHOD: {method_name}")
            report_lines.append(f"{'='*40}")

            for comp_type, result in method_results.items():
                report_lines.append(f"\n  Comparison: {comp_type}")
                report_lines.append(f"  Samples: {result.n_synthetic} (synthetic) vs {result.n_real} (real)")
                report_lines.append(f"  Features: {result.n_features}")
                report_lines.append(f"\n  Scores:")
                report_lines.append(f"    Overall (Weighted): {result.overall_scores.overall_score_weighted:.2f}")
                report_lines.append(f"    Overall (Unweighted): {result.overall_scores.overall_score_unweighted:.2f}")
                report_lines.append(f"    Distribution: {result.overall_scores.distribution_score_weighted:.2f}")
                report_lines.append(f"    Correlation: {result.overall_scores.correlation_score:.2f}")
                report_lines.append(f"    Effect Size: {result.overall_scores.effect_size_score_weighted:.2f}")
                report_lines.append(f"    Wasserstein: {result.overall_scores.wasserstein_score_weighted:.2f}")
                report_lines.append(f"    Multivariate: {result.overall_scores.multivariate_score:.2f}")

                report_lines.append(f"\n  Correlation Metrics:")
                report_lines.append(f"    Pearson: {result.correlation_metrics.pearson_correlation:.4f}")
                report_lines.append(f"    Spearman: {result.correlation_metrics.spearman_correlation:.4f}")

                report_lines.append(f"\n  Multivariate Metrics:")
                report_lines.append(f"    PCA Centroid Distance: {result.multivariate_metrics.pca_centroid_distance:.4f}")
                report_lines.append(f"    Silhouette Score: {result.multivariate_metrics.silhouette_score:.4f}")

                report_lines.append(f"\n  Problematic Features:")
                report_lines.append(f"    Large Effect Size: {len(result.problematic_features['large_effect'])}")
                if result.problematic_features['large_effect']:
                    report_lines.append(f"      {', '.join(result.problematic_features['large_effect'][:5])}")
                report_lines.append(f"    Poor KS Score: {len(result.problematic_features['poor_ks'])}")
                if result.problematic_features['poor_ks']:
                    report_lines.append(f"      {', '.join(result.problematic_features['poor_ks'][:5])}")

                report_lines.append(f"\n  Constant Features:")
                report_lines.append(f"    In Both: {len(result.constant_features['constant_both'])}")
                report_lines.append(f"    Synthetic Only (GAN Issue): {len(result.constant_features['constant_synthetic_only'])}")
                report_lines.append(f"    Real Only: {len(result.constant_features['constant_real_only'])}")

        return "\n".join(report_lines)

    def save_all_results(self) -> None:
        """Save all results to files"""

        # Save comparison table
        comparison_df = self.generate_comparison_table()
        comparison_df.to_csv(self.output_dir / 'comparison_table.csv', index=False)
        print(f"Saved: {self.output_dir / 'comparison_table.csv'}")

        # Save feature comparison table
        feature_df = self.generate_feature_comparison_table()
        feature_df.to_csv(self.output_dir / 'feature_comparison.csv', index=False)
        print(f"Saved: {self.output_dir / 'feature_comparison.csv'}")

        # Save summary report
        report = self.generate_summary_report()
        with open(self.output_dir / 'summary_report.txt', 'w') as f:
            f.write(report)
        print(f"Saved: {self.output_dir / 'summary_report.txt'}")

        # Save raw results as JSON
        results_dict = {}
        for method_name, method_results in self.results.items():
            results_dict[method_name] = {}
            for comp_type, result in method_results.items():
                results_dict[method_name][comp_type] = {
                    'n_synthetic': result.n_synthetic,
                    'n_real': result.n_real,
                    'n_features': result.n_features,
                    'overall_scores': asdict(result.overall_scores),
                    'correlation_metrics': asdict(result.correlation_metrics),
                    'multivariate_metrics': {
                        'pca_centroid_distance': result.multivariate_metrics.pca_centroid_distance,
                        'pca_centroid_distance_2d': result.multivariate_metrics.pca_centroid_distance_2d,
                        'silhouette_score': result.multivariate_metrics.silhouette_score
                    },
                    'problematic_features': result.problematic_features,
                    'constant_features': result.constant_features
                }

        with open(self.output_dir / 'results.json', 'w') as f:
            json.dump(results_dict, f, indent=2, default=str)
        print(f"Saved: {self.output_dir / 'results.json'}")

        # Save plots
        self.plot_overall_comparison(save_path=str(self.output_dir / 'overall_comparison.png'))
        self.plot_method_radar(save_path=str(self.output_dir / 'radar_comparison.png'))
        self.plot_feature_heatmap('ks_statistic', save_path=str(self.output_dir / 'feature_ks_heatmap.png'))
        self.plot_feature_heatmap('wasserstein', save_path=str(self.output_dir / 'feature_wasserstein_heatmap.png'))

        # Save config
        with open(self.output_dir / 'config.json', 'w') as f:
            json.dump(asdict(self.config), f, indent=2)
        print(f"Saved: {self.output_dir / 'config.json'}")


# =============================================================================
# HELPER FUNCTION TO AUTO-DISCOVER DATASETS
# =============================================================================

def auto_discover_datasets(base_path: str) -> Dict[str, Dict[str, str]]:
    """
    Automatically discover synthetic datasets from the results directory.

    Expected directory structure:
    results/
    ├── SCAPY/
    │   └── generated_traffic.csv
    ├── GAN_LSTM_default/
    │   ├── synthetic_rrc05.csv
    │   └── synthetic_rrc04.csv
    ├── SMOTE_kmeans/
    │   ├── synthetic_rrc05.csv
    │   └── synthetic_rrc04.csv
    ...
    """

    datasets = {}
    base = Path(base_path)

    if not base.exists():
        print(f"Base path does not exist: {base_path}")
        return datasets

    # Common patterns to search for
    method_patterns = [
        'SCAPY', 'scapy',
        'GAN_LSTM', 'LSTM', 'lstm',
        'GAN_TimeGAN', 'TimeGAN', 'timegan',
        'GAN_DoppelGanger', 'DoppelGanger', 'doppelganger',
        'SMOTE', 'smote',
        'Hybrid', 'hybrid',
        'Copula', 'copula'
    ]

    # Search for method directories
    for item in base.iterdir():
        if item.is_dir():
            method_name = item.name
            datasets[method_name] = {}

            # Look for CSV files
            for csv_file in item.glob('*.csv'):
                filename = csv_file.stem.lower()

                if 'rrc05' in filename or 'same' in filename:
                    datasets[method_name]['same_rrc05'] = str(csv_file)
                elif 'rrc04' in filename or 'diff' in filename:
                    datasets[method_name]['diff_rrc04'] = str(csv_file)
                elif 'synthetic' in filename or 'generated' in filename:
                    # Default to same comparison
                    datasets[method_name]['generated'] = str(csv_file)

    return datasets


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point for the evaluation script"""

    print("=" * 80)
    print("BGP Traffic Generation - Comprehensive Evaluation")
    print("=" * 80)

    # Create configuration
    config = EvaluationConfig()

    # Auto-discover datasets if available
    print("\nAuto-discovering datasets...")
    discovered = auto_discover_datasets(config.results_base_path)

    if discovered:
        print(f"Found {len(discovered)} method directories:")
        for method, paths in discovered.items():
            print(f"  {method}: {list(paths.keys())}")

        # Update config with discovered paths
        config.synthetic_datasets.update(discovered)

    # Create evaluator
    evaluator = ComprehensiveTrafficEvaluator(config)

    # Run evaluation
    evaluator.evaluate_all_methods()

    # Generate and save results
    evaluator.save_all_results()

    # Print summary report
    print("\n" + evaluator.generate_summary_report())

    return evaluator


if __name__ == "__main__":
    evaluator = main()
