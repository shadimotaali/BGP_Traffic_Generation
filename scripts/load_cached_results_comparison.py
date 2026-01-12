#!/usr/bin/env python3
"""
Load Cached Results Comparison Script

This script loads pre-computed evaluation results from enhanced_v3_summary.csv files
and creates systematic comparisons without recalculating metrics.

Usage:
    python load_cached_results_comparison.py [--output-dir OUTPUT_DIR]
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import warnings

warnings.filterwarnings('ignore')

# Set style
plt.style.use('seaborn-v0_8-whitegrid')
sns.set_palette('husl')


# =============================================================================
# CONFIGURATION - Synthetic Dataset Paths
# =============================================================================

SYNTHETIC_DATASETS = {
    # SCAPY (direct generation - only one version)
    'SCAPY': {
        'generated': '/home/smotaali/BGP_Traffic_Generation/results_zend/Scapy_enhanced_1215_v3'
    },

    # GAN Default Values
    'GAN_LSTM_default': {
        'same_rrc05': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/gan_outputs/Correlation_GAN_LSTM_rrc05',
        'diff_rrc04': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/gan_outputs/Correlation_GAN_LSTM_rrc04'
    },
    'GAN_TimeGAN_default': {
        'same_rrc05': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/gan_outputs/Correlation_GAN_TIME_rrc05',
        'diff_rrc04': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/gan_outputs/Correlation_GAN_TIME_rrc04'
    },
    'GAN_DoppelGanger_default': {
        'same_rrc05': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/gan_outputs/Correlation_GAN_Doppelganger_rrc05',
        'diff_rrc04': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/gan_outputs/Correlation_GAN_Doppelganger_rrc04'
    },

    # GAN Enhanced/Tuned Parameters
    'GAN_LSTM_enhanced': {
        'same_rrc05': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/gan_outputs_improved/Correlation_GAN_LSTM_rrc05',
        'diff_rrc04': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/gan_outputs_improved/Correlation_GAN_LSTM_rrc04'
    },
    'GAN_TimeGAN_enhanced': {
        'same_rrc05': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/gan_outputs_improved/Correlation_GAN_TIME_rrc05',
        'diff_rrc04': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/gan_outputs_improved/Correlation_GAN_TIME_rrc04'
    },
    'GAN_DoppelGanger_enhanced': {
        'same_rrc05': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/gan_outputs_improved/Correlation_GAN_Doppelganger_rrc05',
        'diff_rrc04': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/gan_outputs_improved/Correlation_GAN_Doppelganger_rrc04'
    },

    # SMOTE Variants
    'SMOTE_normal': {
        'same_rrc05': '/home/smotaali/BGP_Traffic_Generation/results_zend/SMOTE_enhanced/normal_rrc05',
        'diff_rrc04': '/home/smotaali/BGP_Traffic_Generation/results_zend/SMOTE_enhanced/normal_rrc04'
    },
    'SMOTE_borderline': {
        'same_rrc05': '/home/smotaali/BGP_Traffic_Generation/results_zend/SMOTE_enhanced/borderline_rrc05',
        'diff_rrc04': '/home/smotaali/BGP_Traffic_Generation/results_zend/SMOTE_enhanced/borderline_rrc04'
    },
    'SMOTE_kmeans': {
        'same_rrc05': '/home/smotaali/BGP_Traffic_Generation/results_zend/SMOTE_enhanced/kmeans_v3_rrc05',
        'diff_rrc04': '/home/smotaali/BGP_Traffic_Generation/results_zend/SMOTE_enhanced/kmeans_v3_rrc04'
    },
    'SMOTE_adasyn': {
        'same_rrc05': '/home/smotaali/BGP_Traffic_Generation/results_zend/SMOTE_enhanced/adasyn_rrc05',
        'diff_rrc04': '/home/smotaali/BGP_Traffic_Generation/results_zend/SMOTE_enhanced/adasyn_rrc04'
    },

    # Hybrid (SMOTE + GAN)
    'Hybrid_SMOTE_GAN': {
        'same_rrc05': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/synthetic_hybrid/compare_hybrid_rrc05',
        'diff_rrc04': '/home/smotaali/BGP_Traffic_Generation/results_huarie/results/synthetic_hybrid/compare_hybrid_rrc04'
    },

    # Copula
    'Copula': {
        'same_rrc05': '/home/smotaali/BGP_Traffic_Generation/results_zend/copula_rrc05',
        'diff_rrc04': '/home/smotaali/BGP_Traffic_Generation/results_zend/copula_rrc04'
    }
}

# Key metrics for comparison (lower is better except for correlation scores)
KEY_METRICS = {
    # Distribution metrics (lower is better)
    'Mean KS Statistic': {'direction': 'lower', 'weight': 1.5},
    'Mean Wasserstein Distance': {'direction': 'lower', 'weight': 1.5},
    'Weighted Wasserstein Distance': {'direction': 'lower', 'weight': 1.5},
    'PCA Centroid Distance': {'direction': 'lower', 'weight': 1.0},

    # Correlation metrics (higher is better)
    'Correlation Similarity (Pearson)': {'direction': 'higher', 'weight': 2.0},
    'Correlation Similarity (Spearman)': {'direction': 'higher', 'weight': 2.0},

    # Score metrics (higher is better, out of 100)
    'Distribution Score (Weighted)': {'direction': 'higher', 'weight': 1.0},
    'Distribution Score (Unweighted)': {'direction': 'higher', 'weight': 1.0},
    'Correlation Score': {'direction': 'higher', 'weight': 1.5},
    'Effect Size Score (Weighted)': {'direction': 'higher', 'weight': 1.0},
    'Effect Size Score (Unweighted)': {'direction': 'higher', 'weight': 1.0},
    'Wasserstein Score (Weighted)': {'direction': 'higher', 'weight': 1.0},

    # Feature quality counts
    'KS Excellent Features': {'direction': 'higher', 'weight': 1.0},
    'KS Good or Better Features': {'direction': 'higher', 'weight': 1.0},
    'Negligible Effect Features': {'direction': 'higher', 'weight': 1.0},
}


def find_summary_csv(directory: str) -> Optional[str]:
    """Find the enhanced_v3_summary.csv file in a directory."""
    summary_file = os.path.join(directory, 'enhanced_v3_summary.csv')
    if os.path.exists(summary_file):
        return summary_file

    # Try to find any summary.csv file
    for f in os.listdir(directory) if os.path.exists(directory) else []:
        if 'summary' in f.lower() and f.endswith('.csv'):
            return os.path.join(directory, f)

    return None


def load_summary_csv(filepath: str) -> Optional[Dict]:
    """Load a summary CSV and convert to dictionary."""
    try:
        df = pd.read_csv(filepath)
        # Convert to dict - assumes 'Metric' and 'Value' columns
        if 'Metric' in df.columns and 'Value' in df.columns:
            result = {}
            for _, row in df.iterrows():
                metric = row['Metric']
                value = row['Value']
                # Try to convert to float, handle strings like "100.0/100"
                if isinstance(value, str) and '/' in value:
                    try:
                        value = float(value.split('/')[0])
                    except:
                        pass
                else:
                    try:
                        value = float(value)
                    except:
                        pass
                result[metric] = value
            return result
        else:
            # Try first two columns
            result = {}
            cols = df.columns.tolist()
            for _, row in df.iterrows():
                metric = row[cols[0]]
                value = row[cols[1]]
                if isinstance(value, str) and '/' in value:
                    try:
                        value = float(value.split('/')[0])
                    except:
                        pass
                else:
                    try:
                        value = float(value)
                    except:
                        pass
                result[metric] = value
            return result
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return None


def load_all_results(datasets: Dict) -> Dict:
    """Load all cached results from the dataset directories."""
    results = {}

    for method_name, variants in datasets.items():
        results[method_name] = {}
        for variant_name, path in variants.items():
            summary_file = find_summary_csv(path)
            if summary_file:
                data = load_summary_csv(summary_file)
                if data:
                    results[method_name][variant_name] = data
                    print(f"✓ Loaded: {method_name} - {variant_name}")
                else:
                    print(f"✗ Failed to parse: {method_name} - {variant_name}")
            else:
                print(f"✗ Not found: {method_name} - {variant_name} ({path})")

    return results


def create_comparison_dataframe(results: Dict, evaluation_type: str = 'same_rrc05') -> pd.DataFrame:
    """Create a comparison DataFrame for a specific evaluation type."""
    rows = []

    for method_name, variants in results.items():
        # Handle special cases like SCAPY which only has 'generated'
        if evaluation_type in variants:
            data = variants[evaluation_type]
        elif 'generated' in variants:
            data = variants['generated']
        else:
            continue

        row = {'Method': method_name}
        row.update(data)
        rows.append(row)

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df.set_index('Method', inplace=True)
    return df


def calculate_overall_score(row: pd.Series, metrics: Dict = KEY_METRICS) -> float:
    """Calculate an overall weighted score for a method."""
    score = 0
    total_weight = 0

    for metric, config in metrics.items():
        if metric in row and pd.notna(row[metric]):
            value = row[metric]
            weight = config['weight']
            direction = config['direction']

            # Normalize based on direction
            if direction == 'higher':
                # For scores out of 100, use as-is percentage
                if 'Score' in metric:
                    normalized = value / 100
                elif 'Correlation' in metric:
                    normalized = value  # Already 0-1
                else:
                    normalized = min(value / 100, 1.0)  # Cap at 1
            else:  # lower is better
                # Invert the metric
                if 'KS' in metric:
                    normalized = max(0, 1 - value)  # KS is 0-1
                elif 'Wasserstein' in metric or 'Distance' in metric:
                    normalized = max(0, 1 - value / 2)  # Assume max ~2
                else:
                    normalized = max(0, 1 - value)

            score += normalized * weight
            total_weight += weight

    return (score / total_weight * 100) if total_weight > 0 else 0


def create_ranking_table(df: pd.DataFrame, metrics: List[str] = None) -> pd.DataFrame:
    """Create a ranking table for methods across metrics."""
    if metrics is None:
        metrics = list(KEY_METRICS.keys())

    available_metrics = [m for m in metrics if m in df.columns]
    rankings = pd.DataFrame(index=df.index)

    for metric in available_metrics:
        if metric in df.columns:
            config = KEY_METRICS.get(metric, {'direction': 'higher'})
            ascending = config['direction'] == 'lower'
            rankings[metric] = df[metric].rank(ascending=ascending, na_option='bottom')

    # Calculate average rank
    rankings['Average Rank'] = rankings.mean(axis=1)
    rankings = rankings.sort_values('Average Rank')

    return rankings


def plot_metric_comparison(df: pd.DataFrame, metric: str, output_dir: str,
                           evaluation_type: str = 'same_rrc05'):
    """Plot a bar chart comparing methods for a specific metric."""
    if metric not in df.columns:
        return

    fig, ax = plt.subplots(figsize=(12, 6))

    values = df[metric].dropna().sort_values(ascending=False)
    colors = plt.cm.RdYlGn(np.linspace(0.2, 0.8, len(values)))

    bars = ax.barh(range(len(values)), values, color=colors)
    ax.set_yticks(range(len(values)))
    ax.set_yticklabels(values.index)
    ax.set_xlabel(metric)
    ax.set_title(f'{metric} Comparison ({evaluation_type})')

    # Add value labels
    for i, (idx, v) in enumerate(values.items()):
        ax.text(v, i, f' {v:.4f}' if isinstance(v, float) else f' {v}',
                va='center', fontsize=9)

    plt.tight_layout()
    safe_metric = metric.replace(' ', '_').replace('/', '_').replace('(', '').replace(')', '')
    plt.savefig(os.path.join(output_dir, f'{safe_metric}_{evaluation_type}.png'), dpi=150)
    plt.close()


def plot_overall_comparison(df_same: pd.DataFrame, df_diff: pd.DataFrame,
                           output_dir: str):
    """Plot overall comparison between same and different dataset evaluations."""
    fig, axes = plt.subplots(1, 2, figsize=(16, 8))

    # Calculate overall scores
    scores_same = df_same.apply(calculate_overall_score, axis=1).sort_values(ascending=False)
    scores_diff = df_diff.apply(calculate_overall_score, axis=1).sort_values(ascending=False)

    # Same dataset plot
    colors_same = plt.cm.RdYlGn(np.linspace(0.3, 0.9, len(scores_same)))
    axes[0].barh(range(len(scores_same)), scores_same, color=colors_same)
    axes[0].set_yticks(range(len(scores_same)))
    axes[0].set_yticklabels(scores_same.index)
    axes[0].set_xlabel('Overall Score')
    axes[0].set_title('Same Dataset (rrc05) - Overall Score')
    for i, (idx, v) in enumerate(scores_same.items()):
        axes[0].text(v, i, f' {v:.1f}', va='center', fontsize=9)

    # Different dataset plot
    colors_diff = plt.cm.RdYlGn(np.linspace(0.3, 0.9, len(scores_diff)))
    axes[1].barh(range(len(scores_diff)), scores_diff, color=colors_diff)
    axes[1].set_yticks(range(len(scores_diff)))
    axes[1].set_yticklabels(scores_diff.index)
    axes[1].set_xlabel('Overall Score')
    axes[1].set_title('Different Dataset (rrc04) - Overall Score')
    for i, (idx, v) in enumerate(scores_diff.items()):
        axes[1].text(v, i, f' {v:.1f}', va='center', fontsize=9)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'overall_comparison.png'), dpi=150)
    plt.close()


def plot_radar_chart(df: pd.DataFrame, output_dir: str, evaluation_type: str):
    """Create a radar chart comparing methods across key metrics."""
    metrics = [
        'Correlation Similarity (Pearson)',
        'Correlation Similarity (Spearman)',
        'Mean KS Statistic',
        'Mean Wasserstein Distance',
        'PCA Centroid Distance'
    ]

    available_metrics = [m for m in metrics if m in df.columns]
    if len(available_metrics) < 3:
        return

    # Normalize metrics (0-1 scale, higher is better)
    normalized_data = pd.DataFrame(index=df.index)
    for m in available_metrics:
        values = df[m].dropna()
        if len(values) == 0:
            continue

        config = KEY_METRICS.get(m, {'direction': 'higher'})
        if config['direction'] == 'lower':
            # Invert so higher is better
            normalized_data[m] = 1 - (values - values.min()) / (values.max() - values.min() + 1e-10)
        else:
            normalized_data[m] = (values - values.min()) / (values.max() - values.min() + 1e-10)

    # Create radar chart
    num_vars = len(available_metrics)
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
    angles += angles[:1]  # Complete the loop

    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(polar=True))

    colors = plt.cm.tab20(np.linspace(0, 1, len(df)))

    for idx, (method, row) in enumerate(normalized_data.iterrows()):
        values = row[available_metrics].values.tolist()
        values += values[:1]  # Complete the loop
        ax.plot(angles, values, 'o-', linewidth=2, label=method, color=colors[idx])
        ax.fill(angles, values, alpha=0.1, color=colors[idx])

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels([m.replace(' ', '\n') for m in available_metrics], size=8)
    ax.set_title(f'Method Comparison Radar ({evaluation_type})', size=14, y=1.1)
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0))

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f'radar_chart_{evaluation_type}.png'), dpi=150, bbox_inches='tight')
    plt.close()


def plot_heatmap(df: pd.DataFrame, output_dir: str, evaluation_type: str):
    """Create a heatmap of metrics across methods."""
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()

    # Select key metrics that exist
    key_metric_names = list(KEY_METRICS.keys())
    available_metrics = [m for m in key_metric_names if m in numeric_cols]

    if len(available_metrics) < 2:
        return

    plot_data = df[available_metrics].copy()

    # Normalize each column to 0-1 for visualization
    for col in plot_data.columns:
        config = KEY_METRICS.get(col, {'direction': 'higher'})
        values = plot_data[col]
        min_val, max_val = values.min(), values.max()
        if max_val > min_val:
            normalized = (values - min_val) / (max_val - min_val)
            if config['direction'] == 'lower':
                normalized = 1 - normalized  # Invert so higher is always better
            plot_data[col] = normalized

    fig, ax = plt.subplots(figsize=(14, 8))

    sns.heatmap(plot_data, annot=True, fmt='.2f', cmap='RdYlGn',
                ax=ax, vmin=0, vmax=1, cbar_kws={'label': 'Normalized Score (higher=better)'})

    ax.set_title(f'Method Performance Heatmap ({evaluation_type})\n(Normalized: 1=best, 0=worst)')
    ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha='right')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f'heatmap_{evaluation_type}.png'), dpi=150)
    plt.close()


def generate_summary_report(results: Dict, df_same: pd.DataFrame, df_diff: pd.DataFrame,
                           output_dir: str) -> str:
    """Generate a text summary report."""
    report_lines = [
        "=" * 80,
        "BGP SYNTHETIC TRAFFIC GENERATION - COMPARISON REPORT",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 80,
        "",
    ]

    # Overall scores
    scores_same = df_same.apply(calculate_overall_score, axis=1).sort_values(ascending=False)
    scores_diff = df_diff.apply(calculate_overall_score, axis=1).sort_values(ascending=False)

    report_lines.extend([
        "OVERALL RANKINGS",
        "-" * 40,
        "",
        "Same Dataset (rrc05) - Higher Score = Better:",
    ])

    for rank, (method, score) in enumerate(scores_same.items(), 1):
        report_lines.append(f"  {rank}. {method}: {score:.2f}")

    report_lines.extend([
        "",
        "Different Dataset (rrc04) - Higher Score = Better:",
    ])

    for rank, (method, score) in enumerate(scores_diff.items(), 1):
        report_lines.append(f"  {rank}. {method}: {score:.2f}")

    # Best methods by category
    report_lines.extend([
        "",
        "=" * 80,
        "BEST METHODS BY METRIC CATEGORY",
        "=" * 80,
        "",
    ])

    categories = {
        'Distribution Similarity': ['Mean KS Statistic', 'Mean Wasserstein Distance'],
        'Correlation Preservation': ['Correlation Similarity (Pearson)', 'Correlation Similarity (Spearman)'],
        'Overall Scores': ['Distribution Score (Weighted)', 'Correlation Score', 'Effect Size Score (Weighted)']
    }

    for eval_type, df in [('Same Dataset (rrc05)', df_same), ('Different Dataset (rrc04)', df_diff)]:
        report_lines.extend([f"{eval_type}:", "-" * 40])

        for category, metrics in categories.items():
            report_lines.append(f"\n  {category}:")
            for metric in metrics:
                if metric in df.columns:
                    config = KEY_METRICS.get(metric, {'direction': 'higher'})
                    if config['direction'] == 'higher':
                        best = df[metric].idxmax()
                        value = df[metric].max()
                    else:
                        best = df[metric].idxmin()
                        value = df[metric].min()
                    report_lines.append(f"    {metric}: {best} ({value:.4f})")

        report_lines.append("")

    # Detailed metrics table
    report_lines.extend([
        "=" * 80,
        "DETAILED METRICS - SAME DATASET (rrc05)",
        "=" * 80,
    ])

    if not df_same.empty:
        report_lines.append(df_same.to_string())

    report_lines.extend([
        "",
        "=" * 80,
        "DETAILED METRICS - DIFFERENT DATASET (rrc04)",
        "=" * 80,
    ])

    if not df_diff.empty:
        report_lines.append(df_diff.to_string())

    report = "\n".join(report_lines)

    # Save report
    report_path = os.path.join(output_dir, 'comparison_report.txt')
    with open(report_path, 'w') as f:
        f.write(report)

    return report


def main(output_dir: str = None):
    """Main function to load cached results and generate comparisons."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if output_dir is None:
        output_dir = f'./cached_results_comparison_{timestamp}'

    os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print("Loading Cached Results Comparison")
    print("=" * 60)
    print()

    # Load all results
    print("Loading results from enhanced_v3_summary.csv files...")
    print("-" * 60)
    results = load_all_results(SYNTHETIC_DATASETS)
    print()

    # Create comparison DataFrames
    print("Creating comparison DataFrames...")
    df_same = create_comparison_dataframe(results, 'same_rrc05')
    df_diff = create_comparison_dataframe(results, 'diff_rrc04')

    # For SCAPY which only has 'generated', include it in both
    for method, variants in results.items():
        if 'generated' in variants and method not in df_same.index:
            row = variants['generated']
            row_df = pd.DataFrame([row], index=[method])
            df_same = pd.concat([df_same, row_df])
            df_diff = pd.concat([df_diff, row_df])

    print(f"  Same dataset (rrc05): {len(df_same)} methods")
    print(f"  Different dataset (rrc04): {len(df_diff)} methods")
    print()

    if df_same.empty and df_diff.empty:
        print("No results loaded! Please check the paths in SYNTHETIC_DATASETS.")
        return

    # Save raw comparison tables
    print("Saving comparison tables...")
    df_same.to_csv(os.path.join(output_dir, 'comparison_same_rrc05.csv'))
    df_diff.to_csv(os.path.join(output_dir, 'comparison_diff_rrc04.csv'))

    # Create ranking tables
    print("Creating ranking tables...")
    rankings_same = create_ranking_table(df_same)
    rankings_diff = create_ranking_table(df_diff)
    rankings_same.to_csv(os.path.join(output_dir, 'rankings_same_rrc05.csv'))
    rankings_diff.to_csv(os.path.join(output_dir, 'rankings_diff_rrc04.csv'))

    # Generate visualizations
    print("Generating visualizations...")

    # Overall comparison
    if not df_same.empty and not df_diff.empty:
        plot_overall_comparison(df_same, df_diff, output_dir)

    # Heatmaps
    if not df_same.empty:
        plot_heatmap(df_same, output_dir, 'same_rrc05')
        plot_radar_chart(df_same, output_dir, 'same_rrc05')

    if not df_diff.empty:
        plot_heatmap(df_diff, output_dir, 'diff_rrc04')
        plot_radar_chart(df_diff, output_dir, 'diff_rrc04')

    # Key metric plots
    key_metrics_to_plot = [
        'Mean KS Statistic',
        'Correlation Similarity (Pearson)',
        'Correlation Score',
        'Distribution Score (Weighted)'
    ]

    for metric in key_metrics_to_plot:
        if metric in df_same.columns:
            plot_metric_comparison(df_same, metric, output_dir, 'same_rrc05')
        if metric in df_diff.columns:
            plot_metric_comparison(df_diff, metric, output_dir, 'diff_rrc04')

    # Generate text report
    print("Generating summary report...")
    report = generate_summary_report(results, df_same, df_diff, output_dir)

    print()
    print("=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    print()

    # Print top 5 for each evaluation
    scores_same = df_same.apply(calculate_overall_score, axis=1).sort_values(ascending=False)
    scores_diff = df_diff.apply(calculate_overall_score, axis=1).sort_values(ascending=False)

    print("Top 5 Methods - Same Dataset (rrc05):")
    for rank, (method, score) in enumerate(scores_same.head(5).items(), 1):
        print(f"  {rank}. {method}: {score:.2f}")

    print()
    print("Top 5 Methods - Different Dataset (rrc04):")
    for rank, (method, score) in enumerate(scores_diff.head(5).items(), 1):
        print(f"  {rank}. {method}: {score:.2f}")

    print()
    print(f"Full results saved to: {output_dir}")
    print("  - comparison_same_rrc05.csv")
    print("  - comparison_diff_rrc04.csv")
    print("  - rankings_same_rrc05.csv")
    print("  - rankings_diff_rrc04.csv")
    print("  - comparison_report.txt")
    print("  - Various visualization plots (.png)")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Load cached results and compare synthetic data methods')
    parser.add_argument('--output-dir', '-o', type=str, default=None,
                        help='Output directory for results (default: auto-generated with timestamp)')
    args = parser.parse_args()

    main(args.output_dir)
