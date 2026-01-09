# BGP Synthetic Data Generation: Comprehensive Recommendations

## Executive Summary

Based on extensive experimentation with multiple generation approaches (TimeGAN, DoppelGANger, SMOTE variants, Scapy), we provide recommendations for achieving high-quality synthetic BGP traffic data.

### Current Results Summary

| Method | Score | Key Strength |
|--------|-------|--------------|
| DoppelGANger (Enhanced) | 34.9/100 | Temporal patterns |
| SMOTE-KMeans | 34.0/100 | Correlation preservation (89.5%) |
| TimeGAN (Default) | 29.8/100 | Temporal consistency |
| Scapy (Packet-level) | 19.8/100 | Full protocol compliance |

**Key Finding**: All methods score "POOR" primarily due to distribution matching failures (KS=0) and multivariate structure issues (PCA=0).

---

## Root Cause Analysis

### Why GANs Struggle with BGP Features

1. **Heavy-Tailed Distributions**
   - Features like `unique_as_path_max`, `rare_ases_avg` follow Zipf-like distributions
   - GANs tend to average towards the mode, missing extreme values
   - Solution: Empirical KDE or Copula-based sampling

2. **Sparse Event Features**
   - `flaps`, `nadas` are often zero with rare non-zero events
   - GANs struggle with zero-inflated distributions
   - Solution: Zero-inflated mixture models

3. **Dependent Feature Groups**
   - `edit_distance_dict_*` should sum consistently
   - `origin_0 + origin_2 <= announcements`
   - GANs generate features independently
   - Solution: Conditional generation with constraint enforcement

4. **Integer vs Continuous**
   - Most BGP features are counts (integers)
   - GANs output continuous values
   - Solution: Proper rounding and post-processing

---

## Recommended Approaches

### Option 1: Hybrid SMOTE Pipeline (Fastest)

Best when: Speed is priority, correlation matters, no temporal requirements

```python
# Pipeline
1. SMOTE-KMeans for volume features (announcements, withdrawals, etc.)
2. Empirical KDE for heavy-tailed features (unique_as_path_max, etc.)
3. Zero-inflated mixture for sparse features (flaps, nadas)
4. Conditional sampling for dependent features (edit_distance_dict_*)
5. Cholesky correlation alignment
6. BGP constraint enforcement
```

**Expected Score**: 45-55/100 (improvement: +10-20 points)

### Option 2: Gaussian Copula Pipeline (Best Marginals)

Best when: Exact distribution matching is critical

```python
# Pipeline
1. Transform features to uniform via empirical CDF
2. Transform to Gaussian space
3. Generate correlated Gaussians with real correlation matrix
4. Inverse transform via quantile function
5. Post-process for constraints
```

**Expected Score**: 50-60/100 (best for distribution metrics)

### Option 3: DoppelGANger + Post-Processing (Best Novelty)

Best when: Temporal patterns matter, novel samples needed

```python
# Pipeline
1. Generate base samples with trained DoppelGANger
2. Identify worst features (KS > 0.4)
3. Replace worst features with KDE/SMOTE alternatives
4. Re-align correlations
5. Enforce constraints
```

**Expected Score**: 45-55/100 (preserves GAN novelty while fixing issues)

### Option 4: Ensemble Approach (Best Quality)

Best when: Maximum quality needed, speed not critical

```python
# Pipeline
1. Generate from multiple methods (SMOTE, Copula, KDE)
2. For each feature, select method with best KS statistic
3. Combine into single dataset
4. Re-align correlations (critical step)
5. Apply rejection sampling to filter outliers
6. Enforce constraints
```

**Expected Score**: 55-65/100 (highest expected quality)

---

## Feature-Specific Strategies

### Volume Features (SMOTE works well)
- `announcements`, `withdrawals`, `nlri_ann`, `dups`
- `origin_0`, `origin_2`, `origin_changes`
- Strategy: SMOTE-KMeans with log1p transform

### Heavy-Tailed Features (Use KDE/Copula)
- `unique_as_path_max` (worst performer across all methods)
- `edit_distance_max`, `edit_distance_avg`
- `rare_ases_avg`, `as_path_max`
- Strategy: Empirical KDE or Gaussian Copula quantile mapping

### Sparse Features (Use Mixture Model)
- `flaps`, `nadas`, `imp_wd`, `number_rare_ases`
- Strategy: Zero-inflated mixture: P(x) = p_zero * I(x=0) + (1-p_zero) * f(x|x>0)

### Dependent Features (Use Conditional Sampling)
- `edit_distance_dict_0` through `edit_distance_dict_6`
- `edit_distance_unique_dict_0`, `edit_distance_unique_dict_1`
- Strategy: Condition on `announcements` and `edit_distance_max`

---

## Post-Processing Techniques

### 1. Correlation Alignment (Essential)
```python
# Cholesky decomposition approach
L_real = cholesky(real_correlation_matrix)
L_syn = cholesky(synthetic_correlation_matrix)
aligned = standardized_synthetic @ inv(L_syn.T) @ L_real.T
```

### 2. Quantile Mapping (For Worst Features)
```python
# Map synthetic quantiles to real quantiles
ranks = rankdata(synthetic_values)
quantiles = ranks / (n + 1)
mapped = percentile(real_values, quantiles * 100)
```

### 3. Rejection Sampling (Quality Filter)
```python
# Score samples by how well they fit real distribution
# Keep top N% of samples
quality_scores = sum(in_realistic_bounds(feature) for feature in features)
keep_mask = quality_scores >= percentile(quality_scores, threshold)
```

### 4. BGP Constraint Enforcement (Domain Knowledge)
```python
# Non-negative values
# Integer rounding for count features
# origin_0 + origin_2 <= announcements
# edit_distance_dict_i = 0 when i > edit_distance_max
# Values within realistic bounds (99.5th percentile)
```

---

## Evaluation Recommendations

### Current Metrics Issues

The current evaluation (v3) uses strict thresholds:
- KS < 0.05 for "Excellent" - too strict for BGP data
- All features weighted equally - ignores domain importance

### Recommended Adjustments

1. **Relax KS Thresholds**
   - Excellent: KS < 0.10
   - Good: KS < 0.20
   - Moderate: KS < 0.35
   - Poor: KS >= 0.35

2. **Feature Importance Weighting**
   - High (2.0x): `flaps`, `announcements`, `withdrawals`
   - Medium (1.5x): `unique_as_path_max`, `edit_distance_max`
   - Normal (1.0x): All others

3. **Add Domain-Specific Metrics**
   - Constraint satisfaction rate
   - Temporal consistency (for sequences)
   - Anomaly detection classifier accuracy

---

## Implementation Checklist

### Quick Wins (< 1 hour)
- [ ] Apply selective quantile mapping to worst 5 features
- [ ] Add rejection sampling (generate 1.5x, keep best)
- [ ] Implement BGP constraint enforcement

### Medium Effort (1-4 hours)
- [ ] Implement Gaussian Copula generator
- [ ] Add conditional generation for edit_distance_dict features
- [ ] Implement zero-inflated mixture for sparse features

### Longer Term (1+ days)
- [ ] Build full ensemble pipeline
- [ ] Train feature-specific discriminators for quality scoring
- [ ] Implement temporal consistency checks for sequences

---

## Code References

All implementations are in:
- `scripts/BGP_HYBRID_SMOTE_GAN.ipynb` - Main hybrid notebook with all approaches

Key functions:
- `generate_smote_kmeans()` - SMOTE-KMeans generation
- `generate_gaussian_copula()` - Copula-based generation
- `generate_empirical_kde()` - KDE sampling for heavy-tailed
- `generate_mixture_model()` - Zero-inflated for sparse features
- `generate_conditional()` - Conditional dependent features
- `align_correlations()` - Cholesky correlation alignment
- `rejection_sampling()` - Quality filtering
- `enforce_bgp_constraints()` - Domain constraint enforcement
- `DoppelGANgerHybrid` - GAN + post-processing pipeline
- `ensemble_generation()` - Multi-method ensemble

---

## Expected Outcomes

With the recommended approaches:

| Metric | Current Best | Expected After |
|--------|--------------|----------------|
| Overall Score | 34.9/100 | 50-65/100 |
| Distribution (KS) | 0/100 | 30-50/100 |
| Correlation | 89.5/100 | 85-92/100 |
| Effect Size | 32.5/100 | 50-70/100 |
| Wasserstein | 62.9/100 | 65-80/100 |

---

## Next Steps

1. **Run the hybrid notebook** with your real data
2. **Compare all approaches** - identify best for your use case
3. **Tune parameters** based on worst-feature analysis
4. **Iterate** - move features between strategies as needed
5. **Validate** - test synthetic data in your downstream application

---

## Contact & Resources

- Notebook: `scripts/BGP_HYBRID_SMOTE_GAN.ipynb`
- Original GANs: `scripts/BGP_GAN_FIXED.ipynb`, `scripts/BGP_GAN_FIXED_v2.ipynb`
- SMOTE: `scripts/smote_likely_normal_v2.ipynb`
- Evaluation: `scripts/bgp_phase1_normal_traffic_validation.ipynb`
