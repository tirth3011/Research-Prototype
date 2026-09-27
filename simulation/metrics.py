"""
Evaluation Metrics for Risk-Adaptive Zero Trust Architecture.

Computes:
  - Security Metrics:
      * Strong control coverage on High/Critical scenarios
      * Quarantine/Hold rate on critical attacks
      * Risk-Response Consistency (Spearman & Pearson correlation)
  - Authentication Burden Metrics:
      * Mean authentication complexity overall and per risk tier
      * Unnecessary authentication friction on low-risk requests
  - Model Robustness Metrics:
      * Decision stability across weighting schemes
      * Factor contribution gradients

IMPORTANT:
This module evaluates decision behavior and policy consistency. It does NOT claim
deepfake detection accuracy or real-world attack mitigation rates.
"""

from typing import Dict, List, Any
import numpy as np
import pandas as pd
from scipy import stats


class MetricsCalculator:
    """
    Computes rigorous academic metrics for the Zero Trust simulation experiments.
    """

    @staticmethod
    def calculate_security_metrics(df_results: pd.DataFrame) -> Dict[str, Any]:
        """
        Evaluate security efficacy on high-risk and critical identity requests.
        """
        high_crit = df_results[df_results['risk_level'].isin(['HIGH', 'CRITICAL'])]
        crit_only = df_results[df_results['risk_level'] == 'CRITICAL']

        # Strong controls defined as complexity >= 3 (beyond standard MFA)
        strong_control_count = len(high_crit[high_crit['auth_complexity'] >= 3])
        prop_high_crit_strong = (strong_control_count / len(high_crit)) if len(high_crit) > 0 else 0.0

        # Critical scenarios requiring out-of-band verification or hold
        crit_oob_count = len(crit_only[crit_only['decision'].isin(['INDEPENDENT_VERIFICATION', 'BLOCK/HOLD'])])
        prop_crit_oob = (crit_oob_count / len(crit_only)) if len(crit_only) > 0 else 0.0

        # Risk-Response Consistency Correlation
        # Measures whether higher risk strictly triggers higher complexity
        pearson_r, pearson_p = stats.pearsonr(df_results['normalized_risk'], df_results['auth_complexity'])
        spearman_rho, spearman_p = stats.spearmanr(df_results['normalized_risk'], df_results['auth_complexity'])

        return {
            'total_scenarios': len(df_results),
            'high_crit_scenarios_count': len(high_crit),
            'critical_scenarios_count': len(crit_only),
            'proportion_high_crit_receiving_strong_controls': round(prop_high_crit_strong, 4),
            'proportion_critical_requiring_independent_verification_or_hold': round(prop_crit_oob, 4),
            'risk_response_pearson_r': round(float(pearson_r), 4),
            'risk_response_pearson_p': float(pearson_p),
            'risk_response_spearman_rho': round(float(spearman_rho), 4),
            'risk_response_spearman_p': float(spearman_p)
        }

    @staticmethod
    def calculate_authentication_metrics(df_results: pd.DataFrame) -> Dict[str, Any]:
        """
        Evaluate user friction and verification overhead.
        """
        mean_complexity_overall = df_results['auth_complexity'].mean()

        complexity_by_tier = {}
        for tier in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
            subset = df_results[df_results['risk_level'] == tier]
            complexity_by_tier[tier] = {
                'count': len(subset),
                'mean_complexity': round(subset['auth_complexity'].mean(), 2) if len(subset) > 0 else 0.0,
                'min_complexity': int(subset['auth_complexity'].min()) if len(subset) > 0 else 0,
                'max_complexity': int(subset['auth_complexity'].max()) if len(subset) > 0 else 0
            }

        # Low-risk unnecessary friction:
        # In Fixed MFA, 100% of low-risk requests undergo complexity = 2.
        # In Risk-Adaptive ZTA, low-risk requests undergo complexity = 1.
        low_risk = df_results[df_results['risk_level'] == 'LOW']
        fixed_mfa_low_risk_friction = 2.0 * len(low_risk)
        zta_low_risk_friction = float(low_risk['auth_complexity'].sum()) if len(low_risk) > 0 else 0.0
        friction_reduction_pct = (
            ((fixed_mfa_low_risk_friction - zta_low_risk_friction) / fixed_mfa_low_risk_friction * 100.0)
            if fixed_mfa_low_risk_friction > 0 else 0.0
        )

        return {
            'mean_auth_complexity_overall': round(mean_complexity_overall, 2),
            'complexity_by_risk_tier': complexity_by_tier,
            'low_risk_scenarios_count': len(low_risk),
            'fixed_mfa_low_risk_total_friction': fixed_mfa_low_risk_friction,
            'adaptive_zta_low_risk_total_friction': zta_low_risk_friction,
            'low_risk_friction_reduction_percentage': round(friction_reduction_pct, 2)
        }

    @staticmethod
    def calculate_weight_sensitivity_metrics(
        df_prop: pd.DataFrame,
        df_equal: pd.DataFrame,
        df_ahp: pd.DataFrame
    ) -> Dict[str, Any]:
        """
        Compare decision stability across the three weighting schemes.
        """
        n = len(df_prop)
        dec_prop = df_prop['decision'].values
        dec_equal = df_equal['decision'].values
        dec_ahp = df_ahp['decision'].values

        tier_prop = df_prop['risk_level'].values
        tier_equal = df_equal['risk_level'].values
        tier_ahp = df_ahp['risk_level'].values

        equal_vs_prop_dec_match = np.sum(dec_equal == dec_prop) / n
        ahp_vs_prop_dec_match = np.sum(dec_ahp == dec_prop) / n
        all_three_dec_match = np.sum((dec_prop == dec_equal) & (dec_prop == dec_ahp)) / n

        equal_vs_prop_tier_match = np.sum(tier_equal == tier_prop) / n
        ahp_vs_prop_tier_match = np.sum(tier_ahp == tier_prop) / n

        # Mean absolute difference in normalized scores
        mad_equal_prop = np.mean(np.abs(df_equal['normalized_risk'].values - df_prop['normalized_risk'].values))
        mad_ahp_prop = np.mean(np.abs(df_ahp['normalized_risk'].values - df_prop['normalized_risk'].values))

        return {
            'total_scenarios_compared': n,
            'decision_stability_equal_vs_proposed_pct': round(float(equal_vs_prop_dec_match * 100.0), 2),
            'decision_stability_ahp_vs_proposed_pct': round(float(ahp_vs_prop_dec_match * 100.0), 2),
            'decision_stability_all_three_pct': round(float(all_three_dec_match * 100.0), 2),
            'risk_level_stability_equal_vs_proposed_pct': round(float(equal_vs_prop_tier_match * 100.0), 2),
            'risk_level_stability_ahp_vs_proposed_pct': round(float(ahp_vs_prop_tier_match * 100.0), 2),
            'mean_absolute_score_difference_equal_vs_prop': round(float(mad_equal_prop), 2),
            'mean_absolute_score_difference_ahp_vs_prop': round(float(mad_ahp_prop), 2)
        }
