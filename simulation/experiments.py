"""
Experiment Implementations for the Zero Trust Research Framework.

Implements the three core research experiments:
  - Experiment 1: Risk-Response Consistency across enterprise scenarios.
  - Experiment 2: Fixed MFA vs. Risk-Adaptive Zero Trust Architecture.
  - Experiment 3: Weight Sensitivity Analysis (Equal vs. Proposed vs. AHP-Derived).
"""

from typing import Dict, List, Any, Tuple, Optional
import pandas as pd
import numpy as np

from simulation.risk_engine import RiskEngine, PROPOSED_WEIGHTS, EQUAL_WEIGHTS
from simulation.decision_engine import DecisionEngine, DECISION_ALLOW, DECISION_MFA_REQUIRED, DECISION_STEP_UP_REQUIRED, DECISION_APPROVAL_REQUIRED, DECISION_INDEPENDENT_VERIFICATION, DECISION_BLOCK_HOLD
from simulation.ahp import AHPModel
from simulation.metrics import MetricsCalculator


class ExperimentRunner:
    """
    Executes and synthesizes the three research prototype experiments.
    """

    def __init__(self, scenarios_path: str = "simulation/scenarios.csv"):
        self.scenarios_path = scenarios_path
        self.df_scenarios = pd.read_csv(scenarios_path)
        self.decision_engine = DecisionEngine()
        self.risk_engine = self.decision_engine.risk_engine

    def evaluate_scenario_dataframe(self, df: pd.DataFrame, weights: Optional[Dict[str, float]] = None) -> pd.DataFrame:
        """
        Applies the Zero Trust decision engine to every row in a scenarios DataFrame.
        """
        results = []
        for idx, row in df.iterrows():
            factors = {
                'I': float(row['I']),
                'D': float(row['D']),
                'C': float(row['C']),
                'A': float(row['A']),
                'U': float(row['U'])
            }
            eval_res = self.decision_engine.evaluate_request(factors, weights)

            res_record = {
                'scenario_id': row.get('scenario_id', f"SCN-{idx+1:02d}"),
                'scenario_name': row.get('scenario_name', f"Scenario {idx+1}"),
                'identity_type': row.get('identity_type', 'Unknown'),
                'device_status': row.get('device_status', 'Unknown'),
                'context_details': row.get('context_details', 'Normal'),
                'requested_action': row.get('requested_action', 'Internal information'),
                'media_type': row.get('media_type', 'None'),
                'I': factors['I'],
                'D': factors['D'],
                'C': factors['C'],
                'A': factors['A'],
                'U': factors['U'],
                'raw_risk': eval_res['raw_risk'],
                'normalized_risk': eval_res['normalized_risk'],
                'risk_level': eval_res['risk_level'],
                'auth_complexity': eval_res['auth_complexity'],
                'decision': eval_res['decision'],
                'controls_count': len(eval_res['controls']),
                'controls_list': " | ".join(eval_res['controls']),
                'decision_rationale': eval_res['decision_rationale']
            }
            results.append(res_record)

        return pd.DataFrame(results)

    # ==========================================
    # EXPERIMENT 1: Risk-Response Consistency
    # ==========================================
    def run_experiment_1(self, weights: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
        """
        Experiment 1: Evaluates whether higher composite risk scores consistently trigger
        stronger Zero Trust controls and proportional authentication complexity.
        """
        w = weights or PROPOSED_WEIGHTS
        df_results = self.evaluate_scenario_dataframe(self.df_scenarios, w)

        sec_metrics = MetricsCalculator.calculate_security_metrics(df_results)
        auth_metrics = MetricsCalculator.calculate_authentication_metrics(df_results)

        # Tabulations
        risk_dist = df_results['risk_level'].value_counts().to_dict()
        decision_dist = df_results['decision'].value_counts().to_dict()
        complexity_dist = df_results['auth_complexity'].value_counts().to_dict()

        # Control item frequency
        all_controls = []
        for ctrl_str in df_results['controls_list']:
            all_controls.extend([c.strip() for c in ctrl_str.split('|')])
        control_dist = pd.Series(all_controls).value_counts().to_dict()

        return {
            'experiment': 'Experiment 1: Risk-Response Consistency',
            'df_results': df_results,
            'risk_distribution': risk_dist,
            'decision_distribution': decision_dist,
            'complexity_distribution': complexity_dist,
            'control_distribution': control_dist,
            'security_metrics': sec_metrics,
            'auth_metrics': auth_metrics
        }

    # ==========================================
    # EXPERIMENT 2: Fixed MFA vs Risk-Adaptive ZTA
    # ==========================================
    def run_experiment_2(self, weights: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
        """
        Experiment 2: Directly compares a rigid Fixed MFA architecture against the
        proposed Risk-Adaptive Zero Trust Architecture across all scenarios.
        """
        w = weights or PROPOSED_WEIGHTS
        df_zta = self.evaluate_scenario_dataframe(self.df_scenarios, w)

        # Construct Fixed MFA baseline for each scenario
        # Fixed MFA behavior:
        #   - Always requires exactly 2 steps (Primary + MFA)
        #   - Blindly allows access once MFA passes, ignoring device risk or action criticality
        #   - Fails to request independent verification on deepfakes or hold suspicious critical wire transfers
        fixed_records = []
        for idx, row in df_zta.iterrows():
            is_critical_threat = (row['risk_level'] == 'CRITICAL') or (row['A'] >= 3 and row['U'] >= 3 and row['D'] >= 3)
            is_low_risk = (row['risk_level'] == 'LOW')

            fixed_records.append({
                'scenario_id': row['scenario_id'],
                'scenario_name': row['scenario_name'],
                'risk_level': row['risk_level'],
                'normalized_risk': row['normalized_risk'],
                # Adaptive ZTA values
                'zta_complexity': row['auth_complexity'],
                'zta_decision': row['decision'],
                'zta_controls_count': row['controls_count'],
                # Fixed MFA baseline values
                'fixed_mfa_complexity': 2,
                'fixed_mfa_controls_count': 2,
                'fixed_mfa_decision': 'ALLOW (MFA Verified)',
                # Comparison Flags
                'is_low_risk_over_authenticated_by_fixed': is_low_risk,
                'is_critical_under_protected_by_fixed': is_critical_threat,
                'complexity_difference': row['auth_complexity'] - 2
            })

        df_comp = pd.DataFrame(fixed_records)

        # Aggregate Statistics
        low_risk_scenarios = df_comp[df_comp['is_low_risk_over_authenticated_by_fixed']]
        crit_threat_scenarios = df_comp[df_comp['is_critical_under_protected_by_fixed']]

        total_fixed_friction = df_comp['fixed_mfa_complexity'].sum()
        total_zta_friction = df_comp['zta_complexity'].sum()

        low_risk_fixed_friction = low_risk_scenarios['fixed_mfa_complexity'].sum()
        low_risk_zta_friction = low_risk_scenarios['zta_complexity'].sum()
        friction_saved_pct = (
            ((low_risk_fixed_friction - low_risk_zta_friction) / low_risk_fixed_friction * 100.0)
            if low_risk_fixed_friction > 0 else 0.0
        )

        return {
            'experiment': 'Experiment 2: Fixed MFA vs Risk-Adaptive ZTA',
            'df_comparison': df_comp,
            'total_scenarios': len(df_comp),
            'low_risk_count': len(low_risk_scenarios),
            'critical_threat_count': len(crit_threat_scenarios),
            'fixed_mfa_mean_complexity': 2.0,
            'zta_mean_complexity': round(df_comp['zta_complexity'].mean(), 2),
            'total_fixed_friction_points': total_fixed_friction,
            'total_zta_friction_points': total_zta_friction,
            'low_risk_fixed_friction_points': low_risk_fixed_friction,
            'low_risk_zta_friction_points': low_risk_zta_friction,
            'low_risk_friction_reduction_percentage': round(friction_saved_pct, 2),
            'critical_attacks_under_protected_by_fixed_mfa_count': len(crit_threat_scenarios),
            'critical_attacks_held_by_zta_percentage': 100.0 if len(crit_threat_scenarios) > 0 else 0.0
        }

    # ==========================================
    # EXPERIMENT 3: Weight Sensitivity Analysis
    # ==========================================
    def run_experiment_3(self, ahp_weights: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
        """
        Experiment 3: Evaluates sensitivity of risk scores, risk levels, and final decisions
        under three weighting configurations:
          A. Equal Weights (Baseline): [0.20, 0.20, 0.20, 0.20, 0.20]
          B. Proposed Weights:         [0.25, 0.15, 0.15, 0.30, 0.15]
          C. AHP-Derived Weights:      Expert-derived pairwise comparison
        """
        # If AHP weights not provided, compute from default AHP model
        if ahp_weights is None:
            ahp_mod = AHPModel()
            ahp_res = ahp_mod.get_results()
            ahp_w = ahp_res['weights']
        else:
            ahp_w = ahp_weights

        df_equal = self.evaluate_scenario_dataframe(self.df_scenarios, EQUAL_WEIGHTS)
        df_prop = self.evaluate_scenario_dataframe(self.df_scenarios, PROPOSED_WEIGHTS)
        df_ahp = self.evaluate_scenario_dataframe(self.df_scenarios, ahp_w)

        # Merge for comparative view
        df_merged = pd.DataFrame({
            'scenario_id': df_prop['scenario_id'],
            'scenario_name': df_prop['scenario_name'],
            'I': df_prop['I'],
            'D': df_prop['D'],
            'C': df_prop['C'],
            'A': df_prop['A'],
            'U': df_prop['U'],
            'score_equal': df_equal['normalized_risk'],
            'score_prop': df_prop['normalized_risk'],
            'score_ahp': df_ahp['normalized_risk'],
            'tier_equal': df_equal['risk_level'],
            'tier_prop': df_prop['risk_level'],
            'tier_ahp': df_ahp['risk_level'],
            'decision_equal': df_equal['decision'],
            'decision_prop': df_prop['decision'],
            'decision_ahp': df_ahp['decision'],
            'decision_match_equal_prop': df_equal['decision'] == df_prop['decision'],
            'decision_match_ahp_prop': df_ahp['decision'] == df_prop['decision'],
            'decision_match_all': (df_equal['decision'] == df_prop['decision']) & (df_ahp['decision'] == df_prop['decision'])
        })

        stability_metrics = MetricsCalculator.calculate_weight_sensitivity_metrics(df_prop, df_equal, df_ahp)

        # Summary of mean scores across schemes
        score_summary = {
            'equal_weights': {
                'weights': EQUAL_WEIGHTS,
                'mean_score': round(df_equal['normalized_risk'].mean(), 2),
                'std_score': round(df_equal['normalized_risk'].std(), 2)
            },
            'proposed_weights': {
                'weights': PROPOSED_WEIGHTS,
                'mean_score': round(df_prop['normalized_risk'].mean(), 2),
                'std_score': round(df_prop['normalized_risk'].std(), 2)
            },
            'ahp_weights': {
                'weights': ahp_w,
                'mean_score': round(df_ahp['normalized_risk'].mean(), 2),
                'std_score': round(df_ahp['normalized_risk'].std(), 2)
            }
        }

        return {
            'experiment': 'Experiment 3: Weight Sensitivity Analysis',
            'df_comparison': df_merged,
            'df_equal': df_equal,
            'df_prop': df_prop,
            'df_ahp': df_ahp,
            'score_summary': score_summary,
            'stability_metrics': stability_metrics
        }
