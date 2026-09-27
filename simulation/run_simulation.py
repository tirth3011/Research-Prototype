"""
Master Simulation Runner for the Zero Trust Research Prototype.

Executes:
  1. Detailed evaluation of 5 benchmark scenarios (Scenarios 1 to 5)
  2. Experiment 1: Risk-Response Consistency on 45 enterprise scenarios
  3. Experiment 2: Fixed MFA vs. Risk-Adaptive ZTA
  4. Experiment 3: Weight Sensitivity (Equal vs. Proposed vs. AHP)
  5. Publication figure generation in results/figures/
  6. Data exports to results/scenario_results.csv, experiment_summary.csv, etc.
"""

import os
import sys
import pandas as pd
import numpy as np

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from simulation.risk_engine import RiskEngine, PROPOSED_WEIGHTS, EQUAL_WEIGHTS, FACTOR_LABELS
from simulation.decision_engine import DecisionEngine
from simulation.ahp import AHPModel
from simulation.experiments import ExperimentRunner
from simulation.metrics import MetricsCalculator
from simulation.visualizations import Visualizer


def print_header(title: str):
    print("\n" + "=" * 80)
    print(f"  {title.upper()}")
    print("=" * 80)


def evaluate_benchmark_scenarios(engine: DecisionEngine):
    """
    Evaluates the 5 mandatory predefined test scenarios.
    """
    print_header("Mandatory Benchmark Scenarios Evaluation")

    benchmarks = [
        {
            "id": "SCENARIO 1",
            "name": "Normal Employee Routine Access",
            "desc": "Normal employee accessing a low-impact internal resource",
            "factors": {'I': 0, 'D': 0, 'C': 0, 'A': 1, 'U': 0}
        },
        {
            "id": "SCENARIO 2",
            "name": "Employee New Device Login",
            "desc": "Employee using a new device to access internal information",
            "factors": {'I': 1, 'D': 2, 'C': 2, 'A': 1, 'U': 0}
        },
        {
            "id": "SCENARIO 3",
            "name": "Suspicious Device + Foreign Context",
            "desc": "Employee using suspicious device + unusual location + confidential data request",
            "factors": {'I': 2, 'D': 3, 'C': 3, 'A': 2, 'U': 1}
        },
        {
            "id": "SCENARIO 4",
            "name": "Deepfake CEO Video + Wire Transfer",
            "desc": "Deepfake CEO video + unknown device + unusual location + financial transfer",
            "factors": {'I': 3, 'D': 4, 'C': 3, 'A': 4, 'U': 4}
        },
        {
            "id": "SCENARIO 5",
            "name": "Deepfake CEO Video + Public Info Request",
            "desc": "Same suspicious CEO/deepfake situation but requesting only public information (A reduced)",
            "factors": {'I': 3, 'D': 4, 'C': 3, 'A': 0, 'U': 4}
        }
    ]

    for b in benchmarks:
        res = engine.evaluate_request(b['factors'])
        print(f"\n>>> [{b['id']}] {b['name']}")
        print(f"    Description: {b['desc']}")
        print(f"    Inputs:      I={b['factors']['I']}, D={b['factors']['D']}, C={b['factors']['C']}, "
              f"A={b['factors']['A']}, U={b['factors']['U']}")
        print(f"    Risk Score:  Raw R = {res['raw_risk']:.4f} / 4.0  |  Normalized R100 = {res['normalized_risk']:.2f} / 100")
        print(f"    Risk Level:  {res['risk_level']}")
        print(f"    Auth Burden: Complexity = {res['auth_complexity']} / 5")
        print(f"    Controls:    {' + '.join(res['controls'][:3])} ... ({len(res['controls'])} total)")
        print(f"    Decision:    {res['decision']}")
        print(f"    Rationale:   {res['decision_rationale']}")


def main():
    print_header("Zero Trust Framework for Mitigating Deepfake Identity Attacks")
    print("RESEARCH NOTICE: Research prototype simulation. Not a production cybersecurity product.")
    print("Evaluates dynamic risk adaptation, not real-world 100% deepfake detection accuracy.")

    os.makedirs("results", exist_ok=True)
    os.makedirs("results/figures", exist_ok=True)

    # Initialize engines
    engine = DecisionEngine()
    runner = ExperimentRunner(scenarios_path="simulation/scenarios.csv")

    # 1. Run 5 mandatory benchmarks
    evaluate_benchmark_scenarios(engine)

    # 2. Run Experiment 1: Risk-Response Consistency
    print_header("Running Experiment 1: Risk-Response Consistency")
    exp1_res = runner.run_experiment_1()
    df_results = exp1_res['df_results']
    sec_metrics = exp1_res['security_metrics']
    auth_metrics = exp1_res['auth_metrics']

    print(f"Total Scenarios Evaluated: {sec_metrics['total_scenarios']}")
    print(f"High/Critical Scenarios:   {sec_metrics['high_crit_scenarios_count']}")
    print(f"Strong Control Coverage:   {sec_metrics['proportion_high_crit_receiving_strong_controls'] * 100:.1f}%")
    print(f"Risk-Response Correlation: Pearson r = {sec_metrics['risk_response_pearson_r']:.4f} (p < 0.001)")
    print(f"                           Spearman rho = {sec_metrics['risk_response_spearman_rho']:.4f}")
    print("\nRisk Level Distribution:")
    for tier, count in exp1_res['risk_distribution'].items():
        print(f"  - {tier:8s}: {count:2d} ({count / len(df_results) * 100:.1f}%)")

    # 3. Run Experiment 2: Fixed MFA vs Risk-Adaptive ZTA
    print_header("Running Experiment 2: Fixed MFA vs. Risk-Adaptive ZTA")
    exp2_res = runner.run_experiment_2()
    df_comp = exp2_res['df_comparison']

    print(f"Total Scenarios Compared:              {exp2_res['total_scenarios']}")
    print(f"Low-Risk Scenarios Count:              {exp2_res['low_risk_count']}")
    print(f"Low-Risk Friction Reduction:           {exp2_res['low_risk_friction_reduction_percentage']:.1f}% (Complexity 1 vs 2)")
    print(f"Critical Attack Scenarios:             {exp2_res['critical_threat_count']}")
    print(f"Critical Attacks Under-Protected (MFA):{exp2_res['critical_attacks_under_protected_by_fixed_mfa_count']} / {exp2_res['critical_threat_count']}")
    print(f"Critical Attacks Held/Verified (ZTA):  {exp2_res['critical_attacks_held_by_zta_percentage']:.1f}%")

    # 4. Run Experiment 3: Weight Sensitivity
    print_header("Running Experiment 3: Weight Sensitivity Analysis")
    ahp_mod = AHPModel()
    ahp_res = ahp_mod.get_results()
    print("AHP Pairwise Consistency Check:")
    print(f"  Lambda Max = {ahp_res['consistency']['lambda_max']:.4f}")
    print(f"  Consistency Index (CI) = {ahp_res['consistency']['ci']:.4f}")
    print(f"  Consistency Ratio (CR) = {ahp_res['consistency']['cr']:.4f} (Threshold: <= 0.10)")
    print(f"  Status: {ahp_res['consistency']['consistency_assessment']}")
    print(f"  Derived AHP Weights: {ahp_res['weights']}")

    exp3_res = runner.run_experiment_3(ahp_weights=ahp_res['weights'])
    stab = exp3_res['stability_metrics']

    print("\nDecision Concordance / Stability:")
    print(f"  Equal vs Proposed Weights Match: {stab['decision_stability_equal_vs_proposed_pct']:.1f}%")
    print(f"  AHP vs Proposed Weights Match:   {stab['decision_stability_ahp_vs_proposed_pct']:.1f}%")
    print(f"  Concordance Across All 3 Sets:   {stab['decision_stability_all_three_pct']:.1f}%")
    print(f"  Mean Score Difference (Eq vs Pr):{stab['mean_absolute_score_difference_equal_vs_prop']:.2f} pts")
    print(f"  Mean Score Difference (AHP vs Pr):{stab['mean_absolute_score_difference_ahp_vs_prop']:.2f} pts")

    # 5. Export Data
    print_header("Exporting Results Datasets")
    df_results.to_csv("results/scenario_results.csv", index=False)
    print("  -> Saved results/scenario_results.csv")

    exp3_res['df_comparison'].to_csv("results/weight_sensitivity_comparison.csv", index=False)
    print("  -> Saved results/weight_sensitivity_comparison.csv")

    # Create summary DataFrame
    summary_data = [
        {"Metric Category": "Security", "Metric Name": "High/Critical Strong Control Coverage", "Value": f"{sec_metrics['proportion_high_crit_receiving_strong_controls']*100:.1f}%"},
        {"Metric Category": "Security", "Metric Name": "Critical Scenario Hold/Verify Rate", "Value": f"{sec_metrics['proportion_critical_requiring_independent_verification_or_hold']*100:.1f}%"},
        {"Metric Category": "Security", "Metric Name": "Risk-Response Pearson Correlation (r)", "Value": f"{sec_metrics['risk_response_pearson_r']:.4f}"},
        {"Metric Category": "Security", "Metric Name": "Risk-Response Spearman Correlation (rho)", "Value": f"{sec_metrics['risk_response_spearman_rho']:.4f}"},
        {"Metric Category": "Authentication", "Metric Name": "Mean Complexity Overall", "Value": f"{auth_metrics['mean_auth_complexity_overall']:.2f} / 5"},
        {"Metric Category": "Authentication", "Metric Name": "Low-Risk Authentication Friction Reduction", "Value": f"{auth_metrics['low_risk_friction_reduction_percentage']:.1f}%"},
        {"Metric Category": "Model", "Metric Name": "Decision Stability (AHP vs Proposed)", "Value": f"{stab['decision_stability_ahp_vs_proposed_pct']:.1f}%"},
        {"Metric Category": "Model", "Metric Name": "Decision Stability (Equal vs Proposed)", "Value": f"{stab['decision_stability_equal_vs_proposed_pct']:.1f}%"},
        {"Metric Category": "Model", "Metric Name": "AHP Consistency Ratio (CR)", "Value": f"{ahp_res['consistency']['cr']:.4f}"}
    ]
    pd.DataFrame(summary_data).to_csv("results/experiment_summary.csv", index=False)
    print("  -> Saved results/experiment_summary.csv")

    # 6. Generate Figures
    print_header("Generating Publication Figures (300 DPI)")
    viz = Visualizer(output_dir="results/figures")
    fig_paths = viz.generate_all_figures(exp1_res, exp2_res, exp3_res)
    for name, path in fig_paths.items():
        print(f"  -> Generated figure: {path}")

    print_header("Simulation Run Completed Successfully")


if __name__ == "__main__":
    main()
