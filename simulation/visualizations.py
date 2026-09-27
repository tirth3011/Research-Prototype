"""
Research Visualization Generator.

Generates high-resolution publication-ready figures (300 DPI):
  1. risk_distribution.png: Histogram & KDE of normalized risk scores with tier thresholds
  2. risk_level_distribution.png: Scenario counts across LOW, MEDIUM, HIGH, CRITICAL
  3. risk_vs_complexity.png: Scatter plot with regression line for Risk Score vs Auth Complexity
  4. fixed_vs_adaptive.png: Grouped comparative chart for Fixed MFA vs Risk-Adaptive ZTA
  5. control_strength_by_level.png: Stacked Zero Trust control deployment across risk tiers
  6. weight_sensitivity.png: Boxplots & score distributions across Equal, Proposed, and AHP
  7. scenario_decision_matrix.png: Decision matrix heatmap for key benchmark scenarios
"""

import os
from typing import Dict, Any, Optional
import matplotlib
matplotlib.use('Agg')  # Headless backend
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

# Academic styling palette
PALETTE_TIERS = {
    'LOW': '#2E7D32',       # Forest Green
    'MEDIUM': '#F57F17',    # Deep Amber
    'HIGH': '#E65100',      # Dark Orange
    'CRITICAL': '#B71C1C'   # Crimson Red
}

plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.size': 10,
    'axes.labelsize': 11,
    'axes.titlesize': 12,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'figure.titlesize': 14,
    'figure.dpi': 300
})


class Visualizer:
    """
    Renders and exports research figures to results/figures/.
    """

    def __init__(self, output_dir: str = "results/figures"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def plot_risk_distribution(self, df_results: pd.DataFrame, filename: str = "risk_distribution.png") -> str:
        """
        Figure 1: Risk score distribution with categorical risk boundary indicators.
        """
        fig, ax = plt.subplots(figsize=(8, 5))
        scores = df_results['normalized_risk']

        # Histogram with KDE
        sns.histplot(scores, bins=15, kde=True, color='#1565C0', ax=ax, edgecolor='white', alpha=0.65)

        # Draw tier boundaries
        ax.axvline(25, color='#2E7D32', linestyle='--', linewidth=1.5, label='Low / Medium Boundary (25)')
        ax.axvline(50, color='#F57F17', linestyle='--', linewidth=1.5, label='Medium / High Boundary (50)')
        ax.axvline(75, color='#B71C1C', linestyle='--', linewidth=1.5, label='High / Critical Boundary (75)')

        ax.set_title("Distribution of Normalized Risk Scores ($R_{100}$) Across Enterprise Scenarios", pad=12, fontweight='bold')
        ax.set_xlabel("Normalized Risk Score ($R_{100}$)", labelpad=8)
        ax.set_ylabel("Scenario Frequency", labelpad=8)
        ax.set_xlim(0, 100)
        ax.grid(True, linestyle=':', alpha=0.5)
        ax.legend(loc='upper right', frameon=True)

        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=300)
        plt.close(fig)
        return path

    def plot_risk_level_distribution(self, df_results: pd.DataFrame, filename: str = "risk_level_distribution.png") -> str:
        """
        Figure 2: Frequency distribution of scenarios across Zero Trust risk levels.
        """
        fig, ax = plt.subplots(figsize=(7, 4.5))
        tier_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        counts = df_results['risk_level'].value_counts().reindex(tier_order).fillna(0)
        colors = [PALETTE_TIERS[t] for t in tier_order]

        bars = ax.bar(tier_order, counts, color=colors, edgecolor='black', alpha=0.85, width=0.55)

        # Annotate percentages
        total = len(df_results)
        for bar in bars:
            height = bar.get_height()
            pct = (height / total * 100) if total > 0 else 0
            ax.annotate(f"{int(height)} ({pct:.1f}%)",
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 4), textcoords="offset points",
                        ha='center', va='bottom', fontweight='bold', fontsize=9)

        ax.set_title("Categorical Risk Level Distribution (Zero Trust Tiers)", pad=12, fontweight='bold')
        ax.set_xlabel("Zero Trust Risk Tier", labelpad=8)
        ax.set_ylabel("Scenario Count", labelpad=8)
        ax.set_ylim(0, max(counts) * 1.25)
        ax.grid(axis='y', linestyle=':', alpha=0.5)

        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=300)
        plt.close(fig)
        return path

    def plot_risk_vs_complexity(self, df_results: pd.DataFrame, filename: str = "risk_vs_complexity.png") -> str:
        """
        Figure 3: Risk Score vs Authentication Complexity with regression line.
        """
        fig, ax = plt.subplots(figsize=(8, 5))
        x = df_results['normalized_risk']
        y = df_results['auth_complexity']

        # Add jitter to y for visual clarity of discrete points
        jitter = np.random.uniform(-0.1, 0.1, size=len(y))
        y_jitter = y + jitter

        colors = [PALETTE_TIERS.get(t, '#333333') for t in df_results['risk_level']]
        scatter = ax.scatter(x, y_jitter, c=colors, s=55, edgecolors='k', linewidth=0.5, alpha=0.85, zorder=3)

        # Linear regression fit
        m, b = np.polyfit(x, y, 1)
        x_line = np.linspace(0, 100, 100)
        ax.plot(x_line, m * x_line + b, color='#1A237E', linewidth=2.0, linestyle='-', label=f'Trend ($y = {m:.2f}x + {b:.2f}$)', zorder=2)

        # Correlation metrics
        r = np.corrcoef(x, y)[0, 1]
        ax.text(0.04, 0.88, f"Pearson $r = {r:.3f}$\n$R^2 = {r**2:.3f}$", transform=ax.transAxes,
                fontsize=10, bbox=dict(boxstyle='round,pad=0.5', facecolor='#F5F5F5', edgecolor='#BDBDBD'))

        ax.set_title("Zero Trust Adaptive Scaling: Risk Score vs. Authentication Complexity", pad=12, fontweight='bold')
        ax.set_xlabel("Normalized Risk Score ($R_{100}$)", labelpad=8)
        ax.set_ylabel("Authentication Complexity (1–5 Steps)", labelpad=8)
        ax.set_yticks([1, 2, 3, 4, 5])
        ax.set_yticklabels(['1: Basic Auth', '2: MFA', '3: Device Attest', '4: Context/Appr', '5: Out-of-Band'])
        ax.set_xlim(0, 100)
        ax.set_ylim(0.5, 5.5)
        ax.grid(True, linestyle=':', alpha=0.5)
        ax.legend(loc='lower right', frameon=True)

        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=300)
        plt.close(fig)
        return path

    def plot_fixed_vs_adaptive(self, df_comp: pd.DataFrame, filename: str = "fixed_vs_adaptive.png") -> str:
        """
        Figure 4: Side-by-side comparison of Fixed MFA vs Risk-Adaptive ZTA.
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

        # Subplot 1: Average Complexity Across Risk Tiers
        tier_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        fixed_means = []
        zta_means = []
        for t in tier_order:
            sub = df_comp[df_comp['risk_level'] == t]
            fixed_means.append(2.0)  # Always 2 for Fixed MFA
            zta_means.append(sub['zta_complexity'].mean() if len(sub) > 0 else 0)

        x = np.arange(len(tier_order))
        width = 0.35

        ax1.bar(x - width/2, fixed_means, width, label='Fixed MFA (Baseline)', color='#78909C', edgecolor='black')
        ax1.bar(x + width/2, zta_means, width, label='Risk-Adaptive ZTA (Proposed)', color='#1976D2', edgecolor='black')

        ax1.set_title("Authentication Burden Across Risk Tiers", fontweight='bold', pad=10)
        ax1.set_ylabel("Average Complexity (Steps)", labelpad=8)
        ax1.set_xticks(x)
        ax1.set_xticklabels(tier_order)
        ax1.set_ylim(0, 5.5)
        ax1.grid(axis='y', linestyle=':', alpha=0.5)
        ax1.legend(loc='upper left')

        # Subplot 2: Treatment of Critical Identity Attacks
        crit_threats = df_comp[df_comp['is_critical_under_protected_by_fixed']]
        crit_total = len(crit_threats)
        crit_caught_zta = len(crit_threats[crit_threats['zta_decision'].isin(['INDEPENDENT_VERIFICATION', 'BLOCK/HOLD'])])
        crit_blindly_allowed_fixed = crit_total  # Fixed MFA allows if MFA passes

        categories = ['Critical Attacks\nUnder-Protected by Fixed MFA', 'Critical Attacks\nHeld/Verified by ZTA']
        counts = [crit_blindly_allowed_fixed, crit_caught_zta]
        bar_colors = ['#D32F2F', '#388E3C']

        bars2 = ax2.bar(categories, counts, color=bar_colors, edgecolor='black', width=0.45)
        for b in bars2:
            h = b.get_height()
            ax2.annotate(f"{int(h)} / {crit_total}",
                         xy=(b.get_x() + b.get_width() / 2, h),
                         xytext=(0, 4), textcoords="offset points",
                         ha='center', va='bottom', fontweight='bold')

        ax2.set_title("Critical Deepfake Threat Mitigation", fontweight='bold', pad=10)
        ax2.set_ylabel("Scenario Count", labelpad=8)
        ax2.set_ylim(0, crit_total * 1.35 if crit_total > 0 else 10)
        ax2.grid(axis='y', linestyle=':', alpha=0.5)

        fig.suptitle("Comparative Evaluation: Fixed MFA vs. Risk-Adaptive Zero Trust Framework", fontsize=13, fontweight='bold')
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=300)
        plt.close(fig)
        return path

    def plot_control_strength_by_level(self, df_results: pd.DataFrame, filename: str = "control_strength_by_level.png") -> str:
        """
        Figure 5: Zero Trust control adoption frequencies across risk categories.
        """
        fig, ax = plt.subplots(figsize=(9, 5))
        tier_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

        controls_tracked = [
            'Normal Authentication',
            'Multi-Factor Authentication',
            'Trusted Device Attestation',
            'Contextual Verification',
            'Independent Out-of-Band Verification',
            'Additional Approval',
            'Block / Hold'
        ]

        matrix_data = []
        for tier in tier_order:
            sub = df_results[df_results['risk_level'] == tier]
            n_tier = len(sub)
            row_rates = []
            for ctrl in controls_tracked:
                # Check how many scenarios in this tier contain the control keyword
                count = sub['controls_list'].str.contains(ctrl.split()[0], case=False, regex=False).sum()
                rate = (count / n_tier * 100) if n_tier > 0 else 0
                row_rates.append(rate)
            matrix_data.append(row_rates)

        df_heatmap = pd.DataFrame(matrix_data, index=tier_order, columns=[
            'Basic Auth', 'MFA', 'Device Attest', 'Context Check', 'Out-of-Band', 'Dual Approval', 'Block / Hold'
        ])

        sns.heatmap(df_heatmap, annot=True, fmt=".1f", cmap="YlGnBu", cbar_kws={'label': '% Activation Rate'}, ax=ax, linewidths=0.5)
        ax.set_title("Zero Trust Control Activation Frequency by Risk Tier (%)", pad=12, fontweight='bold')
        ax.set_xlabel("Zero Trust Security Control", labelpad=8)
        ax.set_ylabel("Risk Tier", labelpad=8)

        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=300)
        plt.close(fig)
        return path

    def plot_weight_sensitivity(self, df_comparison: pd.DataFrame, filename: str = "weight_sensitivity.png") -> str:
        """
        Figure 6: Sensitivity analysis comparing risk scores across Equal, Proposed, and AHP weights.
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

        # Subplot 1: Boxplots of Risk Scores
        score_df = pd.DataFrame({
            'Equal Weights (0.20 each)': df_comparison['score_equal'],
            'Proposed Weights': df_comparison['score_prop'],
            'AHP-Derived Weights': df_comparison['score_ahp']
        })

        sns.boxplot(data=score_df, palette=['#90CAF9', '#A5D6A7', '#FFE082'], ax=ax1, width=0.45)
        ax1.set_title("Score Distribution Under Alternative Weights", fontweight='bold', pad=10)
        ax1.set_ylabel("Normalized Risk Score ($R_{100}$)", labelpad=8)
        ax1.set_ylim(0, 100)
        ax1.grid(axis='y', linestyle=':', alpha=0.5)

        # Subplot 2: Decision Stability Rate
        match_eq = df_comparison['decision_match_equal_prop'].mean() * 100
        match_ahp = df_comparison['decision_match_ahp_prop'].mean() * 100
        match_all = df_comparison['decision_match_all'].mean() * 100

        categories = ['Equal vs Proposed', 'AHP vs Proposed', 'Concordance Across All 3']
        values = [match_eq, match_ahp, match_all]

        bars = ax2.bar(categories, values, color=['#42A5F5', '#66BB6A', '#FFA726'], edgecolor='black', width=0.45)
        for b in bars:
            h = b.get_height()
            ax2.annotate(f"{h:.1f}%",
                         xy=(b.get_x() + b.get_width() / 2, h),
                         xytext=(0, 4), textcoords="offset points",
                         ha='center', va='bottom', fontweight='bold')

        ax2.set_title("Decision Stability (% Decisions Unchanged)", fontweight='bold', pad=10)
        ax2.set_ylabel("Stability Concordance (%)", labelpad=8)
        ax2.set_ylim(0, 115)
        ax2.grid(axis='y', linestyle=':', alpha=0.5)

        fig.suptitle("Sensitivity Analysis: Robustness Across Weighting Schemes", fontsize=13, fontweight='bold')
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=300)
        plt.close(fig)
        return path

    def plot_scenario_decision_matrix(self, df_results: pd.DataFrame, filename: str = "scenario_decision_matrix.png") -> str:
        """
        Figure 7: Factor inputs and authorization outcomes for key benchmark scenarios.
        """
        # Select first 10 scenarios including Scenarios 1-5
        key_scenarios = df_results.head(10).copy()

        fig, ax = plt.subplots(figsize=(10, 5))
        factor_matrix = key_scenarios[['I', 'D', 'C', 'A', 'U']].values

        sns.heatmap(factor_matrix, annot=True, cmap="Reds", vmin=0, vmax=4,
                    xticklabels=['Identity (I)', 'Device (D)', 'Context (C)', 'Action (A)', 'Uncertainty (U)'],
                    yticklabels=[f"{row['scenario_id']}: {row['scenario_name'][:30]}..." for _, row in key_scenarios.iterrows()],
                    cbar_kws={'label': 'Risk Factor Score (0 to 4)'}, ax=ax)

        ax.set_title("Benchmark Scenario Factor Matrix and Multi-Signal Profiles", pad=12, fontweight='bold')
        path = os.path.join(self.output_dir, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=300)
        plt.close(fig)
        return path

    def generate_all_figures(self, exp1_res: Dict[str, Any], exp2_res: Dict[str, Any], exp3_res: Dict[str, Any]) -> Dict[str, str]:
        """
        Renders and saves all 7 publication figures.
        """
        paths = {}
        paths['risk_distribution'] = self.plot_risk_distribution(exp1_res['df_results'])
        paths['risk_level_distribution'] = self.plot_risk_level_distribution(exp1_res['df_results'])
        paths['risk_vs_complexity'] = self.plot_risk_vs_complexity(exp1_res['df_results'])
        paths['fixed_vs_adaptive'] = self.plot_fixed_vs_adaptive(exp2_res['df_comparison'])
        paths['control_strength_by_level'] = self.plot_control_strength_by_level(exp1_res['df_results'])
        paths['weight_sensitivity'] = self.plot_weight_sensitivity(exp3_res['df_comparison'])
        paths['scenario_decision_matrix'] = self.plot_scenario_decision_matrix(exp1_res['df_results'])
        return paths
