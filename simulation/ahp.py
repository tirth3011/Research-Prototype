"""
Analytic Hierarchy Process (AHP) Weight Derivation Module.

Implements Saaty's Analytic Hierarchy Process to compute internally consistent
risk factor weights from pairwise comparison judgments across:
  [Identity Risk (I), Device Risk (D), Context Anomaly (C), Action Criticality (A), Deepfake Uncertainty (U)]

IMPORTANT RESEARCH WORDING:
AHP provides expert-informed and internally consistent weights based on explicit
pairwise judgment. It does NOT prove that the resulting weights are universally or
empirically correct for all organizations.
"""

from typing import Dict, List, Tuple, Any, Optional
import numpy as np

CRITERIA = ['I', 'D', 'C', 'A', 'U']
CRITERIA_NAMES = {
    'I': 'Identity Risk',
    'D': 'Device Risk',
    'C': 'Context Anomaly',
    'A': 'Action Criticality',
    'U': 'Deepfake Uncertainty'
}

# Standard Saaty Random Index (RI) table for matrix sizes n=1 to 10
RANDOM_INDEX = {
    1: 0.00,
    2: 0.00,
    3: 0.58,
    4: 0.90,
    5: 1.12,
    6: 1.24,
    7: 1.32,
    8: 1.41,
    9: 1.45,
    10: 1.49
}

# Default pairwise comparison matrix reflecting cybersecurity domain expertise:
# Action Criticality (A) and Identity Integrity (I) are prioritized over peripheral signals.
# Matrix order: [I, D, C, A, U]
DEFAULT_PAIRWISE_MATRIX = np.array([
    #  I       D       C       A       U
    [1.000,  1.667,  1.667,  0.833,  1.667],  # I (Identity Risk)
    [0.600,  1.000,  1.000,  0.500,  1.000],  # D (Device Risk)
    [0.600,  1.000,  1.000,  0.500,  1.000],  # C (Context Anomaly)
    [1.200,  2.000,  2.000,  1.000,  2.000],  # A (Action Criticality)
    [0.600,  1.000,  1.000,  0.500,  1.000],  # U (Deepfake Uncertainty)
], dtype=float)


class AHPModel:
    """
    Analytic Hierarchy Process solver for Zero Trust risk factors.
    """

    def __init__(self, criteria: Optional[List[str]] = None, matrix: Optional[np.ndarray] = None):
        self.criteria = criteria or CRITERIA
        self.n = len(self.criteria)
        self.matrix = matrix if matrix is not None else DEFAULT_PAIRWISE_MATRIX.copy()
        self._validate_matrix()

    def _validate_matrix(self) -> None:
        """Verify matrix dimensions and reciprocal properties."""
        if self.matrix.shape != (self.n, self.n):
            raise ValueError(f"Matrix shape must be ({self.n}, {self.n}), got {self.matrix.shape}")
        for i in range(self.n):
            if abs(self.matrix[i, i] - 1.0) > 1e-4:
                raise ValueError(f"Diagonal element [{i},{i}] must be 1.0, got {self.matrix[i, i]}")

    def set_pairwise_comparison(self, criterion_1: str, criterion_2: str, value: float) -> None:
        """
        Set pairwise relative importance of criterion_1 over criterion_2.
        Automatically updates reciprocal element.
        """
        i = self.criteria.index(criterion_1)
        j = self.criteria.index(criterion_2)
        if value <= 0:
            raise ValueError("Comparison values must be positive non-zero numbers.")
        self.matrix[i, j] = float(value)
        self.matrix[j, i] = 1.0 / float(value)

    def compute_weights_eigenvector(self) -> Tuple[np.ndarray, float]:
        """
        Compute priority weights using principal eigenvector method (Saaty's exact formulation).
        Returns: (priority_weights_array, lambda_max)
        """
        eigenvalues, eigenvectors = np.linalg.eig(self.matrix)
        # Find index of the maximum real eigenvalue
        max_idx = np.argmax(np.real(eigenvalues))
        lambda_max = float(np.real(eigenvalues[max_idx]))
        principal_vector = np.real(eigenvectors[:, max_idx])

        # Normalize to sum to 1
        weights = principal_vector / np.sum(principal_vector)
        # Ensure positive weights (eigenvectors may have inverted sign)
        if np.any(weights < 0):
            weights = -weights
            weights = weights / np.sum(weights)

        return weights, lambda_max

    def compute_weights_geometric_mean(self) -> Tuple[np.ndarray, float]:
        """
        Compute priority weights using normalized geometric mean (common robust approximation).
        Returns: (priority_weights_array, lambda_max)
        """
        geo_means = np.prod(self.matrix, axis=1) ** (1.0 / self.n)
        weights = geo_means / np.sum(geo_means)

        # Estimate lambda_max from (A * w) / w
        aw = np.dot(self.matrix, weights)
        lambda_max = float(np.mean(aw / weights))
        return weights, lambda_max

    def evaluate_consistency(self, lambda_max: float) -> Dict[str, Any]:
        """
        Calculate Consistency Index (CI) and Consistency Ratio (CR).
        CI = (lambda_max - n) / (n - 1)
        CR = CI / RI
        """
        ci = (lambda_max - self.n) / (self.n - 1) if self.n > 1 else 0.0
        # Guard against minor floating point negative
        ci = max(0.0, ci)
        ri = RANDOM_INDEX.get(self.n, 1.12)
        cr = ci / ri if ri > 0 else 0.0

        is_consistent = cr <= 0.10

        return {
            'n': self.n,
            'lambda_max': round(lambda_max, 4),
            'ci': round(ci, 4),
            'ri': ri,
            'cr': round(cr, 4),
            'is_consistent': is_consistent,
            'consistency_assessment': (
                "CONSISTENT (CR <= 0.10): Judgments exhibit satisfactory transitivity."
                if is_consistent else
                "INCONSISTENT (CR > 0.10): Pairwise judgments conflict significantly; review suggested."
            )
        }

    def get_results(self, method: str = 'eigenvector') -> Dict[str, Any]:
        """
        Run complete AHP evaluation and return structured dictionary.
        """
        if method == 'eigenvector':
            weights_arr, lambda_max = self.compute_weights_eigenvector()
        else:
            weights_arr, lambda_max = self.compute_weights_geometric_mean()

        weights_dict = {self.criteria[i]: round(float(weights_arr[i]), 4) for i in range(self.n)}
        # Re-normalize to exactly 1.0
        tot = sum(weights_dict.values())
        weights_dict = {k: round(v / tot, 4) for k, v in weights_dict.items()}

        consistency = self.evaluate_consistency(lambda_max)

        return {
            'method': method,
            'criteria': self.criteria,
            'criteria_names': [CRITERIA_NAMES.get(c, c) for c in self.criteria],
            'pairwise_matrix': self.matrix.tolist(),
            'weights': weights_dict,
            'consistency': consistency,
            'research_note': (
                "AHP provides expert-informed and internally consistent weights based on explicit "
                "pairwise judgments. It does NOT prove that these weights are universally or empirically correct."
            )
        }

    def sensitivity_perturbation(self, target_criterion: str, delta: float) -> Dict[str, float]:
        """
        Perform one-at-a-time sensitivity analysis by perturbing the relative weight
        of target_criterion by delta, then re-normalizing the rest.
        """
        base_results = self.get_results()
        base_weights = base_results['weights'].copy()

        old_val = base_weights[target_criterion]
        new_val = max(0.01, min(0.90, old_val + delta))
        base_weights[target_criterion] = new_val

        # Proportionately scale other weights
        other_sum = sum(v for k, v in base_weights.items() if k != target_criterion)
        remaining_budget = 1.0 - new_val

        perturbed = {}
        for k, v in base_weights.items():
            if k == target_criterion:
                perturbed[k] = round(new_val, 4)
            else:
                perturbed[k] = round((v / other_sum) * remaining_budget, 4)

        return perturbed
