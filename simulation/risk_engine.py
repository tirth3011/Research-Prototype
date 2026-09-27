"""
Risk Engine for Risk-Adaptive Zero Trust Architecture (ZTA).

Calculates multi-signal risk based on:
  - Identity Risk (I): 0 to 4
  - Device Risk (D): 0 to 4
  - Context Anomaly (C): 0 to 4
  - Action Criticality (A): 0 to 4
  - Deepfake/Identity Uncertainty (U): 0 to 4

Formula:
  R = w_I * I + w_D * D + w_C * C + w_A * A + w_U * U   (0 to 4)
  R_100 = (R / 4) * 100                                (0 to 100)

Risk Tiers:
  LOW:      0 - 25
  MEDIUM:  26 - 50
  HIGH:    51 - 75
  CRITICAL: 76 - 100
"""

from typing import Dict, Any, Tuple
import numpy as np

# Default Proposed Weights (Research Starting Point - Not scientifically absolute)
PROPOSED_WEIGHTS: Dict[str, float] = {
    'I': 0.25,  # Identity Risk
    'D': 0.15,  # Device Risk
    'C': 0.15,  # Context Anomaly
    'A': 0.30,  # Action Criticality (Highest weight due to asset impact)
    'U': 0.15   # Deepfake / Identity Uncertainty
}

EQUAL_WEIGHTS: Dict[str, float] = {
    'I': 0.20,
    'D': 0.20,
    'C': 0.20,
    'A': 0.20,
    'U': 0.20
}

FACTOR_LABELS = {
    'I': 'Identity Risk (I)',
    'D': 'Device Risk (D)',
    'C': 'Context Anomaly (C)',
    'A': 'Action Criticality (A)',
    'U': 'Deepfake Uncertainty (U)'
}

FACTOR_DESCRIPTIONS = {
    'I': {
        0: 'Verified Identity / Clean History',
        1: 'Low Identity Anomaly / Standard User',
        2: 'Moderate Identity Mismatch / Unverified Claim',
        3: 'High Identity Suspicion / Failed Verification',
        4: 'Severe Identity Compromise / Confirmed Mismatch'
    },
    'D': {
        0: 'Managed Corporate Device (Compliant & Enrolled)',
        1: 'Known Personal Device (Registered BYOD)',
        2: 'New / Unrecognized Device (First-time access)',
        3: 'Unmanaged / Non-Compliant Device',
        4: 'Compromised / Highly Suspicious Device / Rooted'
    },
    'C': {
        0: 'Normal Geographic Location, Business Hours & Subnet',
        1: 'Slightly Unusual Working Hours or IP Subnet',
        2: 'Unusual Geo-location / High-Risk Hosting Provider',
        3: 'Suspicious Network / Anonymous VPN / Tor Exit Node',
        4: 'Impossible Travel / Multiple Concurrent Anomaly Indicators'
    },
    'A': {
        0: 'Public / Very Low-Impact Information (Intranet directory)',
        1: 'Standard Internal Data / Routine Operational Access',
        2: 'Confidential Enterprise Data / Source Code / IP',
        3: 'Privileged Operation / Sensitive Account Credential Mod',
        4: 'Financial Wire Transfer / Critical Infrastructure Admin'
    },
    'U': {
        0: 'Strongly Verified Authentic (Hardware token / Biometric match)',
        1: 'Minor Media Anomaly / Slight Audio-Video Artifacts',
        2: 'Uncertain Media Authenticity / Inconclusive Liveness',
        3: 'Strong Manipulation Indicators (Deepfake voice/video signature)',
        4: 'Multiple Severe Manipulation Indicators / Flagged Synthetic Media'
    }
}


class RiskEngine:
    """
    Mathematical calculation engine for the Risk-Adaptive Zero Trust Framework.
    Supports dynamic weight modification (Proposed, Equal, AHP-derived).
    """

    def __init__(self, weights: Dict[str, float] = None):
        self.weights = self._normalize_weights(weights or PROPOSED_WEIGHTS)

    @staticmethod
    def _normalize_weights(weights: Dict[str, float]) -> Dict[str, float]:
        """Ensures weights sum to 1.0."""
        total = sum(weights.values())
        if abs(total - 1.0) > 1e-6:
            return {k: v / total for k, v in weights.items()}
        return dict(weights)

    def set_weights(self, weights: Dict[str, float]) -> None:
        """Update active weighting scheme."""
        self.weights = self._normalize_weights(weights)

    def calculate_raw_risk(self, factors: Dict[str, float], weights: Dict[str, float] = None) -> float:
        """
        Calculate raw composite risk R = sum(w_k * factor_k).
        Factors must be in range [0, 4].
        """
        w = weights or self.weights
        raw_r = sum(w[k] * float(factors[k]) for k in ['I', 'D', 'C', 'A', 'U'])
        return round(float(raw_r), 4)

    @staticmethod
    def calculate_normalized_risk(raw_risk: float) -> float:
        """
        Normalize R (0 to 4) into R100 (0 to 100).
        R100 = (R / 4) * 100
        """
        norm_r = (raw_risk / 4.0) * 100.0
        return round(float(norm_r), 2)

    @staticmethod
    def get_risk_level(normalized_risk: float) -> str:
        """
        Map normalized risk score to categorical Zero Trust risk tiers.
        LOW:      0 - 25
        MEDIUM:  26 - 50 (or >25 and <= 50)
        HIGH:    51 - 75 (or >50 and <= 75)
        CRITICAL: 76 - 100 (or >75)
        """
        if normalized_risk <= 25.0:
            return "LOW"
        elif normalized_risk <= 50.0:
            return "MEDIUM"
        elif normalized_risk <= 75.0:
            return "HIGH"
        else:
            return "CRITICAL"

    def get_factor_contributions(self, factors: Dict[str, float], weights: Dict[str, float] = None) -> Dict[str, Dict[str, float]]:
        """
        Provides transparent factor breakdown:
          - factor_score (0-4)
          - weight
          - raw_contribution (w_k * score)
          - normalized_contribution_points (out of 100)
          - percentage_of_total_risk (% share)
        """
        w = weights or self.weights
        raw_risk = self.calculate_raw_risk(factors, w)
        breakdown = {}

        for k in ['I', 'D', 'C', 'A', 'U']:
            score = float(factors[k])
            raw_contrib = w[k] * score
            norm_contrib = (raw_contrib / 4.0) * 100.0
            pct_share = (raw_contrib / raw_risk * 100.0) if raw_risk > 0 else 0.0

            breakdown[k] = {
                'label': FACTOR_LABELS[k],
                'score': score,
                'weight': round(w[k], 4),
                'raw_contribution': round(raw_contrib, 4),
                'norm_contribution_points': round(norm_contrib, 2),
                'percentage_of_total_risk': round(pct_share, 2),
                'description': FACTOR_DESCRIPTIONS[k].get(int(round(score)), 'N/A')
            }

        return breakdown

    def evaluate(self, factors: Dict[str, float], weights: Dict[str, float] = None) -> Dict[str, Any]:
        """
        Full evaluation pipeline for a set of factor inputs.
        """
        w = weights or self.weights
        raw_risk = self.calculate_raw_risk(factors, w)
        norm_risk = self.calculate_normalized_risk(raw_risk)
        risk_level = self.get_risk_level(norm_risk)
        contributions = self.get_factor_contributions(factors, w)

        return {
            'factors': factors,
            'weights': w,
            'raw_risk': raw_risk,
            'normalized_risk': norm_risk,
            'risk_level': risk_level,
            'contributions': contributions
        }
