"""
Supplementary Dataset Loader.

Loads and maps the 5,000 synthetic enterprise identity attack scenario dataset.

IMPORTANT ACADEMIC DISCLAIMER:
This dataset is a SYNTHETIC SCENARIO DATASET designed to stress-test simulation scaling.
It MUST NOT be described as a real-world enterprise telemetry benchmark or genuine
ASVspoof/DFDC/Celeb-DF raw recording dataset. The PRIMARY evaluation of this research
relies on the 45 curated, auditable scenarios in scenarios.csv.
"""

import os
from typing import Dict, Any, Optional
import pandas as pd


DATASET_DISCLAIMER = (
    "SYNTHETIC SCENARIO DATASET NOTICE: This dataset contains 5,000 programmatically generated "
    "enterprise scenarios used exclusively for supplementary sensitivity and scale testing. "
    "It does not represent real-world enterprise traffic, and labels do not imply testing on raw "
    "acoustic/visual biometric sensor streams."
)


def load_supplementary_dataset(csv_path: str = "data/deepfake_identity_attack_dataset_v1.csv", limit: Optional[int] = None) -> pd.DataFrame:
    """
    Loads the synthetic dataset and maps its 0-100 scaled risk columns to the
    framework's standard 0-4 factor scale.

    Mapping:
      I = (I_identity_risk / 100.0) * 4.0
      D = (D_device_risk / 100.0) * 4.0
      C = (C_context_anomaly / 100.0) * 4.0
      A = (A_action_criticality / 100.0) * 4.0
      U = (U_identity_uncertainty / 100.0) * 4.0
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Supplementary dataset file not found at: {csv_path}")

    df = pd.read_csv(csv_path)
    if limit is not None and limit > 0:
        df = df.head(limit).copy()

    # Map original columns to standard 0-4 scale
    df['I'] = (df['I_identity_risk'] / 25.0).clip(0.0, 4.0)
    df['D'] = (df['D_device_risk'] / 25.0).clip(0.0, 4.0)
    df['C'] = (df['C_context_anomaly'] / 25.0).clip(0.0, 4.0)
    df['A'] = (df['A_action_criticality'] / 25.0).clip(0.0, 4.0)
    df['U'] = (df['U_identity_uncertainty'] / 25.0).clip(0.0, 4.0)

    # Standardize column naming
    df['scenario_id'] = df['record_id']
    df['scenario_name'] = df['attack_type'].astype(str) + " targeting " + df['requested_action'].astype(str)
    df['is_synthetic_supplementary'] = True

    return df
