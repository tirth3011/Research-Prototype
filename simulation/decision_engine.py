"""
Zero Trust Decision Engine.

Translates multi-signal risk evaluations into adaptive Zero Trust controls,
authentication complexity scores, and final authorization decisions.

Key Research Distinction:
  - Authentication (AuthN): Verifying claimed identity (passwords, MFA, biometrics).
  - Authorization (AuthZ): Deciding whether the specific action should be permitted,
    conditional on multi-signal risk, device posture, and out-of-band verification.
    Passing MFA does NOT guarantee access if context/device is compromised or action is critical!
"""

from typing import Dict, Any, List, Optional
from simulation.risk_engine import RiskEngine


# Standard Control Definitions
CONTROL_NORMAL_AUTH = "Normal Authentication (SSO / Standard Credential)"
CONTROL_MFA = "Multi-Factor Authentication (OTP / FIDO2 Step-up)"
CONTROL_TRUSTED_DEVICE = "Trusted Device Attestation (MDM / EDR Compliance)"
CONTROL_CONTEXT_VERIFY = "Contextual Verification (IP / Geo / Behavioral Anomaly Check)"
CONTROL_INDEPENDENT_VERIFY = "Independent Out-of-Band Verification (Direct Callback / Secure Line)"
CONTROL_ADDITIONAL_APPROVAL = "Secondary / Dual-Custody Executive Approval"
CONTROL_BLOCK_HOLD = "Block / Hold Request (Session Quarantined)"

# Possible Final Decision States
DECISION_ALLOW = "ALLOW"
DECISION_MFA_REQUIRED = "MFA_REQUIRED"
DECISION_STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
DECISION_APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
DECISION_INDEPENDENT_VERIFICATION = "INDEPENDENT_VERIFICATION"
DECISION_BLOCK_HOLD = "BLOCK/HOLD"


class DecisionEngine:
    """
    Implements Risk-Adaptive Zero Trust decision rules.
    """

    def __init__(self, risk_engine: Optional[RiskEngine] = None):
        self.risk_engine = risk_engine or RiskEngine()

    def evaluate_request(
        self,
        factors: Dict[str, float],
        weights: Optional[Dict[str, float]] = None,
        auth_status: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Evaluate an enterprise identity request.

        Parameters:
          factors: dict with 'I', 'D', 'C', 'A', 'U' (each 0 to 4)
          weights: optional custom weights
          auth_status: optional simulated outcomes:
              {'mfa': 'PASS'|'FAIL'|'PENDING',
               'device_attestation': 'PASS'|'FAIL'|'PENDING',
               'oob_verification': 'PASS'|'FAIL'|'PENDING'}

        Returns:
          Dictionary with risk details, controls, auth complexity, and final decision.
        """
        risk_result = self.risk_engine.evaluate(factors, weights)
        norm_risk = risk_result['normalized_risk']
        risk_level = risk_result['risk_level']

        I = float(factors['I'])
        D = float(factors['D'])
        C = float(factors['C'])
        A = float(factors['A'])
        U = float(factors['U'])

        controls: List[str] = []
        auth_complexity: int = 1
        decision: str = DECISION_ALLOW
        decision_rationale: str = ""

        # Step 1: Assign Baseline Controls and Complexity by Risk Tier
        if risk_level == "LOW":
            controls = [CONTROL_NORMAL_AUTH]
            auth_complexity = 1
            decision = DECISION_ALLOW
            decision_rationale = "Low composite risk (0-25). Standard credentials sufficient."

        elif risk_level == "MEDIUM":
            controls = [CONTROL_NORMAL_AUTH, CONTROL_MFA]
            auth_complexity = 2
            decision = DECISION_MFA_REQUIRED
            decision_rationale = "Moderate risk (26-50). Step-up MFA challenge required to proceed."

        elif risk_level == "HIGH":
            controls = [
                CONTROL_NORMAL_AUTH,
                CONTROL_MFA,
                CONTROL_TRUSTED_DEVICE,
                CONTROL_CONTEXT_VERIFY
            ]
            auth_complexity = 3
            if A >= 3.0:
                controls.append(CONTROL_ADDITIONAL_APPROVAL)
                auth_complexity = 4
                decision = DECISION_APPROVAL_REQUIRED
                decision_rationale = (
                    "High risk (51-75) with privileged/sensitive action (A >= 3). "
                    "Requires MFA, device attestation, contextual sanity check, and managerial approval."
                )
            else:
                decision = DECISION_STEP_UP_REQUIRED
                decision_rationale = (
                    "High risk (51-75). Requires MFA, trusted-device verification, and contextual verification."
                )

        else:  # CRITICAL (76 - 100)
            controls = [
                CONTROL_NORMAL_AUTH,
                CONTROL_MFA,
                CONTROL_TRUSTED_DEVICE,
                CONTROL_INDEPENDENT_VERIFY,
                CONTROL_ADDITIONAL_APPROVAL,
                CONTROL_BLOCK_HOLD
            ]
            auth_complexity = 5
            decision = DECISION_INDEPENDENT_VERIFICATION
            decision_rationale = (
                "Critical risk (>75). Automatic hold placed. Strict out-of-band verification via direct "
                "independent corporate telephone directory and dual executive sign-off required."
            )

        # Step 2: Critical Zero Trust Authentication vs Authorization Enforcement
        # Specific research rule:
        # If an attacker passes MFA, but Device is suspicious (D >= 3), Action is critical (A >= 3),
        # and Deepfake Uncertainty is high (U >= 3), the request MUST NOT be authorized automatically!
        if D >= 3.0 and A >= 3.0 and U >= 3.0:
            if CONTROL_INDEPENDENT_VERIFY not in controls:
                controls.append(CONTROL_INDEPENDENT_VERIFY)
            if CONTROL_BLOCK_HOLD not in controls:
                controls.append(CONTROL_BLOCK_HOLD)
            auth_complexity = max(auth_complexity, 5)

            if auth_status and auth_status.get('oob_verification') == 'FAIL':
                decision = DECISION_BLOCK_HOLD
                decision_rationale = (
                    "BLOCKED/HELD: Independent out-of-band verification failed for high-criticality action "
                    "from suspicious device and flagged deepfake indicators."
                )
            elif auth_status and auth_status.get('mfa') == 'PASS' and auth_status.get('oob_verification') != 'PASS':
                # Key research distinction: MFA passed, but Authorization denied pending out-of-band confirmation
                decision = DECISION_INDEPENDENT_VERIFICATION
                decision_rationale = (
                    "HOLD (AuthN passed, AuthZ pending): MFA passed successfully, but authorization is held. "
                    "Suspicious device (D>=3), critical action (A>=3), and synthetic media indicators (U>=3) "
                    "mandate mandatory out-of-band verification."
                )
            else:
                decision = DECISION_INDEPENDENT_VERIFICATION
                decision_rationale = (
                    "CRITICAL ATTACK POSTURE: High-impact action requested from unmanaged/suspicious device "
                    "with high deepfake uncertainty. Standard MFA bypassed or insufficient; requires out-of-band confirmation."
                )

        # Step 3: Handle Simulated Auth Status (if provided)
        if auth_status:
            if auth_status.get('mfa') == 'FAIL':
                decision = DECISION_BLOCK_HOLD
                decision_rationale += " [MFA Challenge Failed -> Request Blocked]"
            elif auth_status.get('device_attestation') == 'FAIL' and risk_level in ["HIGH", "CRITICAL"]:
                decision = DECISION_BLOCK_HOLD
                decision_rationale += " [Device Attestation Failed -> Access Quarantined]"
            elif auth_status.get('oob_verification') == 'FAIL':
                decision = DECISION_BLOCK_HOLD
                decision_rationale += " [Independent Out-of-Band Verification Failed -> Threat Quarantined]"
            elif (auth_status.get('mfa') == 'PASS' and
                  (auth_status.get('device_attestation') in ['PASS', None]) and
                  (auth_status.get('oob_verification') == 'PASS' or risk_level != "CRITICAL") and
                  decision != DECISION_BLOCK_HOLD):
                # When all required controls are satisfied
                if risk_level == "LOW":
                    decision = DECISION_ALLOW
                elif risk_level in ["MEDIUM", "HIGH"] and auth_status.get('mfa') == 'PASS':
                    decision = DECISION_ALLOW
                    decision_rationale += " [Step-up controls satisfied -> Access Authorized]"
                elif risk_level == "CRITICAL" and auth_status.get('oob_verification') == 'PASS':
                    decision = DECISION_ALLOW
                    decision_rationale += " [Out-of-band verification confirmed authentic -> Access Authorized]"

        return {
            **risk_result,
            'controls': controls,
            'auth_complexity': auth_complexity,
            'decision': decision,
            'decision_rationale': decision_rationale,
            'complexity_definition': (
                f"Complexity Score = {auth_complexity} / 5 (Number of sequential verification hurdles: "
                "1=Password/SSO, 2=+MFA, 3=+Device Attestation, 4=+Context/Approval, 5=+Out-of-Band Callback/Dual-Auth)"
            )
        }
