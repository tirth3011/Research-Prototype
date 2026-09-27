"""
Interactive Web Application: Risk-Adaptive Zero Trust Framework Prototype.

Research Prototype:
"A Risk-Adaptive Zero Trust Framework for Mitigating Deepfake-Based Identity Attacks in Enterprise Environments"

Features:
  - 1-Click Benchmark Quick-Launchers (Scenarios 1 to 5)
  - Interactive Multi-Signal Sliders (I, D, C, A, U)
  - Live Radial Risk Speedometer Gauge
  - Multi-Signal 5-Axis Radar Attack Polygon
  - 5-Barrier Zero Trust Access Pipeline Visualization
  - Interactive AuthN vs AuthZ Simulation Playground
  - Side-by-Side Deepfake Action Criticality Contrast (SCN-04 vs SCN-05)
  - Interactive AHP Matrix Workshop with Live Consistency Ratio
  - What-If Sensitivity Trajectory Simulator
  - Searchable Scenario Dataset Explorer with 1-Click Simulator Loading
"""

import os
import sys
import math
import pandas as pd
import numpy as np
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

# Ensure simulation package is accessible
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from simulation.risk_engine import RiskEngine, PROPOSED_WEIGHTS, EQUAL_WEIGHTS, FACTOR_LABELS, FACTOR_DESCRIPTIONS
from simulation.decision_engine import DecisionEngine, CONTROL_NORMAL_AUTH, CONTROL_MFA, CONTROL_TRUSTED_DEVICE, CONTROL_CONTEXT_VERIFY, CONTROL_INDEPENDENT_VERIFY, CONTROL_ADDITIONAL_APPROVAL, CONTROL_BLOCK_HOLD
from simulation.ahp import AHPModel, DEFAULT_PAIRWISE_MATRIX, CRITERIA
from simulation.experiments import ExperimentRunner
from simulation.metrics import MetricsCalculator
from simulation.supplementary_loader import load_supplementary_dataset, DATASET_DISCLAIMER

# Configure Page
st.set_page_config(
    page_title="Zero Trust Risk-Adaptive Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced Modern Dark/Glassmorphic Styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap');

    .stApp {
        background-color: #0b0f19;
        font-family: 'Inter', sans-serif;
    }
    .main-title {
        font-size: 2.1rem;
        font-weight: 800;
        background: linear-gradient(135deg, #38bdf8 0%, #818cf8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        font-size: 0.95rem;
        color: #94a3b8;
        margin-bottom: 1.2rem;
    }
    .glass-card {
        background: rgba(19, 28, 46, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 18px;
        box-shadow: 0 8px 24px rgba(0,0,0,0.35);
        backdrop-filter: blur(10px);
        margin-bottom: 16px;
    }
    .preset-btn-container {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        margin-bottom: 16px;
    }
    .badge {
        display: inline-block;
        padding: 6px 14px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.95rem;
        text-align: center;
        letter-spacing: 0.5px;
    }
    .badge-low {
        background: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid #10b981;
    }
    .badge-medium {
        background: rgba(245, 158, 11, 0.15);
        color: #fbbf24;
        border: 1px solid #f59e0b;
    }
    .badge-high {
        background: rgba(249, 115, 22, 0.15);
        color: #fb923c;
        border: 1px solid #f97316;
    }
    .badge-critical {
        background: rgba(239, 68, 68, 0.2);
        color: #f87171;
        border: 1px solid #ef4444;
        box-shadow: 0 0 12px rgba(239, 68, 68, 0.3);
    }
    .pipeline-step {
        display: flex;
        align-items: center;
        padding: 10px 14px;
        border-radius: 8px;
        margin-bottom: 8px;
        font-size: 0.88rem;
        font-weight: 500;
        transition: all 0.2s ease;
    }
    .pipeline-active {
        background: rgba(56, 189, 248, 0.12);
        border-left: 4px solid #38bdf8;
        color: #f8fafc;
    }
    .pipeline-critical {
        background: rgba(239, 68, 68, 0.15);
        border-left: 4px solid #ef4444;
        color: #fca5a5;
        font-weight: 600;
    }
    .pipeline-inactive {
        background: rgba(255, 255, 255, 0.02);
        border-left: 4px solid #334155;
        color: #64748b;
        opacity: 0.6;
    }
    .stat-label {
        font-size: 0.75rem;
        color: #94a3b8;
        text-transform: uppercase;
        font-weight: 600;
        letter-spacing: 0.5px;
    }
    .stat-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.6rem;
        font-weight: 700;
        color: #38bdf8;
    }
    .notice-box {
        background: rgba(56, 189, 248, 0.06);
        border-left: 4px solid #38bdf8;
        border-radius: 4px;
        padding: 10px 14px;
        font-size: 0.85rem;
        color: #cbd5e1;
        margin-bottom: 14px;
    }
    .comparison-card {
        background: rgba(15, 23, 42, 0.8);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 10px;
        padding: 16px;
    }
    @media (max-width: 768px) {
        .main-title { font-size: 1.45rem !important; }
        .sub-title { font-size: 0.82rem !important; }
        .glass-card { padding: 12px 10px !important; }
        .stat-value { font-size: 1.3rem !important; }
        .pipeline-step { font-size: 0.78rem !important; padding: 7px 10px !important; }
    }
</style>
""", unsafe_allow_html=True)


# ==============================================================================
# DATA LOADERS & SESSION STATE INITIALIZATION
# ==============================================================================
@st.cache_data
def get_scenarios_df():
    return pd.read_csv("simulation/scenarios.csv")

df_scenarios = get_scenarios_df()

# Session State for scenario factors
if 'I_val' not in st.session_state:
    st.session_state.I_val = 0.0
if 'D_val' not in st.session_state:
    st.session_state.D_val = 0.0
if 'C_val' not in st.session_state:
    st.session_state.C_val = 0.0
if 'A_val' not in st.session_state:
    st.session_state.A_val = 1.0
if 'U_val' not in st.session_state:
    st.session_state.U_val = 0.0
if 'scen_name' not in st.session_state:
    st.session_state.scen_name = "Normal Employee Routine Internal Access"
if 'scen_desc' not in st.session_state:
    st.session_state.scen_desc = "Normal employee accessing low-impact internal resource from corporate laptop during office hours"
if 'active_weights' not in st.session_state:
    st.session_state.active_weights = PROPOSED_WEIGHTS.copy()
if 'auth_sim_mfa' not in st.session_state:
    st.session_state.auth_sim_mfa = "PASS"
if 'auth_sim_device' not in st.session_state:
    st.session_state.auth_sim_device = "PASS"
if 'auth_sim_oob' not in st.session_state:
    st.session_state.auth_sim_oob = "PENDING"


def apply_scenario(scen_id: str):
    """Callback to load a specific scenario into session state."""
    row = df_scenarios[df_scenarios['scenario_id'] == scen_id].iloc[0]
    st.session_state.I_val = float(row['I'])
    st.session_state.D_val = float(row['D'])
    st.session_state.C_val = float(row['C'])
    st.session_state.A_val = float(row['A'])
    st.session_state.U_val = float(row['U'])
    st.session_state.scen_name = row['scenario_name']
    st.session_state.scen_desc = row['description']


# ==============================================================================
# HELPER: PLOTLY INTERACTIVE GAUGE & RADAR CHARTS
# ==============================================================================
def render_plotly_gauge(norm_score: float, raw_score: float, risk_tier: str):
    """Interactive Plotly radial speedometer."""
    color_map = {
        'LOW': '#10b981',
        'MEDIUM': '#f59e0b',
        'HIGH': '#f97316',
        'CRITICAL': '#ef4444'
    }
    bar_color = color_map.get(risk_tier, '#38bdf8')
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=norm_score,
        number={'suffix': " / 100", 'font': {'size': 24, 'color': '#f8fafc', 'family': 'JetBrains Mono'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': '#64748b', 'nticks': 5},
            'bar': {'color': bar_color, 'thickness': 0.3},
            'bgcolor': '#0f172a',
            'borderwidth': 1,
            'bordercolor': '#1e293b',
            'steps': [
                {'range': [0, 25], 'color': 'rgba(16, 185, 129, 0.25)'},
                {'range': [25, 50], 'color': 'rgba(245, 158, 11, 0.25)'},
                {'range': [50, 75], 'color': 'rgba(249, 115, 22, 0.25)'},
                {'range': [75, 100], 'color': 'rgba(239, 68, 68, 0.35)'}
            ]
        }
    ))
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font={'color': '#94a3b8', 'family': 'Inter'},
        margin=dict(l=15, r=15, t=25, b=5),
        height=165
    )
    return fig


def render_plotly_radar(I: float, D: float, C: float, A: float, U: float):
    """Interactive Plotly 5-axis attack profile radar polygon."""
    categories = ['Identity (I)', 'Device (D)', 'Context (C)', 'Action (A)', 'Uncertainty (U)', 'Identity (I)']
    values = [I, D, C, A, U, I]
    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=values,
        theta=categories,
        fill='toself',
        fillcolor='rgba(56, 189, 248, 0.3)',
        line=dict(color='#38bdf8', width=2.5),
        marker=dict(size=7, color='#38bdf8')
    ))
    fig.update_layout(
        polar=dict(
            radialaxis=dict(visible=True, range=[0, 4], tickfont=dict(color='#64748b', size=9), gridcolor='#1e293b', linecolor='#334155'),
            angularaxis=dict(tickfont=dict(color='#cbd5e1', size=10, family='Inter'), gridcolor='#1e293b', linecolor='#334155'),
            bgcolor='rgba(15, 23, 42, 0.5)'
        ),
        paper_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=25, r=25, t=20, b=20),
        height=190,
        showlegend=False
    )
    return fig


# ==============================================================================
# HELPER: RADIAL SPEEDOMETER GAUGE (SVG)
# ==============================================================================
def render_speedometer_gauge(norm_score: float, raw_score: float, risk_tier: str) -> str:
    """
    Renders an interactive high-contrast SVG semi-circular gauge.
    """
    # Angle calculation: sweeps from 180 deg (left, 0) clockwise across top to 0 deg (right, 100)
    angle_rad = math.radians(180.0 - (norm_score / 100.0) * 180.0)

    # Needle pointer endpoint (radius = 65)
    cx, cy = 150, 130
    nx = cx + 65 * math.cos(angle_rad)
    ny = cy - 65 * math.sin(angle_rad)

    color_map = {
        'LOW': '#10b981',
        'MEDIUM': '#f59e0b',
        'HIGH': '#f97316',
        'CRITICAL': '#ef4444'
    }
    needle_color = color_map.get(risk_tier, '#38bdf8')

    svg = f"""
    <div style="text-align: center;">
      <svg width="280" height="160" viewBox="0 0 300 160">
        <!-- Background Track -->
        <path d="M 40 130 A 110 110 0 0 1 260 130" fill="none" stroke="#1e293b" stroke-width="22" stroke-linecap="round"/>
        
        <!-- Arc Segments -->
        <!-- Green: Low (0-25) -->
        <path d="M 40 130 A 110 110 0 0 1 72 52" fill="none" stroke="#10b981" stroke-width="16" opacity="0.85"/>
        <!-- Yellow: Medium (25-50) -->
        <path d="M 72 52 A 110 110 0 0 1 150 20" fill="none" stroke="#f59e0b" stroke-width="16" opacity="0.85"/>
        <!-- Orange: High (50-75) -->
        <path d="M 150 20 A 110 110 0 0 1 228 52" fill="none" stroke="#f97316" stroke-width="16" opacity="0.85"/>
        <!-- Red: Critical (75-100) -->
        <path d="M 228 52 A 110 110 0 0 1 260 130" fill="none" stroke="#ef4444" stroke-width="16" opacity="0.85"/>

        <!-- Ticks -->
        <text x="32" y="148" fill="#64748b" font-size="11" font-weight="600">0</text>
        <text x="65" y="44" fill="#64748b" font-size="11" font-weight="600">25</text>
        <text x="143" y="14" fill="#64748b" font-size="11" font-weight="600">50</text>
        <text x="225" y="44" fill="#64748b" font-size="11" font-weight="600">75</text>
        <text x="256" y="148" fill="#64748b" font-size="11" font-weight="600">100</text>

        <!-- Needle -->
        <line x1="{cx}" y1="{cy}" x2="{nx:.1f}" y2="{ny:.1f}" stroke="{needle_color}" stroke-width="4.5" stroke-linecap="round"/>
        <circle cx="{cx}" cy="{cy}" r="7" fill="#0f172a" stroke="{needle_color}" stroke-width="3"/>

        <!-- Central Score -->
        <text x="{cx}" y="100" text-anchor="middle" fill="#f8fafc" font-size="24" font-weight="800" font-family="'JetBrains Mono', monospace">{norm_score:.1f}</text>
        <text x="{cx}" y="118" text-anchor="middle" fill="#94a3b8" font-size="10">R100 / 100</text>
      </svg>
    </div>
    """
    return svg


# ==============================================================================
# HELPER: RADAR SPIDER CHART (SVG)
# ==============================================================================
def render_radar_polygon(I: float, D: float, C: float, A: float, U: float) -> str:
    """
    Renders an interactive 5-axis Radar chart showing multi-signal attack profile.
    """
    cx, cy, r_max = 130, 110, 80
    factors = [I, D, C, A, U]
    labels = ["Identity (I)", "Device (D)", "Context (C)", "Action (A)", "Uncertainty (U)"]
    n = 5

    # Calculate 5 axis vertices at r_max
    axis_points = []
    data_points = []
    for i in range(n):
        angle = math.radians(-90.0 + i * (360.0 / n))
        ax = cx + r_max * math.cos(angle)
        ay = cy + r_max * math.sin(angle)
        axis_points.append((ax, ay))

        # Scaled data point (score 0 to 4)
        val_r = (factors[i] / 4.0) * r_max
        dx = cx + val_r * math.cos(angle)
        dy = cy + val_r * math.sin(angle)
        data_points.append(f"{dx:.1f},{dy:.1f}")

    polygon_pts = " ".join(data_points)

    svg = f"""
    <div style="text-align: center;">
      <svg width="270" height="210" viewBox="0 0 260 210">
        <!-- Concentric Background Polygons -->
        <polygon points="
          {cx},{cy-80} {cx+76},{cy-25} {cx+47},{cy+65} {cx-47},{cy+65} {cx-76},{cy-25}
        " fill="none" stroke="#1e293b" stroke-width="1.5"/>
        <polygon points="
          {cx},{cy-40} {cx+38},{cy-12} {cx+23},{cy+32} {cx-23},{cy+32} {cx-38},{cy-12}
        " fill="none" stroke="#1e293b" stroke-dasharray="3,3" stroke-width="1"/>

        <!-- Axis Lines -->
        <line x1="{cx}" y1="{cy}" x2="{axis_points[0][0]}" y2="{axis_points[0][1]}" stroke="#334155" stroke-width="1"/>
        <line x1="{cx}" y1="{cy}" x2="{axis_points[1][0]}" y2="{axis_points[1][1]}" stroke="#334155" stroke-width="1"/>
        <line x1="{cx}" y1="{cy}" x2="{axis_points[2][0]}" y2="{axis_points[2][1]}" stroke="#334155" stroke-width="1"/>
        <line x1="{cx}" y1="{cy}" x2="{axis_points[3][0]}" y2="{axis_points[3][1]}" stroke="#334155" stroke-width="1"/>
        <line x1="{cx}" y1="{cy}" x2="{axis_points[4][0]}" y2="{axis_points[4][1]}" stroke="#334155" stroke-width="1"/>

        <!-- Data Polygon -->
        <polygon points="{polygon_pts}" fill="rgba(56, 189, 248, 0.35)" stroke="#38bdf8" stroke-width="2.5"/>

        <!-- Axis Labels -->
        <text x="{cx}" y="{cy-87}" text-anchor="middle" fill="#94a3b8" font-size="10" font-weight="600">{labels[0]}: {I:.1f}</text>
        <text x="{axis_points[1][0]+8}" y="{axis_points[1][1]}" text-anchor="start" fill="#94a3b8" font-size="10" font-weight="600">{labels[1]}: {D:.1f}</text>
        <text x="{axis_points[2][0]+6}" y="{axis_points[2][1]+12}" text-anchor="middle" fill="#94a3b8" font-size="10" font-weight="600">{labels[2]}: {C:.1f}</text>
        <text x="{axis_points[3][0]-6}" y="{axis_points[3][1]+12}" text-anchor="middle" fill="#94a3b8" font-size="10" font-weight="600">{labels[3]}: {A:.1f}</text>
        <text x="{axis_points[4][0]-8}" y="{axis_points[4][1]}" text-anchor="end" fill="#94a3b8" font-size="10" font-weight="600">{labels[4]}: {U:.1f}</text>
      </svg>
    </div>
    """
    return svg


# ==============================================================================
# SIDEBAR CONFIGURATION
# ==============================================================================
st.sidebar.markdown("### ⚙️ Simulation Controls")

weight_mode = st.sidebar.radio(
    "Active Weight Configuration:",
    ["Proposed Weights", "Equal Weights (Baseline)", "AHP-Derived Weights", "Custom Weights"],
    index=0
)

if weight_mode == "Proposed Weights":
    st.session_state.active_weights = PROPOSED_WEIGHTS.copy()
elif weight_mode == "Equal Weights (Baseline)":
    st.session_state.active_weights = EQUAL_WEIGHTS.copy()
elif weight_mode == "AHP-Derived Weights":
    ahp_mod = AHPModel()
    ahp_res = ahp_mod.get_results()
    st.session_state.active_weights = ahp_res['weights'].copy()
elif weight_mode == "Custom Weights":
    st.sidebar.markdown("**Fine-tune Factor Weights:**")
    cw_I = st.sidebar.slider("w_I (Identity)", 0.0, 1.0, float(st.session_state.active_weights['I']), 0.05)
    cw_D = st.sidebar.slider("w_D (Device)", 0.0, 1.0, float(st.session_state.active_weights['D']), 0.05)
    cw_C = st.sidebar.slider("w_C (Context)", 0.0, 1.0, float(st.session_state.active_weights['C']), 0.05)
    cw_A = st.sidebar.slider("w_A (Action)", 0.0, 1.0, float(st.session_state.active_weights['A']), 0.05)
    cw_U = st.sidebar.slider("w_U (Uncertainty)", 0.0, 1.0, float(st.session_state.active_weights['U']), 0.05)
    tot = cw_I + cw_D + cw_C + cw_A + cw_U
    if tot > 0:
        st.session_state.active_weights = {
            'I': round(cw_I / tot, 4),
            'D': round(cw_D / tot, 4),
            'C': round(cw_C / tot, 4),
            'A': round(cw_A / tot, 4),
            'U': round(cw_U / tot, 4)
        }

st.sidebar.markdown("---")
st.sidebar.markdown("**Current Multi-Signal Weights:**")
for k, v in st.session_state.active_weights.items():
    st.sidebar.markdown(f"- **{k}** ({FACTOR_LABELS[k].split('(')[0]}): `{v:.3f}`")

st.sidebar.markdown("---")
st.sidebar.caption("Research Prototype | Cyber Security Simulation")


# ==============================================================================
# MAIN PAGE HEADER
# ==============================================================================
st.markdown('<div class="main-title">🛡️ Risk-Adaptive Zero Trust Framework</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">A Multi-Signal Zero Trust Simulation for Mitigating Deepfake Identity Attacks in Enterprise Environments</div>', unsafe_allow_html=True)

st.markdown("""
<div class="notice-box">
  <strong>Research Simulation Scope:</strong> Evaluates dynamic risk adaptation across Identity ($I$), Device ($D$), Context ($C$), Action Criticality ($A$), and Deepfake Uncertainty ($U$). 
  Distinguishes strictly between Authentication (identity verification) and Authorization (transaction permission).
</div>
""", unsafe_allow_html=True)


# ==============================================================================
# TABS
# ==============================================================================
tab_sim, tab_contrast, tab_ahp, tab_whatif, tab_exp, tab_data = st.tabs([
    "🎛️ Interactive Scenario Simulator",
    "⚖️ Deepfake Action Criticality (SCN-04 vs 05)",
    "📐 AHP Matrix Workshop",
    "📈 What-If Sensitivity Trajectory",
    "🧪 Empirical Experiments",
    "📂 Curated Scenario Dataset"
])


engine = DecisionEngine(RiskEngine(st.session_state.active_weights))

# ==============================================================================
# TAB 1: INTERACTIVE SCENARIO SIMULATOR
# ==============================================================================
with tab_sim:
    st.markdown("#### ⚡ 1-Click Benchmark Quick-Launchers")
    col_b1, col_b2, col_b3, col_b4, col_b5 = st.columns(5)
    
    with col_b1:
        if st.button("🟢 SCN-01: Benign Access", use_container_width=True, help="Low risk, Low auth burden"):
            apply_scenario("SCN-01")
            st.rerun()
    with col_b2:
        if st.button("🟡 SCN-02: New Device", use_container_width=True, help="Medium risk, Step-up MFA"):
            apply_scenario("SCN-02")
            st.rerun()
    with col_b3:
        if st.button("🟠 SCN-03: Foreign Context", use_container_width=True, help="High risk, Device + Context check"):
            apply_scenario("SCN-03")
            st.rerun()
    with col_b4:
        if st.button("🔴 SCN-04: Deepfake ₹10L Wire", use_container_width=True, help="Critical risk, Out-of-band Callback"):
            apply_scenario("SCN-04")
            st.rerun()
    with col_b5:
        if st.button("🟣 SCN-05: Deepfake Public Info", use_container_width=True, help="Action Criticality reduced"):
            apply_scenario("SCN-05")
            st.rerun()

    st.markdown(f"**Active Scenario:** `{st.session_state.scen_name}`")
    st.caption(f"Context: {st.session_state.scen_desc}")

    st.markdown("---")
    
    col_input, col_vis = st.columns([1.2, 1.0])

    with col_input:
        st.markdown("##### 🎚️ Multi-Signal Risk Sliders (0 to 4)")
        
        I_val = st.slider(
            "Identity Risk (I)", 0.0, 4.0, float(st.session_state.I_val), 0.5,
            help="0 = Verified Employee, 4 = Known Impersonation / Failed Verification"
        )
        st.caption(f"Status: *{FACTOR_DESCRIPTIONS['I'].get(int(round(I_val)), '')}*")

        D_val = st.slider(
            "Device Risk (D)", 0.0, 4.0, float(st.session_state.D_val), 0.5,
            help="0 = Managed Corporate MDM/EDR, 4 = Compromised Host / Rooted"
        )
        st.caption(f"Status: *{FACTOR_DESCRIPTIONS['D'].get(int(round(D_val)), '')}*")

        C_val = st.slider(
            "Context Anomaly (C)", 0.0, 4.0, float(st.session_state.C_val), 0.5,
            help="0 = Normal Office Subnet/Hours, 4 = Impossible Travel / Tor Exit Node"
        )
        st.caption(f"Status: *{FACTOR_DESCRIPTIONS['C'].get(int(round(C_val)), '')}*")

        A_val = st.slider(
            "Action Criticality (A)", 0.0, 4.0, float(st.session_state.A_val), 0.5,
            help="0 = Public Directory, 2 = Confidential PII, 4 = Critical Financial Wire"
        )
        st.caption(f"Status: *{FACTOR_DESCRIPTIONS['A'].get(int(round(A_val)), '')}*")

        U_val = st.slider(
            "Deepfake Uncertainty (U)", 0.0, 4.0, float(st.session_state.U_val), 0.5,
            help="0 = Authentic Hardware Token, 4 = Flagged Synthetic Voice/Video"
        )
        st.caption(f"Status: *{FACTOR_DESCRIPTIONS['U'].get(int(round(U_val)), '')}*")

        st.markdown("---")
        st.markdown("##### 🧪 Simulated Authentication Outcomes (AuthN vs AuthZ)")
        col_m1, col_m2, col_m3 = st.columns(3)
        with col_m1:
            sim_mfa = st.selectbox("Primary MFA Challenge:", ["PASS", "FAIL", "PENDING"], index=["PASS", "FAIL", "PENDING"].index(st.session_state.auth_sim_mfa))
        with col_m2:
            sim_dev = st.selectbox("Device Attestation:", ["PASS", "FAIL", "PENDING"], index=["PASS", "FAIL", "PENDING"].index(st.session_state.auth_sim_device))
        with col_m3:
            sim_oob = st.selectbox("Out-of-Band Callback:", ["PENDING", "PASS", "FAIL"], index=["PENDING", "PASS", "FAIL"].index(st.session_state.auth_sim_oob))

    # Evaluate dynamic request
    current_factors = {'I': I_val, 'D': D_val, 'C': C_val, 'A': A_val, 'U': U_val}
    auth_status = {'mfa': sim_mfa, 'device_attestation': sim_dev, 'oob_verification': sim_oob}
    eval_res = engine.evaluate_request(current_factors, st.session_state.active_weights, auth_status)

    with col_vis:
        st.markdown("##### 🎯 Dynamic Risk Speedometer & Attack Footprint")
        
        # Dual Visuals: Speedometer & Radar
        v_col1, v_col2 = st.columns(2)
        with v_col1:
            st.plotly_chart(render_plotly_gauge(eval_res['normalized_risk'], eval_res['raw_risk'], eval_res['risk_level']), use_container_width=True)
        with v_col2:
            st.plotly_chart(render_plotly_radar(I_val, D_val, C_val, A_val, U_val), use_container_width=True)

        # Decision & Complexity Summary
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        s_c1, s_c2, s_c3 = st.columns(3)
        with s_c1:
            st.markdown('<div class="stat-label">Risk Level</div>', unsafe_allow_html=True)
            tier = eval_res['risk_level']
            tier_class = f"badge-{tier.lower()}"
            st.markdown(f'<div class="badge {tier_class}">{tier}</div>', unsafe_allow_html=True)
        with s_c2:
            st.markdown('<div class="stat-label">Complexity</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="stat-value">{eval_res["auth_complexity"]} <span style="font-size: 0.9rem; color: #94a3b8;">/ 5</span></div>', unsafe_allow_html=True)
        with s_c3:
            st.markdown('<div class="stat-label">Decision</div>', unsafe_allow_html=True)
            dec = eval_res['decision']
            dec_class = "badge-low" if dec == "ALLOW" else ("badge-medium" if dec == "MFA_REQUIRED" else ("badge-high" if "REQUIRED" in dec else "badge-critical"))
            st.markdown(f'<div class="badge {dec_class}">{dec}</div>', unsafe_allow_html=True)

        st.markdown(f"<div style='margin-top: 12px; font-size: 0.85rem; color: #cbd5e1; line-height: 1.4;'><strong>Rationale:</strong> {eval_res['decision_rationale']}</div>", unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

        # 5-Stage Access Pipeline
        st.markdown("##### 🧱 5-Stage Zero Trust Control Pipeline")
        p_steps = [
            ("1. Primary Credential (SSO/Password)", eval_res['auth_complexity'] >= 1, False),
            ("2. Multi-Factor Challenge (MFA Step-up)", eval_res['auth_complexity'] >= 2, False),
            ("3. Endpoint Health & MDM Attestation", eval_res['auth_complexity'] >= 3, False),
            ("4. Contextual Anomaly & Manager Sign-off", eval_res['auth_complexity'] >= 4, False),
            ("5. Out-of-Band Callback & Dual Authorization", eval_res['auth_complexity'] >= 5, True),
        ]

        for name, active, is_critical in p_steps:
            if active:
                c_style = "pipeline-critical" if is_critical else "pipeline-active"
                icon = "🚨 MANDATORY" if is_critical else "✅ ACTIVE"
            else:
                c_style = "pipeline-inactive"
                icon = "⚪ NOT REQUIRED"
            st.markdown(f'<div class="pipeline-step {c_style}"><span>{name}</span><span style="margin-left: auto;">{icon}</span></div>', unsafe_allow_html=True)

    # Factor Breakdown Table
    st.markdown("##### 📊 Factor Contribution Breakdown")
    b_rows = []
    for k in ['I', 'D', 'C', 'A', 'U']:
        c = eval_res['contributions'][k]
        b_rows.append({
            'Factor': c['label'],
            'Score (0–4)': f"{c['score']:.1f}",
            'Weight': f"{c['weight']:.3f}",
            'Weighted Raw': f"{c['raw_contribution']:.4f}",
            'Points (out of 100)': f"{c['norm_contribution_points']:.2f}",
            'Contribution %': f"{c['percentage_of_total_risk']:.1f}%",
            'Interpretation': c['description']
        })
    st.dataframe(pd.DataFrame(b_rows), hide_index=True, use_container_width=True)


# ==============================================================================
# TAB 2: DEEPFAKE ACTION CRITICALITY CONTRAST (SCN-04 vs SCN-05)
# ==============================================================================
with tab_contrast:
    st.subheader("Action Criticality Impact: SCN-04 vs. SCN-05")
    st.markdown("""
    A fundamental flaw of binary deepfake detectors is that they treat synthetic media as an all-or-nothing block.
    In contrast, this Zero Trust framework demonstrates that **Action Criticality ($A$) radically alters the authorization policy**,
    avoiding unnecessary paralysis for benign requests while rigorously protecting critical assets.
    """)

    res_04 = engine.evaluate_request({'I': 3, 'D': 4, 'C': 3, 'A': 4, 'U': 4}, st.session_state.active_weights)
    res_05 = engine.evaluate_request({'I': 3, 'D': 4, 'C': 3, 'A': 0, 'U': 4}, st.session_state.active_weights)

    c_col1, c_col2 = st.columns(2)

    with c_col1:
        st.markdown("""
        <div class="comparison-card" style="border-left: 5px solid #ef4444;">
          <h3 style="color: #f87171; margin-bottom: 4px;">SCN-04: Emergency ₹10 Lakh Wire Transfer</h3>
          <p style="color: #94a3b8; font-size: 0.85rem;">Deepfake CEO video call requesting high-impact treasury transfer.</p>
          <hr style="border-color: rgba(255,255,255,0.08);">
          <p><strong>Inputs:</strong> I=3, D=4, C=3, <span style="color: #f87171; font-weight: 700;">A=4 (Financial Transfer)</span>, U=4</p>
          <p><strong>Raw Score:</strong> 3.60 / 4.0</p>
          <p><strong>Normalized Risk (R100):</strong> <span style="font-size: 1.4rem; font-weight: 800; color: #f87171;">90.00 / 100</span></p>
          <p><strong>Risk Tier:</strong> <span class="badge badge-critical">CRITICAL</span></p>
          <p><strong>Complexity:</strong> 5 / 5 Steps (Maximum Friction)</p>
          <p><strong>Verdict:</strong> <span class="badge badge-critical">INDEPENDENT_VERIFICATION / HOLD</span></p>
          <p style="font-size: 0.85rem; color: #cbd5e1; margin-top: 8px;">
            Even if attacker passes primary MFA, the wire transfer is <strong>quarantined</strong>. An out-of-band phone callback via pre-verified directory and dual executive approval are mandatory.
          </p>
        </div>
        """, unsafe_allow_html=True)

    with c_col2:
        st.markdown("""
        <div class="comparison-card" style="border-left: 5px solid #fb923c;">
          <h3 style="color: #fb923c; margin-bottom: 4px;">SCN-05: Public Press Release Query</h3>
          <p style="color: #94a3b8; font-size: 0.85rem;">Same suspicious deepfake CEO video, but requesting public information.</p>
          <hr style="border-color: rgba(255,255,255,0.08);">
          <p><strong>Inputs:</strong> I=3, D=4, C=3, <span style="color: #38bdf8; font-weight: 700;">A=0 (Public Information)</span>, U=4</p>
          <p><strong>Raw Score:</strong> 2.40 / 4.0</p>
          <p><strong>Normalized Risk (R100):</strong> <span style="font-size: 1.4rem; font-weight: 800; color: #fb923c;">60.00 / 100</span></p>
          <p><strong>Risk Tier:</strong> <span class="badge badge-high">HIGH</span> (Downgraded from Critical)</p>
          <p><strong>Complexity:</strong> 3 / 5 Steps (Reduced Friction)</p>
          <p><strong>Verdict:</strong> <span class="badge badge-high">STEP_UP_REQUIRED</span></p>
          <p style="font-size: 0.85rem; color: #cbd5e1; margin-top: 8px;">
            Because public data has zero confidentiality impact, out-of-band executive call and quarantine are avoided. Standard step-up MFA and device compliance suffice.
          </p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div class="notice-box" style="margin-top: 16px;">
      <strong>Academic Contribution:</strong> This comparison confirms that multi-signal Zero Trust prevents deepfake uncertainty from paralyzing routine enterprise operations, 
      while dynamically escalating controls to maximum strength when critical assets are at stake.
    </div>
    """, unsafe_allow_html=True)


# ==============================================================================
# TAB 3: AHP MATRIX WORKSHOP
# ==============================================================================
with tab_ahp:
    st.subheader("Analytic Hierarchy Process (AHP) Interactive Workshop")
    st.markdown("""
    Adjust pairwise judgments between risk factors. Saaty's eigenvector method computes priority weights and verifies the **Consistency Ratio (CR)**.
    """)

    ahp_default = AHPModel()
    
    st.markdown("##### ⚖️ Pairwise Judgment Sliders (Relative Importance)")
    st.caption("Values > 1 indicate Factor 1 is more important; values < 1 indicate Factor 2 is more important.")

    col_a1, col_a2 = st.columns(2)
    with col_a1:
        cmp_A_I = st.slider("Importance of Action Criticality (A) over Identity (I):", 0.2, 5.0, 1.2, 0.1)
        cmp_A_D = st.slider("Importance of Action Criticality (A) over Device (D):", 0.2, 5.0, 2.0, 0.1)
        cmp_A_C = st.slider("Importance of Action Criticality (A) over Context (C):", 0.2, 5.0, 2.0, 0.1)
        cmp_A_U = st.slider("Importance of Action Criticality (A) over Uncertainty (U):", 0.2, 5.0, 2.0, 0.1)
    with col_a2:
        cmp_I_D = st.slider("Importance of Identity (I) over Device (D):", 0.2, 5.0, 1.67, 0.1)
        cmp_I_C = st.slider("Importance of Identity (I) over Context (C):", 0.2, 5.0, 1.67, 0.1)
        cmp_I_U = st.slider("Importance of Identity (I) over Uncertainty (U):", 0.2, 5.0, 1.67, 0.1)
        cmp_D_C = st.slider("Importance of Device (D) over Context (C):", 0.2, 5.0, 1.0, 0.1)

    # Build custom matrix
    custom_mat = np.eye(5)
    # [I, D, C, A, U] -> indices 0, 1, 2, 3, 4
    custom_mat[3, 0] = cmp_A_I; custom_mat[0, 3] = 1.0 / cmp_A_I
    custom_mat[3, 1] = cmp_A_D; custom_mat[1, 3] = 1.0 / cmp_A_D
    custom_mat[3, 2] = cmp_A_C; custom_mat[2, 3] = 1.0 / cmp_A_C
    custom_mat[3, 4] = cmp_A_U; custom_mat[4, 3] = 1.0 / cmp_A_U
    custom_mat[0, 1] = cmp_I_D; custom_mat[1, 0] = 1.0 / cmp_I_D
    custom_mat[0, 2] = cmp_I_C; custom_mat[2, 0] = 1.0 / cmp_I_C
    custom_mat[0, 4] = cmp_I_U; custom_mat[4, 0] = 1.0 / cmp_I_U
    custom_mat[1, 2] = cmp_D_C; custom_mat[2, 1] = 1.0 / cmp_D_C
    custom_mat[1, 4] = 1.0; custom_mat[4, 1] = 1.0
    custom_mat[2, 4] = 1.0; custom_mat[4, 2] = 1.0

    user_ahp = AHPModel(matrix=custom_mat)
    ahp_out = user_ahp.get_results()

    col_diag, col_res_w = st.columns(2)
    with col_diag:
        st.markdown("##### 📐 Mathematical Diagnostics")
        c = ahp_out['consistency']
        st.markdown(f"- **Max Eigenvalue ($\lambda_{{max}}$):** `{c['lambda_max']:.4f}`")
        st.markdown(f"- **Consistency Index (CI):** `{c['ci']:.4f}`")
        st.markdown(f"- **Random Index (RI for n=5):** `{c['ri']:.2f}`")
        
        cr_val = c['cr']
        cr_color = "#10b981" if c['is_consistent'] else "#ef4444"
        st.markdown(f"- **Consistency Ratio (CR):** <span style='font-size: 1.3rem; font-weight: 800; color: {cr_color};'>{cr_val:.4f}</span> (Threshold: $\le 0.10$)", unsafe_allow_html=True)
        if c['is_consistent']:
            st.success("✅ Judgments are mathematically consistent.")
        else:
            st.error("❌ Judgments conflict; adjust comparison sliders to improve transitivity.")

    with col_res_w:
        st.markdown("##### 🎯 Resulting Priority Weights")
        derived_w = ahp_out['weights']
        st.dataframe(pd.DataFrame([
            {'Factor': FACTOR_LABELS[k], 'Weight': f"{v:.4f}", 'Weight %': f"{v*100:.1f}%"}
            for k, v in derived_w.items()
        ]), hide_index=True, use_container_width=True)

        if st.button("🚀 Apply These AHP Weights to Simulation"):
            st.session_state.active_weights = derived_w.copy()
            st.success("Applied AHP weights to active session!")
            st.rerun()


# ==============================================================================
# TAB 4: WHAT-IF SENSITIVITY TRAJECTORY
# ==============================================================================
with tab_whatif:
    st.subheader("What-If Sensitivity Trajectory Simulator")
    st.markdown("Vary a single target factor from 0.0 to 4.0 while holding other signals constant to observe the trajectory of risk and threshold transitions.")

    sweep_factor = st.selectbox("Select Factor to Sweep:", ["A (Action Criticality)", "U (Deepfake Uncertainty)", "I (Identity Risk)", "D (Device Risk)", "C (Context Anomaly)"])
    sweep_key = sweep_factor[0]

    base_factors = {'I': float(st.session_state.I_val), 'D': float(st.session_state.D_val), 'C': float(st.session_state.C_val), 'A': float(st.session_state.A_val), 'U': float(st.session_state.U_val)}
    
    sweep_x = np.linspace(0.0, 4.0, 21)
    sweep_scores = []
    sweep_tiers = []
    sweep_complexities = []

    for val in sweep_x:
        test_f = base_factors.copy()
        test_f[sweep_key] = val
        e = engine.evaluate_request(test_f, st.session_state.active_weights)
        sweep_scores.append(e['normalized_risk'])
        sweep_tiers.append(e['risk_level'])
        sweep_complexities.append(e['auth_complexity'])

    df_sweep = pd.DataFrame({
        f'{FACTOR_LABELS[sweep_key]} Score': sweep_x,
        'Normalized Risk (R100)': sweep_scores,
        'Auth Complexity (Steps)': sweep_complexities,
        'Risk Tier': sweep_tiers
    })

    fig_sweep = go.Figure()
    # Shaded risk tier bands
    fig_sweep.add_hrect(y0=0, y1=25, fillcolor="rgba(16, 185, 129, 0.12)", line_width=0, annotation_text="LOW (0-25)", annotation_position="top left", annotation_font_color="#34d399")
    fig_sweep.add_hrect(y0=25, y1=50, fillcolor="rgba(245, 158, 11, 0.12)", line_width=0, annotation_text="MEDIUM (26-50)", annotation_position="top left", annotation_font_color="#fbbf24")
    fig_sweep.add_hrect(y0=50, y1=75, fillcolor="rgba(249, 115, 22, 0.12)", line_width=0, annotation_text="HIGH (51-75)", annotation_position="top left", annotation_font_color="#fb923c")
    fig_sweep.add_hrect(y0=75, y1=100, fillcolor="rgba(239, 68, 68, 0.12)", line_width=0, annotation_text="CRITICAL (76-100)", annotation_position="top left", annotation_font_color="#f87171")

    # Risk Score curve
    fig_sweep.add_trace(go.Scatter(
        x=sweep_x, y=sweep_scores,
        mode='lines+markers',
        name='Normalized Risk (R100)',
        line=dict(color='#38bdf8', width=3),
        marker=dict(size=7, color='#38bdf8')
    ))

    # Active value marker
    active_val = float(base_factors[sweep_key])
    fig_sweep.add_vline(x=active_val, line_dash="dash", line_color="#f8fafc", annotation_text=f"Active ({active_val:.1f})", annotation_position="top right")

    fig_sweep.update_layout(
        title=f"Sensitivity Trajectory: Sweeping {FACTOR_LABELS[sweep_key]} from 0.0 to 4.0",
        xaxis_title=f"{FACTOR_LABELS[sweep_key]} Score",
        yaxis_title="Normalized Risk Score (R100)",
        yaxis_range=[0, 105],
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(15, 23, 42, 0.4)',
        font=dict(color='#94a3b8', family='Inter'),
        margin=dict(l=40, r=40, t=50, b=40),
        height=380
    )
    st.plotly_chart(fig_sweep, use_container_width=True)
    st.dataframe(df_sweep, hide_index=True, use_container_width=True)


# ==============================================================================
# TAB 5: EMPIRICAL EXPERIMENTS
# ==============================================================================
with tab_exp:
    st.subheader("Empirical Experiments on 45 Enterprise Scenarios")
    runner = ExperimentRunner("simulation/scenarios.csv")

    exp_choice = st.radio("Choose Experiment to Inspect:", ["Experiment 1: Risk-Response Consistency", "Experiment 2: Fixed MFA vs Adaptive ZTA", "Experiment 3: Weight Sensitivity"], horizontal=True)

    if exp_choice == "Experiment 1: Risk-Response Consistency":
        exp1 = runner.run_experiment_1(st.session_state.active_weights)
        s_m = exp1['security_metrics']
        
        c1, c2, c3 = st.columns(3)
        c1.metric("Pearson Correlation (r)", f"{s_m['risk_response_pearson_r']:.4f}", "p < 0.001")
        c2.metric("Spearman Rank (rho)", f"{s_m['risk_response_spearman_rho']:.4f}", "p < 0.001")
        c3.metric("Strong Control Coverage", f"{s_m['proportion_high_crit_receiving_strong_controls']*100:.1f}%", "13 / 13 High/Critical")

        col_img1, col_img2 = st.columns(2)
        if os.path.exists("results/figures/risk_vs_complexity.png"):
            col_img1.image("results/figures/risk_vs_complexity.png", caption="Figure 3: Risk Score vs Complexity Regression")
        if os.path.exists("results/figures/control_strength_by_level.png"):
            col_img2.image("results/figures/control_strength_by_level.png", caption="Figure 5: Control Activation Rates by Risk Tier")

    elif exp_choice == "Experiment 2: Fixed MFA vs Adaptive ZTA":
        exp2 = runner.run_experiment_2(st.session_state.active_weights)
        c1, c2, c3 = st.columns(3)
        c1.metric("Low-Risk Friction Saved", f"{exp2['low_risk_friction_reduction_percentage']:.1f}%", "Complexity 1 vs 2")
        c2.metric("Critical Threats Caught by ZTA", f"{exp2['critical_attacks_held_by_zta_percentage']:.1f}%", "100% Intercepted")
        c3.metric("Under-Protected Threats in Fixed MFA", f"{exp2['critical_attacks_under_protected_by_fixed_mfa_count']} / {exp2['critical_threat_count']}", "Bypassed if MFA passes")

        if os.path.exists("results/figures/fixed_vs_adaptive.png"):
            st.image("results/figures/fixed_vs_adaptive.png", caption="Figure 4: Comparative Evaluation - Fixed MFA vs Risk-Adaptive ZTA")

    else:
        exp3 = runner.run_experiment_3()
        stab = exp3['stability_metrics']
        c1, c2, c3 = st.columns(3)
        c1.metric("Equal vs Proposed Concordance", f"{stab['decision_stability_equal_vs_proposed_pct']:.1f}%")
        c2.metric("AHP vs Proposed Concordance", f"{stab['decision_stability_ahp_vs_proposed_pct']:.1f}%")
        c3.metric("Concordance Across All 3", f"{stab['decision_stability_all_three_pct']:.1f}%")

        if os.path.exists("results/figures/weight_sensitivity.png"):
            st.image("results/figures/weight_sensitivity.png", caption="Figure 6: Weight Sensitivity Boxplots & Decision Concordance")


# ==============================================================================
# TAB 6: CURATED SCENARIO DATASET
# ==============================================================================
with tab_data:
    st.subheader("Primary Curated Scenario Dataset (45 Auditable Scenarios)")
    st.markdown("Filter and search through all 45 curated enterprise scenarios:")

    col_flt1, col_flt2 = st.columns(2)
    with col_flt1:
        tier_filter = st.multiselect("Filter by Expected Risk Tier:", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    with col_flt2:
        search_query = st.text_input("Search Scenario Name or Context:", value="")

    filtered_df = df_scenarios[df_scenarios['expected_risk_level'].isin(tier_filter)]
    if search_query:
        filtered_df = filtered_df[
            filtered_df['scenario_name'].str.contains(search_query, case=False) |
            filtered_df['description'].str.contains(search_query, case=False)
        ]

    st.dataframe(filtered_df, use_container_width=True)

    st.markdown("##### 🚀 1-Click Load from Table into Simulator")
    selected_row_id = st.selectbox("Select Scenario ID to Load:", filtered_df['scenario_id'].tolist())
    if st.button("Load This Scenario into Simulator"):
        apply_scenario(selected_row_id)
        st.success(f"Loaded {selected_row_id} into Simulator!")
        st.rerun()
