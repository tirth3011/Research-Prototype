"""
FastAPI Web Dashboard for Risk-Adaptive Zero Trust Framework.

Runs standalone on any port (default: 8501 or 8000) using uvicorn.
Provides live interactive evaluation, factor sliders, AHP solver, and experiment visualizer.
"""

import os
import sys
from typing import Dict, Any, Optional
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Ensure simulation is accessible
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from simulation.risk_engine import RiskEngine, PROPOSED_WEIGHTS, EQUAL_WEIGHTS, FACTOR_LABELS, FACTOR_DESCRIPTIONS
from simulation.decision_engine import DecisionEngine
from simulation.ahp import AHPModel
from simulation.experiments import ExperimentRunner

app = FastAPI(title="Risk-Adaptive Zero Trust Simulation API")

engine = DecisionEngine()
runner = ExperimentRunner(scenarios_path="simulation/scenarios.csv")


class EvaluationRequest(BaseModel):
    scenario_name: Optional[str] = "Identity Request"
    I: float
    D: float
    C: float
    A: float
    U: float
    weights: Optional[Dict[str, float]] = None
    mfa_status: Optional[str] = "PASS"
    device_status: Optional[str] = "PASS"
    oob_status: Optional[str] = "PENDING"


@app.get("/api/scenarios")
def get_scenarios():
    df = pd.read_csv("simulation/scenarios.csv")
    return df.to_dict(orient="records")


@app.post("/api/evaluate")
def evaluate_request(req: EvaluationRequest):
    factors = {'I': req.I, 'D': req.D, 'C': req.C, 'A': req.A, 'U': req.U}
    auth_status = {
        'mfa': req.mfa_status,
        'device_attestation': req.device_status,
        'oob_verification': req.oob_status
    }
    res = engine.evaluate_request(factors, req.weights, auth_status)
    return res


@app.get("/api/ahp")
def get_ahp():
    ahp = AHPModel()
    return ahp.get_results()


@app.get("/api/experiments")
def get_experiments():
    exp1 = runner.run_experiment_1()
    exp2 = runner.run_experiment_2()
    exp3 = runner.run_experiment_3()
    return {
        'experiment_1': {
            'security_metrics': exp1['security_metrics'],
            'auth_metrics': exp1['auth_metrics'],
            'risk_distribution': exp1['risk_distribution']
        },
        'experiment_2': {
            'low_risk_friction_reduction_percentage': exp2['low_risk_friction_reduction_percentage'],
            'critical_attacks_under_protected_by_fixed_mfa_count': exp2['critical_attacks_under_protected_by_fixed_mfa_count'],
            'critical_threat_count': exp2['critical_threat_count'],
            'critical_attacks_held_by_zta_percentage': exp2['critical_attacks_held_by_zta_percentage']
        },
        'experiment_3': {
            'stability_metrics': exp3['stability_metrics'],
            'score_summary': exp3['score_summary']
        }
    }


@app.get("/api/figures/{filename}")
def get_figure(filename: str):
    path = os.path.join("results/figures", filename)
    if os.path.exists(path):
        return FileResponse(path)
    raise HTTPException(status_code=404, detail="Figure not found")


@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Risk-Adaptive Zero Trust Framework</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0b0f19;
      --surface: #131c2e;
      --surface-border: #1e293b;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #38bdf8;
      --accent: #6366f1;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --critical: #dc2626;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
    body { background-color: var(--bg); color: var(--text-main); min-height: 100vh; padding: 24px; }
    .header { margin-bottom: 24px; border-bottom: 1px solid var(--surface-border); padding-bottom: 16px; }
    .header h1 { font-size: 1.6rem; font-weight: 700; color: var(--primary); margin-bottom: 6px; }
    .header p { color: var(--text-muted); font-size: 0.9rem; }
    .grid { display: grid; grid-template-columns: 1.1fr 1fr; gap: 24px; }
    .card { background: var(--surface); border: 1px solid var(--surface-border); border-radius: 12px; padding: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
    .card h2 { font-size: 1.15rem; font-weight: 600; margin-bottom: 14px; border-bottom: 1px solid var(--surface-border); padding-bottom: 8px; color: var(--primary); }
    .form-group { margin-bottom: 14px; }
    label { display: block; font-size: 0.85rem; font-weight: 500; color: var(--text-muted); margin-bottom: 4px; }
    select, input[type="text"] { width: 100%; background: #0f172a; border: 1px solid var(--surface-border); color: var(--text-main); padding: 8px 12px; border-radius: 6px; font-size: 0.9rem; }
    .slider-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
    .slider-row label { flex: 1; margin: 0; font-size: 0.85rem; }
    .slider-row input[type="range"] { flex: 1.5; margin: 0 12px; accent-color: var(--primary); }
    .slider-val { width: 45px; text-align: right; font-family: 'JetBrains Mono', monospace; font-weight: 600; color: var(--primary); }
    .badge { display: inline-block; padding: 6px 14px; border-radius: 6px; font-weight: 700; font-size: 0.9rem; }
    .badge-low { background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }
    .badge-medium { background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid var(--warning); }
    .badge-high { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }
    .badge-critical { background: rgba(220, 38, 38, 0.3); color: #ff6b6b; border: 1px solid #ff6b6b; }
    .metrics-summary { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px; }
    .metric-box { background: #0f172a; border: 1px solid var(--surface-border); border-radius: 8px; padding: 12px; text-align: center; }
    .metric-box .label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px; }
    .metric-box .value { font-size: 1.4rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; color: var(--primary); }
    .controls-list { list-style: none; margin-top: 10px; }
    .controls-list li { background: #0f172a; border-left: 3px solid var(--primary); padding: 8px 12px; margin-bottom: 6px; border-radius: 0 6px 6px 0; font-size: 0.85rem; }
    .table { width: 100%; border-collapse: collapse; font-size: 0.8rem; margin-top: 10px; }
    .table th, .table td { padding: 6px 8px; text-align: left; border-bottom: 1px solid var(--surface-border); }
    .table th { color: var(--text-muted); }
    .notice { background: rgba(56, 189, 248, 0.08); border-left: 4px solid var(--primary); padding: 10px 14px; font-size: 0.8rem; border-radius: 4px; margin-bottom: 20px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ Risk-Adaptive Zero Trust Framework</h1>
    <p>A Multi-Signal Adaptive Simulation for Mitigating Deepfake Identity Attacks in Enterprise Environments</p>
  </div>

  <div class="notice">
    <strong>Academic Prototype:</strong> Demonstrates dynamic Zero Trust risk adaptation across Identity (I), Device (D), Context (C), Action Criticality (A), and Deepfake Uncertainty (U).
  </div>

  <div class="grid">
    <!-- Input Card -->
    <div class="card">
      <h2>1. Request & Multi-Signal Configuration</h2>
      <div class="form-group">
        <label>Load Benchmark Scenario:</label>
        <select id="presetSelect" onchange="loadPreset()">
          <option value="custom">-- Custom Input --</option>
        </select>
      </div>

      <div class="slider-row">
        <label>Identity Risk (I):</label>
        <input type="range" id="sliderI" min="0" max="4" step="0.5" value="0" oninput="update()">
        <span class="slider-val" id="valI">0.0</span>
      </div>
      <div class="slider-row">
        <label>Device Risk (D):</label>
        <input type="range" id="sliderD" min="0" max="4" step="0.5" value="0" oninput="update()">
        <span class="slider-val" id="valD">0.0</span>
      </div>
      <div class="slider-row">
        <label>Context Anomaly (C):</label>
        <input type="range" id="sliderC" min="0" max="4" step="0.5" value="0" oninput="update()">
        <span class="slider-val" id="valC">0.0</span>
      </div>
      <div class="slider-row">
        <label>Action Criticality (A):</label>
        <input type="range" id="sliderA" min="0" max="4" step="0.5" value="1" oninput="update()">
        <span class="slider-val" id="valA">1.0</span>
      </div>
      <div class="slider-row">
        <label>Deepfake Uncertainty (U):</label>
        <input type="range" id="sliderU" min="0" max="4" step="0.5" value="0" oninput="update()">
        <span class="slider-val" id="valU">0.0</span>
      </div>

      <div style="margin-top: 16px; border-top: 1px solid var(--surface-border); padding-top: 12px;">
        <label>Simulate Primary MFA Outcome (AuthN vs AuthZ Test):</label>
        <select id="simMFA" onchange="update()">
          <option value="PASS">PASS (MFA Verified)</option>
          <option value="FAIL">FAIL (MFA Rejected)</option>
          <option value="PENDING">PENDING</option>
        </select>
      </div>
    </div>

    <!-- Output Card -->
    <div class="card">
      <h2>2. Adaptive Zero Trust Decision</h2>
      
      <div class="metrics-summary">
        <div class="metric-box">
          <div class="label">Normalized Score</div>
          <div class="value" id="normRisk">0.0</div>
        </div>
        <div class="metric-box">
          <div class="label">Risk Level</div>
          <div id="riskLevelBadge" style="margin-top: 4px;"><span class="badge badge-low">LOW</span></div>
        </div>
        <div class="metric-box">
          <div class="label">Complexity</div>
          <div class="value" id="authComplexity">1 / 5</div>
        </div>
      </div>

      <div style="margin-bottom: 16px;">
        <label>Final Authorization Decision:</label>
        <div id="decisionBadge" style="margin-top: 4px;"><span class="badge badge-low">ALLOW</span></div>
        <p id="decisionRationale" style="font-size: 0.8rem; color: var(--text-muted); margin-top: 8px; line-height: 1.4;"></p>
      </div>

      <div>
        <label>Active Zero Trust Controls:</label>
        <ul class="controls-list" id="controlsList"></ul>
      </div>

      <div style="margin-top: 16px;">
        <label>Factor Contributions Breakdown:</label>
        <table class="table">
          <thead><tr><th>Factor</th><th>Score</th><th>Weight</th><th>Pts</th><th>Share</th></tr></thead>
          <tbody id="contributionsBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    let scenariosData = [];

    async function init() {
      const res = await fetch('/api/scenarios');
      scenariosData = await res.json();
      const sel = document.getElementById('presetSelect');
      scenariosData.forEach((s, idx) => {
        const opt = document.createElement('option');
        opt.value = idx;
        opt.textContent = `${s.scenario_id}: ${s.scenario_name}`;
        sel.appendChild(opt);
      });
      update();
    }

    function loadPreset() {
      const idx = document.getElementById('presetSelect').value;
      if (idx === 'custom') return;
      const s = scenariosData[idx];
      document.getElementById('sliderI').value = s.I;
      document.getElementById('sliderD').value = s.D;
      document.getElementById('sliderC').value = s.C;
      document.getElementById('sliderA').value = s.A;
      document.getElementById('sliderU').value = s.U;
      update();
    }

    async function update() {
      const I = parseFloat(document.getElementById('sliderI').value);
      const D = parseFloat(document.getElementById('sliderD').value);
      const C = parseFloat(document.getElementById('sliderC').value);
      const A = parseFloat(document.getElementById('sliderA').value);
      const U = parseFloat(document.getElementById('sliderU').value);

      document.getElementById('valI').textContent = I.toFixed(1);
      document.getElementById('valD').textContent = D.toFixed(1);
      document.getElementById('valC').textContent = C.toFixed(1);
      document.getElementById('valA').textContent = A.toFixed(1);
      document.getElementById('valU').textContent = U.toFixed(1);

      const mfaStatus = document.getElementById('simMFA').value;

      const payload = { I, D, C, A, U, mfa_status: mfaStatus };
      const resp = await fetch('/api/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await resp.json();

      document.getElementById('normRisk').textContent = data.normalized_risk.toFixed(1);
      document.getElementById('authComplexity').textContent = data.auth_complexity + ' / 5';

      const tierBadge = document.getElementById('riskLevelBadge');
      let badgeClass = 'badge-low';
      if (data.risk_level === 'MEDIUM') badgeClass = 'badge-medium';
      else if (data.risk_level === 'HIGH') badgeClass = 'badge-high';
      else if (data.risk_level === 'CRITICAL') badgeClass = 'badge-critical';
      tierBadge.innerHTML = `<span class="badge ${badgeClass}">${data.risk_level}</span>`;

      const decBadge = document.getElementById('decisionBadge');
      let decClass = badgeClass;
      decBadge.innerHTML = `<span class="badge ${decClass}">${data.decision}</span>`;
      document.getElementById('decisionRationale').textContent = data.decision_rationale;

      const list = document.getElementById('controlsList');
      list.innerHTML = '';
      data.controls.forEach(c => {
        const li = document.createElement('li');
        li.textContent = c;
        list.appendChild(li);
      });

      const tbody = document.getElementById('contributionsBody');
      tbody.innerHTML = '';
      for (const k of ['I', 'D', 'C', 'A', 'U']) {
        const item = data.contributions[k];
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><strong>${k}</strong></td><td>${item.score.toFixed(1)}</td><td>${item.weight.toFixed(2)}</td><td>${item.raw_contribution.toFixed(2)}</td><td>${item.percentage_of_total_risk.toFixed(1)}%</td>`;
        tbody.appendChild(tr);
      }
    }

    init();
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
