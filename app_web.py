"""
FastAPI Web Dashboard and REST API for Risk-Adaptive Zero Trust Framework.

Runs standalone on port 8000 using uvicorn.
Provides live interactive evaluation, factor sliders, AHP solver, experiment visualizer,
and serves the primary research dashboard (index.html).
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

# Mount static folders if present
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if os.path.exists(os.path.join(BASE_DIR, "public")):
    app.mount("/public", StaticFiles(directory=os.path.join(BASE_DIR, "public")), name="public")
if os.path.exists(os.path.join(BASE_DIR, "results")):
    app.mount("/results", StaticFiles(directory=os.path.join(BASE_DIR, "results")), name="results")

engine = DecisionEngine()
runner = ExperimentRunner(scenarios_path=os.path.join(BASE_DIR, "simulation", "scenarios.csv"))


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
    scenarios_file = os.path.join(BASE_DIR, "simulation", "scenarios.csv")
    df = pd.read_csv(scenarios_file)
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
    path = os.path.join(BASE_DIR, "results", "figures", filename)
    if os.path.exists(path):
        return FileResponse(path)
    raise HTTPException(status_code=404, detail="Figure not found")


@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    index_path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Zero Trust Risk-Adaptive Dashboard</h1><p>index.html not found.</p>", status_code=404)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app_web:app", host="127.0.0.1", port=8000, reload=False)
