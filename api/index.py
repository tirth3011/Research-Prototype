"""
Vercel Serverless Entrypoint for Zero Trust Risk Simulation.
Exposes FastAPI application handler.
"""

import os
import sys
from typing import Dict, Any, Optional, List
import pandas as pd
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

# Ensure simulation root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from simulation.risk_engine import RiskEngine, PROPOSED_WEIGHTS, EQUAL_WEIGHTS, FACTOR_LABELS, FACTOR_DESCRIPTIONS
from simulation.decision_engine import DecisionEngine
from simulation.ahp import AHPModel

app = FastAPI(title="Zero Trust Risk-Adaptive API")

# Enable CORS for Vercel cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = DecisionEngine()


@app.get("/", response_class=HTMLResponse)
@app.get("/api", response_class=HTMLResponse)
def root_index():
    for candidate in [
        os.path.join(os.path.dirname(__file__), "..", "index.html"),
        os.path.join(os.path.dirname(__file__), "..", "public", "index.html"),
        os.path.join(os.path.dirname(__file__), "index.html")
    ]:
        if os.path.exists(candidate):
            with open(candidate, "r", encoding="utf-8") as f:
                return f.read()
    return "<h1>Risk-Adaptive Zero Trust Framework API is Live</h1>"


class EvaluatePayload(BaseModel):
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


@app.get("/api/health")
def health_check():
    return {"status": "ok", "framework": "Risk-Adaptive Zero Trust Simulation"}


@app.get("/api/scenarios")
def get_scenarios():
    path = os.path.join(os.path.dirname(__file__), "..", "simulation", "scenarios.csv")
    if os.path.exists(path):
        df = pd.read_csv(path)
        return df.to_dict(orient="records")
    return []


@app.post("/api/evaluate")
def evaluate(payload: EvaluatePayload):
    factors = {
        'I': float(payload.I),
        'D': float(payload.D),
        'C': float(payload.C),
        'A': float(payload.A),
        'U': float(payload.U)
    }
    auth_status = {
        'mfa': payload.mfa_status,
        'device_attestation': payload.device_status,
        'oob_verification': payload.oob_status
    }
    res = engine.evaluate_request(factors, payload.weights, auth_status)
    return res


@app.get("/api/ahp")
def get_ahp():
    ahp = AHPModel()
    return ahp.get_results()


@app.get("/api/experiments")
def get_experiments():
    path = os.path.join(os.path.dirname(__file__), "..", "results", "experiment_summary.csv")
    if os.path.exists(path):
        df = pd.read_csv(path)
        return df.to_dict(orient="records")
    return []
