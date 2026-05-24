import json
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os



# ─── Règles Sigma simplifiées ─────────────────────────────────────────────────
SIGMA_RULES = [
    {
        "id": "SIGMA-001",
        "name": "Brute Force SSH",
        "severity": "HIGH",
        "mitre": "T1110",
        "condition": lambda log: (
            "brute_force" in log.get("tags", []) and
            log.get("attempts_5min", 0) >= 5
        )
    },
    {
        "id": "SIGMA-002",
        "name": "Privilege Escalation",
        "severity": "CRITICAL",
        "mitre": "T1548",
        "condition": lambda log: (
            "privilege_esc" in log.get("tags", [])
        )
    },
    {
        "id": "SIGMA-003",
        "name": "Off-Hours Login",
        "severity": "MEDIUM",
        "mitre": "T1078",
        "condition": lambda log: (
            log.get("is_night", 0) == 1 and
            "login_success" in log.get("tags", [])
        )
    },
    {
        "id": "SIGMA-004",
        "name": "Multiple Users Same IP",
        "severity": "HIGH",
        "mitre": "T1110.003",
        "condition": lambda log: (
            log.get("distinct_users_5min", 0) >= 3
        )
    },
    {
        "id": "SIGMA-005",
        "name": "Critical Severity Event",
        "severity": "CRITICAL",
        "mitre": "T1499",
        "condition": lambda log: (
            log.get("severity", 6) <= 2
        )
    },
]


# ─── Features pour Isolation Forest ──────────────────────────────────────────
FEATURE_COLS = [
    "severity",
    "attempts_5min",
    "distinct_users_5min",
    "avg_severity_5min",
    "brute_force_flag",
    "privilege_flag",
    "hour_of_day",
    "is_night",
    "has_ip",
]

MODEL_PATH = "store/isolation_forest.pkl"
SCALER_PATH = "store/scaler.pkl"


# ─── Rules Engine ─────────────────────────────────────────────────────────────
def run_sigma_rules(log: dict) -> list:
    """Retourne la liste des règles déclenchées."""
    triggered = []
    for rule in SIGMA_RULES:
        try:
            if rule["condition"](log):
                triggered.append({
                    "rule_id":   rule["id"],
                    "rule_name": rule["name"],
                    "severity":  rule["severity"],
                    "mitre":     rule["mitre"],
                })
        except Exception:
            pass
    return triggered


# ─── Isolation Forest ─────────────────────────────────────────────────────────
def extract_features(log: dict) -> np.ndarray:
    """Extrait le vecteur de features d'un log."""
    features = [float(log.get(col, 0) or 0) for col in FEATURE_COLS]
    return np.array(features).reshape(1, -1)


def train_model(logs: list) -> IsolationForest:
    """Entraîne l'Isolation Forest sur une liste de logs."""
    print("[*] Entraînement Isolation Forest...")
    X = np.array([
        [float(log.get(col, 0) or 0) for col in FEATURE_COLS]
        for log in logs
    ])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    model.fit(X_scaled)

    os.makedirs("store", exist_ok=True)
    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"[✓] Modèle sauvegardé : {MODEL_PATH}")
    return model, scaler


def load_model():
    """Charge le modèle et le scaler depuis le disque."""
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        model  = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        return model, scaler
    return None, None


def run_isolation_forest(log: dict, model, scaler) -> dict:
    """Retourne le score d'anomalie ML."""
    X = extract_features(log)
    X_scaled = scaler.transform(X)
    score     = model.decision_function(X_scaled)[0]
    prediction = model.predict(X_scaled)[0]  # -1 = anomalie, 1 = normal
    return {
        "anomaly_score": round(float(score), 4),
        "is_anomaly":    prediction == -1
    }


# ─── Score Fusion ─────────────────────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "CRITICAL": 1.0,
    "HIGH":     0.75,
    "MEDIUM":   0.5,
    "LOW":      0.25,
}

def fuse_scores(sigma_alerts: list, ml_result: dict) -> dict:
    """
    Combine le score Sigma et le score ML en un score final.
    Score final entre 0 et 1.
    """
    # Score Sigma : moyenne des poids de sévérité
    if sigma_alerts:
        sigma_score = max(
            SEVERITY_WEIGHTS.get(a["severity"], 0.25)
            for a in sigma_alerts
        )
    else:
        sigma_score = 0.0

    # Score ML : normaliser entre 0 et 1 (score IF est négatif = anomalie)
    raw_ml = ml_result.get("anomaly_score", 0)
    ml_score = max(0.0, min(1.0, 0.5 - raw_ml))

    # Fusion pondérée 60% Sigma + 40% ML
    final_score = round(0.6 * sigma_score + 0.4 * ml_score, 4)

    return {
        "sigma_score": round(sigma_score, 4),
        "ml_score":    round(ml_score, 4),
        "final_score": final_score,
        "risk_level":  score_to_risk(final_score)
    }


def score_to_risk(score: float) -> str:
    if score >= 0.8:  return "CRITICAL"
    if score >= 0.6:  return "HIGH"
    if score >= 0.4:  return "MEDIUM"
    if score >= 0.2:  return "LOW"
    return "INFO"


# ─── Moteur hybride principal ─────────────────────────────────────────────────
def analyze_log(log: dict, model=None, scaler=None) -> dict:
    """
    Analyse complète d'un log :
    1. Règles Sigma
    2. Isolation Forest ML
    3. Fusion des scores
    """
    # 1. Règles
    sigma_alerts = run_sigma_rules(log)

    # 2. ML
    if model and scaler:
        ml_result = run_isolation_forest(log, model, scaler)
    else:
        ml_result = {"anomaly_score": 0.0, "is_anomaly": False}

    # 3. Fusion
    scores = fuse_scores(sigma_alerts, ml_result)

    return {
        "timestamp":    datetime.utcnow().isoformat(),
        "log":          log,
        "sigma_alerts": sigma_alerts,
        "ml_result":    ml_result,
        "scores":       scores,
        "alert":        scores["final_score"] >= 0.4
    }


if __name__ == "__main__":
    # Test rapide sans modèle ML
    test_log = {
        "ip": "192.168.1.1",
        "user": "root",
        "tags": ["brute_force"],
        "attempts_5min": 10,
        "distinct_users_5min": 4,
        "severity": 3,
        "is_night": 1,
        "hour_of_day": 2,
        "brute_force_flag": 1,
        "privilege_flag": 0,
        "has_ip": 1,
        "avg_severity_5min": 3.5
    }

    result = analyze_log(test_log)
    print(json.dumps(result, indent=2))
