# soc-log-analytics
#  SOC Big Data Log Analytics

> Plateforme de détection d'intrusions basée sur PySpark, Isolation Forest et Flask API

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![PySpark](https://img.shields.io/badge/PySpark-3.4+-orange)
![Flask](https://img.shields.io/badge/Flask-3.0+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

##  Architecture

```
Ingestion (Syslog/Kafka)
        ↓
Normalisation JSON commun
        ↓
ETL PySpark (Window aggregations + Feature engineering)
        ↓
Feature Store ──────────────────────────────┐
        ↓                                   ↓
Détection hybride                      Flask API
  ├── Rules engine (Sigma)           POST /analyze
  ├── Isolation Forest ML            GET  /alerts
  └── Score fusion                   POST /train
        ↓
Alert Store (Parquet / JSON)
        ↓
SOC Dashboard (Live feed + Export)
```

---

## Structure du projet

```
soc-log-analytics/
├── ingestion/
│   ├── log_parser.py        # Parser Syslog RFC 3164/5424, auth.log
│   ├── normalizer.py        # Schéma JSON commun
│   └── kafka_watcher.py     # File watcher / Kafka
├── etl/
│   ├── spark_pipeline.py    # Pipeline PySpark complet
│   ├── feature_engineering.py
│   └── window_aggregations.py
├── detection/
│   ├── hybrid_engine.py     # Moteur hybride principal
│   ├── sigma_rules.py       # Règles Sigma
│   ├── isolation_forest.py  # Modèle ML
│   └── score_fusion.py      # Fusion des scores
├── store/
│   ├── feature_store.py     # Brute-force counters, entropy
│   └── alert_store.py       # Stockage alertes JSON/Parquet
├── api/
│   └── app.py               # Flask API REST
├── dashboard/
│   └── soc_dashboard.py     # Live feed + Export rapport
├── tests/
├── requirements.txt
├── docker-compose.yml
└── .env.example
```

---

##  Installation

### 1. Cloner le projet

```bash
git clone https://github.com/ayayoussfiii/soc-log-analytics.git
cd soc-log-analytics
```

### 2. Créer un environnement virtuel

```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/Mac
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 4. Configurer les variables d'environnement

```bash
cp .env.example .env
# Editer .env avec vos valeurs
```

---

##  Utilisation

### Lancer l'API Flask

```bash
python api/app.py
```

### Analyser un log

```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"log": "May 24 13:00:01 myhost sshd[1234]: Failed password for root from 192.168.1.1"}'
```

### Voir les alertes

```bash
curl http://localhost:5000/alerts
curl http://localhost:5000/alerts?risk=HIGH
```

### Lancer le dashboard

```bash
python dashboard/soc_dashboard.py
```

### Lancer le pipeline PySpark

```bash
python etl/spark_pipeline.py data/logs data/output
```

---

##  API Endpoints

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/analyze` | Analyser un log brut |
| GET | `/alerts` | Récupérer les alertes |
| POST | `/train` | Entraîner le modèle ML |
| GET | `/health` | Statut de l'API |

---

##  MITRE ATT&CK Coverage

| Technique | ID | Règle Sigma |
|-----------|----|-------------|
| Brute Force | T1110 | SIGMA-001 |
| Privilege Escalation | T1548 | SIGMA-002 |
| Valid Accounts | T1078 | SIGMA-003 |
| Password Spraying | T1110.003 | SIGMA-004 |
| Endpoint DoS | T1499 | SIGMA-005 |

---

##  Docker

```bash
docker-compose up -d
```

---



---

## 📄 License

MIT License
