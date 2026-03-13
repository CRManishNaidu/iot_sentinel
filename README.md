# IoT Sentinel - Enterprise IoT Anomaly Detection Systems

A production-grade, real-time network intrusion detection system for IoT device fleets using unsupervised machine learning (Isolation Forest), heuristic rule engines, and entropy-based traffic analysis.

## Quick Start

```bash
# Run the full application (Windows)
start_all.bat

# Or manually:
python src/data_pipeline.py   # Process raw Zeek logs
python src/train.py          # Train the model
python -m uvicorn src.api_server:app --port 8000  # API server
streamlit run src/dashboard.py                   # Dashboard
python src/traffic_simulator.py                  # Traffic simulator
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture, data flow diagrams, component relationships |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat categories detected (data exfiltration, DDoS, port scanning, ICMP flood, C2 beaconing) |
| [docs/DATASET_STRATEGY.md](docs/DATASET_STRATEGY.md) | CTU-IoT-23 dataset selection, class imbalance handling, feature engineering rationale |
| [docs/EXPLAINABILITY.md](docs/EXPLAINABILITY.md) | Scoring explainability spec with worked examples for each threat type |

---

## Detection Capabilities

| Threat | Detection Method | Expected Trust Score |
|--------|-----------------|---------------------|
| Data Exfiltration | ML + Rule (high bytes) + Entropy | 15-35 |
| DDoS Flooding | ML + Rule (high packets + failed conn) | 10-30 |
| Port Scanning | ML (S0 state rare) + Entropy | 25-45 |
| ICMP Flood | ML + Rule (ICMP protocol) | 20-40 |
| C2 Beaconing | ML (novel patterns) | 30-48 |

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| ML Model | scikit-learn Isolation Forest (150 trees, 1% contamination) |
| Feature Scaling | StandardScaler |
| API Server | FastAPI + Uvicorn |
| Real-time | WebSocket broadcasting |
| Dashboard | Streamlit + Plotly |
| Data Format | Zeek/Bro conn.log (CTU-IoT-23 dataset) |

---

## Scoring Formula

```
risk_score = 0.70 * ml_score + 0.20 * rule_score + 0.10 * entropy_score
trust_score = 100 - risk_score

Verdict:  >70 = NORMAL | 50-70 = SUSPICIOUS | 30-50 = RISKY | <=30 = ANOMALY
```

---

## Setup (Full)

**Step 1: Navigate to project directory**
```bash
cd iot_sentinel
```

**Step 2: Create and activate virtual environment**
```bash
python3 -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate
```

**Step 3: Install dependencies**
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Step 4: Download CTU-IoT-23 datasets**

Download from https://www.stratosphereips.org/datasets-iot23:
- CTU-Honeypot-Capture-4-1 → data/raw/CTU-Honeypot-Capture-4-1/bro/conn.log.labeled
- CTU-IoT-Malware-Capture-1-1 → data/raw/CTU-IoT-Malware-Capture-1-1/bro/conn.log.labeled

**Step 5: Run pipeline and training**
```bash
python src/data_pipeline.py
python src/train.py
```

**Step 6: Launch the application**
```bash
start_all.bat
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /score | Score network telemetry, returns trust metrics |
| GET | /health | Health check with model_loaded status |
| GET | /metrics | Prometheus-format metrics |
| GET | /metrics/json | JSON metrics |
| WS | /ws | Real-time score broadcasts |
| GET | /api/docs | Swagger documentation |
