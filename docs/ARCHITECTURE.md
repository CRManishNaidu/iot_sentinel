# IoT Sentinel - System Architecture

## High-Level Architecture Diagram

```
+===========================================================================+
|                         OFFLINE / TRAINING PHASE                          |
|                                                                           |
|  +-------------------------+    +------------------+    +---------------+ |
|  | CTU-IoT-23 Raw Logs     |    | Data Pipeline    |    | Model Trainer | |
|  |                         |    | (data_pipeline.py)|    | (train.py)    | |
|  | CTU-Honeypot-Capture    |--->|                  |--->|               | |
|  |   (benign IoT traffic)  |    | 1. Parse Zeek    |    | StandardScaler| |
|  |                         |    | 2. Extract fields |    | IsolationForest|
|  | CTU-Malware-Capture     |--->| 3. Clean & fill  |    | (150 trees,   | |
|  |   (Mirai botnet traffic)|    | 4. Engineer feats|    |  1% contam.)  | |
|  +-------------------------+    | 5. Combine       |    +-------+-------+ |
|                                 | 6. Label (bin)   |            |         |
|                                 | 7. One-hot encode|    +-------v-------+ |
|                                 | 8. Shuffle       |    | Model Artifacts| |
|                                 +------------------+    |               | |
|                                        |                | isolation_    | |
|                                        v                |  forest.pkl  | |
|                                 +------------------+    | scaler.pkl   | |
|                                 | iot23_processed  |    | metadata.json| |
|                                 | .csv             |    +---------------+ |
|                                 | 1,009,200 rows   |                     |
|                                 | 21 features      |                     |
|                                 +------------------+                     |
+===========================================================================+

+===========================================================================+
|                         ONLINE / INFERENCE PHASE                          |
|                                                                           |
|  +-------------------+     +--------------------+     +-----------------+ |
|  | Traffic Simulator  |     |   API Server       |     |  Scoring Engine | |
|  | (traffic_simulator |     |   (api_server.py)  |     |  (engine.py)    | |
|  |  .py)              |     |                    |     |                 | |
|  |                    |     |  FastAPI + Uvicorn  |     | +-------------+ | |
|  | 10 virtual IoT     | POST|                    |     | | ML Scorer   | | |
|  | devices            |---->|  /score endpoint   |---->| | (Isolation  | | |
|  |                    | JSON|                    |     | |  Forest)    | | |
|  | Normal profiles:   |     |  Request Validation|     | +-------------+ | |
|  |  - web_browsing    |     |  Rate Limiting     |     |        |        | |
|  |  - dns_query       |     |  CORS Middleware   |     | +------v------+ | |
|  |  - file_transfer   |     |  Timing Headers    |     | | Rule Engine | | |
|  |  - ping            |     |                    |     | | (4 heuristic| | |
|  |                    |     |  /health           |     | |  rules)     | | |
|  | Attack patterns:   |     |  /metrics          |     | +-------------+ | |
|  |  - data_exfil      |     |  /metrics/json     |     |        |        | |
|  |  - ddos_flood      |     |  /api/docs         |     | +------v------+ | |
|  |  - port_scan       |     |                    |     | | Entropy     | | |
|  |  - icmp_flood      |     |                    |<----| | Calculator  | | |
|  |  - suspicious      |     |   ScoreResponse    |     | +-------------+ | |
|  +-------------------+     |                    |     |        |        | |
|                             |   WebSocket /ws    |     | +------v------+ | |
|                             |   Broadcast ----+  |     | | Composite   | | |
|                             +----------------+|--+     | | Trust Score | | |
|                                              ||        | | (weighted   | | |
|  +-------------------+                      ||        | |  blend)     | | |
|  | Dashboard          |<--------------------+|        | +-------------+ | |
|  | (dashboard.py)     |   WebSocket Stream   |        +-----------------+ |
|  |                    |   (real-time scores)  |                           |
|  | Streamlit App      |                       |                           |
|  |                    |                       |                           |
|  | +---------------+  |                       |                           |
|  | | Trust Gauge   |  |                       |                           |
|  | +---------------+  |                       |                           |
|  | | Score Timeline|  |                       |                           |
|  | +---------------+  |                       |                           |
|  | | Anomaly       |  |                       |                           |
|  | | Heatmap       |  |                       |                           |
|  | +---------------+  |                       |                           |
|  | | Device Health |  |                       |                           |
|  | | Table         |  |                       |                           |
|  | +---------------+  |                       |                           |
|  | | Recent Events |  |                       |                           |
|  | +---------------+  |                       |                           |
|  +-------------------+                       |                           |
+===========================================================================+
```

## Component-Level Diagram

```
                    +-------------------------------------------------+
                    |              IoT Sentinel System                 |
                    +-------------------------------------------------+
                    |                                                  |
   +----------------v-----------------+    +-------------------------+|
   |        Data Ingestion Layer      |    |    Model Training Layer  ||
   |                                  |    |                         ||
   |  +----------+    +-----------+   |    |  +--------+  +--------+ ||
   |  |Zeek/Bro  |    |Data       |   |    |  |Standard|  |Isolation|| |
   |  |conn.log  |--->|Pipeline   |---+--->|  |Scaler  |  |Forest  || |
   |  |Parser    |    |(ETL)      |   |    |  +--------+  +--------+ ||
   |  +----------+    +-----------+   |    |       |           |     ||
   +----------------------------------+    |  +----v-----------v---+ ||
                                           |  |  Model Artifacts   | ||
                                           |  |  (.pkl + .json)    | ||
                                           |  +--------------------+ ||
                                           +-------------------------+|
                                                      |               |
   +----------------------------------+    +----------v--------------+|
   |     Real-Time Inference Layer    |    |    Scoring Engine       ||
   |                                  |    |                         ||
   |  +----------+    +-----------+   |    |  +---------+            ||
   |  |Traffic   |    |FastAPI    |   |    |  |Feature  |            ||
   |  |Simulator |--->|Server     |---+--->|  |Extract  |            ||
   |  |(or real  |    |(/score)   |   |    |  +---------+            ||
   |  | devices) |    +-----------+   |    |       |                 ||
   |  +----------+         |         |    |  +----v----+             ||
   |                       |         |    |  |ML Score |  (70% wt)   ||
   |                  +----v----+    |    |  |(sigmoid)|             ||
   |                  |WebSocket|    |    |  +---------+             ||
   |                  |Broadcast|    |    |       |                  ||
   |                  +---------+    |    |  +----v----+             ||
   |                       |         |    |  |Rule Scr |  (20% wt)   ||
   +----------------------------------+    |  |(heurist)|             ||
                           |               |  +---------+             ||
   +----------------------------------+    |       |                  ||
   |     Presentation Layer           |    |  +----v----+             ||
   |                                  |    |  |Entropy  |  (10% wt)   ||
   |  +----------+    +-----------+   |    |  |Score    |             ||
   |  |Streamlit |    |Plotly     |   |    |  +---------+             ||
   |  |Dashboard |<---|Charts     |   |    |       |                  ||
   |  +----------+    +-----------+   |    |  +----v-----------+      ||
   |       ^                          |    |  |Composite Trust |      ||
   |       |     WebSocket Client     |    |  |Score + Verdict |      ||
   |       +--------------------------+    |  +----------------+      ||
   +----------------------------------+    +-------------------------+|
                                           +--------------------------+
```

## Data Flow Sequence

```
1. TRAINING (one-time, offline):

   conn.log.labeled --> data_pipeline.py --> iot23_processed.csv --> train.py
                        (parse, clean,       (1M rows x 22 cols)    (fit scaler,
                         engineer, encode)                           fit IsolationForest)
                                                                         |
                                                                         v
                                                                    models/
                                                                    +-- isolation_forest.pkl
                                                                    +-- scaler.pkl
                                                                    +-- metadata.json

2. INFERENCE (real-time, continuous):

   IoT Device / Simulator
         |
         | HTTP POST /score  {duration, orig_bytes, resp_bytes, ...}
         v
   +--api_server.py--+
   | Validate input  |
   | Forward to      |-----> engine.py
   | engine          |       |
   |                 |       +-- _extract_features()   : map raw -> 21 features
   |                 |       +-- scaler.transform()    : standardize
   |                 |       +-- model.decision_function() -> sigmoid -> ml_score
   |                 |       +-- _calculate_rule_score(): 4 heuristic rules
   |                 |       +-- _calculate_entropy_score(): Shannon entropy
   |                 |       +-- Composite: risk = 0.7*ML + 0.2*Rule + 0.1*Entropy
   |                 |       +-- trust = 100 - risk
   |                 |       +-- verdict: NORMAL/SUSPICIOUS/RISKY/ANOMALY
   |                 |<----- return result
   |                 |
   | Return JSON     |-----> HTTP Response to caller
   | Broadcast WS    |-----> WebSocket push to dashboard
   +-----------------+
         |
         v (WebSocket)
   +--dashboard.py--+
   | Update gauges  |
   | Update timeline|
   | Update heatmap |
   | Update tables  |
   +----------------+
```

## Trust Score Computation

```
                   +------------------+
                   | Raw Telemetry    |
                   | (7 input fields) |
                   +--------+---------+
                            |
              +-------------+-------------+
              |             |             |
     +--------v--------+   |    +--------v--------+
     | Feature Extract  |   |    | Rule Engine     |
     | (21 features)    |   |    | (4 heuristics)  |
     +--------+---------+   |    +--------+---------+
              |             |             |
     +--------v--------+   |             |
     | StandardScaler   |   |             |
     +--------+---------+   |             |
              |             |             |
     +--------v--------+  +v-----------+ |
     | IsolationForest  |  | Entropy    | |
     | decision_function|  | Calculator | |
     +--------+---------+  +-----+------+ |
              |                  |         |
     +--------v--------+        |         |
     | sigmoid(-score)  |        |         |
     | * 100            |        |         |
     +--------+---------+        |         |
              |                  |         |
              v                  v         v
     +--------+--------+--------+--------+---------+
     |        WEIGHTED COMBINATION                  |
     |                                              |
     |  risk = 0.70 * ml_score                      |
     |       + 0.20 * rule_score                    |
     |       + 0.10 * entropy_score                 |
     |                                              |
     |  trust_score = 100.0 - risk                  |
     +---------------------+------------------------+
                            |
              +-------------+-------------+
              |             |             |
        trust > 70    70 >= trust > 50   trust <= 30
              |             |             |
         +----v----+  +----v------+  +---v------+
         | NORMAL  |  |SUSPICIOUS|  | ANOMALY  |
         +---------+  +----------+  +----------+
                            |
                      50 >= trust > 30
                            |
                       +----v----+
                       |  RISKY  |
                       +---------+
```

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Data Ingestion | Python, Pandas | Parse Zeek/Bro connection logs |
| Feature Engineering | Pandas, NumPy | Derive bytes_per_second, packet_ratio, one-hot encoding |
| ML Model | scikit-learn IsolationForest | Unsupervised anomaly detection (150 trees, 1% contamination) |
| Feature Scaling | scikit-learn StandardScaler | Zero-mean, unit-variance normalization |
| API Server | FastAPI + Uvicorn | REST API + WebSocket server |
| Real-time Transport | WebSocket | Push-based score broadcasting to dashboard |
| Dashboard | Streamlit + Plotly | Real-time SOC monitoring interface |
| Traffic Simulation | Python requests | Synthetic normal + attack traffic generation |

## Network Ports

| Service | Port | Protocol |
|---------|------|----------|
| API Server | 8000 | HTTP/WS |
| Dashboard | 8501 | HTTP |

## File Structure

```
iot_sentinel/
+-- README.md                     # Setup guide
+-- requirements.txt              # Python dependencies
+-- start_all.bat                 # Windows orchestrator
+-- docs/
|   +-- ARCHITECTURE.md           # This file
|   +-- THREAT_MODEL.md           # Threat detection documentation
|   +-- DATASET_STRATEGY.md       # Dataset selection rationale
|   +-- EXPLAINABILITY.md         # Scoring explainability spec
+-- data/
|   +-- raw/                      # CTU-IoT-23 Zeek connection logs
|   +-- processed/                # Pipeline output (iot23_processed.csv)
+-- models/
|   +-- isolation_forest.pkl      # Trained Isolation Forest
|   +-- scaler.pkl                # Fitted StandardScaler
|   +-- metadata.json             # Feature names, hyperparameters
+-- src/
    +-- data_pipeline.py          # ETL: raw logs -> processed CSV
    +-- train.py                  # Model training script
    +-- engine.py                 # Scoring engine (ML + rules + entropy)
    +-- api_server.py             # FastAPI REST + WebSocket server
    +-- dashboard.py              # Streamlit real-time SOC dashboard
    +-- traffic_simulator.py      # Synthetic traffic generator
```
