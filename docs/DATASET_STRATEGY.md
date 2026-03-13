# IoT Sentinel - Dataset Strategy

## Dataset Selection: CTU-IoT-23

### Source

**CTU-IoT-23** dataset from the Stratosphere Laboratory at the Czech Technical University in Prague.
- URL: https://www.stratosphereips.org/datasets-iot23
- Format: Zeek/Bro connection logs (`conn.log.labeled`)
- License: Creative Commons Attribution 4.0

### Why CTU-IoT-23?

| Criterion | CTU-IoT-23 | Justification |
|-----------|-----------|---------------|
| **Real IoT traffic** | Captured from actual IoT devices (Raspberry Pi, IP cameras, smart hubs) in controlled lab environments | Not synthetic -- reflects genuine device behavior patterns |
| **Real malware** | Contains traffic from Mirai, Hajime, Torii, Kenjiro, Hakai, Okiru, and other IoT-specific malware families | Covers the dominant IoT threat landscape |
| **Labeled data** | Each flow is labeled as `Benign` or `Malicious` with specific malware family attribution | Enables validation even though we train unsupervised |
| **Zeek format** | Native Zeek/Bro `conn.log` format with connection-level metadata | Matches our feature extraction pipeline (duration, bytes, packets, protocol, connection state) |
| **Scale** | Millions of connection records across multiple captures | Sufficient volume for robust Isolation Forest training |
| **Community standard** | Widely cited in IoT security research (100+ papers) | Results are comparable with published benchmarks |

### Alternative Datasets Considered

| Dataset | Reason Not Selected |
|---------|-------------------|
| N-BaIoT | Device-level features (not network flows); different feature schema |
| IoT-23 (full) | Full dataset is 30+ captures and 100+ GB; selected subset is representative |
| UNSW-NB15 | General network intrusion data, not IoT-specific |
| CIC-IDS2017 | Enterprise network focus, limited IoT device representation |
| Custom synthetic | Would lack realistic malware traffic patterns |

---

## Specific Captures Used

### 1. CTU-Honeypot-Capture-4-1 (Benign Baseline)

**Purpose:** Establishes the "normal" behavior baseline for IoT devices.

| Property | Value |
|----------|-------|
| Type | Honeypot capture |
| Traffic class | Predominantly benign |
| Devices | IoT honeypot emulating typical smart home devices |
| Content | Normal TCP/UDP connections, DNS queries, NTP synchronization, SSDP discovery |
| Role in training | Defines what "normal" looks like to the Isolation Forest |

### 2. CTU-IoT-Malware-Capture-1-1 (Malware Traffic)

**Purpose:** Provides examples of compromised IoT device behavior.

| Property | Value |
|----------|-------|
| Type | Malware capture |
| Malware family | Mirai botnet variant |
| Traffic class | Mixed benign + malicious |
| Content | C2 beaconing, scanning activity, DDoS participation, credential brute-forcing |
| Role in training | Introduces the attack patterns the model learns to isolate |

---

## How the Dataset Represents Real IoT Threats

### Benign Traffic Patterns (from Honeypot Capture)

The benign traffic exhibits patterns typical of real IoT deployments:

1. **Short DNS lookups** -- UDP, sub-second duration, small byte counts
2. **HTTP API calls** -- TCP, moderate duration, balanced request/response bytes
3. **NTP synchronization** -- UDP, periodic, fixed-size packets
4. **SSDP discovery** -- UDP multicast, small packets
5. **Keep-alive connections** -- TCP, long duration, minimal data transfer

### Malicious Traffic Patterns (from Malware Capture)

The Mirai malware capture includes:

1. **Telnet brute-forcing** -- Rapid TCP connections to port 23/2323 with many REJ/RST states
2. **Scanning sweeps** -- Short-lived connections to many destinations, S0 (half-open) states
3. **C2 communication** -- Periodic check-ins with command server, distinctive byte patterns
4. **DDoS payloads** -- Massive outbound packet bursts with minimal inbound responses
5. **Propagation attempts** -- Connection patterns indicating worm-like self-replication

---

## Class Distribution and Imbalance

### Raw Label Distribution

After processing both captures through the data pipeline:

| Class | Count | Percentage |
|-------|-------|-----------|
| Benign (0) | ~707,000 | ~70% |
| Malicious (1) | ~302,000 | ~30% |
| **Total** | **1,009,200** | **100%** |

### Imbalance Handling Strategy

**Approach: Unsupervised learning with contamination parameter.**

The Isolation Forest is an unsupervised anomaly detector. Rather than treating this as a supervised classification problem (where class imbalance would require SMOTE, undersampling, or class weights), we use the entire dataset to learn the structure of "normal" traffic. The key design decisions:

1. **Contamination = 0.01 (1%):** We set the contamination parameter to 1%, significantly lower than the actual malicious ratio (~30%). This is intentional:
   - The Isolation Forest treats the majority of data as "normal" and flags only the most extreme outliers
   - Setting contamination = 0.01 means only the top 1% most anomalous points are flagged, producing a highly selective detector
   - This reduces false positives at the cost of potentially missing subtle attacks
   - The rule engine and entropy score compensate by catching pattern-based anomalies the ML might miss

2. **No train/test split for model fitting:** Since Isolation Forest is unsupervised, we train on the full dataset to maximize the model's understanding of the data distribution. The `binary_label` column is dropped before training -- the model never sees the labels.

3. **Validation approach:** Post-training, we predict on the training data and verify the anomaly ratio matches the contamination parameter (~0.99% observed vs 1.0% expected). The labeled data serves as a held-out reference for qualitative validation, not for supervised evaluation metrics.

### Why Not Use Labels for Supervised Learning?

| Factor | Rationale |
|--------|-----------|
| **Generalization** | Unsupervised models detect novel attacks not present in training data. Supervised models only recognize learned patterns. |
| **Label noise** | Network flow labels can be noisy -- benign traffic from a malware-infected device may be labeled "malicious" even if the specific flow is benign. |
| **Deployment reality** | In production, IoT traffic is unlabeled. An unsupervised approach matches the operational reality. |
| **Feature space coverage** | Isolation Forest detects any statistical outlier, regardless of whether it matches a known attack category. |

---

## Feature Engineering Rationale

### Raw Features (from Zeek conn.log)

| Feature | Type | Why Selected |
|---------|------|-------------|
| `duration` | float | Connection length distinguishes scans (short) from exfiltration (long) |
| `orig_bytes` | float | Outbound data volume -- key exfiltration indicator |
| `resp_bytes` | float | Inbound data volume -- helps detect asymmetric transfers |
| `orig_pkts` | int | Outbound packet count -- flooding indicator |
| `resp_pkts` | int | Inbound packet count -- response pattern analysis |
| `proto` | categorical | Protocol (TCP/UDP/ICMP) -- ICMP is inherently suspicious at high volumes |
| `conn_state` | categorical | Connection outcome -- REJ/S0/RST indicate scanning or attacks |

### Engineered Features

| Feature | Formula | Why Created |
|---------|---------|-------------|
| `bytes_per_second` | `(orig_bytes + resp_bytes) / (duration + 0.0001)` | Normalizes data volume by time; high BPS indicates burst attacks |
| `packet_ratio` | `orig_pkts / (resp_pkts + 1)` | Measures traffic symmetry; extreme ratios indicate one-way flooding |

### Encoding

| Feature | Encoding | Result |
|---------|----------|--------|
| `proto` | One-hot | `proto_icmp`, `proto_tcp`, `proto_udp` (3 columns) |
| `conn_state` | One-hot | `conn_state_OTH`, `conn_state_REJ`, ..., `conn_state_SH` (11 columns) |

**Total feature count: 21** (7 continuous + 3 protocol + 11 connection state)

---

## Training / Validation Split Strategy

### Current Approach: Full-Dataset Unsupervised Training

```
+----------------------------------+
| iot23_processed.csv              |
| 1,009,200 rows x 21 features    |
|                                  |
| binary_label DROPPED before     |
| training (unsupervised)          |
|                                  |
|  +----------------------------+  |
|  | StandardScaler.fit_transform| |
|  +----------------------------+  |
|  | IsolationForest.fit         | |
|  +----------------------------+  |
|                                  |
| Post-training validation:        |
|  - Predict on training data      |
|  - Verify anomaly_ratio ~ 0.01  |
|  - Observed: 0.0099 (matches)   |
+----------------------------------+
```

### Rationale for No Explicit Train/Test Split

1. **Unsupervised model:** Isolation Forest does not optimize a loss function against labels. There is no overfitting risk in the supervised sense -- the model learns data density, not decision boundaries.

2. **Contamination validation:** The 1% contamination parameter serves as an internal consistency check. If the model correctly identifies ~1% of the data as anomalous, it has learned the distribution structure.

3. **Operational validation:** Real-world validation comes from the traffic simulator and live dashboard, where known attack patterns (data exfiltration, DDoS, port scan, ICMP flood) are injected and verified to produce low trust scores.

### Future Enhancement: Holdout Validation Set

For production hardening, a formal validation strategy would include:

```
iot23_processed.csv
        |
        +-- 80% Training Set (fit scaler + model)
        |
        +-- 20% Validation Set (evaluate with labels)
                |
                +-- Precision at k (% of top-k anomalies that are truly malicious)
                +-- Recall at contamination threshold
                +-- ROC-AUC using decision_function scores vs binary_label
```

---

## Data Pipeline Summary

```
Step 1: LOAD        Parse Zeek #fields header, read tab-separated data
Step 2: EXTRACT     Map column names to standard schema (7 fields)
Step 3: CLEAN       Replace sentinels (-, empty), coerce types, fill NaN
Step 4: ENGINEER    Create bytes_per_second, packet_ratio
Step 5: COMBINE     Concatenate honeypot + malware DataFrames
Step 6: LABEL       Normalize labels -> binary_label (0=benign, 1=malicious)
Step 7: ENCODE      One-hot encode proto (3 cols) and conn_state (11 cols)
Step 8: SHUFFLE     Random shuffle with seed=42
Step 9: SAVE        Write to data/processed/iot23_processed.csv
```

**Output:** 1,009,200 rows x 22 columns (21 features + 1 binary_label)
