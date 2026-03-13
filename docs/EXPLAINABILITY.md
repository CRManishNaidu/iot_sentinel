# IoT Sentinel - Explainability Specification

## Overview

IoT Sentinel provides multi-layered explanations for every trust score decision. Each scored telemetry record includes not just a numeric score, but the reasoning behind it -- which ML features deviated from normal, which heuristic rules fired, and how traffic entropy contributed to the assessment.

This document specifies the explainability output format, provides worked examples for each threat category, and defines the explanation log format.

---

## Explanation Output Structure

Every call to `engine.score_telemetry()` returns a result dictionary containing these explanation fields:

```json
{
    "trust_score": 22.45,
    "ml_score": 78.32,
    "rule_score": 50,
    "entropy_score": 85.17,
    "confidence": 28.34,
    "verdict": "ANOMALY",
    "risk_factors": ["High origin bytes", "High packet count"],
    "top_features": ["orig_bytes", "bytes_per_second", "packet_ratio"],
    "risk_score_breakdown": {
        "ml_score": 78.32,
        "rule_score": 50,
        "entropy_score": 85.17
    },
    "from_cache": false
}
```

### Field Definitions

| Field | Type | Explanation Role |
|-------|------|-----------------|
| `trust_score` | float [0-100] | Final trust assessment. Higher = more trustworthy. |
| `ml_score` | float [0-100] | How anomalous the ML model considers this flow. Higher = more anomalous. Derived from Isolation Forest `decision_function` passed through sigmoid. |
| `rule_score` | float [0-100] | Sum of penalty points from triggered heuristic rules. Higher = more risky. |
| `entropy_score` | float [0-100] | Shannon entropy-based risk. Low entropy (unidirectional traffic) = high score. |
| `confidence` | float [0-100] | Engine's confidence that the traffic is normal. Uses different weights than trust: 50% ML + 30% rules + 20% entropy. |
| `verdict` | string | Human-readable classification: NORMAL, SUSPICIOUS, RISKY, ANOMALY. |
| `risk_factors` | list[string] | Names of all triggered heuristic rules. Directly explains which rules contributed. |
| `top_features` | list[string] | Top 3 features with the largest absolute deviation from training mean (via scaler). Shows which specific measurements drove the ML decision. |
| `risk_score_breakdown` | dict | Individual component scores for transparency into the weighted combination. |

---

## Worked Examples

### Example 1: Data Exfiltration Detection

**Input Telemetry:**
```json
{
    "device_id": "camera_01",
    "duration": 12.5,
    "orig_bytes": 150000,
    "resp_bytes": 2500,
    "orig_pkts": 450,
    "resp_pkts": 80,
    "proto": "TCP",
    "conn_state": "SF"
}
```

**Explanation Output:**
```
=================================================================
ANOMALY EXPLANATION REPORT
=================================================================
Device:       camera_01
Timestamp:    2026-03-02T14:23:45Z
Trust Score:  18.7 / 100
Verdict:      ANOMALY
Confidence:   22.1%
-----------------------------------------------------------------
RISK SCORE BREAKDOWN:
  ML Score:       82.4 / 100  (weight: 70%)  -->  contribution: 57.7
  Rule Score:     50   / 100  (weight: 20%)  -->  contribution: 10.0
  Entropy Score:  73.2 / 100  (weight: 10%)  -->  contribution:  7.3
  -----------------------------------------
  Composite Risk: 75.0 / 100
  Trust Score:    100.0 - 75.0 = 25.0
-----------------------------------------------------------------
TRIGGERED RULES (2 of 4):
  [!] High origin bytes      (+30 pts)  orig_bytes = 150,000 > threshold 10,000
  [!] High packet count      (+20 pts)  total_pkts = 530 > threshold 100
-----------------------------------------------------------------
TOP CONTRIBUTING FEATURES (ML model):
  1. orig_bytes        = 150,000    (deviation: +8.2 sigma from training mean)
  2. bytes_per_second  = 12,200     (deviation: +6.1 sigma from training mean)
  3. packet_ratio      = 5.63       (deviation: +3.8 sigma from training mean)
-----------------------------------------------------------------
ENTROPY ANALYSIS:
  Traffic distribution: [orig_bytes=150000, resp_bytes=2500,
                         orig_pkts=450, resp_pkts=80]
  Shannon Entropy:      0.535 bits (max possible: 2.0 bits)
  Normalized:           0.268
  Entropy Risk Score:   73.2 (LOW entropy = HIGH risk)
  Interpretation:       Traffic heavily skewed toward outbound data transfer.
                        Pattern consistent with data exfiltration.
-----------------------------------------------------------------
EVIDENCE SUMMARY:
  - 150,000 bytes outbound vs 2,500 inbound (60:1 ratio)
  - 450 outbound packets in 12.5 seconds (sustained high throughput)
  - Successfully completed connection (SF) suggests deliberate transfer
  - Pattern matches data exfiltration profile
-----------------------------------------------------------------
RECOMMENDATION:  Immediate investigation recommended.
                 Isolate device camera_01 from network.
                 Check for unauthorized outbound connections.
=================================================================
```

### Example 2: DDoS Flood Detection

**Input Telemetry:**
```json
{
    "device_id": "thermostat_03",
    "duration": 1.2,
    "orig_bytes": 15000,
    "resp_bytes": 200,
    "orig_pkts": 1500,
    "resp_pkts": 10,
    "proto": "TCP",
    "conn_state": "REJ"
}
```

**Explanation Output:**
```
=================================================================
ANOMALY EXPLANATION REPORT
=================================================================
Device:       thermostat_03
Timestamp:    2026-03-02T14:25:12Z
Trust Score:  12.3 / 100
Verdict:      ANOMALY
Confidence:   15.8%
-----------------------------------------------------------------
RISK SCORE BREAKDOWN:
  ML Score:       88.1 / 100  (weight: 70%)  -->  contribution: 61.7
  Rule Score:     65   / 100  (weight: 20%)  -->  contribution: 13.0
  Entropy Score:  91.4 / 100  (weight: 10%)  -->  contribution:  9.1
  -----------------------------------------
  Composite Risk: 83.8 / 100
  Trust Score:    100.0 - 83.8 = 16.2
-----------------------------------------------------------------
TRIGGERED RULES (3 of 4):
  [!] High origin bytes      (+30 pts)  orig_bytes = 15,000 > threshold 10,000
  [!] High packet count      (+20 pts)  total_pkts = 1,510 > threshold 100
  [!] Failed connection      (+25 pts)  conn_state = REJ (rejected)
  Total: 75 pts (capped to 65 after normalization)
-----------------------------------------------------------------
TOP CONTRIBUTING FEATURES (ML model):
  1. packet_ratio      = 150.0      (deviation: +12.4 sigma)
  2. orig_pkts         = 1,500      (deviation: +9.7 sigma)
  3. bytes_per_second  = 12,666.7   (deviation: +7.2 sigma)
-----------------------------------------------------------------
ENTROPY ANALYSIS:
  Shannon Entropy:      0.173 bits (extremely low)
  Entropy Risk Score:   91.4
  Interpretation:       Almost all traffic is outbound packets with
                        near-zero response. Classic flooding signature.
-----------------------------------------------------------------
EVIDENCE SUMMARY:
  - 1,500 packets sent in 1.2 seconds (1,250 pps)
  - Connection rejected (REJ) -- target refusing connections
  - 150:1 packet ratio (extreme asymmetry)
  - Pattern matches DDoS/flooding attack profile
-----------------------------------------------------------------
RECOMMENDATION:  CRITICAL. Device likely participating in DDoS attack.
                 Immediately isolate thermostat_03.
                 Check for botnet infection (Mirai variant suspected).
=================================================================
```

### Example 3: Port Scan Detection

**Input Telemetry:**
```json
{
    "device_id": "hub_07",
    "duration": 0.3,
    "orig_bytes": 400,
    "resp_bytes": 0,
    "orig_pkts": 50,
    "resp_pkts": 0,
    "proto": "TCP",
    "conn_state": "S0"
}
```

**Explanation Output:**
```
=================================================================
ANOMALY EXPLANATION REPORT
=================================================================
Device:       hub_07
Timestamp:    2026-03-02T14:27:33Z
Trust Score:  31.5 / 100
Verdict:      RISKY
Confidence:   38.2%
-----------------------------------------------------------------
RISK SCORE BREAKDOWN:
  ML Score:       72.8 / 100  (weight: 70%)  -->  contribution: 51.0
  Rule Score:     0    / 100  (weight: 20%)  -->  contribution:  0.0
  Entropy Score:  100  / 100  (weight: 10%)  -->  contribution: 10.0
  -----------------------------------------
  Composite Risk: 61.0 / 100
  Trust Score:    100.0 - 61.0 = 39.0
-----------------------------------------------------------------
TRIGGERED RULES (0 of 4):
  (No rules triggered -- S0 state is detected by ML, not rules)
-----------------------------------------------------------------
TOP CONTRIBUTING FEATURES (ML model):
  1. conn_state_S0     = 1.0        (deviation: +4.5 sigma -- rare state)
  2. packet_ratio      = 50.0       (deviation: +3.9 sigma)
  3. resp_bytes        = 0          (deviation: -1.8 sigma -- zero response)
-----------------------------------------------------------------
ENTROPY ANALYSIS:
  Shannon Entropy:      0.0 bits (minimum possible)
  Entropy Risk Score:   100.0
  Interpretation:       Completely one-directional traffic with zero
                        response. Consistent with unanswered probes.
-----------------------------------------------------------------
EVIDENCE SUMMARY:
  - Half-open connection (SYN sent, no SYN-ACK received)
  - Zero response bytes and packets (target unresponsive or filtered)
  - Very short duration (0.3s) suggests probe-and-move-on behavior
  - ML model flags conn_state_S0 as highly unusual
  - No heuristic rules triggered -- this is a pure ML detection
-----------------------------------------------------------------
RECOMMENDATION:  Investigate hub_07 for scanning activity.
                 Check if device has been compromised.
                 Monitor for sequential connections to different ports.
=================================================================
```

### Example 4: Normal Traffic (No Alert)

**Input Telemetry:**
```json
{
    "device_id": "sensor_02",
    "duration": 2.1,
    "orig_bytes": 1200,
    "resp_bytes": 4500,
    "orig_pkts": 15,
    "resp_pkts": 25,
    "proto": "TCP",
    "conn_state": "SF"
}
```

**Explanation Output:**
```
=================================================================
NORMAL TRAFFIC REPORT
=================================================================
Device:       sensor_02
Timestamp:    2026-03-02T14:30:01Z
Trust Score:  87.3 / 100
Verdict:      NORMAL
Confidence:   89.1%
-----------------------------------------------------------------
RISK SCORE BREAKDOWN:
  ML Score:       12.8 / 100  (weight: 70%)  -->  contribution:  9.0
  Rule Score:     0    / 100  (weight: 20%)  -->  contribution:  0.0
  Entropy Score:  28.5 / 100  (weight: 10%)  -->  contribution:  2.9
  -----------------------------------------
  Composite Risk: 11.9 / 100
  Trust Score:    100.0 - 11.9 = 88.1
-----------------------------------------------------------------
TRIGGERED RULES: None
-----------------------------------------------------------------
TOP CONTRIBUTING FEATURES:
  1. resp_bytes        = 4,500      (deviation: +0.8 sigma -- within normal)
  2. duration          = 2.1        (deviation: +0.5 sigma -- within normal)
  3. orig_bytes        = 1,200      (deviation: +0.3 sigma -- within normal)
  All features within 1.5 sigma of training mean -- consistent with normal.
-----------------------------------------------------------------
ENTROPY ANALYSIS:
  Shannon Entropy:      1.43 bits (balanced traffic)
  Entropy Risk Score:   28.5
  Interpretation:       Balanced bidirectional communication.
                        Typical of legitimate IoT API calls.
=================================================================
```

### Example 5: ICMP Flood Detection

**Input Telemetry:**
```json
{
    "device_id": "device_05",
    "duration": 2.0,
    "orig_bytes": 5000,
    "resp_bytes": 5000,
    "orig_pkts": 800,
    "resp_pkts": 800,
    "proto": "ICMP",
    "conn_state": "SF"
}
```

**Explanation Output:**
```
=================================================================
ANOMALY EXPLANATION REPORT
=================================================================
Device:       device_05
Timestamp:    2026-03-02T14:32:15Z
Trust Score:  24.8 / 100
Verdict:      ANOMALY
Confidence:   30.2%
-----------------------------------------------------------------
RISK SCORE BREAKDOWN:
  ML Score:       76.5 / 100  (weight: 70%)  -->  contribution: 53.6
  Rule Score:     35   / 100  (weight: 20%)  -->  contribution:  7.0
  Entropy Score:  0.0  / 100  (weight: 10%)  -->  contribution:  0.0
  -----------------------------------------
  Composite Risk: 60.6 / 100
  Trust Score:    100.0 - 60.6 = 39.4
-----------------------------------------------------------------
TRIGGERED RULES (2 of 4):
  [!] ICMP protocol         (+15 pts)  proto = ICMP
  [!] High packet count     (+20 pts)  total_pkts = 1,600 > threshold 100
-----------------------------------------------------------------
TOP CONTRIBUTING FEATURES (ML model):
  1. proto_icmp        = 1.0        (deviation: +5.2 sigma -- rare protocol)
  2. orig_pkts         = 800        (deviation: +4.8 sigma)
  3. resp_pkts         = 800        (deviation: +4.1 sigma)
-----------------------------------------------------------------
ENTROPY ANALYSIS:
  Shannon Entropy:      2.0 bits (maximum -- perfectly balanced)
  Entropy Risk Score:   0.0
  Interpretation:       Perfectly symmetric traffic (equal in all 4 fields).
                        Entropy does NOT contribute to risk for this pattern.
                        Detection relies entirely on ML + rules.
-----------------------------------------------------------------
EVIDENCE SUMMARY:
  - 1,600 total ICMP packets in 2 seconds (800 pps)
  - ICMP at this volume is abnormal for IoT devices
  - Symmetric pattern suggests echo flood (ping flood)
  - ML model strongly flags the proto_icmp feature
  - Note: entropy score is 0 because traffic is perfectly balanced --
    this illustrates why the multi-layer approach is important
=================================================================
```

---

## Explanation Log Format

For production logging, each scored event produces a structured JSON explanation log entry:

```json
{
    "timestamp": "2026-03-02T14:23:45.123Z",
    "device_id": "camera_01",
    "input": {
        "duration": 12.5,
        "orig_bytes": 150000,
        "resp_bytes": 2500,
        "orig_pkts": 450,
        "resp_pkts": 80,
        "proto": "TCP",
        "conn_state": "SF"
    },
    "scores": {
        "trust_score": 18.7,
        "ml_score": 82.4,
        "rule_score": 50,
        "entropy_score": 73.2,
        "confidence": 22.1
    },
    "verdict": "ANOMALY",
    "explanation": {
        "risk_factors": ["High origin bytes", "High packet count"],
        "top_features": ["orig_bytes", "bytes_per_second", "packet_ratio"],
        "feature_deviations": {
            "orig_bytes": "+8.2 sigma",
            "bytes_per_second": "+6.1 sigma",
            "packet_ratio": "+3.8 sigma"
        },
        "entropy_detail": {
            "shannon_entropy": 0.535,
            "max_entropy": 2.0,
            "normalized": 0.268,
            "interpretation": "Traffic heavily skewed toward outbound data transfer"
        }
    },
    "risk_score_breakdown": {
        "ml_contribution": 57.7,
        "rule_contribution": 10.0,
        "entropy_contribution": 7.3,
        "composite_risk": 75.0
    },
    "processing_time_ms": 12.3
}
```

---

## Dashboard Explainability Features

The Streamlit dashboard surfaces these explanations through:

1. **Trust Score Gauge** -- Color-coded (green/amber/orange/red) radial gauge with dynamic threshold line
2. **Verdict Badge** -- Styled badge (NORMAL/SUSPICIOUS/RISKY/ANOMALY) with color coding
3. **Risk Factor Display** -- Count of triggered rules shown in the info panel
4. **Score Breakdown** -- Individual ML, rule, and entropy scores visible in the API response
5. **Anomaly Heatmap** -- Time-bucketed anomaly frequency showing when anomalies cluster
6. **Device Health Table** -- Per-device trust score, verdict, confidence, and anomaly count
7. **Recent Events Table** -- Last 20 events with timestamp, device, score, verdict, risk factors, and confidence

---

## Why Multi-Layer Explainability Matters

| Layer | What It Explains | Limitation Addressed |
|-------|-----------------|---------------------|
| **ML Score** | Statistical deviation from learned normal patterns | Catches novel/unknown attacks but is a "black box" -- top_features provides interpretability |
| **Rule Score** | Specific, human-defined threat indicators | Easy to understand but can miss novel attacks -- ML compensates |
| **Entropy Score** | Traffic directionality and balance | Catches data exfiltration patterns that rules might miss, but can't detect symmetric attacks (ICMP flood) -- ML compensates |
| **Top Features** | Which specific measurements drove the ML decision | Bridges the gap between "anomalous" and "why" -- maps statistical deviation to concrete network metrics |
| **Risk Factors** | Which human-defined rules triggered | Provides actionable, domain-specific explanations that security analysts can immediately act on |
