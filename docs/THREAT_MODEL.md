# IoT Sentinel - Threat Model

## Overview

IoT Sentinel is designed to detect network-level threats targeting IoT device fleets. The system uses a combination of unsupervised machine learning (Isolation Forest), heuristic rules, and entropy analysis to identify anomalous network behavior indicative of compromise or attack.

This document catalogs the specific threat categories the system detects, how each is identified, and the detection mechanisms involved.

---

## Threat Categories

### 1. Data Exfiltration

**MITRE ATT&CK:** T1041 (Exfiltration Over C2 Channel)

**Description:** A compromised IoT device transmits large volumes of data to an external destination. This is characteristic of stolen credentials, captured video/audio from cameras, or sensitive data being siphoned from the local network through a compromised device.

**Network Signature:**
- Extremely high `orig_bytes` (50,000 - 200,000+ bytes per connection)
- Low `resp_bytes` relative to `orig_bytes` (asymmetric transfer)
- Moderate-to-long connection duration (8-25 seconds)
- Protocol: TCP with successful completion (conn_state: SF)

**Detection Mechanisms:**
| Mechanism | How It Fires | Contribution |
|-----------|-------------|--------------|
| ML (Isolation Forest) | Large `orig_bytes` and high `bytes_per_second` deviate significantly from the training distribution of normal IoT traffic | 70% weight |
| Rule Engine | `high_orig_bytes` rule triggers when `orig_bytes > 10,000` (30 penalty points) | 20% weight |
| Entropy Score | Heavily skewed toward `orig_bytes` produces low Shannon entropy across the 4 traffic fields, indicating unidirectional flow | 10% weight |

**Expected Trust Score Range:** 15 - 35 (verdict: ANOMALY)

**Real-World Examples:**
- Mirai variant exfiltrating credential databases
- Compromised IP camera streaming captured footage to C2 server
- Smart hub leaking WiFi credentials to external host

---

### 2. DDoS / Flooding Attacks

**MITRE ATT&CK:** T1498 (Network Denial of Service), T1499 (Endpoint Denial of Service)

**Description:** A compromised IoT device participates in a distributed denial-of-service attack, sending massive volumes of packets to overwhelm a target. This is the signature behavior of Mirai-family botnets, which recruit IoT devices into DDoS armies.

**Network Signature:**
- Very short connection duration (0.3 - 3.0 seconds)
- Extremely high `orig_pkts` (800 - 3,000 packets)
- Minimal `resp_pkts` (5 - 30) -- target may not respond
- Failed connection state: REJ (target rejecting the flood)
- High `bytes_per_second` throughput

**Detection Mechanisms:**
| Mechanism | How It Fires | Contribution |
|-----------|-------------|--------------|
| ML (Isolation Forest) | Extreme `packet_ratio` (high orig, near-zero resp) and abnormal `bytes_per_second` are strong isolation signals | 70% weight |
| Rule Engine | `high_packet_counts` triggers at orig_pkts + resp_pkts > 100 (20 pts); `failed_connection` triggers for REJ state (25 pts) | 20% weight |
| Entropy Score | Extreme asymmetry between orig_pkts and resp_pkts produces very low entropy | 10% weight |

**Expected Trust Score Range:** 10 - 30 (verdict: ANOMALY)

**Real-World Examples:**
- Mirai botnet SYN flood against Dyn DNS (2016)
- IoT-based UDP amplification attacks
- HTTP flood from compromised smart appliances

---

### 3. Port Scanning / Reconnaissance

**MITRE ATT&CK:** T1046 (Network Service Scanning)

**Description:** An attacker (or compromised device) systematically probes network ports to discover running services and potential vulnerabilities. This is typically the first phase of a multi-stage attack, preceding exploitation.

**Network Signature:**
- Very short connection duration (0.1 - 1.5 seconds) -- probe and move on
- Minimal data transfer: low `orig_bytes` (100 - 800) and near-zero `resp_bytes`
- Half-open connections: `conn_state: S0` (SYN sent, no SYN-ACK received)
- Low packet counts but high connection frequency

**Detection Mechanisms:**
| Mechanism | How It Fires | Contribution |
|-----------|-------------|--------------|
| ML (Isolation Forest) | S0 connection states are rare in training data (most legitimate connections complete as SF); combined with tiny byte counts, these points are easily isolated | 70% weight |
| Rule Engine | `failed_connection` triggers if state is REJ/RST (25 pts). S0 state alone doesn't trigger a rule, but ML catches it. | 20% weight |
| Entropy Score | Near-zero values across all 4 fields produce degenerate entropy | 10% weight |

**Expected Trust Score Range:** 25 - 45 (verdict: RISKY to ANOMALY)

**Real-World Examples:**
- Hajime botnet scanning for open Telnet ports (23, 2323)
- Nmap-style SYN scans from compromised IoT gateway
- Shodan-like automated IoT discovery probes

---

### 4. ICMP Flood / Ping Flood

**MITRE ATT&CK:** T1498.001 (Direct Network Flood)

**Description:** An attacker uses ICMP echo requests (ping) to overwhelm a target's network bandwidth or processing capacity. ICMP is also used for covert tunneling (ICMP tunneling) to bypass firewalls.

**Network Signature:**
- ICMP protocol (unusual for legitimate IoT traffic beyond occasional pings)
- Symmetric high packet counts: both `orig_pkts` and `resp_pkts` in the 300-1,500 range
- Moderate byte counts (1,000 - 10,000 in both directions)
- Short-to-moderate duration (0.5 - 4.0 seconds)

**Detection Mechanisms:**
| Mechanism | How It Fires | Contribution |
|-----------|-------------|--------------|
| ML (Isolation Forest) | ICMP traffic with high packet counts is extremely rare in the training distribution; the `proto_icmp=1` feature combined with high packet counts creates strong isolation | 70% weight |
| Rule Engine | `icmp_protocol` rule triggers for any ICMP traffic (15 pts); `high_packet_counts` triggers at > 100 total packets (20 pts) | 20% weight |
| Entropy Score | Symmetric traffic (equal orig/resp) actually produces high entropy (balanced), so entropy contributes less to this detection | 10% weight |

**Expected Trust Score Range:** 20 - 40 (verdict: RISKY to ANOMALY)

**Real-World Examples:**
- Smurf attack amplification via IoT devices
- ICMP tunnel for C2 communication bypassing firewall rules
- Ping-of-death variants targeting embedded systems

---

### 5. Botnet Command-and-Control (C2) Beaconing / Suspicious Behavior

**MITRE ATT&CK:** T1071 (Application Layer Protocol), T1571 (Non-Standard Port)

**Description:** Compromised devices exhibit unusual communication patterns that don't match any specific attack profile but deviate from learned normal behavior. This includes C2 beaconing (periodic check-ins with a command server), lateral movement attempts, and protocol misuse.

**Network Signature:**
- Moderate data transfer (8,000 - 40,000 bytes)
- UDP protocol (unusual for most IoT device profiles)
- Abnormal connection states: S0 (half-open) or REJ (rejected)
- Duration and packet counts that fall outside normal device profiles
- Patterns designed to evade simple rule-based detection

**Detection Mechanisms:**
| Mechanism | How It Fires | Contribution |
|-----------|-------------|--------------|
| ML (Isolation Forest) | This is the ML model's primary strength -- detecting anomalies that don't match any known rule pattern. The combination of moderate bytes over UDP with failed connection states isolates these points from the training distribution | 70% weight |
| Rule Engine | May trigger `high_orig_bytes` (30 pts) and/or `failed_connection` (25 pts) depending on specific values | 20% weight |
| Entropy Score | Variable; depends on traffic symmetry | 10% weight |

**Expected Trust Score Range:** 30 - 48 (verdict: RISKY to SUSPICIOUS)

**Real-World Examples:**
- Mirai C2 check-in beacons (periodic UDP to hardcoded IP)
- Hajime P2P communication over non-standard ports
- Lateral movement via UDP broadcast scanning

---

## Detection Matrix Summary

| Threat | ML Score | Rule Score | Entropy Score | Typical Trust | Verdict |
|--------|----------|------------|---------------|---------------|---------|
| Data Exfiltration | High (40-60) | High (30+ pts) | High (skewed) | 15-35 | ANOMALY |
| DDoS Flood | Very High (50-75) | High (45+ pts) | High (asymmetric) | 10-30 | ANOMALY |
| Port Scan | High (45-65) | Medium (0-25 pts) | High (degenerate) | 25-45 | RISKY/ANOMALY |
| ICMP Flood | High (55-80) | Medium (35 pts) | Low (symmetric) | 20-40 | RISKY/ANOMALY |
| C2 Beaconing | Very High (70-92) | Variable (0-55 pts) | Variable | 30-48 | RISKY/SUSPICIOUS |

## Rule Engine Detail

| Rule | Condition | Penalty Points | Primary Threat |
|------|-----------|---------------|----------------|
| High origin bytes | `orig_bytes > 10,000` | 30 | Data exfiltration |
| High packet count | `orig_pkts + resp_pkts > 100` | 20 | DDoS, ICMP flood |
| ICMP protocol | `proto == "ICMP"` | 15 | ICMP flood/tunnel |
| Failed connection | `conn_state in [REJ, RST]` | 25 | Port scan, DDoS |

**Maximum combined rule score:** 90 points (all four rules triggered simultaneously).

## Limitations and Known Gaps

1. **Encrypted traffic:** The system operates on connection metadata (Zeek conn.log), not payload inspection. Encrypted C2 channels using standard HTTPS on port 443 may appear as normal web browsing.

2. **Slow-and-low attacks:** Extremely slow data exfiltration (trickle exfil) that stays below the `orig_bytes > 10,000` threshold may evade rule detection, though the ML model may still flag the overall pattern.

3. **Zero-day patterns:** The Isolation Forest is trained on CTU-IoT-23 data. Novel attack patterns that fall within the training distribution's normal range may not be detected until the model is retrained.

4. **IP/DNS-level threats:** The current feature set does not include destination IP addresses, DNS queries, or geographic information. Threats identifiable only by destination (e.g., known C2 IPs) are not detected.

5. **Application-layer attacks:** SQL injection, credential stuffing, and other application-layer attacks that produce normal-looking network flows are outside the detection scope.
