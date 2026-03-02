#!/usr/bin/env python3
"""
Network Traffic Simulator for IoT Anomaly Detection System
Optimized for dashboard visualization with consistent anomaly patterns
"""

import os
import random
import time
import json
import argparse
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import RequestException, ConnectionError, Timeout

# ==================== CONFIGURATION ====================
API_URL = os.getenv("API_URL", "http://localhost:8000/score")
MAX_RETRIES = 2
RETRY_DELAY = 2
REQUEST_TIMEOUT = 3

# Device pool - ensure all devices get anomalies
DEVICES = [f"device_{i}" for i in range(1, 11)]  # device_1 through device_10

# Protocol weights for normal traffic
PROTOCOLS = ["TCP", "UDP", "ICMP"]
PROTOCOL_WEIGHTS = [0.70, 0.20, 0.10]

# Connection states
CONN_STATES = ["SF", "S0", "REJ", "RST"]

# ==================== ANOMALY PATTERNS ====================
ANOMALY_PATTERNS = [
    {
        "name": "data_exfiltration",
        "description": "Large data transfer outbound",
        "profile": {
            "duration": (8.0, 25.0),
            "orig_bytes": (50000, 200000),
            "resp_bytes": (500, 5000),
            "orig_pkts": (200, 800),
            "resp_pkts": (30, 150),
            "proto": "TCP",
            "conn_state": "SF"
        },
        "trust_range": (15, 35),  # Very low trust
        "rule_boost": (70, 95),    # High rule score
        "ml_boost": (40, 60)       # Moderate ML impact
    },
    {
        "name": "ddos_flood",
        "description": "Packet flood attack",
        "profile": {
            "duration": (0.3, 3.0),
            "orig_bytes": (5000, 30000),
            "resp_bytes": (50, 500),
            "orig_pkts": (800, 3000),
            "resp_pkts": (5, 30),
            "proto": "TCP",
            "conn_state": "REJ"
        },
        "trust_range": (10, 30),
        "rule_boost": (80, 98),
        "ml_boost": (50, 75)
    },
    {
        "name": "port_scan",
        "description": "Reconnaissance scanning",
        "profile": {
            "duration": (0.1, 1.5),
            "orig_bytes": (100, 800),
            "resp_bytes": (0, 50),
            "orig_pkts": (20, 150),
            "resp_pkts": (0, 5),
            "proto": "TCP",
            "conn_state": "S0"
        },
        "trust_range": (25, 45),
        "rule_boost": (60, 85),
        "ml_boost": (45, 65)
    },
    {
        "name": "icmp_flood",
        "description": "ICMP echo flood",
        "profile": {
            "duration": (0.5, 4.0),
            "orig_bytes": (1000, 10000),
            "resp_bytes": (1000, 10000),
            "orig_pkts": (300, 1500),
            "resp_pkts": (300, 1500),
            "proto": "ICMP",
            "conn_state": "SF"
        },
        "trust_range": (20, 40),
        "rule_boost": (65, 90),
        "ml_boost": (55, 80)
    },
    {
        "name": "suspicious_behavior",
        "description": "Unusual pattern flagged by ML",
        "profile": {
            "duration": (2.0, 12.0),
            "orig_bytes": (8000, 40000),
            "resp_bytes": (3000, 15000),
            "orig_pkts": (100, 400),
            "resp_pkts": (80, 300),
            "proto": "UDP",
            "conn_state": random.choice(["S0", "REJ"])
        },
        "trust_range": (30, 48),
        "rule_boost": (40, 60),
        "ml_boost": (70, 92)
    }
]

# ==================== NORMAL TRAFFIC PROFILES ====================
NORMAL_PROFILES = [
    {
        "name": "web_browsing",
        "duration": (0.5, 5.0),
        "orig_bytes": (300, 3000),
        "resp_bytes": (1000, 8000),
        "orig_pkts": (10, 40),
        "resp_pkts": (15, 60),
        "proto": "TCP",
        "conn_state": "SF"
    },
    {
        "name": "dns_query",
        "duration": (0.05, 0.3),
        "orig_bytes": (50, 300),
        "resp_bytes": (100, 600),
        "orig_pkts": (2, 8),
        "resp_pkts": (2, 8),
        "proto": "UDP",
        "conn_state": "SF"
    },
    {
        "name": "file_transfer",
        "duration": (3.0, 15.0),
        "orig_bytes": (5000, 20000),
        "resp_bytes": (200, 2000),
        "orig_pkts": (30, 120),
        "resp_pkts": (10, 40),
        "proto": "TCP",
        "conn_state": "SF"
    },
    {
        "name": "ping",
        "duration": (0.01, 0.1),
        "orig_bytes": (64, 128),
        "resp_bytes": (64, 128),
        "orig_pkts": (1, 2),
        "resp_pkts": (1, 2),
        "proto": "ICMP",
        "conn_state": "SF"
    }
]

# ==================== TRAFFIC GENERATION ====================

class DeviceTrafficGenerator:
    """Manages traffic generation for a single device"""
    
    def __init__(self, device_id: str, base_seed: int = 42):
        self.device_id = device_id
        self.rng = random.Random()
        device_hash = int(hashlib.sha256(device_id.encode("utf-8")).hexdigest()[:8], 16)
        self.rng.seed(base_seed + device_hash)
        self.last_anomaly_time = 0
        self.anomaly_cooldown = 30  # Minimum seconds between anomalies
        self.normal_count = 0
        self.anomaly_count = 0
        
    def should_generate_anomaly(self, anomaly_probability: float) -> bool:
        """Decide if this device should generate an anomaly"""
        # Ensure anomalies are distributed but not too frequent
        current_time = time.time()
        
        # Cooldown period
        if current_time - self.last_anomaly_time < self.anomaly_cooldown:
            return False
            
        # Random chance
        if self.rng.random() < anomaly_probability:
            self.last_anomaly_time = current_time
            self.anomaly_count += 1
            return True
            
        self.normal_count += 1
        return False
    
    def generate_normal_traffic(self) -> Dict:
        """Generate normal traffic with realistic variations"""
        profile = self.rng.choice(NORMAL_PROFILES)
        
        return {
            "duration": round(self.rng.uniform(*profile["duration"]), 3),
            "orig_bytes": round(self.rng.uniform(*profile["orig_bytes"]), 2),
            "resp_bytes": round(self.rng.uniform(*profile["resp_bytes"]), 2),
            "orig_pkts": self.rng.randint(*profile["orig_pkts"]),
            "resp_pkts": self.rng.randint(*profile["resp_pkts"]),
            "proto": profile["proto"],
            "conn_state": profile["conn_state"],
            "device_id": self.device_id,
            "profile": profile["name"]
        }
    
    def generate_anomaly_traffic(self) -> Tuple[Dict, float, float, float]:
        """
        Generate anomalous traffic with expected score ranges
        
        Returns:
            Tuple of (payload, expected_trust, expected_rule, expected_ml)
        """
        pattern = self.rng.choice(ANOMALY_PATTERNS)
        profile = pattern["profile"]
        
        # Generate telemetry with some variation
        payload = {
            "duration": round(self.rng.uniform(*profile["duration"]), 3),
            "orig_bytes": round(self.rng.uniform(*profile["orig_bytes"]), 2),
            "resp_bytes": round(self.rng.uniform(*profile["resp_bytes"]), 2),
            "orig_pkts": self.rng.randint(*profile["orig_pkts"]),
            "resp_pkts": self.rng.randint(*profile["resp_pkts"]),
            "proto": profile["proto"],
            "conn_state": profile["conn_state"] if not callable(profile["conn_state"]) 
                         else profile["conn_state"](),
            "device_id": self.device_id,
            "pattern": pattern["name"]
        }
        
        # Expected scores (for verification/logging)
        expected_trust = self.rng.uniform(*pattern["trust_range"])
        expected_rule = self.rng.uniform(*pattern["rule_boost"])
        expected_ml = self.rng.uniform(*pattern["ml_boost"])
        
        return payload, expected_trust, expected_rule, expected_ml


class TrafficSimulator:
    """Main simulator orchestrator"""
    
    def __init__(self, anomaly_probability: float = 0.15, 
                 interval: float = 2.0,
                 verbose: bool = False,
                 seed: int = 42):
        self.anomaly_probability = anomaly_probability
        self.interval = interval
        self.verbose = verbose
        self.seed = seed
        random.seed(seed)
        self.devices = {dev_id: DeviceTrafficGenerator(dev_id, base_seed=seed) for dev_id in DEVICES}
        self.session = self._build_session()
        
        # Statistics
        self.stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "by_device": {dev_id: {"total": 0, "anomalies": 0} for dev_id in DEVICES},
            "status_codes": {},
            "trust_scores": [],
            "latencies": []
        }

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry_config = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods={"POST"},
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retry_config, pool_connections=20, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
        
    def send_telemetry(self, payload: Dict, is_anomaly: bool) -> bool:
        """Send telemetry to API"""
        for attempt in range(MAX_RETRIES):
            try:
                start_time = time.time()
                response = self.session.post(API_URL, json=payload, timeout=REQUEST_TIMEOUT)
                latency = (time.time() - start_time) * 1000
                status = str(response.status_code)
                self.stats["status_codes"][status] = self.stats["status_codes"].get(status, 0) + 1
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Extract scores
                    trust_score = result.get("trust_score", 50)
                    ml_score = result.get("ml_score", 50)
                    rule_score = result.get("rule_score", 0)
                    
                    # Store stats
                    self.stats["trust_scores"].append(trust_score)
                    self.stats["latencies"].append(latency)
                    self.stats["success"] += 1
                    
                    # Determine appropriate prefix and verdict
                    if is_anomaly:
                        if trust_score < 30:
                            prefix = "🔴 CRITICAL"
                            verdict = "ANOMALY"
                        elif trust_score < 45:
                            prefix = "🟠 HIGH"
                            verdict = "ANOMALY"
                        else:
                            prefix = "🟡 SUSPICIOUS"
                            verdict = "SUSPICIOUS"
                    else:
                        prefix = "🟢 NORMAL"
                        verdict = "NORMAL"
                    
                    # Clean output
                    pattern_info = f" [{payload.get('pattern', 'normal')}]" if is_anomaly else ""
                    print(f"{prefix} [{payload['device_id']}]{pattern_info} "
                          f"Trust: {trust_score:.1f} | ML: {ml_score:.1f} | Rule: {rule_score:.0f} | {verdict}")
                    
                    return True
                else:
                    if attempt == MAX_RETRIES - 1:
                        print(f"⚠️ API returned {response.status_code}")
                    delay = RETRY_DELAY * (2 ** attempt) + random.uniform(0, 0.25)
                    time.sleep(delay)
                    
            except ConnectionError:
                if attempt == MAX_RETRIES - 1:
                    print("⚠️ API unreachable - is the server running?")
                else:
                    delay = RETRY_DELAY * (2 ** attempt) + random.uniform(0, 0.25)
                    time.sleep(delay)
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    print(f"⚠️ Request failed: {str(e)[:50]}")
                else:
                    delay = RETRY_DELAY * (2 ** attempt) + random.uniform(0, 0.25)
                    time.sleep(delay)

        self.stats["failed"] += 1
        return False
    
    def run(self):
        """Main simulation loop"""
        print("\n" + "="*70)
        print("🚀 NETWORK TRAFFIC SIMULATOR STARTED")
        print("="*70)
        print(f"Target API: {API_URL}")
        print(f"Anomaly Probability: {self.anomaly_probability*100:.0f}% per device")
        print(f"Devices: {len(DEVICES)} ({', '.join(DEVICES)})")
        print(f"Interval: {self.interval}s | Verbose: {self.verbose} | Seed: {self.seed}")
        print("="*70 + "\n")
        
        start_time = time.time()
        
        try:
            while True:
                # Pick a random device
                device_id = random.choice(DEVICES)
                device = self.devices[device_id]
                
                # Decide if this request should be anomalous
                is_anomaly = device.should_generate_anomaly(self.anomaly_probability)
                
                # Generate traffic
                if is_anomaly:
                    payload, exp_trust, exp_rule, exp_ml = device.generate_anomaly_traffic()
                    if self.verbose:
                        print(f"📋 Expected: Trust={exp_trust:.1f}, Rule={exp_rule:.1f}, ML={exp_ml:.1f}")
                else:
                    payload = device.generate_normal_traffic()
                
                # Update stats
                self.stats["total"] += 1
                self.stats["by_device"][device_id]["total"] += 1
                if is_anomaly:
                    self.stats["by_device"][device_id]["anomalies"] += 1
                
                # Send to API
                success = self.send_telemetry(payload, is_anomaly)
                
                # Print periodic stats (every 20 requests)
                if self.stats["total"] % 20 == 0:
                    self.print_stats(start_time)
                
                # Wait for next interval
                time.sleep(self.interval)
                
        except KeyboardInterrupt:
            self.print_final_stats(start_time)
        finally:
            self.session.close()
    
    def print_stats(self, start_time: float):
        """Print current statistics"""
        elapsed = time.time() - start_time
        anomalies = sum(d["anomalies"] for d in self.stats["by_device"].values())
        anomaly_rate = (anomalies / self.stats["total"] * 100) if self.stats["total"] > 0 else 0
        
        avg_trust = (sum(self.stats["trust_scores"][-50:]) / 
                    len(self.stats["trust_scores"][-50:])) if self.stats["trust_scores"] else 0
        
        print(f"\n📊 STATS [{int(elapsed)}s] | "
              f"Requests: {self.stats['total']} | "
              f"Success: {self.stats['success']} | "
              f"Failed: {self.stats['failed']} | "
              f"Anomalies: {anomalies} ({anomaly_rate:.1f}%) | "
              f"Avg Trust (last 50): {avg_trust:.1f}\n")
    
    def print_final_stats(self, start_time: float):
        """Print final statistics"""
        elapsed = time.time() - start_time
        anomalies = sum(d["anomalies"] for d in self.stats["by_device"].values())
        anomaly_rate = (anomalies / self.stats["total"] * 100) if self.stats["total"] > 0 else 0
        
        avg_trust = (sum(self.stats["trust_scores"]) / 
                    len(self.stats["trust_scores"])) if self.stats["trust_scores"] else 0
        avg_latency = (sum(self.stats["latencies"]) / 
                      len(self.stats["latencies"])) if self.stats["latencies"] else 0
        
        print("\n" + "="*70)
        print("🛑 SIMULATION COMPLETE")
        print("="*70)
        print(f"Duration: {elapsed:.1f} seconds")
        print(f"Total Requests: {self.stats['total']}")
        print(f"Successful Requests: {self.stats['success']}")
        print(f"Failed Requests: {self.stats['failed']}")
        print(f"Total Anomalies: {anomalies} ({anomaly_rate:.1f}%)")
        print(f"Average Trust Score: {avg_trust:.1f}")
        print(f"Average Latency: {avg_latency:.1f}ms")
        if self.stats["status_codes"]:
            print(f"Status Codes: {self.stats['status_codes']}")
        print("\n📈 Per-Device Statistics:")
        for device_id, stats in self.stats["by_device"].items():
            if stats["total"] > 0:
                dev_anomaly_rate = (stats["anomalies"] / stats["total"] * 100)
                print(f"  {device_id}: {stats['total']} req, "
                      f"{stats['anomalies']} anomalies ({dev_anomaly_rate:.1f}%)")
        print("="*70 + "\n")


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Network Traffic Simulator")
    parser.add_argument("--anomaly-probability", type=float, default=0.15,
                       help="Probability of anomaly per request (0-1)")
    parser.add_argument("--interval", type=float, default=2.0,
                       help="Seconds between requests")
    parser.add_argument("--verbose", action="store_true",
                       help="Enable verbose output")
    parser.add_argument("--seed", type=int, default=42,
                       help="Random seed for reproducible runs")
    parser.add_argument("--mode", choices=["demo", "test", "stress"], default="demo",
                       help="Preset configuration")
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_args()
    
    # Apply mode presets
    if args.mode == "demo":
        anomaly_prob = 0.15
        interval = 2.0
    elif args.mode == "test":
        anomaly_prob = 0.25
        interval = 1.0
    elif args.mode == "stress":
        anomaly_prob = 0.40
        interval = 0.5
    
    # Override with explicit args if provided
    if args.anomaly_probability != 0.15:
        anomaly_prob = args.anomaly_probability
    if args.interval != 2.0:
        interval = args.interval
    
    simulator = TrafficSimulator(
        anomaly_probability=anomaly_prob,
        interval=interval,
        verbose=args.verbose,
        seed=args.seed
    )
    
    try:
        simulator.run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
