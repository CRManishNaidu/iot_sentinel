#!/usr/bin/env python3
"""
IoT Sentinel — Enhanced Hackathon Traffic Simulator
=====================================================

Generates realistic IoT device traffic (normal + anomaly) and optionally
sends each event to the /score API for live trust-score evaluation.

Usage:
    python -m src.traffic_simulator --mode mixed --interval 1.5 --device-count 6

Modes:
    normal  – only normal device patterns
    anomaly – only anomaly patterns
    mixed   – realistic blend of both (default)

Press Ctrl+C to stop.
"""

import os
import sys
import random
import time
import json
import math
import argparse
import hashlib
import string
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import RequestException, ConnectionError, Timeout

# ──────────────────────────── Windows UTF-8 fix ────────────────────────────
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    if os.name == "nt":
        try:
            os.system("chcp 65001 > nul")
        except Exception:
            pass

# ══════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════
API_URL = os.getenv("API_URL", "http://localhost:8000/score")
API_KEY = os.getenv("API_KEY", "hackathon-secret")
MAX_RETRIES = 2
REQUEST_TIMEOUT = 4

# ──────────────────────────── ANSI colours ────────────────────────────────
class C:
    """ANSI colour helpers for console output."""
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

# ══════════════════════════════════════════════════════════════════════════
#  DEVICE TYPE DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════

DEVICE_TYPES = {
    "ip_camera": {
        "icon": "\U0001f4f9",       # 📹
        "label": "IP Camera",
        "patterns": {
            "video_stream": {
                "description": "Live video stream to cloud (high outbound)",
                "duration": (30.0, 120.0),
                "orig_bytes": (200_000, 800_000),
                "resp_bytes": (500, 5000),
                "orig_pkts": (400, 1500),
                "resp_pkts": (20, 80),
                "proto": "TCP",
                "conn_state": "SF",
            },
            "motion_alert": {
                "description": "Short burst motion-detection notification",
                "duration": (0.2, 1.5),
                "orig_bytes": (500, 3000),
                "resp_bytes": (200, 1000),
                "orig_pkts": (5, 20),
                "resp_pkts": (3, 10),
                "proto": "TCP",
                "conn_state": "SF",
            },
            "snapshot_upload": {
                "description": "Periodic JPEG snapshot upload",
                "duration": (1.0, 5.0),
                "orig_bytes": (30_000, 120_000),
                "resp_bytes": (200, 1000),
                "orig_pkts": (50, 200),
                "resp_pkts": (10, 30),
                "proto": "TCP",
                "conn_state": "SF",
            },
        },
    },
    "smart_thermostat": {
        "icon": "\U0001f321\uFE0F",  # 🌡️
        "label": "Smart Thermostat",
        "patterns": {
            "temp_report": {
                "description": "Periodic MQTT temperature telemetry",
                "duration": (0.05, 0.3),
                "orig_bytes": (50, 300),
                "resp_bytes": (30, 150),
                "orig_pkts": (2, 6),
                "resp_pkts": (2, 4),
                "proto": "TCP",
                "conn_state": "SF",
            },
            "schedule_sync": {
                "description": "Sync heating schedule with cloud",
                "duration": (0.5, 2.0),
                "orig_bytes": (300, 2000),
                "resp_bytes": (500, 3000),
                "orig_pkts": (5, 15),
                "resp_pkts": (5, 15),
                "proto": "TCP",
                "conn_state": "SF",
            },
            "firmware_check": {
                "description": "Rare firmware version check",
                "duration": (0.3, 1.0),
                "orig_bytes": (100, 500),
                "resp_bytes": (200, 800),
                "orig_pkts": (3, 8),
                "resp_pkts": (3, 8),
                "proto": "TCP",
                "conn_state": "SF",
            },
        },
    },
    "smart_speaker": {
        "icon": "\U0001f50a",        # 🔊
        "label": "Smart Speaker",
        "patterns": {
            "voice_command": {
                "description": "Voice clip upload for recognition",
                "duration": (1.0, 4.0),
                "orig_bytes": (10_000, 60_000),
                "resp_bytes": (500, 3000),
                "orig_pkts": (20, 80),
                "resp_pkts": (5, 20),
                "proto": "TCP",
                "conn_state": "SF",
            },
            "music_stream": {
                "description": "Music download stream (high inbound)",
                "duration": (30.0, 180.0),
                "orig_bytes": (500, 3000),
                "resp_bytes": (300_000, 1_200_000),
                "orig_pkts": (20, 60),
                "resp_pkts": (400, 2000),
                "proto": "TCP",
                "conn_state": "SF",
            },
            "wake_word_ping": {
                "description": "Local wake-word heartbeat",
                "duration": (0.01, 0.05),
                "orig_bytes": (30, 100),
                "resp_bytes": (30, 100),
                "orig_pkts": (1, 2),
                "resp_pkts": (1, 2),
                "proto": "UDP",
                "conn_state": "SF",
            },
        },
    },
    "smart_plug": {
        "icon": "\U0001f50c",        # 🔌
        "label": "Smart Plug",
        "patterns": {
            "power_report": {
                "description": "Periodic wattage report",
                "duration": (0.05, 0.2),
                "orig_bytes": (40, 200),
                "resp_bytes": (30, 100),
                "orig_pkts": (1, 4),
                "resp_pkts": (1, 3),
                "proto": "UDP",
                "conn_state": "SF",
            },
            "remote_toggle": {
                "description": "Remote on/off toggle command",
                "duration": (0.1, 0.5),
                "orig_bytes": (80, 400),
                "resp_bytes": (80, 400),
                "orig_pkts": (2, 6),
                "resp_pkts": (2, 6),
                "proto": "TCP",
                "conn_state": "SF",
            },
            "energy_stats": {
                "description": "Daily energy usage summary upload",
                "duration": (1.0, 4.0),
                "orig_bytes": (2000, 10_000),
                "resp_bytes": (200, 1000),
                "orig_pkts": (10, 40),
                "resp_pkts": (5, 15),
                "proto": "TCP",
                "conn_state": "SF",
            },
        },
    },
    "smart_lock": {
        "icon": "\U0001f512",        # 🔒
        "label": "Smart Lock",
        "patterns": {
            "lock_unlock_event": {
                "description": "Lock/unlock state change",
                "duration": (0.05, 0.2),
                "orig_bytes": (60, 250),
                "resp_bytes": (40, 150),
                "orig_pkts": (2, 5),
                "resp_pkts": (1, 4),
                "proto": "TCP",
                "conn_state": "SF",
            },
            "battery_report": {
                "description": "Battery level heartbeat",
                "duration": (0.02, 0.1),
                "orig_bytes": (30, 120),
                "resp_bytes": (20, 80),
                "orig_pkts": (1, 2),
                "resp_pkts": (1, 2),
                "proto": "UDP",
                "conn_state": "SF",
            },
            "access_log_upload": {
                "description": "Periodic access log sync",
                "duration": (0.5, 2.0),
                "orig_bytes": (1000, 5000),
                "resp_bytes": (200, 800),
                "orig_pkts": (8, 25),
                "resp_pkts": (4, 12),
                "proto": "TCP",
                "conn_state": "SF",
            },
        },
    },
    "smart_light": {
        "icon": "\U0001f4a1",        # 💡
        "label": "Smart Light Bulb",
        "patterns": {
            "status_update": {
                "description": "On/off & brightness telemetry",
                "duration": (0.02, 0.1),
                "orig_bytes": (30, 150),
                "resp_bytes": (20, 80),
                "orig_pkts": (1, 3),
                "resp_pkts": (1, 2),
                "proto": "UDP",
                "conn_state": "SF",
            },
            "color_change": {
                "description": "RGB colour change command",
                "duration": (0.1, 0.4),
                "orig_bytes": (60, 300),
                "resp_bytes": (40, 200),
                "orig_pkts": (2, 5),
                "resp_pkts": (2, 4),
                "proto": "TCP",
                "conn_state": "SF",
            },
            "schedule_sync": {
                "description": "Scheduling automation sync",
                "duration": (0.5, 2.0),
                "orig_bytes": (500, 3000),
                "resp_bytes": (300, 1500),
                "orig_pkts": (5, 15),
                "resp_pkts": (4, 12),
                "proto": "TCP",
                "conn_state": "SF",
            },
        },
    },
}

# ══════════════════════════════════════════════════════════════════════════
#  ANOMALY TYPE DEFINITIONS (6 types)
# ══════════════════════════════════════════════════════════════════════════

ANOMALY_TYPES = [
    {
        "name": "data_exfiltration",
        "description": "Large outbound data spike — potential data theft",
        "profile": {
            "duration": (8.0, 30.0),
            "orig_bytes": (80_000, 300_000),
            "resp_bytes": (200, 3000),
            "orig_pkts": (300, 1200),
            "resp_pkts": (10, 60),
            "proto": "TCP",
            "conn_state": "SF",
        },
    },
    {
        "name": "ddos_flood",
        "description": "High-volume packet flood (DDoS participation)",
        "profile": {
            "duration": (0.2, 3.0),
            "orig_bytes": (5000, 40_000),
            "resp_bytes": (30, 500),
            "orig_pkts": (800, 5000),
            "resp_pkts": (3, 30),
            "proto": "TCP",
            "conn_state": "REJ",
        },
    },
    {
        "name": "port_scan",
        "description": "Sequential small connections — reconnaissance scan",
        "profile": {
            "duration": (0.05, 1.0),
            "orig_bytes": (60, 600),
            "resp_bytes": (0, 50),
            "orig_pkts": (20, 200),
            "resp_pkts": (0, 5),
            "proto": "TCP",
            "conn_state": "S0",
        },
    },
    {
        "name": "c2_beaconing",
        "description": "Regular small-interval C2 call-home traffic",
        "profile": {
            "duration": (0.5, 3.0),
            "orig_bytes": (100, 800),
            "resp_bytes": (100, 1000),
            "orig_pkts": (5, 20),
            "resp_pkts": (5, 20),
            "proto": "TCP",
            "conn_state": "SF",
        },
    },
    {
        "name": "dns_tunneling",
        "description": "High-entropy DNS requests — covert channel",
        "profile": {
            "duration": (0.1, 1.5),
            "orig_bytes": (200, 2000),
            "resp_bytes": (200, 3000),
            "orig_pkts": (10, 60),
            "resp_pkts": (10, 60),
            "proto": "UDP",
            "conn_state": "SF",
        },
    },
    {
        "name": "slow_exfiltration",
        "description": "Persistent small outbound leak — slow trickle exfil",
        "profile": {
            "duration": (10.0, 60.0),
            "orig_bytes": (3000, 15_000),
            "resp_bytes": (100, 500),
            "orig_pkts": (30, 150),
            "resp_pkts": (5, 25),
            "proto": "TCP",
            "conn_state": "SF",
        },
    },
]

# ══════════════════════════════════════════════════════════════════════════
#  BACKGROUND NOISE (light)
# ══════════════════════════════════════════════════════════════════════════

BACKGROUND_NOISE = [
    {
        "name": "arp_broadcast",
        "description": "ARP who-has broadcast",
        "duration": (0.001, 0.01),
        "orig_bytes": (28, 42),
        "resp_bytes": (0, 42),
        "orig_pkts": (1, 1),
        "resp_pkts": (0, 1),
        "proto": "ICMP",
        "conn_state": "OTH",
    },
    {
        "name": "dns_query",
        "description": "Standard DNS lookup",
        "duration": (0.01, 0.15),
        "orig_bytes": (40, 120),
        "resp_bytes": (80, 300),
        "orig_pkts": (1, 2),
        "resp_pkts": (1, 2),
        "proto": "UDP",
        "conn_state": "SF",
    },
    {
        "name": "ntp_sync",
        "description": "NTP time synchronisation",
        "duration": (0.02, 0.1),
        "orig_bytes": (48, 76),
        "resp_bytes": (48, 76),
        "orig_pkts": (1, 1),
        "resp_pkts": (1, 1),
        "proto": "UDP",
        "conn_state": "SF",
    },
    {
        "name": "random_chatter",
        "description": "Miscellaneous background chatter",
        "duration": (0.01, 0.5),
        "orig_bytes": (20, 200),
        "resp_bytes": (20, 200),
        "orig_pkts": (1, 4),
        "resp_pkts": (1, 4),
        "proto": "UDP",
        "conn_state": "SF",
    },
]

# ══════════════════════════════════════════════════════════════════════════
#  DEVICE  CLASS
# ══════════════════════════════════════════════════════════════════════════

class IoTDevice:
    """Represents a single IoT device with its own RNG seed."""

    def __init__(self, device_id: str, device_type: str, base_seed: int = 42):
        self.device_id = device_id
        self.device_type = device_type
        self.type_info = DEVICE_TYPES[device_type]
        self.icon = self.type_info["icon"]
        self.label = self.type_info["label"]
        # Deterministic per-device RNG
        digest = int(hashlib.sha256(device_id.encode()).hexdigest()[:8], 16)
        self.rng = random.Random(base_seed + digest)

    # ── normal traffic ────────────────────────────────────────────────
    def generate_normal(self) -> Dict:
        pattern_name = self.rng.choice(list(self.type_info["patterns"].keys()))
        p = self.type_info["patterns"][pattern_name]
        return self._build_payload(p, pattern_name, is_anomaly=False)

    # ── anomaly traffic ───────────────────────────────────────────────
    def generate_anomaly(self) -> Tuple[Dict, str]:
        anomaly = self.rng.choice(ANOMALY_TYPES)
        payload = self._build_payload(anomaly["profile"], anomaly["name"], is_anomaly=True)
        return payload, anomaly["name"]

    # ── background noise ──────────────────────────────────────────────
    def generate_noise(self) -> Dict:
        noise = self.rng.choice(BACKGROUND_NOISE)
        return self._build_payload(noise, noise["name"], is_anomaly=False, is_noise=True)

    # ── internal builder ──────────────────────────────────────────────
    def _build_payload(self, profile: Dict, pattern_name: str,
                       is_anomaly: bool, is_noise: bool = False) -> Dict:
        payload = {
            "duration": round(self.rng.uniform(*profile["duration"]), 3),
            "orig_bytes": round(self.rng.uniform(*profile["orig_bytes"]), 2),
            "resp_bytes": round(self.rng.uniform(*profile["resp_bytes"]), 2),
            "orig_pkts": self.rng.randint(*profile["orig_pkts"]),
            "resp_pkts": self.rng.randint(*profile["resp_pkts"]),
            "proto": profile["proto"],
            "conn_state": profile["conn_state"],
            "device_id": self.device_id,
        }
        # metadata for console output (not sent to API internal fields)
        payload["_pattern"] = pattern_name
        payload["_is_anomaly"] = is_anomaly
        payload["_is_noise"] = is_noise
        payload["_device_type"] = self.device_type
        payload["_icon"] = self.icon
        payload["_description"] = profile.get("description", pattern_name)
        return payload


def _compute_entropy(text: str) -> float:
    """Shannon entropy of a string (useful for DNS tunneling display)."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _random_high_entropy_domain(rng: random.Random) -> str:
    """Generate a random high-entropy subdomain for DNS tunneling display."""
    chars = string.ascii_lowercase + string.digits
    sub = "".join(rng.choice(chars) for _ in range(rng.randint(16, 32)))
    return f"{sub}.evil-c2.xyz"

# ══════════════════════════════════════════════════════════════════════════
#  SIMULATOR  CORE
# ══════════════════════════════════════════════════════════════════════════

class EnhancedTrafficSimulator:
    """Generates realistic IoT traffic and optionally scores it via API."""

    DEVICE_TYPE_LIST = list(DEVICE_TYPES.keys())

    def __init__(self, mode: str = "mixed", interval: float = 2.0,
                 device_count: int = 6, seed: int = 42):
        self.mode = mode
        self.interval = interval
        self.device_count = min(device_count, len(self.DEVICE_TYPE_LIST) * 3)
        self.seed = seed
        random.seed(seed)

        # create devices – cycle through device types
        self.devices: List[IoTDevice] = []
        for i in range(self.device_count):
            dtype = self.DEVICE_TYPE_LIST[i % len(self.DEVICE_TYPE_LIST)]
            dev_id = f"iot_{dtype}_{i + 1:02d}"
            self.devices.append(IoTDevice(dev_id, dtype, base_seed=seed))

        # HTTP session with retry
        self.session = self._build_session()

        # stats
        self.total_events = 0
        self.normal_count = 0
        self.anomaly_count = 0

    # ── HTTP session ──────────────────────────────────────────────────
    def _build_session(self) -> requests.Session:
        s = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5,
                      status_forcelist=[429, 500, 502, 503, 504],
                      allowed_methods={"POST"}, raise_on_status=False)
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    # ── decide event type ─────────────────────────────────────────────
    def _next_event(self) -> Dict:
        device = random.choice(self.devices)

        # ~10 % chance of background noise
        if random.random() < 0.10:
            return device.generate_noise()

        if self.mode == "normal":
            return device.generate_normal()
        elif self.mode == "anomaly":
            payload, _ = device.generate_anomaly()
            return payload
        else:  # mixed
            if random.random() < 0.18:  # ~18 % anomaly rate
                payload, _ = device.generate_anomaly()
                return payload
            return device.generate_normal()

    # ── send to API ───────────────────────────────────────────────────
    def _send_to_api(self, payload: Dict) -> Optional[Dict]:
        """Send telemetry to /score, return response dict or None."""
        # strip internal metadata keys before sending
        api_payload = {k: v for k, v in payload.items() if not k.startswith("_")}
        headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
        try:
            resp = self.session.post(API_URL, json=api_payload,
                                     headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 403:
                return {"_error": "403 Forbidden – check API_KEY"}
            else:
                return {"_error": f"HTTP {resp.status_code}"}
        except ConnectionError:
            return None
        except Exception as exc:
            return {"_error": str(exc)[:60]}

    # ── pretty-print one event ────────────────────────────────────────
    def _print_event(self, payload: Dict, api_result: Optional[Dict]):
        is_anomaly = payload.get("_is_anomaly", False)
        is_noise = payload.get("_is_noise", False)
        icon = payload.get("_icon", "?")
        dev_id = payload["device_id"]
        pattern = payload.get("_pattern", "unknown")
        desc = payload.get("_description", "")
        orig_b = payload.get("orig_bytes", 0)
        orig_p = payload.get("orig_pkts", 0)

        # colour selection
        if is_anomaly:
            colour = C.RED
            tag = "ANOMALY"
        elif is_noise:
            colour = C.DIM
            tag = "NOISE"
        else:
            colour = C.GREEN
            tag = "NORMAL"

        # entropy display for DNS tunneling
        entropy_str = ""
        if pattern == "dns_tunneling":
            domain = _random_high_entropy_domain(random.Random(hash(dev_id + str(self.total_events))))
            ent = _compute_entropy(domain)
            entropy_str = f" | entropy={ent:.2f} [{domain[:30]}]"

        # trust score from API
        trust_str = ""
        if api_result and "_error" not in api_result:
            ts = api_result.get("trust_score", "?")
            verdict = api_result.get("verdict", "?")
            trust_str = f" | trust={ts} verdict={verdict}"
        elif api_result and "_error" in api_result:
            trust_str = f" | {C.YELLOW}API: {api_result['_error']}{colour}"

        line = (
            f"{colour}{C.BOLD}[{tag:^7}]{C.RESET}{colour} "
            f"{icon} {dev_id:<22} "
            f"{pattern:<24} "
            f"out={orig_b:>8,.0f}B  pkts={orig_p:>5}"
            f"{entropy_str}{trust_str}"
            f"{C.RESET}"
        )
        print(line)

        # Description on the line below for anomalies
        if is_anomaly:
            print(f"         {C.RED}{C.DIM}  └─ {desc}{C.RESET}")

    # ── periodic summary ──────────────────────────────────────────────
    def _print_summary(self):
        rate = (self.anomaly_count / self.total_events * 100) if self.total_events else 0
        print(
            f"\n{C.CYAN}{C.BOLD}"
            f"{'═' * 70}\n"
            f"  📊  SUMMARY  │  Total: {self.total_events}  │  "
            f"Normal: {self.normal_count}  │  Anomaly: {self.anomaly_count}  │  "
            f"Rate: {rate:.1f}%\n"
            f"{'═' * 70}"
            f"{C.RESET}\n"
        )

    # ── banner ────────────────────────────────────────────────────────
    def _print_banner(self):
        print(f"\n{C.CYAN}{C.BOLD}{'═' * 70}")
        print(f"  🚀  IoT SENTINEL — Enhanced Traffic Simulator")
        print(f"{'═' * 70}{C.RESET}")
        print(f"  Mode:         {C.BOLD}{self.mode.upper()}{C.RESET}")
        print(f"  Interval:     {self.interval}s")
        print(f"  Devices:      {self.device_count}")
        print(f"  API target:   {API_URL}")
        print(f"  Seed:         {self.seed}")
        print(f"{C.CYAN}{'─' * 70}{C.RESET}")
        for dev in self.devices:
            print(f"    {dev.icon}  {dev.device_id:<24} ({dev.label})")
        print(f"{C.CYAN}{'─' * 70}{C.RESET}")
        print(f"  Press {C.BOLD}Ctrl+C{C.RESET} to stop.\n")

    # ── main loop ─────────────────────────────────────────────────────
    def run(self):
        self._print_banner()
        try:
            while True:
                payload = self._next_event()
                is_anomaly = payload.get("_is_anomaly", False)

                # count
                self.total_events += 1
                if is_anomaly:
                    self.anomaly_count += 1
                else:
                    self.normal_count += 1

                # try API
                api_result = self._send_to_api(payload)

                # console output
                self._print_event(payload, api_result)

                # periodic summary every 20 events
                if self.total_events % 20 == 0:
                    self._print_summary()

                time.sleep(self.interval)

        except KeyboardInterrupt:
            self._print_final()
        finally:
            self.session.close()

    # ── final stats ───────────────────────────────────────────────────
    def _print_final(self):
        rate = (self.anomaly_count / self.total_events * 100) if self.total_events else 0
        print(f"\n{C.CYAN}{C.BOLD}{'═' * 70}")
        print(f"  🛑  SIMULATION COMPLETE")
        print(f"{'═' * 70}{C.RESET}")
        print(f"  Total events:   {self.total_events}")
        print(f"  Normal events:  {self.normal_count}")
        print(f"  Anomaly events: {self.anomaly_count}")
        print(f"  Anomaly rate:   {rate:.1f}%")
        print(f"{C.CYAN}{'═' * 70}{C.RESET}\n")


# ══════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="IoT Sentinel — Enhanced Hackathon Traffic Simulator"
    )
    parser.add_argument(
        "--mode", choices=["normal", "anomaly", "mixed"], default="mixed",
        help="Traffic mode (default: mixed)"
    )
    parser.add_argument(
        "--interval", type=float, default=2.0,
        help="Seconds between events (default: 2.0)"
    )
    parser.add_argument(
        "--device-count", type=int, default=6,
        help="Number of IoT devices to simulate (default: 6)"
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    sim = EnhancedTrafficSimulator(
        mode=args.mode,
        interval=args.interval,
        device_count=args.device_count,
        seed=args.seed,
    )
    sim.run()


if __name__ == "__main__":
    main()
