#!/usr/bin/env python3
"""
IoT Sentinel — Comprehensive Test Suite
=========================================

Tests cover:
    PART 1 – Enhanced Traffic Simulator (device types, patterns, anomalies, CLI)
    PART 2 – Docker files existence and content validation
    PART 3 – API key authentication on /score
    PART 4 – Concurrent WebSocket broadcast (asyncio.gather)
    PART 5 – .gitignore correctness

Run:
    cd iot_sentinel-main
    python -m pytest src/tests.py -v
"""

import os
import sys
import json
import asyncio
import importlib
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Resolve project root ─────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent  # iot_sentinel-main/
SRC_DIR = PROJECT_ROOT / "src"

# Make sure project root is on sys.path so `from src.xxx` works
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ══════════════════════════════════════════════════════════════════════════
#  PART 1 — TRAFFIC SIMULATOR TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestTrafficSimulatorDeviceTypes:
    """Verify that all 6 IoT device types are defined with correct patterns."""

    def _load_module(self):
        from src.traffic_simulator import DEVICE_TYPES

        return DEVICE_TYPES

    def test_all_six_device_types_present(self):
        dt = self._load_module()
        expected = {
            "ip_camera",
            "smart_thermostat",
            "smart_speaker",
            "smart_plug",
            "smart_lock",
            "smart_light",
        }
        assert expected == set(dt.keys()), (
            f"Missing device types: {expected - set(dt.keys())}"
        )

    def test_each_device_has_icon_and_patterns(self):
        dt = self._load_module()
        for name, info in dt.items():
            assert "icon" in info, f"{name} missing icon"
            assert "patterns" in info, f"{name} missing patterns"
            assert len(info["patterns"]) >= 2, (
                f"{name} needs >= 2 patterns, has {len(info['patterns'])}"
            )

    @pytest.mark.parametrize(
        "device,expected_patterns",
        [
            ("ip_camera", {"video_stream", "motion_alert", "snapshot_upload"}),
            ("smart_thermostat", {"temp_report", "schedule_sync", "firmware_check"}),
            ("smart_speaker", {"voice_command", "music_stream", "wake_word_ping"}),
            ("smart_plug", {"power_report", "remote_toggle", "energy_stats"}),
            (
                "smart_lock",
                {"lock_unlock_event", "battery_report", "access_log_upload"},
            ),
            ("smart_light", {"status_update", "color_change", "schedule_sync"}),
        ],
    )
    def test_device_patterns(self, device, expected_patterns):
        dt = self._load_module()
        actual = set(dt[device]["patterns"].keys())
        assert expected_patterns == actual, (
            f"{device}: expected {expected_patterns}, got {actual}"
        )


class TestTrafficSimulatorAnomalyTypes:
    """Verify anomaly type definitions."""

    def test_anomaly_count(self):
        from src.traffic_simulator import ANOMALY_TYPES

        assert len(ANOMALY_TYPES) == 6, (
            f"Expected 6 anomaly types, got {len(ANOMALY_TYPES)}"
        )

    def test_anomaly_names(self):
        from src.traffic_simulator import ANOMALY_TYPES

        names = {a["name"] for a in ANOMALY_TYPES}
        expected = {
            "data_exfiltration",
            "ddos_flood",
            "port_scan",
            "c2_beaconing",
            "dns_tunneling",
            "slow_exfiltration",
        }
        assert expected == names, f"Mismatch: {expected.symmetric_difference(names)}"

    def test_anomaly_profiles_have_required_fields(self):
        from src.traffic_simulator import ANOMALY_TYPES

        required = {
            "duration",
            "orig_bytes",
            "resp_bytes",
            "orig_pkts",
            "resp_pkts",
            "proto",
            "conn_state",
        }
        for a in ANOMALY_TYPES:
            profile_keys = set(a["profile"].keys())
            missing = required - profile_keys
            assert not missing, f"{a['name']} profile missing: {missing}"


class TestTrafficSimulatorBackgroundNoise:
    """Background noise should exist and be lightweight."""

    def test_noise_exists(self):
        from src.traffic_simulator import BACKGROUND_NOISE

        assert len(BACKGROUND_NOISE) >= 3, "Need at least 3 noise types"

    def test_noise_names(self):
        from src.traffic_simulator import BACKGROUND_NOISE

        names = {n["name"] for n in BACKGROUND_NOISE}
        assert "arp_broadcast" in names
        assert "dns_query" in names
        assert "ntp_sync" in names


class TestIoTDevice:
    """Test the IoTDevice class produces correct payloads."""

    def test_normal_payload_fields(self):
        from src.traffic_simulator import IoTDevice

        dev = IoTDevice("test_cam_01", "ip_camera", base_seed=99)
        payload = dev.generate_normal()
        for field in (
            "duration",
            "orig_bytes",
            "resp_bytes",
            "orig_pkts",
            "resp_pkts",
            "proto",
            "conn_state",
            "device_id",
        ):
            assert field in payload, f"Missing field: {field}"
        assert payload["device_id"] == "test_cam_01"

    def test_anomaly_payload(self):
        from src.traffic_simulator import IoTDevice

        dev = IoTDevice("test_plug_01", "smart_plug", base_seed=99)
        payload, name = dev.generate_anomaly()
        assert payload["_is_anomaly"] is True
        assert isinstance(name, str)

    def test_noise_payload(self):
        from src.traffic_simulator import IoTDevice

        dev = IoTDevice("test_lock_01", "smart_lock", base_seed=99)
        payload = dev.generate_noise()
        assert payload["_is_noise"] is True

    def test_deterministic_seed(self):
        from src.traffic_simulator import IoTDevice

        dev1 = IoTDevice("dev_a", "smart_light", base_seed=42)
        dev2 = IoTDevice("dev_a", "smart_light", base_seed=42)
        p1 = dev1.generate_normal()
        p2 = dev2.generate_normal()
        assert p1["duration"] == p2["duration"], "Same seed should produce same output"


class TestEnhancedSimulator:
    """Test the main simulator class."""

    def test_creation(self):
        from src.traffic_simulator import EnhancedTrafficSimulator

        sim = EnhancedTrafficSimulator(
            mode="mixed", interval=1.0, device_count=4, seed=42
        )
        assert len(sim.devices) == 4
        assert sim.mode == "mixed"

    def test_event_generation_modes(self):
        from src.traffic_simulator import EnhancedTrafficSimulator

        for mode in ("normal", "anomaly", "mixed", "demo", "test", "stress"):
            sim = EnhancedTrafficSimulator(
                mode=mode, interval=0.01, device_count=2, seed=42
            )
            event = sim._next_event()
            assert "device_id" in event
            assert "proto" in event

    def test_demo_mode_maps_to_mixed_profile(self):
        from src.traffic_simulator import EnhancedTrafficSimulator

        sim = EnhancedTrafficSimulator(mode="demo", device_count=2, seed=42)
        assert sim.base_mode == "mixed"
        assert sim.anomaly_probability == pytest.approx(0.15)


class TestCLIParsing:
    """Verify CLI args match the spec (--mode, --interval, --device-count)."""

    def test_default_args(self):
        from src.traffic_simulator import parse_args

        with patch("sys.argv", ["prog"]):
            args = parse_args()
        assert args.mode == "mixed"
        assert args.interval == 2.0
        assert args.device_count == 6

    def test_custom_args(self):
        from src.traffic_simulator import parse_args

        with patch(
            "sys.argv",
            ["prog", "--mode", "anomaly", "--interval", "0.5", "--device-count", "3"],
        ):
            args = parse_args()
        assert args.mode == "anomaly"
        assert args.interval == 0.5
        assert args.device_count == 3

    def test_demo_mode_args(self):
        from src.traffic_simulator import parse_args

        with patch("sys.argv", ["prog", "--mode", "demo"]):
            args = parse_args()
        assert args.mode == "demo"


# ══════════════════════════════════════════════════════════════════════════
#  PART 2 — DOCKER FILES TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestDockerFiles:
    """Verify Docker artifacts exist and contain key directives."""

    def test_dockerfile_api_exists(self):
        path = PROJECT_ROOT / "Dockerfile.api"
        assert path.exists(), "Dockerfile.api not found at project root"

    def test_dockerfile_dashboard_exists(self):
        path = PROJECT_ROOT / "Dockerfile.dashboard"
        assert path.exists(), "Dockerfile.dashboard not found at project root"

    def test_docker_compose_exists(self):
        path = PROJECT_ROOT / "docker-compose.yml"
        assert path.exists(), "docker-compose.yml not found at project root"

    def test_dockerfile_api_exposes_8000(self):
        content = (PROJECT_ROOT / "Dockerfile.api").read_text()
        assert "EXPOSE 8000" in content, "Dockerfile.api must EXPOSE 8000"

    def test_dockerfile_dashboard_exposes_8501(self):
        content = (PROJECT_ROOT / "Dockerfile.dashboard").read_text()
        assert "EXPOSE 8501" in content, "Dockerfile.dashboard must EXPOSE 8501"

    def test_dockerfile_api_has_healthcheck(self):
        content = (PROJECT_ROOT / "Dockerfile.api").read_text()
        assert "HEALTHCHECK" in content, "Dockerfile.api should have a HEALTHCHECK"

    def test_dockerfile_dashboard_has_healthcheck(self):
        content = (PROJECT_ROOT / "Dockerfile.dashboard").read_text()
        assert "HEALTHCHECK" in content, (
            "Dockerfile.dashboard should have a HEALTHCHECK"
        )

    def test_docker_compose_services(self):
        content = (PROJECT_ROOT / "docker-compose.yml").read_text()
        assert "api:" in content, "docker-compose must define 'api' service"
        assert "dashboard:" in content, "docker-compose must define 'dashboard' service"
        assert "8000:8000" in content, "API ports mapping missing"
        assert "8501:8501" in content, "Dashboard ports mapping missing"

    def test_docker_compose_has_env_support(self):
        content = (PROJECT_ROOT / "docker-compose.yml").read_text()
        assert "API_KEY" in content, "docker-compose should reference API_KEY env var"


# ══════════════════════════════════════════════════════════════════════════
#  PART 3 — API KEY AUTHENTICATION TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestAPIKeyAuth:
    """Verify the /score endpoint requires a valid X-API-Key header."""

    def test_api_server_imports_header_and_depends(self):
        """Check that the api_server imports Header and Depends from FastAPI."""
        content = (SRC_DIR / "api_server.py").read_text()
        assert "Header" in content, "api_server.py must import Header"
        assert "Depends" in content, "api_server.py must import Depends"

    def test_verify_api_key_function_exists(self):
        content = (SRC_DIR / "api_server.py").read_text()
        assert "async def verify_api_key" in content, (
            "verify_api_key function must exist"
        )

    def test_score_endpoint_uses_depends(self):
        content = (SRC_DIR / "api_server.py").read_text()
        assert "Depends(verify_api_key)" in content, (
            "/score must use Depends(verify_api_key)"
        )

    def test_api_key_env_var_read(self):
        content = (SRC_DIR / "api_server.py").read_text()
        assert "API_KEY" in content, "API_KEY env var must be referenced"

    def test_returns_403_on_bad_key(self):
        content = (SRC_DIR / "api_server.py").read_text()
        assert "403" in content or "HTTP_403_FORBIDDEN" in content, (
            "Must return 403 on invalid API key"
        )


class TestAPIKeyIntegration:
    """Integration test hitting the actual FastAPI app with httpx."""

    @pytest.fixture
    def client(self):
        """Create an httpx async test client against the real FastAPI app."""
        try:
            from httpx import AsyncClient, ASGITransport
            from src.api_server import app

            transport = ASGITransport(app=app)
            return AsyncClient(transport=transport, base_url="http://testserver")
        except ImportError:
            pytest.skip("httpx not installed")

    @pytest.mark.asyncio
    async def test_score_returns_403_without_key(self, client):
        payload = {
            "duration": 1.0,
            "orig_bytes": 100,
            "resp_bytes": 100,
            "orig_pkts": 5,
            "resp_pkts": 5,
            "proto": "TCP",
            "conn_state": "SF",
        }
        resp = await client.post("/score", json=payload)
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"

    @pytest.mark.asyncio
    async def test_score_returns_403_with_wrong_key(self, client):
        payload = {
            "duration": 1.0,
            "orig_bytes": 100,
            "resp_bytes": 100,
            "orig_pkts": 5,
            "resp_pkts": 5,
            "proto": "TCP",
            "conn_state": "SF",
        }
        resp = await client.post(
            "/score", json=payload, headers={"X-API-Key": "wrong-key-123"}
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_score_returns_200_with_correct_key(self, client):
        payload = {
            "duration": 1.0,
            "orig_bytes": 100,
            "resp_bytes": 100,
            "orig_pkts": 5,
            "resp_pkts": 5,
            "proto": "TCP",
            "conn_state": "SF",
        }
        resp = await client.post(
            "/score", json=payload, headers={"X-API-Key": "hackathon-secret"}
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        body = resp.json()
        assert "trust_score" in body
        assert "verdict" in body

    @pytest.mark.asyncio
    async def test_health_endpoint_no_key_needed(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════
#  PART 4 — WEBSOCKET BROADCAST (asyncio.gather) TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestWebSocketBroadcast:
    """Verify the broadcast method uses asyncio.gather for concurrency."""

    def test_broadcast_uses_asyncio_gather(self):
        content = (SRC_DIR / "api_server.py").read_text()
        assert "asyncio.gather" in content, "broadcast must use asyncio.gather"

    @pytest.mark.asyncio
    async def test_broadcast_sends_to_all_clients(self):
        from src.api_server import ConnectionManager

        mgr = ConnectionManager()

        ws1 = AsyncMock()
        ws2 = AsyncMock()
        ws3 = AsyncMock()

        mgr.active_connections = [ws1, ws2, ws3]
        message = {"event": "test", "value": 42}

        await mgr.broadcast(message)

        ws1.send_json.assert_called_once_with(message)
        ws2.send_json.assert_called_once_with(message)
        ws3.send_json.assert_called_once_with(message)

    @pytest.mark.asyncio
    async def test_broadcast_removes_failed_clients(self):
        from src.api_server import ConnectionManager

        mgr = ConnectionManager()

        ws_good = AsyncMock()
        ws_bad = AsyncMock()
        ws_bad.send_json.side_effect = Exception("Connection lost")

        mgr.active_connections = [ws_good, ws_bad]
        await mgr.broadcast({"data": "hello"})

        ws_good.send_json.assert_called_once()
        assert ws_bad not in mgr.active_connections, "Failed client should be removed"

    @pytest.mark.asyncio
    async def test_broadcast_empty_connections(self):
        from src.api_server import ConnectionManager

        mgr = ConnectionManager()
        mgr.active_connections = []
        # Should not raise
        await mgr.broadcast({"msg": "no one listening"})


# ══════════════════════════════════════════════════════════════════════════
#  PART 5 — GITIGNORE & ENV TESTS
# ══════════════════════════════════════════════════════════════════════════


class TestGitignoreAndEnv:
    """Verify .gitignore and .env are correct."""

    def test_gitignore_has_required_entries(self):
        content = (PROJECT_ROOT / ".gitignore").read_text()
        required = ["venv/", "__pycache__/", ".env", "models/*.pkl", "logs/"]
        for entry in required:
            assert entry in content, f".gitignore missing: {entry}"

    def test_env_file_exists(self):
        path = PROJECT_ROOT / ".env"
        assert path.exists(), ".env file not found"

    def test_env_file_has_api_key(self):
        content = (PROJECT_ROOT / ".env").read_text()
        assert "API_KEY=hackathon-secret" in content


class TestADWINAndShapEnhancements:
    """Verify drift monitoring and SHAP-style outputs are present."""

    def test_engine_result_includes_drift_and_contributors(self):
        from src.engine import Engine

        engine = Engine(models_path=str(PROJECT_ROOT / "models"))
        result = engine.score_telemetry(
            {
                "duration": 1.0,
                "orig_bytes": 500.0,
                "resp_bytes": 450.0,
                "orig_pkts": 5,
                "resp_pkts": 6,
                "proto": "TCP",
                "conn_state": "SF",
                "device_id": "test_device",
            }
        )

        assert "drift_analysis" in result
        assert "drift_detected" in result["drift_analysis"]
        assert "top_contributors" in result
        assert isinstance(result["top_contributors"], list)
        assert "explanation_method" in result

    def test_drift_monitor_detects_large_distribution_shift(self):
        from src.engine import DriftMonitor

        monitor = DriftMonitor(delta=0.002)
        detected = False
        for value in ([10.0] * 30) + ([95.0] * 30):
            state = monitor.update(value)
            if state["drift_detected"]:
                detected = True
                break
        assert detected, "Expected drift detection after a strong score shift"

    def test_api_response_model_contains_new_fields(self):
        content = (SRC_DIR / "api_server.py").read_text()
        assert "top_contributors" in content
        assert "drift_detected" in content
        assert "explanation_method" in content


# ══════════════════════════════════════════════════════════════════════════
#  PART 6 — GENERAL STRUCTURE & SANITY CHECKS
# ══════════════════════════════════════════════════════════════════════════


class TestProjectStructure:
    """Confirm key project files and directories exist."""

    @pytest.mark.parametrize(
        "rel_path",
        [
            "src/api_server.py",
            "src/engine.py",
            "src/dashboard.py",
            "src/traffic_simulator.py",
            "requirements.txt",
            "Dockerfile.api",
            "Dockerfile.dashboard",
            "docker-compose.yml",
            ".gitignore",
        ],
    )
    def test_file_exists(self, rel_path):
        assert (PROJECT_ROOT / rel_path).exists(), f"Missing: {rel_path}"

    def test_models_directory_exists(self):
        assert (PROJECT_ROOT / "models").is_dir()


# ══════════════════════════════════════════════════════════════════════════
#  ENTRYPOINT
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
