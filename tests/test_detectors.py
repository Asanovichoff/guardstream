"""
Unit tests for the four behavioral detection rules.
Run with: python -m pytest tests/
"""
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../services/ai-consumer"))

from main import (
    analyze_batch,
    detect_credential_stuffing,
    detect_ddos,
    detect_enumeration,
    detect_scraping,
)


def _ts(offset_seconds: float = 0) -> str:
    from datetime import datetime, timezone, timedelta
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


def _login(ip: str, ua: str = "python-requests/2.28.0", offset: float = 0) -> dict:
    return {
        "ip": ip,
        "endpoint": "/api/login",
        "method": "POST",
        "user_agent": ua,
        "status_code": 200,
        "timestamp": _ts(offset),
    }


def _get(ip: str, endpoint: str, ua: str = "Scrapy/2.11", offset: float = 0) -> dict:
    return {
        "ip": ip,
        "endpoint": endpoint,
        "method": "GET",
        "user_agent": ua,
        "status_code": 200,
        "timestamp": _ts(offset),
    }


# ── credential stuffing ───────────────────────────────────────────────────────

class TestCredentialStuffing:
    def test_detects_classic_pattern(self):
        events = [
            _login(f"10.0.0.{i % 3 + 1}") for i in range(30)
        ]
        result = detect_credential_stuffing(events)
        assert result is not None
        assert result["pattern_type"] == "credential_stuffing"
        assert result["confidence"] >= 0.6
        assert result["recommended_action"] == "block"
        assert len(result["affected_ips"]) <= 5

    def test_no_false_positive_on_low_volume(self):
        events = [_login("10.0.0.1") for _ in range(5)]
        assert detect_credential_stuffing(events) is None

    def test_no_false_positive_many_ips(self):
        # 30 logins but each from a different IP — not credential stuffing
        events = [_login(f"10.0.{i}.1") for i in range(30)]
        assert detect_credential_stuffing(events) is None

    def test_no_false_positive_many_user_agents(self):
        # 3 IPs but each with a unique UA — not a cluster
        events = [
            _login(f"10.0.0.{i % 3 + 1}", ua=f"browser-{i}") for i in range(30)
        ]
        assert detect_credential_stuffing(events) is None

    def test_ignores_non_login_endpoints(self):
        events = [_get("10.0.0.1", "/api/data") for _ in range(30)]
        assert detect_credential_stuffing(events) is None


# ── scraping ──────────────────────────────────────────────────────────────────

class TestScraping:
    def _rapid_gets(self, n: int, ip: str = "10.20.0.1") -> list[dict]:
        endpoints = ["/api/users", "/api/data"]
        return [
            _get(ip, endpoints[i % len(endpoints)], offset=i * 0.05)
            for i in range(n)
        ]

    def test_detects_rapid_cycling(self):
        events = self._rapid_gets(20)
        result = detect_scraping(events)
        assert result is not None
        assert result["pattern_type"] == "scraping"
        assert result["affected_ips"] == ["10.20.0.1"]
        assert result["confidence"] >= 0.6

    def test_no_false_positive_on_low_volume(self):
        events = self._rapid_gets(5)
        assert detect_scraping(events) is None

    def test_no_false_positive_slow_requests(self):
        # Same pattern but 5s gaps — human browsing speed
        events = [
            _get("10.20.0.1", "/api/users" if i % 2 == 0 else "/api/data", offset=i * 5.0)
            for i in range(15)
        ]
        assert detect_scraping(events) is None

    def test_no_false_positive_single_endpoint(self):
        # Rapid but only one endpoint — not scraping
        events = [
            _get("10.20.0.1", "/api/data", offset=i * 0.05) for i in range(20)
        ]
        assert detect_scraping(events) is None


# ── DDoS ─────────────────────────────────────────────────────────────────────

class TestDDoS:
    def test_detects_distributed_flood(self):
        events = [
            _get(f"10.{i // 10}.{i % 10}.1", "/api/data") for i in range(50)
        ]
        result = detect_ddos(events)
        assert result is not None
        assert result["pattern_type"] == "ddos"
        assert result["confidence"] >= 0.6

    def test_no_false_positive_low_volume(self):
        events = [_get(f"10.0.0.{i}", "/api/data") for i in range(20)]
        assert detect_ddos(events) is None

    def test_no_false_positive_few_ips(self):
        # High volume but only 3 IPs — not DDoS
        events = [_get(f"10.0.0.{i % 3 + 1}", "/api/data") for i in range(50)]
        assert detect_ddos(events) is None


# ── enumeration ───────────────────────────────────────────────────────────────

class TestEnumeration:
    def test_detects_sequential_ids(self):
        events = [
            _get("10.30.0.1", f"/api/users/{i}") for i in range(1, 15)
        ]
        result = detect_enumeration(events)
        assert result is not None
        assert result["pattern_type"] == "enumeration"
        assert result["affected_ips"] == ["10.30.0.1"]

    def test_no_false_positive_random_ids(self):
        ids = [3, 17, 42, 8, 99, 1, 55, 23, 7, 88]
        events = [_get("10.30.0.1", f"/api/users/{i}") for i in ids]
        assert detect_enumeration(events) is None

    def test_no_false_positive_low_volume(self):
        events = [_get("10.30.0.1", f"/api/users/{i}") for i in range(1, 4)]
        assert detect_enumeration(events) is None


# ── analyze_batch (integration) ───────────────────────────────────────────────

class TestAnalyzeBatch:
    def test_returns_all_matching_patterns(self):
        # Mix: credential stuffing logins + rapid scraping GETs
        logins = [_login(f"10.0.0.{i % 3 + 1}") for i in range(20)]
        gets = [
            _get("10.20.0.1", "/api/users" if i % 2 == 0 else "/api/data", offset=i * 0.05)
            for i in range(20)
        ]
        results = analyze_batch(logins + gets)
        pattern_types = {r["pattern_type"] for r in results}
        assert "credential_stuffing" in pattern_types
        assert "scraping" in pattern_types

    def test_sorted_by_confidence_descending(self):
        events = [_login(f"10.0.0.{i % 3 + 1}") for i in range(30)]
        results = analyze_batch(events)
        if len(results) > 1:
            for i in range(len(results) - 1):
                assert results[i]["confidence"] >= results[i + 1]["confidence"]

    def test_empty_batch_returns_empty_list(self):
        assert analyze_batch([]) == []

    def test_normal_traffic_returns_empty_list(self):
        events = [_get(f"10.0.0.{i}", "/api/data", offset=i * 3.0) for i in range(5)]
        assert analyze_batch(events) == []
