"""Integration checks against the isolated Compose Postgres and Redis services."""
import json
import sqlite3
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from uuid import uuid4

import psycopg2
import pytest
import redis
from fastapi.testclient import TestClient

import app as receiver

CLASSES = ["BENIGN", "C2_BEACON", "TLS_C2", "DNS_DGA", "DNS_DNSCAT2",
           "EXFIL", "SYN_FLOOD", "UDP_REFLECT", "PORT_SCAN"]
SENSOR_ALERT = {
    "timestamp": "2026-09-25T15:32:08",
    "threat_class": "C2_BEACON", "confidence": 0.94,
    "evidence": {"beacon_regularity_score": 0.998, "beacon_iat_cv": 0.0003,
                 "unique_dst_ports": 1, "beacon_event_count": 15, "packet_count": 47},
    "visibility": {"observed_direction": "both", "reverse_available": True,
                   "partial_flow": False, "capture_loss": 0.0},
    "model_version": "xgb-9c-74f-v1",
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("JOURNAL_PATH", str(tmp_path / "alerts.sqlite3"))
    with TestClient(receiver.app) as client:
        storage = receiver.storage
        # DATABASE_URL is set only by docker-compose.tests.yml to a throwaway DB.
        assert storage.pg_query("SELECT current_database() AS name")[0]["name"] == "dhrashta_test"
        storage.pg_query("TRUNCATE alerts RESTART IDENTITY")
        storage.redis.flushdb()
        yield client


def post(client, **overrides):
    return client.post("/alerts", json={"threat_class": "C2_BEACON", "confidence": 0.94,
                                       "evidence": {}, **overrides})


def postgres_down():
    raise psycopg2.OperationalError("simulated unavailable Postgres")


def redis_down(*args, **kwargs):
    raise redis.ConnectionError("simulated unavailable Redis")


def pg_count():
    return int(receiver.storage.pg_query("SELECT count(*) AS n FROM alerts")[0]["n"])


def cache():
    return [json.loads(value) for value in receiver.storage.redis.lrange("alerts_recent", 0, -1)]


def test_exact_sensor_payload_and_minimal_payload(client):
    response = client.post("/alerts", json=SENSOR_ALERT)
    assert response.status_code == 200 and response.json() == {"ok": True}
    record = client.get("/api/alerts").json()["alerts"][0]
    assert record["evidence"] == SENSOR_ALERT["evidence"]
    assert record["visibility"] == SENSOR_ALERT["visibility"]
    assert record["model_version"] == SENSOR_ALERT["model_version"]
    assert record["timestamp"] == "2026-09-25T15:32:08+00:00"
    assert post(client).status_code == 200
    assert pg_count() == 2 and len(cache()) == 2


@pytest.mark.parametrize("threat_class", CLASSES)
def test_all_nine_sensor_classes(client, threat_class):
    assert post(client, threat_class=threat_class).status_code == 200
    stats = client.get("/api/stats").json()
    assert stats["total"] == 1 and stats["by_class"] == {threat_class: 1}


@pytest.mark.parametrize("overrides", [
    {"threat_class": "COMMAND_AND_CONTROL"}, {"confidence": -0.01},
    {"confidence": 1.01}, {"confidence": ".94"}, {"confidence": True},
    {"timestamp": "yesterday"}, {"evidence": []},
    {"visibility": {"capture_loss": 1.1}},
    {"visibility": {"reverse_available": "false"}},
    {"visibility": {"observed_direction": "invalid"}},
    {"unexpected": "field"},
])
def test_invalid_payloads_are_rejected_without_writes(client, overrides):
    assert post(client, **overrides).status_code == 422
    assert pg_count() == 0 and cache() == []


@pytest.mark.parametrize("raw", [
    '{"threat_class":"C2_BEACON","confidence":NaN}',
    '{"threat_class":"C2_BEACON","confidence":Infinity}',
    '{"threat_class":"C2_BEACON","confidence":0.9,"evidence":{"nested":[NaN]}}',
    '{"threat_class":"C2_BEACON","confidence":0.9,"visibility":{"other":Infinity}}',
    '{"threat_class":',
    '{}',
])
def test_nonfinite_and_malformed_json_return_422(client, raw):
    response = client.post("/alerts", content=raw, headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], list)
    assert pg_count() == 0


def test_health_dashboard_and_api_documentation(client):
    health = client.get("/health").json()
    assert all(health[key] is True for key in ("ok", "postgres", "redis", "journal"))
    assert health["pending_postgres"] == health["pending_redis"] == 0
    page = client.get("/")
    assert page.status_code == 200 and "text/html" in page.headers["content-type"]
    assert "DRASHTA" in page.text and page.headers["cache-control"] == "no-cache"
    assert client.get("/docs").status_code == 200


def test_dashboard_navigation_targets_are_unique_sections():
    # A duplicate section/button ID previously hid the System status view.
    class DashboardParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.ids, self.views, self.sections = [], [], set()

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if "id" in attrs:
                self.ids.append(attrs["id"])
                if tag == "section":
                    self.sections.add(attrs["id"])
            if "data-view" in attrs:
                self.views.append(attrs["data-view"])

    parser = DashboardParser()
    parser.feed((Path(receiver.__file__).parent / "static" / "index.html").read_text())
    assert not [key for key, count in Counter(parser.ids).items() if count > 1]
    assert parser.views and all("view-" + view in parser.sections for view in parser.views)


def test_stats_threshold_and_class_counts(client):
    for cls, confidence in [("C2_BEACON", 0.85), ("C2_BEACON", 0.8499), ("BENIGN", 0.9)]:
        assert post(client, threat_class=cls, confidence=confidence).status_code == 200
    stats = client.get("/api/stats").json()
    assert stats == {"total": 3, "by_class": {"C2_BEACON": 2, "BENIGN": 1},
                     "high_severity": 2, "distinct_classes": 2, "source": "postgres"}


@pytest.mark.parametrize("limit", ["0", "501", "-1", "bad"])
def test_invalid_limits(client, limit):
    assert client.get(f"/api/alerts?limit={limit}").status_code == 422


def test_timestamp_normalization_and_pending_order(client, monkeypatch):
    # All timestamps must order by the instant, including fractional seconds.
    with monkeypatch.context() as patch:
        patch.setattr(receiver.storage, "postgres", postgres_down)
        for timestamp in ["2026-09-25T15:32:08", "2026-09-25T15:32:08.123",
                          "2026-09-25T21:02:08.500+05:30"]:
            assert post(client, timestamp=timestamp).status_code == 200
        data = client.get("/api/alerts?limit=2").json()
        assert data["source"] == "journal" and data["count"] == 2
        assert [item["timestamp"] for item in data["alerts"]] == [
            "2026-09-25T15:32:08.500000+00:00", "2026-09-25T15:32:08.123000+00:00"]
    receiver.storage.replay()
    assert pg_count() == 3


def test_postgres_outage_redis_still_written_and_replays_once(client, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(receiver.storage, "postgres", postgres_down)
        assert post(client).json() == {"ok": True}
        assert len(cache()) == 1
        health = client.get("/health").json()
        assert not health["ok"] and not health["postgres"] and health["redis"]
        assert health["pending_postgres"] == 1
        assert client.get("/api/stats").json()["total"] == 1
    receiver.storage.replay()
    receiver.storage.replay()
    assert pg_count() == 1 and len(cache()) == 1
    assert client.get("/health").json()["pending_postgres"] == 0


def test_redis_outage_postgres_still_written(client, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(receiver.storage.redis, "pipeline", redis_down)
        patch.setattr(receiver.storage.redis, "ping", redis_down)
        assert post(client).json() == {"ok": True}
        assert pg_count() == 1
        health = client.get("/health").json()
        assert not health["ok"] and health["postgres"] and not health["redis"]
        assert health["pending_redis"] == 1
    receiver.storage.replay()
    assert len(cache()) == 1 and pg_count() == 1
    assert client.get("/health").json()["pending_redis"] == 0


def test_both_destinations_down_are_durable_and_recover(client, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(receiver.storage, "postgres", postgres_down)
        patch.setattr(receiver.storage.redis, "pipeline", redis_down)
        assert post(client, evidence={"packet_count": 47}).json() == {"ok": True}
        assert client.get("/api/alerts").json()["alerts"][0]["evidence"] == {"packet_count": 47}
        assert client.get("/api/stats").json()["total"] == 1
        health = client.get("/health").json()
        assert health["pending_postgres"] == health["pending_redis"] == 1
    receiver.storage.replay()
    assert pg_count() == 1 and len(cache()) == 1


def test_uncertain_postgres_commit_does_not_double_count_or_duplicate(client, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(receiver.storage, "mark", lambda *args: None)
        assert post(client).status_code == 200
        assert pg_count() == 1
        assert client.get("/api/stats").json()["total"] == 1
        assert client.get("/api/alerts").json()["count"] == 1
    receiver.storage.replay()
    receiver.storage.replay()
    assert pg_count() == 1 and len(cache()) == 1


def test_delivery_crash_after_acceptance_keeps_success_and_retries(client, monkeypatch):
    def crash(*args):
        raise RuntimeError("delivery interrupted after journal committed")
    with monkeypatch.context() as patch:
        patch.setattr(receiver.storage, "deliver", crash)
        assert post(client).json() == {"ok": True}
    assert pg_count() == 0
    receiver.storage.replay()
    assert pg_count() == 1


def test_journal_failure_returns_503_without_false_acknowledgement(client, monkeypatch):
    def disk_full(*args):
        raise sqlite3.OperationalError("disk is full")
    monkeypatch.setattr(receiver.storage, "accept", disk_full)
    assert post(client).status_code == 503
    assert pg_count() == 0 and cache() == []


def test_journal_status_failure_after_commit_still_acknowledges(client, monkeypatch):
    original_journal = receiver.storage.journal
    calls = 0

    @contextmanager
    def fails_after_acceptance():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise sqlite3.OperationalError("journal temporarily unwritable after acceptance")
        with original_journal() as db:
            yield db

    with monkeypatch.context() as patch:
        patch.setattr(receiver.storage, "journal", fails_after_acceptance)
        assert post(client).json() == {"ok": True}
        assert pg_count() == 1
        health = client.get("/health").json()
        assert not health["ok"] and not health["journal"]
        assert health["pending_postgres"] is None
    assert client.get("/api/stats").json()["total"] == 1
    receiver.storage.replay()
    assert pg_count() == 1 and len(cache()) == 1


def test_redis_retention_pending_replay_and_full_fallback_stats(client, monkeypatch):
    start = datetime(2026, 9, 25, tzinfo=timezone.utc)
    # First events are accepted during an outage; subsequent POSTs write both stores.
    with monkeypatch.context() as patch:
        patch.setattr(receiver.storage, "postgres", postgres_down)
        for i in range(5):
            assert post(client, timestamp=(start + timedelta(seconds=i)).isoformat(),
                        evidence={"sequence": i}).status_code == 200
    for i in range(5, 505):
        assert post(client, timestamp=(start + timedelta(seconds=i)).isoformat(),
                    evidence={"sequence": i}).status_code == 200
    assert len(cache()) == 500
    assert [item["evidence"]["sequence"] for item in cache()] == list(range(504, 4, -1))
    receiver.storage.replay()
    assert pg_count() == 505
    assert [item["evidence"]["sequence"] for item in cache()] == list(range(504, 4, -1))
    assert client.get("/api/alerts").json()["count"] == 100
    assert client.get("/api/alerts?limit=500").json()["count"] == 500
    with monkeypatch.context() as patch:
        patch.setattr(receiver.storage, "postgres", postgres_down)
        assert client.get("/api/stats").json()["total"] == 505
        assert client.get("/api/alerts").json()["alerts"][0]["evidence"]["sequence"] == 504


def test_empty_redis_restores_from_journal(client):
    assert post(client).status_code == 200
    receiver.storage.redis.flushdb()
    receiver.storage.replay()
    assert len(cache()) == 1


def test_concurrent_ingestion_preserves_every_alert(client):
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(lambda i: post(client, evidence={"sequence": i}), range(16)))
    assert all(response.status_code == 200 for response in responses)
    assert pg_count() == 16
    assert len({item["id"] for item in cache()}) == 16
    assert client.get("/api/stats").json()["total"] == 16


def test_websocket_last_twenty_then_live_and_fanout(client):
    start = datetime(2026, 9, 25, tzinfo=timezone.utc)
    for i in range(25):
        assert post(client, timestamp=(start + timedelta(seconds=i)).isoformat(),
                    evidence={"sequence": i}).status_code == 200
    with client.websocket_connect("/ws") as first, client.websocket_connect("/ws") as second:
        for connection in (first, second):
            assert [connection.receive_json()["evidence"]["sequence"] for _ in range(20)] == list(range(5, 25))
        assert post(client, evidence={"live": True}).status_code == 200
        a, b = first.receive_json(), second.receive_json()
        assert a["id"] == b["id"] and a["evidence"] == {"live": True}
    assert not receiver.subscribers


def test_journal_survives_storage_instance_restart(client):
    record = {"id": str(uuid4()), **receiver.Alert(**SENSOR_ALERT).model_dump(mode="json")}
    receiver.storage.accept(record)
    restarted = receiver.Storage()
    try:
        restarted.replay()
        assert pg_count() == 1
        assert restarted.stats()["total"] == 1
        assert json.loads(restarted.redis.lindex("alerts_recent", 0))["id"] == record["id"]
    finally:
        restarted.redis.close()
