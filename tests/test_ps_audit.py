"""PS audit: isolated API workflows and integration regression checks.

All labels are supplied test fixtures. Provider calls are mocked; no classifier
is added and main storage is untouched.
"""
import base64
import hashlib
import json
from datetime import datetime, timezone

import pytest

import app as receiver
import reports
from test_backend import client, post
from test_ingest import pcap, upload
from test_reports import configured, wait_report


def test_all_public_routes_workflow(client, monkeypatch):
    monkeypatch.setattr(reports, "worker_call", configured)
    for path in ["/", "/health", "/openapi.json", "/docs", "/redoc", "/api/alerts",
                 "/api/stats", "/api/ingest", "/api/history", "/api/analytics/heatmap",
                 "/api/network", "/api/reports", "/api/investigations/ip?address=192.0.2.1"]:
        assert client.get(path).status_code == 200, path
    for path in ["/api/history/missing", "/api/ingest/missing", "/api/ingest/missing/features",
                 "/api/ingest/missing/original", "/api/reports/missing", "/api/reports/missing/download"]:
        assert client.get(path).status_code == 404, path
    assert client.get("/api/network?mode=capture&input_id=missing").status_code == 404
    assert client.post("/api/monitor", json={"active": True}).status_code == 200
    assert client.post("/api/monitor", json={"active": False}).status_code == 200

    original = pcap()
    job = upload(client, original).json()
    identifier = job["id"]
    assert client.get(f"/api/ingest/{identifier}").json()["sha256"] == hashlib.sha256(original).hexdigest()
    observations = client.get(f"/api/ingest/{identifier}/features?download=true")
    assert "attachment" in observations.headers["content-disposition"]
    flow = observations.json()["records"][0]
    assert client.get(f"/api/ingest/{identifier}/original").content == original
    graph = client.get("/api/network", params={"mode": "capture", "input_id": identifier}).json()
    assert len(graph["nodes"]) == 2 and graph["edges"][0]["unusual_alerts"] == 0
    stamp = datetime.now(timezone.utc).isoformat()
    external = {"timestamp": stamp, "flow_id": flow["flow_id"], "threat_class": "SYN_FLOOD",
                "confidence": .92, "evidence": {"fixture_only": True, "syn_count": 3,
                    "reason": "Supplied fixture explanation", "protocol": 6, "anomaly_score": .91,
                    "feature_assessments": {"syn_count": {"level": "high", "reason": "Fixture only"}},
                    "contributions": ["Supplied test contribution"],
                    "flow_timeline": [{"timestamp": stamp, "event": "Fixture alert"}]}}
    with client.websocket_connect("/ws") as ws:
        response = client.post(f"/api/ingest/{identifier}/detections", json={"alerts": [external]})
        assert response.json() == {"ok": True, "accepted": 1}
        alert = ws.receive_json()
    assert alert["evidence"] == external["evidence"]
    assert alert["src_ip"] == flow["src_ip"] and alert["endpoint_source"]["src"] == "input observation"
    assert client.get("/api/history/" + alert["id"]).json()["input_id"] == identifier
    assert client.get("/api/history", params={"alert_id": alert["id"]}).json()["total"] == 1
    graph = client.get("/api/network", params={"mode": "capture", "input_id": identifier,
                                             "unusual_only": True}).json()
    assert graph["edges"][0]["unusual_alerts"] == 1
    assert client.get("/api/network?mode=live").json()["nodes"] == []
    ip = client.get("/api/investigations/ip", params={"address": flow["src_ip"], "download": True})
    assert ip.json()["total_alerts"] == 1 and "attachment" in ip.headers["content-disposition"]
    heatmap = client.get("/api/analytics/heatmap").json()
    assert heatmap["total"] == 1 and len(heatmap["days"]) == 7
    assert sum(cell["count"] for day in heatmap["days"] for cell in day["hours"]) == 1
    created = client.post("/api/reports", json={"alert_ids": [alert["id"]]})
    assert created.status_code == 202
    report = wait_report(client, created.json()["id"])
    assert report["state"] == "draft" and report["sources"][0]["alert"]["input_id"] == identifier
    assert report["sources"][0]["alert"]["evidence"] == external["evidence"]
    assert client.get(f"/api/reports/{report['id']}/download?format=json").json() == report
    assert client.get(f"/api/reports/{report['id']}/download?format=text").status_code == 200
    assert post(client, flow_id="management-fixture").status_code == 200


@pytest.mark.parametrize("params", [{"severity": "critical"}, {"origin": "sensor"},
    {"threat_class": "unmapped"}, {"ip": "sensor.example"}, {"since": "yesterday"},
    {"since": "2026-09-28", "until": "2026-09-27"}, {"cursor": "garbage"}, {"limit": 101}])
def test_history_validation(client, params):
    assert client.get("/api/history", params=params).status_code == 422


def test_history_beyond_cache_and_stable_pagination(client):
    stamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    # Bulk isolated journal records bypass transport to exercise the >500 retained-history boundary.
    with receiver.storage.journal() as db:
        for index in range(521):
            record = {"id": f"audit-{index:04}", "timestamp": stamp, "flow_id": f"fixture-{index}",
                      "threat_class": "PORT_SCAN", "confidence": .91, "severity": "high", "evidence": {},
                      "visibility": None, "model_version": "test-only", "src_ip": "192.0.2.10",
                      "dst_ip": "198.51.100.20", "origin": "external", "input_id": None}
            db.execute("INSERT INTO journal(event_id,payload,postgres_done,redis_done) VALUES(?,?,1,1)",
                       (record["id"], json.dumps(record)))
    ids, params = [], {"limit": 100}
    while True:
        page = client.get("/api/history", params=params).json()
        assert page["total"] == 521
        ids.extend(row["id"] for row in page["alerts"])
        if not page["next_cursor"]:
            break
        params["cursor"] = page["next_cursor"]
    assert len(ids) == len(set(ids)) == 521
    assert client.get("/api/investigations/ip?address=192.0.2.10").json()["total_alerts"] == 521
    assert client.get("/api/analytics/heatmap").json()["total"] == 521


def test_missing_cursor_watermarks_rejected(client):
    client._transport.raise_server_exceptions = False
    filters = receiver.investigations.filters()
    token = base64.urlsafe_b64encode(json.dumps({"filters": filters,
        "after": [datetime.now(timezone.utc).isoformat(timespec="microseconds"), "id"], "marks": {"wrong": 0}}).encode()).decode()
    assert client.get("/api/history", params={"cursor": token}).status_code == 422


def test_external_zero_detection_completion(client):
    job = upload(client).json()
    result = client.post(f"/api/ingest/{job['id']}/detections", json={"alerts": []})
    assert result.status_code == 200 and result.json() == {"ok": True, "accepted": 0}
    summary = client.get(f"/api/ingest/{job['id']}").json()
    assert summary["state"] == "replayed_detections" and summary["alert_count"] == 0
    assert client.get("/api/stats").json()["total"] == 0
    assert client.post("/api/ingest/missing/detections", json={"alerts": []}).status_code == 404
    assert client.post(f"/api/ingest/{job['id']}/detections", json={"alerts": [], "typo": True}).status_code == 422


def test_report_accepts_legacy_history_id(client, monkeypatch):
    monkeypatch.setattr(reports, "worker_call", configured)
    receiver.storage.pg_query("INSERT INTO alerts(ts,threat_class,confidence,evidence) VALUES(now(),'EXFIL',.9,'{}')")
    legacy = client.get("/api/history").json()["alerts"][0]
    assert legacy["id"].startswith("pg-")
    assert client.post("/api/reports", json={"alert_ids": [legacy["id"]]}).status_code == 202


@pytest.mark.parametrize("body", [None, {}, {"alerts": "wrong"}, {"alerts": [{"threat_class": "PORT_SCAN", "confidence": .9}]}, {"alerts": [], "unknown": True}])
def test_detection_batch_contract_rejects_malformed_requests(client, body):
    job = upload(client).json()
    assert client.post(f"/api/ingest/{job['id']}/detections", json=body).status_code == 422
    assert client.get(f"/api/ingest/{job['id']}").json()["state"] == "awaiting_model"
    assert client.get("/api/stats").json()["total"] == 0


def test_openapi_exposes_detection_contract(client):
    schema = client.get("/openapi.json").json()
    models = schema["components"]["schemas"]
    assert "DetectionBatch" in models and "DetectionResult" in models
    assert models["DetectionBatch"]["properties"]["alerts"]["maxItems"] == 100
    assert set(["timestamp", "flow_id", "threat_class", "confidence", "evidence"]) <= set(models["DetectionResult"]["required"])
