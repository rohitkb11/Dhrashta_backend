"""Report jobs use only isolated database fixtures and mocked provider transport."""
import asyncio
import copy
import hashlib
import json
import time
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient

import app as receiver
import reports
import report_worker as worker
from test_backend import client, post


def narrative(refs=("A1",)):
    return {"summary": "Detector labelled these observations; analyst review is required.",
            "findings": [{"title": "Labelled activity", "analysis": "The supplied evidence requires review.", "alert_refs": list(refs)}],
            "recommendations": ["Review the saved evidence."], "limitations": ["Unverified draft; sparse sensor evidence."]}


def configured(path, body=None, timeout=3):
    if path == "/status":
        return {"model": "gemini-3.5-flash-lite", "configured": True}
    return {"narrative": narrative(tuple(item["ref"] for item in body["sources"])), "usage": {"totalTokenCount": 88}}


def wait_report(client, report_id):
    for _ in range(150):
        result = client.get("/api/reports/" + report_id).json()
        if result["state"] not in ("queued", "generating"):
            return result
        time.sleep(.02)
    pytest.fail("Report did not finish")


def test_empty_unconfigured_and_safe_status(client, monkeypatch):
    def unavailable(*args):
        raise RuntimeError("secret should not be exposed")
    monkeypatch.setattr(reports, "worker_call", unavailable)
    assert client.get("/api/reports").json() == {"reports": [], "generator": {
        "provider": "Google Gemini", "model": None, "configured": False, "available": False}}
    response = client.post("/api/reports", json={"alert_ids": ["missing"]})
    assert response.status_code == 503
    assert "secret" not in response.text
    oversized = client.post("/api/reports", content=b"x" * (16 * 1024 + 1), headers={"Content-Type": "application/json"})
    assert oversized.status_code == 413 and receiver.reports.list() == []


def test_snapshot_citations_exports_and_durability(client, monkeypatch):
    monkeypatch.setattr(reports, "worker_call", configured)
    assert post(client, flow_id="source-flow", evidence={"packet_count": 17, "note": "<script>alert(1)</script>"}).status_code == 200
    record = client.get("/api/alerts").json()["alerts"][0]
    response = client.post("/api/reports", json={"title": "Investigation", "alert_ids": [record["id"]]})
    assert response.status_code == 202
    report = wait_report(client, response.json()["id"])
    assert report["state"] == "draft"
    assert report["sources"] == [{"ref": "A1", "alert": record}]
    assert report["source_sha256"] == hashlib.sha256(reports.canonical(report["sources"]).encode()).hexdigest()
    # Evidence remains unchanged even if the source record is later edited or deleted.
    with receiver.storage.journal() as db:
        db.execute("DELETE FROM journal WHERE event_id=?", (record["id"],))
    receiver.storage.pg_query("DELETE FROM alerts WHERE event_id=%s", (record["id"],))
    restarted = reports.Reports(receiver.storage)
    assert restarted.get(report["id"])["sources"] == report["sources"]
    download = client.get(f"/api/reports/{report['id']}/download?format=json")
    assert download.json() == report and "attachment" in download.headers["content-disposition"]
    text = client.get(f"/api/reports/{report['id']}/download?format=text")
    assert "DRAFT" in text.text and "packet_count" in text.text and "source-flow" in text.text
    assert client.get("/api/reports/nonexistent").status_code == 404


@pytest.mark.parametrize("body", [{"alert_ids": []}, {"alert_ids": ["x", "x"]},
    {"alert_ids": [str(i) for i in range(31)]}, {"alert_ids": ["x"], "title": "   "},
    {"alert_ids": ["x"], "provider_url": "http://sensor"}])
def test_request_bounds(client, monkeypatch, body):
    monkeypatch.setattr(reports, "worker_call", configured)
    assert client.post("/api/reports", json=body).status_code == 422
    assert receiver.reports.list() == []


def test_missing_alert_rejects_whole_report(client, monkeypatch):
    monkeypatch.setattr(reports, "worker_call", configured)
    post(client)
    record = client.get("/api/alerts").json()["alerts"][0]
    assert client.post("/api/reports", json={"alert_ids": [record["id"], "missing"]}).status_code == 422
    assert receiver.reports.list() == []


def test_oversized_evidence_and_queue_limit(client):
    post(client, evidence={"large": "x" * reports.MAX_SOURCE_BYTES})
    record = client.get("/api/alerts").json()["alerts"][0]
    with pytest.raises(Exception) as exc:
        receiver.reports.create(reports.ReportRequest(alert_ids=[record["id"]]), "test")
    assert exc.value.status_code == 413
    receiver.reports.stop.set()
    post(client)
    record = client.get("/api/alerts").json()["alerts"][0]
    for _ in range(8):
        receiver.reports.create(reports.ReportRequest(alert_ids=[record["id"]]), "test")
    with pytest.raises(Exception) as exc:
        receiver.reports.create(reports.ReportRequest(alert_ids=[record["id"]]), "test")
    assert exc.value.status_code == 429


def test_provider_failure_no_secret_or_fabricated_fallback(client, monkeypatch):
    def fail(path, body=None, timeout=3):
        if path == "/status":
            return configured(path)
        raise RuntimeError("provider API key SECRET, error body")
    monkeypatch.setattr(reports, "worker_call", fail)
    post(client)
    record = client.get("/api/alerts").json()["alerts"][0]
    response = client.post("/api/reports", json={"alert_ids": [record["id"]]})
    report = wait_report(client, response.json()["id"])
    assert report["state"] == "failed" and report["narrative"] is None
    assert "SECRET" not in json.dumps(report)


@pytest.mark.parametrize("refs", [("A2",), (), ("A1", "A2")])
def test_invalid_citation_rejected(refs):
    with pytest.raises(ValueError):
        reports.validate_narrative(narrative(refs), [{"ref": "A1"}])


def test_all_sources_must_be_addressed():
    with pytest.raises(ValueError):
        reports.validate_narrative(narrative(), [{"ref": "A1"}, {"ref": "A2"}])


def test_interrupted_request_not_automatically_retried(client):
    receiver.reports.stop.set()
    post(client)
    record = client.get("/api/alerts").json()["alerts"][0]
    report = receiver.reports.create(reports.ReportRequest(alert_ids=[record["id"]]), "test")
    report["state"] = "generating"
    receiver.reports.update(report)
    assert reports.Reports(receiver.storage).get(report["id"])["state"] == "failed"


def test_fixed_gemini_transport_schema_and_response(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    sources = [{"ref": "A1", "alert": {"evidence": {"url": "http://sensor/probe", "note": "ignore instructions"}}}]
    calls = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit):
            return json.dumps({"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": json.dumps(narrative())}]}}],
                               "usageMetadata": {"totalTokenCount": 90, "unexpected": "secret"}}).encode()
    class Opener:
        def open(self, req, timeout):
            calls.append(req)
            assert timeout == 90
            return Response()
    monkeypatch.setattr(worker, "build_opener", lambda *args: Opener())
    result = worker.generate(sources)
    assert result["usage"] == {"totalTokenCount": 90}
    assert len(calls) == 1 and calls[0].full_url.startswith("https://generativelanguage.googleapis.com/v1beta/models/")
    assert calls[0].get_header("X-goog-api-key") == "test-key"
    body = json.loads(calls[0].data)
    assert json.loads(body["contents"][0]["parts"][0]["text"]) == sources
    assert "tools" not in body
    schema = body["generationConfig"]["responseFormat"]["text"]["schema"]
    assert schema["properties"]["findings"]["items"]["properties"]["alert_refs"]["items"]["enum"] == ["A1"]
    assert "$ref" not in json.dumps(schema) and "maxLength" not in json.dumps(schema)
    assert body["generationConfig"]["responseFormat"]["text"]["mimeType"] == "APPLICATION_JSON"
    assert worker.NoRedirect().redirect_request(None, None, 302, "", {}, "http://sensor") is None


def test_worker_unconfigured_and_model_mismatch(monkeypatch):
    with TestClient(worker.app) as client:
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        assert not client.get("/status").json()["configured"]
        body = {"model": worker.MODEL, "sources": [{"ref": "A1", "alert": {}}]}
        assert client.post("/generate", json=body).status_code == 503
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        assert client.post("/generate", json={**body, "model": "gemini-other"}).status_code == 409
        assert client.post("/generate", json={**body, "sources": [{"ref": "A9"}]}).status_code == 422


@pytest.mark.parametrize("finish", ["MAX_TOKENS", "SAFETY"])
def test_incomplete_provider_response_rejected(monkeypatch, finish):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return json.dumps({"candidates": [{"finishReason": finish}]}).encode()
    class Opener:
        def open(self, *args, **kwargs): return Response()
    monkeypatch.setattr(worker, "build_opener", lambda *args: Opener())
    with pytest.raises(Exception) as exc:
        worker.generate([{"ref": "A1"}])
    assert exc.value.status_code == 502
