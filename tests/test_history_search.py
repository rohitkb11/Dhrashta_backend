"""Alert-ID search against the isolated test database and durable journal."""
import pytest

import app as receiver
from test_backend import client, post


@pytest.mark.parametrize("source", ["both", "journal", "postgres"])
def test_exact_alert_id_search(client, monkeypatch, source):
    assert post(client).status_code == 200
    assert post(client, threat_class="EXFIL", confidence=0.73).status_code == 200
    records = client.get("/api/alerts").json()["alerts"]
    target = next(record for record in records if record["threat_class"] == "EXFIL")
    if source == "journal":
        def unavailable(*args, **kwargs):
            raise RuntimeError("isolated database outage")
        monkeypatch.setattr(receiver.storage, "pg_query", unavailable)
    elif source == "postgres":
        with receiver.storage.journal() as db:
            db.execute("DELETE FROM journal")

    page = client.get("/api/history", params={"alert_id": "  " + target["id"] + "  "}).json()
    assert page["total"] == 1
    assert [record["id"] for record in page["alerts"]] == [target["id"]]
    assert page["next_cursor"] is None
    for missing in [target["id"][:8], "missing-id", "' OR 1=1 --"]:
        response = client.get("/api/history", params={"alert_id": missing})
        assert response.status_code == 200
        assert response.json()["alerts"] == []
        assert response.json()["total"] == 0


def test_alert_id_respects_filters_and_length(client):
    assert post(client).status_code == 200
    target = client.get("/api/alerts").json()["alerts"][0]
    assert client.get("/api/history", params={"alert_id": target["id"], "severity": "low"}).json()["total"] == 0
    assert client.get("/api/history", params={"alert_id": "x" * 201}).status_code == 422
    page = client.get("/api/history", params={"alert_id": " "}).json()
    assert page["total"] == 1


def test_history_search_controls(client):
    page = client.get("/").text
    assert 'id="history-alert-id"' in page
    assert 'id="history-ip"' not in page
    assert "$('history-form').addEventListener('submit'" in page
