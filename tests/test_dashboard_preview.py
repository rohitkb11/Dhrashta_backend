"""Assets and retained-history drill-downs; isolated fixtures only."""
import app as receiver
from test_backend import client, post, postgres_down


def test_local_chart_and_preview_assets(client):
    for name in ("charts.js", "preview.js", "threats.js"):
        response = client.get("/assets/" + name)
        assert response.status_code == 200
        assert "javascript" in response.headers["content-type"]
    assert client.get("/api/history?alert_id=sample-alert-0001").json()["total"] == 0


def test_heatmap_history_excludes_benign_in_both_stores(client, monkeypatch):
    assert post(client, threat_class="BENIGN").status_code == 200
    assert post(client, threat_class="SYN_FLOOD").status_code == 200
    for degraded in (False, True):
        if degraded:
            monkeypatch.setattr(receiver.storage, "postgres", postgres_down)
        history = client.get("/api/history?exclude_benign=true").json()
        assert history["total"] == 1
        assert history["alerts"][0]["threat_class"] == "SYN_FLOOD"
        assert client.get("/api/history").json()["total"] == 2
        assert client.get("/api/analytics/heatmap").json()["total"] == 1
