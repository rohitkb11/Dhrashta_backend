"""Receipt throughput must not count alerts as flows or infer link bandwidth."""
from types import SimpleNamespace

import ingest


def test_completed_window_rates_expire_and_ignore_current_second(monkeypatch):
    monkeypatch.setattr(ingest.time, "time", lambda: 1000)
    collector = ingest.PassiveCollector(SimpleNamespace(model_status=lambda: {}), None, None)
    collector.started_epoch = 900
    collector.observed_flows = 1200
    for tick in range(940, 1000):
        collector.flow_bins[tick] = 20
        collector.byte_bins[tick] = 62500
    collector.flow_bins[1000] = 9999
    collector.byte_bins[1000] = 9999999
    collector.byte_bins[939] = 9999999
    status = collector.status()
    assert status["flow_records_per_second"] == 20
    assert status["feed_mbps"] == .5
    assert status["rate_window_seconds"] == 60
    assert 939 not in collector.byte_bins
    monkeypatch.setattr(ingest.time, "time", lambda: 1061)
    status = collector.status()
    assert status["feed_mbps"] == 0
    assert status["flow_records_per_second"] == 0


def test_flow_rate_unknown_without_decoded_observations(monkeypatch):
    monkeypatch.setattr(ingest.time, "time", lambda: 1000)
    collector = ingest.PassiveCollector(SimpleNamespace(model_status=lambda: {}), None, None)
    assert collector.status()["feed_mbps"] is None
    collector.started_epoch = 999
    collector.byte_bins[999] = 1000
    assert collector.status()["feed_mbps"] == .008
    assert collector.status()["flow_records_per_second"] is None
    collector.record_flows(3)
    assert collector.observed_flows == 3
    assert collector.flow_bins[1000] == 3
