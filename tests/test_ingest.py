"""Passive parser, immutable upload, external model contract, and one-way tests."""
import hashlib
import ipaddress
import json
import socket
import struct
import sys
import time
from types import SimpleNamespace

import pytest

import app as receiver
from passive import ExportDecoder, InputError, decode, normalize
from test_backend import client


def ip_packet(src="192.0.2.1", dst="198.51.100.2", sport=40000, dport=443, flags=2):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 4096, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0,
                     ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed)
    return b"\0" * 12 + b"\x08\x00" + ip + tcp


def pcap(endian="<", nano=False):
    magic = (0xa1b23c4d if nano else 0xa1b2c3d4)
    data = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)
    for seconds in (1700000000, 1700000001, 1700000002):
        packet = ip_packet()
        data += struct.pack(endian + "IIII", seconds, 0, len(packet), len(packet)) + packet
    return data


def block(kind, body, endian="<"):
    body += b"\0" * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


def pcapng(endian="<"):
    packet = ip_packet(); stamp = 1700000000 * 1000000
    return (block(0x0a0d0d0a, struct.pack(endian + "IHHq", 0x1a2b3c4d, 1, 0, -1), endian)
            + block(1, struct.pack(endian + "HHI", 1, 0, 65535), endian)
            + block(6, struct.pack(endian + "IIIII", 0, stamp >> 32, stamp & 0xffffffff, len(packet), len(packet)) + packet, endian))


def netflow5():
    header = struct.pack("!HHIIIIBBH", 5, 1, 3000, 1700000003, 0, 1, 0, 0, 0)
    row = bytearray(48)
    row[:4] = ipaddress.ip_address("192.0.2.1").packed
    row[4:8] = ipaddress.ip_address("198.51.100.2").packed
    row[16:32] = struct.pack("!IIII", 3, 120, 0, 2000)
    row[32:36] = struct.pack("!HH", 40000, 443); row[37:39] = bytes([2, 6])
    return header + row


def templated(version=10, templates=True):
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4)]
    template = struct.pack("!HH", 256, len(fields)) + b"".join(struct.pack("!HH", *field) for field in fields)
    values = ipaddress.ip_address("192.0.2.1").packed + ipaddress.ip_address("198.51.100.2").packed + struct.pack("!HHBII", 40000, 443, 6, 3, 120)
    body = (struct.pack("!HH", 2 if version == 10 else 0, len(template) + 4) + template) if templates else b""
    body += struct.pack("!HH", 256, len(values) + 4) + values
    if version == 10:
        return struct.pack("!HHIII", 10, len(body) + 16, 1700000000, 1, 42) + body
    return struct.pack("!HHIIII", 9, 2, 1000, 1700000000, 1, 42) + body


def sflow5():
    record = struct.pack("!II", 60, 6) + ipaddress.ip_address("192.0.2.1").packed + ipaddress.ip_address("198.51.100.2").packed + struct.pack("!IIII", 40000, 443, 2, 0)
    sample = struct.pack("!IIIIIIII", 1, 1, 100, 1000, 0, 1, 2, 1) + struct.pack("!II", 3, len(record)) + record
    return struct.pack("!II", 5, 1) + ipaddress.ip_address("192.0.2.10").packed + struct.pack("!IIII", 0, 1, 1000, 1) + struct.pack("!II", 1, len(sample)) + sample


@pytest.mark.parametrize("payload,kind,packets", [(pcap(), "pcap", 3), (pcap(">"), "pcap", 3), (pcap(nano=True), "pcap", 3),
    (pcapng(), "pcapng", 1), (pcapng(">"), "pcapng", 1), (netflow5(), "netflow", 3),
    (templated(9), "netflow", 3), (templated(), "ipfix", 3), (sflow5(), "sflow", 1)])
def test_binary_inputs_without_network_calls(payload, kind, packets, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("A passive parser attempted a network operation")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    for method in ("connect", "connect_ex", "send", "sendall", "sendto"):
        monkeypatch.setattr(socket.socket, method, forbidden)
    rows, notes = decode(payload, kind)
    assert len(rows) == 1 and rows[0]["flow_id"].startswith("flow-")
    assert rows[0]["features"]["packet_count"] == packets
    assert rows[0]["src_ip"] == "192.0.2.1" and rows[0]["dst_port"] == 443
    if kind == "pcap":
        assert rows[0]["features"]["iat_mean_seconds"] == 1
        assert rows[0]["features"]["iat_cv"] == 0
        assert rows[0]["features"]["syn_count"] == 3


def test_template_state_is_passive_and_exporter_scoped():
    parser = ExportDecoder()
    rows, notes = decode(templated(templates=False), "ipfix", parser, "sender-a")
    assert rows == [] and "no passively received template" in notes[0]
    assert len(decode(templated(), "ipfix", parser, "sender-a")[0]) == 1
    assert len(decode(templated(templates=False), "ipfix", parser, "sender-a")[0]) == 1
    assert decode(templated(templates=False), "ipfix", parser, "sender-b")[0] == []


@pytest.mark.parametrize("payload,kind", [(pcap()[:-1], "pcap"), (pcapng()[:-4], "pcapng"),
    (netflow5()[:-1], "netflow"), (templated()[:-1], "ipfix"), (sflow5()[:-1], "sflow"),
    (b"not a capture", "pcap"), (b"{", "metadata"), (b"[]", "flow-json")])
def test_malformed_inputs_fail_explicitly(payload, kind):
    with pytest.raises(InputError):
        decode(payload, kind)


def test_exported_csv_aliases_and_unknown_measurements():
    rows, _ = decode(b"sourceIPv4Address,destinationIPv4Address,sourceTransportPort,destinationTransportPort,protocolIdentifier,packetDeltaCount,octetDeltaCount\n192.0.2.1,198.51.100.2,40000,443,6,3,120\n", "flow-csv")
    assert rows[0]["features"]["mean_packet_bytes"] == 40
    assert "duration_seconds" not in rows[0]["features"]
    assert "bytes_per_second" not in rows[0]["features"]


@pytest.mark.parametrize("row", [{"flow_id": " ", "features": {}}, {"flow_id": "x", "features": {"bad": float("nan")}},
    {"src_ip": "example.com", "dst_ip": "192.0.2.1", "src_port": 1, "dst_port": 2, "protocol": 6},
    {"flow_id": "x", "packet_count": True}, {"flow_id": "x", "duration_seconds": -1},
    {"flow_id": "x", "flowStartMilliseconds": "bad"}])
def test_metadata_validation(row):
    with pytest.raises(InputError):
        normalize(row)


def upload(client, payload=None, kind="pcap"):
    return client.post("/api/ingest/upload", data={"format": kind}, files={"file": ("test-input.bin", payload or pcap(), "application/octet-stream")})


def model_alert(flow_id):
    # Explicit test double/replay record, not a trained classifier.
    return {"flow_id": flow_id, "timestamp": "2026-09-26T12:00:00Z", "threat_class": "C2_BEACON", "confidence": .94,
            "evidence": {"fixture_only": True, "packet_count": 3}, "model_version": "qa-external-output"}


def test_immutable_upload_awaits_model_and_does_not_fabricate_alerts(client):
    payload = pcap(); response = upload(client, payload)
    assert response.status_code == 200
    job = response.json(); assert job["state"] == "awaiting_model" and job["flow_count"] == 1
    assert job["sha256"] == hashlib.sha256(payload).hexdigest()
    assert client.get(f"/api/ingest/{job['id']}/original").content == payload
    features = client.get(f"/api/ingest/{job['id']}/features").json()
    assert features["records"][0]["features"]["packet_count"] == 3
    assert client.get("/api/stats").json()["total"] == 0
    assert client.get("/api/ingest").json()["model"]["available"] is False


def test_replay_linked_outputs_are_atomic_and_idempotent(client):
    job = upload(client).json(); flow = client.get(f"/api/ingest/{job['id']}/features").json()["records"][0]
    payload = {"alerts": [model_alert(flow["flow_id"])]}
    with client.websocket_connect("/ws") as ws:
        response = client.post(f"/api/ingest/{job['id']}/detections", json=payload)
        assert response.json() == {"ok": True, "accepted": 1}
        record = ws.receive_json()
        assert record["input_id"] == job["id"] and record["flow_id"] == flow["flow_id"] and record["severity"] == "high"
    assert client.post(f"/api/ingest/{job['id']}/detections", json=payload).json()["accepted"] == 0
    assert client.get("/api/stats").json()["total"] == 1
    assert client.get(f"/api/ingest/{job['id']}/original").content == pcap()
    bad = {"alerts": [model_alert(flow["flow_id"]), model_alert("foreign-flow")]}
    assert client.post(f"/api/ingest/{job['id']}/detections", json=bad).status_code == 422
    assert client.get("/api/stats").json()["total"] == 1


def test_standalone_detection_replay_preserves_original_bytes(client):
    original = json.dumps([model_alert("sensor-flow-123")], indent=2).encode()
    response = upload(client, original, "detections"); assert response.status_code == 200
    job = response.json(); assert job["state"] == "replayed_detections" and job["alert_count"] == 1
    assert client.get(f"/api/ingest/{job['id']}/original").content == original
    assert job["sha256"] == hashlib.sha256(original).hexdigest()


def test_local_external_adapter_hook(client, monkeypatch):
    def predict(*, observations, input_bytes, input_format):
        assert input_bytes == pcap() and input_format == "pcap"
        return [model_alert(observations[0]["flow_id"])]
    receiver.pipeline.model = SimpleNamespace(predict=predict)
    job = upload(client).json()
    assert job["state"] == "model_inferred" and job["alert_count"] == 1


def test_bad_model_output_keeps_evidence_without_alert(client):
    receiver.pipeline.model = SimpleNamespace(predict=lambda **kwargs: [model_alert("wrong-flow")])
    job = upload(client).json()
    assert job["state"] == "model_error"
    assert client.get(f"/api/ingest/{job['id']}/original").content == pcap()
    assert client.get("/api/stats").json()["total"] == 0


def test_udp_monitor_is_receive_only_and_requires_flow_id(client):
    assert client.post("/api/monitor", json={"active": True}).status_code == 200
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.settimeout(.2)
        data = json.dumps({"kind": "alerts", "alerts": [model_alert("udp-qa-flow")]}).encode()
        sender.sendto(data, ("127.0.0.1", receiver.collector.port))
        for _ in range(30):
            status = client.get("/api/ingest").json()["monitor"]
            if status["processed"]:
                break
            time.sleep(.02)
        assert status["processed"] == 1
        with pytest.raises(socket.timeout):
            sender.recvfrom(65535)  # No ACK or other return packet.
        assert client.get("/api/stats").json()["total"] == 1
        bad = model_alert("x"); del bad["flow_id"]
        sender.sendto(json.dumps({"kind": "alerts", "alerts": [bad]}).encode(), ("127.0.0.1", receiver.collector.port))
        for _ in range(30):
            if client.get("/api/ingest").json()["monitor"]["rejected"]:
                break
            time.sleep(.02)
        assert client.get("/api/ingest").json()["monitor"]["rejected"] == 1
        assert client.get("/api/stats").json()["total"] == 1
        assert client.post("/api/monitor", json={"active": False}).json()["active"] is False


def test_rejected_uploads_and_monitor_controls(client):
    assert upload(client, b"bad", "pcap").status_code == 422
    assert upload(client, b"bad", "anything").status_code == 422
    assert upload(client, b"[]", "detections").status_code == 422
    assert client.get("/api/ingest").json()["inputs"] == []
    assert client.post("/api/monitor", json={"active": "true"}).status_code == 422
    assert client.get("/api/ingest/not-found/features").status_code == 404


def test_relay_framing_preserves_original_bytes(client):
    client.post("/api/monitor", json={"active": True})
    original = json.dumps({"records": [{"flow_id": "relay-flow", "features": {"packet_count": 3}}]}).encode()
    frame = b"DRASHTA-PASSIVE-V1\x00" + b"192.0.2.3:2055\x00" + original
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.sendto(frame, ("127.0.0.1", receiver.collector.port))
    for _ in range(30):
        jobs = client.get("/api/ingest").json()["inputs"]
        if jobs:
            break
        time.sleep(.02)
    assert len(jobs) == 1 and jobs[0]["state"] == "awaiting_model"
    assert client.get(f"/api/ingest/{jobs[0]['id']}/original").content == original
    assert client.get("/api/stats").json()["total"] == 0


def test_upload_size_limit_before_multipart_spooling(client):
    def chunks():
        for _ in range(12):
            yield b"x" * (1024 * 1024)
    response = client.post("/api/ingest/upload", content=chunks(),
                           headers={"Content-Type": "multipart/form-data; boundary=qa"})
    assert response.status_code == 413
    assert client.get("/api/ingest").json()["inputs"] == []
