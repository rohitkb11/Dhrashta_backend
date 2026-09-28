# Drashta receiving API

Management base URL: `http://localhost:8000`. Production-side passive sources use receive-only UDP, not this HTTP API.

## POST /alerts

The supplied sensor payload is accepted unchanged:

```json
{
  "timestamp": "2026-09-25T15:32:08",
  "threat_class": "C2_BEACON",
  "confidence": 0.94,
  "evidence": {
    "beacon_regularity_score": 0.998,
    "beacon_iat_cv": 0.0003,
    "unique_dst_ports": 1,
    "beacon_event_count": 15,
    "packet_count": 47
  },
  "visibility": {
    "observed_direction": "both",
    "reverse_available": true,
    "partial_flow": false,
    "capture_loss": 0.0
  },
  "model_version": "xgb-9c-74f-v1"
}
```

The response is exactly HTTP 200 with `{"ok": true}` after durable acceptance. If one or both external stores fail, this remains HTTP 200 because the alert is journaled and scheduled for replay. Journal-commit failure returns HTTP 503 and requires sender retry. Invalid payloads return HTTP 422 with validation details and are not stored.

Required fields: `threat_class` and `confidence`. `evidence` defaults to `{}`, `timestamp` defaults to the receiver's current UTC time, and `visibility`/`model_version` default to `null`. Confidence is a finite JSON number from 0 to 1; strings and booleans are rejected. Evidence supports nested JSON values, but NaN and infinity are rejected throughout evidence and visibility.

The exact nine classes are `BENIGN`, `C2_BEACON`, `TLS_C2`, `DNS_DGA`, `DNS_DNSCAT2`, `EXFIL`, `SYN_FLOOD`, `UDP_REFLECT`, and `PORT_SCAN`. Other top-level fields are rejected. Visibility accepts `both`, `forward`, `reverse`, or `unknown`, boolean flow flags, and capture loss from 0 to 1. Additional visibility measurements are retained. UTC is assumed when a timestamp omits its timezone; supplied offsets are normalized to UTC.

The sensor contract has no request ID. Each received POST represents a new event, even if its payload matches an earlier POST. Internal replay uses the receiver-assigned event ID and does not create duplicate events.

## GET /api/alerts?limit=100

`limit` must be an integer from 1 to 500. Default: 100. Alerts are returned newest sensor timestamp first. Each includes a stable receiver-assigned `id`, `timestamp`, and the supplied alert fields.

```json
{"count": 0, "alerts": [], "source": "postgres"}
```

`count` is the number of records in this response, not the full-history total. Pending events are merged without duplicate IDs. `source` reports `postgres` or `journal` for outage fallback.

## GET /api/stats

```json
{
  "total": 0,
  "by_class": {},
  "high_severity": 0,
  "distinct_classes": 0,
  "source": "postgres"
}
```

Counts include durable pending events. `high_severity` follows the supplied threshold `confidence >= 0.85`, including `BENIGN` if its confidence meets that threshold. This is a prototype confidence-based display measure, not an independent severity assessment. `distinct_classes` includes every observed class. Counts cover full retained history, even when the 500-entry cache or 100-entry feed has rolled over.

## GET /health

```json
{
  "ok": true,
  "redis": true,
  "postgres": true,
  "pending_postgres": 0,
  "pending_redis": 0,
  "journal": true
}
```

The endpoint returns HTTP 200 with dependency status. `ok` is true when both stores and the journal are usable. Pending counters expose outstanding destination writes. A false dependency status does not discard accepted alerts. If the journal cannot be read, its status is false and pending counters are null.

## WebSocket /ws

Connect to `ws://<host>:8000/ws`. The server sends up to 20 recent alerts, oldest first within that snapshot, then one JSON text message per newly accepted alert. Snapshot registration and ingestion are serialized to prevent gaps between snapshot and live delivery. Each message has the same record shape as `/api/alerts`.

The server does not send empty history or heartbeat messages as alerts. Slow clients whose 500-message queue fills are closed with code 1013 and should reconnect. The dashboard reconnects after two seconds, reconciles recent history by record ID, and retains at most 100 alerts. Its connection indicator describes browser-to-receiver connectivity.

## GET / and API documentation

`/` serves the dashboard; `/assets/` serves its local JavaScript modules. `/docs`, `/redoc` and `/openapi.json` expose API documentation and schemas. The dashboard consumes the management HTTP APIs and `/ws`.

## Evidence reports

Report endpoints, cloud configuration, immutable evidence snapshots and limits are documented in [REPORTS.md](REPORTS.md). Reports use the selected Google Gemini cloud provider independently of the external detection model. The separate frontend can consume these report endpoints.

## Passive observations

Management HTTP is now localhost-only by default. Strict one-way sensor ingest uses receive-only UDP 2055 through a fixed-target ingress relay, with no source ACK or template query. POST /alerts is retained for management compatibility and is not a one-way source connection.

See [PASSIVE_INGEST.md](PASSIVE_INGEST.md) for upload, feature/original retrieval, attached detections, monitor controls, limits and format support, and [MODEL_INTEGRATION.md](MODEL_INTEGRATION.md) for future raw PCAP/NetFlow inference. New alert records include flow_id, input_id when associated, and confidence-derived severity. New-path alerts require flow IDs; legacy records can omit them. Missing visibility booleans/loss remain null (unknown).

## Retained investigations and integration

- `GET /api/history`: `limit` 1-100, opaque `cursor`, exact `alert_id`, literal `ip`, `threat_class`, confidence-derived `severity`, `origin`, `since`/`until`, and `exclude_benign`. Response: `alerts`, matching `total`, `next_cursor`, `source`. Keep filters unchanged across pages; malformed/incomplete cursors return 422.
- `GET /api/history/{alert_id}`: retained record, or 404; unavailable history returns 503.
- `GET /api/analytics/heatmap`: seven UTC dates x 24 hours, non-BENIGN counts and peak confidence.
- `GET /api/network?mode=live|capture&input_id=...&unusual_only=true|false`: retained passive endpoint graph. Capture mode requires a retained input. This API remains available although its dashboard panel was removed.
- `GET /api/investigations/ip?address=...&download=true|false`: retained endpoint summary without external reputation or source queries.
- `POST /api/ingest/{input_id}/detections`: OpenAPI `DetectionBatch`; required fields are timestamp, flow_id, threat_class, confidence and evidence. Empty `alerts` is valid completion. At most 100 results and 16 KiB body. Returns `{ok:true,accepted:N}` for newly stored alerts; identical input-linked replay returns zero.

See [DETECTOR_HANDOFF.md](DETECTOR_HANDOFF.md) for the verified detector-to-dashboard/report workflow and runtime limitations. Input/report routes are detailed in [PASSIVE_INGEST.md](PASSIVE_INGEST.md) and [REPORTS.md](REPORTS.md).
