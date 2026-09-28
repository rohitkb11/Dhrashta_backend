# Detection developer handoff

The prototype provides passive ingest, basic observed-feature extraction, durable alert output, visualization and Gemini report jobs. It does not include the actual detector. Select **Actual input** in the dashboard; **Sample preview** uses browser-only fictional records.

## Connection paths

1. **Management-side detector worker:** upload an input, retrieve its observations and original bytes, run your model, then submit results for that input. This HTTP connection stays in the management enclave; it is not the one-way production source feed.
2. **Trusted local adapter:** implement synchronous `predict` as described in [MODEL_INTEGRATION.md](MODEL_INTEGRATION.md). Install dependencies and artifacts in the API image, configure `MODEL_ADAPTER` and rebuild. The API has no external default route; runtime artifact downloading is unavailable.
3. **Already labelled passive sensor:** send supported observation/alert UDP envelopes described in [PASSIVE_INGEST.md](PASSIVE_INGEST.md). The receiver sends no acknowledgement, probe or template request. Missing NetFlow/IPFIX templates wait for passive arrival.

## Verified management workflow

Base URL: `http://localhost:8000`. Interactive schema: [API docs](http://localhost:8000/docs).

| Request | Result |
| --- | --- |
| `GET /health` | 200 with store/journal health and delivery backlog; inspect fields, not status alone |
| `GET /api/ingest` | Model availability, receiver status, latest 20 inputs and limits |
| `POST /api/ingest/upload` | Multipart `file` and `format`; 200 input summary containing `id`, SHA-256, flow count and state |
| `GET /api/ingest/{id}/features` | `{input_id, feature_version, records}` |
| `GET /api/ingest/{id}/original` | Exact original bytes as an attachment |
| `POST /api/ingest/{id}/detections` | JSON below; 200 `{ok:true,accepted:N}` for newly accepted alerts |
| `GET /api/ingest/{id}` | Completed state `replayed_detections`, cumulative alert count and retained association |
| `WS /ws` | Up to 20 recent records, then one record per accepted alert; deduplicate by receiver `id` |
| `GET /api/history/{alert_id}` | Durable alert evidence, endpoints, provenance and input association |
| `POST /api/reports` | `{"alert_ids":["receiver-alert-id"],"title":"Investigation"}`; 202 queued report job |
| `GET /api/reports/{id}` | Poll `queued` / `generating` / `draft` / `failed` |
| `GET /api/reports/{id}/download?format=json` or `text` | Report with immutable source evidence and citations |

Upload formats: `pcap` (also PCAPNG), `netflow`, `ipfix`, `sflow`, `flow-json`, `flow-csv`, `metadata`, `detections`. Offline input is bounded to 10 MiB, 10,000 flows and 100,000 packets. Ordinary JSON requests are bounded to 16 KiB; at most 100 detection results per batch. Split large evidence into smaller batches satisfying both limits. Retain returned input IDs; the latest-input list is not a complete historical work queue.

## Required output

Copy the exact `flow_id` from that input's observations. Preserve it when deriving another representation from raw PCAP/NetFlow. Receiver ID, input ID, severity, endpoints and provenance are receiver-owned top-level fields; do not post a frontend record back as detector output.

```json
{"alerts":[{
  "timestamp":"2026-09-27T12:00:00.123Z",
  "flow_id":"COPY-FROM-INPUT-OBSERVATIONS",
  "threat_class":"UDP_REFLECT",
  "confidence":0.984,
  "evidence":{
    "protocol":17,
    "packets_per_second":18420,
    "source_ip_entropy":0.14,
    "iat_mean_seconds":0.00005,
    "burst_ratio":0.93,
    "reason":"Supply the real detector explanation",
    "anomaly_score":0.91,
    "feature_assessments":{"packets_per_second":{"level":"high","reason":"Supply the actual measured baseline or threshold"}},
    "contributions":["Supply the model's actual contribution statement"],
    "flow_timeline":[{"timestamp":"2026-09-27T12:00:00.123Z","event":"Supply an actually observed event"}]
  },
  "model_version":"YOUR-REAL-MODEL-VERSION"
}]}
```

This is a schema example, not a detection. Confidence must be a finite JSON number in [0,1]. Include a timezone in timestamps; legacy naive timestamps are interpreted as UTC. Evidence must be finite JSON. Unsupported classes, missing required fields, malformed batches, unknown top-level keys and foreign flow IDs return 422 before any result is accepted. Valid submissions to missing inputs return 404. Rejection retains original bytes and features.

Use `{"alerts":[]}` to complete an input with no detections. Identical input-linked results are idempotent and return `accepted:0`. Changed timestamps/evidence represent additional events, not edits. Resend an identical batch after a lost response; retry 503 durable-journal failures with backoff. Reduce request size on 413. Correct 422 errors before retrying. UDP has no acknowledgement or reliable delivery guarantee.

Class mapping: DDoS = `SYN_FLOOD` / `UDP_REFLECT`; C2 = `C2_BEACON`; DNS/DGA = `DNS_DGA` / `DNS_DNSCAT2`; encrypted sessions = `TLS_C2`; scanning = `PORT_SCAN`; exfiltration = `EXFIL`. `BENIGN` remains accepted for compatibility, but normal traffic need not generate alerts; threat history and category cards exclude it. Severity currently follows confidence: high >= .85, medium >= .70, otherwise low. It is not a detector-supplied risk or criticality score.

## Evidence mapping

Observation records contain flow identity, timestamp, endpoints/ports/protocol, `features`, feature version and source-time availability. Basic extraction is not the model's full engineered feature vector. The detector owns its windowed rates/entropy, DNS n-grams, TLS/QUIC fingerprints, periodicity, fan-out and directional-volume analysis. Supply observable measurements only; never decrypt payloads, query a production source or invent reverse traffic.

Frontend aliases and units are defined in `backend/static/threats.js`: numbers must be JSON numbers, sequences numeric arrays, distributions objects mapping labels to nonnegative counts. Missing fields stay unavailable. Rationale, assessments, anomaly score, contributions and timeline belong inside `evidence`. These fields survive acceptance, WebSocket delivery, history and report snapshots. The frontend displays supplied explanations; it does not compute model attribution. Gemini reports are analyst-review drafts, not another classifier.

Other routes: `/api/alerts`, `/api/stats`, `/api/history` (filters and cursor pagination), `/api/analytics/heatmap`, `/api/network`, `/api/investigations/ip`, `/api/reports`, `/`, `/docs`, `/redoc`, `/openapi.json`. `POST /api/monitor` accepts only `{"active":true}` or false. Legacy `POST /alerts` is management acceptance, not idempotent passive-source transport. See [API.md](API.md) and [REPORTS.md](REPORTS.md).

## Remaining runtime acceptance work

- Local inference runs in a thread without a hard timeout. A hung predictor can hold an ingest slot and stall the serial UDP processor. Use a separate management inference worker for the first integration; a killable execution boundary is needed before claiming bounded model latency.
- Offline uploads are whole bounded inputs. Timed capture replay, cross-input model window/state ownership/reset and inference queue/latency policy require agreement with the detector developer.
- Parser/transport throughput is not model throughput or accuracy. Benchmark actual feature extraction, inference and alert delivery together after supplying artifacts/dependencies.
- The detector handoff must specify preprocessing order/units, missing-data policy, complete passive DNS/TLS/window features, training/validation, calibration and real model version.
- Physical mirror/diode acceptance, deployment authentication and provider data-handling policy are not established by this localhost prototype.

## Verification

Run `docker compose -p dhrashta-test -f docker-compose.tests.yml run --build --rm tests`, then `docker compose -p dhrashta-test -f docker-compose.tests.yml down`. Test storage is isolated from prototype volumes. Fixtures supply test labels and mock provider calls; no actual classifier or live Gemini request is used. `tests/test_ps_audit.py` verifies upload, original/features, output, WebSocket, durable history/analytics and report snapshots/exports, plus malformed requests and repaired regressions.
