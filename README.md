# Dhrashta backend

Backend-only export of the verified prototype at source commit `ff7cf4a` from `codeWith-Ashwani/SIH_Dhrashta`. No dashboard, static assets, sample preview, model artifact, secrets or stored traffic are included.

Includes FastAPI management APIs, immutable passive inputs, PCAP/PCAPNG and NetFlow/IPFIX/sFlow decoding, basic feature extraction, detector integration, durable alert history/WebSocket delivery, analytics endpoints, and a separate Gemini report worker. The supplied detection model is still required.

## Run

Copy `.env.example` to `.env`, configure local settings, then run:

```sh
docker compose up -d --build
```

Management API: http://localhost:8000/docs. Health: http://localhost:8000/health. `/` returns JSON service metadata. Passive UDP defaults to localhost:2055 and starts paused; enable using `POST /api/monitor` with `{"active":true}`. Management HTTP is separate from one-way production observations.

If another prototype is running, choose unused `API_PORT` and `PASSIVE_UDP_PORT` values. Compose networks are project-scoped. Keep one Uvicorn worker for in-process WebSocket fan-out. Persistent volumes contain Postgres, Redis and the local durable journal; do not remove volumes unless intentionally deleting stored data.

Add `GEMINI_API_KEY` only to the ignored `.env` file for report generation. The inference API has no cloud key or external default route; the separate report gateway has management egress. Keep production-side mirror/diode deployment separate from management connections. No probe, source ACK, mitigation or payload decryption is implemented.

## Integration

Start with [DETECTOR_HANDOFF.md](DETECTOR_HANDOFF.md), [MODEL_INTEGRATION.md](MODEL_INTEGRATION.md) and [API.md](API.md). Passive formats and isolation boundaries: [PASSIVE_INGEST.md](PASSIVE_INGEST.md). Gemini evidence reports: [REPORTS.md](REPORTS.md).

Use a separate management detector worker to retrieve an input's original bytes/features and submit structured results to `/api/ingest/{id}/detections`. Empty result batches are valid. The local adapter is optional; local inference currently has no hard execution deadline, and whole uploaded captures are not timed streaming replay. Actual model latency, window/state policy and accuracy require the supplied detector and acceptance tests.

## Tests

```sh
docker compose -p dhrashta-backend-test -f docker-compose.tests.yml run --build --rm tests
docker compose -p dhrashta-backend-test -f docker-compose.tests.yml down
```

Tests use isolated Postgres/Redis and disposable journal data. Provider responses and detection labels are test fixtures; no real classifier or live Gemini request is used. Dashboard asset tests are excluded, while backend history, integration, report and receive-only ingest checks are retained.
