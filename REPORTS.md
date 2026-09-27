# Reports and evidence

Open **Reports & evidence**, select up to 30 received alerts, enter a title and choose **Generate report**. Open a saved report for the summary, cited findings, recommended checks, limitations and original evidence. Reports are unverified drafts for analyst review, separate from the user-supplied detection model. No sample alerts or fabricated fallback reports are created.

## Configuration

Add these settings to the ignored `sih_dhrashta_backend/.env`; never commit or paste the key:

```dotenv
GEMINI_API_KEY=your-key-here
GEMINI_REPORT_MODEL=gemini-3.5-flash-lite
```

Run `docker compose up -d --build` from that folder. Key changes require recreating `report-service`. The key is never sent to the browser or processing API. **Configured** means a key and valid model setting exist; it does not claim provider reachability or available quota. Failed cloud calls are not automatically retried; create a new report after fixing the issue.

The default is Google's stable [Gemini 3.5 Flash-Lite](https://ai.google.dev/gemini-api/docs/models/gemini-3.5-flash-lite). The implementation uses the fixed HTTPS `generateContent` endpoint, JSON output with `responseFormat.text.mimeType=APPLICATION_JSON`, and a bounded, flattened schema. See the [REST reference](https://ai.google.dev/api/generate-content) and [structured output guide](https://ai.google.dev/gemini-api/docs/generate-content/structured-output). Local validation enforces constraints unsupported by the provider's schema subset. No SDK or model weights are required. Availability and charges depend on the Google account.

## Data and isolation

- Generate sends only selected alert records, including evidence, network identifiers and visibility, to Google Gemini. Use the agency's approved cloud account/data arrangement. Original capture/export bytes and other alerts are not sent.
- The processing API stays on the internal-only Docker network without an external default route. Source UDP ingest remains receive-only and never replies to monitored sources.
- A separate report gateway connects to Google's fixed API hostname on the management network. It has no sensor ingress, published port, capture access, storage volume, tools, URL fetching or arbitrary provider URL setting. Redirects are refused.
- Credentials exist only in the gateway environment. API/UI errors never expose provider bodies or keys; Docker administrators can inspect container environments.
- Generation cannot change detector labels, confidence or evidence. The prompt treats embedded strings as untrusted data, prohibits invented observations and requests read-only analyst checks. These controls do not prove generated reasoning is correct: review cited evidence.

## Persistence and limits

Each job commits an immutable selected-alert snapshot before generation, its canonical UTF-8 JSON SHA-256, provider/model, timestamps and state to a separate `reports` table in the existing SQLite journal volume. Findings must cite only snapshot references (`A1`, `A2`, …), and every selected alert must be addressed. Output is validated again in gateway and API. Blocked, truncated or invalid responses fail without substituting a narrative.

Limits: 1–30 distinct alerts, title 120 characters, creation body 16 KiB, source snapshot 96 KiB, eight pending jobs, one generation at a time, provider timeout 90 seconds, response 256 KiB, 12 findings and 8,192 output tokens. Queued jobs survive restart; interrupted generating jobs become failed to avoid duplicate cloud calls. The recent list shows 20 reports; older reports remain accessible by ID. Run one API process. Authentication and report retention/deletion are outside this prototype.

The hash records snapshot integrity, not a digital signature or independent capture provenance. Draft analysis and exact source facts are displayed separately. Text/JSON downloads retain the snapshot and hash after source alerts leave the browser's 100-record window.

## API

| Route | Result |
| --- | --- |
| `GET /api/reports` | Recent summaries and generator configuration |
| `POST /api/reports` | `{"title":"Investigation","alert_ids":["received-alert-id"]}`; 202 with durable queued report |
| `GET /api/reports/{id}` | Sources, hash, narrative, metadata and state |
| `GET /api/reports/{id}/download?format=json` | Full JSON attachment |
| `GET /api/reports/{id}/download?format=text` | Plain UTF-8 report with exact source JSON |

Missing selections are rejected as a whole. Invalid selection: 422; oversized request/evidence: 413; full queue: 429; unconfigured/unavailable gateway: 503. Generation is asynchronous; poll detail for `queued`, `generating`, `draft` or `failed`.

## Validation workflow

The standard isolated tests never pass cloud credentials; only provider transport is mocked. Explicit live browser QA uses its own project and synthetic alerts:

```powershell
docker compose -p dhrashta-ui -f docker-compose.tests.yml -f tests/dashboard-preview.yml -f tests/cloud-preview.yml up -d --build
# Browser QA: localhost:8001
docker compose -p dhrashta-ui -f docker-compose.tests.yml -f tests/dashboard-preview.yml -f tests/cloud-preview.yml down -v
```

Remove volumes only for this disposable QA project; never remove the main volumes during QA cleanup.
