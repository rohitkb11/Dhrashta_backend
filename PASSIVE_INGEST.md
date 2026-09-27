# Read-only observation input

Sprint 5 adds offline ingest and an external, receive-only UDP sensor feed. No capture interface, probe, exporter query, inline block, packet retransmission, or source acknowledgement is implemented. Browser HTTP/WebSocket traffic is a separate management connection and necessarily responds to the browser.

## Deployment boundary

The API container runs without Linux capabilities, with no-new-privileges, a read-only root filesystem, an internal Docker bridge with no default external route, and external DNS disabled. Redis and Postgres remain reachable on that bridge. Management HTTP defaults to `127.0.0.1:8000`; passive UDP defaults to `127.0.0.1:2055`. Do not attach the container to a monitored network or give it another routed interface.

A fourth, small `ingress` service is necessary because Docker Desktop does not publish host ports directly from the internal-only bridge. It forwards management TCP only to api:8000 and source UDP only to api:2055. It has no model, upload processing or user-selected destination. The source-facing UDP socket only receives; a separate socket sends to the fixed internal backend and never reads a reply. Private framing preserves the UDP peer address/port observed by the relay for template scope; original stored bytes exclude that framing. Backend ports are never directly published. Management TCP supports the existing HTTP/WebSocket contract and returns responses to local browsers. The ingress bridge is a software boundary, not a physical diode.

These restrictions and receive-only application code do not constitute a physical data diode. Docker permits communication on its own bridge and responses on published management connections. A production source must feed a physically unidirectional mirror/data diode on a segregated observation path. A future trusted model adapter must also obey this boundary. The prototype cannot guarantee one-way isolation of the Windows host itself.

For an external sensor, set `PASSIVE_BIND_HOST` to the dedicated observation-side host address and recreate the API. Allow only UDP 2055 from that sensor in the host firewall; do not expose HTTP to the traffic source. Remote sensor acceptance is pending. The older HTTP sensor instructions in HANDOFF.md are superseded for the strict one-way observation path.

## Supported inputs

Use Inputs & monitor to select a format and upload a file. Files are read offline, never executed. Limits: 10 MiB per input, 100,000 captured packets, 10,000 observations, two concurrent processing jobs. Original bytes and their SHA-256 digest are inserted once in the persistent journal. Feature JSON and original-byte downloads permit inspection. Latest 20 inputs are listed; stored inputs remain available by ID.

| Format | Supported subset |
| --- | --- |
| PCAP / PCAPNG | Standard PCAP 2.4, either byte order and micro/nanosecond timing; PCAPNG sections/interfaces/enhanced packet blocks. Ethernet/VLAN, raw IP, Linux cooked headers; IPv4/IPv6, TCP/UDP and basic extensions. Untimed simple/legacy packet blocks are rejected. |
| NetFlow | Binary v5 export datagrams; v9 ordinary template/data sets. |
| IPFIX | v10 ordinary template/data sets; variable-length and enterprise fields can be skipped; mapped standard fields are retained. |
| sFlow | v5 standard/expanded flow samples with supported raw header or IPv4/IPv6 flow records. Counter and unknown enterprise records are not treated as flows. |
| Flow JSON / CSV | JSON array or `{ "records": [...] }`; CSV header with observation fields below. |
| Metadata JSON | Same observation schema, with additional JSON measurements in `features`. |
| Labelled detection JSON | Array or `{ "alerts": [...] }`, 1–100 externally generated alerts. Replay is explicit and does not run the model. |

Binary export files contain the UDP **payload**, not a router configuration or a vendor-specific container format. Captured UDP exports can be supplied to a future raw-input adapter as PCAP; the current PCAP extractor reports observed packet flows rather than decoding embedded export payloads. Template-dependent exports need their templates in the input or previously received from the same exporter. Cache scope is exporter address/port, protocol, observation domain and template ID; bounded to 256 templates with 30-minute expiry. Missing templates yield an honest waiting state and are never requested. Options templates are skipped. This is a bounded prototype parser, not an exhaustive implementation of every exporter extension.

## Observation and engineered features

An observation has `flow_id`, UTC `timestamp`, `source_timestamp_supplied`, optional `src_ip`, `dst_ip`, `src_port`, `dst_port`, numeric `protocol`, `features`, and sampling metadata. Supply a flow identifier or a complete directional five-tuple; the latter produces a deterministic hash identifier scoped by the input ID. Addresses must be literal IPs; hostnames are never resolved. Missing timestamps use receipt time and are marked as such.

```json
{"records":[{"flow_id":"sensor-flow-42","timestamp":"2026-09-26T12:00:00Z","src_ip":"192.0.2.1","dst_ip":"198.51.100.2","src_port":42000,"dst_port":443,"protocol":"TCP","packet_count":12,"byte_count":960,"duration_seconds":2,"features":{"sensor_observation":true}}]}
```

Feature schema is `passive-flow-v1`, not a promised 74-column training schema. Packet input produces observed packet/IP-byte counts, measured duration, packets/bytes per second, mean packet size, SYN/ACK counts, partial-packet count, inter-arrival mean/standard deviation/coefficient of variation, and whether a reverse tuple was observed in that input. Flow exports preserve available counts, timing, flags and sampling metadata. Rates require a positive measured duration; absent measurements remain absent. sFlow samples are not inflated into complete-network packet counts. No payload decryption, guessed reverse flows, DNS entropy, TLS fingerprint, accuracy estimate, or trained classifier is supplied.

## Live monitor

Start passive monitor accepts externally sent UDP datagrams; Pause ignores new datagrams while allowing queued work to finish. The socket remains bound while paused so the application never sends an acknowledgement. Datagram size is at most 65,535 bytes; queue capacity is 256. Received/processed/rejected/dropped/ignored counters are visible. UDP has no reliable delivery or retransmission; capture loss is not inferred from these counters. Monitor state, counters and templates reset on restart; original inputs and alerts persist.

The feed accepts NetFlow/IPFIX/sFlow payloads, observation JSON, or labelled JSON `{"kind":"alerts","alerts":[...]}`. The ingress accepts at most 65,507 bytes including its small framing header; larger framed datagrams are discarded without response. Every new-path alert needs timestamp, flow identifier, threat class, confidence and evidence. The nine existing class labels are retained. Severity is the established confidence band: high >= .85, medium >= .70, otherwise low, including BENIGN. It is not an independent threat-risk estimate.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/ingest` | Recent inputs, collector/model status and limits |
| `POST /api/ingest/upload` | Multipart `file` and `format`: pcap, netflow, ipfix, sflow, flow-json, flow-csv, metadata, detections |
| `GET /api/ingest/{id}/features` | Engineered observations; `?download=true` for attachment |
| `GET /api/ingest/{id}/original` | Exact original bytes |
| `POST /api/ingest/{id}/detections` | Management-side external results as `{"alerts":[...]}`; identifiers must reference that input |
| `POST /api/monitor` | Management-only `{"active":true}` / false |

Result validation is batch-atomic before durable alert acceptance. Input-linked identical results are idempotent within that input; UDP alerts without an input ID are independent deliveries. Original bytes never change when results are attached. Existing `POST /alerts` remains a legacy **management-side** interface and is not the one-way sensor transport; old records can lack flow IDs.

Format references: [NetFlow v9 RFC 3954](https://www.rfc-editor.org/info/rfc3954/), [IPFIX RFC 7011](https://www.rfc-editor.org/info/rfc7011/), [sFlow v5 specification](https://sflow.org/sflow_version_5.txt), and [Docker internal networks](https://docs.docker.com/reference/compose-file/networks/).
