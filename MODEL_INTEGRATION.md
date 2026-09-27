# External model contract

No model artifact has been supplied. The prototype performs ingestion and observed-feature extraction, then records **awaiting model** with zero generated detections. Training, validation datasets, splits, preprocessing, metrics, calibration and accuracy are unavailable; none are claimed. Externally labelled outputs can already be replayed and visualized.

Your model may accept **PCAP or NetFlow**, as requested. The local adapter receives both original bytes and normalized observations so you can select the correct input. Implement a trusted local `backend/model_adapter.py` providing:

```python
def predict(*, observations, input_bytes, input_format):
    # Call your supplied model locally and return its structured results.
    # There is deliberately no example classifier or invented prediction.
    raise NotImplementedError("Connect the supplied model here")
```

Set `MODEL_ADAPTER=model_adapter` in `.env` and rebuild the API after providing the real implementation and required artifact/dependencies. Python modules are copied into the image; artifact copying/mounting must be configured when its actual format is known. No uploaded Python/pickle/model is executed, no model is downloaded, and there is no remote inference endpoint.

Return a list of at most 100 alerts per input; an empty list is a valid completed inference result. Each result must reference an observation's flow ID:

```json
[{"timestamp":"2026-09-26T12:00:00Z","flow_id":"sensor-flow-42","threat_class":"PORT_SCAN","confidence":0.91,"evidence":{"unique_dst_ports":12},"model_version":"YOUR-SUPPLIED-VERSION"}]
```

This is a schema example, not a detected incident. Confidence must be finite in [0,1]. Supported classes: BENIGN, C2_BEACON, TLS_C2, DNS_DGA, DNS_DNSCAT2, EXFIL, SYN_FLOOD, UDP_REFLECT, PORT_SCAN. The receiver adds alert ID, input ID and confidence-derived severity. Malformed outputs or adapter exceptions yield model_error while retaining original input/features; no partial batch is committed.

For the selected-alert SOC investigation, include the actual decision explanation in `evidence.reason` (string) or `evidence.reasons` (string array), alongside the measurements, units and any genuine rule thresholds or feature attributions. The dashboard also recognizes `explanation`, `decision_reason` and `rationale` within evidence. If no explanation is supplied it displays that absence; it does not generate a detector rationale or call an LLM on click. Alert history shows non-BENIGN records only; the underlying nine-class integration contract remains available.

The adapter must document its actual raw-input format, feature names/order/units, missing-data policy, artifact/runtime, nine-class mapping, training/validation approach and calibrated confidence semantics. Do not assume passive-flow-v1 equals an existing trained model's feature vector. The current observation flow ID must be carried through raw-input inference. The trusted adapter must not contact monitored hosts, probe, capture, download models or create a return path. Model throughput and end-to-end detection accuracy must be tested after integration; parser or transport QA is not model validation.

Optional dossier evidence fields: `protocol` (6/TCP, 17/UDP, or a string), `anomaly_score` (finite number in the model's documented scale), `feature_assessments` (object keyed by the supplied feature name, with a string or `{level, reason}`), `contributions` (array of actual model explanation strings), and `flow_timeline` (array of `{timestamp, event}` observations). Supply timestamps with an explicit timezone and document units. These fields are displayed as provided; the dashboard does not calculate a model attribution, assessment level, or prior normal/spike/anomaly events.

## Integration handoff

See [DETECTOR_HANDOFF.md](DETECTOR_HANDOFF.md) for the verified management API workflow, limits, output field mapping, retry behavior and remaining runtime acceptance work. `/docs` and `/openapi.json` now expose the required detection result and batch schemas. External result submissions accept `{"alerts":[]}` as a completed input with no detections.

The current local `predict` function must be synchronous and finish promptly. It runs in a Python thread without a hard execution deadline; a hung predictor can hold an ingest slot and stall the serial UDP processor. Whole uploaded captures are processed as one input, not replayed in timed windows. Do not claim bounded model latency, cross-input streaming state or raw-capture streaming acceptance until an inference execution boundary and the detector's window/state policy are implemented and tested. A separate management-side inference worker can retrieve retained inputs and submit results without running model computation inside the receiver. It must not contact production endpoints or use management HTTP across the passive source path.
