"""Durable immutable inputs, local model adapter hook, and receive-only UDP feed."""
import asyncio
import hashlib
import importlib
import json
import os
import socket
import time
from collections import Counter
from datetime import datetime, timezone
from uuid import uuid4

from passive import ExportDecoder, FEATURE_VERSION, InputError, decode, normalize


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class Pipeline:
    def __init__(self, storage, classify):
        self.storage, self.classify = storage, classify
        self.model = None
        self.model_error = None
        module_name = os.getenv("MODEL_ADAPTER", "").strip()
        if module_name:
            try:
                self.model = importlib.import_module(module_name)
                if not callable(getattr(self.model, "predict", None)):
                    raise ValueError("Adapter must provide predict")
            except Exception:
                self.model = None
                self.model_error = "Configured local adapter could not be loaded"
        with storage.journal() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS inputs (
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL, name TEXT NOT NULL,
                kind TEXT NOT NULL, sha256 TEXT NOT NULL, original BLOB NOT NULL,
                observations TEXT NOT NULL, notes TEXT NOT NULL, state TEXT NOT NULL,
                alert_count INTEGER NOT NULL DEFAULT 0, processing_ms REAL NOT NULL)""")
            if "origin" not in {row[1] for row in db.execute("PRAGMA table_info(inputs)")}:
                db.execute("ALTER TABLE inputs ADD COLUMN origin TEXT NOT NULL DEFAULT 'unknown'")
        self.slots = asyncio.Semaphore(2)

    def summary(self, row):
        return {"id": row[0], "created_at": row[1], "name": row[2], "format": row[3], "sha256": row[4],
                "bytes": row[5], "flow_count": row[6], "notes": json.loads(row[7]), "state": row[8],
                "alert_count": row[9], "processing_ms": row[10], "feature_version": FEATURE_VERSION, "origin": row[11]}

    def recent(self):
        with self.storage.journal() as db:
            rows = db.execute("SELECT id,created_at,name,kind,sha256,length(original),json_array_length(observations),"
                              "notes,state,alert_count,processing_ms,origin FROM inputs ORDER BY created_at DESC LIMIT 20").fetchall()
        return [self.summary(row) for row in rows]

    def by_id(self, input_id):
        with self.storage.journal() as db:
            row = db.execute("SELECT id,created_at,name,kind,sha256,length(original),json_array_length(observations),"
                             "notes,state,alert_count,processing_ms,origin FROM inputs WHERE id=?", (input_id,)).fetchone()
        if not row:
            raise KeyError(input_id)
        return self.summary(row)

    def get(self, input_id):
        with self.storage.journal() as db:
            row = db.execute("SELECT kind,original,observations,state,origin FROM inputs WHERE id=?", (input_id,)).fetchone()
        if not row:
            raise KeyError(input_id)
        return {"format": row[0], "original": row[1], "observations": json.loads(row[2]), "state": row[3], "origin": row[4]}

    def set_state(self, input_id, state, note=None):
        with self.storage.journal() as db:
            if note:
                notes = json.loads(db.execute("SELECT notes FROM inputs WHERE id=?", (input_id,)).fetchone()[0])
                notes.append(note)
                db.execute("UPDATE inputs SET state=?,notes=? WHERE id=?", (state, json.dumps(notes), input_id))
            else:
                db.execute("UPDATE inputs SET state=? WHERE id=?", (state, input_id))

    async def process(self, data, kind, name, decoder=None, exporter="upload", replay_results=None, origin="upload"):
        async with self.slots:
            start = time.perf_counter()
            if replay_results is not None:
                observations = [normalize({"flow_id": row["flow_id"], "timestamp": row["timestamp"], "features": row["evidence"]}) for row in replay_results]
                notes = ["Imported externally labelled detections; the receiver did not infer these labels"]
            else:
                observations, notes = await asyncio.to_thread(decode, data, kind, decoder, exporter)
            input_id = str(uuid4())
            state = "awaiting_model" if observations else "awaiting_template_or_data"
            elapsed = round((time.perf_counter() - start) * 1000, 3)
            # Original bytes and observations are inserted once and never updated.
            with self.storage.journal() as db:
                db.execute("INSERT INTO inputs(id,created_at,name,kind,sha256,original,observations,notes,state,processing_ms,origin) "
                           "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (input_id, now(), name[:200], kind,
                           hashlib.sha256(data).hexdigest(), data, json.dumps(observations, allow_nan=False),
                           json.dumps(notes), state, elapsed, origin))
            if replay_results is not None:
                await self.classify(input_id, replay_results, "replayed_detections")
            elif observations and self.model:
                try:
                    alerts = await asyncio.to_thread(self.model.predict, observations=observations,
                                                     input_bytes=data, input_format=kind)
                    if not isinstance(alerts, list) or len(alerts) > 100:
                        raise InputError("Adapter must return at most 100 structured alerts per input")
                    await self.classify(input_id, alerts, "model_inferred")
                except Exception:
                    self.set_state(input_id, "model_error", "Local model adapter failed; original input/features retained")
            elif observations and self.model_error:
                self.set_state(input_id, "model_error", self.model_error)
            return self.by_id(input_id)

    def model_status(self):
        return {"available": self.model is not None, "state": "configured_local_adapter" if self.model else "adapter_error" if self.model_error else "awaiting_model",
                "feature_version": FEATURE_VERSION, "message": self.model_error or "No model is trained, downloaded, or invented by this receiver"}


class PassiveCollector:
    def __init__(self, pipeline, alert_type, save_alerts):
        self.pipeline, self.alert_type, self.save_alerts = pipeline, alert_type, save_alerts
        self.active = False
        self.queue = asyncio.Queue(maxsize=256)
        self.decoder = ExportDecoder()
        self.received = self.processed = self.rejected = self.dropped = self.ignored = 0
        self.last_received = self.last_error = None
        self.started = time.monotonic()
        self.started_epoch = int(time.time())
        self.receipt_bins = Counter()
        self.byte_bins = Counter()
        self.flow_bins = Counter()
        self.observed_flows = 0
        self.socket = None
        self.tasks = []
        self.port = int(os.getenv("PASSIVE_UDP_PORT", "2055"))
        self.bind_error = None

    async def start(self):
        # No connect(), send(), sendto(), DNS lookup, or raw capture socket.
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setblocking(False)
            self.socket.bind(("0.0.0.0", self.port))
        except OSError:
            if self.socket:
                self.socket.close()
            self.socket = None; self.bind_error = "Passive UDP port could not be bound"; return
        self.tasks = [asyncio.create_task(self.receive()), asyncio.create_task(self.process())]

    async def close(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        if self.socket:
            self.socket.close()

    def status(self):
        current = int(time.time())
        for bins in (self.receipt_bins, self.byte_bins, self.flow_bins):
            for tick in list(bins):
                if tick < current - 60:
                    del bins[tick]
        # Completed receipt-time seconds avoid presenting a partial second as
        # a measured full-second rate. These are ingest rates, not link capacity.
        window = min(60, max(0, current - self.started_epoch))
        ticks = range(current - window, current)
        feed_bytes = sum(self.byte_bins[tick] for tick in ticks)
        flows = sum(self.flow_bins[tick] for tick in ticks)
        series = [{"timestamp": datetime.fromtimestamp(tick, timezone.utc).isoformat(), "datagrams": self.receipt_bins[tick]}
                  for tick in range(max(self.started_epoch, current - 59), current + 1)] if self.received else []
        return {"active": self.active, "bound": self.socket is not None, "port": self.port,
                "receipt_series": series,
                "rate_window_seconds": window,
                "flow_records_per_second": round(flows / window, 2) if window and self.observed_flows else None,
                "feed_mbps": round(feed_bytes * 8 / window / 1000000, 4) if window else None,
                "rate_scope": "Passive UDP payload bytes received and decoded flow records; completed receipt-time window",
                "published_host": os.getenv("PASSIVE_PUBLIC_HOST", "127.0.0.1"),
                "published_port": int(os.getenv("PASSIVE_PUBLIC_PORT", str(self.port))),
                "received": self.received, "processed": self.processed, "rejected": self.rejected,
                "queue_dropped": self.dropped, "ignored_while_paused": self.ignored,
                "queued": self.queue.qsize(), "last_received_at": self.last_received,
                "last_error": self.last_error or self.bind_error,
                "received_datagrams_per_second": round(self.received / max(1, time.monotonic() - self.started), 2),
                "mode": "receive_only_udp", "model": self.pipeline.model_status()}

    async def receive(self):
        loop = asyncio.get_running_loop()
        while True:
            # add_reader works with both asyncio and Uvicorn's uvloop. Some
            # uvloop versions do not implement loop.sock_recvfrom().
            ready = loop.create_future()
            def readable():
                if not ready.done():
                    ready.set_result(None)
            loop.add_reader(self.socket.fileno(), readable)
            try:
                await ready
                data, address = self.socket.recvfrom(65535)
            finally:
                loop.remove_reader(self.socket.fileno())
            self.received += 1; self.last_received = now()
            tick = int(time.time())
            self.receipt_bins[tick] += 1
            self.byte_bins[tick] += len(data)
            if not self.active:
                self.ignored += 1; continue
            try:
                self.queue.put_nowait((data, address))
            except asyncio.QueueFull:
                self.dropped += 1

    async def process(self):
        while True:
            data, address = await self.queue.get()
            try:
                exporter = f"{address[0]}:{address[1]}"
                prefix = b"DRASHTA-PASSIVE-V1\x00"
                if data.startswith(prefix):
                    identity, data = data[len(prefix):].split(b"\x00", 1)
                    exporter = identity.decode("ascii")
                if data.lstrip().startswith((b"{", b"[")):
                    envelope = json.loads(data)
                    if isinstance(envelope, dict) and envelope.get("kind") == "alerts":
                        alerts = envelope.get("alerts")
                        if not isinstance(alerts, list) or not 1 <= len(alerts) <= 100:
                            raise InputError("UDP alert envelope needs 1–100 alerts")
                        required = ("timestamp", "flow_id", "threat_class", "confidence", "evidence")
                        if any(not isinstance(row, dict) or any(key not in row for key in required) for row in alerts):
                            raise InputError("UDP alerts require complete standardized records")
                        parsed = [self.alert_type.model_validate(alert) for alert in alerts]
                        if any(not alert.flow_id for alert in parsed):
                            raise InputError("One-way sensor alerts require flow_id")
                        await self.save_alerts(parsed, origin="live")
                    else:
                        result = await self.pipeline.process(data, "metadata", "Passive metadata datagram", origin="live")
                        self.record_flows(result["flow_count"])
                else:
                    kind = "sflow" if data[:4] == b"\x00\x00\x00\x05" else "ipfix" if data[:2] == b"\x00\x0a" else "netflow"
                    result = await self.pipeline.process(data, kind, "Passive " + kind + " datagram", self.decoder, exporter, origin="live")
                    self.record_flows(result["flow_count"])
                self.processed += 1; self.last_error = None
            except Exception:
                self.rejected += 1; self.last_error = "Input rejected or storage unavailable; no response was sent to the source"
            finally:
                self.queue.task_done()

    def record_flows(self, count):
        self.observed_flows += count
        self.flow_bins[int(time.time())] += count
