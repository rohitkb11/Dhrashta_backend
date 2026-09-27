"""Dhrashta receiving enclave: passive observations and external-model alerts."""
import asyncio
import json
import logging
import math
import os
import sqlite3
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4, uuid5, NAMESPACE_URL

import psycopg2
import redis
import anyio
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, UploadFile, File, Form
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from psycopg2.extras import Json, RealDictCursor
from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator
from ingest import Pipeline, PassiveCollector
from passive import InputError, MAX_BYTES
from reports import Reports, ReportRequest, plain_report
from investigations import Investigations, decorate

log = logging.getLogger("uvicorn.error")


class UploadLimitMiddleware:
    """Bound multipart bytes before Starlette can spool a large upload."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        path = scope.get("path")
        if scope["type"] != "http" or path not in ("/api/ingest/upload", "/api/reports") or scope.get("method") != "POST":
            return await self.app(scope, receive, send)
        limit = MAX_BYTES + 128 * 1024 if path == "/api/ingest/upload" else 16 * 1024
        chunks, total = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            total += len(message.get("body", b""))
            if total > limit:
                response = JSONResponse({"detail": "Upload request exceeds 10 MiB plus multipart overhead" if path == "/api/ingest/upload" else "Report request exceeds 16 KiB"},
                                        status_code=413, headers={"Connection": "close"})
                return await response(scope, receive, send)
            chunks.append(message)
            if not message.get("more_body", False):
                break
        iterator = iter(chunks)
        async def bounded_receive():
            try:
                return next(iterator)
            except StopIteration:
                return await receive()
        await self.app(scope, bounded_receive, send)
ThreatClass = Literal["BENIGN", "C2_BEACON", "TLS_C2", "DNS_DGA", "DNS_DNSCAT2",
                      "EXFIL", "SYN_FLOOD", "UDP_REFLECT", "PORT_SCAN"]


def finite_json(value):
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Measurements must be finite JSON numbers")
    if isinstance(value, dict):
        for item in value.values():
            finite_json(item)
    elif isinstance(value, list):
        for item in value:
            finite_json(item)
    return value


class Visibility(BaseModel):
    model_config = ConfigDict(extra="allow")
    observed_direction: Literal["both", "forward", "reverse", "unknown"] = "unknown"
    reverse_available: bool | None = Field(default=None, strict=True)
    partial_flow: bool | None = Field(default=None, strict=True)
    capture_loss: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False, strict=True)

    @model_validator(mode="after")
    def valid_measurements(self):
        finite_json(self.model_dump())
        return self


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    threat_class: ThreatClass
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False, strict=True)
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    visibility: Visibility | None = None
    model_version: str | None = Field(default=None, max_length=200)
    flow_id: str | None = Field(default=None, min_length=1, max_length=200)

    @field_validator("flow_id")
    @classmethod
    def nonblank_flow(cls, value):
        if value is not None and not value.strip():
            raise ValueError("flow_id cannot be blank")
        return value

    @field_validator("timestamp")
    @classmethod
    def utc_timestamp(cls, value):
        # The sensor's naive ISO timestamps are interpreted as UTC.
        return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value).astimezone(timezone.utc)

    @field_validator("evidence")
    @classmethod
    def valid_evidence(cls, value):
        return finite_json(value)


class DetectionResult(Alert):
    """Required detector fields exposed in OpenAPI; validated before acceptance."""
    timestamp: datetime
    flow_id: str = Field(min_length=1, max_length=200)
    evidence: dict[str, JsonValue]


class DetectionBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alerts: list[DetectionResult] = Field(max_length=100)


class Storage:
    def __init__(self):
        self.schema_ready = False
        self.path = os.getenv("JOURNAL_PATH", "/data/alerts.sqlite3")
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.journal() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS journal (
                event_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                postgres_done INTEGER NOT NULL DEFAULT 0,
                redis_done INTEGER NOT NULL DEFAULT 0)""")
            db.execute("CREATE INDEX IF NOT EXISTS journal_pending ON journal(postgres_done)")
            db.execute("CREATE INDEX IF NOT EXISTS journal_timestamp ON "
                       "journal(json_extract(payload, '$.timestamp') DESC)")
        self.redis = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"),
                                         decode_responses=True, socket_connect_timeout=2, socket_timeout=2)

    @contextmanager
    def journal(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def postgres(self):
        return psycopg2.connect(os.getenv("DATABASE_URL", "postgresql://dhrash:dhrash@postgres:5432/dhrash"),
                                connect_timeout=2, options="-c statement_timeout=3000")

    def pg_query(self, sql, params=()):
        db = self.postgres()
        try:
            with db, db.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, params)
                return [dict(row) for row in cur.fetchall()] if cur.description else []
        finally:
            db.close()

    def accept(self, alert):
        if "endpoint_source" not in alert:
            alert = decorate(alert)
        payload = json.dumps(alert, allow_nan=False)
        # Acknowledge only after the durable local volume has committed the alert.
        with self.journal() as db:
            db.execute("INSERT INTO journal(event_id, payload) VALUES (?, ?)", (alert["id"], payload))

    def mark(self, sql, params=()):
        try:
            with self.journal() as db:
                db.execute(sql, params)
        except (sqlite3.Error, OSError):
            # Metadata failure cannot reverse an already durable acceptance.
            log.exception("Delivery status update failed; replay will retry safely")

    def sync_redis(self):
        try:
            with self.journal() as db:
                rows = db.execute("SELECT rowid, payload FROM journal ORDER BY rowid DESC LIMIT 500").fetchall()
            # Atomic replacement preserves acceptance order during outage replay,
            # including when Redis has restarted with an empty cache.
            with self.redis.pipeline(transaction=True) as pipe:
                pipe.delete("alerts_recent")
                if rows:
                    pipe.rpush("alerts_recent", *(payload for _, payload in rows))
                pipe.execute()
        except (redis.RedisError, sqlite3.Error, OSError):
            log.warning("Redis delivery deferred; durable journal retained")
            return False
        if rows:
            self.mark("UPDATE journal SET redis_done=1 WHERE rowid<=? AND redis_done=0", (rows[0][0],))
        return True

    def deliver(self, alert, sync_cache=True):
        pg_done = False
        try:
            if not self.schema_ready:
                self.pg_query("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS flow_id TEXT; "
                              "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS input_id TEXT; "
                              "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS src_ip TEXT; ALTER TABLE alerts ADD COLUMN IF NOT EXISTS dst_ip TEXT; "
                              "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS endpoint_source JSONB; ALTER TABLE alerts ADD COLUMN IF NOT EXISTS origin TEXT; "
                              "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS received_at TIMESTAMPTZ")
                self.schema_ready = True
            self.pg_query("""INSERT INTO alerts
                (event_id, ts, threat_class, confidence, evidence, visibility, model_version, flow_id, input_id,src_ip,dst_ip,endpoint_source,origin,received_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (event_id) DO NOTHING""",
                (alert["id"], alert["timestamp"], alert["threat_class"], alert["confidence"],
                 Json(alert["evidence"]), Json(alert["visibility"]), alert["model_version"], alert.get("flow_id"), alert.get("input_id"),
                 alert.get("src_ip"),alert.get("dst_ip"),Json(alert.get("endpoint_source")),alert.get("origin"),alert.get("received_at")))
            pg_done = True
            self.mark("UPDATE journal SET postgres_done=1 WHERE event_id=?", (alert["id"],))
        except (psycopg2.Error, OSError):
            log.warning("Postgres write deferred; alert %s is safe in the journal", alert["id"])
        if sync_cache:
            self.sync_redis()  # Independent attempt even when Postgres is down.
        return pg_done

    def replay(self):
        with self.journal() as db:
            rows = db.execute("SELECT payload FROM journal WHERE postgres_done=0 "
                              "ORDER BY rowid LIMIT 100").fetchall()
        for (payload,) in rows:
            if not self.deliver(json.loads(payload), sync_cache=False):
                # Bound outage latency to one failed connection per retry pass.
                break
        self.sync_redis()

    def local_alerts(self, pending_only=False, limit=500):
        with self.journal() as db:
            query = "SELECT payload FROM journal" + (" WHERE postgres_done=0" if pending_only else "")
            query += " ORDER BY json_extract(payload, '$.timestamp') DESC, rowid DESC LIMIT ?"
            return [json.loads(row[0]) for row in db.execute(query, (limit,))]

    @staticmethod
    def serialize_row(row):
        return {"id": row["event_id"] or f"pg-{row['id']}",
                "timestamp": row["ts"].astimezone(timezone.utc).isoformat(),
                "threat_class": row["threat_class"], "confidence": float(row["confidence"]),
                "evidence": row["evidence"] or {}, "visibility": row["visibility"],
                "model_version": row["model_version"], "flow_id": row.get("flow_id"), "input_id": row.get("input_id"),
                "src_ip": row.get("src_ip"), "dst_ip": row.get("dst_ip"), "endpoint_source": row.get("endpoint_source"), "origin": row.get("origin"),
                "received_at": row["received_at"].astimezone(timezone.utc).isoformat() if row.get("received_at") else None,
                "severity": "high" if row["confidence"] >= .85 else "medium" if row["confidence"] >= .7 else "low"}

    def recent(self, limit):
        try:
            rows = self.pg_query("SELECT * FROM alerts ORDER BY ts DESC, id DESC LIMIT %s", (limit,))
            alerts = [self.serialize_row(row) for row in rows] + self.local_alerts(pending_only=True, limit=limit)
            source = "postgres"
        except (psycopg2.Error, OSError):
            alerts = self.local_alerts(limit=limit)
            source = "journal"
        unique = {item["id"]: item for item in alerts}
        # Z and +00:00 represent the same timezone; compare instants, not strings.
        result = sorted(unique.values(), key=lambda item: datetime.fromisoformat(
            item["timestamp"].replace("Z", "+00:00")), reverse=True)[:limit]
        return result, source

    def stats(self):
        with self.journal() as db:
            pending_ids = [row[0] for row in db.execute("SELECT event_id FROM journal WHERE postgres_done=0")]
            pending = [dict(threat_class=row[0], total=row[1], high=row[2]) for row in db.execute(
                "SELECT json_extract(payload, '$.threat_class'), count(*), "
                "sum(json_extract(payload, '$.confidence')>=0.85) FROM journal "
                "WHERE postgres_done=0 GROUP BY json_extract(payload, '$.threat_class')")]
        try:
            rows = self.pg_query("""SELECT threat_class, count(*) AS total,
                count(*) FILTER (WHERE confidence >= 0.85) AS high
                FROM alerts WHERE event_id IS NULL OR NOT (event_id = ANY(%s::text[]))
                GROUP BY threat_class""", (pending_ids,))
            # Exclusion prevents double counts after INSERT committed but the
            # connection/status acknowledgement failed before it was recorded.
            rows += pending
            source = "postgres"
        except (psycopg2.Error, OSError):
            with self.journal() as db:
                rows = [dict(threat_class=row[0], total=row[1], high=row[2]) for row in db.execute(
                    "SELECT json_extract(payload, '$.threat_class'), count(*), "
                    "sum(json_extract(payload, '$.confidence')>=0.85) FROM journal "
                    "GROUP BY json_extract(payload, '$.threat_class')")]
            source = "journal"
        by_class = {}
        for row in rows:
            cls = row["threat_class"]
            by_class[cls] = by_class.get(cls, 0) + int(row["total"])
        high = sum(int(row["high"]) for row in rows)
        return {"total": sum(by_class.values()), "by_class": by_class,
                "high_severity": high, "distinct_classes": len(by_class), "source": source}

    def health(self):
        pg_ok = redis_ok = False
        try:
            self.pg_query("SELECT 1")
            pg_ok = True
        except (psycopg2.Error, OSError):
            pass
        try:
            redis_ok = bool(self.redis.ping())
        except (redis.RedisError, OSError):
            pass
        try:
            with self.journal() as db:
                pg_pending, redis_pending = db.execute("SELECT coalesce(sum(postgres_done=0),0), "
                                                       "coalesce(sum(redis_done=0),0) FROM journal").fetchone()
            journal_ok = True
        except (sqlite3.Error, OSError):
            pg_pending = redis_pending = None
            journal_ok = False
        return {"ok": pg_ok and redis_ok and journal_ok, "redis": redis_ok, "postgres": pg_ok,
                "pending_postgres": pg_pending, "pending_redis": redis_pending,
                "journal": journal_ok}


lock = asyncio.Lock()
subscribers: set[asyncio.Queue] = set()


async def replay_loop(stop):
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=5)
            break
        except asyncio.TimeoutError:
            pass
        try:
            async with lock:
                await asyncio.to_thread(storage.replay)
        except Exception:
            log.exception("Journal replay failed; will retry")


@asynccontextmanager
async def lifespan(app):
    global storage, lock, subscribers, pipeline, collector, reports, investigations
    storage = Storage()
    lock, subscribers = asyncio.Lock(), set()
    pipeline = Pipeline(storage, classify_input)
    investigations = await asyncio.to_thread(Investigations, storage, pipeline)
    reports = Reports(storage)
    report_task = asyncio.create_task(reports.run())
    collector = PassiveCollector(pipeline, Alert, save_alerts)
    await collector.start()
    stop = asyncio.Event()
    task = asyncio.create_task(replay_loop(stop))
    try:
        yield
    finally:
        # Let any active replay finish before closing its Redis client.
        stop.set()
        reports.stop.set()
        report_task.cancel()
        with anyio.CancelScope(shield=True):
            try:
                await report_task
            except asyncio.CancelledError:
                pass
        await collector.close()
        await task
        storage.redis.close()


app = FastAPI(title="Dhrashta alert receiver", version="1.0.0", lifespan=lifespan)
app.add_middleware(UploadLimitMiddleware)


@app.get("/api/reports")
async def report_list():
    return {"reports": await asyncio.to_thread(reports.list), "generator": await reports.status()}


@app.post("/api/reports", status_code=202)
async def create_report(body: ReportRequest):
    generator = await reports.status()
    if not generator["configured"]:
        raise HTTPException(503, "Gemini report service is not configured or available")
    return await asyncio.to_thread(reports.create, body, generator["model"])


@app.get("/api/reports/{report_id}")
async def report_detail(report_id: str):
    return await asyncio.to_thread(reports.get, report_id)


@app.get("/api/reports/{report_id}/download")
async def report_download(report_id: str, format: Literal["json", "text"] = "json"):
    report = await asyncio.to_thread(reports.get, report_id)
    # Stored generated UUID determines the filename; URL/input text cannot set headers.
    if format == "text":
        return Response(plain_report(report), media_type="text/plain; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="drashta-report-{report["id"]}.txt"'})
    return Response(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="drashta-report-{report["id"]}.json"'})


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # Invalid NaN/Infinity inputs must produce 422, not fail while serializing
    # the default error response that echoes those non-JSON values.
    errors = [{key: error[key] for key in ("loc", "msg", "type")} for error in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.get("/")
async def service_info():
    return {"service": "Dhrashta backend", "docs": "/docs", "health": "/health"}


@app.get("/health")
async def health():
    return await asyncio.to_thread(storage.health)


@app.post("/alerts")
async def receive_alert(alert: Alert):
    await save_alerts([alert])
    return {"ok": True}


async def save_alerts(alerts, input_id=None, finish_state=None, origin="external"):
    records = []
    source = pipeline.get(input_id) if input_id else None
    receipt_time = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    for alert in alerts:
        record = alert.model_dump(mode="json")
        record["timestamp"] = alert.timestamp.isoformat(timespec="microseconds")
        record["input_id"] = input_id
        record["severity"] = "high" if alert.confidence >= .85 else "medium" if alert.confidence >= .7 else "low"
        identity = json.dumps(record, sort_keys=True, allow_nan=False)
        record["id"] = str(uuid5(NAMESPACE_URL, input_id + identity)) if input_id else str(uuid4())
        record = decorate(record, source["observations"] if source else (), source["origin"] if source else origin, receipt_time)
        records.append(record)
    async with lock:
        try:
            if input_id:
                # Raw input association, alert acceptance, and input state commit
                # together. Identical model-output replays are idempotent.
                with storage.journal() as db:
                    fresh = []
                    for record in records:
                        result = db.execute("INSERT OR IGNORE INTO journal(event_id,payload) VALUES(?,?)",
                                            (record["id"], json.dumps(record, allow_nan=False)))
                        if result.rowcount:
                            fresh.append(record)
                    db.execute("UPDATE inputs SET state=?,alert_count=alert_count+? WHERE id=?",
                               (finish_state, len(fresh), input_id))
                    records = fresh
            elif len(records) == 1:
                for record in records:
                    await asyncio.to_thread(storage.accept, record)
            else:
                with storage.journal() as db:
                    db.executemany("INSERT INTO journal(event_id,payload) VALUES(?,?)",
                                   [(record["id"], json.dumps(record, allow_nan=False)) for record in records])
        except (sqlite3.Error, OSError):
            log.exception("Durable journal unavailable; sensor must retry")
            raise HTTPException(503, "Durable journal unavailable; retry this alert")
        for record in records:
            try:
                await asyncio.to_thread(storage.deliver, record, sync_cache=False)
            except Exception:
                log.exception("Delivery failed after durable acceptance; replay will retry")
            for queue in tuple(subscribers):
                if queue.full():
                    while not queue.empty():
                        queue.get_nowait()
                    queue.put_nowait(None); subscribers.discard(queue)
                else:
                    queue.put_nowait(record)
        if records:
            await asyncio.to_thread(storage.sync_redis)
    return len(records)


async def classify_input(input_id, results, state="replayed_detections"):
    try:
        source = pipeline.get(input_id)
    except KeyError:
        raise HTTPException(404, "Input not found")
    if not isinstance(results, list) or len(results) > 100:
        raise HTTPException(422, "At most 100 model alerts per batch")
    flows = {row["flow_id"] for row in source["observations"]}
    parsed = []
    for result in results:
        if not isinstance(result, dict) or not all(key in result for key in ("timestamp", "flow_id", "threat_class", "confidence", "evidence")):
            raise HTTPException(422, "Model outputs need timestamp, flow_id, threat_class, confidence, and evidence")
        try:
            alert = Alert.model_validate(result)
        except ValueError:
            raise HTTPException(422, "Invalid structured model alert") from None
        if alert.flow_id not in flows:
            raise HTTPException(422, "Detection flow_id does not belong to this input")
        parsed.append(alert)
    return await save_alerts(parsed, input_id, state)


@app.get("/api/ingest")
async def ingestion_status():
    return {"inputs": await asyncio.to_thread(pipeline.recent), "monitor": collector.status(), "model": pipeline.model_status(),
            "limits": {"max_upload_bytes": MAX_BYTES, "max_flows": 10000, "max_packets": 100000}}


@app.post("/api/ingest/upload")
async def upload_observations(file: UploadFile = File(...), format: str = Form(...)):
    try:
        data = await file.read(MAX_BYTES + 1)
        if not data or len(data) > MAX_BYTES:
            raise HTTPException(413, "File must contain 1 byte to 10 MiB")
        if format == "detections":
            try:
                results = json.loads(data)
                if isinstance(results, dict):
                    results = results.get("alerts", [results])
                if not isinstance(results, list) or not 1 <= len(results) <= 100 or any(not isinstance(row, dict) or not row.get("flow_id") for row in results):
                    raise ValueError()
                # Build the input association without inventing any measurements.
                # Validate all outputs before writing input or emitting any alert.
                for row in results:
                    if not all(key in row for key in ("timestamp", "flow_id", "threat_class", "confidence", "evidence")):
                        raise ValueError()
                    Alert.model_validate(row)
            except (ValueError, TypeError):
                raise HTTPException(422, "Detection replay needs 1–100 valid structured alerts with flow_id") from None
            return await pipeline.process(data, "detections", Path(file.filename or "detections.json").name, replay_results=results)
        return await pipeline.process(data, format, Path(file.filename or "Uploaded input").name)
    except InputError as exc:
        raise HTTPException(422, str(exc)) from None
    finally:
        await file.close()


@app.get("/api/ingest/{input_id}/features")
async def input_features(input_id: str, download: bool = False):
    try:
        source = await asyncio.to_thread(pipeline.get, input_id)
    except KeyError:
        raise HTTPException(404, "Input not found") from None
    payload = {"input_id": input_id, "feature_version": "passive-flow-v1", "records": source["observations"]}
    headers = {"Content-Disposition": f'attachment; filename="features-{input_id}.json"'} if download else {}
    return JSONResponse(payload, headers=headers)


@app.get("/api/ingest/{input_id}")
async def input_summary(input_id: str):
    try:
        return await asyncio.to_thread(pipeline.by_id, input_id)
    except KeyError:
        raise HTTPException(404, "Input not found") from None


@app.get("/api/ingest/{input_id}/original")
async def original_input(input_id: str):
    try:
        source = await asyncio.to_thread(pipeline.get, input_id)
    except KeyError:
        raise HTTPException(404, "Input not found") from None
    return Response(source["original"], media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="original-{input_id}.bin"'})


@app.post("/api/ingest/{input_id}/detections")
async def replay_model_output(input_id: str, body: DetectionBatch):
    results = [alert.model_dump(mode="json") for alert in body.alerts]
    count = await classify_input(input_id, results)
    return {"ok": True, "accepted": count}


@app.post("/api/monitor")
async def control_monitor(body: dict):
    if set(body) != {"active"} or not isinstance(body["active"], bool):
        raise HTTPException(422, "Provide only the boolean active field")
    if body["active"] and collector.socket is None:
        raise HTTPException(503, "Passive UDP receiver unavailable")
    collector.active = body["active"]
    return collector.status()


@app.get("/api/alerts")
async def recent_alerts(limit: int = Query(default=100, ge=1, le=500)):
    async with lock:
        alerts, source = await asyncio.to_thread(storage.recent, limit)
    return {"count": len(alerts), "alerts": alerts, "source": source}


@app.get("/api/stats")
async def stats():
    async with lock:
        return await asyncio.to_thread(storage.stats)


@app.get("/api/history")
async def alert_history(limit: int = Query(50, ge=1, le=100), cursor: str | None = Query(None, max_length=4096),
                        ip: str | None = Query(None, max_length=45), threat_class: ThreatClass | None = None,
                        severity: Literal["high", "medium", "low"] | None = None,
                        origin: Literal["live", "upload", "external", "unknown"] | None = None,
                        since: str | None = Query(None, max_length=40), until: str | None = Query(None, max_length=40),
                        alert_id: str | None = Query(None, max_length=200), exclude_benign: bool = False):
    filters = investigations.filters(ip, threat_class, severity, origin, since, until, alert_id, exclude_benign)
    return await asyncio.to_thread(investigations.history, filters, limit, cursor)


@app.get("/api/history/{alert_id}")
async def historical_alert(alert_id: str):
    return await asyncio.to_thread(investigations.get, alert_id)


@app.get("/api/analytics/heatmap")
async def threat_heatmap():
    return await asyncio.to_thread(investigations.heatmap)


@app.get("/api/network")
async def network_view(mode: Literal["live", "capture"] = "live", input_id: str | None = Query(None, max_length=100), unusual_only: bool = False):
    return await asyncio.to_thread(investigations.network, mode, input_id, unusual_only)


@app.get("/api/investigations/ip")
async def ip_evidence_report(address: str = Query(..., max_length=45), download: bool = False):
    report = await asyncio.to_thread(investigations.ip_report, address)
    headers = {"Content-Disposition": 'attachment; filename="drashta-ip-evidence.json"'} if download else {}
    return JSONResponse(report, headers=headers)


@app.websocket("/ws")
async def websocket_feed(websocket: WebSocket):
    await websocket.accept()
    queue = asyncio.Queue(maxsize=500)
    # Registration and snapshot are atomic with respect to ingestion.
    async with lock:
        snapshot, _ = await asyncio.to_thread(storage.recent, 20)
        subscribers.add(queue)

    async def sender():
        for item in reversed(snapshot):
            await websocket.send_json(item)
        while True:
            item = await queue.get()
            if item is None:
                await websocket.close(code=1013)
                return
            await websocket.send_json(item)

    async def receiver():
        while True:
            await websocket.receive_text()

    tasks = [asyncio.create_task(sender()), asyncio.create_task(receiver())]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    except (WebSocketDisconnect, RuntimeError, OSError, asyncio.CancelledError):
        # Client teardown can cancel the handler before receive_text observes
        # the disconnect. Treat that as a normal WebSocket close.
        pass
    finally:
        subscribers.discard(queue)
        for task in tasks:
            task.cancel()
        # AnyIO may repeatedly cancel at each await during client teardown.
        # Shield cleanup so neither child task survives a closed connection.
        with anyio.CancelScope(shield=True):
            await asyncio.gather(*tasks, return_exceptions=True)
