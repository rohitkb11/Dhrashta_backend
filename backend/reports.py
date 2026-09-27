"""Durable report jobs and immutable alert snapshots; no cloud credentials here."""
import asyncio
import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated
from urllib.request import Request, urlopen
from uuid import uuid4

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_SOURCE_BYTES = 96 * 1024
WORKER_URL = "http://report-service:8010"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def now():
    return datetime.now(timezone.utc).isoformat()


class ReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(default="Evidence report", min_length=1, max_length=120)
    alert_ids: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(min_length=1, max_length=30)

    @field_validator("title")
    @classmethod
    def title_nonblank(cls, value):
        if not value.strip():
            raise ValueError("Report title cannot be blank")
        return value.strip()

    @field_validator("alert_ids")
    @classmethod
    def unique_ids(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("Select each alert only once")
        return value


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=160)
    analysis: str = Field(min_length=1, max_length=2400)
    alert_refs: list[Annotated[str, Field(pattern=r"^A[1-9][0-9]*$")]] = Field(min_length=1, max_length=30)


class Narrative(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=4000)
    findings: list[Finding] = Field(min_length=1, max_length=12)
    recommendations: list[Annotated[str, Field(min_length=1, max_length=1500)]] = Field(max_length=10)
    limitations: list[Annotated[str, Field(min_length=1, max_length=1500)]] = Field(min_length=1, max_length=8)


def validate_narrative(value, sources):
    narrative = Narrative.model_validate(value)
    allowed = {source["ref"] for source in sources}
    if any(ref not in allowed for finding in narrative.findings for ref in finding.alert_refs):
        raise ValueError("Report cites an alert outside its snapshot")
    # Every selected alert must be addressed, even if only to note insufficient evidence.
    cited = {ref for finding in narrative.findings for ref in finding.alert_refs}
    if cited != allowed:
        raise ValueError("Report did not address every selected alert")
    return narrative.model_dump()


def worker_call(path, body=None, timeout=3):
    encoded = canonical(body).encode() if body is not None else None
    request = Request(WORKER_URL + path, data=encoded, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=timeout) as response:
        raw = response.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        raise ValueError("Report service response exceeds limit")
    return json.loads(raw)


class Reports:
    def __init__(self, storage):
        self.storage = storage
        self.stop = asyncio.Event()
        with storage.journal() as db:
            db.execute("CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
            # An interrupted cloud request is not retried automatically: it may have been billed.
            for report_id, payload in db.execute("SELECT id,payload FROM reports").fetchall():
                report = json.loads(payload)
                if report["state"] == "generating":
                    report.update(state="failed", error="Generation interrupted. Create a new report to retry.", completed_at=now())
                    db.execute("UPDATE reports SET payload=? WHERE id=?", (canonical(report), report_id))

    async def status(self):
        try:
            result = await asyncio.to_thread(worker_call, "/status")
            return {"provider": "Google Gemini", "model": str(result["model"]),
                    "configured": result["configured"] is True, "available": True}
        except Exception:
            return {"provider": "Google Gemini", "model": None, "configured": False, "available": False}

    def get(self, report_id):
        with self.storage.journal() as db:
            row = db.execute("SELECT payload FROM reports WHERE id=?", (report_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Report not found")
        return json.loads(row[0])

    def list(self):
        with self.storage.journal() as db:
            rows = db.execute("SELECT payload FROM reports ORDER BY rowid DESC LIMIT 20").fetchall()
        return [{key: report[key] for key in ("id", "title", "created_at", "state", "model", "source_count", "error")}
                for report in (json.loads(row[0]) for row in rows)]

    def create(self, request, model):
        placeholders = ",".join("?" for _ in request.alert_ids)
        with self.storage.journal() as db:
            found = {row[0]: json.loads(row[1]) for row in db.execute(
                "SELECT event_id,payload FROM journal WHERE event_id IN (" + placeholders + ")", request.alert_ids)}
        missing = [item for item in request.alert_ids if item not in found]
        if missing:
            try:
                rows = self.storage.pg_query("SELECT * FROM alerts WHERE coalesce(event_id,'pg-'||id::text) = ANY(%s)", (missing,))
                found.update({record["id"]: record for record in (self.storage.serialize_row(row) for row in rows)})
            except Exception:
                raise HTTPException(503, "Selected alert history is unavailable") from None
        if any(item not in found for item in request.alert_ids):
            raise HTTPException(422, "One or more selected alerts no longer exist")
        sources = [{"ref": f"A{index + 1}", "alert": found[item]} for index, item in enumerate(request.alert_ids)]
        raw = canonical(sources).encode()
        if len(raw) > MAX_SOURCE_BYTES:
            raise HTTPException(413, "Selected evidence exceeds 96 KiB; select fewer alerts")
        report = dict(id=str(uuid4()), title=request.title, created_at=now(), completed_at=None,
                      state="queued", provider="Google Gemini", model=model, source_count=len(sources),
                      sources=sources, source_sha256=hashlib.sha256(raw).hexdigest(),
                      narrative=None, error=None, usage=None)
        with self.storage.journal() as db:
            db.execute("BEGIN IMMEDIATE")
            pending = db.execute("SELECT count(*) FROM reports WHERE json_extract(payload,'$.state') IN ('queued','generating')").fetchone()[0]
            if pending >= 8:
                raise HTTPException(429, "Report queue is full")
            db.execute("INSERT INTO reports VALUES (?,?)", (report["id"], canonical(report)))
        return report

    def update(self, report):
        with self.storage.journal() as db:
            db.execute("UPDATE reports SET payload=? WHERE id=?", (canonical(report), report["id"]))

    async def run(self):
        while not self.stop.is_set():
            with self.storage.journal() as db:
                row = db.execute("SELECT payload FROM reports WHERE json_extract(payload,'$.state')='queued' ORDER BY rowid LIMIT 1").fetchone()
            if not row:
                try:
                    await asyncio.wait_for(self.stop.wait(), 1)
                except asyncio.TimeoutError:
                    pass
                continue
            report = json.loads(row[0])
            report["state"] = "generating"
            self.update(report)
            try:
                result = await asyncio.to_thread(worker_call, "/generate",
                                                {"sources": report["sources"], "model": report["model"]}, 100)
                report["narrative"] = validate_narrative(result["narrative"], report["sources"])
                report["usage"] = result.get("usage")
                report["state"] = "draft"
            except asyncio.CancelledError:
                report.update(state="failed", error="Generation interrupted. Create a new report to retry.", completed_at=now())
                self.update(report)
                raise
            except Exception:
                report.update(state="failed", error="Generation failed. Check Gemini credentials, quota and model settings, then create a new report.")
            report["completed_at"] = now()
            self.update(report)


def plain_report(report):
    """Plain text export keeps sensor strings inert and preserves the exact snapshot."""
    lines = [report["title"], "DRAFT — analyst review required", "", f"Report ID: {report['id']}",
             f"Created: {report['created_at']}", f"Provider/model: {report['provider']} / {report['model']}",
             f"Evidence SHA-256: {report['source_sha256']}", ""]
    narrative = report["narrative"] or {}
    lines += ["SUMMARY", narrative.get("summary", report["state"]), "", "FINDINGS"]
    for finding in narrative.get("findings", []):
        lines += [finding["title"], finding["analysis"], "Sources: " + ", ".join(finding["alert_refs"]), ""]
    for key in ("recommendations", "limitations"):
        lines += [key.upper(), *["• " + item for item in narrative.get(key, [])], ""]
    lines += ["ORIGINAL ALERT EVIDENCE", json.dumps(report["sources"], ensure_ascii=False, indent=2, allow_nan=False)]
    return "\n".join(lines)
