"""Read-only history and network views. No enrichment, sockets or detection rules."""
import base64
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException

IP_KEYS = {"src": ("src_ip", "source_ip", "sourceIPv4Address", "sourceIPv6Address", "srcaddr"),
           "dst": ("dst_ip", "destination_ip", "destinationIPv4Address", "destinationIPv6Address", "dstaddr")}


def literal_ip(value):
    if not isinstance(value, str) or "%" in value or len(value) > 45:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def stamp(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def decorate(record, observations=(), origin="external", received_at=None):
    result = dict(record)
    matches = [row for row in observations if row["flow_id"] == record.get("flow_id")]
    sources = {}
    for side in ("src", "dst"):
        evidence = record.get("evidence") or {}
        address = next((literal_ip(evidence.get(key)) for key in IP_KEYS[side] if literal_ip(evidence.get(key))), None)
        if address:
            sources[side] = "alert evidence"
        else:
            values = {literal_ip(row.get(side + "_ip")) for row in matches} - {None}
            address = next(iter(values)) if len(values) == 1 else None
            sources[side] = "input observation" if address else "not supplied / ambiguous"
        result[side + "_ip"] = address
    result["endpoint_source"] = sources
    result["origin"] = origin
    result["received_at"] = received_at
    result["timestamp"] = stamp(record["timestamp"])
    return result


class Investigations:
    def __init__(self, storage, pipeline):
        self.storage, self.pipeline = storage, pipeline
        # Existing immutable input/alert evidence is unchanged. Only derived display metadata is added.
        with storage.journal() as db:
            rows = db.execute("SELECT event_id,payload FROM journal").fetchall()
            for alert_id, payload in rows:
                record = json.loads(payload)
                if "endpoint_source" in record:
                    continue
                source = None
                if record.get("input_id"):
                    source = db.execute("SELECT observations,origin FROM inputs WHERE id=?", (record["input_id"],)).fetchone()
                updated = decorate(record, json.loads(source[0]) if source else (), source[1] if source else "unknown")
                db.execute("UPDATE journal SET payload=? WHERE event_id=?", (json.dumps(updated, allow_nan=False), alert_id))
            db.execute("CREATE INDEX IF NOT EXISTS journal_history ON journal(json_extract(payload,'$.timestamp') DESC,event_id DESC)")
            db.execute("CREATE INDEX IF NOT EXISTS journal_src ON journal(json_extract(payload,'$.src_ip'))")
            db.execute("CREATE INDEX IF NOT EXISTS journal_dst ON journal(json_extract(payload,'$.dst_ip'))")
        try:
            self.ensure_pg()
            # Backfill only legacy PG rows missing derived metadata, including PG-only history.
            last = 0
            while True:
                rows = storage.pg_query("SELECT * FROM alerts WHERE endpoint_source IS NULL AND id>%s ORDER BY id LIMIT 500", (last,))
                if not rows:
                    break
                for row in rows:
                    record = storage.serialize_row(row)
                    source = None
                    if record.get("input_id"):
                        try:
                            source = pipeline.get(record["input_id"])
                        except KeyError:
                            pass
                    updated = decorate(record, source["observations"] if source else (), source["origin"] if source else "unknown")
                    storage.pg_query("UPDATE alerts SET src_ip=%s,dst_ip=%s,endpoint_source=%s::jsonb,origin=%s WHERE id=%s",
                                     (updated["src_ip"], updated["dst_ip"], json.dumps(updated["endpoint_source"]), updated["origin"], row["id"]))
                last = rows[-1]["id"]
        except Exception:
            # History still works from the complete local journal during a PG outage.
            pass

    def ensure_pg(self):
        self.storage.pg_query("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS flow_id TEXT; ALTER TABLE alerts ADD COLUMN IF NOT EXISTS input_id TEXT; "
                              "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS src_ip TEXT; ALTER TABLE alerts ADD COLUMN IF NOT EXISTS dst_ip TEXT; "
                              "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS endpoint_source JSONB; ALTER TABLE alerts ADD COLUMN IF NOT EXISTS origin TEXT; "
                              "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS received_at TIMESTAMPTZ")

    @staticmethod
    def filters(ip=None, threat_class=None, severity=None, origin=None, since=None, until=None, alert_id=None, exclude_benign=False):
        if ip and not literal_ip(ip):
            raise HTTPException(422, "Use a literal IPv4 or IPv6 address")
        def utc(value):
            try:
                return stamp(value) if value else None
            except (ValueError, TypeError, OverflowError):
                raise HTTPException(422, "Use an ISO timestamp") from None
        values = dict(ip=literal_ip(ip), threat_class=threat_class, severity=severity, origin=origin, since=utc(since), until=utc(until), alert_id=alert_id.strip() if alert_id else None, exclude_benign=exclude_benign)
        if values["since"] and values["until"] and values["since"] >= values["until"]:
            raise HTTPException(422, "End time must follow start time")
        return values

    def conditions(self, filters, pg=False, cursor=None, watermark=None):
        time = "ts" if pg else "json_extract(payload,'$.timestamp')"
        identifier = "coalesce(event_id,'pg-'||id::text) COLLATE \"C\"" if pg else "event_id"
        def field(name):
            return name if pg else f"json_extract(payload,'$.{name}')"
        marker = "%s" if pg else "?"
        terms, values = [], []
        if filters.get("exclude_benign"):
            terms.append(f"{field('threat_class')}<>{marker}")
            values.append("BENIGN")
        if filters.get("alert_id"):
            terms.append(f"{identifier}={marker}")
            values.append(filters["alert_id"])
        if filters["ip"]:
            terms.append(f"({field('src_ip')}={marker} OR {field('dst_ip')}={marker})")
            values.extend([filters["ip"]] * 2)
        for name in ("threat_class", "origin"):
            if filters.get(name):
                terms.append(f"{field(name)}={marker}"); values.append(filters[name])
        if filters.get("severity"):
            confidence = field("confidence")
            terms.append({"high": f"{confidence}>=0.85", "medium": f"{confidence}>=0.7 AND {confidence}<0.85", "low": f"{confidence}<0.7"}[filters["severity"]])
        for name, operator in (("since", ">="), ("until", "<")):
            if filters.get(name):
                terms.append(f"{time}{operator}{marker}"); values.append(filters[name])
        if cursor:
            terms.append(f"({time}<{marker} OR ({time}={marker} AND {identifier}<{marker}))")
            values.extend([cursor[0], cursor[0], cursor[1]])
        if watermark is not None:
            terms.append(f"{'id' if pg else 'rowid'}<={marker}"); values.append(watermark)
        return " AND ".join(terms) or "1=1", values

    def history(self, filters, limit=50, token=None):
        cursor, marks = None, None
        if token:
            try:
                body = json.loads(base64.urlsafe_b64decode(token))
                if body["filters"] != filters or stamp(body["after"][0]) != body["after"][0] or not isinstance(body["after"][1], str):
                    raise ValueError()
                if not isinstance(body["after"], list) or len(body["after"]) != 2 or not isinstance(body["marks"], dict) or set(body["marks"]) != {"journal", "postgres"}:
                    raise ValueError()
                if len(body["after"][1]) > 200 or any(type(value) is not int or value < 0 for value in body["marks"].values()):
                    raise ValueError()
                cursor, marks = body["after"], body["marks"]
            except Exception:
                raise HTTPException(422, "Invalid history cursor; refresh the search") from None
        with self.storage.journal() as db:
            local_mark = marks["journal"] if marks else db.execute("SELECT coalesce(max(rowid),0) FROM journal").fetchone()[0]
            where, args = self.conditions(filters, cursor=cursor, watermark=local_mark)
            rows = db.execute("SELECT payload FROM journal WHERE " + where + " ORDER BY json_extract(payload,'$.timestamp') DESC,event_id DESC LIMIT ?", [*args, limit + 1]).fetchall()
            local = [json.loads(row[0]) for row in rows]
            count_where, count_args = self.conditions(filters, watermark=local_mark)
            local_ids = [row[0] for row in db.execute("SELECT event_id FROM journal WHERE " + count_where, count_args)]
        pg_mark, remote, source = 0, [], "journal"
        try:
            pg_mark = marks["postgres"] if marks else int(self.storage.pg_query("SELECT coalesce(max(id),0) AS n FROM alerts")[0]["n"])
            where, args = self.conditions(filters, pg=True, cursor=cursor, watermark=pg_mark)
            rows = self.storage.pg_query("SELECT * FROM alerts WHERE " + where + " ORDER BY ts DESC,coalesce(event_id,'pg-'||id::text) COLLATE \"C\" DESC LIMIT %s", (*args, limit + 1))
            remote = [self.storage.serialize_row(row) for row in rows]
            count_where, count_args = self.conditions(filters, pg=True, watermark=pg_mark)
            pg_count = int(self.storage.pg_query("SELECT count(*) AS n FROM alerts WHERE " + count_where + " AND (event_id IS NULL OR NOT(event_id=ANY(%s::text[])))", (*count_args, local_ids))[0]["n"])
            total, source = len(local_ids) + pg_count, "postgres + journal"
        except Exception:
            total = len(local_ids)
        unique = {row["id"]: row for row in remote}
        unique.update({row["id"]: row for row in local})
        ordered = sorted(unique.values(), key=lambda row: (stamp(row["timestamp"]), row["id"]), reverse=True)
        page = ordered[:limit]
        next_cursor = None
        if len(ordered) > limit:
            body = dict(filters=filters, after=[stamp(page[-1]["timestamp"]), page[-1]["id"]], marks={"journal": local_mark, "postgres": pg_mark})
            next_cursor = base64.urlsafe_b64encode(json.dumps(body).encode()).decode()
        return dict(alerts=page, total=total, next_cursor=next_cursor, source=source)

    def get(self, alert_id):
        with self.storage.journal() as db:
            row = db.execute("SELECT payload FROM journal WHERE event_id=?", (alert_id,)).fetchone()
        if row:
            return json.loads(row[0])
        try:
            rows = self.storage.pg_query("SELECT * FROM alerts WHERE coalesce(event_id,'pg-'||id::text)=%s", (alert_id,))
        except Exception:
            raise HTTPException(503, "Alert history unavailable") from None
        if not rows:
            raise HTTPException(404, "Alert not found")
        return self.storage.serialize_row(rows[0])

    def iterate(self, filters):
        token = None
        while True:
            page = self.history(filters, 500, token)
            yield page
            token = page["next_cursor"]
            if not token:
                break

    def heatmap(self):
        end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        start = end - timedelta(days=7)
        days = [(start + timedelta(days=i)).date().isoformat() for i in range(7)]
        cells = {day: [{"count": 0, "peak_confidence": None} for _ in range(24)] for day in days}
        total, excluded, source = 0, 0, "journal"
        for page in self.iterate(self.filters(since=start.isoformat(), until=end.isoformat())):
            source = page["source"]
            for row in page["alerts"]:
                if row["threat_class"] == "BENIGN":
                    excluded += 1; continue
                dt = datetime.fromisoformat(stamp(row["timestamp"]))
                cell = cells[dt.date().isoformat()][dt.hour]
                cell["count"] += 1; cell["peak_confidence"] = max(cell["peak_confidence"] or 0, row["confidence"]); total += 1
        return dict(days=[{"date": day, "hours": cells[day]} for day in days], total=total, benign_excluded=excluded, timezone="UTC", source=source)

    def ip_report(self, address):
        address = literal_ip(address)
        if not address:
            raise HTTPException(422, "Use a literal IP address")
        classes, bands, peers = Counter(), Counter(), Counter()
        first = last = None
        total = missing_peer = 0
        source = "journal"
        for page in self.iterate(self.filters(ip=address)):
            source = page["source"]
            for row in page["alerts"]:
                total += 1; classes[row["threat_class"]] += 1
                bands[row.get("severity", "low")] += 1
                time = stamp(row["timestamp"])
                first, last = min(first or time, time), max(last or time, time)
                peer = row.get("dst_ip") if row.get("src_ip") == address else row.get("src_ip")
                if peer: peers[peer] += 1
                else: missing_peer += 1
        return dict(ip=address, total_alerts=total, first_detection=first, last_detection=last, by_class=dict(classes),
                    confidence_bands=dict(bands), peers=[{"ip": ip, "alerts": count} for ip, count in peers.most_common(20)],
                    peers_total=len(peers), missing_peer=missing_peer, source=source, generated_at=datetime.now(timezone.utc).isoformat(),
                    scope="Retained alert evidence only; no active queries, reputation lookup, geolocation or attribution")

    def network(self, mode, input_id=None, unusual_only=False):
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat(timespec="microseconds")
        observations, alerts = [], []
        with self.storage.journal() as db:
            if mode == "capture":
                if not input_id:
                    return dict(nodes=[], edges=[], observations=0, mapped_alerts=0, unmapped_alerts=0, omitted_edges=0, mode=mode)
                row = db.execute("SELECT observations FROM inputs WHERE id=?", (input_id,)).fetchone()
                if not row: raise HTTPException(404, "Uploaded input not found")
                observations = json.loads(row[0])
                alerts = [json.loads(row[0]) for row in db.execute("SELECT payload FROM journal WHERE json_extract(payload,'$.input_id')=?", (input_id,))]
            else:
                for row in db.execute("SELECT observations FROM inputs WHERE origin='live' AND created_at>=? ORDER BY created_at DESC LIMIT 200", (cutoff,)):
                    observations.extend(json.loads(row[0])[:max(0,10000-len(observations))])
                    if len(observations) >= 10000: break
                alerts = [json.loads(row[0]) for row in db.execute("SELECT payload FROM journal WHERE json_extract(payload,'$.origin')='live' AND json_extract(payload,'$.received_at')>=?", (cutoff,))]
        edges = {}
        def edge(src, dst):
            return edges.setdefault((src, dst), dict(src_ip=src, dst_ip=dst, observations=0, alerts=0, unusual_alerts=0, peak_confidence=None))
        unmapped_flows = unmapped_alerts = 0
        for row in observations:
            src, dst = literal_ip(row.get("src_ip")), literal_ip(row.get("dst_ip"))
            if src and dst: edge(src, dst)["observations"] += 1
            else: unmapped_flows += 1
        for row in alerts:
            src, dst = row.get("src_ip"), row.get("dst_ip")
            if not src or not dst:
                unmapped_alerts += 1; continue
            item = edge(src, dst); item["alerts"] += 1
            if row["threat_class"] != "BENIGN":
                item["unusual_alerts"] += 1
                item["peak_confidence"] = max(item["peak_confidence"] or 0, row["confidence"])
        ranked = sorted((row for row in edges.values() if not unusual_only or row["unusual_alerts"]),
                        key=lambda row: (-row["unusual_alerts"], -row["observations"], row["src_ip"], row["dst_ip"]))
        displayed, nodes = [], set()
        for row in ranked:
            endpoints = {row["src_ip"], row["dst_ip"]}
            if len(displayed) >= 48 or len(nodes | endpoints) > 20: continue
            displayed.append(row); nodes |= endpoints
        return dict(nodes=[{"ip": ip, "unusual_alerts": sum(row["unusual_alerts"] for row in displayed if ip in (row["src_ip"], row["dst_ip"]))} for ip in sorted(nodes)],
                    edges=displayed, observations=len(observations), unmapped_observations=unmapped_flows,
                    mapped_alerts=sum(row["alerts"] for row in edges.values()), unmapped_alerts=unmapped_alerts,
                    omitted_edges=len(ranked)-len(displayed), mode=mode, window_seconds=60 if mode=="live" else None,
                    scope="Latest 200 live inputs / first 10,000 observations received in 60 seconds" if mode=="live" else "Selected saved input")
