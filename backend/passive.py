"""Offline decoders and observed-flow features. No sockets, probes, or capture API.

Only the bytes already supplied by an upload or receive-only collector are read.
Unknown templates never trigger an exporter query. Payload is never decrypted.
"""
import csv
import hashlib
import io
import ipaddress
import json
import math
import statistics
import struct
import time
from datetime import datetime, timezone

MAX_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 10000
MAX_PACKETS = 100000
FEATURE_VERSION = "passive-flow-v1"


class InputError(ValueError):
    pass


def utc(value):
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            parsed = datetime.fromtimestamp(value, timezone.utc)
        elif isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            raise ValueError()
        return (parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed).astimezone(timezone.utc).isoformat(timespec="microseconds")
    except (ValueError, OverflowError, OSError):
        raise InputError("Invalid observation timestamp") from None


def finite(value, depth=0):
    if depth > 12:
        raise InputError("Metadata nesting exceeds 12 levels")
    if isinstance(value, float) and not math.isfinite(value):
        raise InputError("Measurements must be finite")
    if isinstance(value, dict):
        if len(value) > 200:
            raise InputError("Too many metadata fields")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 200:
                raise InputError("Invalid metadata field name")
            finite(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 1000:
            raise InputError("Metadata array too large")
        for item in value:
            finite(item, depth + 1)
    elif not isinstance(value, (str, int, float, bool, type(None))):
        raise InputError("Metadata must contain JSON values")
    elif isinstance(value, str) and len(value) > 4000:
        raise InputError("Metadata value too long")


def integer(value, maximum, field):
    if isinstance(value, bool):
        raise InputError(f"Invalid {field}")
    try:
        number = int(value)
        if isinstance(value, float) and value != number:
            raise ValueError()
        if isinstance(value, str) and str(number) != value.strip():
            raise ValueError()
        if not 0 <= number <= maximum:
            raise ValueError()
        return number
    except (TypeError, ValueError, OverflowError):
        raise InputError(f"Invalid {field}") from None


ALIASES = {
    "src_ip": ("src_ip", "sourceIPv4Address", "sourceIPv6Address", "srcaddr"),
    "dst_ip": ("dst_ip", "destinationIPv4Address", "destinationIPv6Address", "dstaddr"),
    "src_port": ("src_port", "sourceTransportPort", "srcport"),
    "dst_port": ("dst_port", "destinationTransportPort", "dstport"),
    "protocol": ("protocol", "protocolIdentifier", "prot"),
    "packet_count": ("packet_count", "packetDeltaCount", "dPkts"),
    "byte_count": ("byte_count", "octetDeltaCount", "dOctets"),
    "timestamp": ("timestamp", "flowStart", "flowStartMilliseconds"),
}


def normalize(row, observed_at=None):
    if not isinstance(row, dict):
        raise InputError("Each observation must be an object")
    finite(row)
    mapped = {key: next((row[name] for name in names if row.get(name) not in (None, "")), None) for key, names in ALIASES.items()}
    for field in ("src_ip", "dst_ip"):
        if mapped[field] is not None:
            try:
                if not isinstance(mapped[field], str):
                    raise ValueError()
                mapped[field] = str(ipaddress.ip_address(mapped[field]))
            except ValueError:
                raise InputError(f"{field} must be a literal IP address; hostnames are not queried") from None
    protocol = mapped["protocol"]
    if isinstance(protocol, str) and protocol.upper() in ("TCP", "UDP", "ICMP", "ICMPV6"):
        protocol = {"TCP": 6, "UDP": 17, "ICMP": 1, "ICMPV6": 58}[protocol.upper()]
    if protocol is not None:
        mapped["protocol"] = integer(protocol, 255, "protocol")
    for field in ("src_port", "dst_port"):
        if mapped[field] is not None:
            mapped[field] = integer(mapped[field], 65535, field)
    supplied_id = row.get("flow_id")
    if supplied_id is not None and (not isinstance(supplied_id, str) or not supplied_id.strip() or len(supplied_id) > 200):
        raise InputError("flow_id must be a nonempty string of at most 200 characters")
    identity = [mapped[key] for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")]
    if not supplied_id and any(value is None for value in identity):
        raise InputError("Supply flow_id or a complete directional five-tuple")
    flow_id = supplied_id or "flow-" + hashlib.sha256(json.dumps(identity).encode()).hexdigest()[:24]
    stamp = mapped["timestamp"]
    if "flowStartMilliseconds" in row and row.get("timestamp") is None and row.get("flowStart") is None:
        try:
            stamp = float(stamp) / 1000
        except (TypeError, ValueError, OverflowError):
            raise InputError("Invalid flowStartMilliseconds") from None
    timestamp = utc(stamp) if stamp is not None else utc(observed_at or datetime.now(timezone.utc).isoformat())
    features = row.get("features", row.get("evidence", {}))
    if not isinstance(features, dict):
        raise InputError("features must be an object")
    features = dict(features)
    for key in ("packet_count", "byte_count"):
        if mapped[key] is not None:
            features[key] = integer(mapped[key], 2**64 - 1, key)
        elif key in features:
            features[key] = integer(features[key], 2**64 - 1, key)
    duration = row.get("duration_seconds")
    if row.get("end_timestamp") is not None and stamp is not None:
        duration = (datetime.fromisoformat(utc(row["end_timestamp"])) - datetime.fromisoformat(timestamp)).total_seconds()
    if duration is not None:
        if isinstance(duration, bool):
            raise InputError("Invalid duration_seconds")
        try:
            duration = float(duration)
        except (TypeError, ValueError):
            raise InputError("Invalid duration_seconds") from None
        if not math.isfinite(duration) or duration < 0:
            raise InputError("Invalid duration_seconds")
        features["duration_seconds"] = duration
        if duration > 0:
            for count, rate in (("packet_count", "packets_per_second"), ("byte_count", "bytes_per_second")):
                if count in features and isinstance(features[count], (int, float)) and not isinstance(features[count], bool):
                    result = features[count] / duration
                    if math.isfinite(result):
                        features[rate] = result
    if features.get("packet_count", 0) and "byte_count" in features:
        if all(isinstance(features[k], (int, float)) and not isinstance(features[k], bool) and features[k] >= 0 for k in ("packet_count", "byte_count")):
            features["mean_packet_bytes"] = features["byte_count"] / features["packet_count"]
    finite(features)
    return {"flow_id": flow_id, "timestamp": timestamp,
            **{key: mapped[key] for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")},
            "features": features, "feature_version": FEATURE_VERSION,
            "source_timestamp_supplied": stamp is not None,
            "sampled": row.get("sampled", None), "sampling_rate": row.get("sampling_rate", None)}


def decode_text(data, kind):
    try:
        text = data.decode("utf-8-sig")
        if kind == "flow-csv":
            rows = list(csv.DictReader(io.StringIO(text)))
        else:
            parsed = json.loads(text)
            rows = parsed.get("records") if isinstance(parsed, dict) and "records" in parsed else parsed
            if isinstance(rows, dict):
                rows = [rows]
        if not isinstance(rows, list) or not rows:
            raise InputError("Supply a nonempty record array or an object containing records")
        if len(rows) > MAX_RECORDS:
            raise InputError("At most 10000 observations per input")
        return [normalize(row) for row in rows], []
    except (UnicodeError, json.JSONDecodeError, csv.Error):
        raise InputError("Invalid UTF-8 JSON/CSV input") from None


class Cursor:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, size):
        if size < 0 or self.offset + size > len(self.data):
            raise InputError("Truncated binary input")
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def u32(self):
        return struct.unpack("!I", self.take(4))[0]


def packet_metadata(data, linktype=1):
    # Ethernet/VLAN, raw IP, Linux cooked v1/v2. Never replay the bytes.
    if linktype == 1:
        if len(data) < 14:
            return None
        ethertype = struct.unpack("!H", data[12:14])[0]
        data = data[14:]
        for _ in range(4):
            if ethertype not in (0x8100, 0x88a8):
                break
            if len(data) < 4:
                return None
            ethertype = struct.unpack("!H", data[2:4])[0]; data = data[4:]
        if ethertype not in (0x800, 0x86dd):
            return None
    elif linktype == 113:
        data = data[16:]
    elif linktype == 276:
        data = data[20:]
    elif linktype not in (101, 228, 229):
        raise InputError("Unsupported capture link type (supported: Ethernet, raw IP, Linux cooked)")
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            return None
        header = (data[0] & 15) * 4
        if header < 20 or len(data) < header:
            return None
        total = struct.unpack("!H", data[2:4])[0]
        if total < header:
            return None
        fragment = struct.unpack("!H", data[6:8])[0]
        if fragment & 0x1fff:
            return None  # Cannot recover ports from noninitial fragments.
        src, dst = map(str, (ipaddress.ip_address(data[12:16]), ipaddress.ip_address(data[16:20])))
        protocol, payload = data[9], data[header:min(total, len(data))]
        partial = bool(fragment & 0x2000) or total > len(data)
    elif version == 6:
        if len(data) < 40:
            return None
        total = 40 + struct.unpack("!H", data[4:6])[0]
        src, dst = map(str, (ipaddress.ip_address(data[8:24]), ipaddress.ip_address(data[24:40])))
        protocol, payload = data[6], data[40:min(total, len(data))]
        partial = total > len(data)
        for _ in range(8):
            if protocol not in (0, 43, 44, 60, 51):
                break
            if len(payload) < 8:
                return None
            if protocol == 44:
                if struct.unpack("!H", payload[2:4])[0] & 0xfff8:
                    return None
                length = 8; partial = True
            else:
                length = (payload[1] + (2 if protocol == 51 else 1)) * (4 if protocol == 51 else 8)
            protocol, payload = payload[0], payload[length:]
    else:
        return None
    ports, flags = (0, 0), 0
    if protocol in (6, 17):
        if len(payload) < (20 if protocol == 6 else 8):
            return None
        ports = struct.unpack("!HH", payload[:4])
        if protocol == 6:
            flags = payload[13]
    return {"src_ip": src, "dst_ip": dst, "src_port": ports[0], "dst_port": ports[1],
            "protocol": protocol, "byte_count": total, "flags": flags, "partial": partial}


def capture_packets(data):
    reader = Cursor(data)
    magic = reader.take(4)
    if magic != b"\x0a\x0d\x0d\x0a":
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
                   b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
        if magic not in formats:
            raise InputError("Not a PCAP or PCAPNG capture")
        endian, resolution = formats[magic]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", reader.take(20))
        if (major, minor) != (2, 4) or not snaplen:
            raise InputError("Unsupported PCAP header")
        for index in range(MAX_PACKETS + 1):
            if reader.offset == len(data):
                return
            if index == MAX_PACKETS:
                raise InputError("At most 100000 captured packets per input")
            seconds, fraction, included, original = struct.unpack(endian + "IIII", reader.take(16))
            if included > original or included > snaplen or fraction >= resolution:
                raise InputError("Invalid PCAP packet header")
            yield seconds + fraction / resolution, reader.take(included), linktype
        return
    # PCAPNG sections may change byte order and interface definitions.
    reader.offset = 0; endian, interfaces = None, []
    count = 0
    while reader.offset < len(data):
        start = reader.offset; header = reader.take(8)
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            bom = reader.take(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
            if endian is None:
                raise InputError("Invalid PCAPNG byte order")
            reader.offset = start + 8; interfaces = []
        if endian is None:
            raise InputError("PCAPNG section header is required")
        kind, length = struct.unpack(endian + "II", header)
        if length < 12 or length % 4:
            raise InputError("Invalid PCAPNG block length")
        body = reader.take(length - 12)
        if struct.unpack(endian + "I", reader.take(4))[0] != length:
            raise InputError("PCAPNG block lengths disagree")
        if kind == 0x0a0d0d0a:
            if len(body) < 16 or struct.unpack(endian + "H", body[4:6])[0] != 1:
                raise InputError("Unsupported PCAPNG section")
        elif kind == 1:
            if len(body) < 8:
                raise InputError("Truncated PCAPNG interface")
            linktype, _, snaplen = struct.unpack(endian + "HHI", body[:8]); resolution, offset = 1e6, 0
            options = Cursor(body[8:])
            while options.offset < len(options.data):
                code, size = struct.unpack(endian + "HH", options.take(4))
                value = options.take(size); options.take((-size) % 4)
                if code == 0:
                    break
                if code == 9 and size == 1:
                    exponent = value[0] & 127
                    if exponent > 30:
                        raise InputError("Unsupported timestamp resolution")
                    resolution = (2 if value[0] & 128 else 10)**exponent
                if code == 14 and size == 8:
                    offset = struct.unpack(endian + "q", value)[0]
            interfaces.append((linktype, resolution, offset, snaplen))
        elif kind == 6:
            if len(body) < 20:
                raise InputError("Truncated enhanced packet block")
            interface, high, low, included, original = struct.unpack(endian + "IIIII", body[:20])
            if interface >= len(interfaces) or included > original or len(body) < 20 + ((included + 3) // 4 * 4):
                raise InputError("Invalid PCAPNG packet block")
            linktype, resolution, offset, snaplen = interfaces[interface]
            if snaplen and included > snaplen:
                raise InputError("Packet exceeds PCAPNG snap length")
            count += 1
            if count > MAX_PACKETS:
                raise InputError("At most 100000 captured packets per input")
            yield ((high << 32) | low) / resolution + offset, body[20:20 + included], linktype
        elif kind in (2, 3):
            raise InputError("Legacy/simple PCAPNG packet blocks lack supported timing; use enhanced packet blocks")


def decode_capture(data):
    flows, skipped = {}, 0
    for timestamp, raw, linktype in capture_packets(data):
        packet = packet_metadata(raw, linktype)
        if packet is None:
            skipped += 1; continue
        key = tuple(packet[field] for field in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol"))
        if key not in flows:
            if len(flows) >= MAX_RECORDS:
                raise InputError("Capture exceeds 10000 directional flows")
            flows[key] = {**packet, "times": [], "packet_count": 0, "byte_count": 0, "syn_count": 0, "ack_count": 0, "partial_packets": 0}
        flow = flows[key]; flow["times"].append(timestamp); flow["packet_count"] += 1
        flow["byte_count"] += packet["byte_count"]; flow["syn_count"] += bool(packet["flags"] & 2)
        flow["ack_count"] += bool(packet["flags"] & 16); flow["partial_packets"] += packet["partial"]
    observations = []
    for key, flow in flows.items():
        times = sorted(flow.pop("times")); gaps = [b - a for a, b in zip(times, times[1:])]
        features = {name: flow[name] for name in ("syn_count", "ack_count", "partial_packets")}
        if gaps:
            features["iat_mean_seconds"] = statistics.mean(gaps)
            features["iat_std_seconds"] = statistics.pstdev(gaps)
            if features["iat_mean_seconds"] > 0:
                features["iat_cv"] = features["iat_std_seconds"] / features["iat_mean_seconds"]
        reverse = (key[1], key[0], key[3], key[2], key[4])
        features["reverse_observed_in_input"] = reverse in flows
        observations.append(normalize({**flow, "timestamp": times[0], "duration_seconds": times[-1] - times[0], "features": features}))
    if not observations:
        raise InputError("No supported IP packets found in the capture")
    return observations, ([f"Skipped {skipped} non-IP, noninitial fragment, or unsupported/truncated packets"] if skipped else [])


def decode(data, kind, decoder=None, exporter="upload"):
    if not data or len(data) > MAX_BYTES:
        raise InputError("Input must contain 1 byte to 10 MiB")
    if kind in ("pcap", "pcapng"):
        return decode_capture(data)
    if kind in ("flow-json", "flow-csv", "metadata"):
        return decode_text(data, kind)
    if kind in ("netflow", "ipfix", "sflow"):
        return (decoder or ExportDecoder()).decode(data, kind, exporter)
    raise InputError("Unsupported input format")


class ExportDecoder:
    """Bounded passive template cache; never requests templates from exporters."""
    def __init__(self):
        self.templates = {}

    def decode(self, data, kind, exporter):
        if kind == "sflow":
            return self.sflow(data)
        if len(data) < 2:
            raise InputError("Truncated flow export")
        version = struct.unpack("!H", data[:2])[0]
        if kind == "netflow" and version == 5:
            return self.v5(data)
        if version not in (9, 10) or (kind == "ipfix" and version != 10):
            raise InputError("Supported binary exports: NetFlow v5/v9, IPFIX v10, sFlow v5")
        records, notes, offset = [], [], 0
        now = time.monotonic()
        self.templates = {key: value for key, value in self.templates.items() if now - value[1] < 1800}
        while offset < len(data):
            header_size = 20 if version == 9 else 16
            if len(data) - offset < header_size:
                raise InputError("Truncated export header")
            if version == 9:
                _, _, uptime, seconds, _, domain = struct.unpack("!HHIIII", data[offset:offset + 20])
                size = len(data) - offset
            else:
                current, size, seconds, _, domain = struct.unpack("!HHIII", data[offset:offset + 16])
                uptime = None
                if current != 10 or size < 16 or size > len(data) - offset:
                    raise InputError("Invalid IPFIX message length")
            cursor = Cursor(data[offset + header_size:offset + size])
            while cursor.offset < len(cursor.data):
                set_id, length = struct.unpack("!HH", cursor.take(4))
                if length < 4:
                    raise InputError("Invalid flow set length")
                body = cursor.take(length - 4)
                if set_id == (0 if version == 9 else 2):
                    templates = Cursor(body)
                    while templates.offset < len(body):
                        if len(body) - templates.offset <= 3 and not any(body[templates.offset:]):
                            break
                        template_id, count = struct.unpack("!HH", templates.take(4))
                        if template_id < 256 or count > 100:
                            raise InputError("Invalid export template")
                        key = (exporter, version, domain, template_id)
                        if count == 0:
                            self.templates.pop(key, None); continue
                        fields = []
                        for _ in range(count):
                            field, field_length = struct.unpack("!HH", templates.take(4))
                            enterprise = struct.unpack("!I", templates.take(4))[0] if version == 10 and field & 0x8000 else 0
                            if field_length == 0:
                                raise InputError("Zero-length template field")
                            fields.append((field & 0x7fff if version == 10 else field, field_length, enterprise))
                        if key not in self.templates and len(self.templates) >= 256:
                            self.templates.pop(next(iter(self.templates)))
                        self.templates[key] = (fields, now)
                elif set_id in (1, 3):
                    notes.append("Options templates/records are not interpreted as traffic flows")
                elif set_id >= 256:
                    key = (exporter, version, domain, set_id)
                    template = self.templates.get(key)
                    if template is None:
                        notes.append(f"Data set {set_id} has no passively received template; no exporter query was sent")
                        continue
                    fields, _ = template; values = Cursor(body)
                    minimum = sum(1 if length == 65535 else length for _, length, _ in fields)
                    while len(body) - values.offset >= minimum:
                        fields_data = {}
                        for field, field_length, enterprise in fields:
                            if field_length == 65535:
                                field_length = values.take(1)[0]
                                if field_length == 255:
                                    field_length = struct.unpack("!H", values.take(2))[0]
                            value = values.take(field_length)
                            if not enterprise:
                                fields_data[field] = value
                        observation = self.fields(fields_data, seconds, uptime)
                        if observation is not None:
                            records.append(observation)
                        if len(records) > MAX_RECORDS:
                            raise InputError("Too many flow records")
                    if any(body[values.offset:]):
                        raise InputError("Truncated export data record")
            offset += size
        if not records and not notes:
            notes.append("No compatible directional five-tuple records decoded; raw bytes retained")
        return records, list(dict.fromkeys(notes))

    @staticmethod
    def fields(fields, seconds, uptime):
        mapping = {1: "byte_count", 2: "packet_count", 4: "protocol", 7: "src_port", 11: "dst_port"}
        row = {name: int.from_bytes(fields[field], "big") for field, name in mapping.items() if field in fields}
        for field, name, length in ((8, "src_ip", 4), (12, "dst_ip", 4), (27, "src_ip", 16), (28, "dst_ip", 16)):
            if field in fields:
                if len(fields[field]) != length:
                    raise InputError("Invalid exported IP address length")
                row[name] = str(ipaddress.ip_address(fields[field]))
        if any(key not in row for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")):
            return None
        start, end = None, None
        if 152 in fields:
            start = int.from_bytes(fields[152], "big") / 1000
        elif 150 in fields:
            start = int.from_bytes(fields[150], "big")
        elif 22 in fields and uptime is not None:
            start = seconds - ((uptime - int.from_bytes(fields[22], "big")) % 2**32) / 1000
        if 153 in fields:
            end = int.from_bytes(fields[153], "big") / 1000
        elif 151 in fields:
            end = int.from_bytes(fields[151], "big")
        elif 21 in fields and uptime is not None:
            end = seconds - ((uptime - int.from_bytes(fields[21], "big")) % 2**32) / 1000
        if start is not None:
            row["timestamp"] = start
        if start is not None and end is not None:
            row["duration_seconds"] = end - start
        row["features"] = {"tcp_flags": int.from_bytes(fields[6], "big")} if 6 in fields else {}
        if 34 in fields:
            row["sampling_rate"] = int.from_bytes(fields[34], "big")
            row["sampled"] = row["sampling_rate"] > 1
        # If exporter timing is missing, use its export timestamp, explicitly
        # identified as export time rather than the beginning of the flow.
        if start is None:
            row["timestamp"] = seconds; row["features"]["timestamp_is_export_time"] = True
        return normalize(row)

    @staticmethod
    def v5(data):
        if len(data) < 24:
            raise InputError("Truncated NetFlow v5 header")
        _, count, uptime, seconds, nanoseconds, _, _, _, sampling = struct.unpack("!HHIIIIBBH", data[:24])
        if count > MAX_RECORDS or len(data) != 24 + count * 48 or nanoseconds >= 1e9:
            raise InputError("Invalid NetFlow v5 record count/length")
        rows = []
        for index in range(count):
            raw = data[24 + index * 48:72 + index * 48]
            first, last = struct.unpack("!II", raw[24:32])
            timestamp = seconds + nanoseconds / 1e9 - ((uptime - first) % 2**32) / 1000
            duration = ((last - first) % 2**32) / 1000
            rows.append(normalize({"src_ip": str(ipaddress.ip_address(raw[:4])), "dst_ip": str(ipaddress.ip_address(raw[4:8])),
                                   "src_port": struct.unpack("!H", raw[32:34])[0], "dst_port": struct.unpack("!H", raw[34:36])[0],
                                   "protocol": raw[38], "packet_count": struct.unpack("!I", raw[16:20])[0],
                                   "byte_count": struct.unpack("!I", raw[20:24])[0], "timestamp": timestamp,
                                   "duration_seconds": duration, "features": {"tcp_flags": raw[37]},
                                   "sampling_rate": sampling & 0x3fff or None, "sampled": bool(sampling & 0xc000)}))
        return rows, []

    @staticmethod
    def sflow(data):
        cursor = Cursor(data)
        if cursor.u32() != 5:
            raise InputError("Only sFlow v5 is supported")
        address_type = cursor.u32()
        if address_type not in (1, 2):
            raise InputError("Invalid sFlow agent address")
        cursor.take(4 if address_type == 1 else 16); cursor.take(12)
        samples = cursor.u32()
        if samples > MAX_RECORDS:
            raise InputError("Too many sFlow samples")
        rows, notes = [], []
        observed_at = datetime.now(timezone.utc).isoformat()
        for _ in range(samples):
            tag, length = cursor.u32(), cursor.u32(); sample = Cursor(cursor.take(length))
            enterprise, kind = tag >> 12, tag & 4095
            if enterprise or kind not in (1, 3):
                notes.append("sFlow counter/enterprise samples are retained only in the raw input, not treated as flows"); continue
            sample.take(8 if kind == 1 else 12); sampling = sample.u32()
            sample.take(16 if kind == 1 else 24); count = sample.u32()
            if count > 1000:
                raise InputError("Too many sFlow records in a sample")
            for _ in range(count):
                record_tag, size = sample.u32(), sample.u32(); record = Cursor(sample.take(size))
                if record_tag >> 12:
                    continue
                packet = None
                if record_tag == 1:
                    protocol, frame_length, _, header_length = record.u32(), record.u32(), record.u32(), record.u32()
                    header = record.take(header_length)
                    if protocol in (1, 11, 12):
                        packet = packet_metadata(header, 1 if protocol == 1 else 101)
                        if packet:
                            packet["features"] = {"sampled_frame_bytes": frame_length}
                elif record_tag in (3, 4):
                    frame_length, protocol = record.u32(), record.u32(); width = 4 if record_tag == 3 else 16
                    src, dst = str(ipaddress.ip_address(record.take(width))), str(ipaddress.ip_address(record.take(width)))
                    src_port, dst_port, flags, _ = record.u32(), record.u32(), record.u32(), record.u32()
                    packet = {"src_ip": src, "dst_ip": dst, "src_port": src_port, "dst_port": dst_port,
                              "protocol": protocol, "byte_count": frame_length, "features": {"tcp_flags": flags}}
                if packet:
                    packet.update(timestamp=observed_at, packet_count=1, sampled=True, sampling_rate=sampling)
                    packet.setdefault("features", {})["timestamp_is_receipt_time"] = True
                    rows.append(normalize(packet))
                    if len(rows) > MAX_RECORDS:
                        raise InputError("Too many sFlow records")
        if cursor.offset != len(data):
            raise InputError("Trailing bytes after sFlow datagram")
        return rows, list(dict.fromkeys(notes))
