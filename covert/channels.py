from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass

CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789-"


# ---- DNS exfil (labels with steganographic bytes) ----

def _to_bytes(payload: bytes) -> bytes:
    return payload


def _b64(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _b64_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def dns_encode(payload: bytes, domain: str = "example.com", label: str = "x") -> str:
    """Encode payload into DNS subdomain labels: <label>.<b64>.<domain>"""
    b64 = _b64(payload)
    labels: list[str] = []
    while b64:
        chunk, b64 = b64[:50], b64[50:]
        labels.append(chunk)
    full = ".".join([label] + labels + [domain])
    if len(full) > 253:
        raise ValueError("encoded DNS name too long")
    return full


def dns_decode(query: str, domain: str = "example.com") -> bytes | None:
    """Extract payload from a DNS query name. Returns None if no marker."""
    q = query.rstrip(".")
    domain = domain.rstrip(".")
    if not q.endswith("." + domain):
        return None
    body = q[: -(len(domain) + 1)]
    parts = body.split(".")
    if len(parts) < 2:
        return None
    b64 = "".join(parts[1:])
    return _b64_decode(b64)


# ---- ICMP echo data ----

def icmp_encode(payload: bytes, ident: int = 0x1234, seq: int = 1) -> bytes:
    """Build a raw ICMP echo request with hidden payload in the data field."""
    data = b"COVERT:" + payload
    checksum = _icmp_checksum(8, 0, ident, seq, data)
    return struct.pack("!BBHHH", 8, 0, checksum, ident, seq) + data


def icmp_decode(packet: bytes) -> bytes | None:
    """Extract hidden payload from an ICMP packet. Returns None if absent."""
    if len(packet) < 8:
        return None
    data = packet[8:]
    marker = b"COVERT:"
    if not data.startswith(marker):
        return None
    return data[len(marker):]


def _icmp_checksum(typ: int, code: int, ident: int, seq: int, data: bytes) -> int:
    parts = [struct.pack("!BB", typ, code), struct.pack("!HH", ident, seq), data]
    raw = b"".join(parts)
    if len(raw) % 2:
        raw += b"\x00"
    total = 0
    for i in range(0, len(raw), 2):
        total += struct.unpack("!H", raw[i : i + 2])[0]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _icmp_checksum_valid(packet: bytes) -> bool:
    if len(packet) < 8:
        return False
    raw = packet
    if len(raw) % 2:
        raw = raw + b"\x00"
    total = 0
    for i in range(0, len(raw), 2):
        total += struct.unpack("!H", raw[i : i + 2])[0]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF == 0


# ---- HTTP header steganography ----

def http_encode(payload: bytes, secret_header: str = "X-Cache") -> tuple[str, str]:
    """Return (header_line, value) hiding payload in a benign-looking header."""
    b64 = _b64(payload)
    value = f"miss, cached-by={b64}"
    return secret_header, value


def http_decode(header_value: str, secret_header: str = "X-Cache") -> bytes | None:
    if header_value is None:
        return None
    for line in header_value.splitlines():
        line = line.strip()
        if line.lower().startswith(secret_header.lower() + ":"):
            value = line.split(":", 1)[1].strip()
            if "cached-by=" in value:
                return _b64_decode(value.split("cached-by=", 1)[1])
    return None


def http_encode_multi(payload: bytes, num_chunks: int = 3) -> list[tuple[str, str]]:
    """Split payload across several headers (chunked steganography)."""
    chunk = max(1, (len(payload) + num_chunks - 1) // num_chunks)
    out: list[tuple[str, str]] = []
    for i in range(0, len(payload), chunk):
        out.append(("X-Cache-Part", _b64(payload[i : i + chunk])))
    return out


def http_decode_multi(headers: list[str]) -> bytes | None:
    chunks = [_b64_decode(h.split(":", 1)[1].strip()) for h in headers if h.lower().startswith("x-cache-part:")]
    return b"".join(chunks) if chunks else None


# ---- full pipeline ----

@dataclass
class CovertMessage:
    payload: bytes
    channel: str
    encoded: object

    def decode(self) -> bytes | None:
        if self.channel == "dns":
            return dns_decode(self.encoded) if isinstance(self.encoded, str) else None
        if self.channel == "icmp":
            return icmp_decode(self.encoded) if isinstance(self.encoded, bytes) else None
        if self.channel == "http":
            return http_decode(self.encoded)
        if self.channel == "http-multi":
            return http_decode_multi(self.encoded)
        return None


def encode_on_all(payload: bytes) -> list[CovertMessage]:
    http_header, http_value = http_encode(payload)
    return [
        CovertMessage(payload, "dns", dns_encode(payload)),
        CovertMessage(payload, "icmp", icmp_encode(payload)),
        CovertMessage(payload, "http", f"{http_header}: {http_value}"),
        CovertMessage(payload, "http-multi", [f"X-Cache-Part: {v}" for _, v in http_encode_multi(payload)]),
    ]


def hash_identity(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
