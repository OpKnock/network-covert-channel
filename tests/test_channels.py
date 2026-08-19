from covert import (
    dns_decode,
    dns_encode,
    encode_on_all,
    http_decode,
    http_decode_multi,
    http_encode,
    http_encode_multi,
    icmp_decode,
    icmp_encode,
)
from covert.channels import _icmp_checksum, _icmp_checksum_valid

PAYLOAD = b"top secret: launch codes are 1234"


def test_dns_roundtrip():
    query = dns_encode(PAYLOAD)
    assert query.endswith(".example.com")
    assert dns_decode(query) == PAYLOAD


def test_dns_decode_plain():
    assert dns_decode("www.example.com") is None


def test_dns_oversize():
    try:
        dns_encode(b"A" * 2000)
        assert False, "should raise"
    except ValueError:
        pass


def test_icmp_roundtrip():
    packet = icmp_encode(PAYLOAD, ident=0xABCD)
    assert icmp_decode(packet) == PAYLOAD
    assert _icmp_checksum_valid(packet)


def test_icmp_no_marker():
    assert icmp_decode(b"\x08\x00\x00\x00\x12\x34\x00\x01plain") is None


def test_icmp_short():
    assert icmp_decode(b"\x08\x00") is None


def test_http_roundtrip():
    header, value = http_encode(PAYLOAD)
    assert header == "X-Cache"
    headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" + header + ": " + value + "\r\n"
    assert http_decode(headers) == PAYLOAD


def test_http_no_secret():
    assert http_decode("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n") is None


def test_http_multi_roundtrip():
    chunks = http_encode_multi(PAYLOAD, num_chunks=4)
    lines = [f"X-Cache-Part: {v}" for _, v in chunks]
    assert http_decode_multi(lines) == PAYLOAD


def test_encode_on_all():
    msgs = encode_on_all(PAYLOAD)
    assert len(msgs) == 4
    for m in msgs:
        assert m.decode() == PAYLOAD
