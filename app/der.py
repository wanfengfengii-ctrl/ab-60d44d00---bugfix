"""Minimal DER helpers for extensions the cryptography library exposes only
as raw OCTET STRING values (notably policyMappings) and for stable identity
material (raw SubjectPublicKeyInfo, RDNSequence bytes, key identifier)."""
from __future__ import annotations

from .errors import MalformedEvidenceError

# Tag / class constants
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
UTF8_STRING = 0x0C
SEQUENCE = 0x30
SET = 0x31


def _read_len(data: bytes, i: int) -> tuple[int, int]:
    b = data[i]
    i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7F
    if n == 0 or n > 4 or i + n > len(data):
        raise MalformedEvidenceError("DER: invalid length")
    length = 0
    for _ in range(n):
        length = (length << 8) | data[i]
        i += 1
    return length, i


def tlv(data: bytes, i: int = 0) -> tuple[int, bytes, int]:
    """Return (tag, value_bytes, next_index) for one DER TLV."""
    if i >= len(data):
        raise MalformedEvidenceError("DER: unexpected end")
    tag = data[i]
    length, j = _read_len(data, i + 1)
    if j + length > len(data):
        raise MalformedEvidenceError("DER: value overruns buffer")
    return tag, data[j:j + length], j + length


def iter_tlv(value: bytes):
    i = 0
    while i < len(value):
        tag, val, i = tlv(value, i)
        yield tag, val


def encode_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def build_tlv(tag: int, value: bytes = b"") -> bytes:
    return bytes([tag]) + encode_len(len(value)) + value


def decode_oid(data: bytes) -> str:
    if not data:
        raise MalformedEvidenceError("DER: empty OID")
    first = data[0]
    if first < 40:
        parts = ["0", str(first)]
    elif first < 80:
        parts = ["1", str(first - 40)]
    else:
        parts = ["2", str(first - 80)]
    v = 0
    for idx, b in enumerate(data[1:]):
        v = (v << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(v))
            v = 0
        elif idx == len(data) - 2:
            raise MalformedEvidenceError("DER: truncated OID")
    return ".".join(parts)


def parse_policy_mappings(ext_value: bytes) -> list[tuple[str, str]]:
    """PolicyMappings ::= SEQUENCE OF SEQUENCE { issuerDomainPolicy OID,
                                                  subjectDomainPolicy OID }
    ``ext_value`` is the extension OCTET STRING payload (the inner SEQUENCE)."""
    tag, seq, _ = tlv(ext_value)
    if tag != SEQUENCE:
        raise MalformedEvidenceError("policyMappings: expected SEQUENCE")
    mappings: list[tuple[str, str]] = []
    for _, mval in iter_tlv(seq):
        oids = []
        for t2, o in iter_tlv(mval):
            if t2 != OID:
                raise MalformedEvidenceError("policyMappings: expected OID")
            oids.append(decode_oid(o))
        if len(oids) != 2:
            raise MalformedEvidenceError("policyMappings: expected 2 OIDs")
        mappings.append((oids[0], oids[1]))
    return mappings
