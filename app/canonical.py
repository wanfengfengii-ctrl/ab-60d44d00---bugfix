"""Deterministic canonical JSON (RFC 8785 style) used for all hashing.

Rules:
* UTF-8 output;
* object keys sorted lexicographically by UTF-16 code unit (matches JCS);
* no insignificant whitespace;
* integers exact; floats rejected (the domain only uses ints/strings/bools/
  lists/dicts/None);
* strings use the minimal required JSON escapes;
* None -> null.
"""
from __future__ import annotations

import json
import struct
from typing import Any


def _sort_key(key: str):
    # JCS orders object members by UTF-16 code units; BMP chars are one unit,
    # supplementary planes are surrogate pairs. Python strings sort by
    # Unicode code point, which differs for astral chars — encode to UTF-16-LE
    # to obtain the JCS ordering.
    return key.encode("utf-16-le")


def _escape(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _emit(obj: Any) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        # Deterministic IEEE-754 double shortest-roundtrip (RFC 8785 §3.2.2.3).
        # Domain objects never carry floats; keep this conservative.
        raise TypeError("floating point values are not allowed in canonical data")
    if isinstance(obj, str):
        return _escape(obj)
    if isinstance(obj, (bytes, bytearray)):
        raise TypeError("bytes must be hex/base64 encoded before canonicalization")
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_emit(x) for x in obj) + "]"
    if isinstance(obj, dict):
        parts = []
        for k in sorted(obj.keys(), key=_sort_key):
            if not isinstance(k, str):
                raise TypeError("object keys must be strings")
            parts.append(_escape(k) + ":" + _emit(obj[k]))
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"unsupported type: {type(obj)!r}")


def dumps(obj: Any) -> bytes:
    return _emit(obj).encode("utf-8")


def sha256_hex(obj: Any) -> str:
    import hashlib

    return hashlib.sha256(dumps(obj)).hexdigest()
