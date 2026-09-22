"""Certificate graph construction and whole-graph path building.

Nodes are distinct DER certificates (identified by SHA-256). Edges link a
child to every certificate that can issuer-name/key identify itself as the
child's issuer and whose real signature verifies. Cross-signs, duplicates and
cycles are native to the graph; path search never collapses it to a single
shortest chain before revocation checking.
"""
from __future__ import annotations

import dataclasses

from cryptography.exceptions import InvalidSignature

from . import certmodel
from .certmodel import ParsedCert, verify_cert_signature


@dataclasses.dataclass
class Edge:
    child: str
    issuer: str
    # Intrinsic edge checks (path independent).
    sig_ok: bool
    sig_rule: str | None
    name_key_ok: bool


class CertGraph:
    def __init__(self, certs: dict[str, ParsedCert]):
        self.certs = certs
        # subject name DER -> fingerprints
        self.by_name: dict[bytes, list[str]] = {}
        # (name, key bytes) -> fingerprints
        self.by_name_key: dict[tuple[bytes, bytes], list[str]] = {}
        for fp, pc in certs.items():
            self.by_name.setdefault(pc.subject_der, []).append(fp)
            self.by_name_key.setdefault(
                (pc.subject_der, pc.spki_bitstring), []).append(fp)
        for v in self.by_name.values():
            v.sort()
        for v in self.by_name_key.values():
            v.sort()
        self._edge_cache: dict[tuple[str, str], Edge] = {}

    def by_issuer(self, name_der: bytes, aki: bytes | None) -> list[ParsedCert]:
        out: list[ParsedCert] = []
        for fp in self.by_name.get(name_der, []):
            pc = self.certs[fp]
            if aki is not None and pc.ski is not None and pc.ski != aki:
                continue
            out.append(pc)
        return out

    def edge(self, child_fp: str, issuer_fp: str) -> Edge:
        key = (child_fp, issuer_fp)
        cached = self._edge_cache.get(key)
        if cached is not None:
            return cached
        child = self.certs[child_fp]
        issuer = self.certs[issuer_fp]
        name_key_ok = (
            child.issuer_der == issuer.subject_der
            and (child.aki is None or issuer.ski is None
                 or child.aki == issuer.ski)
        )
        if not name_key_ok:
            e = Edge(child_fp, issuer_fp, False, "ISSUER_NAME_KEY", False)
        else:
            ok, rule = verify_cert_signature(child, issuer)
            e = Edge(child_fp, issuer_fp, ok, rule, True)
        self._edge_cache[key] = e
        return e

    def candidate_issuers(self, child_fp: str) -> list[str]:
        """Name/key-compatible issuers, signature not necessarily valid yet."""
        child = self.certs[child_fp]
        return list(self.by_name.get(child.issuer_der, []))

    def get_cert(self, fp: str) -> ParsedCert | None:
        return self.certs.get(fp)
