"""Materialize a sealed evidence set into lazily parsed indexes.

Certificates are parsed on first access (the acceptance load has 100k certs
but adjudicates a handful of leaves); revocation objects are parsed eagerly
(max 2,000) since the limits make that cheap and they are always needed for
evidence logging.
"""
from __future__ import annotations

from . import evidence as ev
from .certmodel import ParsedCert, parse_certificate
from .errors import MalformedEvidenceError, UnsupportedError
from .graph import CertGraph


class LoadedSet:
    def __init__(self, store, manifest: dict):
        self.store = store
        self.manifest = manifest
        self.content = manifest["content"]
        self._parsed: dict[str, ParsedCert] = {}
        self.crls: dict[str, ev.CrlObject] = {}
        self.ocsps: dict[str, ev.OcspObject] = {}
        self.parse_problems: list[dict] = []

    @classmethod
    def from_store(cls, store, manifest: dict) -> "LoadedSet":
        return cls(store, manifest)

    def get_blob(self, digest: str) -> bytes:
        return self.store.get_blob(digest)

    # -------------------------------------------------------- certificates
    def cert(self, digest: str) -> ParsedCert | None:
        if digest in self._parsed:
            return self._parsed[digest]
        try:
            data = self.get_blob(digest)
            pc = parse_certificate(data)
        except (UnsupportedError, MalformedEvidenceError) as exc:
            self._parsed[digest] = None  # type: ignore[assignment]
            self.parse_problems.append({
                "sha256": digest, "kind": "certificate",
                "code": exc.code, "message": exc.message, "detail": exc.detail})
            return None
        self._parsed[digest] = pc
        return pc

    def all_cert_digests(self) -> list[str]:
        return list(self.content["certificates"])

    def build_graph(self, anchor_digests: set[str]) -> CertGraph:
        """Parse only anchor certs eagerly; everything else stays lazy."""
        certs: dict[str, ParsedCert] = {}
        for d in anchor_digests:
            pc = self.cert(d)
            if pc is not None:
                certs[d] = pc

        class LazyGraph(CertGraph):
            def __init__(self_inner, loader, anchor_ds):
                self_inner.loader = loader
                self_inner.anchor_ds = anchor_ds
                self_inner.certs = certs
                self_inner.by_name = {}
                self_inner.by_name_key = {}
                self_inner._edge_cache = {}

            def _materialize(self_inner, digest: str) -> ParsedCert | None:
                if digest in self_inner.certs:
                    return self_inner.certs[digest]
                pc = self_inner.loader.cert(digest)
                if pc is None:
                    return None
                self_inner.certs[digest] = pc
                self_inner.by_name.setdefault(pc.subject_der, []).append(digest)
                self_inner.by_name_key.setdefault(
                    (pc.subject_der, pc.spki_bitstring), []).append(digest)
                return pc

            def get_cert(self_inner, digest: str) -> ParsedCert | None:
                return self_inner._materialize(digest)

        graph = LazyGraph(self, anchor_digests)

        # Override candidate lookup to lazily parse: find certs whose SUBJECT
        # equals child's issuer DN. That needs an index by subject name, so we
        # build name buckets from raw DER cheaply using cached ParsedCert where
        # available, parsing only issuers reachable by name. To find issuers by
        # name without parsing all certificates, maintain a precomputed name
        # index (built during ingestion; see store detail). Fallback: parse all
        # when the index is absent (older stores).
        index = self._subject_name_index()
        graph._subject_index = index

        def candidate_issuers(child_fp: str) -> list[str]:
            child = graph.certs.get(child_fp) or self.cert(child_fp)
            if child is None:
                return []
            digests = index.get(child.issuer_der, [])
            out = []
            for d in digests:
                pc = graph._materialize(d)
                if pc is not None:
                    out.append(d)
            return sorted(out)

        graph.candidate_issuers = candidate_issuers  # type: ignore[assignment]

        # by_issuer used by revocation engine: resolve by name + AKI.
        def by_issuer(name_der, aki):
            res = []
            for d in index.get(name_der, []):
                pc = graph._materialize(d)
                if pc is None:
                    continue
                if aki is not None and pc.ski is not None and pc.ski != aki:
                    continue
                res.append(pc)
            return res

        graph.by_issuer = by_issuer  # type: ignore[assignment]
        return graph

    def _subject_name_index(self) -> dict[bytes, list[str]]:
        """Use the cheap index materialized at seal time (raw Name DER keys,
        base64 encoded in the sidecar file)."""
        import base64
        import json
        import os

        cached = getattr(self, "_name_idx", None)
        if cached is not None:
            return cached
        idx_path = self._name_index_path()
        idx: dict[bytes, list[str]] = {}
        if os.path.exists(idx_path):
            with open(idx_path) as f:
                raw_index = json.load(f)
            for name_b64, digests in raw_index.items():
                idx[base64.b64decode(name_b64)] = digests
        else:
            # Slow fallback for stores sealed before sidecars existed.
            for d in self.content["certificates"]:
                pc = self.cert(d)
                if pc is not None:
                    idx.setdefault(pc.subject_der, []).append(d)
        self._name_idx = idx
        return idx

    def _name_index_path(self) -> str:
        import os

        return os.path.join(self.store.root, "packages",
                            f"{self.manifest['evidence_set_id']}.nameindex.json")

    # --------------------------------------------------------- revocation
    def load_revocation(self) -> None:
        # Identical bytes archived multiple times: evidence is possessed at
        # the earliest recorded received_at.
        def _earliest(items):
            m: dict[str, int] = {}
            for item in items:
                d, r = item["sha256"], item["received_at"]
                m[d] = r if d not in m else min(m[d], r)
            return m
        for digest, received_at in _earliest(self.content["crls"]).items():
            try:
                raw = self.get_blob(digest)
                self.crls[digest] = ev.parse_crl(raw, received_at)
            except (UnsupportedError, MalformedEvidenceError) as exc:
                self.parse_problems.append({
                    "sha256": digest, "kind": "crl",
                    "code": exc.code, "message": exc.message, "detail": exc.detail})
        for digest, received_at in _earliest(self.content["ocsps"]).items():
            try:
                raw = self.get_blob(digest)
                self.ocsps[digest] = ev.parse_ocsp(raw, received_at)
            except (UnsupportedError, MalformedEvidenceError) as exc:
                self.parse_problems.append({
                    "sha256": digest, "kind": "ocsp",
                    "code": exc.code, "message": exc.message, "detail": exc.detail})
