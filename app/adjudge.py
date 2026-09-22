"""Adjudication orchestration (storage-independent core).

``run_core`` takes a blob-backed :class:`~app.loader.LoadedSet`, the sealed
manifest and the *raw* request, and deterministically produces the result.
The HTTP layer wraps it with persistence/idempotency; the offline verifier
re-runs the same core against the package ZIP with no database or network.
"""
from __future__ import annotations

import re

from . import canonical
from .certmodel import verify_artifact_signature, verify_cert_signature
from .errors import ConflictError, MalformedEvidenceError, UnsupportedError
from .loader import LoadedSet
from .pathfinder import PathFinder
from .revocation import RevocationEngine
from .timeutil import parse_time

OID_RE = re.compile(r"^(\d+)(\.\d+)*$")
PROFILE_VERSION = "rfc5280-forensic-profile-v1"


def _b64_or_hex(value: str, field: str) -> bytes:
    import base64
    import binascii

    if not isinstance(value, str):
        raise MalformedEvidenceError(f"{field}: must be a string")
    s = value.strip()
    try:
        if re.fullmatch(r"[0-9a-fA-F]*", s) and len(s) % 2 == 0:
            return bytes.fromhex(s)
        return base64.b64decode(s, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise MalformedEvidenceError(f"{field}: not hex or base64") from exc


def normalize_request(body: dict) -> dict:
    required = ["artifact_digest", "signature", "signature_algorithm",
                "signed_at", "knowledge_cutoff", "leaf_certificate_sha256",
                "initial_policies", "trust_anchors"]
    for k in required:
        if k not in body:
            raise MalformedEvidenceError(f"missing field: {k}")
    digest = _b64_or_hex(body["artifact_digest"], "artifact_digest")
    signature = _b64_or_hex(body["signature"], "signature")
    alg = body["signature_algorithm"]
    if not isinstance(alg, str) or not OID_RE.fullmatch(alg):
        raise MalformedEvidenceError("signature_algorithm: must be an OID dotted string")
    signed_at = parse_time(body["signed_at"], "signed_at")
    cutoff = parse_time(body["knowledge_cutoff"], "knowledge_cutoff")
    leaf = body["leaf_certificate_sha256"]
    if not isinstance(leaf, str) or not re.fullmatch(r"[0-9a-f]{64}", leaf):
        raise MalformedEvidenceError("leaf_certificate_sha256: expected 64 hex chars")
    policies = body["initial_policies"]
    if not isinstance(policies, list) or not policies:
        raise MalformedEvidenceError("initial_policies: non-empty list of OIDs required")
    for p in policies:
        if not isinstance(p, str) or not OID_RE.fullmatch(p):
            raise MalformedEvidenceError(f"initial_policies: bad OID {p!r}")
    anchors = body["trust_anchors"]
    if not isinstance(anchors, list) or not anchors:
        raise MalformedEvidenceError("trust_anchors: non-empty list required")
    anchor_norm = []
    for a in anchors:
        fp = a if isinstance(a, str) else a.get("sha256") if isinstance(a, dict) else None
        if not fp or not re.fullmatch(r"[0-9a-f]{64}", fp):
            raise MalformedEvidenceError("trust_anchors entries: 64 hex chars")
        anchor_norm.append(fp)
    return {
        "artifact_digest_hex": digest.hex(),
        "artifact_digest_bytes": len(digest),
        "signature_hex": signature.hex(),
        "signature_algorithm": alg,
        "signed_at_epoch": signed_at,
        "signed_at": _z(signed_at),
        "knowledge_cutoff_epoch": cutoff,
        "knowledge_cutoff": _z(cutoff),
        "leaf_certificate_sha256": leaf,
        "initial_policies": sorted(set(policies)),
        "trust_anchors": sorted(set(anchor_norm)),
        "profile": PROFILE_VERSION,
    }


def _z(epoch: int) -> str:
    from .timeutil import format_time

    return format_time(epoch)


def _final_digest(result: dict) -> str:
    return canonical.sha256_hex({k: v for k, v in result.items() if k != "final_digest"})


def run_core(loaded: LoadedSet, manifest: dict, req: dict) -> dict:
    """Deterministic adjudication. ``req`` is already normalized."""
    request_digest = canonical.sha256_hex(req)
    set_id = manifest["evidence_set_id"]
    content_digests = set(manifest["content"]["certificates"])
    anchors = set(req["trust_anchors"])
    missing = sorted(anchors - content_digests)
    if missing:
        raise MalformedEvidenceError("trust anchor not present in sealed evidence set",
                                     {"missing": missing})
    if req["leaf_certificate_sha256"] not in content_digests:
        raise MalformedEvidenceError("leaf certificate not present in sealed evidence set")

    graph = loaded.build_graph(anchors)
    # Leaf parse/profile problems surface as structured UNSUPPORTED rather
    # than a misleading "not in evidence set".
    leaf_pc = loaded.cert(req["leaf_certificate_sha256"])
    if leaf_pc is None:
        problem = next((p for p in loaded.parse_problems
                        if p["sha256"] == req["leaf_certificate_sha256"]), None)
        if problem is not None and problem["code"] == "UNSUPPORTED":
            raise UnsupportedError("leaf certificate is outside the RFC 5280 profile",
                                   problem)
        raise MalformedEvidenceError("leaf certificate could not be parsed",
                                     problem or {"sha256": req["leaf_certificate_sha256"]})
    anchor_checks = []
    for afp in sorted(anchors):
        apc = loaded.cert(afp)
        if apc is None:
            problem = next((p for p in loaded.parse_problems if p["sha256"] == afp), None)
            raise UnsupportedError("trust anchor outside parse profile",
                                   problem or {"sha256": afp})
        ok, rule = verify_cert_signature(apc, apc)
        anchor_checks.append({"certificate": afp, "self_signature_valid": ok,
                              "rule": rule})
        if not ok:
            return _result(manifest, req, request_digest, anchor_checks, loaded,
                           early={"rule": "ANCHOR",
                                  "detail": {"anchor": afp, "rule": rule}})

    loaded.load_revocation()
    engine = RevocationEngine(
        crls=loaded.crls, ocsps=loaded.ocsps, cert_loader=graph,
        anchors_by_name_key={}, signed_at=req["signed_at_epoch"],
        cutoff=req["knowledge_cutoff_epoch"])
    finder = PathFinder(graph, anchors, engine.evaluate,
                        signed_at=req["signed_at_epoch"],
                        initial_policies=frozenset(req["initial_policies"]))
    outcome = finder.find(req["leaf_certificate_sha256"])
    return _result(manifest, req, request_digest, anchor_checks, loaded,
                   outcome=outcome, engine=engine, graph=graph)


def _result(manifest, req, request_digest, anchor_checks, loaded,
            early=None, outcome=None, engine=None, graph=None) -> dict:
    rules = [
        {"rule": "PROFILE", "ok": True, "detail": {"profile": PROFILE_VERSION}},
        {"rule": "TRUST_ANCHORS", "ok": early is None, "detail": anchor_checks},
    ]
    result = {
        "profile": PROFILE_VERSION,
        "api_version": "v1",
        "adjudication": {
            "evidence_set_id": manifest["evidence_set_id"],
            "evidence_set_content_digest": manifest["content_digest"],
            "request": req,
            "request_digest": request_digest,
        },
        "rules": rules,
        "policy_trace": [],
        "revocation_results": [],
        "revocation_snapshot": [],
        "path_search": {"explored_edges": [], "node_failures": []},
    }

    if early is not None:
        rules.append({"rule": "PATH_CONSTRUCTION", "ok": False,
                      "detail": {"status": "REJECTED", "reason": early}})
        verdict = {"status": "REJECTED", "failed_rule": early["rule"],
                   "failure": early, "selected_path": None,
                   "rejection_proof": None, "artifact_signature": None}
    elif outcome["status"] != "ACCEPTED":
        rules.append({"rule": "PATH_CONSTRUCTION", "ok": False,
                      "detail": {"status": "REJECTED", "reason": outcome["reason"]}})
        rules.append({"rule": "ARTIFACT_SIGNATURE", "ok": False,
                      "detail": {"reason": "not_evaluated_no_valid_path"}})
        if engine is not None:
            result["revocation_snapshot"] = engine.snapshot()
        verdict = {"status": "REJECTED",
                   "failed_rule": outcome["reason"]["rule"],
                   "failure": outcome["reason"], "selected_path": None,
                   "rejection_proof": outcome["rejection_proof"],
                   "artifact_signature": None}
    else:
        path = outcome["selected_path"]
        rules.append({"rule": "PATH_CONSTRUCTION", "ok": True,
                      "detail": {"status": "ACCEPTED"}})
        rules.append({"rule": "PATH_CONSTRUCTION.path", "ok": True,
                      "detail": {"path_leaf_to_root": path}})
        result["policy_trace"] = outcome["policy_trace"]
        rev_results = [engine.evaluate(graph.certs[f]) for f in path[:-1]]
        result["revocation_results"] = rev_results
        result["revocation_snapshot"] = engine.snapshot()
        result["path_search"] = {
            "explored_edges": [{"child": c, "parent": p}
                               for c, p in outcome.get("explored_edges", [])],
            "node_failures": outcome.get("node_failures", []),
        }
        leaf_pc = loaded.cert(path[0])
        art = verify_artifact_signature(
            leaf_pc.cert.public_key(),
            bytes.fromhex(req["signature_hex"]),
            bytes.fromhex(req["artifact_digest_hex"]),
            req["signature_algorithm"])
        rules.append({"rule": "ARTIFACT_SIGNATURE", "ok": bool(art.get("ok")),
                      "detail": {k: v for k, v in art.items() if k != "ok"}})
        verdict = {
            "status": "VALID" if art.get("ok") else "INVALID",
            "failed_rule": None if art.get("ok") else art.get("rule", "ARTIFACT_SIGNATURE"),
            "selected_path": path,
            "rejection_proof": None,
            "artifact_signature": {
                "valid": bool(art.get("ok")),
                "algorithm": req["signature_algorithm"],
                "failure": None if art.get("ok") else art.get("rule")},
        }

    result["verdict"] = verdict
    result["evidence_disposition"] = {"parse_rejected": loaded.parse_problems}
    result["evidence_manifest"] = {
        "evidence_set_id": manifest["evidence_set_id"],
        "content_digest": manifest["content_digest"],
        "counts": manifest["counts"],
    }
    result["summary"] = {
        "status": verdict["status"],
        "evidence_set_content_digest": manifest["content_digest"],
        "request_digest": request_digest,
    }
    result["final_digest"] = _final_digest(result)
    return result


def adjudicate(store, set_id: str, raw_request: dict) -> dict:
    """HTTP-layer entry point: sealed-set checks, replay cache, persistence."""
    import json

    set_row = store.get_set(set_id)
    if set_row["state"] != "sealed":
        raise ConflictError(f"evidence set {set_id} is not sealed")
    manifest = json.loads(set_row["manifest_json"])
    req = normalize_request(raw_request)
    request_digest = canonical.sha256_hex(req)
    existing = store.get_adjudication_by_request(set_id, request_digest)
    if existing is not None:
        return json.loads(existing["result_json"])

    loaded = LoadedSet.from_store(store, manifest)
    result = run_core(loaded, manifest, req)
    store.save_adjudication(request_digest, set_id, manifest["content_digest"],
                            request_digest, result, None)
    return result
