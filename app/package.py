"""Build the self-contained, independently re-verifiable evidence package.

Package layout (ZIP, deterministic member order, no timestamps)::

    result.json                  canonical adjudication result
    request.json                 canonical adjudication request
    manifest.json                evidence-set content summary + digest
    package-manifest.json        member inventory with SHA-256 of each DER
    der/certificates/<sha256>.der
    der/crls/<sha256>.der
    der/ocsps/<sha256>.der
"""
from __future__ import annotations

import io
import json
import zipfile

from . import canonical


def _collect_references(result: dict) -> dict[str, set[str]]:
    refs = {"certificates": set(), "crls": set(), "ocsps": set()}
    verdict = result.get("verdict") or {}
    path = verdict.get("selected_path") or []
    refs["certificates"].update(path)
    # anchors live inside the request
    for a in result["adjudication"]["request"].get("trust_anchors", []):
        refs["certificates"].add(a)
    # revocation snapshot: every piece of evidence touched during evaluation
    for rr in result.get("revocation_snapshot", []):
        sel = rr.get("selected_evidence") or {}
        if sel.get("kind") == "ocsp" and sel.get("fingerprint"):
            refs["ocsps"].add(sel["fingerprint"])
        elif sel.get("kind") == "crl":
            if sel.get("base"):
                refs["crls"].add(sel["base"])
            if sel.get("delta"):
                refs["crls"].add(sel["delta"])
        for c in rr.get("considered_evidence", []):
            refs["crls" if c["kind"] in ("crl", "delta_crl") else "ocsps"].add(
                c["fingerprint"])
    # rejection proof: include every explored node/edge certificate
    proof = verdict.get("rejection_proof")
    if proof:
        refs["certificates"].add(proof["leaf"])
        for e in proof.get("edges", []):
            refs["certificates"].add(e["child"])
            refs["certificates"].add(e["parent"])
        for nf in proof.get("node_failures", []):
            refs["certificates"].add(nf["certificate"])
    # all edges actually explored during whole-graph path search
    for e in result.get("path_search", {}).get("explored_edges", []):
        refs["certificates"].add(e["child"])
        refs["certificates"].add(e["parent"])
    for nf in result.get("path_search", {}).get("node_failures", []):
        refs["certificates"].add(nf["certificate"])
    # parse-rejected evidence is itself evidence the verifier must see
    for p in result.get("evidence_disposition", {}).get("parse_rejected", []):
        refs[{"certificate": "certificates", "crl": "crls",
              "ocsp": "ocsps"}.get(p["kind"], "certificates")].add(p["sha256"])
    return refs


def build_package(store, result: dict, set_manifest: dict | None = None) -> bytes:
    refs = _collect_references(result)
    # Every CRL/OCSP object in the sealed set is bundled (max 2,000 by policy),
    # so independent recomputation sees exactly the same evidence universe.
    if set_manifest is not None:
        for item in set_manifest["content"].get("crls", []):
            refs["crls"].add(item["sha256"])
        for item in set_manifest["content"].get("ocsps", []):
            refs["ocsps"].add(item["sha256"])
    req = result["adjudication"]["request"]
    manifest = {
        "evidence_set_id": result["adjudication"]["evidence_set_id"],
        "content_digest": result["adjudication"]["evidence_set_content_digest"],
        "counts": result["evidence_manifest"]["counts"],
        "content": set_manifest["content"] if set_manifest is not None else None,
    }
    members: list[tuple[str, bytes]] = []
    inventory = {"certificates": [], "crls": [], "ocsps": []}
    for bucket, sub in (("certificates", "certificates"),
                        ("crls", "crls"), ("ocsps", "ocsps")):
        for digest in sorted(refs[bucket]):
            try:
                data = store.get_blob(digest)
            except Exception:
                continue
            name = f"der/{sub}/{digest}.der"
            members.append((name, data))
            inventory[bucket].append(digest)
    members.sort(key=lambda m: m[0])

    result_bytes = canonical.dumps(result)
    package_manifest = {
        "format": "forensic-evidence-package/v1",
        "members": [{"name": n, "sha256": __import__("hashlib").sha256(d).hexdigest(),
                     "length": len(d)} for n, d in members],
        "result_sha256": __import__("hashlib").sha256(result_bytes).hexdigest(),
        "inventory": inventory,
    }
    fixed = [
        ("result.json", result_bytes),
        ("request.json", canonical.dumps(req)),
        ("manifest.json", canonical.dumps(manifest)),
        ("package-manifest.json", canonical.dumps(package_manifest)),
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in fixed + members:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o644 << 16)
            zf.writestr(info, data)
    return buf.getvalue()
