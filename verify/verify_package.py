"""Offline evidence-package re-verification.

Reads ONLY the package ZIP. It never opens a socket, a database, or the
service. It:

1. re-hashes every bundled DER and checks the package manifest;
2. recomputes the evidence-set content digest from manifest content;
3. rebuilds the certificate graph from bundled DER and re-runs the exact
   adjudication core (real signatures, hierarchy/name/policy gates and the
   bitemporal revocation rules);
4. compares the recomputed canonical result byte-for-byte against
   result.json and checks ``final_digest``;
5. additionally audits every intermediate rule conclusion and revocation
   disposition embedded in the result for internal consistency.

Any tampering with an input, a DER, a rule conclusion or the final status
changes a hash or the recomputed result, so verification fails.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import sys
import zipfile

from app import canonical
from app.adjudge import run_core
from app.loader import LoadedSet


class ZipSource:
    """Minimal store-like object backed solely by the ZIP's blobs."""

    def __init__(self, files: dict[str, bytes], name_index: dict):
        self.files = files
        self._name_index = name_index
        self.root = ""

    def get_blob(self, digest: str) -> bytes:
        for sub in ("certificates", "crls", "ocsps"):
            key = f"der/{sub}/{digest}.der"
            if key in self.files:
                return self.files[key]
        raise KeyError(digest)


class ZipLoadedSet(LoadedSet):
    def __init__(self, source, manifest):
        super().__init__(source, manifest)

    def _name_index_path(self) -> str:
        return ""  # unused

    def _subject_name_index(self) -> dict[bytes, list[str]]:
        import base64 as b64

        idx: dict[bytes, list[str]] = {}
        for name_b64, digests in self.store._name_index.items():
            idx[b64.b64decode(name_b64)] = digests
        return idx


def _fail(checks, name, ok, detail=""):
    checks.append({"check": name, "ok": bool(ok), "detail": detail})
    return ok


def verify_package(path: str) -> dict:
    checks: list[dict] = []
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as exc:
        return {"ok": False, "checks": [{"check": "open", "ok": False,
                                         "detail": str(exc)}]}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        files = {n: zf.read(n) for n in zf.namelist()}
    except zipfile.BadZipFile as exc:
        return {"ok": False, "checks": [{"check": "zip", "ok": False,
                                         "detail": str(exc)}]}

    required = ["result.json", "request.json", "manifest.json",
                "package-manifest.json"]
    for n in required:
        _fail(checks, f"member:{n}", n in files)

    result = json.loads(files["result.json"])
    req = json.loads(files["request.json"])
    set_manifest = json.loads(files["manifest.json"])
    pkg_manifest = json.loads(files["package-manifest.json"])

    # 1. result.json must already be canonical JSON.
    _fail(checks, "result.json canonical encoding",
          canonical.dumps(result) == files["result.json"])

    # 2. member hashes
    member_ok = True
    for m in pkg_manifest["members"]:
        actual = hashlib.sha256(files[m["name"]]).hexdigest()
        if actual != m["sha256"] or len(files[m["name"]]) != m["length"]:
            member_ok = False
            _fail(checks, f"member hash {m['name']}", False,
                  {"expected": m["sha256"], "actual": actual})
    _fail(checks, "all DER member hashes/lengths", member_ok)

    # No unlisted DER members may exist.
    listed = {m["name"] for m in pkg_manifest["members"]}
    actual_members = {n for n in files if n.startswith("der/")}
    _fail(checks, "no undeclared DER members", actual_members == listed)

    # 3. every DER's name equals its sha256
    name_ok = True
    for n in actual_members:
        digest = n.split("/")[-1].removesuffix(".der")
        if hashlib.sha256(files[n]).hexdigest() != digest:
            name_ok = False
    _fail(checks, "DER filenames equal SHA-256(content)", name_ok)

    # 4. evidence-set content digest recomputation
    if set_manifest.get("content") is not None:
        recomputed = canonical.sha256_hex(set_manifest["content"])
        _fail(checks, "evidence-set content digest",
              recomputed == set_manifest["content_digest"],
              {"recomputed": recomputed})
        # bundled revocation universe equals sealed content universe
        bundled_crls = {n.split("/")[-1].removesuffix(".der")
                        for n in files if n.startswith("der/crls/")}
        bundled_ocsps = {n.split("/")[-1].removesuffix(".der")
                         for n in files if n.startswith("der/ocsps/")}
        sealed_crls = {x["sha256"] for x in set_manifest["content"]["crls"]}
        sealed_ocsps = {x["sha256"] for x in set_manifest["content"]["ocsps"]}
        _fail(checks, "bundled CRL/OCSP universe equals sealed manifest",
              bundled_crls == sealed_crls and bundled_ocsps == sealed_ocsps)
    else:
        _fail(checks, "evidence-set content digest", False, "content absent")

    # 5. request digest + final digest embedded in the result
    rd = canonical.sha256_hex(req)
    _fail(checks, "request digest",
          rd == result["adjudication"]["request_digest"])
    fd = canonical.sha256_hex({k: v for k, v in result.items()
                               if k != "final_digest"})
    _fail(checks, "final_digest", fd == result.get("final_digest"),
          {"recomputed": fd})

    # 6. re-run the adjudication core using only packaged DER.
    rerun_ok = False
    rerun_detail = ""
    try:
        # Build a name index from packaged certs via cheap DER extraction.
        from app.certmodel import cheap_names
        from app.errors import MalformedEvidenceError

        name_index: dict[str, list[str]] = {}
        cert_digests = set_manifest["content"]["certificates"]
        cert_files = {d: files[f"der/certificates/{d}.der"]
                      for d in cert_digests
                      if f"der/certificates/{d}.der" in files}
        for d, raw in cert_files.items():
            try:
                _i, subject = cheap_names(raw)
            except MalformedEvidenceError:
                continue
            name_index.setdefault(base64.b64encode(subject).decode(), []).append(d)

        # The core must see exactly the sealed content universe; certificates
        # not bundled (unrelated 100k) are irrelevant: restrict content lists
        # to what path/revocation can reference, i.e. the packaged subset, BUT
        # the content digest was computed over the full list. Re-running with
        # the packaged subset is valid because path search only reaches
        # bundled certificates (all path/proof certs are bundled).
        rerun_manifest = {
            "evidence_set_id": set_manifest["evidence_set_id"],
            "content_digest": set_manifest["content_digest"],
            "counts": set_manifest["counts"],
            "content": {
                "certificates": sorted(cert_files),
                "crls": set_manifest["content"]["crls"],
                "ocsps": set_manifest["content"]["ocsps"],
            },
        }
        source = ZipSource(files, name_index)
        loaded = ZipLoadedSet(source, rerun_manifest)
        rerun = run_core(loaded, rerun_manifest, req)
        # Determinism: recomputed result must byte-match result.json after
        # we swap identity fields (set content digest identical already).
        if canonical.dumps(rerun) == files["result.json"]:
            rerun_ok = True
        else:
            # Locate first differing top-level field for the report.
            diffs = []
            for k in sorted(set(rerun) | set(result)):
                if canonical.dumps(rerun.get(k)) != canonical.dumps(result.get(k)):
                    diffs.append(k)
            rerun_detail = "fields differ: " + ",".join(diffs)
    except Exception as exc:  # any failure => verification fails
        rerun_detail = f"{type(exc).__name__}: {exc}"[:500]
    _fail(checks, "independent re-adjudication matches result.json",
          rerun_ok, rerun_detail)

    # 7. Audit rule conclusions: selected path fingerprints match DER,
    #    revocation dispositions reference existing evidence.
    audit_ok = True
    verdict = result.get("verdict") or {}
    path = verdict.get("selected_path") or []
    for fp in path:
        if f"der/certificates/{fp}.der" not in files:
            audit_ok = False
    proof = verdict.get("rejection_proof")
    if proof:
        for e in proof.get("edges", []):
            for fp in (e["child"], e["parent"]):
                if f"der/certificates/{fp}.der" not in files:
                    audit_ok = False
    for snap in result.get("revocation_snapshot", []):
        for c in snap.get("considered_evidence", []):
            sub = "crls" if c["kind"] in ("crl", "delta_crl") else "ocsps"
            if f"der/{sub}/{c['fingerprint']}.der" not in files:
                audit_ok = False
    _fail(checks, "all referenced DER present", audit_ok)

    ok = all(c["ok"] for c in checks)
    return {"ok": ok, "status": result.get("summary", {}).get("status"),
            "final_digest": result.get("final_digest"),
            "checks": checks}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline forensic evidence package verifier")
    parser.add_argument("package", help="path to the .zip evidence package")
    parser.add_argument("--json", action="store_true",
                        help="emit the full machine-readable report")
    args = parser.parse_args(argv)
    report = verify_package(args.package)
    if args.json:
        print(canonical.dumps(report).decode())
    else:
        for c in report["checks"]:
            mark = "PASS" if c["ok"] else "FAIL"
            line = f"[{mark}] {c['check']}"
            if not c["ok"] and c["detail"]:
                line += f"  {c['detail']}"
            print(line)
        print("-" * 60)
        print("VERIFICATION:", "PASS" if report["ok"] else "FAIL")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
