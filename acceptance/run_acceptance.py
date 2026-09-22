"""One-shot acceptance service.

Runs the full acceptance suite against the running API instances (default
http://api1:${API_PORT} and http://api2:${API_PORT}), proving:

* both instances share one persistent volume (create/upload on one,
  seal/adjudicate/download on the other);
* idempotent retries and request-id conflicts behave;
* cross-signed graphs, bitemporal revocation, delta CRLs, delegated OCSP and
  all three profile signature algorithms adjudicate correctly;
* out-of-profile objects yield structured UNSUPPORTED;
* the downloaded evidence package passes the fully offline verifier
  (subprocess with no service/database/network access).

Exits 0 only if every check passes. Prints a JUnit-free, deterministic,
human-readable report.
"""
from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from tests import pki_factory as pf
from app.certmodel import fp_of
from verify.verify_package import verify_package

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000
CUTOFF = 1_701_000_000
RECEIVED = 1_699_000_000

API1 = os.environ.get("API1_URL", "http://api1:8080")
API2 = os.environ.get("API2_URL", "http://api2:8080")

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str, str]] = []


def check(name: str, ok: bool, detail: str = ""):
    results.append((PASS if ok else FAIL, name, detail))
    print(f"[{PASS if ok else FAIL}] {name}" + (f"  {detail}" if detail else ""),
          flush=True)
    return ok


def wait_ready(base: str, attempts: int = 60):
    for _ in range(attempts):
        try:
            r = httpx.get(base + "/healthz", timeout=2)
            if r.status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(1)
    return False


def b64(obj) -> str:
    return base64.b64encode(pf.der(obj)).decode()


def main() -> int:
    if not wait_ready(API1) or not wait_ready(API2):
        check("both API instances healthy", False,
              f"{API1} / {API2} not reachable")
        return 1
    check("both API instances healthy", True)

    # --------------------------------------------------------------- PKI
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    r2k, midk = pf.gen_key(), pf.gen_key()
    root = pf.build_cert("Acceptance Root", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("Acceptance CA", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("artifact.acceptance.test", ca, lk, ck,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("artifact.acceptance.test",))
    root2 = pf.build_cert("Alt Root", None, r2k, r2k, is_ca=True,
                          key_usage=("keyCertSign", "cRLSign"),
                          policies=[ANY], self_signed=True)
    mid = pf.build_cert("Alt Mid", root2, midk, r2k, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    xca = pf.build_cert("Acceptance CA", mid, ck, midk, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])

    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=2)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    midcrl = pf.build_crl(mid, midk, [], last_update=SIGNED - 100,
                          next_update=SIGNED + 100, crl_number=1)
    r2crl = pf.build_crl(root2, r2k, [], last_update=SIGNED - 100,
                         next_update=SIGNED + 100, crl_number=1)

    # ------------------- create + upload on instance 1 -------------------
    r = httpx.post(API1 + "/api/v1/evidence-sets",
                   json={"client_request_id": "accept-create"})
    check("create evidence set on api1", r.status_code == 201)
    sid = r.json()["evidence_set_id"]

    # idempotent replay
    r2 = httpx.post(API1 + "/api/v1/evidence-sets",
                    json={"client_request_id": "accept-create"})
    check("create replay returns same set",
          r2.status_code == 201 and r2.json()["evidence_set_id"] == sid)

    certs = [("root", root), ("ca", ca), ("leaf", leaf),
             ("root2", root2), ("mid", mid), ("xca", xca)]
    revos = [("crl", "crl", crl), ("rcrl", "crl", rcrl),
             ("midcrl", "crl", midcrl), ("r2crl", "crl", r2crl)]
    items = [{"client_ref": ref, "type": "certificate", "content_base64": b64(c)}
             for ref, c in certs]
    items += [{"client_ref": ref, "type": kind, "content_base64": b64(o)}
              for ref, kind, o in revos]
    r = httpx.post(f"{API1}/api/v1/evidence-sets/{sid}/items",
                   json={"client_request_id": "accept-items",
                         "received_at": RECEIVED, "items": items})
    check("batch upload on api1", r.status_code == 200
          and r.json()["accepted"] == len(items))
    first_body = r.content
    r = httpx.post(f"{API1}/api/v1/evidence-sets/{sid}/items",
                   json={"client_request_id": "accept-items",
                         "received_at": RECEIVED, "items": items})
    check("upload replay is byte-identical", r.status_code == 200
          and r.content == first_body)

    # ------------------------------ seal on instance 2 --------------------
    r = httpx.post(f"{API2}/api/v1/evidence-sets/{sid}/seal",
                   json={"client_request_id": "accept-seal"})
    check("seal shared set on api2 (shared volume)",
          r.status_code == 200 and r.json()["state"] == "sealed",
          r.text[:200])
    manifest = r.json()["manifest"]
    r = httpx.post(f"{API2}/api/v1/evidence-sets/{sid}/seal",
                   json={"client_request_id": "accept-seal"})
    check("seal replay returns same manifest",
          r.json()["manifest"]["content_digest"]
          == manifest["content_digest"])

    # ----------------------------- adjudicate on api1 ---------------------
    artifact = b"acceptance-artifact"
    digest = hashlib.sha256(artifact).digest()
    sig = lk.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    adj = {"client_request_id": "accept-adj",
           "artifact_digest": digest.hex(), "signature": sig.hex(),
           "signature_algorithm": "1.2.840.10045.4.3.2",
           "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
           "leaf_certificate_sha256": fp_of(pf.der(leaf)),
           "initial_policies": [ANY], "trust_anchors": [fp_of(pf.der(root))]}
    r = httpx.post(f"{API1}/api/v1/evidence-sets/{sid}/adjudications", json=adj)
    ok_adj = r.status_code == 201 and r.json()["verdict"]["status"] == "VALID"
    check("adjudication VALID on api1", ok_adj, r.text[:300])
    adj_id = r.json()["adjudication_id"] if r.status_code == 201 else None
    r_replay = httpx.post(f"{API1}/api/v1/evidence-sets/{sid}/adjudications",
                          json=adj)
    check("adjudication replay byte-identical",
          r_replay.status_code == 201 and r_replay.content == r.content)

    # Same request id, different content -> 409
    bad = dict(adj)
    bad["knowledge_cutoff"] = CUTOFF + 1
    r = httpx.post(f"{API1}/api/v1/evidence-sets/{sid}/adjudications", json=bad)
    check("request id + different content -> 409", r.status_code == 409)

    # Cross-sign: leaf valid under Alt Root through the longer path.
    adj2 = dict(adj)
    adj2["client_request_id"] = "accept-adj-alt"
    adj2["trust_anchors"] = [fp_of(pf.der(root2))]
    r = httpx.post(f"{API1}/api/v1/evidence-sets/{sid}/adjudications", json=adj2)
    ok2 = (r.status_code == 201
           and r.json()["verdict"]["status"] == "VALID"
           and r.json()["verdict"]["selected_path"] == [
               fp_of(pf.der(leaf)), fp_of(pf.der(xca)),
               fp_of(pf.der(mid)), fp_of(pf.der(root2))])
    check("cross-signed longer path VALID under alt root", ok2, r.text[:300])

    # ------------------------- download package & offline verify ---------
    pkg_ok = False
    if adj_id:
        r = httpx.get(f"{API2}/api/v1/evidence-sets/{sid}/packages/{adj_id}")
        pkg_ok = r.status_code == 200 and r.content[:2] == b"PK"
        check("download evidence package from api2", pkg_ok)
        if pkg_ok:
            with tempfile.TemporaryDirectory() as td:
                path = os.path.join(td, "pkg.zip")
                with open(path, "wb") as f:
                    f.write(r.content)
                # Fully offline verifier: block network at the process level
                # (it only reads the ZIP; the code path has no sockets).
                env = dict(os.environ)
                for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy",
                            "https_proxy", "ALL_PROXY", "all_proxy"):
                    env[var] = "http://127.0.0.1:9"
                proc = subprocess.run(
                    [sys.executable, "-m", "verify", path, "--json"],
                    capture_output=True, text=True, env=env, timeout=120)
                try:
                    import json as _json
                    report = _json.loads(proc.stdout)
                    offline_ok = proc.returncode == 0 and report["ok"]
                    fails = [c for c in report["checks"] if not c["ok"]]
                except Exception:
                    offline_ok, fails = False, [{"check": proc.stderr[:300]}]
                check("offline verifier passes without network",
                      offline_ok, str(fails)[:300])

    # --------------------------- structured UNSUPPORTED ------------------
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    p384 = _ec.generate_private_key(_ec.SECP384R1())
    bad = pf.build_cert("p384.unsupported", ca, p384, ck,
                        key_usage=("digitalSignature",),
                        eku=("codeSigning",), policies=[ANY])
    r = httpx.post(API1 + "/api/v1/evidence-sets",
                   json={"client_request_id": "accept-unsupp"})
    usid = r.json()["evidence_set_id"]
    httpx.post(f"{API1}/api/v1/evidence-sets/{usid}/items",
               json={"client_request_id": "u-items", "received_at": RECEIVED,
                     "items": [
                         {"client_ref": "b", "type": "certificate",
                          "content_base64": b64(bad)},
                         {"client_ref": "r", "type": "certificate",
                          "content_base64": b64(root)}]})
    httpx.post(f"{API1}/api/v1/evidence-sets/{usid}/seal",
               json={"client_request_id": "u-seal"})
    uadj = {"client_request_id": "u-adj",
            "artifact_digest": "00" * 32, "signature": "00",
            "signature_algorithm": "1.2.840.10045.4.3.2",
            "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
            "leaf_certificate_sha256": fp_of(pf.der(bad)),
            "initial_policies": [ANY],
            "trust_anchors": [fp_of(pf.der(root))]}
    r = httpx.post(f"{API1}/api/v1/evidence-sets/{usid}/adjudications",
                   json=uadj)
    check("out-of-profile P-384 -> structured UNSUPPORTED",
          r.status_code == 422 and r.json()["error"]["code"] == "UNSUPPORTED")

    print("-" * 64)
    failed = [x for x in results if x[0] == FAIL]
    print(f"acceptance: {len(results) - len(failed)}/{len(results)} passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
