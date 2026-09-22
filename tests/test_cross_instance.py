"""True cross-process concurrency: two ``python -m app.main`` instances share
one SQLite data directory, exactly like the docker-compose deployment.

These tests fire the same ``client_request_id`` at both instances at once and
assert unique ownership: identical content converges on one replayable
result; different content conflicts before any business write; no duplicate
evidence set / adjudication is ever persisted.
"""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app.certmodel import fp_of
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000
CUTOFF = 1_701_000_000
RECEIVED = 1_699_000_000


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def servers(tmp_path):
    root = str(tmp_path / "shared")
    os.makedirs(root, exist_ok=True)
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    procs, urls = [], []
    for _ in range(2):
        port = _free_port()
        env = dict(os.environ, DATA_DIR=root, API_PORT=str(port),
                   API_HOST="127.0.0.1", LOG_LEVEL="error")
        procs.append(subprocess.Popen(
            [sys.executable, "-m", "app.main"], cwd=repo, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        urls.append(f"http://127.0.0.1:{port}")
    deadline = time.time() + 30
    ready = [False, False]
    while time.time() < deadline and not all(ready):
        for i, u in enumerate(urls):
            if ready[i]:
                continue
            try:
                if httpx.get(u + "/healthz", timeout=1).status_code == 200:
                    ready[i] = True
            except httpx.HTTPError:
                pass
        time.sleep(0.2)
    if not all(ready):
        for p in procs:
            p.kill()
        pytest.fail("API instances did not become healthy")
    yield urls
    for p in procs:
        p.kill()
    for p in procs:
        p.wait(timeout=5)


def _post_all(urls, path, body):
    """POST the same body to every URL at the same instant; collect
    responses in the same order as ``urls``."""
    results: list[httpx.Response] = [None] * len(urls)  # type: ignore[list-item]
    start = threading.Barrier(len(urls))

    def hit(i, base):
        start.wait(5.0)
        results[i] = httpx.post(base + path, json=body, timeout=30)

    threads = [threading.Thread(target=hit, args=(i, u))
               for i, u in enumerate(urls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(35)
    assert not any(t.is_alive() for t in threads)
    return results


def test_concurrent_create_same_content_single_set(servers):
    body = {"client_request_id": "cc-create-same", "note": "identical"}
    rs = _post_all(servers, "/api/v1/evidence-sets", body)
    assert all(r.status_code == 201 for r in rs), [r.text for r in rs]
    ids = {r.json()["evidence_set_id"] for r in rs}
    assert len(ids) == 1
    sid = ids.pop()
    # Only the single evidence set is reachable and persisted.
    assert all(httpx.get(f"{u}/api/v1/evidence-sets/{sid}").status_code == 200
               for u in servers)


def test_concurrent_create_different_content_conflict(servers):
    rs = []
    bodies = [{"client_request_id": "cc-create-diff", "note": f"note-{i}"}
              for i in range(2)]
    start = threading.Barrier(2)

    def hit(base, body):
        start.wait(5.0)
        rs.append(httpx.post(base + "/api/v1/evidence-sets", json=body,
                             timeout=30))
    threads = [threading.Thread(target=hit, args=(servers[i], bodies[i]))
               for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(35)
    codes = sorted(r.status_code for r in rs)
    assert codes == [201, 409], [r.text for r in rs]
    winner = next(r for r in rs if r.status_code == 201)
    loser = next(r for r in rs if r.status_code == 409)
    sid = winner.json()["evidence_set_id"]
    # Replaying the winner's exact body (from either instance) returns the
    # same set; the loser's body and any third content stay conflicts.
    replay = httpx.post(servers[0] + "/api/v1/evidence-sets",
                       content=winner.request.content,
                       headers={"content-type": "application/json"})
    assert replay.status_code == 201
    assert replay.json()["evidence_set_id"] == sid
    again_loser = httpx.post(servers[0] + "/api/v1/evidence-sets",
                             content=loser.request.content,
                             headers={"content-type": "application/json"})
    assert again_loser.status_code == 409
    assert httpx.post(servers[1] + "/api/v1/evidence-sets",
                      json={"client_request_id": "cc-create-diff",
                            "note": "note-other"}).status_code == 409
    assert httpx.get(f"{servers[1]}/api/v1/evidence-sets/{sid}").status_code == 200


def _sealed_set(base, alt_base, certs, revos):
    r = httpx.post(base + "/api/v1/evidence-sets",
                   json={"client_request_id": "cc-set"})
    assert r.status_code == 201
    sid = r.json()["evidence_set_id"]
    items = [{"client_ref": ref, "type": "certificate",
              "content_base64": base64.b64encode(pf.der(c)).decode()}
             for ref, c in certs]
    items += [{"client_ref": ref, "type": kind,
               "content_base64": base64.b64encode(pf.der(o)).decode()}
              for ref, kind, o in revos]
    r = httpx.post(f"{base}/api/v1/evidence-sets/{sid}/items",
                   json={"client_request_id": "cc-items",
                         "received_at": RECEIVED, "items": items})
    assert r.status_code == 200
    r = httpx.post(f"{alt_base}/api/v1/evidence-sets/{sid}/seal",
                   json={"client_request_id": "cc-seal"})
    assert r.status_code == 200
    return sid


def test_concurrent_upload_different_content_conflict(servers):
    r = httpx.post(servers[0] + "/api/v1/evidence-sets",
                   json={"client_request_id": "cc-up-set"})
    sid = r.json()["evidence_set_id"]
    k1, k2 = pf.gen_key(), pf.gen_key()
    c1 = pf.build_cert("U1", None, k1, k1, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"),
                       policies=[ANY], self_signed=True)
    c2 = pf.build_cert("U2", None, k2, k2, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"),
                       policies=[ANY], self_signed=True)

    def body_for(cert):
        return {"client_request_id": "cc-up", "received_at": RECEIVED,
                "items": [{"client_ref": "same-ref", "type": "certificate",
                           "content_base64": base64.b64encode(
                               pf.der(cert)).decode()}]}
    rs = []
    certs = [c1, c2]
    start = threading.Barrier(2)

    def hit(base, cert):
        start.wait(5.0)
        rs.append(httpx.post(
            f"{base}/api/v1/evidence-sets/{sid}/items",
            json=body_for(cert), timeout=30))
    threads = [threading.Thread(target=hit, args=(servers[i], certs[i]))
               for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(35)
    codes = sorted(r.status_code for r in rs)
    assert codes == [200, 409], [r.text for r in rs]


def test_concurrent_adjudication_single_result(servers):
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("X Root", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("X CA", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("x.test", ca, lk, ck,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("x.test",))
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    sid = _sealed_set(servers[0], servers[1],
                      [("root", root), ("ca", ca), ("leaf", leaf)],
                      [("crl", "crl", crl), ("rcrl", "crl", rcrl)])
    digest = hashlib.sha256(b"cross-instance-artifact").digest()
    sig = lk.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    adj = {"client_request_id": "cc-adj-same",
           "artifact_digest": digest.hex(), "signature": sig.hex(),
           "signature_algorithm": "1.2.840.10045.4.3.2",
           "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
           "leaf_certificate_sha256": fp_of(pf.der(leaf)),
           "initial_policies": [ANY], "trust_anchors": [fp_of(pf.der(root))]}
    rs = _post_all(servers, f"/api/v1/evidence-sets/{sid}/adjudications", adj)
    assert all(r.status_code == 201 for r in rs), [r.text for r in rs]
    # Same business result, byte-identical, one adjudication id.
    assert rs[0].content == rs[1].content
    adj_ids = {r.json()["adjudication_id"] for r in rs}
    assert len(adj_ids) == 1
    assert rs[0].json()["verdict"]["status"] == "VALID"


def test_concurrent_adjudication_different_content_conflict(servers):
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("Y Root", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("Y CA", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("y.test", ca, lk, ck,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("y.test",))
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    sid = _sealed_set(servers[0], servers[1],
                      [("root", root), ("ca", ca), ("leaf", leaf)],
                      [("crl", "crl", crl), ("rcrl", "crl", rcrl)])

    def adj(cutoff):
        digest = hashlib.sha256(b"diff-artifact").digest()
        sig = lk.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return {"client_request_id": "cc-adj-diff",
                "artifact_digest": digest.hex(), "signature": sig.hex(),
                "signature_algorithm": "1.2.840.10045.4.3.2",
                "signed_at": SIGNED, "knowledge_cutoff": cutoff,
                "leaf_certificate_sha256": fp_of(pf.der(leaf)),
                "initial_policies": [ANY],
                "trust_anchors": [fp_of(pf.der(root))]}
    rs = []
    start = threading.Barrier(2)

    def hit(base, cutoff):
        start.wait(5.0)
        rs.append(httpx.post(
            f"{base}/api/v1/evidence-sets/{sid}/adjudications",
            json=adj(cutoff), timeout=30))
    threads = [threading.Thread(target=hit, args=(servers[0], CUTOFF)),
               threading.Thread(target=hit, args=(servers[1], CUTOFF + 1))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(35)
    codes = sorted(r.status_code for r in rs)
    assert codes == [201, 409], [r.text for r in rs]
