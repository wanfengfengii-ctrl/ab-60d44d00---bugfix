"""HTTP API integration tests (FastAPI TestClient, no network)."""
import base64
import hashlib
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app.api import create_app
from app.storage import Store
from app.certmodel import fp_of
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000
CUTOFF = 1_701_000_000
RECEIVED = 1_699_000_000


@pytest.fixture
def client(tmp_path):
    store = Store(str(tmp_path / "data"))
    app = create_app(store)
    return TestClient(app), store


def _pki():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    return rk, ck, lk, root, ca, leaf


def test_health(client):
    c, _ = client
    r = c.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_full_flow_and_idempotency(client):
    c, store = client
    rk, ck, lk, root, ca, leaf = _pki()
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)

    r = c.post("/api/v1/evidence-sets", json={"client_request_id": "create-1"})
    assert r.status_code == 201
    sid = r.json()["evidence_set_id"]
    # Replay same request id -> identical
    r2 = c.post("/api/v1/evidence-sets", json={"client_request_id": "create-1"})
    assert r2.status_code == 201 and r2.json()["evidence_set_id"] == sid

    def item(client_ref, typ, obj):
        d = pf.der(obj)
        return {"client_ref": client_ref, "type": typ,
                "content_base64": base64.b64encode(d).decode()}

    body = {"client_request_id": "items-1", "received_at": RECEIVED,
            "items": [item("root", "certificate", root),
                      item("ca", "certificate", ca),
                      item("leaf", "certificate", leaf),
                      item("crl", "crl", crl),
                      item("rcrl", "crl", rcrl)]}
    r = c.post(f"/api/v1/evidence-sets/{sid}/items", json=body)
    assert r.status_code == 200 and r.json()["accepted"] == 5
    # Replay -> same result, no duplicates
    r = c.post(f"/api/v1/evidence-sets/{sid}/items", json=body)
    assert r.status_code == 200 and r.json()["accepted"] == 5

    # Same client_ref, different content -> 409
    conflict_body = dict(body)
    conflict_body["items"] = [item("root", "certificate", ca)]
    r = c.post(f"/api/v1/evidence-sets/{sid}/items", json=conflict_body)
    assert r.status_code == 409

    # Same request id, different normalized content -> 409
    other = {"client_request_id": "items-1", "received_at": RECEIVED,
             "items": [item("ca", "certificate", ca)]}
    r = c.post(f"/api/v1/evidence-sets/{sid}/items", json=other)
    assert r.status_code == 409

    r = c.post(f"/api/v1/evidence-sets/{sid}/seal",
               json={"client_request_id": "seal-1"})
    assert r.status_code == 200 and r.json()["state"] == "sealed"
    manifest = r.json()["manifest"]

    # Sealed set is immutable: a NEW request must conflict even with
    # identical content (idempotent replays use the same request id).
    sealed_body = dict(body)
    sealed_body["client_request_id"] = "items-after-seal"
    r = c.post(f"/api/v1/evidence-sets/{sid}/items", json=sealed_body)
    assert r.status_code == 409

    digest = hashlib.sha256(b"artifact").digest()
    sig = lk.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    adj = {"client_request_id": "adj-1",
           "artifact_digest": digest.hex(), "signature": sig.hex(),
           "signature_algorithm": "1.2.840.10045.4.3.2",
           "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
           "leaf_certificate_sha256": fp_of(pf.der(leaf)),
           "initial_policies": [ANY], "trust_anchors": [fp_of(pf.der(root))]}
    r = c.post(f"/api/v1/evidence-sets/{sid}/adjudications", json=adj)
    assert r.status_code == 201 and r.json()["verdict"]["status"] == "VALID"
    adj_id = r.json()["adjudication_id"]
    body1 = r.content
    # Replay identical request
    r = c.post(f"/api/v1/evidence-sets/{sid}/adjudications", json=adj)
    assert r.status_code == 201 and r.content == body1

    r = c.get(f"/api/v1/evidence-sets/{sid}/adjudications/{adj_id}")
    assert r.status_code == 200
    r = c.get(f"/api/v1/evidence-sets/{sid}/packages/{adj_id}")
    assert r.status_code == 200 and r.content[:2] == b"PK"
    assert "X-Content-Digest" in r.headers


def test_unsupported_algorithm_returns_structured(client):
    c, store = client
    rk, ck, lk, root, ca, leaf = _pki()
    r = c.post("/api/v1/evidence-sets", json={"client_request_id": "u"})
    sid = r.json()["evidence_set_id"]
    # P-384 EC leaf is outside the profile (only P-256 is accepted).
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    p384_key = _ec.generate_private_key(_ec.SECP384R1())
    bad = pf.build_cert("legacy-p384", ca, p384_key, ck,
                        key_usage=("digitalSignature",),
                        eku=("codeSigning",), policies=[ANY])
    body = {"client_request_id": "i", "received_at": RECEIVED,
            "items": [{"client_ref": "b", "type": "certificate",
                       "content_base64": base64.b64encode(pf.der(bad)).decode()},
                      {"client_ref": "root", "type": "certificate",
                       "content_base64": base64.b64encode(pf.der(root)).decode()}]}
    r = c.post(f"/api/v1/evidence-sets/{sid}/items", json=body)
    assert r.status_code == 200  # ingestion accepts raw bytes
    c.post(f"/api/v1/evidence-sets/{sid}/seal", json={"client_request_id": "s"})
    adj = {"client_request_id": "a", "artifact_digest": "00" * 32,
           "signature": "00", "signature_algorithm": "1.2.840.10045.4.3.2",
           "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
           "leaf_certificate_sha256": fp_of(pf.der(bad)),
           "initial_policies": [ANY], "trust_anchors": [fp_of(pf.der(root))]}
    r = c.post(f"/api/v1/evidence-sets/{sid}/adjudications", json=adj)
    assert r.status_code == 422 and r.json()["error"]["code"] == "UNSUPPORTED"


def test_concurrent_items_and_seal(client, tmp_path):
    """Two writers against one store: seal converges on one manifest."""
    import threading
    c, store = client
    rk, ck, lk, root, ca, leaf = _pki()
    r = c.post("/api/v1/evidence-sets", json={"client_request_id": "x"})
    sid = r.json()["evidence_set_id"]

    def add(obj, ref, rid):
        d = pf.der(obj)
        body = {"client_request_id": rid, "received_at": RECEIVED,
                "items": [{"client_ref": ref, "type": "certificate",
                           "content_base64": base64.b64encode(d).decode()}]}
        rr = c.post(f"/api/v1/evidence-sets/{sid}/items", json=body)
        assert rr.status_code == 200

    threads = [
        threading.Thread(target=add, args=(root, "root", "r1")),
        threading.Thread(target=add, args=(ca, "ca", "r2")),
        threading.Thread(target=add, args=(leaf, "leaf", "r3")),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    m1 = store.seal(sid)
    m2 = store.seal(sid)
    assert m1 == m2 and m1["state"] == "sealed"
    assert m1["counts"]["certificates"] == 3
