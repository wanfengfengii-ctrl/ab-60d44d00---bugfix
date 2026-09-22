"""Concurrency semantics: racing sealers and two Store handles on one volume
must converge on a single immutable manifest."""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

from tests import pki_factory as pf
from app.certmodel import fp_of
from app.storage import Store


def test_racing_seals_single_manifest(tmp_path):
    root_dir = str(tmp_path / "shared")
    s1 = Store(root_dir)
    s2 = Store(root_dir)
    sid = "es_race_0000000000000000000000000001"
    s1.create_set(sid, "c")
    rk = pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"),
                         policies=["2.5.29.32.0"], self_signed=True)
    d = pf.der(root)
    s1.put_blob(d)
    s1.add_items(sid, [{"client_ref": "root", "kind": "certificate",
                        "content_sha256": fp_of(d), "received_at": 100}])
    manifests = []
    errors = []

    def seal(store):
        try:
            manifests.append(store.seal(sid))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    t1 = threading.Thread(target=seal, args=(s1,))
    t2 = threading.Thread(target=seal, args=(s2,))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert not errors
    assert len(manifests) == 2
    assert manifests[0] == manifests[1]
    assert manifests[0]["state"] == "sealed"
    # A third seal after reopening the store still returns the same manifest.
    s3 = Store(root_dir)
    m3 = s3.seal(sid)
    assert m3 == manifests[0]


def test_concurrent_uploads_serialize(tmp_path):
    root_dir = str(tmp_path / "shared2")
    s = Store(root_dir)
    sid = "es_up_000000000000000000000000000001"
    s.create_set(sid, "c")
    errors = []

    def upload(i):
        k = pf.gen_key()
        cert = pf.build_cert(f"C{i}", None, k, k, is_ca=True,
                             key_usage=("keyCertSign", "cRLSign"),
                             policies=["2.5.29.32.0"], self_signed=True)
        d = pf.der(cert)
        try:
            s.put_blob(d)
            s.add_items(sid, [{"client_ref": f"c{i}", "kind": "certificate",
                               "content_sha256": fp_of(d), "received_at": 100}])
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=upload, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    m = s.seal(sid)
    assert m["counts"]["certificates"] == 20


def test_same_ref_different_content_conflicts(tmp_path):
    s = Store(str(tmp_path / "d"))
    sid = "es_conflict_0000000000000000000000001"
    s.create_set(sid, "c")
    k1, k2 = pf.gen_key(), pf.gen_key()
    a = pf.build_cert("A", None, k1, k1, is_ca=True,
                      key_usage=("keyCertSign", "cRLSign"),
                      policies=["2.5.29.32.0"], self_signed=True)
    b = pf.build_cert("A", None, k2, k2, is_ca=True,
                      key_usage=("keyCertSign", "cRLSign"),
                      policies=["2.5.29.32.0"], self_signed=True)
    da, db = pf.der(a), pf.der(b)
    s.put_blob(da); s.put_blob(db)
    s.add_items(sid, [{"client_ref": "x", "kind": "certificate",
                       "content_sha256": fp_of(da), "received_at": 1}])
    from app.errors import ConflictError
    with pytest.raises(ConflictError):
        s.add_items(sid, [{"client_ref": "x", "kind": "certificate",
                           "content_sha256": fp_of(db), "received_at": 1}])
