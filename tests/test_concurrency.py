"""Concurrency semantics: racing sealers and two Store handles on one volume
must converge on a single immutable manifest."""
import os
import sqlite3
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

from tests import pki_factory as pf
from app import canonical
from app.certmodel import fp_of
from app.errors import ConflictError
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
    with pytest.raises(ConflictError):
        s.add_items(sid, [{"client_ref": "x", "kind": "certificate",
                           "content_sha256": fp_of(db), "received_at": 1}])


# ---------------------------------------------------------------------------
# Cross-instance idempotency: the (scope, client_request_id) claim must be
# settled before any domain write, so racing instances can never both enter
# the domain flow.
# ---------------------------------------------------------------------------

def _create_norm(rid, note):
    return {"op": "create_evidence_set", "client_request_id": rid, "note": note}


def _create_via_claim(store, rid, note):
    """Storage-level equivalent of the create-evidence-set API handler."""
    norm = _create_norm(rid, note)
    with store.idempotent("create_set", rid, norm) as claim:
        if claim.replay is not None:
            return "replay", claim.replay["body"]
        sid = "es_" + canonical.sha256_hex(norm)[:32]
        store.create_set(sid, rid)
        resp = {"evidence_set_id": sid, "state": "open", "client_request_id": rid}
        claim.save(sid, 201, resp)
        return "owned", resp


def _count_sets(root_dir):
    conn = sqlite3.connect(os.path.join(root_dir, "app.db"))
    try:
        return conn.execute("SELECT COUNT(*) FROM sets").fetchone()[0]
    finally:
        conn.close()


def test_racing_create_same_id_different_content(tmp_path):
    """Two instances, same request id, different normalized content: exactly
    one claim is granted before any domain write; the loser conflicts and
    persists nothing."""
    root_dir = str(tmp_path / "race_diff")
    s1, s2 = Store(root_dir), Store(root_dir)
    outcomes, errors = [], []

    def run(store, note):
        try:
            outcomes.append(_create_via_claim(store, "race-1", note))
        except ConflictError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(s1, "note-a")),
               threading.Thread(target=run, args=(s2, "note-b"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(errors) == 1
    assert len(outcomes) == 1 and outcomes[0][0] == "owned"
    # Only the winner's evidence set exists.
    assert _count_sets(root_dir) == 1


def test_racing_create_same_content_single_result(tmp_path):
    """Same id, same content: one request owns the claim, the other waits
    and replays the identical response; exactly one set is persisted."""
    root_dir = str(tmp_path / "race_same")
    s1, s2 = Store(root_dir), Store(root_dir)
    outcomes, errors = [], []

    def run(store):
        try:
            outcomes.append(_create_via_claim(store, "race-2", "note"))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(s1,)),
               threading.Thread(target=run, args=(s2,))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert sorted(kind for kind, _ in outcomes) == ["owned", "replay"]
    assert outcomes[0][1] == outcomes[1][1]
    assert _count_sets(root_dir) == 1


def test_pending_claim_waits_for_owner_and_replays(tmp_path):
    """A same-content request arriving while the owner's work is in flight
    blocks until the response is published, then replays it."""
    root_dir = str(tmp_path / "wait_replay")
    s1, s2 = Store(root_dir), Store(root_dir)
    norm = _create_norm("race-3", "note")
    entered, finish, waiter_done = (threading.Event() for _ in range(3))
    waiter_outcome = []

    def owner():
        with s1.idempotent("create_set", "race-3", norm) as claim:
            assert claim.replay is None
            entered.set()
            assert finish.wait(10)
            claim.save("es_x", 201, {"evidence_set_id": "es_x"})

    def waiter():
        assert entered.wait(10)
        with s2.idempotent("create_set", "race-3", norm) as claim:
            waiter_outcome.append(claim.replay)
            waiter_done.set()

    t1 = threading.Thread(target=owner)
    t2 = threading.Thread(target=waiter)
    t1.start()
    t2.start()
    assert entered.wait(10)
    time.sleep(0.5)
    assert not waiter_done.is_set()  # blocked while the owner is working
    finish.set()
    t1.join(10)
    t2.join(10)
    assert waiter_done.is_set()
    assert waiter_outcome[0]["status_code"] == 201
    assert waiter_outcome[0]["body"] == {"evidence_set_id": "es_x"}


def test_crashed_owner_claim_taken_over_after_lease(tmp_path):
    """If the owning instance dies mid-request, the pending claim neither
    blocks retries forever nor allows a second result: once the lease
    expires, an identical retry takes over and completes exactly once."""
    root_dir = str(tmp_path / "crash")
    s1, s2 = Store(root_dir), Store(root_dir)
    norm = _create_norm("race-4", "note")
    crashed = s1.idempotent("create_set", "race-4", norm)
    crashed.__enter__()
    crashed._stop.set()  # process "died": heartbeat stopped, no save/abort
    # Different content conflicts even against the orphaned pending claim.
    with pytest.raises(ConflictError):
        with s2.idempotent("create_set", "race-4", _create_norm("race-4", "x")):
            pass
    # Force the lease into the past instead of waiting it out.
    s1._conn.execute("UPDATE idempotency SET lease_expires=0"
                     " WHERE scope='create_set' AND request_id='race-4'")
    s1._conn.commit()
    with s2.idempotent("create_set", "race-4", norm) as claim:
        assert claim.replay is None  # took the orphaned claim over
        sid = "es_" + canonical.sha256_hex(norm)[:32]
        s2.create_set(sid, "race-4")
        claim.save(sid, 201, {"evidence_set_id": sid})
    # The completed record replays; different content still conflicts.
    with s2.idempotent("create_set", "race-4", norm) as claim:
        assert claim.replay is not None
        assert claim.replay["body"] == {"evidence_set_id": sid}
    with pytest.raises(ConflictError):
        with s2.idempotent("create_set", "race-4", _create_norm("race-4", "x")):
            pass
    assert _count_sets(root_dir) == 1


def test_failed_request_releases_claim(tmp_path):
    """A request whose domain work fails releases the claim: no response was
    persisted, so a later retry is treated as a fresh first request."""
    s = Store(str(tmp_path / "fail"))
    with pytest.raises(RuntimeError):
        with s.idempotent("create_set", "race-5", _create_norm("race-5", "a")):
            raise RuntimeError("boom")
    with s.idempotent("create_set", "race-5", _create_norm("race-5", "b")) as claim:
        assert claim.replay is None
        claim.save("es_z", 201, {"evidence_set_id": "es_z"})
    with s.idempotent("create_set", "race-5", _create_norm("race-5", "b")) as claim:
        assert claim.replay is not None
        assert claim.replay["body"] == {"evidence_set_id": "es_z"}
