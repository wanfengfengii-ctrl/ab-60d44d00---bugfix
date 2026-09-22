"""Concurrency semantics: racing sealers and two Store handles on one volume
must converge on a single immutable manifest."""
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

from tests import pki_factory as pf
from app.certmodel import fp_of
from app.errors import ConflictError
from app.storage import Store


def _set_count(store):
    with store._lock:
        return store._conn.execute("SELECT COUNT(*) FROM sets").fetchone()[0]


def _idem_row(store, scope, rid):
    with store._lock:
        return store._conn.execute(
            "SELECT * FROM idempotency WHERE scope=? AND request_id=?",
            (scope, rid)).fetchone()


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


# =====================================================================
# Cross-instance idempotency ownership (same (scope, client_request_id),
# two Store handles sharing one SQLite directory).
# =====================================================================

def _make_stores(root, **kw):
    opts = dict(inflight_lease_seconds=2.0, inflight_poll_seconds=0.01,
                inflight_wait_seconds=15.0)
    opts.update(kw)
    shared = root / "shared"
    s1 = Store(str(shared), **opts)
    s2 = Store(str(shared), **opts)
    return s1, s2


def test_claim_exists_before_domain_write(tmp_path):
    s1, s2 = _make_stores(tmp_path)
    started = threading.Event()
    done = threading.Event()

    def owner():
        replay, claim = s1.idempotent("create_set", "k", {"v": 1})
        assert replay is None
        started.set()
        done.wait(2.0)
        claim.complete("es_x", 201, {"evidence_set_id": "es_x"})

    t = threading.Thread(target=owner)
    t.start()
    assert started.wait(2.0)
    row = _idem_row(s2, "create_set", "k")
    # The durable in-flight claim precedes every business write.
    assert row is not None and row["state"] == "inflight"
    assert _set_count(s2) == 0
    done.set()
    t.join(2.0)
    assert not t.is_alive()


def test_same_content_concurrent_converges_single_result(tmp_path):
    s1, s2 = _make_stores(tmp_path)
    barrier = threading.Barrier(2)
    winners = []
    replays = []

    def call(store):
        barrier.wait(2.0)  # release both callers at the same instant
        replay, claim = store.idempotent("create_set", "k", {"v": 1})
        if replay is None:
            set_id = "es_same_000000000000000000000001"
            store.create_set(set_id, "k")
            claim.complete(set_id, 201, {"evidence_set_id": set_id})
            winners.append(set_id)
        else:
            replays.append(replay)

    t1 = threading.Thread(target=call, args=(s1,))
    t2 = threading.Thread(target=call, args=(s2,))
    t1.start(); t2.start(); t1.join(5.0); t2.join(5.0)
    assert not t1.is_alive() and not t2.is_alive()
    assert len(winners) == 1
    assert len(replays) == 1
    assert replays[0]["status_code"] == 201
    assert replays[0]["body"]["evidence_set_id"] == winners[0]
    # Exactly one business result exists.
    assert _set_count(s1) == 1


def test_different_content_concurrent_conflicts_before_write(tmp_path):
    s1, s2 = _make_stores(tmp_path)
    holder = threading.Event()
    proceed = threading.Event()
    outcomes = []

    def first():
        replay, claim = s1.idempotent("create_set", "k", {"note": "a"})
        holder.set()
        proceed.wait(2.0)
        if replay is None:
            s1.create_set("es_a", "k")
            claim.complete("es_a", 201, {"evidence_set_id": "es_a"})

    def second():
        assert holder.wait(2.0)
        try:
            replay, claim = s2.idempotent("create_set", "k", {"note": "b"})
            if replay is None:
                s2.create_set("es_b", "k")
                claim.complete("es_b", 201, {"evidence_set_id": "es_b"})
            outcomes.append(("ok", replay))
        except ConflictError as exc:
            outcomes.append(("conflict", exc))

    t1 = threading.Thread(target=first)
    t2 = threading.Thread(target=second)
    t1.start(); t2.start()
    t2.join(5.0)
    proceed.set()
    t1.join(5.0)
    assert outcomes and outcomes[0][0] == "conflict"
    # The losing, different-content request produced no business result.
    assert _set_count(s1) == 1


def test_different_content_vs_completed_request_conflicts(tmp_path):
    s1, s2 = _make_stores(tmp_path)
    replay, claim = s1.idempotent("create_set", "k", {"note": "a"})
    assert replay is None
    s1.create_set("es_done", "k")
    claim.complete("es_done", 201, {"evidence_set_id": "es_done"})
    with pytest.raises(ConflictError):
        s2.idempotent("create_set", "k", {"note": "b"})
    assert _set_count(s2) == 1


def test_crashed_owner_does_not_block_retry(tmp_path):
    # Lease shorter than the wait; a claim whose owner never completes nor
    # heartbeats must be taken over after expiry.
    s1, s2 = _make_stores(tmp_path, inflight_lease_seconds=0.3)
    replay, claim = s1.idempotent("create_set", "k", {"note": "a"})
    assert replay is None
    # Simulate a hard crash: drop the heartbeat without completing.
    claim._stop_heartbeat()
    with s1._lock:
        s1._conn.execute(
            "UPDATE idempotency SET expires_at=? WHERE scope='create_set'"
            " AND request_id='k'", (time.time() - 1.0,))
        s1._conn.commit()
    t0 = time.monotonic()
    replay2, claim2 = s2.idempotent("create_set", "k", {"note": "a"})
    assert replay2 is None
    assert time.monotonic() - t0 < 5.0
    s2.create_set("es_retry", "k")
    claim2.complete("es_retry", 201, {"evidence_set_id": "es_retry"})
    assert _set_count(s2) == 1


def test_abandoned_claim_is_reattributable(tmp_path):
    s1, s2 = _make_stores(tmp_path)
    replay, claim = s1.idempotent("create_set", "k", {"note": "a"})
    assert replay is None
    claim.abandon()
    # A retry (even with different content) is free once released.
    replay2, claim2 = s2.idempotent("create_set", "k", {"note": "b"})
    assert replay2 is None
    claim2.abandon()


def test_different_content_cannot_take_over_expired_lease(tmp_path):
    s1, s2 = _make_stores(tmp_path, inflight_lease_seconds=0.3)
    replay, claim = s1.idempotent("create_set", "k", {"note": "a"})
    assert replay is None
    claim._stop_heartbeat()
    with s1._lock:
        s1._conn.execute(
            "UPDATE idempotency SET expires_at=? WHERE scope='create_set'"
            " AND request_id='k'", (time.time() - 1.0,))
        s1._conn.commit()
    with pytest.raises(ConflictError):
        s2.idempotent("create_set", "k", {"note": "different"})
    # Identical content can take the expired lease over.
    replay2, claim2 = s2.idempotent("create_set", "k", {"note": "a"})
    assert replay2 is None
    claim2.abandon()


def test_heartbeat_holds_lease_for_live_long_owner(tmp_path):
    # Lease ~0.3s; the claim heartbeat must keep extending it while the
    # (still alive) owner works for well past the original deadline.
    s1, s2 = _make_stores(tmp_path, inflight_lease_seconds=0.3)
    replay, claim = s1.idempotent("create_set", "k", {"note": "a"})
    assert replay is None
    took_over = threading.Event()

    def waiter():
        r, c = s2.idempotent("create_set", "k", {"note": "a"})
        if r is not None:
            took_over.set()  # owner completed -> replay
        else:
            c.abandon()

    t = threading.Thread(target=waiter, daemon=True)
    t.start()
    time.sleep(1.5)  # several lease periods; owner still alive
    assert not took_over.is_set()
    s1.create_set("es_live", "k")
    claim.complete("es_live", 201, {"evidence_set_id": "es_live"})
    t.join(5.0)
    assert not t.is_alive()
    assert _set_count(s1) == 1


def test_fenced_zombie_cannot_complete_after_takeover(tmp_path):
    s1, s2 = _make_stores(tmp_path, inflight_lease_seconds=0.3)
    replay, claim = s1.idempotent("create_set", "k", {"note": "a"})
    assert replay is None
    # Owner stalls past its lease (heartbeat stopped); successor takes over.
    claim._stop_heartbeat()
    with s1._lock:
        s1._conn.execute(
            "UPDATE idempotency SET expires_at=? WHERE scope='create_set'"
            " AND request_id='k'", (time.time() - 1.0,))
        s1._conn.commit()
    replay2, claim2 = s2.idempotent("create_set", "k", {"note": "a"})
    assert replay2 is None
    s2.create_set("es_successor", "k")
    claim2.complete("es_successor", 201, {"evidence_set_id": "es_successor"})
    # The original owner wakes up and tries to publish its response: fenced.
    assert claim.complete("es_zombie", 201,
                          {"evidence_set_id": "es_zombie"}) is False
    # The persisted replay stays the successor's, and no second set exists.
    replay3, none_claim = s1.idempotent("create_set", "k", {"note": "a"})
    assert replay3["body"]["evidence_set_id"] == "es_successor"
    assert _set_count(s1) == 1


def test_old_schema_rows_treated_as_completed(tmp_path):
    root = str(tmp_path / "legacy")
    os.makedirs(root, exist_ok=True)
    import sqlite3 as _sq
    conn = _sq.connect(os.path.join(root, "app.db"))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
    CREATE TABLE sets (id TEXT PRIMARY KEY, state TEXT NOT NULL,
        created_request_id TEXT, content_digest TEXT, manifest_json TEXT,
        sealed_at INTEGER);
    CREATE TABLE items (set_id TEXT NOT NULL, client_ref TEXT NOT NULL,
        kind TEXT NOT NULL, content_sha256 TEXT NOT NULL,
        received_at INTEGER NOT NULL, detail_json TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY (set_id, client_ref));
    CREATE TABLE idempotency (scope TEXT NOT NULL, request_id TEXT NOT NULL,
        set_id TEXT NOT NULL DEFAULT '', normalized_digest TEXT NOT NULL,
        status_code INTEGER NOT NULL, response_json TEXT NOT NULL,
        PRIMARY KEY (scope, request_id));
    CREATE TABLE adjudications (id TEXT PRIMARY KEY, set_id TEXT NOT NULL,
        set_content_digest TEXT NOT NULL, request_digest TEXT NOT NULL,
        result_json TEXT NOT NULL, package_path TEXT);
    CREATE UNIQUE INDEX idx_adj_unique ON adjudications(set_id, request_digest);
    """)
    conn.execute(
        "INSERT INTO idempotency(scope, request_id, normalized_digest,"
        " status_code, response_json) VALUES ('create_set','k','d1',201,"
        " '{\"evidence_set_id\":\"es_legacy\"}')")
    conn.commit()
    conn.close()
    s = Store(root)
    from app import canonical
    nd = canonical.sha256_hex({"x": 1})
    # Unknown digest content on a legacy row -> conflict (it is completed).
    with pytest.raises(ConflictError):
        s.idempotent("create_set", "k", {"x": 1})
    row = _idem_row(s, "create_set", "k")
    assert row["state"] == "completed"
    assert nd  # silence unused

