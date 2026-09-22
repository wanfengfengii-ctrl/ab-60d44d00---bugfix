"""Persistent storage: SQLite (WAL) plus content-addressed blob files.

Two API instances may share one volume. All state transitions happen inside
SQLite transactions (``BEGIN IMMEDIATE``) so concurrent uploads and racing
seals produce one immutable manifest. Blobs are written temp-file + rename.
The server clock is never used here; ``received_at`` is client supplied.

Cross-instance idempotency ownership is established *before* any domain
write: the first request for a ``(scope, client_request_id)`` pair inserts an
``inflight`` marker inside a write transaction, so a racing request on
another instance either waits for the identical response (same normalized
content) or receives a deterministic conflict (different content). A lease
on the marker lets a crashed holder's key be taken over by a retry instead
of blocking it forever.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid

from . import canonical
from .errors import (
    ConflictError,
    InflightTimeoutError,
    MalformedEvidenceError,
    NotFoundError,
)

# An in-flight marker is presumed abandoned after this many wall-clock
# seconds (the holder process crashed or was killed). Identical-content
# waiters take over then; all domain writes below are themselves
# content-idempotent, so a slow-but-alive holder past the lease cannot yield
# a second, divergent result.
INFLIGHT_LEASE_SECONDS = 600.0
# Safety bound for a waiter observing a continuously renewed in-flight row
# (chains of crashing successors). Normal requests finish far earlier.
INFLIGHT_WAIT_SECONDS = 3600.0
INFLIGHT_POLL_SECONDS = 0.05

SCHEMA = """
CREATE TABLE IF NOT EXISTS sets (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL,                 -- open | sealed
    created_request_id TEXT,
    content_digest TEXT,
    manifest_json TEXT,
    sealed_at INTEGER
);
CREATE TABLE IF NOT EXISTS items (
    set_id TEXT NOT NULL,
    client_ref TEXT NOT NULL,
    kind TEXT NOT NULL,                  -- certificate | crl | ocsp
    content_sha256 TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (set_id, client_ref)
);
CREATE TABLE IF NOT EXISTS idempotency (
    scope TEXT NOT NULL,
    request_id TEXT NOT NULL,
    set_id TEXT NOT NULL DEFAULT '',
    normalized_digest TEXT NOT NULL,
    status_code INTEGER NOT NULL DEFAULT 0,
    response_json TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'inflight',  -- inflight | completed
    expires_at REAL,                        -- inflight lease deadline
    owner_token TEXT,                       -- fences off crashed holders
    PRIMARY KEY (scope, request_id)
);
CREATE TABLE IF NOT EXISTS adjudications (
    id TEXT PRIMARY KEY,
    set_id TEXT NOT NULL,
    set_content_digest TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    result_json TEXT NOT NULL,
    package_path TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_adj_unique
    ON adjudications(set_id, request_digest);
"""


class _IdempotencyClaim:
    """Exclusive ownership of one ``(scope, request_id)`` marker.

    A daemon heartbeat extends the lease while the (potentially long
    running) domain work executes. The owner must call exactly one of
    :meth:`complete` or :meth:`abandon`; if the process dies the lease
    simply expires and an identical-content retry takes over.
    """

    def __init__(self, store: "Store", scope: str, request_id: str,
                 norm_digest: str, token: str, lease_seconds: float):
        self._store = store
        self.scope = scope
        self.request_id = request_id
        self.norm_digest = norm_digest
        self.token = token
        self._lease = lease_seconds
        self._stop = threading.Event()
        interval = max(0.05, lease_seconds / 3.0)
        self._thread = threading.Thread(
            target=self._heartbeat_loop, args=(interval,), daemon=True)
        self._thread.start()

    def _heartbeat_loop(self, interval: float) -> None:
        while not self._stop.wait(interval):
            try:
                with self._store._lock:
                    cur = self._store._conn.execute(
                        "UPDATE idempotency SET expires_at=?"
                        " WHERE scope=? AND request_id=? AND owner_token=?"
                        " AND state='inflight'",
                        (time.time() + self._lease, self.scope,
                         self.request_id, self.token))
                    self._store._conn.commit()
                    if cur.rowcount == 0:
                        # Ownership was lost (expired lease taken over);
                        # stop renewing — the successor fences us out.
                        self._stop.set()
                        return
            except sqlite3.Error:
                # A transient SQLite error is retried on the next beat;
                # if the database is unusable the domain work fails too.
                pass

    def _stop_heartbeat(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)

    def complete(self, set_id: str, status_code: int, response: dict) -> bool:
        """Publish the replay response. Returns False if ownership was lost
        to a lease successor (which publishes the identical response)."""
        self._stop_heartbeat()
        body = canonical.dumps(response).decode("utf-8")
        conn = self._store._conn
        with self._store._lock:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "UPDATE idempotency SET state='completed', set_id=?,"
                    " status_code=?, response_json=?, expires_at=NULL"
                    " WHERE scope=? AND request_id=? AND owner_token=?"
                    " AND state='inflight'",
                    (set_id, status_code, body, self.scope,
                     self.request_id, self.token))
                if cur.rowcount == 0:
                    conn.rollback()
                    return False
                conn.commit()
                return True
            except BaseException:
                conn.rollback()
                raise

    def abandon(self) -> None:
        """Release an unfulfilled claim after the domain work failed, so a
        retry waits for no lease. Only the current owner's row is removed."""
        self._stop_heartbeat()
        conn = self._store._conn
        try:
            with self._store._lock:
                conn.execute(
                    "DELETE FROM idempotency WHERE scope=? AND request_id=?"
                    " AND owner_token=? AND state='inflight'",
                    (self.scope, self.request_id, self.token))
                conn.commit()
        except sqlite3.Error:
            # Best-effort fast path; lease expiry remains the fallback.
            pass


class Store:
    def __init__(self, root: str, inflight_lease_seconds: float = INFLIGHT_LEASE_SECONDS,
                 inflight_wait_seconds: float = INFLIGHT_WAIT_SECONDS,
                 inflight_poll_seconds: float = INFLIGHT_POLL_SECONDS):
        self.root = os.path.abspath(root)
        os.makedirs(os.path.join(self.root, "blobs"), exist_ok=True)
        os.makedirs(os.path.join(self.root, "packages"), exist_ok=True)
        self.db_path = os.path.join(self.root, "app.db")
        # In-process writers are additionally serialized by this lock, but
        # cross-instance exclusion relies on SQLite write transactions alone.
        self._lock = threading.Lock()
        self._idem_lease = inflight_lease_seconds
        self._idem_wait = inflight_wait_seconds
        self._idem_poll = inflight_poll_seconds
        self._conn = sqlite3.connect(self.db_path, timeout=60, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout=60000")
        # Two API instances may race on first startup; WAL mode is persistent
        # once set, so retry briefly under contention.
        for attempt in range(30):
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError:
                if attempt == 29:
                    raise
                time.sleep(0.5)
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA wal_autocheckpoint=1000")
        self._conn.executescript(SCHEMA)
        self._migrate_idempotency()
        self._conn.commit()

    def close(self):
        self._conn.close()

    # ---------------------------------------------------------------- blobs
    def blob_path(self, digest: str) -> str:
        return os.path.join(self.root, "blobs", digest[:2], digest)

    def put_blob(self, data: bytes) -> str:
        import hashlib

        digest = hashlib.sha256(data).hexdigest()
        path = self.blob_path(digest)
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = os.path.join(os.path.dirname(path), f".{digest}.{uuid.uuid4().hex}.tmp")
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        return digest

    def get_blob(self, digest: str) -> bytes:
        path = self.blob_path(digest)
        if not os.path.exists(path):
            raise NotFoundError(f"blob {digest} missing")
        with open(path, "rb") as f:
            return f.read()

    def put_package(self, package_id: str, data: bytes) -> str:
        path = os.path.join(self.root, "packages", package_id + ".zip")
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return path

    def package_path(self, package_id: str) -> str:
        return os.path.join(self.root, "packages", package_id + ".zip")

    # ---------------------------------------------------------- idempotency
    def idempotent(self, scope: str, request_id: str, normalized: dict):
        """Claim unique ownership of ``(scope, request_id)``.

        The claim is inserted durably (``state='inflight'``) inside a write
        transaction *before* the caller performs any domain write, so the
        decision is global across every instance sharing this directory:

        * a prior identical request has completed
          -> ``(replay, None)`` with the exact status/body to return;
        * a prior/current claim carries different normalized content
          -> :class:`ConflictError` (stable, before any domain write);
        * an identical request is in flight on another instance
          -> this call blocks until it completes and then replays it;
        * otherwise this caller owns the key -> ``(None, claim)`` and it
          must call ``claim.complete(...)`` after the domain work, or
          ``claim.abandon()`` if the work fails.

        A crashed owner stops heartbeating; once its lease expires an
        identical-content request takes over, so retries are never blocked
        forever and a second, divergent result can never be produced.
        """
        norm_digest = canonical.sha256_hex(normalized)
        return self._acquire(scope, request_id, norm_digest)

    def _acquire(self, scope: str, request_id: str, norm_digest: str):
        deadline = time.monotonic() + self._idem_wait
        while True:
            replay = None
            won_token = None
            conflict: ConflictError | None = None
            try:
                with self._lock:
                    self._conn.execute("BEGIN IMMEDIATE")
                    try:
                        row = self._conn.execute(
                            "SELECT state, normalized_digest, expires_at, owner_token,"
                            " status_code, response_json FROM idempotency"
                            " WHERE scope=? AND request_id=?",
                            (scope, request_id)).fetchone()
                        if row is None:
                            token = uuid.uuid4().hex
                            self._conn.execute(
                                "INSERT INTO idempotency(scope, request_id,"
                                " normalized_digest, state, expires_at, owner_token)"
                                " VALUES (?,?,?,'inflight',?,?)",
                                (scope, request_id, norm_digest,
                                 time.time() + self._idem_lease, token))
                            self._conn.commit()
                            won_token = token
                        elif row["normalized_digest"] != norm_digest:
                            # Content identity is fixed by the first durable
                            # claim for a key — even an abandoned one. Never
                            # let different content take the key over.
                            self._conn.commit()
                            conflict = ConflictError(
                                "request id reused with different normalized content",
                                {"existing_normalized_digest": row["normalized_digest"],
                                 "submitted_normalized_digest": norm_digest})
                        elif row["state"] == "completed":
                            self._conn.commit()
                            replay = {"status_code": row["status_code"],
                                      "body": json.loads(row["response_json"])}
                        elif row["expires_at"] is not None \
                                and row["expires_at"] <= time.time():
                            # Lease lapsed: the holder crashed or stalled.
                            # Take over atomically; content is identical
                            # (checked above), so all domain writes converge
                            # on one deterministic result.
                            token = uuid.uuid4().hex
                            now = time.time()
                            cur = self._conn.execute(
                                "UPDATE idempotency SET owner_token=?, expires_at=?,"
                                " status_code=0, response_json=''"
                                " WHERE scope=? AND request_id=? AND state='inflight'"
                                " AND expires_at<=?",
                                (token, now + self._idem_lease,
                                 scope, request_id, now))
                            self._conn.commit()
                            if cur.rowcount == 1:
                                won_token = token
                            # The holder completed between SELECT and UPDATE;
                            # fall through and replay on the next iteration.
                        else:
                            # Identical request still in flight with a live
                            # lease: release the write lock and wait/poll.
                            self._conn.commit()
                    except BaseException:
                        self._conn.rollback()
                        raise
            except sqlite3.OperationalError as exc:
                # Another instance holds the write lock (e.g. a long seal).
                # Re-evaluate until the wait budget is exhausted.
                if "locked" not in str(exc).lower() or time.monotonic() >= deadline:
                    raise
                time.sleep(self._idem_poll)
                continue
            if conflict is not None:
                raise conflict
            if replay is not None:
                return replay, None
            if won_token is not None:
                return None, _IdempotencyClaim(
                    self, scope, request_id, norm_digest, won_token,
                    self._idem_lease)
            if time.monotonic() >= deadline:
                raise InflightTimeoutError(
                    "request with identical content is still being processed"
                    " by another instance",
                    {"scope": scope, "client_request_id": request_id})
            time.sleep(self._idem_poll)

    def _migrate_idempotency(self) -> None:
        """Add in-flight bookkeeping columns to databases created before
        claims existed; old rows are treated as completed replays."""
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(idempotency)")}
        if not cols:
            return
        if "state" not in cols:
            self._conn.execute(
                "ALTER TABLE idempotency ADD COLUMN state TEXT NOT NULL"
                " DEFAULT 'completed'")
        if "expires_at" not in cols:
            self._conn.execute("ALTER TABLE idempotency ADD COLUMN expires_at REAL")
        if "owner_token" not in cols:
            self._conn.execute("ALTER TABLE idempotency ADD COLUMN owner_token TEXT")
        self._conn.execute(
            "UPDATE idempotency SET state='completed' WHERE state IS NULL")

    # -------------------------------------------------------------- sets
    def create_set(self, set_id: str, request_id: str | None) -> bool:
        """Return True if created, False if it already existed."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO sets(id, state, created_request_id)"
                " VALUES (?, 'open', ?)", (set_id, request_id))
            self._conn.commit()
            return cur.rowcount == 1

    def get_set(self, set_id: str) -> sqlite3.Row:
        with self._lock:
            row = self._conn.execute("SELECT * FROM sets WHERE id=?", (set_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"evidence set {set_id} not found")
        return row

    def assert_open(self, set_id: str) -> None:
        row = self.get_set(set_id)
        if row["state"] != "open":
            raise ConflictError(f"evidence set {set_id} is sealed and immutable")

    def add_items(self, set_id: str, items: list[dict]) -> None:
        """Atomic batch insert. ``items`` already blob-stored. Duplicate
        (set, client_ref) with identical content is an idempotent no-op;
        different content is a conflict."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT state FROM sets WHERE id=?", (set_id,)).fetchone()
                if row is None:
                    raise NotFoundError(f"evidence set {set_id} not found")
                if row[0] != "open":
                    raise ConflictError(f"evidence set {set_id} is sealed and immutable")
                for it in items:
                    existing = self._conn.execute(
                        "SELECT content_sha256, kind, received_at FROM items"
                        " WHERE set_id=? AND client_ref=?",
                        (set_id, it["client_ref"])).fetchone()
                    if existing is not None:
                        if (existing["content_sha256"], existing["kind"],
                                existing["received_at"]) != (
                                it["content_sha256"], it["kind"], it["received_at"]):
                            raise ConflictError(
                                "client item ref reused with different content",
                                {"client_ref": it["client_ref"]})
                        continue
                    self._conn.execute(
                        "INSERT INTO items(set_id, client_ref, kind, content_sha256,"
                        " received_at, detail_json) VALUES (?,?,?,?,?,?)",
                        (set_id, it["client_ref"], it["kind"], it["content_sha256"],
                         it["received_at"], json.dumps(it.get("detail", {}), sort_keys=True)))
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def list_items(self, set_id: str) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(
                "SELECT * FROM items WHERE set_id=? ORDER BY client_ref", (set_id,)))

    def seal(self, set_id: str) -> dict:
        """Atomically seal; returns the manifest. Safe under racing sealers."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT state, manifest_json FROM sets WHERE id=?",
                    (set_id,)).fetchone()
                if row is None:
                    raise NotFoundError(f"evidence set {set_id} not found")
                if row[0] == "sealed":
                    self._conn.commit()
                    return json.loads(row[1])
                items = list(self._conn.execute(
                    "SELECT kind, content_sha256, received_at FROM items"
                    " WHERE set_id=?", (set_id,)))
                groups = {"certificate": [], "crl": [], "ocsp": []}
                for it in items:
                    groups[it["kind"]].append(
                        {"sha256": it["content_sha256"], "received_at": it["received_at"]})
                # Content-addressed identity: identical bytes uploaded under
                # different client refs are one object. Certificates need no
                # received_at; revocation evidence keeps the EARLIEST
                # received_at (possession timeline).
                cert_dedup = sorted({x["sha256"] for x in groups["certificate"]})
                groups["certificate"] = [{"sha256": d} for d in cert_dedup]
                for k in ("crl", "ocsp"):
                    earliest: dict[str, int] = {}
                    for x in groups[k]:
                        if x["sha256"] not in earliest:
                            earliest[x["sha256"]] = x["received_at"]
                        else:
                            earliest[x["sha256"]] = min(earliest[x["sha256"]],
                                                        x["received_at"])
                    groups[k] = sorted(
                        ({"sha256": d, "received_at": r} for d, r in earliest.items()),
                        key=lambda x: x["sha256"])

                # Resource limits (per single sealed set).
                n_cert = len(groups["certificate"])
                n_rev = len(groups["crl"]) + len(groups["ocsp"])
                if n_cert > 100_000:
                    raise ConflictError("resource limit exceeded",
                                        {"limit": "certificates", "max": 100_000,
                                         "actual": n_cert})
                if n_rev > 2_000:
                    raise ConflictError("resource limit exceeded",
                                        {"limit": "crl_ocsp_evidence", "max": 2_000,
                                         "actual": n_rev})
                # Cheap subject-name index for lazy graph construction.
                import base64

                from .certmodel import cheap_names
                from .errors import MalformedEvidenceError

                name_index: dict[str, list[str]] = {}
                for x in groups["certificate"]:
                    d = x["sha256"]
                    try:
                        _issuer, subject = cheap_names(self.get_blob(d))
                    except MalformedEvidenceError:
                        continue
                    name_index.setdefault(base64.b64encode(subject).decode(), []).append(d)
                total_revocation_entries = 0
                for x in groups["crl"]:
                    from cryptography import x509 as _x509

                    total_revocation_entries += len(
                        _x509.load_der_x509_crl(self.get_blob(x["sha256"])))
                if total_revocation_entries > 1_000_000:
                    raise ConflictError("resource limit exceeded",
                                        {"limit": "revocation_entries", "max": 1_000_000,
                                         "actual": total_revocation_entries})

                content = {
                    "certificates": [x["sha256"] for x in groups["certificate"]],
                    "crls": groups["crl"],
                    "ocsps": groups["ocsp"],
                }
                manifest = {
                    "evidence_set_id": set_id,
                    "state": "sealed",
                    "content": content,
                    "counts": {"certificates": len(content["certificates"]),
                               "crls": len(content["crls"]),
                               "ocsps": len(content["ocsps"]),
                               "revocation_entries": total_revocation_entries},
                }
                manifest["content_digest"] = canonical.sha256_hex(content)
                self._conn.execute(
                    "UPDATE sets SET state='sealed', content_digest=?,"
                    " manifest_json=?, sealed_at=strftime('%s','now') WHERE id=?",
                    (manifest["content_digest"],
                     canonical.dumps(manifest).decode("utf-8"), set_id))
                self._conn.commit()
                # Subject-name index sidecar (content-addressed in set dir).
                import os as _os

                idx_path = _os.path.join(self.root, "packages", f"{set_id}.nameindex.json")
                tmp = idx_path + ".tmp"
                with open(tmp, "w") as f:
                    f.write(canonical.dumps(name_index).decode("utf-8"))
                _os.replace(tmp, idx_path)
                return manifest
            except Exception:
                self._conn.rollback()
                raise

    def save_adjudication(self, adj_id: str, set_id: str, set_digest: str,
                          request_digest: str, result: dict, package_path: str | None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO adjudications(id, set_id, set_content_digest,"
                " request_digest, result_json, package_path) VALUES (?,?,?,?,?,?)",
                (adj_id, set_id, set_digest, request_digest,
                 canonical.dumps(result).decode("utf-8"), package_path))
            self._conn.commit()

    def get_adjudication_by_request(self, set_id: str, request_digest: str):
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM adjudications WHERE set_id=? AND request_digest=?",
                (set_id, request_digest)).fetchone()

    def get_adjudication(self, adj_id: str):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM adjudications WHERE id=?", (adj_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"adjudication {adj_id} not found")
        return row
