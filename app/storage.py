"""Persistent storage: SQLite (WAL) plus content-addressed blob files.

Two API instances may share one volume. All state transitions happen inside
SQLite transactions (``BEGIN IMMEDIATE``) so concurrent uploads and racing
seals produce one immutable manifest. Blobs are written temp-file + rename.
The server clock never influences persisted results; ``received_at`` is
client supplied and the clock is only used for idempotency claim leases.

Idempotency is claim-first: a ``(scope, client_request_id)`` pair is
atomically claimed (``BEGIN IMMEDIATE`` … ``INSERT``) *before* any domain
write, so two instances racing with the same request id can never both
enter the domain flow. A racing request whose normalized content differs
fails with ``409`` before anything is written; one with identical content
waits for the owner to finish and replays the stored response. Claims
carry a lease so a crashed owner never blocks retries permanently — a
later identical request takes the claim over and, because every domain
operation is deterministic for identical normalized content, converges on
the same single persisted result.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid

from . import canonical
from .errors import ConflictError, MalformedEvidenceError, NotFoundError

# Idempotency claim tuning. The lease only gates crash recovery; it never
# affects persisted results.
IDEMPOTENCY_LEASE_SECONDS = 15.0
IDEMPOTENCY_HEARTBEAT_SECONDS = 5.0
IDEMPOTENCY_POLL_SECONDS = 0.05
IDEMPOTENCY_MAX_WAIT_SECONDS = 1800.0

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
    status_code INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'done',      -- pending | done
    owner TEXT NOT NULL DEFAULT '',
    lease_expires REAL NOT NULL DEFAULT 0,
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


class Store:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        os.makedirs(os.path.join(self.root, "blobs"), exist_ok=True)
        os.makedirs(os.path.join(self.root, "packages"), exist_ok=True)
        self.db_path = os.path.join(self.root, "app.db")
        self._lock = threading.Lock()
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
        self._conn.commit()
        self._migrate_idempotency()

    def _migrate_idempotency(self) -> None:
        """Add claim columns to databases created by older versions."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(idempotency)")}
        additions = (
            ("state", "ALTER TABLE idempotency ADD COLUMN state"
                      " TEXT NOT NULL DEFAULT 'done'"),
            ("owner", "ALTER TABLE idempotency ADD COLUMN owner"
                      " TEXT NOT NULL DEFAULT ''"),
            ("lease_expires", "ALTER TABLE idempotency ADD COLUMN lease_expires"
                              " REAL NOT NULL DEFAULT 0"),
        )
        for col, ddl in additions:
            if col in cols:
                continue
            try:
                self._conn.execute(ddl)
                self._conn.commit()
            except sqlite3.OperationalError:
                # A concurrently starting instance may have added it.
                self._conn.rollback()
                cols = {r[1] for r in self._conn.execute(
                    "PRAGMA table_info(idempotency)")}
                if col not in cols:
                    raise

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
        """Claim ``(scope, request_id)`` before any domain write.

        Returns a context manager::

            with store.idempotent("seal:SET", rid, norm) as claim:
                if claim.replay is not None:       # completed earlier
                    return claim.replay
                ... do domain work ...             # exactly one instance
                claim.save(set_id, 200, response)  # publishes the replay

        Entering blocks until this caller owns the claim or a stored
        response can be replayed. The same id submitted with different
        normalized content raises :class:`ConflictError` before any domain
        write happens. A pending claim whose owner crashed is taken over
        once its lease expires, so retries are never blocked permanently.
        """
        return _IdempotencyClaim(self, scope, request_id,
                                 canonical.sha256_hex(normalized))

    def _claim_once(self, scope: str, request_id: str, norm_digest: str):
        """One atomic claim attempt; returns ``(outcome, payload)`` with
        outcome ``owned`` (payload = claim token), ``replay`` (payload =
        stored response) or ``wait`` (another instance holds a live claim).
        """
        now = time.time()
        token = uuid.uuid4().hex
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT normalized_digest, status_code, response_json,"
                    " state, lease_expires FROM idempotency"
                    " WHERE scope=? AND request_id=?",
                    (scope, request_id)).fetchone()
                if row is None:
                    self._conn.execute(
                        "INSERT INTO idempotency(scope, request_id, set_id,"
                        " normalized_digest, status_code, response_json,"
                        " state, owner, lease_expires)"
                        " VALUES (?,?,?,?,-1,'','pending',?,?)",
                        (scope, request_id, "", norm_digest, token,
                         now + IDEMPOTENCY_LEASE_SECONDS))
                    self._conn.commit()
                    return "owned", token
                if row["normalized_digest"] != norm_digest:
                    self._conn.commit()
                    raise ConflictError(
                        "request id reused with different normalized content",
                        {"existing_normalized_digest": row["normalized_digest"],
                         "submitted_normalized_digest": norm_digest})
                if row["state"] == "done":
                    payload = {"status_code": row["status_code"],
                               "body": json.loads(row["response_json"])}
                    self._conn.commit()
                    return "replay", payload
                if row["lease_expires"] <= now:
                    # The owner crashed or froze: take the claim over. Only
                    # identical content can reach this branch, and domain
                    # operations are deterministic for identical normalized
                    # content, so the takeover converges on one result.
                    cur = self._conn.execute(
                        "UPDATE idempotency SET owner=?, lease_expires=?"
                        " WHERE scope=? AND request_id=? AND state='pending'"
                        " AND lease_expires<=?",
                        (token, now + IDEMPOTENCY_LEASE_SECONDS,
                         scope, request_id, now))
                    self._conn.commit()
                    if cur.rowcount == 1:
                        return "owned", token
                    return "wait", None  # another waiter stole it first
                self._conn.commit()
                return "wait", None
            except Exception:
                self._conn.rollback()
                raise

    def _extend_lease(self, scope: str, request_id: str, token: str,
                      lease_seconds: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE idempotency SET lease_expires=?"
                " WHERE scope=? AND request_id=? AND owner=? AND state='pending'",
                (time.time() + lease_seconds, scope, request_id, token))
            self._conn.commit()

    def _complete_claim(self, scope: str, request_id: str, token: str,
                        set_id: str, status_code: int, response: dict) -> None:
        """Publish the response. Token-conditional: if the claim was lost
        (lease expired while this instance was frozen), the takeover request
        persists the identical deterministic response instead."""
        with self._lock:
            self._conn.execute(
                "UPDATE idempotency SET state='done', set_id=?, status_code=?,"
                " response_json=?, lease_expires=0"
                " WHERE scope=? AND request_id=? AND owner=? AND state='pending'",
                (set_id, status_code, canonical.dumps(response).decode("utf-8"),
                 scope, request_id, token))
            self._conn.commit()

    def _release_claim(self, scope: str, request_id: str, token: str) -> None:
        """Drop a pending claim whose domain work failed. Nothing was
        persisted, so no replay semantics exist for the id yet."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM idempotency WHERE scope=? AND request_id=?"
                " AND owner=? AND state='pending'",
                (scope, request_id, token))
            self._conn.commit()

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


class _IdempotencyClaim:
    """Context manager backing :meth:`Store.idempotent`.

    Exactly one instance owns a ``(scope, request_id)`` claim at a time.
    While owned, a heartbeat thread keeps the lease fresh so long-running
    adjudications are not stolen; if the process dies, the lease expires
    and a later identical request takes over.
    """

    def __init__(self, store: Store, scope: str, request_id: str,
                 norm_digest: str):
        self._store = store
        self._scope = scope
        self._request_id = request_id
        self._digest = norm_digest
        self.replay: dict | None = None
        self._token: str | None = None
        self._saved = False
        self._stop = threading.Event()

    def __enter__(self) -> "_IdempotencyClaim":
        deadline = time.monotonic() + IDEMPOTENCY_MAX_WAIT_SECONDS
        while True:
            outcome, payload = self._store._claim_once(
                self._scope, self._request_id, self._digest)
            if outcome == "owned":
                self._token = payload
                threading.Thread(target=self._heartbeat, daemon=True).start()
                return self
            if outcome == "replay":
                self.replay = payload
                return self
            # Another instance holds a live claim with identical content:
            # wait for it to publish the response, then replay it.
            if time.monotonic() >= deadline:
                raise ConflictError(
                    "request id is still being processed by another instance")
            time.sleep(IDEMPOTENCY_POLL_SECONDS)

    def __exit__(self, exc_type, exc, tb):
        if self._token is not None and not self._saved:
            # Domain work raised (or save was never reached): release the
            # claim so a retry is not blocked. Nothing was persisted, so no
            # replay semantics have been established for this id yet.
            self._store._release_claim(self._scope, self._request_id,
                                       self._token)
        self._stop.set()
        return False

    def save(self, set_id: str, status_code: int, response: dict) -> None:
        """Publish the response that future identical requests replay."""
        if self._token is None:
            raise RuntimeError("cannot save without owning the claim")
        self._store._complete_claim(self._scope, self._request_id,
                                    self._token, set_id, status_code, response)
        self._saved = True
        self._stop.set()

    def _heartbeat(self) -> None:
        while not self._stop.wait(IDEMPOTENCY_HEARTBEAT_SECONDS):
            try:
                self._store._extend_lease(self._scope, self._request_id,
                                          self._token,
                                          IDEMPOTENCY_LEASE_SECONDS)
            except Exception:  # noqa: BLE001 - best effort; save is conditional
                pass
