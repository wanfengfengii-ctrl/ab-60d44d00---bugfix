"""Versioned HTTP API (``/api/v1``).

Endpoints:

* ``POST   /api/v1/evidence-sets``
* ``POST   /api/v1/evidence-sets/{id}/items``
* ``POST   /api/v1/evidence-sets/{id}/seal``
* ``GET    /api/v1/evidence-sets/{id}``
* ``POST   /api/v1/evidence-sets/{id}/adjudications``
* ``GET    /api/v1/evidence-sets/{id}/adjudications/{adj_id}``
* ``GET    /api/v1/evidence-sets/{id}/packages/{adj_id}``  (ZIP download)
* ``GET    /healthz``

All mutating requests accept an explicit ``client_request_id`` (or the
``Idempotency-Key`` header). ``received_at`` for ingested evidence is
client-supplied forensic metadata — the server clock never affects results.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, Response

from . import canonical
from .adjudge import adjudicate, normalize_request
from .errors import (
    ConflictError,
    MalformedEvidenceError,
    NotFoundError,
    ProfileError,
    UnsupportedError,
)
from .package import build_package
from .storage import Store
from .timeutil import parse_time

MAX_BATCH_ITEMS = 10_000
MAX_ITEM_BYTES = 8 * 1024 * 1024  # single DER/OCSP object


def create_app(store: Store) -> FastAPI:
    class CanonicalResponse(JSONResponse):
        """Every response body is canonical JSON (RFC 8785-style), so a
        persisted replay is byte-identical to the first response."""

        def render(self, content) -> bytes:
            return canonical.dumps(content)

    app = FastAPI(title="Forensic PKI Adjudication Service", version="1.0.0",
                  docs_url=None, redoc_url=None, openapi_url=None,
                  default_response_class=CanonicalResponse)

    # ------------------------------------------------------------ errors
    @app.exception_handler(ProfileError)
    async def _profile_exc(request: Request, exc: ProfileError):
        return CanonicalResponse(status_code=422,
                                 content={"error": {"code": exc.code,
                                                    "message": exc.message,
                                                    "detail": exc.detail}})

    @app.exception_handler(ConflictError)
    async def _conflict_exc(request: Request, exc: ConflictError):
        return CanonicalResponse(status_code=409,
                                 content={"error": {"code": "CONFLICT",
                                                    "message": str(exc),
                                                    "detail": exc.existing}})

    @app.exception_handler(NotFoundError)
    async def _nf_exc(request: Request, exc: NotFoundError):
        return CanonicalResponse(status_code=404,
                                 content={"error": {"code": "NOT_FOUND",
                                                    "message": str(exc)}})

    @app.get("/healthz")
    async def healthz():
        return CanonicalResponse(
            content={"status": "ok", "service": "forensic-pki", "api": "v1"})

    # ------------------------------------------------------ evidence sets
    @app.post("/api/v1/evidence-sets", status_code=201)
    async def create_set(body: dict = None, idempotency_key: str | None = Header(default=None)):
        body = body or {}
        rid = body.get("client_request_id") or idempotency_key
        if not rid:
            raise MalformedEvidenceError("client_request_id is required")
        norm = {"op": "create_evidence_set", "client_request_id": rid,
                "note": body.get("note", "")}
        replay, save = store.idempotent("create_set", rid, norm)
        if replay:
            return CanonicalResponse(status_code=replay["status_code"],
                                    content=replay["body"])
        set_id = "es_" + canonical.sha256_hex(norm)[:32]
        store.create_set(set_id, rid)
        resp = {"evidence_set_id": set_id, "state": "open",
                "client_request_id": rid}
        save(set_id, 201, resp)
        return CanonicalResponse(status_code=201, content=resp)

    @app.post("/api/v1/evidence-sets/{set_id}/items")
    async def add_items(set_id: str, body: dict,
                        idempotency_key: str | None = Header(default=None)):
        store.get_set(set_id)  # 404 if missing
        rid = body.get("client_request_id") or idempotency_key
        if not rid:
            raise MalformedEvidenceError("client_request_id is required")
        if "received_at" not in body:
            raise MalformedEvidenceError(
                "received_at is required (forensic acquisition time)")
        received_at = parse_time(body["received_at"], "received_at")
        items = body.get("items")
        if not isinstance(items, list) or not items:
            raise MalformedEvidenceError("items: non-empty list required")
        if len(items) > MAX_BATCH_ITEMS:
            raise MalformedEvidenceError("items: batch too large",
                                         {"max": MAX_BATCH_ITEMS})

        norm_items = []
        prepared = []
        for it in items:
            ref = it.get("client_ref")
            kind = it.get("type")
            if not ref or not isinstance(ref, str):
                raise MalformedEvidenceError("item.client_ref required")
            if kind not in ("certificate", "crl", "ocsp"):
                raise MalformedEvidenceError(
                    "item.type must be certificate|crl|ocsp", {"client_ref": ref})
            data = _decode_item(it, ref)
            if len(data) > MAX_ITEM_BYTES:
                raise MalformedEvidenceError("item exceeds size limit",
                                             {"client_ref": ref,
                                              "max_bytes": MAX_ITEM_BYTES})
            digest = hashlib.sha256(data).hexdigest()
            norm_items.append({"client_ref": ref, "type": kind, "sha256": digest})
            prepared.append({"client_ref": ref, "kind": kind, "raw": data,
                             "content_sha256": digest, "received_at": received_at})
        norm_items.sort(key=lambda x: x["client_ref"])
        norm = {"op": "add_items", "evidence_set_id": set_id,
                "client_request_id": rid, "received_at": received_at,
                "items": norm_items}
        replay, save = store.idempotent(f"items:{set_id}", rid, norm)
        if replay:
            return CanonicalResponse(status_code=replay["status_code"],
                                    content=replay["body"])

        # Persist blobs (content dedup is inherently idempotent).
        rows = []
        for p in prepared:
            store.put_blob(p["raw"])
            rows.append({"client_ref": p["client_ref"], "kind": p["kind"],
                         "content_sha256": p["content_sha256"],
                         "received_at": p["received_at"]})
        store.assert_open(set_id)
        store.add_items(set_id, rows)
        accepted = [{"client_ref": p["client_ref"], "type": p["kind"],
                     "sha256": p["content_sha256"]} for p in prepared]
        accepted.sort(key=lambda x: x["client_ref"])
        resp = {"evidence_set_id": set_id, "accepted": len(rows),
                "items": accepted, "client_request_id": rid}
        save(set_id, 200, resp)
        return resp

    @app.post("/api/v1/evidence-sets/{set_id}/seal")
    async def seal(set_id: str, body: dict | None = None,
                   idempotency_key: str | None = Header(default=None)):
        store.get_set(set_id)
        body = body or {}
        rid = body.get("client_request_id") or idempotency_key
        if not rid:
            raise MalformedEvidenceError("client_request_id is required")
        norm = {"op": "seal", "evidence_set_id": set_id,
                "client_request_id": rid}
        replay, save = store.idempotent(f"seal:{set_id}", rid, norm)
        if replay:
            return CanonicalResponse(status_code=replay["status_code"],
                                    content=replay["body"])
        manifest = store.seal(set_id)
        resp = {"evidence_set_id": set_id, "state": "sealed",
                "manifest": manifest, "client_request_id": rid}
        save(set_id, 200, resp)
        return resp

    @app.get("/api/v1/evidence-sets/{set_id}")
    async def get_set(set_id: str):
        row = store.get_set(set_id)
        return {"evidence_set_id": set_id, "state": row["state"],
                "content_digest": row["content_digest"],
                "manifest": json.loads(row["manifest_json"])
                if row["manifest_json"] else None}

    # -------------------------------------------------------- adjudication
    @app.post("/api/v1/evidence-sets/{set_id}/adjudications", status_code=201)
    async def create_adjudication(set_id: str, body: dict,
                                  idempotency_key: str | None = Header(default=None)):
        rid = body.get("client_request_id") or idempotency_key
        if not rid:
            raise MalformedEvidenceError("client_request_id is required")
        # Validate + normalize for the idempotency scope.
        req_norm = normalize_request(body)
        norm = {"op": "adjudicate", "evidence_set_id": set_id,
                "client_request_id": rid, "request": req_norm}
        replay, _save = store.idempotent(f"adjudicate:{set_id}", rid, norm)
        if replay:
            return CanonicalResponse(status_code=replay["status_code"],
                                    content=replay["body"])
        result = adjudicate(store, set_id, body)
        adj_id = result["adjudication"]["request_digest"]
        out = {"adjudication_id": adj_id, **result}
        # Persist the idempotency replay row pointing at the same content.
        _save(set_id, 201, out)
        return CanonicalResponse(status_code=201, content=out)

    @app.get("/api/v1/evidence-sets/{set_id}/adjudications/{adj_id}")
    async def get_adjudication(set_id: str, adj_id: str):
        row = store.get_adjudication(adj_id)
        if row["set_id"] != set_id:
            raise NotFoundError("adjudication not in this evidence set")
        return {"adjudication_id": adj_id, **json.loads(row["result_json"])}

    @app.get("/api/v1/evidence-sets/{set_id}/packages/{adj_id}")
    async def download_package(set_id: str, adj_id: str):
        row = store.get_adjudication(adj_id)
        if row["set_id"] != set_id:
            raise NotFoundError("adjudication not in this evidence set")
        result = json.loads(row["result_json"])
        set_row = store.get_set(set_id)
        manifest = json.loads(set_row["manifest_json"])
        blob = build_package(store, result, manifest)
        return Response(
            content=blob, media_type="application/zip",
            headers={"Content-Disposition":
                     f'attachment; filename="{adj_id}.zip"',
                     "X-Content-Digest": f"sha-256={hashlib.sha256(blob).hexdigest()}"})

    return app


def _decode_item(it: dict, ref: str) -> bytes:
    if "content_base64" in it:
        try:
            return base64.b64decode(it["content_base64"], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise MalformedEvidenceError("content_base64 invalid",
                                         {"client_ref": ref}) from exc
    if "content_hex" in it:
        try:
            return bytes.fromhex(it["content_hex"])
        except ValueError as exc:
            raise MalformedEvidenceError("content_hex invalid",
                                         {"client_ref": ref}) from exc
    raise MalformedEvidenceError("item requires content_base64 or content_hex",
                                 {"client_ref": ref})
