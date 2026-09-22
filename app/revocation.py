"""Bitemporal revocation evaluation (RFC 5280 CRL + RFC 6960 OCSP).

Two independent timelines (see ``timeutil``):

* evidence *eligibility* uses ``received_at <= knowledge_cutoff``;
* the revocation *conclusion* uses ``signed_at`` — never the cutoff and
  never the server clock.

Deterministic selection rules (documented in README):

1. Only evidence received no later than ``knowledge_cutoff`` with a valid
   signature and matching scope is considered.
2. Clearance (GOOD / no-entry) evidence must have been current at
   ``signed_at``: ``this_update <= signed_at <= next_update``. A REVOKED
   response is an archival record of an earlier event: it is decisive when
   ``revocation_date <= signed_at`` even if produced after ``signed_at``
   (provided it was possessed by the cutoff).
3. A delta CRL merges only with a complete CRL sharing issuer, AKI,
   distribution point and whose cRLNumber equals the delta's
   baseCRLNumber; removeFromCRL entries delete base entries.
4. Among decisive items the newest generation time wins; ties prefer OCSP,
   then the smaller evidence fingerprint.
5. Outcomes: GOOD / REVOKED / UNKNOWN / STALE / MALFORMED_EVIDENCE, with the
   disposition of every considered item recorded.
"""
from __future__ import annotations

import dataclasses
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID

from . import evidence as ev
from .certmodel import (
    ParsedCert,
    parse_certificate,
    verify_cert_signature,
)
from .errors import MalformedEvidenceError

DP_OID = "2.5.29.31"  # cRLDistributionPoints


@dataclasses.dataclass
class _IssuerIdentity:
    cert: ParsedCert
    raw: bytes


def _sha1(b: bytes) -> bytes:
    return hashlib.sha1(b).digest()


class RevocationEngine:
    """Resolves the revocation status of certificates within one sealed set.

    ``cert_loader(digest) -> ParsedCert`` and evidence indexes are supplied by
    the graph/adjudication layer.
    """

    def __init__(self, crls: dict[str, ev.CrlObject], ocsps: dict[str, ev.OcspObject],
                 cert_loader, anchors_by_name_key, signed_at: int, cutoff: int):
        self.crls = crls
        self.ocsps = ocsps
        self.load_cert = cert_loader
        self.anchors_by_name_key = anchors_by_name_key  # (name_der, key) -> ParsedCert
        self.signed_at = signed_at
        self.cutoff = cutoff
        self._cache: dict[str, dict] = {}

    # -------------------------------------------------- signer resolution
    def _issuer_certs(self, name_der: bytes, ski: bytes | None) -> list[ParsedCert]:
        out = self.load_cert.by_issuer(name_der, ski)
        if not out:
            anchor = self.anchors_by_name_key.get((name_der, ski)) if ski else None
            if anchor is not None:
                out = [anchor]
        return out

    # ------------------------------------------------------------- CRL
    def _crl_scope_ok(self, crl: ev.CrlObject, cert: ParsedCert) -> tuple[bool, str]:
        # onlyContains flags
        if cert.is_ca and crl.only_user_certs:
            return False, "scope: CRL only contains user certificates"
        if not cert.is_ca and crl.only_ca_certs:
            return False, "scope: CRL only contains CA certificates"
        # Distribution point matching.
        cert_dp_uris: set[str] = set()
        try:
            dps = cert.cert.extensions.get_extension_for_oid(
                x509.ObjectIdentifier(DP_OID)).value
            for dp in dps:
                if dp.full_name:
                    for gn in dp.full_name:
                        if isinstance(gn, x509.UniformResourceIdentifier):
                            cert_dp_uris.add(gn.value.lower())
        except x509.ExtensionNotFound:
            dps = None
        if crl.idp_uris:
            if not cert_dp_uris:
                return False, "scope: certificate names no matching CRL distribution point"
            if not set(crl.idp_uris) & cert_dp_uris:
                return False, "scope: IDP distribution point not named by certificate"
        return True, ""

    def _verify_crl_signer(self, crl: ev.CrlObject, cert: ParsedCert):
        """Find a key that signed this CRL for cert's issuer. Returns cert or None."""
        issuers = self._issuer_certs(cert.issuer_der, crl.aki or cert.aki)
        for ic in issuers:
            if ic.subject_der != crl.issuer_der:
                continue
            ok, err = ev.verify_crl_signature(crl, ic.cert)
            if not ok:
                continue
            if "cRLSign" not in ic.key_usage and ic.key_usage:
                # KU extension present without cRLSign -> not a valid CRL signer.
                continue
            return ic
        return None

    def _merge_base_delta(self, base: ev.CrlObject, delta: ev.CrlObject | None):
        entries = dict(base.entries)
        if delta is None:
            return entries
        for serial, e in delta.entries.items():
            if e.removed:
                entries.pop(serial, None)
            else:
                entries[serial] = e
        return entries

    def _crl_candidates(self, cert: ParsedCert):
        """Yield (combo_key, base, delta|None, entries, scope_reason)."""
        bases, deltas = [], []
        for crl in self.crls.values():
            if crl.issuer_der != cert.issuer_der:
                continue
            if crl.aki and cert.aki and crl.aki != cert.aki:
                continue
            (bases if not crl.is_delta else deltas).append(crl)
        combos = []
        for base in bases:
            chosen_delta = None
            for d in deltas:
                compatible = (
                    d.issuer_der == base.issuer_der
                    and (d.aki or b"") == (base.aki or b"")
                    and tuple(sorted(d.idp_uris)) == tuple(sorted(base.idp_uris))
                    and d.base_crl_number == base.crl_number
                    and (d.crl_number is None or base.crl_number is None
                         or d.crl_number > base.crl_number)
                )
                if compatible and (chosen_delta is None
                                   or (d.crl_number or -1) > (chosen_delta.crl_number or -1)
                                   or (d.crl_number == chosen_delta.crl_number
                                       and d.fingerprint < chosen_delta.fingerprint)):
                    chosen_delta = d
            combos.append((base, chosen_delta))
        return combos

    def _eval_crl(self, cert: ParsedCert, considered: list[dict]) -> dict | None:
        """Return a decision item dict for the best usable CRL combo, or None."""
        t = self.signed_at
        usable = []  # (generation, fingerprint, result)
        scope_candidates = 0
        crypto_failures = 0
        stale_any = False
        for base, delta in self._crl_candidates(cert):
            for crl in [base] + ([delta] if delta else []):
                if crl.fingerprint in {c["fingerprint"] for c in considered}:
                    continue
            scope_ok, scope_reason = self._crl_scope_ok(base, cert)
            considered.append({
                "kind": "crl", "fingerprint": base.fingerprint,
                "received_at": base.received_at,
                "eligible": base.received_at <= self.cutoff,
                "decision": "EXCLUDED",
                "reason": "not_received_by_knowledge_cutoff"
                if base.received_at > self.cutoff else (scope_reason or "pending"),
            })
            if delta is not None:
                considered.append({
                    "kind": "delta_crl", "fingerprint": delta.fingerprint,
                    "received_at": delta.received_at,
                    "eligible": delta.received_at <= self.cutoff,
                    "decision": "EXCLUDED",
                    "reason": "not_received_by_knowledge_cutoff"
                    if delta.received_at > self.cutoff else "pending",
                })
            if base.received_at > self.cutoff:
                continue
            if delta is not None and delta.received_at > self.cutoff:
                delta = None  # fall back to base alone
            if not scope_ok:
                continue
            scope_candidates += 1
            signer = self._verify_crl_signer(base, cert)
            if signer is None:
                crypto_failures += 1
                self._mark(considered, base.fingerprint, "signature_or_signer_unverified")
                if delta:
                    self._mark(considered, delta.fingerprint, "base_unverified")
                continue
            if delta is not None:
                dsig = self._verify_crl_signer(delta, cert)
                if dsig is None:
                    self._mark(considered, delta.fingerprint, "signature_or_signer_unverified")
                    delta = None
            # Freshness at signed_at.
            window_base = base.last_update <= t and (
                base.next_update is None or t <= base.next_update)
            window_delta = delta is None or (
                delta.last_update <= t and (
                    delta.next_update is None or t <= delta.next_update))
            if not window_base or not window_delta:
                stale_any = True
                self._mark(considered, base.fingerprint,
                           "stale_at_signed_at" if not window_base else "current")
                if delta is not None:
                    self._mark(considered, delta.fingerprint,
                               "stale_at_signed_at" if not window_delta else "current")
                continue
            entries = self._merge_base_delta(base, delta)
            e = entries.get(cert.serial)
            if e is not None and not e.removed and e.revocation_date <= t:
                status, rev = "REVOKED", e
            else:
                status, rev = "GOOD", None
            generation = (delta.last_update if delta else base.last_update)
            fp_key = delta.fingerprint if delta else base.fingerprint
            self._mark(considered, base.fingerprint, "USED_BASE" if delta else "USED",
                       decision="USED")
            if delta is not None:
                self._mark(considered, delta.fingerprint, "USED_DELTA", decision="USED")
            usable.append({
                "generation": generation,
                "kind_rank": 1,
                "fingerprint": fp_key,
                "status": status,
                "entry": rev,
                "base": base.fingerprint,
                "delta": delta.fingerprint if delta else None,
                "signer": signer.fingerprint,
            })
        if not usable:
            return {"scope_candidates": scope_candidates,
                    "crypto_failures": crypto_failures, "stale": stale_any}
        usable.sort(key=lambda u: (-u["generation"], u["kind_rank"], u["fingerprint"]))
        return {"best": usable[0]}

    @staticmethod
    def _mark(considered, fp, reason, decision="EXCLUDED"):
        for c in considered:
            if c["fingerprint"] == fp and c["reason"] in ("pending", "current"):
                c["decision"] = decision
                c["reason"] = reason

    # ------------------------------------------------------------- OCSP
    def _ocsp_match(self, resp: ev.OcspObject, cert: ParsedCert, single: ev.SingleOcsp):
        if single.serial != cert.serial:
            return None
        # Find issuer identities (name + key) and recompute certID hashes.
        issuers = self._issuer_certs(cert.issuer_der, cert.aki)
        for ic in issuers:
            nh, kh = ev.certid_hashes(ic.subject_der, ic.spki_bitstring, single.hash_alg)
            if nh == single.issuer_name_hash and kh == single.issuer_key_hash:
                return ic
        return None

    def _ocsp_responder(self, resp: ev.OcspObject, issuer: ParsedCert):
        """Validate direct-CA or delegated responder; return (ok, reason)."""
        # Direct CA responder?
        if resp.responder_name_der == issuer.subject_der:
            return issuer, None
        if resp.responder_key_hash is not None and \
                resp.responder_key_hash == _sha1(issuer.spki_bitstring):
            return issuer, None
        # Delegated responder among embedded certs.
        for raw in resp.embedded_certs:
            try:
                rc = parse_certificate(raw)
            except Exception:
                continue
            # RFC 6960 §4.2.2.3: byKey KeyHash is SHA-1 of the responder's
            # public key BIT STRING (excluding tag/length), NOT the SKI ext.
            id_match = (
                (resp.responder_name_der is not None
                 and resp.responder_name_der == rc.subject_der)
                or (resp.responder_key_hash is not None
                    and resp.responder_key_hash == _sha1(rc.spki_bitstring)))
            if not id_match:
                continue
            if rc.issuer_der != issuer.subject_der:
                continue
            ok, err = verify_cert_signature(rc, issuer)
            if not ok:
                return None, "delegated_responder_signature"
            if rc.eku is None or "1.3.6.1.5.5.7.3.9" not in rc.eku:
                return None, "delegated_responder_missing_ocsp_signing_eku"
            if rc.is_ca:
                return None, "delegated_responder_must_not_be_ca"
            if "digitalSignature" not in rc.key_usage and rc.key_usage:
                return None, "delegated_responder_key_usage"
            if not (rc.not_before <= self.signed_at <= rc.not_after):
                nocheck = False
                try:
                    rc.cert.extensions.get_extension_for_oid(
                        x509.ObjectIdentifier(ev.OID_OCSP_NO_CHECK))
                    nocheck = True
                except x509.ExtensionNotFound:
                    nocheck = False
                if not nocheck:
                    return None, "delegated_responder_expired_at_signed_at"
            return rc, None
        return None, "responder_identity_unresolved"

    def _eval_ocsp(self, cert: ParsedCert, considered: list[dict]) -> dict | None:
        t = self.signed_at
        usable = []
        scope_candidates = 0
        crypto_failures = 0
        stale_any = False
        for resp in self.ocsps.values():
            single = resp.responses.get(cert.serial)
            if single is None:
                continue
            considered.append({
                "kind": "ocsp", "fingerprint": resp.fingerprint,
                "received_at": resp.received_at,
                "eligible": resp.received_at <= self.cutoff,
                "decision": "EXCLUDED",
                "reason": "not_received_by_knowledge_cutoff"
                if resp.received_at > self.cutoff else "pending",
            })
            if resp.received_at > self.cutoff:
                continue
            scope_candidates += 1
            issuer = self._ocsp_match(resp, cert, single)
            if issuer is None:
                crypto_failures += 1
                self._mark(considered, resp.fingerprint, "certid_does_not_match_issuer")
                continue
            responder, reason = self._ocsp_responder(resp, issuer)
            if responder is None:
                crypto_failures += 1
                self._mark(considered, resp.fingerprint, reason)
                continue
            ok, _err = ev.verify_ocsp_signature(resp, responder.cert.public_key())
            if not ok:
                crypto_failures += 1
                self._mark(considered, resp.fingerprint, "signature_unverified")
                continue
            effective_revoked = (single.status == "REVOKED"
                                 and single.revocation_time is not None
                                 and single.revocation_time <= t)
            later_revocation = (single.status == "REVOKED"
                                and single.revocation_time is not None
                                and single.revocation_time > t)
            window_ok = single.this_update <= t and (
                single.next_update is None or t <= single.next_update)
            if not effective_revoked and not window_ok:
                stale_any = True
                self._mark(considered, resp.fingerprint, "stale_at_signed_at")
                continue
            if later_revocation:
                status = "GOOD"  # revocation event is after the signing time
            else:
                status = single.status
            self._mark(considered, resp.fingerprint, "USED", decision="USED")
            usable.append({
                "generation": single.this_update,
                "kind_rank": 0,
                "fingerprint": resp.fingerprint,
                "status": status,
                "entry": single,
                "responder": responder.fingerprint,
            })
        if not usable:
            return {"scope_candidates": scope_candidates,
                    "crypto_failures": crypto_failures, "stale": stale_any}
        usable.sort(key=lambda u: (-u["generation"], u["kind_rank"], u["fingerprint"]))
        return {"best": usable[0]}

    # --------------------------------------------------------- public API
    def evaluate(self, cert: ParsedCert) -> dict:
        if cert.fingerprint in self._cache:
            return self._cache[cert.fingerprint]
        considered: list[dict] = []
        crl_res = self._eval_crl(cert, considered)
        ocsp_res = self._eval_ocsp(cert, considered)

        best = []
        crl_fail = ocsp_fail = None
        if crl_res and "best" in crl_res:
            best.append(crl_res["best"])
        else:
            crl_fail = crl_res
        if ocsp_res and "best" in ocsp_res:
            best.append(ocsp_res["best"])
        else:
            ocsp_fail = ocsp_res

        if best:
            best.sort(key=lambda u: (-u["generation"], u["kind_rank"], u["fingerprint"]))
            win = best[0]
            conclusion = win["status"]
            selected = {
                "kind": "ocsp" if win["kind_rank"] == 0 else "crl",
                "fingerprint": win["fingerprint"],
                "generation_time": win["generation"],
                "signer": win.get("responder") or win.get("signer"),
            }
            if "base" in win:
                selected["base"] = win["base"]
                selected["delta"] = win["delta"]
            entry = win.get("entry")
            rev_time = getattr(entry, "revocation_time", None)
            reason = getattr(entry, "reason", None)
        else:
            selected = None
            rev_time = reason = None
            fails = [f for f in (crl_fail, ocsp_fail) if f]
            scope_total = sum(f.get("scope_candidates", 0) for f in fails)
            crypto_total = sum(f.get("crypto_failures", 0) for f in fails)
            stale_total = sum(1 for f in fails if f.get("stale"))
            if scope_total == 0:
                conclusion = "UNKNOWN"
            elif stale_total and crypto_total == 0 and scope_total <= stale_total:
                conclusion = "STALE"
            elif crypto_total and crypto_total >= scope_total - stale_total:
                conclusion = "MALFORMED_EVIDENCE"
            elif stale_total:
                conclusion = "STALE"
            else:
                conclusion = "UNKNOWN"

        # Finalise considered entries: normalize leftover reasons.
        for c in considered:
            if c["reason"] == "pending":
                c["reason"] = "not_applicable"
                c["decision"] = "EXCLUDED"
            elif c["reason"] == "current":
                c["reason"] = "superseded_by_newer_evidence"
            elif c["reason"] == "USED_BASE":
                c["reason"] = "used_as_base_crl"
            elif c["reason"] == "USED_DELTA":
                c["reason"] = "used_as_delta_crl"
        considered.sort(key=lambda c: (c["kind"], c["fingerprint"]))

        result = {
            "certificate": cert.fingerprint,
            "conclusion": conclusion,
            "revocation_time": rev_time,
            "revocation_reason": reason,
            "selected_evidence": selected,
            "considered_evidence": considered,
            "timelines": {
                "signed_at": self.signed_at,
                "knowledge_cutoff": self.cutoff,
            },
        }
        self._cache[cert.fingerprint] = result
        return result

    def snapshot(self) -> list[dict]:
        """All revocation evaluations performed (any cert on any attempted
        path), deterministically ordered — embedded in the result so the
        evidence package can be independently re-computed from a subset."""
        return [self._cache[k] for k in sorted(self._cache)]
