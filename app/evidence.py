"""CRL / OCSP evidence parsing and cryptographic validation.

Every piece of revocation evidence is verified before it can influence any
result: the TBS signature is checked against a real issuer public key found
in the certificate graph (never against a key claimed inside the evidence),
scopes (IDP / certID) are matched cryptographically, and nothing is fetched
from the network.
"""
from __future__ import annotations

import dataclasses
import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID

from . import der
from .certmodel import OID_EKU_OCSP_SIGNING, _hash, fp_of
from .errors import MalformedEvidenceError, UnsupportedError

OID_DELTA_CRL_INDICATOR = "2.5.29.31.27"
OID_CRL_NUMBER = "2.5.29.20"
OID_ISSUING_DP = "2.5.29.28.7"
OID_FRESHEST_CRL = "2.5.29.46"
OID_OCSP_NO_CHECK = "1.3.6.1.5.5.7.48.1.5"

# Reason flags relevant to revocation decisions.
_REASON_CODES = {
    x509.ReasonFlags.key_compromise: "keyCompromise",
    x509.ReasonFlags.ca_compromise: "cACompromise",
    x509.ReasonFlags.affiliation_changed: "affiliationChanged",
    x509.ReasonFlags.superseded: "superseded",
    x509.ReasonFlags.cessation_of_operation: "cessationOfOperation",
    x509.ReasonFlags.certificate_hold: "certificateHold",
    x509.ReasonFlags.privilege_withdrawn: "privilegeWithdrawn",
    x509.ReasonFlags.aa_compromise: "aACompromise",
    x509.ReasonFlags.remove_from_crl: "removeFromCRL",
    x509.ReasonFlags.unspecified: "unspecified",
}


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


@dataclasses.dataclass
class RevokedEntry:
    serial: int
    revocation_date: int
    reason: str
    removed: bool  # removeFromCRL (delta CRL only)


@dataclasses.dataclass
class CrlObject:
    raw: bytes
    fingerprint: str
    received_at: int
    is_delta: bool
    issuer_der: bytes
    aki: bytes | None
    crl_number: int | None
    base_crl_number: int | None  # delta CRL indicator
    last_update: int
    next_update: int | None
    indirect: bool
    only_user_certs: bool
    only_ca_certs: bool
    # distribution point full URIs from the IDP extension
    idp_uris: tuple[str, ...]
    entries: dict[int, RevokedEntry]
    sig_oid: str
    sig_hash: str | None

    def entry_for(self, serial: int) -> RevokedEntry | None:
        return self.entries.get(serial)


@dataclasses.dataclass
class OcspObject:
    raw: bytes
    fingerprint: str
    received_at: int
    sig_oid: str
    responder_name_der: bytes | None
    responder_key_hash: bytes | None
    # serial -> single response
    responses: dict[int, "SingleOcsp"]
    # embedded delegated-responder certs (DER)
    embedded_certs: tuple[bytes, ...]


@dataclasses.dataclass
class SingleOcsp:
    serial: int
    hash_alg: str
    issuer_name_hash: bytes
    issuer_key_hash: bytes
    status: str  # GOOD / REVOKED / UNKNOWN
    revocation_time: int | None
    reason: str | None
    this_update: int
    next_update: int | None


def _crl_sig_parts(raw: bytes):
    # CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
    tag, body, _ = der.tlv(raw)
    if tag != der.SEQUENCE:
        raise MalformedEvidenceError("CRL: expected SEQUENCE")
    elems = list(der.iter_tlv(body))
    if len(elems) != 3 or elems[1][0] != der.SEQUENCE or elems[2][0] != der.BIT_STRING:
        raise MalformedEvidenceError("CRL: bad structure")
    tbs = der.build_tlv(elems[0][0], elems[0][1])
    sigval = elems[2][1]
    if not sigval or sigval[0] != 0:
        raise MalformedEvidenceError("CRL: signature unused bits")
    alg_parts = list(der.iter_tlv(elems[1][1]))
    if not alg_parts or alg_parts[0][0] != der.OID:
        raise MalformedEvidenceError("CRL: bad algorithm identifier")
    oid = der.decode_oid(alg_parts[0][1])
    params = alg_parts[1][1] if len(alg_parts) > 1 else None
    return tbs, sigval[1:], oid, params


def parse_crl(raw: bytes, received_at: int) -> CrlObject:
    crl = x509.load_der_x509_crl(raw)
    tbs, _sig, sig_oid, params = _crl_sig_parts(raw)
    from .errors import SUPPORTED_SIG_ALGS

    if sig_oid not in SUPPORTED_SIG_ALGS:
        raise UnsupportedError("CRL signature algorithm outside profile", {"oid": sig_oid})
    if sig_oid != "1.2.840.113549.1.1.10" and params not in (None, b""):
        raise UnsupportedError("CRL: unexpected signature parameters")
    crl_pss = None
    if sig_oid == "1.2.840.113549.1.1.10":
        from .certmodel import parse_pss_params

        p = parse_pss_params(params)
        crl_pss = {"hash": p["hash_name"], "salt_length": p["salt_length"]}
        if p["salt_length"] != _hash(p["hash_name"]).digest_size:
            raise UnsupportedError("CRL RSA-PSS parameters outside profile")

    crl_number = None
    try:
        crl_number = crl.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(OID_CRL_NUMBER)).value.crl_number
    except x509.ExtensionNotFound:
        pass

    is_delta = False
    base_number = None
    try:
        d = crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator).value
        is_delta = True
        base_number = d.crl_number
    except x509.ExtensionNotFound:
        pass

    aki = None
    try:
        aki = crl.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
    except x509.ExtensionNotFound:
        pass

    idp_uris: tuple[str, ...] = ()
    indirect = only_user = only_ca = False
    try:
        idp = crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint).value
        indirect = bool(idp.indirect_crl)
        only_user = bool(idp.only_contains_user_certs)
        only_ca = bool(idp.only_contains_ca_certs)
        if idp.only_contains_attribute_certs:
            raise UnsupportedError("attribute certificate CRLs are outside profile")
        if idp.only_some_reasons is not None:
            # Only the standard reason subset may be present; all reasons are
            # represented, entries outside the subset would be authoritative
            # for their reasons. Profile keeps full-scope CRLs only.
            raise UnsupportedError("CRL with onlySomeReasons partition is outside profile")
        if idp.distribution_point is not None and idp.distribution_point.full_name:
            uris = []
            for gn in idp.distribution_point.full_name:
                if isinstance(gn, x509.UniformResourceIdentifier):
                    uris.append(gn.value.lower())
                else:
                    raise UnsupportedError("IDP fullName: only URI general names supported")
            idp_uris = tuple(sorted(uris))
    except x509.ExtensionNotFound:
        pass

    if indirect:
        # Indirect CRLs require per-entry certIssuer handling; out of profile.
        raise UnsupportedError("indirect CRLs are outside profile")

    entries: dict[int, RevokedEntry] = {}
    for rc in crl:
        reason = "unspecified"
        removed = False
        try:
            rf = rc.extensions.get_extension_for_class(x509.CRLReason).value.reason
            if rf == x509.ReasonFlags.remove_from_crl:
                removed = True
                reason = "removeFromCRL"
            else:
                reason = _REASON_CODES.get(rf, "unspecified")
        except x509.ExtensionNotFound:
            pass
        entries[rc.serial_number] = RevokedEntry(
            serial=rc.serial_number,
            revocation_date=int(rc.revocation_date_utc.timestamp()),
            reason=reason,
            removed=removed,
        )

    return CrlObject(
        raw=raw,
        fingerprint=fp_of(raw),
        received_at=int(received_at),
        is_delta=is_delta,
        issuer_der=crl.issuer.public_bytes(),
        aki=aki,
        crl_number=crl_number,
        base_crl_number=base_number,
        last_update=int(crl.last_update_utc.timestamp()),
        next_update=int(crl.next_update_utc.timestamp()) if crl.next_update_utc else None,
        indirect=False,
        only_user_certs=only_user,
        only_ca_certs=only_ca,
        idp_uris=idp_uris,
        entries=entries,
        sig_oid=sig_oid,
        sig_hash=(crl_pss["hash"] if crl_pss else
                  (crl.signature_hash_algorithm.name
                   if crl.signature_hash_algorithm else None)),
    )


def verify_crl_signature(crl_obj: CrlObject, issuer_cert) -> tuple[bool, str | None]:
    """issuer_cert is a cryptography x509.Certificate whose key signed the CRL."""
    try:
        tbs, sig, oid, params = _crl_sig_parts(crl_obj.raw)
        pss = None
        if oid == "1.2.840.113549.1.1.10":
            from .certmodel import parse_pss_params
            pp = parse_pss_params(params)
            pss = {"salt_length": pp["salt_length"]}
        _verify_with(issuer_cert.public_key(), sig, tbs, oid,
                     hash_name=crl_obj.sig_hash, pss_params=pss)
        return True, None
    except InvalidSignature:
        return False, "SIGNATURE"
    except UnsupportedError:
        return False, "UNSUPPORTED"
    except Exception:
        return False, "SIGNATURE"


def _sig_hash(obj, oid):
    # obj.cert-style: cryptography object exposes signature_hash_algorithm
    h = obj.signature_hash_algorithm if hasattr(obj, "signature_hash_algorithm") else None
    return h.name if h else None


def _verify_with(pub, sig: bytes, tbs: bytes, oid: str, hash_name: str | None,
                  pss_params=None):
    if oid in ("1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12",
               "1.2.840.113549.1.1.13"):
        if not isinstance(pub, rsa.RSAPublicKey):
            raise UnsupportedError("CRL/OCSP alg/key mismatch")
        pub.verify(sig, tbs, padding.PKCS1v15(), _hash(hash_name))
    elif oid == "1.2.840.113549.1.1.10":
        if not isinstance(pub, rsa.RSAPublicKey):
            raise UnsupportedError("CRL/OCSP alg/key mismatch")
        salt = pss_params["salt_length"] if pss_params else _hash(hash_name).digest_size
        pub.verify(sig, tbs,
                   padding.PSS(mgf=padding.MGF1(_hash(hash_name)),
                               salt_length=salt),
                   _hash(hash_name))
    elif oid in ("1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3",
                 "1.2.840.10045.4.3.4"):
        if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(
                pub.curve, ec.SECP256R1):
            raise UnsupportedError("CRL/OCSP alg/key mismatch")
        pub.verify(sig, tbs, ec.ECDSA(_hash(hash_name)))
    elif oid == "1.3.101.112":
        if not isinstance(pub, ed25519.Ed25519PublicKey):
            raise UnsupportedError("CRL/OCSP alg/key mismatch")
        pub.verify(sig, tbs)
    else:
        raise UnsupportedError("signature algorithm outside profile", {"oid": oid})


def _ocsp_sig_algorithm(raw: bytes) -> tuple[str, bytes | None]:
    """Extract (alg OID, raw params value) of the signatureAlgorithm inside
    BasicOCSPResponse straight from the DER."""
    _t, outer, _ = der.tlv(raw)
    elems = list(der.iter_tlv(outer))
    if len(elems) < 2 or elems[1][0] != 0xA0:
        raise MalformedEvidenceError("OCSP: missing responseBytes")
    # [0] EXPLICIT ResponseBytes
    rb = elems[1][1]
    _t2, rb_body, _ = der.tlv(rb)
    rb_parts = list(der.iter_tlv(rb_body))
    if len(rb_parts) < 2 or rb_parts[0][0] != der.OID or rb_parts[1][0] != der.OCTET_STRING:
        raise MalformedEvidenceError("OCSP: bad responseBytes")
    if der.decode_oid(rb_parts[0][1]) != "1.3.6.1.5.5.7.48.1.1":
        raise UnsupportedError("OCSP: only id-pkix-ocsp-basic is supported")
    basic = rb_parts[1][1]
    _t3, basic_body, _ = der.tlv(basic)
    bparts = list(der.iter_tlv(basic_body))
    if len(bparts) < 3:
        raise MalformedEvidenceError("OCSP: bad BasicOCSPResponse")
    # bparts[1] = signatureAlgorithm AlgorithmIdentifier SEQUENCE
    alg_t, alg_v = bparts[1]
    if alg_t != der.SEQUENCE:
        raise MalformedEvidenceError("OCSP: bad signatureAlgorithm")
    ap = list(der.iter_tlv(alg_v))
    if not ap or ap[0][0] != der.OID:
        raise MalformedEvidenceError("OCSP: bad algorithm OID")
    oid = der.decode_oid(ap[0][1])
    params = ap[1][1] if len(ap) > 1 else None
    return oid, params


def parse_ocsp(raw: bytes, received_at: int) -> OcspObject:
    resp = ocsp.load_der_ocsp_response(raw)
    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise MalformedEvidenceError(
            "OCSP response not successful",
            {"status": resp.response_status.name})
    sig_oid = resp.signature_algorithm_oid.dotted_string
    from .errors import SUPPORTED_SIG_ALGS

    if sig_oid not in SUPPORTED_SIG_ALGS:
        raise UnsupportedError("OCSP signature algorithm outside profile", {"oid": sig_oid})
    # Strict parameter handling straight from the DER.
    ocsp_sig_oid, ocsp_params = _ocsp_sig_algorithm(raw)
    if ocsp_sig_oid != sig_oid:
        raise MalformedEvidenceError("OCSP: signature algorithm mismatch")
    if sig_oid == "1.2.840.113549.1.1.10":
        from .certmodel import parse_pss_params

        _pss = parse_pss_params(ocsp_params)
    elif ocsp_params not in (None, b""):
        raise UnsupportedError("OCSP: unexpected signature parameters")

    singles: dict[int, SingleOcsp] = {}
    # cryptography exposes ``responses`` as a one-shot Rust iterator; consume
    # it exactly once into a materialized list.
    raw_singles = list(resp.responses)
    for sr in raw_singles:
        status = {
            ocsp.OCSPCertStatus.GOOD: "GOOD",
            ocsp.OCSPCertStatus.REVOKED: "REVOKED",
            ocsp.OCSPCertStatus.UNKNOWN: "UNKNOWN",
        }[sr.certificate_status]
        reason = None
        rev_time = None
        if status == "REVOKED":
            rev_time = int(sr.revocation_time_utc.timestamp())
            rf = sr.revocation_reason
            if rf is not None:
                reason = _REASON_CODES.get(rf, "unspecified")
        alg_name = sr.hash_algorithm.name
        if alg_name not in ("sha1", "sha256", "sha384", "sha512"):
            raise UnsupportedError("OCSP certID hash outside profile", {"hash": alg_name})
        singles[sr.serial_number] = SingleOcsp(
            serial=sr.serial_number,
            hash_alg=alg_name,
            issuer_name_hash=sr.issuer_name_hash,
            issuer_key_hash=sr.issuer_key_hash,
            status=status,
            revocation_time=rev_time,
            reason=reason,
            this_update=int(sr.this_update_utc.timestamp()),
            next_update=int(sr.next_update_utc.timestamp()) if sr.next_update_utc else None,
        )

    from cryptography.hazmat.primitives.serialization import Encoding

    embedded = tuple(c.public_bytes(Encoding.DER) for c in (resp.certificates or []))
    return OcspObject(
        raw=raw,
        fingerprint=fp_of(raw),
        received_at=int(received_at),
        sig_oid=sig_oid,
        responder_name_der=resp.responder_name.public_bytes() if resp.responder_name else None,
        responder_key_hash=resp.responder_key_hash,
        responses=singles,
        embedded_certs=embedded,
    )


def ocsp_tbs_signature(raw: bytes) -> tuple[bytes, bytes, str]:
    """Return (tbs_responseData DER, signature, alg_oid) from raw OCSP response.

    We must sign over the exact responseData DER that cryptography signed;
    cryptography exposes ``tbs_response_bytes`` for that purpose.
    """
    resp = ocsp.load_der_ocsp_response(raw)
    return (resp.tbs_response_bytes, resp.signature,
            resp.signature_algorithm_oid.dotted_string)


def verify_ocsp_signature(ocsp_obj: OcspObject, pub) -> tuple[bool, str | None]:
    try:
        tbs, sig, oid = ocsp_tbs_signature(ocsp_obj.raw)
        resp = ocsp.load_der_ocsp_response(ocsp_obj.raw)
        h = resp.signature_hash_algorithm
        pss = None
        if oid == "1.2.840.113549.1.1.10":
            _oid2, params = _ocsp_sig_algorithm(ocsp_obj.raw)
            from .certmodel import parse_pss_params

            pp = parse_pss_params(params)
            pss = {"salt_length": pp["salt_length"]}
        _verify_with(pub, sig, tbs, oid, h.name if h else None,
                     pss_params=pss)
        return True, None
    except InvalidSignature:
        return False, "SIGNATURE"
    except UnsupportedError:
        return False, "UNSUPPORTED"
    except Exception:
        return False, "SIGNATURE"


def certid_hashes(name_der: bytes, spki_key_bytes: bytes, alg: str) -> tuple[bytes, bytes]:
    """issuerNameHash / issuerKeyHash as RFC 6960 defines them.

    issuerKeyHash is over the subjectPublicKey BIT STRING content (the key
    itself), excluding tag/length/unused-bits octet.
    """
    alg_cls = {"sha1": hashes.SHA1, "sha256": hashes.SHA256,
               "sha384": hashes.SHA384, "sha512": hashes.SHA512}[alg]
    nh = hashes.Hash(alg_cls())
    kh = hashes.Hash(alg_cls())
    nh.update(name_der)
    kh.update(spki_key_bytes)
    return nh.finalize(), kh.finalize()
