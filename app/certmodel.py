"""Certificate parsing, profile enforcement and signature verification.

Nothing here trusts uploaded parsed fields: every signature is verified with
the issuer public key over the real TBS bytes, and profile conformance is
checked from the DER, not from client-supplied metadata.
"""
from __future__ import annotations

import dataclasses
import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa, utils
from cryptography.x509.oid import ExtensionOID

from . import der
from .errors import (
    OID_ANY_POLICY,
    OID_EKU_CODE_SIGNING,
    OID_EKU_OCSP_SIGNING,
    SUPPORTED_HASHES,
    SUPPORTED_NAMED_CURVES,
    SUPPORTED_PUBLIC_KEY_ALGS,
    SUPPORTED_RSA_SIZES,
    SUPPORTED_SIG_ALGS,
    MalformedEvidenceError,
    UnsupportedError,
)

OID_POLICY_MAPPINGS = "2.5.29.33"
OID_POLICY_CONSTRAINTS = "2.5.29.36"
OID_INHIBIT_ANY_POLICY = "2.5.29.54"
OID_CPS = "1.3.6.1.5.5.7.2.1"
OID_USER_NOTICE = "1.3.6.1.5.5.7.2.2"
OID_RSA_PSS = "1.2.840.113549.1.1.10"
OID_PKCS1_SHA1 = "1.2.840.113549.1.1.5"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_RSA_KEY = "1.2.840.113549.1.1.1"
OID_ED25519 = "1.3.101.112"


def fp_of(der_bytes: bytes) -> str:
    return hashlib.sha256(der_bytes).hexdigest()


def _raw_sig_algorithm(cert_der: bytes) -> tuple[str, bytes | None, bytes, bytes]:
    """Extract (outer_alg_oid, outer_params_der, tbs_bytes, signature_bytes)
    straight from the Certificate DER, and confirm the TBS alg OID matches."""
    tag, body, _ = der.tlv(cert_der)
    if tag != der.SEQUENCE:
        raise MalformedEvidenceError("certificate: expected SEQUENCE")
    elems = list(der.iter_tlv(body))
    if len(elems) < 3:
        raise MalformedEvidenceError("certificate: truncated")
    tbs_tag, tbs = elems[0]
    alg_tag, alg_val = elems[1]
    sig_tag, sig_val = elems[2]
    if tbs_tag != der.SEQUENCE or alg_tag != der.SEQUENCE or sig_tag != der.BIT_STRING:
        raise MalformedEvidenceError("certificate: bad structure")
    if not sig_val or sig_val[0] != 0:
        raise MalformedEvidenceError("certificate: signature unused bits")
    alg_parts = list(der.iter_tlv(alg_val))
    if not alg_parts or alg_parts[0][0] != der.OID:
        raise MalformedEvidenceError("certificate: bad signatureAlgorithm")
    outer_oid = der.decode_oid(alg_parts[0][1])
    outer_params = alg_parts[1][1] if len(alg_parts) > 1 else None
    # TBS: [0] version?, serial, sigAlg(inner), issuer ...
    tbs_elems = list(der.iter_tlv(tbs))
    idx = 0
    if tbs_elems and tbs_elems[0][0] == 0xA0:
        idx = 1
    if len(tbs_elems) < idx + 2:
        raise MalformedEvidenceError("certificate: truncated TBS")
    inner_tag, inner_alg_val = tbs_elems[idx + 1]
    if inner_tag != der.SEQUENCE:
        raise MalformedEvidenceError("certificate: bad inner signatureAlgorithm")
    inner_parts = list(der.iter_tlv(inner_alg_val))
    inner_oid = der.decode_oid(inner_parts[0][1])
    if inner_oid != outer_oid:
        raise MalformedEvidenceError("certificate: inner/outer signature algorithm mismatch")
    # The signature is computed over the full TBSCertificate TLV.
    tbs_tlv = der.build_tlv(tbs_tag, tbs)
    return outer_oid, outer_params, tbs_tlv, sig_val[1:]


def _check_validity_encoding(tbs_tlv: bytes) -> None:
    """Profile time rules: UTCTime Z (1950-2049) or GeneralizedTime Z with
    seconds and no fractional seconds."""
    _tag, tbs, _ = der.tlv(tbs_tlv)
    elems = list(der.iter_tlv(tbs))
    idx = 1 if elems and elems[0][0] == 0xA0 else 0
    # serial idx, sig idx+1, issuer idx+2, validity idx+3
    _, validity = elems[idx + 3]
    for tag, val in der.iter_tlv(validity):
        s = val.decode("ascii", "replace")
        if tag == 0x17:  # UTCTime
            if not s.endswith("Z") or len(s) != 13:
                raise MalformedEvidenceError("time: UTCTime must be YYMMDDHHMMSSZ")
            # YY 50-99 -> 19xx, 00-49 -> 20xx; validate the calendar date.
            import datetime as _dt

            yy = int(s[:2])
            year = 1900 + yy if yy >= 50 else 2000 + yy
            _dt.datetime.strptime(f"{year:04d}{s[2:-1]}", "%Y%m%d%H%M%S")
        elif tag == 0x18:  # GeneralizedTime
            if not s.endswith("Z") or "." in s or len(s) < 15:
                raise MalformedEvidenceError("time: GeneralizedTime must be YYYYMMDDHHMMSSZ, no fraction")
            import datetime as _dt

            _dt.datetime.strptime(s[:-1], "%Y%m%d%H%M%S")
        else:
            raise MalformedEvidenceError("time: bad validity time tag")


@dataclasses.dataclass
class PolicyInfo:
    oids: frozenset[str]
    present: bool


@dataclasses.dataclass
class ParsedCert:
    der: bytes
    fingerprint: str
    cert: x509.Certificate
    subject_der: bytes
    issuer_der: bytes
    ski: bytes | None
    aki: bytes | None
    serial: int
    not_before: int
    not_after: int
    is_ca: bool
    path_len: int | None
    key_usage: set[str]  # subset of keyCertSign,cRLSign,digitalSignature
    eku: frozenset[str] | None  # None = extension absent
    san_dns: tuple[str, ...]
    san_uri: tuple[str, ...]
    nc_permitted_dns: tuple[str, ...]
    nc_permitted_uri: tuple[str, ...]
    nc_excluded_dns: tuple[str, ...]
    nc_excluded_uri: tuple[str, ...]
    policies: PolicyInfo
    policy_mappings: tuple[tuple[str, str], ...]
    require_explicit_policy: int | None
    inhibit_policy_mapping: int | None
    inhibit_any_policy: int | None
    sig_oid: str
    sig_params_der: bytes | None
    sig_hash: str | None  # None for Ed25519; sha256/384/512 otherwise
    pss_salt_length: int | None
    spki_bitstring: bytes  # subjectPublicKey BIT STRING content (key bytes)


def _gn_dns_uri(gns, where: str):
    dns, uri = [], []
    for gn in gns:
        if isinstance(gn, x509.DNSName):
            dns.append(gn.value)
        elif isinstance(gn, x509.UniformResourceIdentifier):
            uri.append(gn.value)
        else:
            raise UnsupportedError(f"{where}: only DNS and URI general names are in profile",
                                   {"type": type(gn).__name__})
    for v in dns + uri:
        try:
            v.encode("ascii")
        except UnicodeEncodeError as exc:
            raise UnsupportedError(f"{where}: non-ASCII names are outside the profile") from exc
    return tuple(sorted(v.encode("ascii").decode().lower() for v in dns)), \
        tuple(sorted(v.encode("ascii").decode().lower() for v in uri))


def _spki_key_bytes(cert: x509.Certificate) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    _, body, _ = der.tlv(spki)
    elems = list(der.iter_tlv(body))
    bitval = elems[1][1]
    return bitval[1:]  # drop unused-bits octet


def parse_pss_params(params_value: bytes | None) -> dict:
    """Parse RSASSA-PSS-params from the AlgorithmIdentifier parameters.

    RSASSA-PSS-params ::= SEQUENCE {
        hashAlgorithm      [0] AlgorithmIdentifier DEFAULT sha1,
        maskGenAlgorithm   [1] AlgorithmIdentifier DEFAULT mgf1SHA1,
        saltLength         [2] INTEGER DEFAULT 20,
        trailerField       [3] INTEGER DEFAULT 1 }
    Defaults are deliberately treated as out of profile (SHA-1/20 bytes),
    so all fields must be present explicitly for acceptance.
    """
    if params_value is None:
        raise MalformedEvidenceError("RSA-PSS requires explicit parameters")
    # Accept either the full AlgorithmIdentifier parameters TLV or, when the
    # caller has already consumed one TLV layer, the SEQUENCE body.
    if params_value[:1] == bytes([der.SEQUENCE]):
        _t, body, _ = der.tlv(params_value)
    else:
        body = params_value
    seen: dict[int, bytes] = {}
    for t2, v2 in der.iter_tlv(body):
        if t2 & 0xC0 != 0x80 or (t2 & 0x1F) > 3:
            raise MalformedEvidenceError("RSA-PSS: unexpected parameter tag")
        seen[t2 & 0x1F] = v2

    def algid(v: bytes) -> str:
        at, ab, _ = der.tlv(v)
        if at != der.SEQUENCE:
            raise MalformedEvidenceError("RSA-PSS: expected AlgorithmIdentifier")
        parts = list(der.iter_tlv(ab))
        if not parts or parts[0][0] != der.OID:
            raise MalformedEvidenceError("RSA-PSS: bad AlgorithmIdentifier")
        oid = der.decode_oid(parts[0][1])
        return oid

    def integer(v: bytes) -> int:
        it, iv, _ = der.tlv(v)
        if it != der.INTEGER:
            raise MalformedEvidenceError("RSA-PSS: expected INTEGER")
        return int.from_bytes(iv, "big", signed=True)

    if 0 not in seen or 1 not in seen or 2 not in seen:
        raise UnsupportedError(
            "RSA-PSS requires explicit hash, MGF and saltLength")
    hash_oid = algid(seen[0])
    mgf_tag, mgf_body, _ = der.tlv(seen[1])
    if mgf_tag != der.SEQUENCE:
        raise MalformedEvidenceError("RSA-PSS: bad maskGenAlgorithm")
    mp = list(der.iter_tlv(mgf_body))
    if len(mp) < 2 or mp[0][0] != der.OID or \
            der.decode_oid(mp[0][1]) != "1.2.840.113549.1.1.8":
        raise UnsupportedError("RSA-PSS: only MGF1 is in profile")
    mgf_hash_oid = algid(der.build_tlv(mp[1][0], mp[1][1]))
    salt_len = integer(seen[2])
    # trailerField defaults to 1 when absent (RFC 4055).
    trailer = integer(seen[3]) if 3 in seen else 1
    from .errors import SUPPORTED_HASHES

    if hash_oid not in SUPPORTED_HASHES:
        raise UnsupportedError("RSA-PSS hash outside profile", {"oid": hash_oid})
    if mgf_hash_oid != hash_oid:
        raise UnsupportedError("RSA-PSS MGF hash must equal signature hash",
                               {"hash": hash_oid, "mgf_hash": mgf_hash_oid})
    digest_size = {"2.16.840.1.101.3.4.2.1": 32,
                   "2.16.840.1.101.3.4.2.2": 48,
                   "2.16.840.1.101.3.4.2.3": 64}[hash_oid]
    if salt_len != digest_size:
        raise UnsupportedError("RSA-PSS salt length must equal digest length",
                               {"salt": salt_len, "digest": digest_size})
    if trailer != 1:
        raise UnsupportedError("RSA-PSS trailer field must be 1")
    hash_name = {"2.16.840.1.101.3.4.2.1": "sha256",
                 "2.16.840.1.101.3.4.2.2": "sha384",
                 "2.16.840.1.101.3.4.2.3": "sha512"}[hash_oid]
    return {"hash_oid": hash_oid, "hash_name": hash_name,
            "salt_length": salt_len}


def _sig_hash_for_oid(oid: str, pss_info: dict | None) -> str | None:
    if oid == "1.3.101.112":
        return None
    if oid == "1.2.840.113549.1.1.10":
        return pss_info["hash_name"]
    return {
        "1.2.840.113549.1.1.11": "sha256",
        "1.2.840.113549.1.1.12": "sha384",
        "1.2.840.113549.1.1.13": "sha512",
        "1.2.840.10045.4.3.2": "sha256",
        "1.2.840.10045.4.3.3": "sha384",
        "1.2.840.10045.4.3.4": "sha512",
    }[oid]


def parse_certificate(data: bytes) -> ParsedCert:
    cert = x509.load_der_x509_certificate(data)
    sig_oid, sig_params_der, tbs, _sig = _raw_sig_algorithm(data)
    if sig_oid not in SUPPORTED_SIG_ALGS:
        raise UnsupportedError("signature algorithm outside profile", {"oid": sig_oid})
    _check_validity_encoding(tbs)
    if cert.version != x509.Version.v3:
        raise UnsupportedError("only v3 certificates are in profile",
                               {"version": cert.version.name})

    # Public key profile
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        if pk.key_size not in SUPPORTED_RSA_SIZES:
            raise UnsupportedError("RSA key size outside profile", {"size": pk.key_size})
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        curve_oid = pk.curve.name
        # map by OID properly
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

        if not isinstance(pk.curve, SECP256R1):
            raise UnsupportedError("only EC P-256 is in profile", {"curve": pk.curve.name})
    elif isinstance(pk, ed25519.Ed25519PublicKey):
        pass
    else:
        raise UnsupportedError("public key algorithm outside profile",
                               {"type": type(pk).__name__})

    # Signature parameters (PSS strictness): parse from real DER, never
    # trust a library-default parameter object.
    pss_info = None
    if sig_oid == OID_RSA_PSS:
        pss_info = parse_pss_params(sig_params_der)
    elif sig_params_der is not None and sig_params_der != b"":
        # Non-PSS profile algorithms carry absent params (ECDSA/Ed25519) or
        # NULL (RSA PKCS#1). Anything else is out of profile.
        raise UnsupportedError("unexpected signature algorithm parameters",
                               {"oid": sig_oid})

    ski = None
    try:
        ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
    except x509.ExtensionNotFound:
        pass

    aki = None
    try:
        a = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
        aki = a.key_identifier
    except x509.ExtensionNotFound:
        pass

    bc = None
    try:
        bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        if not bc_ext.critical:
            raise MalformedEvidenceError("basicConstraints in a CA certificate must be critical")
        bc = bc_ext.value
    except x509.ExtensionNotFound:
        bc = None

    ku: set[str] = set()
    try:
        kuv = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if kuv.key_cert_sign:
            ku.add("keyCertSign")
        if kuv.crl_sign:
            ku.add("cRLSign")
        if kuv.digital_signature:
            ku.add("digitalSignature")
    except x509.ExtensionNotFound:
        pass

    eku = None
    try:
        ev = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        eku = frozenset(o.dotted_string for o in ev)
    except x509.ExtensionNotFound:
        pass

    san_dns: tuple[str, ...] = ()
    san_uri: tuple[str, ...] = ()
    try:
        sanv = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        san_dns, san_uri = _gn_dns_uri(list(sanv), "subjectAltName")
    except x509.ExtensionNotFound:
        pass

    ncpd = ncpu = nced = nceu = ()
    try:
        ncv = cert.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
        if not ncv.critical:
            raise MalformedEvidenceError("nameConstraints must be critical")
        v = ncv.value
        if v.permitted_subtrees:
            ncpd, ncpu = _gn_dns_uri(list(v.permitted_subtrees), "nameConstraints.permitted")
        if v.excluded_subtrees:
            nced, nceu = _gn_dns_uri(list(v.excluded_subtrees), "nameConstraints.excluded")
    except x509.ExtensionNotFound:
        pass

    # Policies
    policy_oids: set[str] = set()
    policies_present = False
    try:
        cp = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
        policies_present = True
        for pi in cp:
            policy_oids.add(pi.policy_identifier.dotted_string)
            for q in pi.policy_qualifiers or []:
                if isinstance(q, str):
                    qoid = OID_CPS
                else:
                    qoid = q.policy_qualifier_id.dotted_string
                if qoid not in (OID_CPS, OID_USER_NOTICE):
                    raise UnsupportedError("unsupported policy qualifier", {"oid": qoid})
    except x509.ExtensionNotFound:
        pass

    # Policy mappings (cryptography does not expose parsed values)
    mappings: tuple[tuple[str, str], ...] = ()
    try:
        m_ext = cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(OID_POLICY_MAPPINGS))
        mappings = tuple(sorted(der.parse_policy_mappings(m_ext.value.public_bytes())))
        for a, b in mappings:
            if a == OID_ANY_POLICY or b == OID_ANY_POLICY:
                raise MalformedEvidenceError("policyMappings must not involve anyPolicy")
    except x509.ExtensionNotFound:
        pass

    require_explicit = inhibit_map = inhibit_any = None
    try:
        pc = cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(OID_POLICY_CONSTRAINTS)).value
        require_explicit = pc.require_explicit_policy
        inhibit_map = pc.inhibit_policy_mapping
    except x509.ExtensionNotFound:
        pass
    try:
        ia = cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(OID_INHIBIT_ANY_POLICY)).value
        inhibit_any = ia.skip_certs
    except x509.ExtensionNotFound:
        pass

    # Subject DN / Issuer DN raw DER
    subject_der = cert.subject.public_bytes()
    issuer_der = cert.issuer.public_bytes()

    return ParsedCert(
        der=data,
        fingerprint=fp_of(data),
        cert=cert,
        subject_der=subject_der,
        issuer_der=issuer_der,
        ski=ski,
        aki=aki,
        serial=cert.serial_number,
        not_before=int(cert.not_valid_before_utc.timestamp()),
        not_after=int(cert.not_valid_after_utc.timestamp()),
        is_ca=bool(bc and bc.ca),
        path_len=bc.path_length if bc else None,
        key_usage=ku,
        eku=eku,
        san_dns=san_dns,
        san_uri=san_uri,
        nc_permitted_dns=ncpd,
        nc_permitted_uri=ncpu,
        nc_excluded_dns=nced,
        nc_excluded_uri=nceu,
        policies=PolicyInfo(oids=frozenset(policy_oids), present=policies_present),
        policy_mappings=mappings,
        require_explicit_policy=require_explicit,
        inhibit_policy_mapping=inhibit_map,
        inhibit_any_policy=inhibit_any,
        sig_oid=sig_oid,
        sig_params_der=sig_params_der,
        sig_hash=_sig_hash_for_oid(sig_oid, pss_info),
        pss_salt_length=pss_info["salt_length"] if pss_info else None,
        spki_bitstring=_spki_key_bytes(cert),
    )


def verify_signature(pub, sig: bytes, tbs: bytes, sig_oid: str,
                     hash_name: str | None, pss_params=None) -> None:
    if sig_oid in (
        "1.2.840.113549.1.1.11",
        "1.2.840.113549.1.1.12",
        "1.2.840.113549.1.1.13",
    ):
        if not isinstance(pub, rsa.RSAPublicKey):
            raise UnsupportedError("PKCS1v15 signature with non-RSA key")
        pub.verify(sig, tbs, padding.PKCS1v15(), _hash(hash_name))
    elif sig_oid == OID_RSA_PSS:
        if not isinstance(pub, rsa.RSAPublicKey):
            raise UnsupportedError("RSA-PSS signature with non-RSA key")
        if pss_params is None:
            raise MalformedEvidenceError("RSA-PSS signature without parameters")
        salt = pss_params["salt_length"]
        pub.verify(sig, tbs,
                   padding.PSS(mgf=padding.MGF1(_hash(hash_name)),
                               salt_length=salt),
                   _hash(hash_name))
    elif sig_oid in ("1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4"):
        if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(
                pub.curve, ec.SECP256R1):
            raise UnsupportedError("ECDSA signature with non-P256 key")
        pub.verify(sig, tbs, ec.ECDSA(_hash(hash_name)))
    elif sig_oid == OID_ED25519:
        if not isinstance(pub, ed25519.Ed25519PublicKey):
            raise UnsupportedError("Ed25519 signature with non-Ed25519 key")
        pub.verify(sig, tbs)
    else:
        raise UnsupportedError("signature algorithm outside profile", {"oid": sig_oid})


def _hash(name: str | None) -> hashes.HashAlgorithm:
    if name == "sha256":
        return hashes.SHA256()
    if name == "sha384":
        return hashes.SHA384()
    if name == "sha512":
        return hashes.SHA512()
    raise UnsupportedError("hash outside profile", {"hash": str(name)})


def verify_cert_signature(child: ParsedCert, issuer: ParsedCert) -> tuple[bool, str | None]:
    """Verify child's signature using issuer public key over child TBS.

    The issuer key is loaded directly from the issuer DER; nothing parsed
    from fields is trusted for the cryptographic check.
    """
    try:
        issuer_x = x509.load_der_x509_certificate(issuer.der)
        hn = child.sig_hash
        pss = {"salt_length": child.pss_salt_length} if child.sig_oid == OID_RSA_PSS else None
        _, _, tbs, sig = _raw_sig_algorithm(child.der)
        verify_signature(issuer_x.public_key(), sig, tbs, child.sig_oid, hn, pss)
        return True, None
    except InvalidSignature:
        return False, "SIGNATURE"
    except UnsupportedError:
        return False, "UNSUPPORTED"
    except MalformedEvidenceError:
        return False, "MALFORMED_EVIDENCE"
    except Exception:
        return False, "SIGNATURE"


def cheap_names(cert_der: bytes) -> tuple[bytes, bytes]:
    """Extract (issuer Name DER, subject Name DER) without crypto parsing.

    Used to build the large-graph subject-name index cheaply at seal time.
    Name field contents are the raw Name (RDNSequence) DER bytes.
    """
    tag, body, _ = der.tlv(cert_der)
    if tag != der.SEQUENCE:
        raise MalformedEvidenceError("certificate: expected SEQUENCE")
    elems = list(der.iter_tlv(body))
    if not elems:
        raise MalformedEvidenceError("certificate: truncated")
    tbs = elems[0][1]
    t = list(der.iter_tlv(tbs))
    i = 1 if t and t[0][0] == 0xA0 else 0
    # serial i, signature i+1, issuer i+2, validity i+3, subject i+4
    if len(t) < i + 5:
        raise MalformedEvidenceError("certificate: truncated TBS")
    issuer = der.build_tlv(t[i + 2][0], t[i + 2][1])
    subject = der.build_tlv(t[i + 4][0], t[i + 4][1])
    return issuer, subject


def is_self_signed(pc: ParsedCert) -> bool:
    return pc.subject_der == pc.issuer_der


def verify_artifact_signature(pub, signature: bytes, digest: bytes, sig_oid: str) -> dict:
    """Verify the raw artifact signature over ``digest``.

    PKCS#1 v1.5 signs the DER DigestInfo containing the digest (RFC 8017
    §9.2); RSA-PSS/ECDSA/Ed25519 sign the raw digest. The digest length is
    matched to the algorithm profile.
    """
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    pkcs1_oids = {
        "1.2.840.113549.1.1.11": "sha256",
        "1.2.840.113549.1.1.12": "sha384",
        "1.2.840.113549.1.1.13": "sha512",
    }
    ecdsa_oids = {
        "1.2.840.10045.4.3.2": "sha256",
        "1.2.840.10045.4.3.3": "sha384",
        "1.2.840.10045.4.3.4": "sha512",
    }
    digest_sizes = {"sha256": 32, "sha384": 48, "sha512": 64}
    hash_algid_der = {
        "sha256": bytes.fromhex("06096086480165030402010500"),
        "sha384": bytes.fromhex("06096086480165030402020500"),
        "sha512": bytes.fromhex("06096086480165030402030500"),
    }
    try:
        if sig_oid in pkcs1_oids:
            hn = pkcs1_oids[sig_oid]
            if len(digest) != digest_sizes[hn]:
                return {"ok": False, "rule": "MALFORMED_REQUEST",
                        "detail": {"expected_digest_bytes": digest_sizes[hn]}}
            if not isinstance(pub, rsa.RSAPublicKey):
                return {"ok": False, "rule": "UNSUPPORTED", "detail": {"reason": "non-RSA key"}}
            algid = der.build_tlv(der.SEQUENCE, hash_algid_der[hn])
            octets = der.build_tlv(der.OCTET_STRING, digest)
            payload = der.build_tlv(der.SEQUENCE, algid + octets)
            pub.verify(signature, payload, padding.PKCS1v15(), _hash(hn))
        elif sig_oid == OID_RSA_PSS:
            if not isinstance(pub, rsa.RSAPublicKey):
                return {"ok": False, "rule": "UNSUPPORTED", "detail": {"reason": "non-RSA key"}}
            if len(digest) != 32:
                return {"ok": False, "rule": "MALFORMED_REQUEST",
                        "detail": {"expected_digest_bytes": 32}}
            pub.verify(signature, digest,
                       padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                       Prehashed(hashes.SHA256()))
        elif sig_oid in ecdsa_oids:
            hn = ecdsa_oids[sig_oid]
            if len(digest) != digest_sizes[hn]:
                return {"ok": False, "rule": "MALFORMED_REQUEST",
                        "detail": {"expected_digest_bytes": digest_sizes[hn]}}
            if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(
                    pub.curve, ec.SECP256R1):
                return {"ok": False, "rule": "UNSUPPORTED", "detail": {"reason": "non-P256"}}
            pub.verify(signature, digest, ec.ECDSA(Prehashed(_hash(hn))))
        elif sig_oid == OID_ED25519:
            if not isinstance(pub, ed25519.Ed25519PublicKey):
                return {"ok": False, "rule": "UNSUPPORTED",
                        "detail": {"reason": "non-Ed25519"}}
            if len(digest) != 64:
                return {"ok": False, "rule": "MALFORMED_REQUEST",
                        "detail": {"expected_digest_bytes": 64}}
            pub.verify(signature, digest)
        else:
            return {"ok": False, "rule": "UNSUPPORTED", "detail": {"oid": sig_oid}}
        return {"ok": True}
    except InvalidSignature:
        return {"ok": False, "rule": "ARTIFACT_SIGNATURE"}
    except UnsupportedError as exc:
        return {"ok": False, "rule": "UNSUPPORTED", "detail": exc.detail}
    except Exception as exc:
        return {"ok": False, "rule": "ARTIFACT_SIGNATURE", "detail": str(exc)[:200]}
