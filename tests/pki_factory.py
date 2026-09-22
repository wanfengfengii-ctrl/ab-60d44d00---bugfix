"""Runtime PKI fixture generation for unit tests and offline acceptance.

All keys/certificates/CRLs/OCSP responses are generated freshly; no fixture
fingerprint is ever compiled into business logic.
"""
from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def utc(epoch_seconds: int) -> dt.datetime:
    return EPOCH + dt.timedelta(seconds=epoch_seconds)


def gen_key(kind="ec"):
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kind == "rsa3072":
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    return ec.generate_private_key(ec.SECP256R1())


def ski_of(cert: x509.Certificate) -> bytes:
    return cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier).value.digest


def _sig_args(key, alg):
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return {"algorithm": None}
    if alg == "pss":
        return {"algorithm": hashes.SHA256(),
                "rsa_padding": padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                           salt_length=hashes.SHA256().digest_size)}
    return {"algorithm": hashes.SHA256()}


def build_cert(subject_cn, issuer_obj, subject_key, issuer_key, *,
               serial=None, not_before=1_000_000_000, not_after=2_000_000_000,
               is_ca=False, path_len=None, key_usage=(), eku=(),
               san_dns=(), san_uri=(),
               nc_permitted_dns=(), nc_excluded_dns=(),
               nc_permitted_uri=(), nc_excluded_uri=(),
               policies=(), policy_mappings=(),
               require_explicit_policy=None, inhibit_policy_mapping=None,
               inhibit_any_policy=None, sig_alg="sha256",
               issuer_ski_override=None, self_signed=False,
               subject_dn_extra=()):
    """issuer_obj: certificate used to derive issuer Name + AKI (or None to
    self-issue). Returns an x509.Certificate."""
    subject_name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]
    for oid, val in subject_dn_extra:
        subject_name_attrs.append(x509.NameAttribute(oid, val))
    subject_name = x509.Name(subject_name_attrs)
    if issuer_obj is None:
        issuer_name = subject_name
    else:
        issuer_name = issuer_obj.subject
    if serial is None:
        import os

        serial = int.from_bytes(os.urandom(8), "big")
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(utc(not_before))
        .not_valid_after(utc(not_after))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False)
    )
    if self_signed:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(subject_key.public_key())
    elif issuer_ski_override is not None:
        aki = x509.AuthorityKeyIdentifier(
            key_identifier=issuer_ski_override,
            authority_cert_issuer=None, authority_cert_serial_number=None)
    else:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key())
    builder = builder.add_extension(aki, critical=False)

    bc = x509.BasicConstraints(ca=is_ca, path_length=path_len)
    builder = builder.add_extension(bc, critical=True)

    if key_usage:
        ku = x509.KeyUsage(
            digital_signature="digitalSignature" in key_usage,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            key_cert_sign="keyCertSign" in key_usage,
            crl_sign="cRLSign" in key_usage,
            encipher_only=False, decipher_only=False)
        builder = builder.add_extension(ku, critical=True)

    if eku:
        oids = []
        for e in eku:
            if e == "codeSigning":
                oids.append(x509.ObjectIdentifier("1.3.6.1.5.5.7.3.3"))
            elif e == "ocspSigning":
                oids.append(x509.ObjectIdentifier("1.3.6.1.5.5.7.3.9"))
            else:
                oids.append(x509.ObjectIdentifier(e))
        builder = builder.add_extension(x509.ExtendedKeyUsage(oids), critical=False)

    if san_dns or san_uri:
        names = [x509.DNSName(d) for d in san_dns] + \
                [x509.UniformResourceIdentifier(u) for u in san_uri]
        builder = builder.add_extension(x509.SubjectAlternativeName(names),
                                        critical=False)

    if nc_permitted_dns or nc_excluded_dns or nc_permitted_uri or nc_excluded_uri:
        permitted = [x509.DNSName(d) for d in nc_permitted_dns] + \
                    [x509.UniformResourceIdentifier(u) for u in nc_permitted_uri]
        excluded = [x509.DNSName(d) for d in nc_excluded_dns] + \
                   [x509.UniformResourceIdentifier(u) for u in nc_excluded_uri]
        builder = builder.add_extension(
            x509.NameConstraints(permitted or None, excluded or None), critical=True)

    if policies:
        pis = [x509.PolicyInformation(x509.ObjectIdentifier(p), []) for p in policies]
        builder = builder.add_extension(x509.CertificatePolicies(pis),
                                        critical=False)

    if policy_mappings:
        # Build via raw DER since cryptography lacks a high-level class.
        ext = _policy_mappings_ext(policy_mappings)
        builder = builder.add_extension(ext, critical=False)

    if require_explicit_policy is not None or inhibit_policy_mapping is not None:
        builder = builder.add_extension(
            x509.PolicyConstraints(
                require_explicit_policy=require_explicit_policy,
                inhibit_policy_mapping=inhibit_policy_mapping),
            critical=False)
    if inhibit_any_policy is not None:
        builder = builder.add_extension(
            x509.InhibitAnyPolicy(inhibit_any_policy), critical=False)

    kwargs = _sig_args(issuer_key, sig_alg)
    return builder.sign(issuer_key, **kwargs)


def _policy_mappings_ext(mappings):
    from app import der

    pairs = []
    for iss, sub in mappings:
        pairs.append(der.build_tlv(der.SEQUENCE,
                                   _oid_der(iss) + _oid_der(sub)))
    body = der.build_tlv(der.SEQUENCE, b"".join(pairs))
    return x509.UnrecognizedExtension(
        x509.ObjectIdentifier("2.5.29.33"), body)


def _oid_ver(oid: str):
    out = []
    parts = [int(x) for x in oid.split(".")]
    first = 40 * parts[0] + parts[1]
    out.append(first)
    for v in parts[2:]:
        if v < 0x80:
            out.append(v)
        else:
            chunks = [v & 0x7F]
            v >>= 7
            while v:
                chunks.append((v & 0x7F) | 0x80)
                v >>= 7
            out.extend(reversed(chunks))
    return bytes(out)


def _oid_der(oid: str) -> bytes:
    from app import der

    return der.build_tlv(der.OID, _oid_ver(oid))


def der(cert_or_crl) -> bytes:
    return cert_or_crl.public_bytes(serialization.Encoding.DER)


# --------------------------------------------------------------------- CRL
def build_crl(issuer_cert, issuer_key, entries, *,
              last_update, next_update=None, crl_number=1,
              delta_of=None, idp_uris=(), only_ca=False, only_user=False,
              indirect=False, sig_alg="sha256", akify=True):
    """entries: list of (serial, revocation_epoch, reason|None)."""
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(utc(last_update))
        .next_update(utc(next_update) if next_update else None)
        .add_extension(x509.CRLNumber(crl_number), critical=False)
    )
    if akify:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()), critical=False)
    if delta_of is not None:
        builder = builder.add_extension(
            x509.DeltaCRLIndicator(delta_of), critical=True)
    if idp_uris or only_ca or only_user or indirect:
        full = [x509.UniformResourceIdentifier(u) for u in idp_uris] or None
        dp = x509.DistributionPoint(full_name=full, relative_name=None,
                                    reasons=None, crl_issuer=None)
        idp = x509.IssuingDistributionPoint(
            full_name=None, relative_name=None,
            only_contains_user_certs=only_user, only_contains_ca_certs=only_ca,
            only_some_reasons=None, indirect_crl=indirect,
            only_contains_attribute_certs=False)
        # cryptography's IDP needs distribution point to carry URIs: emulate
        # by constructing via DistributionPoint full name injection.
        if full:
            idp = x509.IssuingDistributionPoint(
                full_name=full, relative_name=None,
                only_contains_user_certs=only_user, only_contains_ca_certs=only_ca,
                only_some_reasons=None, indirect_crl=indirect,
                only_contains_attribute_certs=False)
        builder = builder.add_extension(idp, critical=False)
    for serial, rev_epoch, reason in entries:
        rb = (x509.RevokedCertificateBuilder()
              .serial_number(serial)
              .revocation_date(utc(rev_epoch)))
        if reason is not None:
            rb = rb.add_extension(
                x509.CRLReason(x509.ReasonFlags.__members__[reason]),
                critical=False)
        builder = builder.add_revoked_certificate(rb.build())
    kwargs = _sig_args(issuer_key, sig_alg)
    return builder.sign(issuer_key, **kwargs)


# -------------------------------------------------------------------- OCSP
def build_ocsp(leaf_cert, issuer_cert, issuer_key, status, *,
               this_update, next_update=None, revocation_time=None,
               reason=None, responder_key=None, responder_cert=None,
               sig_alg="sha256", hash_alg=hashes.SHA1()):
    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            leaf_cert,
            issuer_cert,
            hash_alg,
            {
                "good": ocsp.OCSPCertStatus.GOOD,
                "revoked": ocsp.OCSPCertStatus.REVOKED,
                "unknown": ocsp.OCSPCertStatus.UNKNOWN,
            }[status],
            utc(this_update),
            utc(next_update) if next_update else None,
            utc(revocation_time) if revocation_time else None,
            (x509.ReasonFlags.__members__[reason] if reason else None))
        .responder_id(ocsp.OCSPResponderEncoding.NAME, responder_cert
                      if responder_cert is not None else issuer_cert)
    )
    if responder_cert is not None:
        builder = builder.certificates([responder_cert])
    sign_key = responder_key or issuer_key
    if sig_alg == "pss":
        return builder.sign(sign_key, hashes.SHA256(),
                            rsa_padding=padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=hashes.SHA256().digest_size))
    if isinstance(sign_key, ed25519.Ed25519PrivateKey):
        return builder.sign(sign_key, None)
    return builder.sign(sign_key, hashes.SHA256())
