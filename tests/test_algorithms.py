"""All three mandatory signature algorithms end-to-end:
RSA-PSS, ECDSA P-256 and Ed25519, for certificates, CRL/OCSP evidence and
the raw artifact signature."""
import hashlib
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from tests.test_e2e import Harness, SIGNED, CUTOFF, ANY
from app.certmodel import fp_of

PSS_OID = "1.2.840.113549.1.1.10"
ECDSA_OID = "1.2.840.10045.4.3.2"
ED25519_OID = "1.3.101.112"


def _chain(leaf_key_kind, sig_mode):
    """sig_mode: 'pss' for RSA keys, 'sha256' for EC, None for Ed25519."""
    if sig_mode == "pss":
        rk, ck, lk = pf.gen_key("rsa"), pf.gen_key("rsa"), pf.gen_key("rsa")
    elif sig_mode is None:
        rk, ck, lk = pf.gen_key("ed25519"), pf.gen_key("ed25519"), \
            pf.gen_key("ed25519")
    else:
        rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    kw = dict(is_ca=True, key_usage=("keyCertSign", "cRLSign"),
              policies=[ANY], self_signed=True)
    if sig_mode:
        kw["sig_alg"] = sig_mode
    root = pf.build_cert("R", None, rk, rk, **kw)
    kw2 = dict(is_ca=True, key_usage=("keyCertSign", "cRLSign"),
               policies=[ANY])
    if sig_mode:
        kw2["sig_alg"] = sig_mode
    ca = pf.build_cert("C", root, ck, rk, **kw2)
    kw3 = dict(key_usage=("digitalSignature",), eku=("codeSigning",),
               policies=[ANY])
    if sig_mode:
        kw3["sig_alg"] = sig_mode
    leaf = pf.build_cert("L", ca, lk, ck, **kw3)
    return rk, ck, lk, root, ca, leaf


def _artifact_sig(kind, lk, artifact):
    if kind == "pss":
        d = hashlib.sha256(artifact).digest()
        s = lk.sign(d, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                   salt_length=32),
                    Prehashed(hashes.SHA256()))
        return d, s, PSS_OID
    if kind == "ed25519":
        d = hashlib.sha512(artifact).digest()
        return d, lk.sign(d), ED25519_OID
    d = hashlib.sha256(artifact).digest()
    return d, lk.sign(d, ec.ECDSA(Prehashed(hashes.SHA256()))), ECDSA_OID


def _run(tmp_path, kind, sig_mode, ocsp_too=False):
    h = Harness(tmp_path)
    rk, ck, lk, root, ca, leaf = _chain("x", sig_mode)
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1,
                       sig_alg=sig_mode or "sha256")
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1,
                        sig_alg=sig_mode or "sha256")
    revs = [crl, rcrl]
    rev_kinds = ["crl", "crl"]
    if ocsp_too:
        # cryptography's OCSP builder only emits PKCS#1 v1.5 for RSA; the
        # verifier itself accepts PSS OCSP too. Ed25519/ECDSA use their own.
        oc_sig = "sha256" if sig_mode == "pss" else (sig_mode or "sha256")
        oc = pf.build_ocsp(leaf, ca, ck, "good", this_update=SIGNED - 100,
                           next_update=SIGNED + 100, sig_alg=oc_sig)
        revs.append(oc)
        rev_kinds.append("ocsp")
    for c in (root, ca, leaf):
        h.add_cert(c)
    for i, (obj, k2) in enumerate(zip(revs, rev_kinds)):
        h.add_rev(obj, i, kind=k2)
    h.seal()
    d, s, alg = _artifact_sig(kind, lk, b"artifact-bytes")
    res = h.judge(leaf, fp_of(pf.der(root)), digest_sig=(d, s, alg))
    return res


def test_rsa_pss(tmp_path):
    res = _run(tmp_path, "pss", "pss", ocsp_too=True)
    assert res["verdict"]["status"] == "VALID", res["verdict"]


def test_ecdsa_p256(tmp_path):
    res = _run(tmp_path, "ecdsa", "sha256", ocsp_too=True)
    assert res["verdict"]["status"] == "VALID", res["verdict"]


def test_ed25519(tmp_path):
    res = _run(tmp_path, "ed25519", None, ocsp_too=True)
    assert res["verdict"]["status"] == "VALID", res["verdict"]


def test_bad_artifact_signature_invalid(tmp_path):
    h = Harness(tmp_path)
    rk, ck, lk, root, ca, leaf = _chain("x", "sha256")
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(crl, 0)
    h.add_rev(rcrl, 1)
    h.seal()
    d = hashlib.sha256(b"artifact").digest()
    good = lk.sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
    bad = bytes([good[0] ^ 1]) + good[1:]
    res = h.judge(leaf, fp_of(pf.der(root)), digest_sig=(d, bad, ECDSA_OID))
    assert res["verdict"]["status"] == "INVALID"
    assert res["verdict"]["failed_rule"] == "ARTIFACT_SIGNATURE"
