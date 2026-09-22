import base64
import hashlib
import os
import sys

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app.storage import Store
from app.adjudge import adjudicate
from app.package import build_package
from app.certmodel import fp_of
from app import canonical

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000          # 2023-11-14
RECEIVED = 1_699_000_000
CUTOFF = 1_701_000_000


def make_simple_pki(key_kind="ec", leaf_kind="ec"):
    root_key = pf.gen_key(key_kind)
    ca_key = pf.gen_key("ec")
    leaf_key = pf.gen_key(leaf_kind)
    root = pf.build_cert("Root CA", None, root_key, root_key,
                         not_before=1_262_304_000, not_after=2_000_000_000,
                         is_ca=True, key_usage=("keyCertSign", "cRLSign"),
                         policies=[ANY], self_signed=True)
    ca = pf.build_cert("Issuing CA", root, ca_key, root_key,
                       not_before=1_400_000_000, not_after=1_900_000_000,
                       is_ca=True, path_len=0,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("codesign.example", ca, leaf_key, ca_key,
                         not_before=1_600_000_000, not_after=1_850_000_000,
                         is_ca=False, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("codesign.example",),
                         san_uri=("https://codesign.example/app",))
    return root_key, ca_key, leaf_key, root, ca, leaf


def sign_artifact_ec(leaf_key, artifact):
    digest = hashlib.sha256(artifact).digest()
    sig = leaf_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    return digest, sig, "1.2.840.10045.4.3.2"


def _b64(b):
    return base64.b64encode(b).decode()


def upload_and_seal(tmp_path, certs, revobjs, received=RECEIVED):
    store = Store(str(tmp_path / "data"))
    set_id = "es_test000000000000000000000000000001"
    store.create_set(set_id, "create-1")
    rows = []
    for c in certs:
        rows.append({"client_ref": "c" + fp_of(pf.der(c))[:16],
                     "kind": "certificate", "raw": pf.der(c),
                     "content_sha256": fp_of(pf.der(c)), "received_at": received})
    for i, (kind, obj) in enumerate(revobjs):
        raw = pf.der(obj)
        rows.append({"client_ref": f"r{i}", "kind": kind, "raw": raw,
                     "content_sha256": fp_of(raw), "received_at": received})
    for r in rows:
        store.put_blob(r.pop("raw"))
    store.add_items(set_id, rows)
    manifest = store.seal(set_id)
    return store, set_id, manifest


def test_valid_chain_with_good_crl(tmp_path):
    rk, ck, lk, root, ca, leaf = make_simple_pki()
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 86400 * 5,
                       next_update=SIGNED + 86400 * 5, crl_number=2)
    root_crl = pf.build_crl(root, rk, [],
                            last_update=SIGNED - 86400 * 10,
                            next_update=SIGNED + 86400 * 10, crl_number=1)
    store, set_id, manifest = upload_and_seal(
        tmp_path, [root, ca, leaf], [("crl", crl), ("crl", root_crl)])
    artifact = b"artifact-bytes"
    digest, sig, alg = sign_artifact_ec(lk, artifact)
    result = adjudicate(store, set_id, {
        "artifact_digest": digest.hex(), "signature": sig.hex(),
        "signature_algorithm": alg, "signed_at": SIGNED,
        "knowledge_cutoff": CUTOFF,
        "leaf_certificate_sha256": fp_of(pf.der(leaf)),
        "initial_policies": [ANY],
        "trust_anchors": [fp_of(pf.der(root))]})
    assert result["verdict"]["status"] == "VALID", result
    path = result["verdict"]["selected_path"]
    assert path == [fp_of(pf.der(leaf)), fp_of(pf.der(ca)), fp_of(pf.der(root))]
    rev = result["revocation_results"][0]
    assert rev["conclusion"] == "GOOD"
    assert rev["selected_evidence"]["kind"] == "crl"
    pkg = build_package(store, result, manifest)
    assert pkg[:2] == b"PK"
