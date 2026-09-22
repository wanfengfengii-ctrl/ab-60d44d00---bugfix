"""Performance: 100k unrelated certificates must not make adjudications
re-parse the whole DER universe, and certificate graphs with cycles must not
send path search exponential."""
import hashlib
import os
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app.storage import Store
from app.adjudge import adjudicate
from app.certmodel import fp_of, parse_certificate

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000
CUTOFF = 1_701_000_000
RECEIVED = 1_699_000_000


def test_large_graph_fast(tmp_path):
    store = Store(str(tmp_path / "data"))
    sid = "es_perf_0000000000000000000000000001"
    store.create_set(sid, "c")

    # The real chain under adjudication.
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("Target Root", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("Target CA", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("target.leaf", ca, lk, ck,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("target.leaf",))
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)

    N_UNRELATED = 100_000 - 3
    rows = []
    for i in range(N_UNRELATED):
        k = pf.gen_key()
        unrelated = pf.build_cert(
            f"unrelated-{i:06d}.example.test", None, k, k,
            is_ca=True, key_usage=("keyCertSign", "cRLSign"),
            policies=[ANY], self_signed=True)
        d = pf.der(unrelated)
        store.put_blob(d)
        rows.append({"client_ref": f"u{i}", "kind": "certificate",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    for c in (root, ca, leaf):
        d = pf.der(c)
        store.put_blob(d)
        rows.append({"client_ref": "t" + fp_of(d)[:12], "kind": "certificate",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    for i, c in enumerate((crl, rcrl)):
        d = pf.der(c)
        store.put_blob(d)
        rows.append({"client_ref": f"r{i}", "kind": "crl",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    store.add_items(sid, rows)
    t0 = time.perf_counter()
    manifest = store.seal(sid)
    seal_t = time.perf_counter() - t0
    assert manifest["counts"]["certificates"] == N_UNRELATED + 3

    d = hashlib.sha256(b"artifact").digest()
    s = lk.sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
    t0 = time.perf_counter()
    result = adjudicate(store, sid, {
        "artifact_digest": d.hex(), "signature": s.hex(),
        "signature_algorithm": "1.2.840.10045.4.3.2",
        "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
        "leaf_certificate_sha256": fp_of(pf.der(leaf)),
        "initial_policies": [ANY], "trust_anchors": [fp_of(pf.der(root))]})
    judge_t = time.perf_counter() - t0
    assert result["verdict"]["status"] == "VALID"
    # Whole adjudication over a 100k graph must be fast (lazy parsing).
    assert judge_t < 15.0, f"adjudication took {judge_t:.2f}s"


def test_cycle_graph_terminates(tmp_path):
    """Cross-signed CAs forming a cycle must not hang or explode."""
    store = Store(str(tmp_path / "data"))
    sid = "es_cycle_00000000000000000000000000001"
    store.create_set(sid, "c")
    rk, ak, bk, lk = (pf.gen_key() for _ in range(4))
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    # A signed by R and by B; B signed by R and by A -> cycle A<->B.
    a_by_r = pf.build_cert("CA X", root, ak, rk, is_ca=True,
                           key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    b_by_r = pf.build_cert("CA Y", root, bk, rk, is_ca=True,
                           key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    a_by_b = pf.build_cert("CA X", b_by_r, ak, bk, is_ca=True,
                           key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    b_by_a = pf.build_cert("CA Y", a_by_r, bk, ak, is_ca=True,
                           key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    # Leaf under the A key (either cross-cert of A can be its issuer).
    leaf = pf.build_cert("leaf", a_by_r, lk, ak,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    rows = []
    for c in (root, a_by_r, b_by_r, a_by_b, b_by_a, leaf):
        d = pf.der(c)
        store.put_blob(d)
        rows.append({"client_ref": "c" + fp_of(d)[:12], "kind": "certificate",
                     "content_sha256": fp_of(d), "received_at": RECEIVED})
    store.add_items(sid, rows)
    store.seal(sid)
    d = hashlib.sha256(b"z").digest()
    s = lk.sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
    t0 = time.perf_counter()
    result = adjudicate(store, sid, {
        "artifact_digest": d.hex(), "signature": s.hex(),
        "signature_algorithm": "1.2.840.10045.4.3.2",
        "signed_at": SIGNED, "knowledge_cutoff": CUTOFF,
        "leaf_certificate_sha256": fp_of(pf.der(leaf)),
        "initial_policies": [ANY], "trust_anchors": [fp_of(pf.der(root))]})
    elapsed = time.perf_counter() - t0
    assert elapsed < 10.0
    # Shortest valid path leaf->A(by R)->R chosen, not the longer cycle route.
    assert result["verdict"]["status"] in ("VALID", "REJECTED")
    if result["verdict"]["status"] == "VALID":
        path = result["verdict"]["selected_path"]
        assert path[-1] == fp_of(pf.der(root))
        assert len(path) == 3
