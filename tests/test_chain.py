"""Unit tests for chain-level gates: pathLen, name constraints, EKU,
RFC 5280 policy processing (mappings, anyPolicy inhibition)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app import chain
from app.certmodel import parse_certificate

ANY = "2.5.29.32.0"
P1 = "1.2.3.4.5.1"
P2 = "1.2.3.4.5.2"
T = 1_700_000_000


def _p(derb):
    return parse_certificate(derb)


def _chain3(root_b, ca_b, leaf_b):
    return [_p(leaf_b), _p(ca_b), _p(root_b)]


def _chain4(root_b, ca1_b, ca2_b, leaf_b):
    return [_p(leaf_b), _p(ca2_b), _p(ca1_b), _p(root_b)]


def test_pathlen_violation():
    rk, k1, k2, lk = [pf.gen_key() for _ in range(4)]
    root = pf.build_cert("R", None, rk, rk, is_ca=True, path_len=0,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca1 = pf.build_cert("C1", root, k1, rk, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    ca2 = pf.build_cert("C2", ca1, k2, k1, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca2, lk, k2, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    p = _chain4(pf.der(root), pf.der(ca1), pf.der(ca2), pf.der(leaf))
    ok, d = chain.check_path_len(p)
    assert not ok and d["rule"] == "PATH_LEN"


def test_dns_name_constraint_permitted_and_excluded():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         nc_permitted_dns=("example.com",), self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf_ok = pf.build_cert("L1", ca, lk, ck, key_usage=("digitalSignature",),
                            eku=("codeSigning",), policies=[ANY],
                            san_dns=("app.example.com",))
    leaf_bad = pf.build_cert("L2", ca, pf.gen_key(), ck,
                             key_usage=("digitalSignature",),
                             eku=("codeSigning",), policies=[ANY],
                             san_dns=("evil.test",))
    assert chain.check_name_constraints(_chain3(pf.der(root), pf.der(ca), pf.der(leaf_ok)))[0]
    ok, d = chain.check_name_constraints(_chain3(pf.der(root), pf.der(ca), pf.der(leaf_bad)))
    assert not ok and d["rule"] == "NAME_CONSTRAINTS"

    # excluded subtree
    root2 = pf.build_cert("R2", None, rk, rk, is_ca=True,
                          key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                          nc_excluded_dns=("bad.example.com",), self_signed=True)
    leaf_ex = pf.build_cert("L3", ca, pf.gen_key(), ck,
                            key_usage=("digitalSignature",),
                            eku=("codeSigning",), policies=[ANY],
                            san_dns=("x.bad.example.com",))
    # root2 signed its own CA chain variant: rebuild ca under root2
    ca2 = pf.build_cert("C2b", root2, ck, rk, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf_ex2 = pf.build_cert("L3b", ca2, pf.gen_key(), ck,
                             key_usage=("digitalSignature",),
                             eku=("codeSigning",), policies=[ANY],
                             san_dns=("x.bad.example.com",))
    ok, d = chain.check_name_constraints(_chain3(pf.der(root2), pf.der(ca2), pf.der(leaf_ex2)))
    assert not ok and d["rule"] == "NAME_CONSTRAINTS"


def test_uri_name_constraint():
    assert chain.uri_in_subtree("https://a.example.com/x", "example.com")
    assert chain.uri_in_subtree("https://example.com:8443/", "example.com")
    assert not chain.uri_in_subtree("https://example.com.evil.test/", "example.com")


def test_eku_code_signing_required():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf_no_eku = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                                policies=[ANY])
    ok, d = chain.check_eku(_chain3(pf.der(root), pf.der(ca), pf.der(leaf_no_eku)))
    assert not ok and d["rule"] == "EKU"


def test_policy_simple_intersection():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[P1])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[P1])
    p = _chain3(pf.der(root), pf.der(ca), pf.der(leaf))
    ok, d, _ = chain.process_policies(p, frozenset({P1}))
    assert ok
    ok, d, _ = chain.process_policies(p, frozenset({P2}))
    assert not ok and d["reason"] == "no_acceptable_policy"


def test_policy_mapping_allowed():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    # CA maps its issuer-domain P1 to subject-domain P2 for the leaf.
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[P1],
                       policy_mappings=((P1, P2),))
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[P2])
    p = _chain3(pf.der(root), pf.der(ca), pf.der(leaf))
    ok, d, _ = chain.process_policies(p, frozenset({P1}))
    assert ok, d


def test_policy_mapping_inhibited():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         inhibit_policy_mapping=0, self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[P1],
                       policy_mappings=((P1, P2),))
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[P2])
    p = _chain3(pf.der(root), pf.der(ca), pf.der(leaf))
    ok, d, _ = chain.process_policies(p, frozenset({P1}))
    assert not ok and d["reason"] == "policyMapping_inhibited"


def test_any_policy_inhibited():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    # Root inhibits anyPolicy after 1 cert: CA may still use ANY, leaf must not.
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         inhibit_any_policy=1, self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    p = _chain3(pf.der(root), pf.der(ca), pf.der(leaf))
    ok, d, _ = chain.process_policies(p, frozenset({P1}))
    assert not ok
