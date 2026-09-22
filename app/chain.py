"""RFC 5280 chain-level validation over a completed candidate path.

The implemented profile is documented in README ("Certificate profile").
Checks here operate on parsed-and-cryptographically-verified certificates
only. Paths are supplied leaf -> root; policy processing runs root -> leaf.
"""
from __future__ import annotations

from urllib.parse import urlparse

from .certmodel import ParsedCert
from .errors import OID_ANY_POLICY, OID_EKU_CODE_SIGNING

# Deterministic rule identifiers used in intermediate conclusions and in
# rejection proofs.
RULE_ORDER = [
    "PROFILE",
    "VALIDITY",
    "ISSUER_NAME_KEY",
    "SIGNATURE",
    "BASIC_CONSTRAINTS",
    "KEY_USAGE",
    "PATH_LEN",
    "NAME_CONSTRAINTS",
    "POLICY",
    "EKU",
    "REVOCATION",
    "ANCHOR",
    "LOOP",
    "PATH_DEPTH",
]

MAX_PATH_DEPTH = 20


def dns_in_subtree(host: str, constraint: str) -> bool:
    host = host.lower().rstrip(".")
    c = constraint.lower().lstrip(".").rstrip(".")
    if c == "":
        return True  # "." subtree matches every DNS name
    return host == c or host.endswith("." + c)


def uri_host(uri: str) -> str | None:
    try:
        u = urlparse(uri.lower())
        return u.hostname
    except ValueError:
        return None


def uri_in_subtree(uri: str, constraint: str) -> bool:
    host = uri_host(uri)
    if host is None:
        return False
    c = constraint.lower()
    if "://" in c or c.startswith("."):
        chost = uri_host(c if "://" in c else "http://" + c.lstrip("."))
        if chost is None:
            return False
        return dns_in_subtree(host, chost)
    # A bare constraint value is matched against the host component.
    return dns_in_subtree(host, c)


def _leaf_dns_names(leaf: ParsedCert) -> list[str]:
    names = list(leaf.san_dns)
    if not names:
        # Legacy: treat subject CNs as DNS names when constrained (RFC 5280
        # §4.2.1.10 guidance).
        from cryptography.x509.oid import NameOID

        for attr in leaf.cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            if isinstance(attr.value, str):
                try:
                    names.append(attr.value.encode("ascii").decode().lower())
                except UnicodeEncodeError:
                    # non-ASCII CN cannot be matched by a DNS constraint
                    names.append("\x00-non-ascii-")
    return names


def _leaf_uri_names(leaf: ParsedCert) -> list[str]:
    return list(leaf.san_uri)


def check_name_constraints(path_leaf_to_root: list[ParsedCert]) -> tuple[bool, dict | None]:
    """Every CA's constraints apply to all certificates below it."""
    leaf = path_leaf_to_root[0]
    dns_names = _leaf_dns_names(leaf)
    uri_names = _leaf_uri_names(leaf)
    # path[0] leaf, path[1:] issuers; only issuers carry constraints that
    # constrain the leaf. (A self-issued leaf constraints are irrelevant.)
    for ca in path_leaf_to_root[1:]:
        for name in dns_names:
            if ca.nc_excluded_dns and any(dns_in_subtree(name, c) for c in ca.nc_excluded_dns):
                return False, {"rule": "NAME_CONSTRAINTS", "at": ca.fingerprint,
                               "kind": "dns_excluded", "name": name}
            if ca.nc_permitted_dns and not any(
                    dns_in_subtree(name, c) for c in ca.nc_permitted_dns):
                return False, {"rule": "NAME_CONSTRAINTS", "at": ca.fingerprint,
                               "kind": "dns_not_permitted", "name": name}
        for name in uri_names:
            if ca.nc_excluded_uri and any(uri_in_subtree(name, c) for c in ca.nc_excluded_uri):
                return False, {"rule": "NAME_CONSTRAINTS", "at": ca.fingerprint,
                               "kind": "uri_excluded", "name": name}
            if ca.nc_permitted_uri and not any(
                    uri_in_subtree(name, c) for c in ca.nc_permitted_uri):
                return False, {"rule": "NAME_CONSTRAINTS", "at": ca.fingerprint,
                               "kind": "uri_not_permitted", "name": name}
        if not dns_names and not uri_names and (
                ca.nc_permitted_dns or ca.nc_permitted_uri):
            return False, {"rule": "NAME_CONSTRAINTS", "at": ca.fingerprint,
                           "kind": "no_name_matching_permitted_subtree"}
    return True, None


def check_path_len(path_leaf_to_root: list[ParsedCert]) -> tuple[bool, dict | None]:
    """pathLenConstraint in CA cert C limits non-self-issued CA certs below it."""
    n = len(path_leaf_to_root)
    for i, ca in enumerate(path_leaf_to_root[1:], start=1):
        if ca.path_len is None:
            continue
        below = [
            c for c in path_leaf_to_root[:i]
            if c.subject_der != c.issuer_der and c.is_ca
        ]
        if len(below) > ca.path_len:
            return False, {"rule": "PATH_LEN", "at": ca.fingerprint,
                           "path_len": ca.path_len, "counted_below": len(below)}
    return True, None


def check_eku(path_leaf_to_root: list[ParsedCert]) -> tuple[bool, dict | None]:
    """Code-signing EKU profile: leaf must assert codeSigning; any EKU in a
    CA must also include it (RFC 5280 §4.2.1.12)."""
    leaf = path_leaf_to_root[0]
    if leaf.eku is None or OID_EKU_CODE_SIGNING not in leaf.eku:
        return False, {"rule": "EKU", "at": leaf.fingerprint,
                       "required": OID_EKU_CODE_SIGNING, "present": sorted(leaf.eku or [])}
    for ca in path_leaf_to_root[1:]:
        if ca.eku is not None and OID_EKU_CODE_SIGNING not in ca.eku:
            return False, {"rule": "EKU", "at": ca.fingerprint,
                           "present": sorted(ca.eku)}
    return True, None


def process_policies(path_leaf_to_root: list[ParsedCert],
                     initial_policies: frozenset[str]) -> tuple[bool, dict | None, list[dict]]:
    """RFC 5280 §6.1.3/§6.1.4 policy processing with an explicit policy tree.

    Covers certificatePolicies intersection, anyPolicy suppression via
    inhibitAnyPolicy / requireExplicitPolicy, and policyMappings that are
    allowed or inhibited layer by layer. Qualifiers (CPS URIs / user notices)
    are accepted as present but never influence the decision.
    """
    path = list(reversed(path_leaf_to_root))  # root -> leaf
    n = len(path)
    ANY = OID_ANY_POLICY
    LARGE = 10 ** 6

    class Node:
        __slots__ = ("policy", "expected", "parent", "lineage")

        def __init__(self, policy, expected, parent, lineage=frozenset()):
            self.policy = policy
            self.expected = set(expected)
            self.parent = parent
            # Concrete policy OIDs accumulated root->this node, including
            # both sides of mappings, so the final intersection can match a
            # user policy that was mapped deeper in the chain.
            self.lineage = frozenset(lineage)

    # Defaults from RFC 5280 §6.1.2 (b)/(e); user supplies no initial
    # constraint values.
    explicit = n
    inhibit_any = n
    inhibit_map = n + 1
    parents = [Node(ANY, {ANY}, -1)]
    trace: list[dict] = []

    for i, cert in enumerate(path, start=1):
        self_issued = cert.subject_der == cert.issuer_der
        # RFC 5280 §6.1.3 ordering: the certificate is matched against the
        # *current* counters; non-self-issued certs then consume one level;
        # the certificate's own constraint extensions finally take effect
        # for certificates below it. This reproduces the PKITS semantics
        # (e.g. inhibitAnyPolicy SkipCerts=1 admits anyPolicy in the first
        # CA but suppresses it in the next).
        mappings = list(cert.policy_mappings)
        if inhibit_map == 0 and mappings:
            return False, {"rule": "POLICY", "at": cert.fingerprint,
                           "reason": "policyMapping_inhibited",
                           "mappings": [list(m) for m in mappings]}, trace

        cps = sorted(cert.policies.oids)
        kids: list[Node] = []
        # (b)/(c) key policy matching.
        for p in cps:
            for pi, node in enumerate(parents):
                if p == ANY:
                    if node.policy == ANY and (i == 1 or self_issued
                                              or inhibit_any > 0):
                        kids.append(Node(ANY, node.expected, pi, node.lineage))
                    else:
                        # anyPolicy suppressed: expand only concrete expected
                        # policies, never re-introduce ANY.
                        for o in sorted(node.expected):
                            if o == ANY:
                                continue
                            kids.append(Node(o, {o}, pi,
                                             node.lineage | {o}))
                elif node.policy == ANY or p in node.expected:
                    kids.append(Node(p, {p}, pi, node.lineage | {p}))
        # (d) policy mappings.
        if mappings:
            for idp, sdp in mappings:
                for node in parents:
                    if idp in node.expected:
                        node.expected.add(sdp)
                        node.expected.discard(idp)
            for idp, sdp in mappings:
                for pi, node in enumerate(parents):
                    if node.policy == ANY and sdp in node.expected:
                        kids.append(Node(sdp, {sdp}, pi,
                                         node.lineage | {idp, sdp}))
                for k in kids:
                    if k.policy == idp:
                        k.policy = sdp
                        k.expected = {sdp}
                        k.lineage = k.lineage | {idp, sdp}
            seen = set()
            deduped = []
            for k in kids:
                key = (k.parent, k.policy, tuple(sorted(k.expected)),
                       tuple(sorted(k.lineage)))
                if key not in seen:
                    seen.add(key)
                    deduped.append(k)
            kids = deduped
        # anyPolicy suppression at this depth.
        if inhibit_any == 0 and i > 1 and not self_issued:
            kids = [k for k in kids if k.policy != ANY]
        if not kids:
            return False, {"rule": "POLICY", "at": cert.fingerprint,
                           "reason": "valid_policy_tree_empty",
                           "certificate_policies": cps}, trace

        # Consume one level, then adopt this certificate's constraints.
        if not self_issued:
            explicit = max(explicit - 1, 0)
            inhibit_any = max(inhibit_any - 1, 0)
            inhibit_map = max(inhibit_map - 1, 0)
        if cert.require_explicit_policy is not None:
            explicit = min(explicit, cert.require_explicit_policy)
        if cert.inhibit_policy_mapping is not None:
            inhibit_map = min(inhibit_map, cert.inhibit_policy_mapping)
        if cert.inhibit_any_policy is not None:
            inhibit_any = min(inhibit_any, cert.inhibit_any_policy)

        trace.append({
            "certificate": cert.fingerprint,
            "depth": i,
            "certificate_policies": cps,
            "valid_policies": sorted({k.policy for k in kids}),
            "explicit_policy_remaining": explicit,
            "inhibit_any_policy_remaining": inhibit_any,
            "inhibit_policy_mapping_remaining": inhibit_map,
            "applied_mappings": [list(m) for m in mappings],
        })
        parents = kids

    # §6.1.5 wrap-up policy intersection. Union every leaf lineage (this is
    # what concrete policies, including mapped ones, the chain can assert).
    authority_concrete: set[str] = set()
    has_any_leaf = False
    for k in parents:
        if k.policy == ANY:
            has_any_leaf = True
        else:
            authority_concrete |= k.lineage | {k.policy}
    user = set(initial_policies)
    if user == {ANY}:
        result = set(authority_concrete)
        if has_any_leaf:
            result.add(ANY)
    else:
        result = authority_concrete & user
        # An anyPolicy leaf satisfies any explicitly requested user policy
        # unless explicit policy was required before the leaf.
        if has_any_leaf and explicit > 0:
            result |= user
    if not result:
        return False, {"rule": "POLICY", "at": path[-1].fingerprint,
                       "reason": "no_acceptable_policy",
                       "authority_policies": sorted(
                           {k.policy for k in parents}),
                       "initial_policies": sorted(user)}, trace
    return True, {"user_constrained_policy_set": sorted(result)}, trace


def validate_static_chain(path_leaf_to_root: list[ParsedCert],
                          signed_at: int,
                          initial_policies: frozenset[str]) -> tuple[bool, dict | None, list[dict]]:
    """Validity windows, basic constraints/KU are checked during graph
    traversal; this re-runs name/pathLen/EKU/policy on the complete chain
    and returns the policy trace for the evidence package."""
    ok, detail = check_path_len(path_leaf_to_root)
    if not ok:
        return False, detail, []
    ok, detail = check_name_constraints(path_leaf_to_root)
    if not ok:
        return False, detail, []
    ok, detail = check_eku(path_leaf_to_root)
    if not ok:
        return False, detail, []
    ok, detail, trace = process_policies(path_leaf_to_root, initial_policies)
    if not ok:
        return False, detail, trace
    return True, detail, trace
