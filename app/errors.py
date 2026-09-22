"""Stable structured error codes.

Any encoding/algorithm outside the implemented RFC 5280 profile yields
``UNSUPPORTED`` — never silent downgrade acceptance.
"""
from __future__ import annotations


class ProfileError(Exception):
    """Base class for profile violations carrying a stable machine code."""

    code = "PROFILE_ERROR"

    def __init__(self, message: str, detail: dict | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


class UnsupportedError(ProfileError):
    code = "UNSUPPORTED"


class MalformedEvidenceError(ProfileError):
    code = "MALFORMED_EVIDENCE"


class ConflictError(Exception):
    """Client request id reused with different normalized content."""

    def __init__(self, message: str, existing: dict | None = None):
        super().__init__(message)
        self.existing = existing or {}


class NotFoundError(Exception):
    pass


# Signature / public-key algorithm profile
# (name, OID) pairs that the service knows how to verify.
SUPPORTED_SIG_ALGS: dict[str, str] = {
    # RSA PKCS#1 v1.5
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.113549.1.1.11": "SHA256_WITH_RSA",
    "1.2.840.113549.1.1.12": "SHA384_WITH_RSA",
    "1.2.840.113549.1.1.13": "SHA512_WITH_RSA",
    # ECDSA
    "1.2.840.10045.4.3.2": "ECDSA_WITH_SHA256",
    "1.2.840.10045.4.3.3": "ECDSA_WITH_SHA384",
    "1.2.840.10045.4.3.4": "ECDSA_WITH_SHA512",
    # Pure EdDSA
    "1.3.101.112": "ED25519",
}

SUPPORTED_PUBLIC_KEY_ALGS: dict[str, str] = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.80000.10045.2.1": "EC",
    "1.3.101.112": "ED25519",
}

SUPPORTED_NAMED_CURVES: dict[str, str] = {
    "1.2.840.10045.3.1.7": "SECP256R1",  # P-256 (P-384/P-521 -> UNSUPPORTED)
}

SUPPORTED_RSA_SIZES = (2048, 3072, 4096)
SUPPORTED_HASHES = {"2.16.840.1.101.3.4.2.1": "SHA256",
                    "2.16.840.1.101.3.4.2.2": "SHA384",
                    "2.16.840.1.101.3.4.2.3": "SHA512"}

# 1.3.6.1.5.5.7.3.3 — id-kp-codeSigning
OID_EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
# 1.3.6.1.5.5.7.3.9 — id-kp-OCSPSigning
OID_EKU_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"
# 2.5.29.32.0 — anyPolicy
OID_ANY_POLICY = "2.5.29.32.0"
