"""
SPIFFE JWT-SVID verification: identity issued by the customer's own infrastructure.

WHY THIS AND NOT ANOTHER BEARER TOKEN
A shared bearer token says "whoever holds this string". A SPIFFE SVID says "this
workload, attested by the platform it runs on, valid for the next few minutes". The
customer's own issuer decides who the agent is; we only verify and map. That means
UBAG stops being one more credential to provision and rotate, and starts consuming
the identity the platform already assigns. It is also the integration path into
Google's zero-trust reference architecture, where SPIFFE is the named standard, and
it is cloud-neutral because SPIFFE is an open spec rather than one vendor's IAM.

WHAT THIS DELIBERATELY DOES NOT DO
It does not admit an SVID just because the signature checks out. A valid identity is
not an authorization: the SPIFFE ID must ALSO be explicitly registered here, or the
answer is no. Auto-admitting every workload in a trust domain would hand the whole
domain the gateway, which is the opposite of the point.

X.509-SVIDs are the other half of SPIFFE and are not handled here, because behind a
managed proxy the client certificate is usually not available to the application at
all. JWT-SVID is what survives that hop.

Fail CLOSED on every path. Requires the `cryptography` package.

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import base64
import json
import math
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

# JWS algorithms a SPIFFE issuer realistically emits. Anything else, including
# "none" and any HMAC family, is refused: an HMAC alg with a public JWKS is the
# classic key-confusion forgery, where the published verification key is used as
# the signing secret.
_ALLOWED_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA")

_EC_CURVES = {"ES256": ("P-256", "SHA256"), "ES384": ("P-384", "SHA384"),
              "ES512": ("P-521", "SHA512")}
_RS_HASHES = {"RS256": "SHA256", "RS384": "SHA384", "RS512": "SHA512"}


@dataclass
class SvidResult:
    ok: bool
    reason: str
    spiffe_id: str = ""
    trust_domain: str = ""
    path: str = ""
    claims: dict = field(default_factory=dict)


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_uint(s: str) -> int:
    return int.from_bytes(_b64url_decode(s), "big")


def parse_spiffe_id(value: str):
    """(trust_domain, path) for a well-formed SPIFFE ID, else (None, None).

    Per the spec: scheme must be exactly `spiffe`, there is no port, no userinfo,
    no query and no fragment, and the trust domain is the authority lowercased.
    """
    try:
        u = urlparse(str(value))
    except Exception:                                        # noqa: BLE001
        return None, None
    if u.scheme != "spiffe" or not u.netloc:
        return None, None
    if u.query or u.fragment or "@" in u.netloc or ":" in u.netloc:
        return None, None
    path = u.path or ""
    if path and not path.startswith("/"):
        return None, None
    return u.netloc.lower(), path


def _key_from_jwk(jwk: dict, alg: str):
    """A public key object from one JWK entry, or None if it cannot be used."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519

    kty = jwk.get("kty")
    try:
        if kty == "RSA" and alg in _RS_HASHES:
            return rsa.RSAPublicNumbers(
                e=_b64url_uint(jwk["e"]), n=_b64url_uint(jwk["n"])).public_key()
        if kty == "EC" and alg in _EC_CURVES:
            want_crv, _ = _EC_CURVES[alg]
            if jwk.get("crv") != want_crv:
                return None
            curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(),
                     "P-521": ec.SECP521R1()}[want_crv]
            return ec.EllipticCurvePublicNumbers(
                x=_b64url_uint(jwk["x"]), y=_b64url_uint(jwk["y"]),
                curve=curve).public_key()
        if kty == "OKP" and alg == "EdDSA":
            if jwk.get("crv") != "Ed25519":
                return None
            return ed25519.Ed25519PublicKey.from_public_bytes(
                _b64url_decode(jwk["x"]))
    except (KeyError, ValueError, TypeError):
        return None
    return None


def _verify_signature(key, alg: str, signing_input: bytes, sig: bytes) -> bool:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
    from cryptography.exceptions import InvalidSignature

    try:
        if alg in _RS_HASHES:
            key.verify(sig, signing_input, padding.PKCS1v15(),
                       getattr(hashes, _RS_HASHES[alg])())
            return True
        if alg in _EC_CURVES:
            # JWS carries R||S fixed width; `cryptography` wants DER.
            half = len(sig) // 2
            if half == 0 or len(sig) % 2:
                return False
            r = int.from_bytes(sig[:half], "big")
            s = int.from_bytes(sig[half:], "big")
            key.verify(utils.encode_dss_signature(r, s), signing_input,
                       ec.ECDSA(getattr(hashes, _EC_CURVES[alg][1])()))
            return True
        if alg == "EdDSA":
            key.verify(sig, signing_input)
            return True
    except InvalidSignature:
        return False
    except Exception:                                        # noqa: BLE001
        return False
    return False


def verify_jwt_svid(token: Optional[str], bundle, *, audience: str,
                    trust_domain: Optional[str] = None, leeway_s: float = 30.0,
                    max_ttl_s: float = 86400.0,
                    now: Optional[float] = None) -> SvidResult:
    """Verify a JWT-SVID against a trust bundle (a JWKS dict or its JSON text).

    `audience` is REQUIRED and checked. An SVID minted for another service is not
    valid here: without that check, any workload able to obtain a token for any
    audience in the trust domain could replay it at this gateway.
    """
    if not token:
        return SvidResult(False, "no SVID presented")
    if not audience:
        return SvidResult(False, "an audience must be configured to verify an SVID")
    if isinstance(bundle, str):
        try:
            bundle = json.loads(bundle)
        except ValueError:
            return SvidResult(False, "trust bundle is not valid JSON")
    keys = (bundle or {}).get("keys")
    if not isinstance(keys, list) or not keys:
        return SvidResult(False, "trust bundle has no keys")

    try:
        h_b64, p_b64, s_b64 = token.split(".")
        signing_input = (h_b64 + "." + p_b64).encode("ascii")
        header = json.loads(_b64url_decode(h_b64))
        claims = json.loads(_b64url_decode(p_b64))
        sig = _b64url_decode(s_b64)
    except Exception:                                        # noqa: BLE001
        return SvidResult(False, "malformed SVID")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return SvidResult(False, "malformed SVID: header/claims must be objects")

    alg = header.get("alg")
    if alg not in _ALLOWED_ALGS:
        return SvidResult(False, f"unsupported alg {alg!r}")

    kid = header.get("kid")
    # A `kid` selects one key. Without one every key of the right type is tried,
    # which is correct but slower; it is never a reason to skip verification.
    candidates = [k for k in keys if isinstance(k, dict)
                  and (kid is None or k.get("kid") == kid)]
    if not candidates:
        return SvidResult(False, f"no key in the trust bundle matches kid {kid!r}")

    verified = False
    for jwk in candidates:
        if jwk.get("use") not in (None, "sig"):
            continue
        if jwk.get("alg") not in (None, alg):
            continue
        key = _key_from_jwk(jwk, alg)
        if key is not None and _verify_signature(key, alg, signing_input, sig):
            verified = True
            break
    if not verified:
        return SvidResult(False, "SVID signature verification failed")

    current = time.time() if now is None else float(now)
    try:
        exp = float(claims.get("exp", 0))
        iat = float(claims.get("iat", 0) or 0)
    except (TypeError, ValueError):
        return SvidResult(False, "bad iat/exp")
    if not math.isfinite(exp) or not math.isfinite(iat):
        return SvidResult(False, "bad iat/exp: values must be finite")
    # SPIFFE requires exp. A token that never expires is a password.
    if exp <= 0:
        return SvidResult(False, "SVID has no expiry")
    if current > exp + leeway_s:
        return SvidResult(False, "SVID expired")
    if iat and current + leeway_s < iat:
        return SvidResult(False, "SVID not yet valid (iat in future)")
    if iat and exp - iat > max_ttl_s:
        return SvidResult(False, f"SVID lifetime exceeds max {max_ttl_s:.0f}s")

    aud = claims.get("aud")
    aud = [aud] if isinstance(aud, str) else list(aud or [])
    if audience not in [str(a) for a in aud]:
        return SvidResult(False, "SVID is not for this audience")

    domain, path = parse_spiffe_id(claims.get("sub", ""))
    if not domain:
        return SvidResult(False, "SVID subject is not a valid SPIFFE ID")
    # The bundle proves the key; this proves the ISSUER did not mint an identity
    # for a trust domain it has no business speaking for.
    if trust_domain and domain != str(trust_domain).lower():
        return SvidResult(False,
                          f"SVID is from trust domain '{domain}', not '{trust_domain}'")

    return SvidResult(True, "SVID verified", spiffe_id=str(claims["sub"]),
                      trust_domain=domain, path=path, claims=claims)
