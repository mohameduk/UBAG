"""
SPIFFE JWT-SVID verification tests. Runs under pytest, or standalone:
    python tests/test_spiffe.py

The negatives are the point. The two that would be quietly catastrophic are the
audience check (an SVID minted for another service replayed here) and the alg
check (an HMAC alg verified against the published JWKS, which is forgery).
"""
import base64
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ubag_core.spiffe import (verify_jwt_svid, parse_spiffe_id,   # noqa: E402
                              SvidResult)

from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization        # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, utils    # noqa: E402

AUD = "ubag-gateway"
DOMAIN = "acme.example"
SUB = f"spiffe://{DOMAIN}/ns/prod/sa/payments-bot"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64uint(n: int) -> str:
    return _b64(n.to_bytes((n.bit_length() + 7) // 8 or 1, "big"))


# ── issuers, one per algorithm family ───────────────────────────────────────────
EC_KEY = ec.generate_private_key(ec.SECP256R1())
RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ED_KEY = ed25519.Ed25519PrivateKey.generate()


def _jwks():
    ecn = EC_KEY.public_key().public_numbers()
    rsn = RSA_KEY.public_key().public_numbers()
    edb = ED_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    size = (ecn.curve.key_size + 7) // 8
    return {"keys": [
        {"kty": "EC", "crv": "P-256", "kid": "ec1",
         "x": _b64(ecn.x.to_bytes(size, "big")),
         "y": _b64(ecn.y.to_bytes(size, "big"))},
        {"kty": "RSA", "kid": "rsa1", "n": _b64uint(rsn.n), "e": _b64uint(rsn.e)},
        {"kty": "OKP", "crv": "Ed25519", "kid": "ed1", "x": _b64(edb)},
    ]}


JWKS = _jwks()


def _sign(alg, kid, claims, key=None):
    header = _b64(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    payload = _b64(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    if alg == "ES256":
        der = (key or EC_KEY).sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    elif alg == "RS256":
        sig = (key or RSA_KEY).sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "EdDSA":
        sig = (key or ED_KEY).sign(signing_input)
    else:                                        # forged / unsupported
        sig = b"\x00" * 32
    return f"{header}.{payload}.{_b64(sig)}"


def _claims(**over):
    now = time.time()
    c = {"sub": SUB, "aud": [AUD], "exp": now + 300, "iat": now}
    c.update(over)
    return c


def _v(token, **kw):
    kw.setdefault("audience", AUD)
    kw.setdefault("trust_domain", DOMAIN)
    return verify_jwt_svid(token, JWKS, **kw)


# ── the SPIFFE ID grammar ───────────────────────────────────────────────────────
def test_valid_spiffe_ids_parse():
    assert parse_spiffe_id(SUB) == (DOMAIN, "/ns/prod/sa/payments-bot")
    assert parse_spiffe_id("spiffe://Acme.Example/x")[0] == "acme.example"


def test_malformed_spiffe_ids_are_rejected():
    for bad in ("https://acme.example/x", "spiffe:///x", "spiffe://a:8443/x",
                "spiffe://u@a/x", "spiffe://a/x?q=1", "spiffe://a/x#f",
                "", "not a uri"):
        assert parse_spiffe_id(bad) == (None, None), bad


# ── the happy paths, one per algorithm ──────────────────────────────────────────
def test_es256_verifies():
    r = _v(_sign("ES256", "ec1", _claims()))
    assert r.ok, r.reason
    assert r.spiffe_id == SUB and r.trust_domain == DOMAIN
    assert r.path == "/ns/prod/sa/payments-bot"


def test_rs256_verifies():
    assert _v(_sign("RS256", "rsa1", _claims())).ok


def test_eddsa_verifies():
    assert _v(_sign("EdDSA", "ed1", _claims())).ok


def test_aud_as_a_bare_string_is_accepted():
    assert _v(_sign("ES256", "ec1", _claims(aud=AUD))).ok


# ── forgery ─────────────────────────────────────────────────────────────────────
def test_hmac_alg_is_refused():
    """Key confusion: the published JWKS used as an HMAC secret."""
    r = _v(_sign("HS256", "ec1", _claims()))
    assert not r.ok and "unsupported alg" in r.reason


def test_alg_none_is_refused():
    r = _v(_sign("none", "ec1", _claims()))
    assert not r.ok and "unsupported alg" in r.reason


def test_another_issuers_key_is_refused():
    other = ec.generate_private_key(ec.SECP256R1())
    r = _v(_sign("ES256", "ec1", _claims(), key=other))
    assert not r.ok and "signature" in r.reason


def test_edited_claims_break_the_signature():
    token = _sign("ES256", "ec1", _claims())
    h, _, s = token.split(".")
    forged = h + "." + _b64(json.dumps(
        _claims(sub=f"spiffe://{DOMAIN}/ns/prod/sa/admin")).encode()) + "." + s
    assert not _v(forged).ok


def test_unknown_kid_is_refused():
    assert not _v(_sign("ES256", "nope", _claims())).ok


def test_malformed_tokens_are_refused():
    for bad in ("", None, "a.b", "garbage", "a.b.c"):
        assert not _v(bad).ok


# ── scope: a valid identity is not an authorization ─────────────────────────────
def test_svid_for_another_audience_is_refused():
    r = _v(_sign("ES256", "ec1", _claims(aud=["some-other-service"])))
    assert not r.ok and "audience" in r.reason


def test_svid_from_another_trust_domain_is_refused():
    r = _v(_sign("ES256", "ec1", _claims(sub="spiffe://evil.example/ns/x/sa/y")))
    assert not r.ok and "trust domain" in r.reason


def test_non_spiffe_subject_is_refused():
    r = _v(_sign("ES256", "ec1", _claims(sub="https://acme.example/bot")))
    assert not r.ok and "not a valid SPIFFE ID" in r.reason


def test_verification_requires_a_configured_audience():
    r = verify_jwt_svid(_sign("ES256", "ec1", _claims()), JWKS, audience="")
    assert not r.ok


# ── time ────────────────────────────────────────────────────────────────────────
def test_expired_svid_is_refused():
    now = time.time()
    r = _v(_sign("ES256", "ec1", _claims(exp=now - 600, iat=now - 900)))
    assert not r.ok and "expired" in r.reason


def test_svid_without_expiry_is_refused():
    c = _claims()
    c.pop("exp")
    r = _v(_sign("ES256", "ec1", c))
    assert not r.ok and "no expiry" in r.reason


def test_future_svid_is_refused():
    now = time.time()
    r = _v(_sign("ES256", "ec1", _claims(iat=now + 900, exp=now + 1800)))
    assert not r.ok and "not yet valid" in r.reason


def test_overlong_svid_is_refused():
    now = time.time()
    r = _v(_sign("ES256", "ec1", _claims(iat=now, exp=now + 90 * 86400)))
    assert not r.ok and "lifetime exceeds" in r.reason


# ── bundle handling ─────────────────────────────────────────────────────────────
def test_empty_bundle_fails_closed():
    assert not verify_jwt_svid(_sign("ES256", "ec1", _claims()), {"keys": []},
                               audience=AUD).ok


def test_bundle_as_json_text_is_accepted():
    assert verify_jwt_svid(_sign("ES256", "ec1", _claims()), json.dumps(JWKS),
                           audience=AUD, trust_domain=DOMAIN).ok


def test_garbage_bundle_fails_closed():
    assert not verify_jwt_svid(_sign("ES256", "ec1", _claims()), "{not json",
                               audience=AUD).ok


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok    {name}")
            except AssertionError as exc:
                failed += 1
                print(f"  FAIL  {name}: {exc}")
    print(f"\n{'FAILED' if failed else 'all SPIFFE tests passed'}"
          f"{f' ({failed})' if failed else ''}")
    raise SystemExit(1 if failed else 0)
