"""
Signed decision receipt tests. Runs under pytest, or standalone:
    python tests/test_receipt.py

The tests that matter here are the negative ones. A receipt that verifies when it
should is worth little; a receipt that verifies when the arguments have been swapped
is a bearer token that authorizes anything, which is worse than having no receipt at
all because it looks like a control.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ubag_core import (sign_receipt, verify_receipt, action_digest,     # noqa: E402
                       generate_keypair, InMemoryReplayStore)
from ubag_core.receipt import (_b64url_encode, _canonical,              # noqa: E402
                               RECEIPT_TYP)

PRIV, PUB = generate_keypair()

TOOL = "send_money"
ARGS = {"destination": "alice@example.com", "amount": 100}


def _receipt(**over):
    kw = dict(decision="ALLOW", tool=TOOL, arguments=ARGS, tenant="acme",
              session="s1", reason="authorized")
    kw.update(over)
    return sign_receipt(PRIV, **kw)


# ── the happy path ──────────────────────────────────────────────────────────────
def test_round_trip_verifies():
    r = verify_receipt(PUB, TOOL, ARGS, _receipt(), tenant_id="acme")
    assert r.ok, r.reason
    assert r.claims["decision"] == "ALLOW"
    assert r.jti


def test_digest_is_key_order_independent():
    a = action_digest(TOOL, {"destination": "x", "amount": 1})
    b = action_digest(TOOL, {"amount": 1, "destination": "x"})
    assert a == b


# ── the binding: this is the property the whole module exists for ───────────────
def test_swapped_amount_is_refused():
    token = _receipt()
    tampered = dict(ARGS, amount=5000)
    r = verify_receipt(PUB, TOOL, tampered, token)
    assert not r.ok
    assert "does not match this action" in r.reason


def test_swapped_destination_is_refused():
    token = _receipt()
    tampered = dict(ARGS, destination="attacker@evil.com")
    assert not verify_receipt(PUB, TOOL, tampered, token).ok


def test_added_argument_is_refused():
    token = _receipt()
    tampered = dict(ARGS, cc="attacker@evil.com")
    assert not verify_receipt(PUB, TOOL, tampered, token).ok


def test_receipt_for_one_tool_does_not_release_another():
    token = _receipt()
    r = verify_receipt(PUB, "delete_account", ARGS, token)
    assert not r.ok
    assert "authorizes" in r.reason


# ── verdict ─────────────────────────────────────────────────────────────────────
def test_block_receipt_does_not_satisfy_allow():
    token = _receipt(decision="BLOCK", reason="novel destination")
    r = verify_receipt(PUB, TOOL, ARGS, token)
    assert not r.ok
    assert "not ALLOW" in r.reason
    # ... but it verifies as the BLOCK it is, which is what an auditor reads.
    assert verify_receipt(PUB, TOOL, ARGS, token, require_decision="BLOCK").ok


# ── signature and format ────────────────────────────────────────────────────────
def test_other_key_is_refused():
    _, other_pub = generate_keypair()
    assert not verify_receipt(other_pub, TOOL, ARGS, _receipt()).ok


def test_no_token_is_refused():
    assert not verify_receipt(PUB, TOOL, ARGS, None).ok
    assert not verify_receipt(PUB, TOOL, ARGS, "").ok


def test_malformed_token_is_refused():
    for bad in ("garbage", "a.b", "a.b.c", "...", "x" * 50):
        assert not verify_receipt(PUB, TOOL, ARGS, bad).ok


def test_payload_edit_breaks_the_signature():
    h, p, s = _receipt().split(".")
    claims = json.loads(__import__("base64").urlsafe_b64decode(p + "==="))
    claims["decision"] = "ALLOW"
    claims["act"] = action_digest(TOOL, {"destination": "attacker", "amount": 9999})
    forged = h + "." + _b64url_encode(_canonical(claims)) + "." + s
    r = verify_receipt(PUB, TOOL, {"destination": "attacker", "amount": 9999}, forged)
    assert not r.ok
    assert "signature" in r.reason


def test_capability_grant_shape_is_not_a_receipt():
    """Cross-protocol confusion: same alg, same key, different typ."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key(PRIV.encode(), password=None)
    now = time.time()
    header = {"alg": "EdDSA", "typ": "UBAG-GRANT"}
    claims = {"decision": "ALLOW", "tool": TOOL, "act": action_digest(TOOL, ARGS),
              "tenant": "acme", "iat": now, "exp": now + 60, "jti": "abc"}
    h = _b64url_encode(_canonical(header))
    p = _b64url_encode(_canonical(claims))
    token = h + "." + p + "." + _b64url_encode(key.sign((h + "." + p).encode()))
    r = verify_receipt(PUB, TOOL, ARGS, token)
    assert not r.ok
    assert "not a UBAG receipt" in r.reason


# ── time ────────────────────────────────────────────────────────────────────────
def test_expired_receipt_is_refused():
    token = _receipt(ttl_s=10, now=time.time() - 600)
    r = verify_receipt(PUB, TOOL, ARGS, token)
    assert not r.ok and "expired" in r.reason


def test_future_receipt_is_refused():
    token = _receipt(now=time.time() + 600)
    r = verify_receipt(PUB, TOOL, ARGS, token)
    assert not r.ok and "not yet valid" in r.reason


def test_overlong_lifetime_is_refused():
    token = _receipt(ttl_s=86400)
    r = verify_receipt(PUB, TOOL, ARGS, token)
    assert not r.ok and "lifetime exceeds" in r.reason


# ── tenant ──────────────────────────────────────────────────────────────────────
def test_other_tenant_is_refused():
    assert not verify_receipt(PUB, TOOL, ARGS, _receipt(), tenant_id="globex").ok


def test_untenanted_receipt_fails_closed_when_tenant_enforced():
    token = _receipt(tenant=None)
    assert not verify_receipt(PUB, TOOL, ARGS, token, tenant_id="acme").ok


# ── replay ──────────────────────────────────────────────────────────────────────
def test_receipt_is_single_use_when_consumed():
    store = InMemoryReplayStore()
    token = _receipt()
    first = verify_receipt(PUB, TOOL, ARGS, token, replay_store=store, consume=True)
    assert first.ok, first.reason
    second = verify_receipt(PUB, TOOL, ARGS, token, replay_store=store, consume=True)
    assert not second.ok and "replay" in second.reason


def test_consume_without_a_store_fails_closed():
    r = verify_receipt(PUB, TOOL, ARGS, _receipt(), consume=True)
    assert not r.ok and "replay store is required" in r.reason


def test_typ_constant_is_stable():
    """Changing this breaks every deployed verifier. Deliberate change only."""
    assert RECEIPT_TYP == "UBAG-RCPT"


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
    print(f"\n{'FAILED' if failed else 'all receipt tests passed'}"
          f"{f' ({failed})' if failed else ''}")
    raise SystemExit(1 if failed else 0)
