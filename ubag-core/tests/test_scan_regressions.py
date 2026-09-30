"""Regressions for the 2026-09-29 Strix scan of ubag-core. Each test fails if the
corresponding hole reopens."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_core import _make_signer                                   # noqa: E402
from ubag_core import verify_grant, StaticStateProvider             # noqa: E402
from ubag_core.authorize import precheck_irreversible               # noqa: E402
from ubag_core.plan import Action                                   # noqa: E402
from ubag_core.injection import redact                              # noqa: E402


def _signer():
    s = _make_signer()
    if s is None:
        import pytest
        pytest.skip("cryptography not installed")
    return s


def test_grant_refuses_arguments_it_does_not_cover():
    pub, sign = _signer()
    now = time.time()
    tok = sign({"tool": "withdraw", "iat": now, "exp": now + 60, "jti": "a1",
                "bind": {"amount": {"lte": 100}}})
    r = verify_grant(pub, "withdraw", {"amount": 50, "admin_override": True}, tok)
    assert r.ok is False and "admin_override" in r.reason
    # the bound call alone still passes, reason and _cost are not parameters
    tok = sign({"tool": "withdraw", "iat": now, "exp": now + 60, "jti": "a2",
                "bind": {"amount": {"lte": 100}}})
    assert verify_grant(pub, "withdraw", {"amount": 50, "reason": "x", "_cost": 1}, tok).ok


def test_grant_allow_extra_is_an_explicit_opt_in():
    pub, sign = _signer()
    now = time.time()
    tok = sign({"tool": "withdraw", "iat": now, "exp": now + 60, "jti": "b1",
                "bind": {"amount": {"lte": 100}}, "allow_extra": ["memo"]})
    assert verify_grant(pub, "withdraw", {"amount": 50, "memo": "rent"}, tok).ok
    tok = sign({"tool": "withdraw", "iat": now, "exp": now + 60, "jti": "b2",
                "bind": {"amount": {"lte": 100}}, "allow_extra": ["memo"]})
    assert not verify_grant(pub, "withdraw", {"amount": 50, "to": "x"}, tok).ok


class _Owns(StaticStateProvider):
    def __init__(self, owned):
        super().__init__(allowed_destinations=None)
        self.owned = owned

    def owns_resource(self, principal_id, tool_name, arguments):
        return self.owned


def _cancel():
    return Action(step=1, tool="booking.cancel", destination="", amount=0.0,
                  reason="", arguments={"booking_id": "4471"})


def test_fire_time_recheck_halts_when_ownership_is_lost():
    ok, why = precheck_irreversible(_cancel(), _Owns(False), principal_id="alice")
    assert ok is False and "ownership" in why


def test_fire_time_recheck_passes_when_still_owned_or_unknown():
    assert precheck_irreversible(_cancel(), _Owns(True), principal_id="alice")[0] is True
    assert precheck_irreversible(_cancel(), _Owns(None), principal_id="alice")[0] is True


def test_redaction_covers_prefixes_keys_sets_and_escapes():
    s = ["secret", "secret_long"]
    assert "_long" not in redact("a secret_long b", s)
    assert "secret" not in repr(redact({"secret": 1, "k": {"secret_long"}}, s))
    esc = "".join(chr(92) + "u%04x" % ord(c) for c in "secret_long")
    assert esc not in redact('{"t":"' + esc + '"}', s)
    assert b"secret" not in redact(b"key=secret", s)
