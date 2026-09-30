"""Safe injection: the agent holds a placeholder; the real key appears only on
the bound host, in the bound header, and a stray placeholder is a tripwire."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from ubag_core import SafeInjector, StaticVault, PLACEHOLDER_PREFIX

REAL = "sk-live-REALSECRET-0001"


class CountingVault(StaticVault):
    def __init__(self, s):
        super().__init__(s)
        self.reads = 0

    def resolve(self, ref):
        self.reads += 1
        return super().resolve(ref)


def _inj():
    v = CountingVault({"vault:api": REAL})
    inj = SafeInjector(v)
    return inj, inj.mint("vault:api", "api.example.com"), v


def test_placeholder_is_not_the_secret():
    inj, ph, _ = _inj()
    assert ph.startswith(PLACEHOLDER_PREFIX) and REAL not in ph


def test_swap_on_bound_host_and_header():
    inj, ph, v = _inj()
    r = inj.inject("api.example.com", "https://api.example.com/v1",
                   {"Authorization": f"Bearer {ph}"})
    assert r.ok and r.headers["Authorization"] == f"Bearer {REAL}"
    assert r.injected == [{"ref": "vault:api", "host": "api.example.com",
                           "header": "authorization"}]
    assert v.reads == 1


def test_other_host_is_blocked_as_exfiltration_and_vault_untouched():
    inj, ph, v = _inj()
    r = inj.inject("evil.example", "https://evil.example/c",
                   {"Authorization": f"Bearer {ph}"})
    assert not r.ok and r.tripwire and "exfiltration" in r.reason
    assert v.reads == 0 and REAL not in repr(r.headers)


@pytest.mark.parametrize("url,headers,body", [
    ("https://api.example.com/v1?key={ph}", {}, ""),
    ("https://api.example.com/v1", {"X-Debug": "{ph}"}, ""),
    ("https://api.example.com/v1", {}, '{{"token": "{ph}"}}'),
])
def test_placeholder_outside_its_header_is_blocked_even_on_the_right_host(url, headers, body):
    inj, ph, v = _inj()
    r = inj.inject("api.example.com", url.format(ph=ph),
                   {k: val.format(ph=ph) for k, val in headers.items()}, body.format(ph=ph))
    assert not r.ok and r.tripwire and v.reads == 0


def test_forged_placeholder_is_refused():
    inj, ph, v = _inj()
    r = inj.inject("api.example.com", "", {"Authorization": "Bearer ubag_ph_" + "0" * 24})
    assert not r.ok and r.tripwire and "never minted" in r.reason


def test_request_without_placeholder_passes_untouched():
    inj, _, v = _inj()
    r = inj.inject("api.example.com", "https://api.example.com/", {"Accept": "json"})
    assert r.ok and r.headers == {"Accept": "json"} and v.reads == 0


def test_echoed_secret_is_redacted_on_the_way_back():
    inj, ph, _ = _inj()
    r = inj.inject("api.example.com", "", {"Authorization": f"Bearer {ph}"})
    echoed = {"headers": {"Authorization": f"Bearer {REAL}"}, "note": REAL}
    clean = r.redact(echoed)
    assert REAL not in repr(clean)


def test_check_judges_without_reading_the_vault():
    inj, ph, v = _inj()
    good = inj.check("api.example.com", "", {"Authorization": f"Bearer {ph}"})
    bad = inj.check("evil.example", "", {"Authorization": f"Bearer {ph}"})
    assert good.ok and not bad.ok and bad.tripwire
    assert v.reads == 0 and REAL not in repr(good.headers)


def test_cannot_mint_for_a_key_the_vault_does_not_hold():
    inj = SafeInjector(StaticVault({}))
    with pytest.raises(KeyError):
        inj.mint("vault:missing", "api.example.com")
