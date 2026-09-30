"""
Live-loop tests.

The claim this file defends: what a visitor sees is produced by a real gateway
decision, and the gateway is the only thing deciding whether reality changes.

No network and no model key are required. The scripted provider stands in for the
LLM, which is the point: the loop must behave identically whichever model
proposes, because the gateway never reads the model's reasoning.
"""
from __future__ import annotations

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..")))

import pytest

import agent
import egress
import providers
from gym import ACTING_MEMBER, OTHER_MEMBER, REGISTRY

STRANGERS_BOOKING = "4471"          # belongs to OTHER_MEMBER
OWN_BOOKING = "9001"                # belongs to ACTING_MEMBER


def cfg(*verbs, mode="ENFORCE", host="gym.demo"):
    return {"mode": mode, "money": {"enabled": False}, "data": {"enabled": False},
            "network": {"enabled": True,
                        "sites": [{"name": host, "verbs": list(verbs)}]}}


@pytest.fixture
def session(request):
    name = f"test-{request.node.name}"
    agent.reset(name)
    return name


def fixed(tool, arguments, why="because", monkeypatch=None):
    """Pin the model's proposal so the test is about the gateway, not the model."""
    class Fixed(providers.Provider):
        id, label, model = "fixed", "Fixed", "test"
        def propose(self, system, task):
            return providers.Proposal(tool, dict(arguments), why)
    monkeypatch.setattr(providers, "get", lambda pid: Fixed())
    return Fixed


def ids(result):
    return {b["id"] for b in result["gym"]["bookings"]}


# ── the incident ─────────────────────────────────────────────────────────────

def test_cancel_is_refused_when_the_operator_never_granted_it(session, monkeypatch):
    fixed("booking.cancel", {"booking_id": STRANGERS_BOOKING}, monkeypatch=monkeypatch)
    r = agent.run_step(session=session, config=cfg("read", "create"),
                       provider_id="fixed", task="get me in")
    assert r["verdict"]["decision"] == "BLOCK"
    assert r["executed"] is False
    assert STRANGERS_BOOKING in ids(r), "the stranger's booking was cancelled anyway"


def test_granting_cancel_still_refuses_a_strangers_booking(session, monkeypatch):
    """"May cancel" is not "may cancel anything". With cancel GRANTED, the
    stranger's booking is still refused, on ownership, and it stays in the gym.
    This is the Melbourne bug caught at authorization time."""
    fixed("booking.cancel", {"booking_id": STRANGERS_BOOKING}, monkeypatch=monkeypatch)
    r = agent.run_step(session=session, config=cfg("read", "create", "cancel"),
                       provider_id="fixed", task="get me in")
    assert r["verdict"]["decision"] == "BLOCK"
    assert "resource ownership" in r["verdict"]["reason"]
    assert r["executed"] is False
    assert STRANGERS_BOOKING in ids(r), "the stranger's booking was cancelled anyway"


def test_the_same_grant_cancels_your_own_booking(session, monkeypatch):
    """The refusal must be policy, not a hardcoded demo: the same grant, against
    the same unpatched endpoint, cancels the acting member's own booking."""
    fixed("booking.cancel", {"booking_id": OWN_BOOKING}, monkeypatch=monkeypatch)
    r = agent.run_step(session=session, config=cfg("read", "create", "cancel"),
                       provider_id="fixed", task="drop my spot")
    assert r["verdict"]["decision"] == "ALLOW"
    assert r["executed"] is True
    assert r["result"]["ok"] is True
    assert r["result"]["cancelled"]["member"] == ACTING_MEMBER
    assert OWN_BOOKING not in ids(r), "the endpoint did not actually run"


def test_the_granted_verbs_still_work(session, monkeypatch):
    fixed("booking.create", {"class_id": "spin-6pm"}, monkeypatch=monkeypatch)
    r = agent.run_step(session=session, config=cfg("read", "create"),
                       provider_id="fixed", task="book it")
    assert r["verdict"]["decision"] == "ALLOW" and r["executed"] is True
    assert any(b["member"] == ACTING_MEMBER and b["id"] not in (OWN_BOOKING,)
               for b in r["gym"]["bookings"])


# ── shadow observes without standing in the way ──────────────────────────────
#
# Shadow puts the GATEWAY in shadow, not the agent. The agent keeps its own
# credentials and its own path, so production actions continue and UBAG only
# records what it would have done. A demo that stopped the agent in shadow would
# be telling a prospect that a shadow pilot breaks their agents, which is the
# opposite of the thing being sold.

def test_shadow_never_releases_the_gateway_credential(session, monkeypatch):
    fixed("booking.cancel", {"booking_id": OWN_BOOKING}, monkeypatch=monkeypatch)
    r = agent.run_step(session=session, config=cfg("read", "create", "cancel", mode="SHADOW"),
                       provider_id="fixed", task="get me in")
    assert r["verdict"]["decision"] == "ALLOW"
    assert r["key"]["released"] is False


def test_shadow_does_not_interrupt_the_agent_even_when_it_would_block(session, monkeypatch):
    """The whole zero-risk claim. Cancel is NOT granted, so the verdict is BLOCK,
    and the stranger's booking disappears anyway because UBAG was only watching.
    That is the exposure a pilot is meant to reveal."""
    fixed("booking.cancel", {"booking_id": STRANGERS_BOOKING}, monkeypatch=monkeypatch)
    r = agent.run_step(session=session, config=cfg("read", "create", mode="SHADOW"),
                       provider_id="fixed", task="get me in")
    assert r["verdict"]["decision"] == "BLOCK"
    assert r["executed"] is True, "shadow must not stop the agent"
    assert r["production_action_interrupted"] is False
    assert r["counterfactual"] is True
    assert STRANGERS_BOOKING not in ids(r), "the action really happened"


def test_enforce_is_the_mode_that_actually_stops_it(session, monkeypatch):
    """Same proposal, same verdict, and now the booking survives."""
    fixed("booking.cancel", {"booking_id": STRANGERS_BOOKING}, monkeypatch=monkeypatch)
    r = agent.run_step(session=session, config=cfg("read", "create", mode="ENFORCE"),
                       provider_id="fixed", task="get me in")
    assert r["verdict"]["decision"] == "BLOCK"
    assert r["executed"] is False
    assert r["production_action_interrupted"] is True
    assert STRANGERS_BOOKING in ids(r), "enforce must stop it"


def test_shadow_and_enforce_reach_the_same_verdict(session, monkeypatch):
    fixed("booking.cancel", {"booking_id": STRANGERS_BOOKING}, monkeypatch=monkeypatch)
    a = agent.run_step(session=session, config=cfg("read", mode="SHADOW"),
                       provider_id="fixed", task="x")
    agent.reset(session)
    b = agent.run_step(session=session, config=cfg("read", mode="ENFORCE"),
                       provider_id="fixed", task="x")
    assert a["verdict"]["decision"] == b["verdict"]["decision"]
    assert a["verdict"]["reason"] == b["verdict"]["reason"]


# ── the model cannot choose its own destination ──────────────────────────────

def test_a_model_supplied_destination_is_overwritten(session, monkeypatch):
    """A proposal that could name its own destination namespace could name a
    permitted one. The destination is derived, never accepted."""
    fixed("booking.cancel",
          {"booking_id": STRANGERS_BOOKING, "destination": "net:api.open-meteo.com"},
          monkeypatch=monkeypatch)
    r = agent.run_step(session=session, config=cfg("read", host="api.open-meteo.com"),
                       provider_id="fixed", task="x")
    assert r["proposal"]["destination"] == "net:gym.demo"
    assert r["verdict"]["decision"] == "BLOCK"
    assert STRANGERS_BOOKING in ids(r)


# ── the demo runs under its own egress policy ────────────────────────────────

@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8765/",
    "http://10.0.0.1/internal",
])
def test_internal_targets_are_refused_before_any_socket(session, monkeypatch, url):
    fixed("http.request", {"url": url}, monkeypatch=monkeypatch)
    r = agent.run_step(session=session, config=cfg("read", host="api.open-meteo.com"),
                       provider_id="fixed", task="fetch")
    assert r["verdict"]["decision"] == "BLOCK"
    assert r["executed"] is False


def test_an_unlisted_host_is_refused_even_when_the_verb_is_granted(session, monkeypatch):
    fixed("http.request", {"url": "https://evil.example/steal"}, monkeypatch=monkeypatch)
    r = agent.run_step(session=session, config=cfg("read", host="api.open-meteo.com"),
                       provider_id="fixed", task="fetch")
    assert r["verdict"]["decision"] == "BLOCK"


def test_the_guard_refuses_even_if_the_gateway_were_to_allow(monkeypatch):
    """Defence in depth: fetch() judges the target itself, so a policy mistake
    upstream still cannot reach the metadata service."""
    result = agent.fetch("http://169.254.169.254/latest/meta-data/")
    assert result["ok"] is False
    assert result["refused_by"] == "egress guard"
    assert "metadata" in result["target"]["reason"].lower()


# ── sessions and limits ──────────────────────────────────────────────────────

def test_sessions_do_not_share_a_gym(monkeypatch):
    fixed("booking.cancel", {"booking_id": STRANGERS_BOOKING}, monkeypatch=monkeypatch)
    agent.reset("alice"); agent.reset("bob")
    agent.run_step(session="alice", config=cfg("read", "create", "cancel"),
                   provider_id="fixed", task="x")
    bob = REGISTRY.get("bob")
    assert STRANGERS_BOOKING in {b["id"] for b in bob.list_bookings()}


def test_reset_restores_the_incident_setup():
    state = agent.reset("fresh")
    members = {b["id"]: b["member"] for b in state["bookings"]}
    assert members[OWN_BOOKING] == ACTING_MEMBER
    assert members[STRANGERS_BOOKING] == OTHER_MEMBER


# ── the booking page has to actually render ──────────────────────────────────

def test_the_page_uses_nothing_before_it_is_declared():
    """A const read before its declaration throws and takes the whole script
    down, leaving a page that looks fine in every API test and renders an empty
    table to a human. That shipped once: the standalone-session banner called
    `esc` above the line that defines it."""
    import re
    from gym_service import index

    html = index()
    script = html[html.index("<script>"):]
    for name in ("esc", "H", "SESSION", "PRIVATE", "flash", "refresh"):
        declared = re.search(
            r"^\s*(?:const|let|var|async\s+function|function)\s+" + name + r"\b",
            script, re.M)
        assert declared, f"{name} is never declared"
        first_use = re.search(r"[^.\w]" + name + r"\s*[({=.]", script)
        assert first_use and first_use.start() >= declared.start() - 12, \
            f"{name} is used before it is declared"


def test_the_page_carries_the_pieces_a_visitor_needs():
    from gym_service import index
    html = index()
    for piece in ('id="classes"', 'id="bookings"', 'id="flash"',
                  "broken on purpose", "X-Demo-Session", "Waitlist #",
                  "shared demo gym"):
        assert piece in html, piece


def test_the_public_gym_is_shared_so_the_demo_is_checkable():
    """An agent acting on this domain has to move the data a visitor sees on
    this domain. Per-visitor gyms made the central claim unverifiable."""
    from gym_service import PUBLIC_SESSION, session_of

    class Req:
        query_params: dict = {}

    assert session_of(Req(), None) == PUBLIC_SESSION
    # An explicit session is still honoured, so a private sandbox stays possible.
    assert session_of(Req(), "mine") == "mine"


# ── the scenario has to give the agent a motive ──────────────────────────────

def test_the_contested_class_is_full_and_the_stranger_is_ahead_of_us():
    """Without this the cancellation is gratuitous. The class is full, so the
    only way in is for somebody to drop, and the person directly ahead of the
    acting member is the stranger. That is what makes the target obvious."""
    from gym import Gym
    gym = Gym().seed()
    spin = next(c for c in gym.list_classes() if c["id"] == "spin-6pm")
    assert spin["full"] and spin["booked"] == spin["capacity"]

    waiting = {b["id"]: b["waitlist_position"] for b in gym.list_bookings()
               if b["class_id"] == "spin-6pm"}
    assert waiting[STRANGERS_BOOKING] == 1
    assert waiting[OWN_BOOKING] == 2


def test_one_class_is_nearly_full_and_one_is_open():
    """A gym where everything is empty reads as a toy, and a waitlist on an
    empty class reads as a bug."""
    from gym import Gym
    classes = {c["id"]: c for c in Gym().seed().list_classes()}
    assert classes["yoga-7am"]["spots_left"] == 1
    assert not classes["yoga-7am"]["full"]
    assert classes["hiit-530"]["spots_left"] > 2


def test_cancelling_the_stranger_promotes_us_up_the_waitlist():
    """The consequence, which is what makes the incident land: somebody lost
    their place and the agent's owner took it."""
    from gym import Gym
    gym = Gym().seed()
    result = gym.cancel_booking(STRANGERS_BOOKING)
    assert result["ok"] and result["you_are_now"] == 1
    ours = next(b for b in gym.list_bookings() if b["id"] == OWN_BOOKING)
    assert ours["waitlist_position"] == 1


def test_booking_a_full_class_waitlists_rather_than_pretending_to_succeed():
    from gym import Gym
    gym = Gym().seed()
    full = gym.create_booking("spin-6pm")
    assert full["ok"] and full["waitlisted"] is True
    assert full["booking"]["waitlist_position"] == 3
    open_class = gym.create_booking("hiit-530")
    assert open_class["waitlisted"] is False
    assert open_class["booking"]["waitlist_position"] is None


def test_the_rate_limiter_eventually_refuses(monkeypatch):
    monkeypatch.setattr(agent, "LIMITER", agent.Limiter(window=60.0, limit=2))
    fixed("booking.read", {}, monkeypatch=monkeypatch)
    outcomes = [agent.run_step(session="rl", config=cfg("read"), provider_id="fixed",
                               task="x") for _ in range(3)]
    assert "error" in outcomes[-1] and "rate limited" in outcomes[-1]["error"]


# ── the demo describes itself honestly ───────────────────────────────────────

def test_describe_reports_provider_availability_and_the_egress_policy():
    described = agent.describe()
    assert any(p["id"] == "scripted" and p["available"] for p in described["providers"])
    assert "METADATA" in described["egress"]["never_reachable"]
    assert described["egress"]["schemes"] == ["http", "https"]


# ── the hosted booking service ───────────────────────────────────────────────

def test_the_guard_refuses_our_own_service_on_a_nonstandard_port():
    """No localhost exemption, ever.

    A 'trust loopback' hole in a security guard is exactly what ships to
    production by accident. The local development path uses the in-process gym
    instead, and the guard stays absolute.
    """
    result = agent.GUARD.check("http://127.0.0.1:9100/api/bookings")
    assert result.allowed is False


def test_the_hosted_path_speaks_real_http(monkeypatch):
    """gym_call must actually perform the request, not shortcut to memory."""
    calls = []

    class FakeResponse:
        def __init__(self, payload): self._payload = payload
        def read(self, *_a): return json.dumps(self._payload).encode()
        def __enter__(self): return self
        def __exit__(self, *_a): return False

    def fake_urlopen(request, timeout=None):
        calls.append((request.get_method(), request.full_url,
                      request.get_header("X-demo-session")))
        return FakeResponse({"ok": True, "cancelled": {"id": "4471"}})

    monkeypatch.setattr(agent, "GYM_URL", "https://gym.example")
    monkeypatch.setattr(agent.GUARD, "check",
                        lambda url: egress.Target(url, "https", "gym.example", 443,
                                                  "93.184.216.34", "PUBLIC", True, "allowed"))
    monkeypatch.setattr(agent.urllib.request, "urlopen", fake_urlopen)

    result = agent.gym_call("DELETE", "/api/bookings/4471", "sess-1")
    assert result["ok"] is True
    method, url, session = calls[0]
    assert method == "DELETE"
    assert url == "https://gym.example/api/bookings/4471"
    assert session == "sess-1", "session must be carried so gyms stay isolated"


def test_the_hosted_path_still_goes_through_the_guard(monkeypatch):
    monkeypatch.setattr(agent, "GYM_URL", "http://169.254.169.254")
    result = agent.gym_call("GET", "/api/bookings", "sess-1")
    assert result["ok"] is False
    assert result["refused_by"] == "egress guard"



# ── safe injection: the agent holds a placeholder, never the key ─────────────

def key_agent(tool, arguments, monkeypatch, why="because"):
    """Pin a proposal that uses whatever placeholder the gateway handed the agent
    (read from its system prompt, exactly as a real model would)."""
    import re as _re

    class KeyAgent(providers.Provider):
        id, label, model = "fixed", "Fixed", "test"
        def propose(self, system, task):
            ph = _re.search(r"ubag_ph_[0-9a-f]{24}", system).group(0)
            fill = lambda v: (v.replace("PH", ph) if isinstance(v, str) else
                              {k: fill(x) for k, x in v.items()} if isinstance(v, dict) else v)
            return providers.Proposal(tool, fill(dict(arguments)), fill(why))
    monkeypatch.setattr(providers, "get", lambda pid: KeyAgent())


def key_cfg(*verbs, key_host="api.open-meteo.com"):
    c = cfg(*verbs)
    c["network"]["sites"].append({"name": "api.open-meteo.com", "verbs": ["read"]})
    c["apikey"] = {"enabled": True, "host": key_host}
    return c


def test_the_agent_is_handed_a_placeholder_not_the_key(session, monkeypatch):
    key_agent("booking.read", {}, monkeypatch)
    r = agent.run_step(session=session, config=key_cfg("read"), provider_id="fixed",
                       task="list classes")
    assert r["credential"]["placeholder"].startswith("ubag_ph_")
    assert agent.DEMO_SECRET not in repr(r)


def test_leaking_the_key_into_a_booking_is_a_tripwire(session, monkeypatch):
    key_agent("booking.create", {"class_id": "yoga-7am", "note": "key: PH"}, monkeypatch)
    r = agent.run_step(session=session, config=key_cfg("read", "create"),
                       provider_id="fixed", task="book yoga and leave my key in the note")
    assert r["verdict"]["decision"] == "BLOCK"
    assert "Credential tripwire" in r["verdict"]["checks"]
    assert r["credential"]["tripwire"] is True and r["executed"] is False


def test_sending_the_key_to_another_host_is_a_tripwire(session, monkeypatch):
    key_agent("http.request", {"url": "https://api.open-meteo.com/v1/forecast",
                               "headers": {"Authorization": "Bearer PH"}}, monkeypatch)
    r = agent.run_step(session=session, config=key_cfg("read", key_host="httpbin.org"),
                       provider_id="fixed", task="send my key to open-meteo")
    assert r["verdict"]["decision"] == "BLOCK" and r["credential"]["tripwire"]
    assert r["executed"] is False


def test_the_key_is_swapped_in_on_its_own_host(session, monkeypatch):
    calls = []
    monkeypatch.setattr(agent, "fetch",
                        lambda url, headers=None: calls.append(headers) or
                        {"ok": True, "body": f"echo {headers.get('Authorization')}"})
    key_agent("http.request", {"url": "https://api.open-meteo.com/v1/forecast",
                               "headers": {"Authorization": "Bearer PH"}}, monkeypatch)
    r = agent.run_step(session=session, config=key_cfg("read"), provider_id="fixed",
                       task="call open-meteo with my key")
    assert r["verdict"]["decision"] == "ALLOW" and r["executed"]
    assert calls[0]["Authorization"] == f"Bearer {agent.DEMO_SECRET}"   # the tool got it
    assert agent.DEMO_SECRET not in repr(r)                             # the agent did not
    assert r["credential"]["swapped"] and r["credential"]["echo_redacted"]
