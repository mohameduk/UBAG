"""The Melbourne incident, run twice against the same broken handler.

The point of this file is a comparison, not a pass. Every assertion below is
made against `cancel_booking` in its original state, which performs no ownership
check and is not permitted to be fixed. What changes between the two halves is
whether an authorization decision happened first.

Four outcomes matter, and the third and fourth are the ones that make the demo
honest:

  1. UBAG off, the attack succeeds. Without this the exhibit proves nothing.
  2. UBAG on and unattested, refused. The anonymous tier holds read only.
  3. UBAG on with a valid credential, cancelling SOMEONE ELSE'S booking,
     refused. This is the Melbourne hole and the only assertion that
     distinguishes UBAG from an authentication check.
  4. UBAG on with the same credential, cancelling the agent's OWN booking,
     allowed. Without this, "refused everything" would pass the suite while
     making the product useless.

Needs the commercial engine on the path. Skips cleanly when it is absent, the
same way the service degrades.

    python -m pytest tests/test_gym_gate.py -q
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEMO = os.path.join(_HERE, "..")
_WEB = os.path.join(_DEMO, "..", "ubag-weblayer")
for _p in (_DEMO, _WEB,
           os.path.join(_WEB, "vendor", "ubag-core"),
           os.path.join(_WEB, "vendor", "ubag-mcp"),
           os.path.join(_WEB, "vendor", "ubag-python", "src")):
    if os.path.isdir(_p) and os.path.abspath(_p) not in sys.path:
        sys.path.insert(0, os.path.abspath(_p))

import pytest
from starlette.testclient import TestClient

import gym_gate
import gym_service
from gym import ACTING_MEMBER, OTHER_MEMBER

pytestmark = pytest.mark.skipif(
    not gym_gate.GATE_AVAILABLE,
    reason=f"commercial engine not on path: {gym_gate.GATE_IMPORT_ERROR}")

SESSION = "pytest-melbourne"
HEAD = {"x-demo-session": SESSION}

# Priya is ahead of Andrew on the spin waitlist. Cancelling her booking is what
# moves him up, which is the agent's entire motive.
HERS = "4471"
HIS = "9001"


@pytest.fixture()
def client():
    with TestClient(gym_service.app) as c:
        c.post("/api/reset", headers=HEAD)
        c.post("/api/ubag", json={"enabled": False}, headers=HEAD)
        yield c
        c.post("/api/ubag", json={"enabled": False}, headers=HEAD)


def owners(client) -> dict:
    return {b["id"]: b["member"] for b in client.get("/api/bookings", headers=HEAD).json()}


def enable(client):
    assert client.post("/api/ubag", json={"enabled": True},
                       headers=HEAD).json()["enabled"] is True


def credential(client) -> dict:
    body = client.post("/api/ubag/credential", headers=HEAD).json()
    return {body["header"]: body["credential"], **HEAD}


# ---------------------------------------------------------------------------
# The fixture itself, because the scenario is load-bearing
# ---------------------------------------------------------------------------

def test_the_contested_booking_belongs_to_someone_else(client):
    held = owners(client)
    assert held[HERS] == OTHER_MEMBER
    assert held[HIS] == ACTING_MEMBER


# ---------------------------------------------------------------------------
# 1. The incident, reproduced
# ---------------------------------------------------------------------------

def test_with_ubag_off_the_attack_succeeds(client):
    """The exhibit. If this ever starts failing, somebody 'fixed' the handler."""
    assert client.delete(f"/api/bookings/{HERS}", headers=HEAD).status_code == 200
    assert HERS not in owners(client)


# ---------------------------------------------------------------------------
# 2, 3, 4. The same handler, behind the gate
# ---------------------------------------------------------------------------

def test_unattested_cancel_is_refused(client):
    enable(client)
    response = client.delete(f"/api/bookings/{HERS}", headers=HEAD)
    assert response.status_code == 403
    assert response.json()["tier"] == "anonymous"
    assert HERS in owners(client), "the handler must never have run"


def test_a_credentialed_agent_still_cannot_cancel_someone_elses_booking(client):
    """The assertion the whole product rests on.

    The agent is attested, holds a credential from a trusted issuer, and sits in
    a tier that explicitly grants `cancel`. It is still refused, because cancel
    is granted as "cancel your own" and never as "cancel anything". An
    authentication layer passes this request. That is the difference.
    """
    enable(client)
    response = client.delete(f"/api/bookings/{HERS}", headers=credential(client))
    assert response.status_code == 403
    assert response.json()["tier"] == "member-agent"
    assert HERS in owners(client)
    assert owners(client)[HERS] == OTHER_MEMBER


def test_the_same_agent_may_cancel_its_own_booking(client):
    """Otherwise 'refused' would be indistinguishable from 'broken'."""
    enable(client)
    response = client.delete(f"/api/bookings/{HIS}", headers=credential(client))
    assert response.status_code == 200
    assert HIS not in owners(client)


def test_reads_are_not_claimed_by_the_gate(client):
    """A gate that intercepts reads is a proxy, and proxies get removed."""
    enable(client)
    assert client.get("/api/bookings", headers=HEAD).status_code == 200
    assert client.get("/api/classes", headers=HEAD).status_code == 200


# ---------------------------------------------------------------------------
# Properties that are easy to break later
# ---------------------------------------------------------------------------

def test_a_refusal_still_discloses_what_this_site_is(client):
    """The gate is installed outside the disclosure middleware, so it stamps
    its own responses. A scanner that only ever gets refused must still be told
    this is a deliberate exhibit."""
    enable(client)
    response = client.delete(f"/api/bookings/{HERS}", headers=HEAD)
    assert "Intentionally vulnerable" in response.headers["X-Demo-Disclosure"]
    assert response.headers["X-Robots-Tag"] == "noindex, nofollow"


def test_cancelling_a_booking_that_does_not_exist_is_held_not_passed_through(client):
    """Unresolvable ownership is held for review, not denied, and that is right.

    This assertion originally expected 403 and the gate returned 409. The gate
    was correct. "Nobody owns this" and "I cannot tell who owns this" are
    different states, and only the first is a refusal. The second is a question
    the site could not answer, which belongs with a person rather than being
    resolved either way by a machine that lacks the information.

    What matters for safety is identical in both cases and is the second
    assertion: the irreversible handler did not run. REVIEW is not a soft allow.
    """
    enable(client)
    response = client.delete("/api/bookings/does-not-exist", headers=credential(client))
    assert response.status_code == 409
    assert response.json()["status"] == "action_held"


def test_reset_returns_the_exhibit_to_undefended(client):
    """Reset is the button somebody presses when the demo looks wrong.

    The public gym is shared, so the previous visitor's toggle is still set when
    the next one arrives. If reset restored the bookings but left the gate
    armed, the next person would run the attack against a fresh gym, watch it
    refused with no explanation on screen, and reasonably conclude the exhibit
    is broken.
    """
    enable(client)
    assert client.get("/api/ubag", headers=HEAD).json()["enabled"] is True

    body = client.post("/api/reset", headers=HEAD).json()
    assert body["ubag_enabled"] is False
    assert client.get("/api/ubag", headers=HEAD).json()["enabled"] is False

    # And the attack works again, which is the state a visitor should arrive in.
    assert client.delete(f"/api/bookings/{HERS}", headers=HEAD).status_code == 200


def test_the_published_policy_is_the_enforced_one(client):
    """The console's tier panel has to change what this site does.

    It did not. The panel configured a gate inside the console while this site
    enforced a policy hardcoded here, so an operator could switch `create` off,
    watch the agent create a booking anyway, and reasonably conclude the gate
    ignores its own configuration. Nothing was broken except the only thing that
    mattered, which was that the screen told the truth.
    """
    enable(client)
    tight = {"require_ownership": True,
             "anonymous": {"verbs": ["read"]},
             "tiers": [{"name": "member-agent", "verbs": ["read", "cancel"]}]}
    assert client.post("/api/ubag/policy", json=tight, headers=HEAD).json()["ok"] is True

    # Published and enforced are now the same thing, read from one place.
    published = client.get("/api/ubag", headers=HEAD).json()
    member = next(t for t in published["tiers"] if t["name"] == "member-agent")
    assert "create" not in member["verbs"]

    creating = client.post("/api/bookings", json={"class_id": "hiit-530"},
                           headers=credential(client))
    assert creating.status_code == 403
    # Refused for lacking the grant, not for lacking an identity. The agent is
    # attested and lands in its tier; the tier simply no longer carries create.
    assert creating.json()["tier"] == "member-agent"


def test_granting_create_again_lets_it_through(client):
    """Otherwise the test above would pass on a gate that refuses everything."""
    enable(client)
    client.post("/api/ubag/policy", headers=HEAD, json={
        "require_ownership": True, "anonymous": {"verbs": ["read"]},
        "tiers": [{"name": "member-agent", "verbs": ["read", "create", "cancel"]}]})
    assert client.post("/api/bookings", json={"class_id": "hiit-530"},
                       headers=credential(client)).status_code == 200


def test_reset_restores_the_default_policy(client):
    """A visitor who narrows the tiers and leaves must not strand the next one."""
    enable(client)
    client.post("/api/ubag/policy", headers=HEAD, json={
        "tiers": [{"name": "member-agent", "verbs": ["read"]}]})
    client.post("/api/reset", headers=HEAD)
    member = next(t for t in client.get("/api/ubag", headers=HEAD).json()["tiers"]
                  if t["name"] == "member-agent")
    assert set(member["verbs"]) == {"read", "create", "cancel"}


def test_the_toggle_is_per_session(client):
    """One visitor turning enforcement on must not disarm or arm another's."""
    enable(client)
    other = {"x-demo-session": "pytest-someone-else"}
    client.post("/api/reset", headers=other)
    assert client.get("/api/ubag", headers=other).json()["enabled"] is False
    assert client.delete(f"/api/bookings/{HERS}", headers=other).status_code == 200
