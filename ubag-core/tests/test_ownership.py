"""
Ownership binding (engine step 1b-ii): "may cancel" is not "may cancel anything".

Regression guard. This step was deployed on 2026-09-14 but never committed, and
later builds silently shipped without it, so a granted cancel could remove a
stranger's booking again. These tests fail if the step or the port method goes.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ubag_core import (ALLOW, BLOCK, GatewayEngine, Registry, StateProvider,
                       StaticStateProvider, ToolRule, legacy_context)


class Owners(StaticStateProvider):
    def __init__(self, owned: dict):
        super().__init__(allowed_destinations=None)
        self._owned = owned

    def owns_resource(self, principal_id, tool_name, arguments):
        return self._owned.get(str(arguments.get("booking_id")))


def _engine(owned, reversible=False):
    reg = Registry(default_allow=False)
    reg.register("booking.cancel", ToolRule(reversible=reversible))
    return GatewayEngine(reg, state=Owners(owned))


def _cancel(engine, booking_id):
    return engine.decide(legacy_context("member-andrew"), "booking.cancel",
                         {"booking_id": booking_id}, reason="free up a spot", grant=None)


def test_port_method_exists_and_defaults_to_unknown():
    assert StateProvider().owns_resource("p", "booking.cancel", {}) is None


def test_cancelling_a_strangers_booking_is_blocked_even_when_cancel_is_granted():
    d = _cancel(_engine({"4471": False, "9001": True}), "4471")
    assert d.decision == BLOCK
    assert "resource ownership" in d.reason


def test_cancelling_your_own_booking_is_allowed():
    d = _cancel(_engine({"4471": False, "9001": True}), "9001")
    assert d.decision == ALLOW


def test_unknown_owner_is_not_invented():
    d = _cancel(_engine({}), "5555")
    assert "resource ownership" not in d.reason


def test_ownership_only_binds_irreversible_verbs():
    d = _cancel(_engine({"4471": False}, reversible=True), "4471")
    assert "resource ownership" not in d.reason
