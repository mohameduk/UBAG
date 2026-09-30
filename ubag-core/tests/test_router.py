"""Execution router: deterministic, compliance-first, cheapest eligible agent."""
from ubag_core import Router, RouteCandidate, RouteTask


def _fleet():
    return Router([
        RouteCandidate("local", cost=1.0, latency_ms=40,
                       allowed_data_classes=frozenset({"public", "pii", "regulated"}),
                       capabilities=frozenset({"chat", "extract"}), local=True),
        RouteCandidate("cheap-api", cost=0.5, latency_ms=120,
                       allowed_data_classes=frozenset({"public"}),
                       capabilities=frozenset({"chat", "extract", "vision"})),
        RouteCandidate("frontier", cost=5.0, latency_ms=300,
                       allowed_data_classes=frozenset({"public"}),
                       capabilities=frozenset({"chat", "extract", "vision", "reason"})),
    ])


def test_public_task_picks_cheapest():
    d = _fleet().route(RouteTask(data_class="public"))
    assert d.chosen == "cheap-api"          # 0.5 < 1.0 < 5.0
    assert d.routed


def test_pii_pins_to_local_even_though_it_is_pricier():
    # cheap-api and frontier do not allow pii; only local does, so cost is moot.
    d = _fleet().route(RouteTask(data_class="pii"))
    assert d.chosen == "local"
    assert any(cid == "cheap-api" and not ok for cid, ok, _ in d.considered)


def test_no_compliant_agent_refuses():
    d = _fleet().route(RouteTask(data_class="top_secret"))
    assert d.chosen is None and not d.routed
    assert "no eligible agent" in d.reason


def test_capability_filter():
    # only frontier has 'reason'; it wins by being the sole eligible one.
    d = _fleet().route(RouteTask(data_class="public",
                                 required_capabilities=frozenset({"reason"})))
    assert d.chosen == "frontier"


def test_latency_slo_excludes_slow_agents():
    # SLO 100ms drops cheap-api (120) and frontier (300); only local (40) survives.
    d = _fleet().route(RouteTask(data_class="public", max_latency_ms=100))
    assert d.chosen == "local"


def test_budget_excludes_expensive_agents():
    # budget 0.9 units: cheap-api (0.5) fits, local (1.0) does not.
    d = _fleet().route(RouteTask(data_class="public", budget_remaining=0.9))
    assert d.chosen == "cheap-api"
    # budget below everything -> refuse
    d2 = _fleet().route(RouteTask(data_class="public", budget_remaining=0.1))
    assert d2.chosen is None


def test_est_units_scales_cost_against_budget():
    # cheap-api cost 0.5 * 3 units = 1.5 > budget 1.0 -> excluded; local 1.0*... no,
    # local is 1.0*3 = 3.0 too. Both excluded -> refuse.
    d = _fleet().route(RouteTask(data_class="public", est_units=3.0,
                                 budget_remaining=1.0))
    assert d.chosen is None


def test_latency_objective_prefers_fastest():
    d = _fleet().route(RouteTask(data_class="public"), objective="latency")
    assert d.chosen == "local"              # 40ms fastest, despite not cheapest


def test_deterministic_same_snapshot_same_choice():
    fleet = _fleet()
    a = fleet.route(RouteTask(data_class="public"))
    b = fleet.route(RouteTask(data_class="public"))
    assert a.chosen == b.chosen == "cheap-api"


def test_record_updates_telemetry_and_can_change_routing():
    fleet = _fleet()
    # Under a 100ms SLO only local qualifies initially.
    assert fleet.route(RouteTask(data_class="public", max_latency_ms=100)).chosen == "local"
    # cheap-api gets consistently fast; fold that in until it drops under 100ms.
    for _ in range(20):
        fleet.record("cheap-api", latency_ms=30)
    d = fleet.route(RouteTask(data_class="public", max_latency_ms=100))
    assert d.chosen == "cheap-api"          # now eligible AND cheaper than local


def test_projected_cost_reported():
    d = _fleet().route(RouteTask(data_class="public", est_units=2.0))
    assert d.chosen == "cheap-api" and abs(d.projected_cost - 1.0) < 1e-9


# --- credential-bound routing -------------------------------------------------
from ubag_core import StaticVault


def _vaulted():
    vault = StaticVault({"vault:local-1": "s-local", "vault:cheap-1": "s-cheap",
                         "vault:frontier-1": "s-frontier"})
    r = Router([
        RouteCandidate("local", cost=1.0, latency_ms=40, credential_ref="vault:local-1",
                       allowed_data_classes=frozenset({"public", "pii"}), local=True),
        RouteCandidate("cheap-api", cost=0.5, latency_ms=120, credential_ref="vault:cheap-1",
                       allowed_data_classes=frozenset({"public"})),
        RouteCandidate("frontier", cost=5.0, latency_ms=300, credential_ref="vault:frontier-1",
                       allowed_data_classes=frozenset({"public"})),
        # Cheapest of all, but it carries its own key: UBAG holds nothing for it.
        RouteCandidate("shadow-agent", cost=0.01, latency_ms=10, credential_ref="",
                       allowed_data_classes=frozenset({"public", "pii"})),
    ], vault=vault)
    return r


def test_agent_without_vault_key_is_never_routed_even_if_cheapest():
    d = _vaulted().route(RouteTask(data_class="public"))
    assert d.chosen == "cheap-api"
    assert ("shadow-agent", False, "no credential held in the vault for this agent") in d.considered


def test_decision_releases_exactly_one_key_and_withholds_the_rest():
    d = _vaulted().route(RouteTask(data_class="public"))
    assert d.credential_ref == "vault:cheap-1"
    assert sorted(d.withheld) == ["vault:frontier-1", "vault:local-1"]


def test_pii_releases_only_the_local_key():
    r = _vaulted()
    d = r.route(RouteTask(data_class="pii"))
    assert d.chosen == "local" and d.credential_ref == "vault:local-1"
    assert "vault:cheap-1" in d.withheld and "vault:frontier-1" in d.withheld
    assert r.release(d) == "s-local"          # only the chosen secret resolves


def test_refused_decision_releases_nothing():
    r = _vaulted()
    d = r.route(RouteTask(data_class="top_secret"))
    assert d.chosen is None and d.credential_ref == ""
    assert r.release(d) is None
    assert sorted(d.withheld) == ["vault:cheap-1", "vault:frontier-1", "vault:local-1"]


def test_without_vault_custody_is_not_checked():
    # back-compat: no vault attached -> the keyless agent is routable
    r = Router([RouteCandidate("shadow-agent", cost=0.01,
                               allowed_data_classes=frozenset({"public"}))])
    assert r.route(RouteTask()).chosen == "shadow-agent"
    assert r.release(r.route(RouteTask())) is None
