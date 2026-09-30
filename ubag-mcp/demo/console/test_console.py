"""
Console authorization tests.

The console makes a security claim: nothing is permitted until the operator
permits it, permitting one thing never permits another, and a verb granted on
one site is not granted on the next. These tests assert that directly rather
than trusting the happy path.

Run:  python test_console.py
"""
from __future__ import annotations

import sys

import server
from ubag_core import legacy_context

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = ""):
    (PASS if condition else FAIL).append(name)
    print(f"  [{'ok  ' if condition else 'FAIL'}] {name}"
          + (f"  <- {detail}" if detail and not condition else ""))


def site(name, *verbs):
    return {"name": name, "verbs": list(verbs)}


def cfg(money=False, network=False, data=False, *, destinations=("payroll-main",),
        net_sites=None, data_sites=None, max_per_action=500, review_above=250):
    return {
        "money": {"enabled": money, "max_per_action": max_per_action,
                  "review_above": review_above, "max_per_day": 400,
                  "destinations": list(destinations), "balance": 25_000},
        "network": {"enabled": network,
                    "sites": net_sites if net_sites is not None
                    else [site("api.stripe.com", "read")]},
        "data": {"enabled": data,
                 "sites": data_sites if data_sites is not None
                 else [site("orders", "read")]},
    }


def verdict(config, tool, arguments, reason="routine"):
    """One proposal through the real engine, exactly as the console does it."""
    engine, state, _c = server.build_engine(config)
    state.for_tool(tool)
    return engine.decide(legacy_context("test-agent"), tool, dict(arguments), reason=reason)


XFER = {"amount": 10, "destination": "wallet:payroll-main"}
STRIPE = {"destination": "net:api.stripe.com"}
GYM = {"destination": "net:api.gymbooking.com.au"}
ORDERS = {"destination": "data:orders"}


print("\n1. Default deny - nothing granted until the operator grants it")
none = cfg()
check("no tools reachable", server.granted_tools(none) == [], str(server.granted_tools(none)))
for tool, args in (("payments.transfer", XFER), ("http.request", STRIPE), ("data.read", ORDERS)):
    check(f"{tool} blocked", verdict(none, tool, args).decision == "BLOCK")
for s in ("gym", "huggingface", "drain", "benign_ops", "benign_large"):
    r = server.evaluate(none, s)
    check(f"scenario {s} fully blocked", r["totals"]["blocked"] == r["totals"]["total"])


print("\n2. Panel isolation - granting one capability grants nothing else")
check("money only: transfer allowed",
      verdict(cfg(money=True), "payments.transfer", XFER).decision == "ALLOW")
check("money only: http blocked", verdict(cfg(money=True), "http.request", STRIPE).decision == "BLOCK")
check("money only: data.read blocked", verdict(cfg(money=True), "data.read", ORDERS).decision == "BLOCK")
check("network only: http allowed",
      verdict(cfg(network=True), "http.request", STRIPE).decision == "ALLOW")
check("network only: transfer blocked",
      verdict(cfg(network=True), "payments.transfer", XFER).decision == "BLOCK")
check("data only: read allowed", verdict(cfg(data=True), "data.read", ORDERS).decision == "ALLOW")
check("data only: http blocked", verdict(cfg(data=True), "http.request", STRIPE).decision == "BLOCK")


print("\n3. Per-site verbs - a grant on one site grants nothing on another")
two = cfg(network=True, net_sites=[site("api.gymbooking.com.au", "read", "create"),
                                   site("api.stripe.com", "read")])
check("create granted on gym: booking.create allowed there",
      verdict(two, "booking.create", GYM).decision == "ALLOW")
check("create NOT granted on stripe: booking.create refused there",
      verdict(two, "booking.create", STRIPE).decision == "BLOCK")
check("read granted on both: booking.read allowed on stripe",
      verdict(two, "booking.read", STRIPE).decision == "ALLOW")
check("cancel granted nowhere: booking.cancel refused on gym",
      verdict(two, "booking.cancel", GYM).decision == "BLOCK")
check("cancel granted nowhere: booking.cancel refused on stripe",
      verdict(two, "booking.cancel", STRIPE).decision == "BLOCK")

# The block above must be policy, not a hardcoded deny list. Grant it and it works.
granted_cancel = cfg(network=True, net_sites=[site("api.gymbooking.com.au", "read", "cancel")])
check("cancel IS grantable when the operator ticks it",
      verdict(granted_cancel, "booking.cancel", GYM).decision == "ALLOW")
check("and only on the site that granted it",
      verdict(granted_cancel, "booking.cancel", STRIPE).decision == "BLOCK")

check("a named site with no verbs grants nothing",
      verdict(cfg(network=True, net_sites=[site("api.stripe.com")]),
              "http.request", STRIPE).decision == "BLOCK")
check("an unnamed site is refused even when verbs exist elsewhere",
      verdict(two, "http.request", {"destination": "net:evil.com"}).decision == "BLOCK")


print("\n4. Namespace isolation - a domain grant never authorizes a wallet")
crossed = cfg(money=True, network=True, destinations=("payroll-main",),
              net_sites=[site("evil.com", "read", "create")])
check("transfer to a domain-named destination is refused",
      verdict(crossed, "payments.transfer",
              {"amount": 10, "destination": "wallet:evil.com"}).decision == "BLOCK")
check("http to a wallet-named destination is refused",
      verdict(cfg(money=True, network=True, destinations=("ext-9f2",)),
              "http.request", {"destination": "net:ext-9f2"}).decision == "BLOCK")
check("unprefixed destination is refused",
      verdict(cfg(network=True), "http.request", {"destination": "api.stripe.com"}).decision == "BLOCK")
check("foreign namespace is refused",
      verdict(cfg(network=True), "http.request", {"destination": "wallet:anything"}).decision == "BLOCK")
check("transfer into the net namespace is refused",
      verdict(cfg(money=True), "payments.transfer",
              {"amount": 10, "destination": "net:api.stripe.com"}).decision == "BLOCK")


print("\n5. An empty allow-list denies everything (it must not fail open)")
check("no destinations denies transfers",
      verdict(cfg(money=True, destinations=()), "payments.transfer", XFER).decision == "BLOCK")
check("no sites denies requests",
      verdict(cfg(network=True, net_sites=[]), "http.request", STRIPE).decision == "BLOCK")
check("no sources denies reads",
      verdict(cfg(data=True, data_sites=[]), "data.read", ORDERS).decision == "BLOCK")


print("\n6. Turning a capability off revokes it")
check("granted while on", verdict(cfg(money=True), "payments.transfer", XFER).decision == "ALLOW")
check("revoked when off", verdict(cfg(money=False), "payments.transfer", XFER).decision == "BLOCK")
on = cfg(network=True, net_sites=[site("api.stripe.com", "read", "create")])
off = cfg(network=False, net_sites=[site("api.stripe.com", "read", "create")])
check("network verbs revoked when the panel is off",
      verdict(off, "booking.create", STRIPE).decision == "BLOCK")
check("network verbs live when the panel is on",
      verdict(on, "booking.create", STRIPE).decision == "ALLOW")


print("\n7. Value ceilings still bind inside a granted capability")
c = cfg(money=True, max_per_action=500, review_above=250)
for amount, want in ((100, "ALLOW"), (300, "REVIEW"), (900, "BLOCK"),
                     (-50, "BLOCK"), ("abc", "BLOCK"), (float("nan"), "BLOCK")):
    check(f"amount {amount!r} -> {want}",
          verdict(c, "payments.transfer", {**XFER, "amount": amount}).decision == want)


print("\n8. Benign controls stay usable under a sensible configuration")
sensible = cfg(money=True, network=True, data=True,
               net_sites=[site("api.gymbooking.com.au", "read", "create"),
                          site("api.stripe.com", "read")],
               data_sites=[site("orders", "read")])
ops = server.evaluate(sensible, "benign_ops")
check("ordinary operations fully allowed",
      ops["totals"]["allowed"] == ops["totals"]["total"], str(ops["totals"]))
large = server.evaluate(sensible, "benign_large")
check("large but legitimate reaches review, not a block",
      large["totals"]["review"] == 1 and large["totals"]["blocked"] == 0, str(large["totals"]))


print("\n9. Incidents - the ungranted verb is the one that stops")
gym = server.evaluate(sensible, "gym")
cancel = [s for s in gym["steps"] if s["tool"] == "booking.cancel"][0]
check("gym: booking.cancel blocked", cancel["ubag"]["decision"] == "BLOCK")
check("gym: the granted verbs are not punished",
      all(s["ubag"]["decision"] == "ALLOW" for s in gym["steps"] if s["tool"] != "booking.cancel"),
      str([(s["tool"], s["ubag"]["decision"]) for s in gym["steps"]]))
hf = server.evaluate(sensible, "huggingface")
check("hugging face fully stopped", hf["totals"]["blocked"] == hf["totals"]["total"],
      str([(s["tool"], s["ubag"]["decision"]) for s in hf["steps"]]))


print("\n10. Composition - every step passes and the sequence does not")
drain = server.evaluate(sensible, "drain")
check("all drain steps allowed individually",
      drain["totals"]["allowed"] == drain["totals"]["total"], str(drain["totals"]))
check("per-order control lets all of them through",
      drain["totals"]["naive_through"] == drain["totals"]["total"])
check("whole-plan gate refuses the sequence",
      drain["plan"]["decision"] in ("REFUSE", "DISCARD"), drain["plan"]["decision"])


print("\n11. Credential isolation - shadow moves no key and interrupts nothing")
sensible_enforce = {**sensible, "mode": "ENFORCE"}
sensible_shadow = {**sensible, "mode": "SHADOW"}
enforced = server.evaluate(sensible_enforce, "benign_ops")
shadowed = server.evaluate(sensible_shadow, "benign_ops")

check("the verdicts are identical in both modes",
      [s["ubag"]["decision"] for s in enforced["steps"]]
      == [s["ubag"]["decision"] for s in shadowed["steps"]],
      "shadow must not change what the engine decides")
check("enforce releases a key for every allowed step",
      enforced["totals"]["keys_released"] == enforced["totals"]["allowed"])
check("shadow releases no key at all", shadowed["totals"]["keys_released"] == 0)
check("shadow reports the counterfactual on an allowed step",
      "would have released" in shadowed["steps"][0]["key"]["label"])

blocked_run = server.evaluate({**sensible_enforce}, "huggingface")
check("a blocked step never releases a key",
      blocked_run["totals"]["keys_released"] == 0, str(blocked_run["totals"]))

check("the proposal carries no credential field",
      not any(k.lower() in ("authorization", "credential", "token", "key")
              for k in (enforced["injection"]["proposed"] or {})))
check("enforce shows the credential in the outbound call",
      "Authorization" in (enforced["injection"]["sent"] or {}))
check("shadow sends nothing at all", shadowed["injection"]["sent"] is None)
check("the audit keeps a reference, not a secret",
      enforced["injection"]["audit"]["credential_id"] == "gateway-held-1"
      and "Authorization" not in str(enforced["injection"]["audit"]))

report = server.shadow_report(sensible_shadow)
check("the shadow report is generated by the real renderer",
      report["summary"]["operating_mode"] == "SHADOW"
      and report["summary"]["production_actions_interrupted"] == 0)
check("the report counts every proposal across all scenarios",
      report["records"] == report["summary"]["observations"] > 0,
      f"{report['records']} vs {report['summary']['observations']}")
check("the report markdown states nothing was interrupted",
      "Production actions interrupted: **0**" in report["markdown"])



# ── 12. The proposed checklist: drafting is automatic, granting is a person ──
print("\n12. Proposed policy from the shadow window")

named = {"mode": "SHADOW", "network": {"enabled": True,
                                       "sites": [site("api.gymbooking.com.au", "read")]}}
proposal = server.policy_proposal(named)
draft = proposal["draft"]
proposed = {i["grant"] for i in draft["proposals"] + draft["irreversible_proposals"]}
reviewed = {i["destination"] for i in draft["review_required"]}

check("the draft is produced by the real recommender, not the console",
      draft["safety"]["auto_apply"] is False and proposal["records"] > 0)
check("a missing verb on a site the operator named is proposed",
      "net:api.gymbooking.com.au::booking.create" in proposed)
check("an irreversible verb is proposed in its own section, never inline",
      "net:api.gymbooking.com.au::booking.cancel"
      in {i["grant"] for i in draft["irreversible_proposals"]}
      and "net:api.gymbooking.com.au::booking.cancel"
      not in {i["grant"] for i in draft["proposals"]})
check("the metadata probe is never proposed",
      "net:169.254.169.254" in reviewed
      and not any("169.254" in g for g in proposed))
check("the exfiltration destination is never proposed",
      "net:pastebin.com" in reviewed and not any("pastebin" in g for g in proposed))
check("a wallet the operator never approved is never proposed",
      "wallet:payroll-main" in reviewed
      and not any("payroll" in g for g in proposed))
check("nothing in the draft arrives pre-selected",
      all(i["preselected"] is False for i in
          draft["proposals"] + draft["irreversible_proposals"]
          + draft["review_required"] + draft["findings"]))

applied = server.apply_proposals(named, ["net:api.gymbooking.com.au::booking.create"])
check("accepting a proposal grants the verb on that site only",
      applied["applied"] == ["net:api.gymbooking.com.au::booking.create"]
      and applied["config"]["network"]["sites"][0]["verbs"] == ["read", "create"])
check("accepting a proposal is what makes the tool grantable",
      "booking.create" not in server.granted_tools(named)
      and "booking.create" in applied["granted"])
check("the original config is never mutated in place",
      named["network"]["sites"][0]["verbs"] == ["read"])

for forged in ("net:pastebin.com::http.request",
               "net:169.254.169.254::http.request",
               "wallet:payroll-main::payments.transfer",
               "net:never-seen.example::booking.cancel"):
    result = server.apply_proposals(named, [forged])
    check(f"a grant the draft never proposed is refused: {forged}",
          result["applied"] == [] and result["rejected"] == [forged])

check("an empty acceptance changes nothing at all",
      server.apply_proposals(named, []) == named)

check("the proposal markdown states plainly that nothing was applied",
      "**Nothing here has been applied.**" in proposal["markdown"])

# Egress: a declaration covers the site's www form and nothing wider, and a
# redirect is only followed when the new destination passes both gates again.
import egress_console                                                # noqa: E402
check("declaring a domain also covers its www form",
      egress_console._covers(["google.com"]) == ["google.com", "www.google.com"])
check("a declaration never opens other subdomains",
      "mail.google.com" not in egress_console._covers(["google.com"]))
check("declaring the www form does not add a www.www form",
      egress_console._covers(["www.example.com"]) == ["www.example.com"])


class _Redirecting:
    """Stand-in for egress.pinned_get: first hop 301 to `to`, second hop 200."""
    def __init__(self, to):
        self.to, self.calls = to, 0

    def __call__(self, target, headers=None, **kw):
        self.calls += 1
        if self.calls == 1:
            return 301, {"location": self.to}, b""
        return 200, {}, b"final page"


def _fetch_with(fake_get, gate_ok):
    orig = egress_console.egress.pinned_get
    egress_console.egress.pinned_get = fake_get
    try:
        class T: url, host = "https://a.example/", "a.example"
        return egress_console._fetch(
            T, lambda u: (gate_ok(u), "not declared", type("N", (), {"url": u, "host": u})))
    finally:
        egress_console.egress.pinned_get = orig


_off = _fetch_with(_Redirecting("https://evil.example/"), lambda u: False)
check("a redirect to an undeclared host is refused, nothing fetched",
      _off.get("refused") and _off["content"] is None)
_on = _fetch_with(_Redirecting("https://b.example/"), lambda u: True)
check("a redirect to a declared host is followed and re-gated",
      _on["content"] == "final page" and len(_on["hops"]) == 1)

# DNS rebinding and header smuggling: the fetch connects only to the address the
# guard approved, and only allow-listed headers leave the box.
import os, egress as _eg                                              # noqa: E401,E402
_hs = _eg.safe_headers({"Authorization": "Bearer x", "Metadata-Flavor": "Google",
                        "X-aws-ec2-metadata-token": "t", "Accept": "text/html",
                        "Host": "169.254.169.254", "X-Evil": "a" + chr(13) + chr(10) + "Injected: 1"})
check("only allow-listed agent headers are forwarded",
      set(_hs) == {"Authorization", "Accept"}, str(_hs))
try:
    _eg.pinned_get(_eg.Target("http://x.example/", "http", "x.example", 80, None,
                              "PUBLIC", False, "not allowed"))
    check("pinned_get refuses a destination the guard did not approve", False)
except ValueError:
    check("pinned_get refuses a destination the guard did not approve", True)
check("refusal wording no longer calls a model",
      "_generate" not in __import__("inspect").getsource(egress_console._narrate))
check("the console escapes dynamic values before writing HTML",
      "function H(v)" in open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "console.html"), encoding="utf-8").read())

# Safe injection on the egress tab: the agent holds a placeholder; one bound to
# httpbin.org heading anywhere else is a tripwire, and the real key never appears.
def _inj_step(url, headers, allowed):
    egress_console._narrate = lambda *a: "(narration)"
    def fake(prompt, credential=None):
        ph = credential["placeholder"]
        return {"reply": "x", "fetch": url.replace("PH", ph),
                "headers": {k: v.replace("PH", ph) for k, v in headers.items()}}
    egress_console._ask_model = fake
    return egress_console.step("go", allowed, key_host="httpbin.org")


_r = _inj_step("https://example.com/c", {"Authorization": "Bearer PH"},
               ["httpbin.org", "example.com"])
check("a placeholder sent to another (even declared) host trips the credential gate",
      _r["verdict"] == "BLOCK" and _r["layer"] == "credential" and _r.get("tripwire"))
check("the real demo key never appears in a refused step",
      egress_console.DEMO_SECRET not in repr(_r))
_r = _inj_step("https://httpbin.org/get?k=PH", {}, ["httpbin.org"])
check("a placeholder in the URL is refused even on its own host",
      _r["verdict"] == "BLOCK" and _r["layer"] == "credential")
check("the agent is shown a placeholder, not the key",
      _r["credential"]["placeholder"].startswith("ubag_ph_")
      and egress_console.DEMO_SECRET not in _r["credential"]["placeholder"])

# One syntax error in the page script blanks EVERY panel, so the shipped page is
# parsed here. Skipped (not passed) only when node is not installed.
import os, re as _re, shutil as _sh, subprocess as _sp, tempfile as _tf   # noqa: E401,E402
_node = _sh.which("node")
if _node:
    _html = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "console.html"), encoding="utf-8").read()
    for _i, _js in enumerate(_re.findall(r"<script>(.*?)</script>", _html, _re.S)):
        with _tf.NamedTemporaryFile("w", suffix=".js", delete=False,
                                    encoding="utf-8") as _fh:
            _fh.write(_js)
        _r = _sp.run([_node, "--check", _fh.name], capture_output=True, text=True)
        os.unlink(_fh.name)
        check(f"the console page script #{_i} parses", _r.returncode == 0,
              (_r.stderr or "").strip().splitlines()[0:5] and
              " | ".join((_r.stderr or "").strip().splitlines()[:5]))
else:
    print("  [skip] node not installed; page script not parsed")


print(f"\n{len(PASS)}/{len(PASS) + len(FAIL)} passed")
if FAIL:
    print("\nfailed:")
    for f in FAIL:
        print("  -", f)
sys.exit(1 if FAIL else 0)
