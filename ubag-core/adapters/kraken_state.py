"""
Kraken state adapter — a REFERENCE implementation of the StateProvider port.

This is the "appliance you plug into the socket." It is NOT part of ubag-core; it
shows how a deployment answers the gate's ground-truth questions against a real
system. A bank, a brokerage account, or any other backend would supply its own
adapter implementing the same four methods, and core would not change.

It takes any Kraken client with a get_balance() method
returning {asset: amount}. The withdrawal allow-list is supplied by the deployment
(Kraken's own withdrawal address book, mirrored here); the gate must never invent it.
"""
from __future__ import annotations

from typing import Optional

from ubag_core import StateProvider, ResultVerifier


class KrakenStateProvider(StateProvider, ResultVerifier):
    def __init__(self, client, *, quote_asset: str = "USDC",
                 allowed_destinations=None, exposure_by_agent=None):
        self._client = client                                   # duck-typed: get_balance()
        self._quote = quote_asset
        # None = not configured (skip the check); a list (even empty) IS the
        # allow-list, so an empty list denies every destination. See state.py.
        self._allowed = None if allowed_destinations is None \
            else {d.lower() for d in allowed_destinations}
        self._exposure = exposure_by_agent or {}               # agent_id -> committed value

    def is_destination_allowed(self, destination: str) -> Optional[bool]:
        # Only addresses on the deployment's withdrawal allow-list may receive funds.
        if self._allowed is None:
            return None
        return (destination or "").lower() in self._allowed

    def available_balance(self) -> Optional[float]:
        try:
            bal = self._client.get_balance() or {}
        except Exception:
            return None                                         # unknown -> gate skips the check
        # Kraken returns balances keyed by asset; sum any key matching the quote asset.
        total = 0.0
        for asset, amt in bal.items():
            if self._quote.upper() in str(asset).upper():
                try:
                    total += float(amt)
                except (TypeError, ValueError):
                    pass
        return total

    def current_exposure(self, agent_id: str) -> Optional[float]:
        return self._exposure.get(agent_id)

    def note_committed(self, agent_id: str, amount: float) -> None:
        """Deployment calls this after a real fill so exposure reflects reality."""
        self._exposure[agent_id] = self._exposure.get(agent_id, 0.0) + float(amount)

    # ── ResultVerifier: authoritative outcome of a prior order ──────────────────
    def action_status(self, reference: str) -> Optional[dict]:
        """Query the real order status so the agent cannot invent a fill. Expects a
        client with query_order(txid) -> {status, vol_exec, price, ...} (Kraken-shaped)."""
        q = getattr(self._client, "query_order", None)
        if q is None:
            return None
        try:
            o = q(reference) or {}
        except Exception:
            return None
        status = str(o.get("status", "")).lower()
        return {"success": status == "closed",
                "filled_qty": _f(o.get("vol_exec")),
                "price": _f(o.get("price")),
                "error": o.get("reason", "") if status not in ("closed", "open") else ""}


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0
