"""Shared state ports for plan sessions and execution correlations."""
from __future__ import annotations

import threading
from abc import ABC, abstractmethod


class GatewayStateStore(ABC):
    """Atomic store used by every gateway worker in a deployment."""

    @abstractmethod
    def create_plan(self, session_id: str, owner_key: str, created_at: float) -> None:
        raise NotImplementedError

    @abstractmethod
    def append_plan(self, session_id: str, owner_key: str, item: dict) -> int:
        """Append an item and return its one-based step number."""
        raise NotImplementedError

    @abstractmethod
    def pop_plan(self, session_id: str, owner_key: str) -> list[dict]:
        raise NotImplementedError

    @abstractmethod
    def remember_execution(self, correlation_id: str, owner_key: str,
                           tool_name: str, occurred_at: float) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_execution(self, correlation_id: str):
        """Return (owner_key, tool_name, occurred_at), or None."""
        raise NotImplementedError


class InMemoryGatewayStateStore(GatewayStateStore):
    """Thread-safe single-process implementation for tests and development."""
    def __init__(self, *, correlation_limit: int = 4096,
                 correlation_ttl_s: float = 86400.0):
        self._plans: dict[str, dict] = {}
        self._correlations: dict[str, tuple[str, str, float]] = {}
        self._lock = threading.RLock()
        self.correlation_limit = correlation_limit
        self.correlation_ttl_s = correlation_ttl_s

    def create_plan(self, session_id: str, owner_key: str, created_at: float) -> None:
        with self._lock:
            if session_id in self._plans:
                raise KeyError("plan session already exists")
            self._plans[session_id] = {"owner": owner_key, "items": [],
                                       "created_at": created_at}

    def append_plan(self, session_id: str, owner_key: str, item: dict) -> int:
        with self._lock:
            record = self._plans.get(session_id)
            if record is None:
                raise KeyError("unknown or closed plan session")
            if record["owner"] != owner_key:
                raise PermissionError("plan session belongs to a different security context")
            record["items"].append(item)
            return len(record["items"])

    def pop_plan(self, session_id: str, owner_key: str) -> list[dict]:
        with self._lock:
            record = self._plans.get(session_id)
            if record is None:
                raise KeyError("unknown or already-closed plan session")
            if record["owner"] != owner_key:
                raise PermissionError("plan session belongs to a different security context")
            self._plans.pop(session_id)
            return record["items"]

    def remember_execution(self, correlation_id: str, owner_key: str,
                           tool_name: str, occurred_at: float) -> None:
        with self._lock:
            cutoff = occurred_at - self.correlation_ttl_s
            if len(self._correlations) >= self.correlation_limit:
                self._correlations = {
                    key: value for key, value in self._correlations.items()
                    if value[2] >= cutoff}
            if len(self._correlations) >= self.correlation_limit:
                oldest = min(self._correlations,
                             key=lambda key: self._correlations[key][2])
                self._correlations.pop(oldest, None)
            self._correlations[correlation_id] = (owner_key, tool_name, occurred_at)

    def get_execution(self, correlation_id: str):
        with self._lock:
            return self._correlations.get(correlation_id)
