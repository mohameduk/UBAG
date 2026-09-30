"""Trusted identity context supplied by the authenticated execution surface."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AttributionStatus(str, Enum):
    ATTRIBUTED = "ATTRIBUTED"
    UNATTRIBUTED = "UNATTRIBUTED"
    REVOKED = "REVOKED"


class CredentialStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class SecurityContext:
    """Identity dimensions that policy may safely use.

    Values must be derived from authenticated transport context and gateway-held
    registration, never copied from agent-controlled tool arguments.
    """
    tenant_id: str
    principal_id: str
    agent_id: str
    account_id: str
    credential_id: str
    integration_id: str = "default"
    attribution_status: AttributionStatus = AttributionStatus.ATTRIBUTED
    credential_status: CredentialStatus = CredentialStatus.ACTIVE

    def __post_init__(self):
        for name in ("tenant_id", "principal_id", "agent_id", "account_id",
                     "credential_id", "integration_id"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ValueError(f"SecurityContext.{name} must be a non-empty string")
        if not isinstance(self.attribution_status, AttributionStatus):
            raise ValueError("SecurityContext.attribution_status must be AttributionStatus")
        if not isinstance(self.credential_status, CredentialStatus):
            raise ValueError("SecurityContext.credential_status must be CredentialStatus")

    @property
    def revoked(self) -> bool:
        return (self.attribution_status == AttributionStatus.REVOKED or
                self.credential_status == CredentialStatus.REVOKED)

    @property
    def credential_blocked(self) -> bool:
        """Unknown and revoked credentials are unusable unless resolved upstream."""
        return self.credential_status in (
            CredentialStatus.UNKNOWN,
            CredentialStatus.REVOKED,
        )

    @property
    def breaker_key(self) -> str:
        return "\x1f".join((self.tenant_id, self.principal_id, self.agent_id))

    @property
    def account_key(self) -> str:
        return "\x1f".join((self.tenant_id, self.integration_id,
                            self.account_id, self.credential_id))


def legacy_context(agent_id: str) -> SecurityContext:
    """Compatibility for direct core callers; deployment surfaces must not use it."""
    aid = str(agent_id or "legacy")
    return SecurityContext("legacy", aid, aid, "legacy", "legacy", "legacy",
                           AttributionStatus.UNATTRIBUTED,
                           CredentialStatus.ABSENT)


def coerce_context(value) -> SecurityContext:
    if not isinstance(value, SecurityContext):
        raise TypeError(
            "UBAG core requires SecurityContext derived by a trusted execution "
            "surface; use legacy_context(...) only as an explicit compatibility opt-in"
        )
    return value
