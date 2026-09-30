"""Private verified-provenance to authoritative-context resolution."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Protocol
from urllib.parse import urlsplit

from ubag_core import AttributionStatus, CredentialStatus, SecurityContext


class ResolutionFailure(ValueError):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


class VerifiedProvenanceLike(Protocol):
    agent_ref: str
    credential_ref: Optional[str]
    htu: str


@dataclass(frozen=True)
class TenantBinding:
    tenant_id: str
    public_origin: str
    default_account_id: str = "unattributed"
    integration_id: str = "ubag-web"
    allow_unregistered_credentials: bool = False


@dataclass(frozen=True)
class IdentityRegistration:
    principal_id: str
    account_id: str
    integration_id: str = "ubag-web"
    identity_revoked: bool = False

    def __post_init__(self):
        if self.principal_id.startswith("unattributed:"):
            raise ValueError("'unattributed:' is a reserved internal principal prefix")


@dataclass(frozen=True)
class CredentialRegistration:
    credential_id: str
    credential_revoked: bool = False


class IdentityRegistry(Protocol):
    def resolve_identity(self, tenant_id: str,
                         agent_ref: str) -> Optional[IdentityRegistration]: ...

    def resolve_credential(self, tenant_id: str, agent_ref: str,
                           credential_ref: str) -> Optional[CredentialRegistration]: ...


class StaticIdentityRegistry:
    """Deterministic registry for tests and single-process pilots."""

    def __init__(
        self,
        identities: Optional[Mapping[tuple[str, str], IdentityRegistration]] = None,
        credentials: Optional[
            Mapping[tuple[str, str, str], CredentialRegistration]] = None,
    ):
        self._identities = dict(identities or {})
        self._credentials = dict(credentials or {})

    def resolve_identity(self, tenant_id: str,
                         agent_ref: str) -> Optional[IdentityRegistration]:
        return self._identities.get((tenant_id, agent_ref))

    def resolve_credential(self, tenant_id: str, agent_ref: str,
                           credential_ref: str) -> Optional[CredentialRegistration]:
        return self._credentials.get((tenant_id, agent_ref, credential_ref))


class SecurityContextFactory:
    """Total, fail-closed mapping from verified provenance to core context."""

    def __init__(self, bindings: Mapping[str, TenantBinding],
                 registry: IdentityRegistry):
        normalized: dict[str, TenantBinding] = {}
        for origin, binding in bindings.items():
            key = self._origin(origin)
            if key in normalized and normalized[key] != binding:
                raise ValueError(f"ambiguous tenant binding for {key}")
            if self._origin(binding.public_origin) != key:
                raise ValueError("binding key and public_origin disagree")
            normalized[key] = binding
        self._bindings = normalized
        self._registry = registry

    @staticmethod
    def _origin(value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ResolutionFailure("INVALID_PUBLIC_ORIGIN")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ResolutionFailure("INVALID_PUBLIC_ORIGIN")
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

    def resolve(self, verified: VerifiedProvenanceLike) -> SecurityContext:
        try:
            origin = self._origin(verified.htu)
            agent_ref = verified.agent_ref
            credential_ref = verified.credential_ref
        except (AttributeError, TypeError) as exc:
            raise ResolutionFailure("INVALID_VERIFIED_PROVENANCE") from exc
        if not isinstance(agent_ref, str) or not agent_ref.startswith("ubag:sha256:"):
            raise ResolutionFailure("INVALID_VERIFIED_PROVENANCE")
        binding = self._bindings.get(origin)
        if binding is None:
            raise ResolutionFailure("TENANT_NOT_RESOLVED")

        identity = self._registry.resolve_identity(binding.tenant_id, agent_ref)
        credential = (
            self._registry.resolve_credential(
                binding.tenant_id, agent_ref, credential_ref
            )
            if credential_ref is not None else None
        )
        if identity is None and credential is not None:
            raise ResolutionFailure(
                "REGISTRY_INCONSISTENT",
                "credential registration exists without an identity registration",
            )
        if identity is not None:
            if (
                not isinstance(getattr(identity, "principal_id", None), str)
                or not identity.principal_id
                or identity.principal_id.startswith("unattributed:")
                or not isinstance(getattr(identity, "account_id", None), str)
                or not identity.account_id
                or not isinstance(getattr(identity, "integration_id", None), str)
                or not isinstance(getattr(identity, "identity_revoked", None), bool)
            ):
                raise ResolutionFailure(
                    "REGISTRY_INCONSISTENT", "invalid identity registration"
                )
        if credential is not None and (
            not isinstance(getattr(credential, "credential_id", None), str)
            or not credential.credential_id
            or not isinstance(getattr(credential, "credential_revoked", None), bool)
        ):
            raise ResolutionFailure(
                "REGISTRY_INCONSISTENT", "invalid credential registration"
            )
        unknown_status = (
            CredentialStatus.ACTIVE
            if binding.allow_unregistered_credentials
            else CredentialStatus.UNKNOWN
        )
        if identity is None:
            return SecurityContext(
                tenant_id=binding.tenant_id,
                principal_id=f"unattributed:{agent_ref}",
                agent_id=agent_ref,
                account_id=binding.default_account_id,
                credential_id=credential_ref or "absent",
                integration_id=binding.integration_id,
                attribution_status=AttributionStatus.UNATTRIBUTED,
                credential_status=(CredentialStatus.ABSENT if credential_ref is None
                                   else CredentialStatus.REVOKED
                                   if credential and credential.credential_revoked
                                   else CredentialStatus.ACTIVE
                                   if credential else unknown_status),
            )

        return SecurityContext(
            tenant_id=binding.tenant_id,
            principal_id=identity.principal_id,
            agent_id=agent_ref,
            account_id=identity.account_id,
            credential_id=(credential.credential_id if credential
                           else credential_ref or "absent"),
            integration_id=identity.integration_id,
            attribution_status=(AttributionStatus.REVOKED
                                if identity.identity_revoked
                                else AttributionStatus.ATTRIBUTED),
            credential_status=(CredentialStatus.REVOKED
                               if credential and credential.credential_revoked
                               else CredentialStatus.ABSENT
                               if credential_ref is None
                               else CredentialStatus.ACTIVE
                               if credential
                               else unknown_status),
        )
