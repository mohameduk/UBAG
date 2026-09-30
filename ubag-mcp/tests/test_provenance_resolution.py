from types import SimpleNamespace

import pytest

from ubag_core import (
    AttributionStatus,
    CredentialStatus,
    GatewayEngine,
    Registry,
    ToolRule,
)
from ubag_mcp.provenance import (
    CredentialRegistration,
    IdentityRegistration,
    ResolutionFailure,
    SecurityContextFactory,
    StaticIdentityRegistry,
    TenantBinding,
)


AGENT = "ubag:sha256:verified-key-thumbprint"
ORIGIN = "https://service.example"


def _verified(**extra):
    values = {
        "agent_ref": AGENT,
        "credential_ref": "credential-jti",
        "htu": f"{ORIGIN}/payments",
    }
    values.update(extra)
    return SimpleNamespace(**values)


def _factory(identities=None, credentials=None, *,
             allow_unregistered_credentials=False):
    binding = TenantBinding(
        tenant_id="tenant-from-trusted-host",
        public_origin=ORIGIN,
        default_account_id="unattributed-account",
        allow_unregistered_credentials=allow_unregistered_credentials,
    )
    return SecurityContextFactory(
        {ORIGIN: binding},
        StaticIdentityRegistry(identities, credentials),
    )


def test_registered_key_resolves_authoritative_context():
    registration = IdentityRegistration(
        principal_id="principal-from-registry",
        account_id="account-from-registry",
    )
    context = _factory({
        ("tenant-from-trusted-host", AGENT): registration,
    }, {
        ("tenant-from-trusted-host", AGENT, "credential-jti"):
            CredentialRegistration("credential-from-registry"),
    }).resolve(_verified())
    assert context.tenant_id == "tenant-from-trusted-host"
    assert context.principal_id == "principal-from-registry"
    assert context.attribution_status == AttributionStatus.ATTRIBUTED


def test_registry_miss_is_explicit_unattributed_context():
    context = _factory().resolve(_verified(credential_ref=None))
    assert context.tenant_id == "tenant-from-trusted-host"
    assert context.attribution_status == AttributionStatus.UNATTRIBUTED
    assert context.credential_status == CredentialStatus.ABSENT
    assert context.principal_id.startswith("unattributed:ubag:sha256:")


def test_unknown_or_ambiguous_transport_never_creates_context():
    with pytest.raises(ResolutionFailure) as exc:
        _factory().resolve(_verified(htu="https://attacker.example/payments"))
    assert exc.value.code == "TENANT_NOT_RESOLVED"

    one = TenantBinding("tenant-one", "https://SERVICE.example")
    two = TenantBinding("tenant-two", "https://service.example")
    with pytest.raises(ValueError):
        SecurityContextFactory(
            {"https://SERVICE.example": one, "https://service.example": two},
            StaticIdentityRegistry(),
        )


def test_revoked_resolution_reaches_core_and_is_mandatory_block():
    registration = IdentityRegistration(
        principal_id="known-principal",
        account_id="known-account",
    )
    context = _factory({
        ("tenant-from-trusted-host", AGENT): registration,
    }, {
        ("tenant-from-trusted-host", AGENT, "credential-jti"):
            CredentialRegistration("known-credential", credential_revoked=True),
    }).resolve(_verified())
    assert context.credential_status == CredentialStatus.REVOKED
    registry = Registry(default_allow=False)
    registry.register("read", ToolRule())
    decision = GatewayEngine(registry).decide(context, "read", {})
    assert decision.decision == "BLOCK"
    assert "revoked" in decision.reason


def test_property_agent_fields_cannot_set_tenant_or_principal():
    """Property corpus: every attacker-authored identity-shaped value is inert."""
    registration = IdentityRegistration(
        principal_id="principal-from-registry",
        account_id="account-from-registry",
    )
    factory = _factory({
        ("tenant-from-trusted-host", AGENT): registration,
    }, {
        ("tenant-from-trusted-host", AGENT, "credential-jti"):
            CredentialRegistration("credential-from-registry"),
    })
    adversarial = [
        "", "acme", "other-tenant", "../../root", "\x00admin",
        "tenant-from-trusted-host", "principal-from-registry",
        "A" * 4096, "例.example", "null", "undefined",
    ]
    for value in adversarial:
        verified = _verified(
            tenant=value,
            tenant_ref=value,
            tenant_id=value,
            principal=value,
            principal_ref=value,
            principal_id=value,
            account_id=value,
        )
        context = factory.resolve(verified)
        assert context.tenant_id == "tenant-from-trusted-host"
        assert context.principal_id == "principal-from-registry"
        assert context.account_id == "account-from-registry"


def test_credential_rotation_never_erases_stable_attribution():
    identity = IdentityRegistration(
        principal_id="stable-principal",
        account_id="stable-account",
    )
    factory = _factory({
        ("tenant-from-trusted-host", AGENT): identity,
    }, {
        ("tenant-from-trusted-host", AGENT, "old-jti"):
            CredentialRegistration("old-credential"),
        ("tenant-from-trusted-host", AGENT, "new-jti"):
            CredentialRegistration("new-credential"),
    })
    for credential_ref, expected_status in (
        ("old-jti", CredentialStatus.ACTIVE),
        ("new-jti", CredentialStatus.ACTIVE),
        ("fresh-unregistered-jti", CredentialStatus.UNKNOWN),
        (None, CredentialStatus.ABSENT),
    ):
        context = factory.resolve(_verified(credential_ref=credential_ref))
        assert context.principal_id == "stable-principal"
        assert context.attribution_status == AttributionStatus.ATTRIBUTED
        assert context.credential_status == expected_status


def test_unknown_credential_blocks_before_policy_unless_explicitly_promoted():
    identity = IdentityRegistration("stable-principal", "stable-account")
    identities = {("tenant-from-trusted-host", AGENT): identity}
    unknown = _factory(identities).resolve(
        _verified(credential_ref="deleted-or-unregistered-jti")
    )
    assert unknown.credential_status == CredentialStatus.UNKNOWN

    class PolicyMustNotRun:
        @property
        def tools(self):
            raise AssertionError("customer policy ran for unknown credential")

    decision = GatewayEngine(PolicyMustNotRun()).decide(unknown, "write", {})
    assert decision.decision == "BLOCK"
    assert "credential is unknown" in decision.reason

    promoted = _factory(
        identities,
        allow_unregistered_credentials=True,
    ).resolve(_verified(credential_ref="deliberately-unregistered-jti"))
    assert promoted.credential_status == CredentialStatus.ACTIVE


def test_credential_without_identity_is_registry_inconsistency():
    credentials = {
        ("tenant-from-trusted-host", AGENT, "credential-jti"):
            CredentialRegistration("orphaned-credential"),
    }
    with pytest.raises(ResolutionFailure) as exc:
        _factory(credentials=credentials).resolve(_verified())
    assert exc.value.code == "REGISTRY_INCONSISTENT"


def test_unattributed_principal_prefix_is_reserved():
    with pytest.raises(ValueError):
        IdentityRegistration(
            principal_id="unattributed:ubag:sha256:collision",
            account_id="account",
        )


def test_unregistered_credential_policy_is_isolated_per_tenant():
    permissive = TenantBinding(
        "permissive", "https://permissive.example",
        allow_unregistered_credentials=True,
    )
    strict = TenantBinding("strict", "https://strict.example")
    registry = StaticIdentityRegistry({
        ("permissive", AGENT): IdentityRegistration("p1", "a1"),
        ("strict", AGENT): IdentityRegistration("p2", "a2"),
    })
    factory = SecurityContextFactory({
        permissive.public_origin: permissive,
        strict.public_origin: strict,
    }, registry)
    assert factory.resolve(_verified(
        htu="https://permissive.example/write",
    )).credential_status == CredentialStatus.ACTIVE
    assert factory.resolve(_verified(
        htu="https://strict.example/write",
    )).credential_status == CredentialStatus.UNKNOWN


def test_duck_typed_registry_cannot_bypass_factory_validation():
    class BadRegistry:
        def resolve_identity(self, _tenant, _agent):
            return SimpleNamespace(
                principal_id="unattributed:collision",
                account_id="account",
                integration_id="test",
                identity_revoked=False,
            )

        def resolve_credential(self, _tenant, _agent, _credential):
            return None

    binding = TenantBinding("tenant", ORIGIN)
    factory = SecurityContextFactory({ORIGIN: binding}, BadRegistry())
    with pytest.raises(ResolutionFailure) as exc:
        factory.resolve(_verified())
    assert exc.value.code == "REGISTRY_INCONSISTENT"
