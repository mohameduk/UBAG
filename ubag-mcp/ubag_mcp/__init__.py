"""
UBAG MCP gateway - credential isolation and transactional commit around the
full deterministic UBAG core (one brain, many plugs; this is the MCP plug).

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from .gateway import Gateway, Tool, ModelAgent, GatewaySecurityError
from .gateway_state import GatewayStateStore, InMemoryGatewayStateStore
from .postgres_security import PostgresSecurityStore
from .provenance import (
    CredentialRegistration,
    IdentityRegistration,
    ResolutionFailure,
    SecurityContextFactory,
    StaticIdentityRegistry,
    TenantBinding,
)
from .shadow import render_shadow_report, summarize_shadow
from .recommend import propose_policy, render_policy_proposal
from .credentials import HttpArgs, CredentialVerdict, find_placeholders, placeholder_note
from .mcp_server import create_mcp_server, run_mcp_server

# Re-export the core configuration surface so a deployment configures the MCP
# gateway from one import. The verdict logic itself lives in ubag-core only.
from ubag_core import (ToolRule, GroundingRule, Claim, Fact,
                       StateProvider, StaticStateProvider,
                       FactProvider, StaticFactProvider, FactRouter,
                       CallableFactProvider, AuditFactProvider,
                       DenyMemory, StaticDenyMemory,
                       ResultVerifier, StaticResultVerifier, SecurityContext,
                       CompositionPolicy, SpendBudget,
                       Router, RouteCandidate, RouteTask, CredentialVault, StaticVault,
                       SafeInjector,
                       ALLOW, REVIEW, BLOCK)

__version__ = "0.6.0"
__all__ = ["Gateway", "Tool", "ModelAgent", "GatewaySecurityError", "GatewayStateStore",
           "SpendBudget", "Router", "RouteCandidate", "RouteTask",
           "CredentialVault", "StaticVault",
           "InMemoryGatewayStateStore", "PostgresSecurityStore",
           "ToolRule", "GroundingRule", "Claim", "Fact",
           "StateProvider", "StaticStateProvider",
           "FactProvider", "StaticFactProvider", "FactRouter",
           "CallableFactProvider", "AuditFactProvider",
           "DenyMemory", "StaticDenyMemory",
           "ResultVerifier", "StaticResultVerifier", "SecurityContext",
           "CompositionPolicy",
           "IdentityRegistration", "ResolutionFailure", "SecurityContextFactory",
           "CredentialRegistration",
           "StaticIdentityRegistry", "TenantBinding",
           "render_shadow_report", "summarize_shadow",
           "propose_policy", "render_policy_proposal",
           "HttpArgs", "CredentialVerdict", "find_placeholders", "placeholder_note",
           "SafeInjector",
           "create_mcp_server", "run_mcp_server",
           "ALLOW", "REVIEW", "BLOCK"]
