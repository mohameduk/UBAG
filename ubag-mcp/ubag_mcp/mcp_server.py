"""Official Model Context Protocol transport for a configured UBAG Gateway."""
from __future__ import annotations

from typing import Optional

from .gateway import Gateway


def create_mcp_server(gateway: Gateway, *, name: str = "UBAG Gateway"):
    """Expose a configured gateway through the official MCPServer API.

    The deployment remains responsible for authenticating the transport and for
    making ``gateway.context_provider`` resolve that authenticated request.  The
    protocol surface never accepts tenant or principal identifiers as tool args.
    """
    try:
        from mcp.server import MCPServer
    except ImportError as exc:  # pragma: no cover - optional dependency boundary
        raise RuntimeError(
            "MCP transport requires the 'mcp' extra: pip install 'ubag-mcp[mcp]'") from exc

    server = MCPServer(name=name)

    @server.tool()
    def ubag_observe(tool_name: str, arguments: Optional[dict] = None,
                     grant: Optional[str] = None) -> dict:
        """Evaluate a tool proposal in shadow mode without executing it."""
        return gateway.observe(tool_name, arguments, grant=grant)

    @server.tool()
    def ubag_propose(tool_name: str, arguments: Optional[dict] = None,
                     grant: Optional[str] = None) -> dict:
        """Evaluate and, only on ALLOW, execute a registered protected tool."""
        return gateway.propose(tool_name, arguments, grant=grant)

    @server.tool()
    def ubag_begin_plan() -> dict:
        """Open a caller-bound UBAG plan session."""
        return {"session_id": gateway.begin_plan()}

    @server.tool()
    def ubag_stage(session_id: str, tool_name: str, arguments: dict,
                   grant: Optional[str] = None) -> dict:
        """Stage one immutable proposal into a caller-bound plan."""
        gateway.stage(session_id, tool_name, arguments, grant=grant)
        return {"session_id": session_id, "staged": True}

    @server.tool()
    def ubag_commit(session_id: str) -> dict:
        """Authorize and execute a complete staged plan."""
        return gateway.commit(session_id)

    @server.tool()
    def ubag_observe_plan(session_id: str) -> dict:
        """Evaluate a complete staged plan without executing it."""
        return gateway.observe_plan(session_id)

    return server


def run_mcp_server(gateway: Gateway, *, transport: str = "streamable-http",
                   name: str = "UBAG Gateway") -> None:
    """Run the configured gateway using an official MCP transport."""
    server = create_mcp_server(gateway, name=name)
    if transport == "streamable-http":
        server.run(transport=transport, stateless_http=True, json_response=True)
    else:
        server.run(transport=transport)
