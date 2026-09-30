"""
The demo's own outbound guard.

A public demo where a stranger picks the destination and the server makes the
request is an open SSRF proxy. Point it at 169.254.169.254 and you have handed
over the host's cloud credentials; point it at 127.0.0.1 and you have exposed
every internal service; point it at a third party and your address is the source
of the attack traffic.

That is the exact failure class this product exists to prevent, so the demo runs
under the policy it demonstrates. Every destination the agent proposes is
resolved, classified, pinned, and checked against an allow-list before a socket
is opened, and the refusal is shown to the visitor rather than hidden.

Refusing a visitor's metadata probe on screen, with the reason, is a better
advertisement than any slide.

Copyright (c) 2026 Dixit Algorizmi Inc. Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). Patent pending.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

PUBLIC, PRIVATE, LOOPBACK, LINK_LOCAL = "PUBLIC", "PRIVATE", "LOOPBACK", "LINK_LOCAL"
METADATA, MULTICAST, RESERVED, CGNAT = "METADATA", "MULTICAST", "RESERVED", "CGNAT"

# Never reachable, whatever the allow-list says. Cloud metadata first, because it
# is the one that turns a demo into a credential leak.
METADATA_HOSTS = frozenset({"169.254.169.254", "metadata.google.internal",
                            "metadata.goog", "100.100.100.200",
                            "fd00:ec2::254"})
DENIED_CLASSES = frozenset({METADATA, LOOPBACK, LINK_LOCAL, PRIVATE,
                            MULTICAST, RESERVED, CGNAT})

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})


@dataclass(frozen=True)
class Target:
    """A destination that has been resolved and judged, with the address pinned."""
    url: str
    scheme: str
    host: str
    port: int
    ip: Optional[str]
    address_class: str
    allowed: bool
    reason: str

    def to_dict(self) -> dict:
        return {"url": self.url, "host": self.host, "port": self.port, "ip": self.ip,
                "address_class": self.address_class, "allowed": self.allowed,
                "reason": self.reason}


def classify(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return RESERVED
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        # An IPv4 address wearing an IPv6 costume is still that IPv4 address.
        addr = addr.ipv4_mapped
    if str(addr) in METADATA_HOSTS:
        return METADATA
    if addr.is_loopback:
        return LOOPBACK
    if addr.is_link_local:
        return LINK_LOCAL
    if addr.is_multicast:
        return MULTICAST
    # Unspecified and reserved are checked BEFORE private: Python counts
    # 0.0.0.0/8 as private, so an earlier is_private test would label 0.0.0.0
    # "private" and show a visitor a less accurate refusal. Both are denied
    # either way; only the reason string differs.
    if addr.is_unspecified or addr.is_reserved:
        return RESERVED
    if isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network("100.64.0.0/10"):
        return CGNAT
    if addr.is_private:
        return PRIVATE
    return PUBLIC


def resolve(host: str) -> list[str]:
    """Every address this name currently answers with.

    All of them are judged, not just the first: a name that resolves to one public
    and one private address is a rebinding attempt, and taking the first answer
    would let it through.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, ValueError):
        return []
    return sorted({info[4][0] for info in infos})


def check(url: str, allowed_hosts) -> Target:
    """Judge one destination. Nothing here opens a socket."""
    raw = (url or "").strip()

    # Parsing must never raise. `urlsplit` is lenient but its `.port` and
    # `.hostname` properties are not: `data:text/html,hi` makes `.port` throw
    # because it tries to read "text" as a number, and an unhandled exception here
    # is a 500 on a public endpoint rather than a refusal. Anything unparseable is
    # simply not a destination we can judge, so it is refused.
    try:
        parts = urlsplit(raw if "://" in raw else "https://" + raw)
        scheme = (parts.scheme or "").lower()
        host = (parts.hostname or "").lower()
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        return Target(raw, "", "", 0, None, RESERVED, False,
                      "the destination could not be parsed as a URL")

    def no(reason, ip=None, klass=RESERVED):
        return Target(raw, scheme, host, port, ip, klass, False, reason)

    if scheme not in ALLOWED_SCHEMES:
        return no(f"scheme '{scheme or 'none'}' is not http or https")
    if not host:
        return no("no host in the destination")
    if port not in ALLOWED_PORTS:
        return no(f"port {port} is not 80 or 443")
    if host in METADATA_HOSTS:
        return no("cloud metadata endpoints are never reachable", klass=METADATA)

    allow = {h.strip().lower() for h in (allowed_hosts or ()) if str(h).strip()}
    if host not in allow:
        return no(f"'{host}' is not on this demo's destination allow-list")

    addresses = resolve(host)
    if not addresses:
        return no(f"'{host}' does not resolve")

    for ip in addresses:
        klass = classify(ip)
        if klass in DENIED_CLASSES:
            # One bad answer condemns the name. This is the DNS-rebinding case.
            return no(f"'{host}' resolves to a {klass.lower().replace('_', '-')} "
                      f"address ({ip}); refused", ip=ip, klass=klass)

    pinned = addresses[0]
    return Target(raw, scheme, host, port, pinned, classify(pinned), True,
                  f"allow-listed and resolves only to public addresses ({pinned})")


class EgressGuard:
    """The allow-list the demo actually runs under."""

    def __init__(self, allowed_hosts):
        self.allowed_hosts = sorted({str(h).strip().lower()
                                     for h in allowed_hosts if str(h).strip()})

    def check(self, url: str) -> Target:
        return check(url, self.allowed_hosts)

    def describe(self) -> dict:
        return {"allowed_hosts": self.allowed_hosts,
                "never_reachable": sorted(DENIED_CLASSES),
                "schemes": sorted(ALLOWED_SCHEMES),
                "ports": sorted(ALLOWED_PORTS)}


# ── Fetching the judged address, not the name ────────────────────────────────
# check() resolves the name and judges every answer, but a plain urlopen() then
# resolves it AGAIN. A rebinding name can answer "public" to the check and
# "169.254.169.254" to the connect (DNS rebinding, a classic time-of-check /
# time-of-use gap). pinned_get() closes it: it connects to the exact IP the check
# approved (Target.ip) and keeps TLS verification against the real hostname via
# SNI, so the certificate still has to match the name.
#
# Headers the agent supplies are filtered to a small allow-list. Anything else,
# notably `Metadata-Flavor: Google` or `X-aws-ec2-metadata-token`, would let a
# request that did reach a metadata address read cloud credentials.
SAFE_AGENT_HEADERS = frozenset({"authorization", "accept", "accept-language"})


def safe_headers(headers) -> dict:
    """The subset of agent-supplied headers that may leave the box."""
    out = {}
    for k, v in (headers or {}).items():
        name = str(k).strip()
        if name.lower() in SAFE_AGENT_HEADERS and "\n" not in str(v) and "\r" not in str(v):
            out[name] = str(v)
    return out


def pinned_get(target: "Target", headers=None, timeout: float = 10.0,
               max_bytes: int = 20000):
    """GET `target.url` by connecting to `target.ip` only.

    Returns (status, response_headers: dict, body: bytes). Never follows redirects;
    the caller re-judges a Location header as a new destination. Refuses a target
    that was not allowed or has no pinned address."""
    import http.client
    import ssl

    if not target.allowed or not target.ip:
        raise ValueError("refusing to fetch a destination the guard did not approve")
    parts = urlsplit(target.url if "://" in target.url else "https://" + target.url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    ip, host, port = target.ip, target.host, target.port

    if target.scheme == "https":
        ctx = ssl.create_default_context()

        class _Pinned(http.client.HTTPSConnection):
            def connect(self):
                sock = socket.create_connection((ip, port), self.timeout)
                self.sock = ctx.wrap_socket(sock, server_hostname=host)
        conn = _Pinned(host, port, timeout=timeout, context=ctx)
    else:
        class _PinnedHTTP(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.create_connection((ip, port), self.timeout)
        conn = _PinnedHTTP(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={**safe_headers(headers),
                                           "Host": host if port in (80, 443) else f"{host}:{port}",
                                           "User-Agent": "UBAG-demo/1.0"})
        resp = conn.getresponse()
        body = resp.read(max_bytes)
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, body
    finally:
        conn.close()
