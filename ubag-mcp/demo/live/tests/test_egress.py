"""
Egress guard tests.

This module is the only thing standing between a public demo and the host's
cloud credentials, so it is tested as an attack surface rather than a helper.
Resolution is stubbed where the assertion is about classification, so the suite
is hermetic and does not depend on what a name happens to answer today.
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..")))

import pytest

import egress
from egress import (CGNAT, LINK_LOCAL, LOOPBACK, METADATA, MULTICAST, PRIVATE,
                    PUBLIC, RESERVED, EgressGuard, classify)

ALLOWED = ["api.example.com", "httpbin.org"]


@pytest.fixture
def guard(monkeypatch):
    """A guard whose DNS answers we control."""
    answers = {"api.example.com": ["93.184.216.34"], "httpbin.org": ["100.28.182.24"]}
    monkeypatch.setattr(egress, "resolve", lambda host: answers.get(host, []))
    return EgressGuard(ALLOWED)


# ── classification ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("ip,expected", [
    ("169.254.169.254", METADATA),      # AWS/GCP/Azure metadata
    ("100.100.100.200", METADATA),      # Alibaba metadata
    ("127.0.0.1", LOOPBACK),
    ("::1", LOOPBACK),
    ("::ffff:127.0.0.1", LOOPBACK),     # IPv4 in an IPv6 costume
    ("::ffff:10.0.0.1", PRIVATE),
    ("169.254.1.1", LINK_LOCAL),
    ("10.0.0.5", PRIVATE),
    ("192.168.1.1", PRIVATE),
    ("172.16.0.1", PRIVATE),
    ("fd00::1", PRIVATE),               # IPv6 unique-local
    ("224.0.0.1", MULTICAST),
    ("0.0.0.0", RESERVED),
    ("not-an-ip", RESERVED),            # never guess in favour of the caller
    ("8.8.8.8", PUBLIC),
])
def test_address_classes(ip, expected):
    assert classify(ip) == expected


@pytest.mark.parametrize("ip,expected", [
    ("100.63.255.255", PUBLIC),         # just below the CGNAT block
    ("100.64.0.0", CGNAT),              # first CGNAT address
    ("100.127.255.255", CGNAT),         # last CGNAT address
    ("100.128.0.0", PUBLIC),            # just above
    ("100.28.182.24", PUBLIC),          # real public AWS space, must not be caught
])
def test_cgnat_boundary_is_exact(ip, expected):
    assert classify(ip) == expected


# ── the SSRF payloads a visitor would actually try ───────────────────────────

@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.goog/",
    "http://100.100.100.200/latest/meta-data/",
])
def test_metadata_is_never_reachable_even_if_allow_listed(url):
    # Allow-listing it explicitly must not help. This is the one that turns a
    # demo into a credential leak.
    hosts = ALLOWED + ["169.254.169.254", "metadata.google.internal",
                       "metadata.goog", "100.100.100.200"]
    result = EgressGuard(hosts).check(url)
    assert not result.allowed
    assert "metadata" in result.reason.lower()


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/admin",
    "http://localhost/admin",
    "http://10.0.0.5/internal",
    "http://192.168.1.1/router",
    "http://[::1]/",
])
def test_internal_destinations_are_refused(url, guard):
    assert not guard.check(url).allowed


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://evil.com/",
    "ftp://evil.com/",
    "//evil.com/protocol-relative",
])
def test_non_http_schemes_are_refused(url, guard):
    assert not guard.check(url).allowed


def test_an_unlisted_host_is_refused(guard):
    result = guard.check("https://evil.com/steal")
    assert not result.allowed
    assert "allow-list" in result.reason


def test_a_nonstandard_port_is_refused(guard):
    assert not guard.check("https://api.example.com:8080/x").allowed
    assert not guard.check("http://api.example.com:22/x").allowed


def test_an_allow_listed_public_host_passes(guard):
    result = guard.check("https://api.example.com/v1/thing?a=1")
    assert result.allowed
    assert result.ip == "93.184.216.34"
    assert result.address_class == PUBLIC


# ── rebinding ────────────────────────────────────────────────────────────────

def test_one_bad_answer_condemns_the_name(monkeypatch):
    """A name answering with both a public and a private address is a rebinding
    attempt. Taking the first answer would let it straight through."""
    monkeypatch.setattr(egress, "resolve",
                        lambda host: ["93.184.216.34", "127.0.0.1"])
    result = EgressGuard(["rebind.example.com"]).check("https://rebind.example.com/")
    assert not result.allowed
    assert "loopback" in result.reason.lower()


def test_a_name_that_does_not_resolve_is_refused(monkeypatch):
    monkeypatch.setattr(egress, "resolve", lambda host: [])
    result = EgressGuard(["gone.example.com"]).check("https://gone.example.com/")
    assert not result.allowed
    assert "does not resolve" in result.reason


def test_the_allowed_address_is_pinned(guard):
    """Authorization and connection must name the same address, or the check was
    decorative."""
    result = guard.check("https://httpbin.org/get")
    assert result.allowed and result.ip == "100.28.182.24"


# ── the guard describes itself honestly ──────────────────────────────────────

def test_describe_lists_what_is_never_reachable(guard):
    described = guard.describe()
    assert set(described["never_reachable"]) >= {METADATA, LOOPBACK, PRIVATE, LINK_LOCAL}
    assert described["schemes"] == ["http", "https"]
    assert described["ports"] == [80, 443]
