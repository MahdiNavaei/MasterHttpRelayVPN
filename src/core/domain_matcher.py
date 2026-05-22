"""Pure host, domain, and IP matching helpers for routing policy.

Rule behavior intentionally mirrors the existing proxy host-list style:
exact rules match only the normalized host, while leading-dot rules such as
`.example.com` match subdomains only (`api.example.com`) and do not match the
bare domain (`example.com`). Use both `example.com` and `.example.com` when
both should match.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from urllib.parse import urlsplit


_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def normalize_host(value: object) -> str:
    """Normalize a hostname, URL host, IPv4 literal, or bracketed IPv6 host."""
    text = str(value or "").strip()
    if not text:
        return ""

    if _SCHEME_RE.match(text):
        try:
            return (urlsplit(text).hostname or "").lower().rstrip(".")
        except ValueError:
            return ""

    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            return text[1:end].lower().rstrip(".")

    if text.count(":") == 1:
        host, _, port = text.rpartition(":")
        if port.isdigit():
            text = host

    return text.lower().rstrip(".")


def is_ip_literal(value: object) -> bool:
    """Return True for IPv4 and IPv6 literals."""
    host = normalize_host(value)
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_localhost(value: object) -> bool:
    """Return True for localhost names and loopback literals."""
    host = normalize_host(value)
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_private_or_local_ip(value: object) -> bool:
    """Return True for local/private/non-global IP literals.

    Uses stdlib `ipaddress` flags, covering RFC1918, loopback, link-local,
    IPv6 unique-local, multicast/reserved, and other non-global ranges.
    Hostnames are not resolved and return False unless they are localhost.
    """
    host = normalize_host(value)
    if is_localhost(host):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not ip.is_global


def match_host(host: object, patterns: object) -> str | None:
    """Return the first matching pattern, or None."""
    normalized = normalize_host(host)
    if not normalized:
        return None
    for raw in patterns or []:
        pattern = normalize_host(raw)
        if not pattern:
            continue
        if host_matches_pattern(normalized, pattern):
            return str(raw)
    return None


def host_matches_pattern(host: object, pattern: object) -> bool:
    """Match a normalized host against exact, suffix, or simple wildcard rules."""
    normalized = normalize_host(host)
    rule = normalize_host(pattern)
    if not normalized or not rule:
        return False

    if rule.startswith("*."):
        suffix = rule[1:]
        return normalized.endswith(suffix) and normalized != suffix.lstrip(".")

    if rule.startswith("."):
        return normalized.endswith(rule) and normalized != rule.lstrip(".")

    if "*" in rule or "?" in rule:
        return fnmatch.fnmatchcase(normalized, rule)

    return normalized == rule
