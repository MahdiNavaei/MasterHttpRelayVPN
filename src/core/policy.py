"""Observe-only routing policy decisions.

This module is pure: it recommends route actions but does not enforce them.
Runtime callers must treat every decision as advisory while `enforce` is False.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .domain_matcher import (
    is_private_or_local_ip,
    match_host,
    normalize_host,
)


KNOWN_ACTIONS = {"direct", "relay", "block", "sensitive", "unknown"}
KNOWN_TRANSPORTS = {"direct", "apps_script", "exit_node", "none"}


@dataclass(frozen=True)
class RouteDecision:
    """Advisory route decision produced by `PolicyRouter`."""

    action: str
    transport: str
    reason: str
    matched_rule: str | None = None
    mitm_allowed: bool = True
    enforce: bool = False


class PolicyRouter:
    """Produce observe-only route recommendations from legacy and routing config."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        routing = config.get("routing") if isinstance(config.get("routing"), dict) else {}
        self.routing: dict[str, Any] = routing
        self.observe_only = bool(routing.get("observe_only", True))

    def decide(
        self,
        *,
        host: object,
        port: int | str | None = None,
        protocol: str = "connect",
        url: str | None = None,
    ) -> RouteDecision:
        """Return an advisory route decision for a host/protocol."""
        del port, protocol, url  # reserved for future policy dimensions
        normalized = normalize_host(host)
        enforce = False  # Enforcement is intentionally not implemented yet.

        if not normalized:
            return RouteDecision(
                "unknown", "none", "missing_host", None, False, enforce,
            )

        matched = match_host(normalized, self.config.get("block_hosts", []))
        if matched:
            return RouteDecision("block", "none", "block_hosts",
                                 matched, False, enforce)

        if bool(self.routing.get("private_ip_bypass", True)) and is_private_or_local_ip(normalized):
            return RouteDecision("direct", "direct", "private_or_local_ip",
                                 None, False, enforce)

        matched = match_host(normalized, self.routing.get("sensitive_domains", []))
        if matched:
            no_mitm = bool(self.routing.get("no_mitm_sensitive", True))
            return RouteDecision("sensitive", "direct", "sensitive_domain",
                                 matched, not no_mitm, enforce)

        matched = match_host(normalized, self.routing.get("direct_domains", []))
        if matched:
            return RouteDecision("direct", "direct", "routing.direct_domains",
                                 matched, False, enforce)

        matched = match_host(normalized, self.config.get("direct_hosts", []))
        if matched:
            return RouteDecision("direct", "direct", "direct_hosts",
                                 matched, False, enforce)

        matched = match_host(normalized, self.config.get("bypass_hosts", []))
        if matched:
            return RouteDecision("direct", "direct", "bypass_hosts",
                                 matched, False, enforce)

        domestic = self.routing.get("domestic_direct")
        if isinstance(domestic, dict) and bool(domestic.get("enabled", False)):
            matched = match_host(normalized, domestic.get("suffixes", []))
            if matched:
                return RouteDecision("direct", "direct", "routing.domestic_direct",
                                     matched, False, enforce)

        matched = match_host(normalized, self.routing.get("relay_domains", []))
        if matched:
            return RouteDecision("relay", "apps_script", "routing.relay_domains",
                                 matched, True, enforce)

        exit_decision = self._exit_node_decision(normalized, enforce)
        if exit_decision is not None:
            return exit_decision

        default_action = str(self.routing.get("default_action", "relay")).lower()
        if default_action == "direct":
            return RouteDecision("direct", "direct", "default_direct",
                                 None, False, enforce)
        if default_action == "block":
            return RouteDecision("block", "none", "default_block",
                                 None, False, enforce)
        if default_action == "unknown":
            return RouteDecision("unknown", "none", "default_unknown",
                                 None, False, enforce)
        return RouteDecision("relay", "apps_script", "default_relay",
                             None, True, enforce)

    def _exit_node_decision(self, host: str, enforce: bool) -> RouteDecision | None:
        exit_node = self.config.get("exit_node") or {}
        if not isinstance(exit_node, dict) or not bool(exit_node.get("enabled", False)):
            return None
        if str(exit_node.get("mode") or "selective").lower() == "full":
            return RouteDecision("relay", "exit_node", "exit_node.full",
                                 None, True, enforce)
        matched = match_host(host, exit_node.get("hosts", []))
        if matched:
            return RouteDecision("relay", "exit_node", "exit_node.hosts",
                                 matched, True, enforce)
        return None
