"""Backward-compatible configuration validation for diagnostics."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from .redaction import redact_value


PLACEHOLDER_AUTH_KEYS = {
    "",
    "CHANGE_ME_TO_A_STRONG_SECRET",
    "your-secret-password-here",
}

PLACEHOLDER_SCRIPT_IDS = {
    "",
    "YOUR_APPS_SCRIPT_DEPLOYMENT_ID",
}

PLACEHOLDER_PSKS = {
    "",
    "CHANGE_ME_TO_A_STRONG_SECRET",
    "your-secret-password-here",
}

LOCALHOSTS = {"127.0.0.1", "localhost", "::1"}


@dataclass(frozen=True)
class ValidationIssue:
    """One validation finding."""

    severity: str
    code: str
    message: str
    field: str | None = None


@dataclass(frozen=True)
class ValidationReport:
    """Collection of validation findings."""

    issues: tuple[ValidationIssue, ...]

    @property
    def has_errors(self) -> bool:
        return any(issue.severity == "error" for issue in self.issues)

    @property
    def has_warnings(self) -> bool:
        return any(issue.severity == "warn" for issue in self.issues)


def validate_config(
    config: dict[str, Any],
    *,
    ca_cert_file: str | None = None,
    ca_key_file: str | None = None,
) -> ValidationReport:
    """Validate current config without requiring a new schema."""
    issues: list[ValidationIssue] = []

    auth_key = str(config.get("auth_key", ""))
    if auth_key in PLACEHOLDER_AUTH_KEYS:
        issues.append(ValidationIssue(
            "error",
            "auth_key_missing_or_placeholder",
            "auth_key is missing or uses a known placeholder.",
            "auth_key",
        ))

    _validate_script_ids(config, issues)
    _validate_ports(config, issues)
    _validate_listen_security(config, issues)
    _validate_exit_node(config, issues)
    _validate_ca_files(ca_cert_file, ca_key_file, issues)

    issues.append(ValidationIssue(
        "info",
        "mitm_required_by_current_architecture",
        "Current HTTPS relay behavior relies on local MITM unless a host is routed directly.",
        "mode",
    ))
    issues.append(ValidationIssue(
        "info",
        "sensitive_domain_guardrail_not_implemented",
        "No first-class sensitive-domain/no-MITM policy guardrail exists yet.",
        "routing",
    ))

    return ValidationReport(tuple(issues))


def _validate_script_ids(config: dict[str, Any], issues: list[ValidationIssue]) -> None:
    raw_ids = config.get("script_ids")
    single_id = str(config.get("script_id", ""))

    if isinstance(raw_ids, list):
        ids = [str(item).strip() for item in raw_ids if str(item).strip()]
        if not ids:
            issues.append(ValidationIssue(
                "error",
                "script_ids_empty",
                "script_ids is present but contains no deployment IDs.",
                "script_ids",
            ))
            return
        bad = [sid for sid in ids if sid in PLACEHOLDER_SCRIPT_IDS]
        if bad:
            issues.append(ValidationIssue(
                "error",
                "script_ids_placeholder",
                "script_ids contains a known placeholder deployment ID.",
                "script_ids",
            ))
        return

    if single_id in PLACEHOLDER_SCRIPT_IDS:
        issues.append(ValidationIssue(
            "error",
            "script_id_missing_or_placeholder",
            "script_id is missing or uses a known placeholder.",
            "script_id",
        ))


def _as_port(value: object) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _validate_ports(config: dict[str, Any], issues: list[ValidationIssue]) -> None:
    http_port = _as_port(config.get("http_port", config.get("listen_port", 8080)))
    socks_port = _as_port(config.get("socks5_port", 1080))

    if http_port is None:
        issues.append(ValidationIssue(
            "warn", "http_port_invalid", "HTTP proxy port is invalid.", "http_port",
        ))
    if socks_port is None:
        issues.append(ValidationIssue(
            "warn", "socks5_port_invalid", "SOCKS5 proxy port is invalid.", "socks5_port",
        ))
    if http_port is not None and socks_port is not None and http_port == socks_port:
        issues.append(ValidationIssue(
            "warn",
            "proxy_ports_conflict",
            "HTTP and SOCKS5 ports are equal; startup will fail on the same host.",
            "socks5_port",
        ))


def _validate_listen_security(config: dict[str, Any],
                              issues: list[ValidationIssue]) -> None:
    listen_host = str(config.get("listen_host", "127.0.0.1")).strip()
    socks_host = str(config.get("socks5_host", listen_host)).strip()

    if bool(config.get("lan_sharing", False)):
        issues.append(ValidationIssue(
            "warn",
            "lan_sharing_enabled",
            "LAN sharing is enabled; proxy access may be exposed to local network devices.",
            "lan_sharing",
        ))
    if listen_host in {"0.0.0.0", "::"}:
        issues.append(ValidationIssue(
            "warn",
            "http_proxy_listens_all_interfaces",
            "HTTP proxy listens on all interfaces.",
            "listen_host",
        ))
    if socks_host not in LOCALHOSTS:
        issues.append(ValidationIssue(
            "warn",
            "socks5_exposed_without_auth",
            "SOCKS5 listens beyond localhost and does not implement authentication.",
            "socks5_host",
        ))


def _validate_exit_node(config: dict[str, Any],
                        issues: list[ValidationIssue]) -> None:
    exit_node = config.get("exit_node") or {}
    if not isinstance(exit_node, dict) or not bool(exit_node.get("enabled", False)):
        return

    url = str(exit_node.get("url") or exit_node.get("relay_url") or "").strip()
    psk = str(exit_node.get("psk") or "").strip()
    if not url:
        issues.append(ValidationIssue(
            "warn",
            "exit_node_url_missing",
            "Exit node is enabled but no URL is configured.",
            "exit_node.url",
        ))
    if psk in PLACEHOLDER_PSKS:
        issues.append(ValidationIssue(
            "warn",
            "exit_node_psk_missing_or_placeholder",
            f"Exit node PSK is missing or placeholder ({redact_value(psk)}).",
            "exit_node.psk",
        ))


def _validate_ca_files(
    ca_cert_file: str | None,
    ca_key_file: str | None,
    issues: list[ValidationIssue],
) -> None:
    if ca_cert_file and os.path.exists(ca_cert_file):
        issues.append(ValidationIssue(
            "warn",
            "mitm_ca_cert_exists",
            "MITM CA certificate exists on disk.",
            "ca.crt",
        ))
    if ca_key_file and os.path.exists(ca_key_file):
        issues.append(ValidationIssue(
            "warn",
            "mitm_ca_private_key_exists",
            "MITM CA private key exists on disk; protect this file.",
            "ca.key",
        ))
