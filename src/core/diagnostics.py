"""Read-only diagnostics for the doctor command."""

from __future__ import annotations

import socket
import ssl
import time
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urlsplit

from .config_validation import ValidationIssue, validate_config
from .domain_matcher import normalize_host
from .policy import PolicyRouter, RouteDecision
from .redaction import redact_text, redact_url


Status = str


@dataclass(frozen=True)
class DiagnosticResult:
    """One doctor check result."""

    name: str
    status: Status
    message: str
    detail: str | None = None
    category: str = "connectivity"


@dataclass(frozen=True)
class DoctorReport:
    """Doctor command output model."""

    results: tuple[DiagnosticResult, ...]

    @property
    def has_failures(self) -> bool:
        return any(result.status == "fail" for result in self.results)


@dataclass(frozen=True)
class HostPolicyCheck:
    """Parsed host target and observe-only policy decision."""

    raw: str
    host: str
    port: int
    protocol: str
    decision: RouteDecision


def run_doctor(
    config: dict,
    *,
    ca_cert_file: str | None = None,
    ca_key_file: str | None = None,
    is_ca_trusted_func: Callable[[str], bool] | None = None,
    network_checks: bool = True,
    timeout: float = 3.0,
) -> DoctorReport:
    """Run read-only diagnostics. Does not start proxy listeners."""
    results: list[DiagnosticResult] = []

    validation = validate_config(
        config,
        ca_cert_file=ca_cert_file,
        ca_key_file=ca_key_file,
    )
    results.extend(_validation_to_results(validation.issues))

    listen_host = str(config.get("listen_host", "127.0.0.1"))
    http_port = config.get("http_port", config.get("listen_port", 8080))
    socks_host = str(config.get("socks5_host", listen_host))
    socks_port = config.get("socks5_port", 1080)

    if _ports_conflict(http_port, socks_port, listen_host, socks_host):
        results.append(DiagnosticResult(
            "PORT CONFLICT",
            "fail",
            "HTTP and SOCKS5 listeners are configured on the same host and port.",
        ))
    results.append(_check_bind("HTTP BIND", listen_host, http_port))
    results.append(_check_bind("SOCKS5 BIND", socks_host, socks_port))

    results.append(_check_ca_state(ca_cert_file, is_ca_trusted_func))

    if network_checks:
        results.append(_check_google_front(config, timeout=timeout))
        results.append(_check_exit_node(config, timeout=timeout))
        results.append(_check_apps_script(config, timeout=timeout))
    else:
        results.append(DiagnosticResult(
            "GOOGLE FRONT", "skip", "Live network checks disabled.",
        ))
        results.append(DiagnosticResult(
            "EXIT NODE", "skip", "Live network checks disabled.",
        ))
        results.append(DiagnosticResult(
            "APPS SCRIPT", "skip", "Live network checks disabled.",
        ))

    return DoctorReport(tuple(results))


def build_policy_checks(config: dict, targets: Iterable[str]) -> tuple[HostPolicyCheck, ...]:
    """Build observe-only policy decisions for user-supplied host targets."""
    router = PolicyRouter(config)
    checks: list[HostPolicyCheck] = []
    for target in targets or []:
        host, port, protocol = parse_policy_target(target)
        decision = router.decide(host=host, port=port, protocol=protocol, url=target)
        checks.append(HostPolicyCheck(str(target), host, port, protocol, decision))
    return tuple(checks)


def format_doctor_report(
    report: DoctorReport,
    *,
    policy_checks: Iterable[HostPolicyCheck] = (),
) -> str:
    """Render a terminal-friendly report."""
    lines = ["MasterHttpRelayVPN doctor", "", "Connectivity & Setup"]
    primary = [result for result in report.results if result.category != "safety"]
    safety = [result for result in report.results if result.category == "safety"]

    width = max((len(result.name) for result in primary), default=12)
    for result in primary:
        lines.append(_format_result(result, width))
    if safety:
        lines.extend(["", "Safety Notes"])
        safety_width = max(len(result.name) for result in safety)
        for result in safety:
            lines.append(_format_result(result, safety_width))
    policy_checks = tuple(policy_checks)
    if policy_checks:
        lines.extend(["", "Policy Dry Run"])
        target_width = max(len(_policy_target_label(check)) for check in policy_checks)
        action_width = max(len(check.decision.action) for check in policy_checks)
        transport_width = max(len(check.decision.transport) for check in policy_checks)
        reason_width = max(len(check.decision.reason) for check in policy_checks)
        for check in policy_checks:
            decision = check.decision
            matched = f"matched={decision.matched_rule}" if decision.matched_rule else "matched=-"
            lines.append(
                f"{_policy_target_label(check):<{target_width}}  "
                f"{decision.action:<{action_width}}  "
                f"{decision.transport:<{transport_width}}  "
                f"{decision.reason:<{reason_width}}  "
                f"{matched}  "
                f"mitm_allowed={str(decision.mitm_allowed).lower()}  "
                f"enforce={str(decision.enforce).lower()}"
            )
    return "\n".join(lines)


def parse_policy_target(value: object) -> tuple[str, int, str]:
    """Parse a host/URL target into `(host, port, protocol)` for policy dry-run."""
    text = str(value or "").strip()
    if not text:
        return "", 443, "https"

    scheme = ""
    port: int | None = None
    if "://" in text:
        try:
            parsed = urlsplit(text)
            scheme = (parsed.scheme or "").lower()
            host = normalize_host(parsed.hostname or "")
            port = parsed.port
        except ValueError:
            host = normalize_host(text)
    elif text.startswith("["):
        end = text.find("]")
        host = normalize_host(text[:end + 1] if end != -1 else text)
        if end != -1 and text[end + 1:].startswith(":"):
            maybe_port = text[end + 2:]
            if maybe_port.isdigit():
                port = int(maybe_port)
    else:
        host = normalize_host(text)
        if text.count(":") == 1:
            raw_host, _, raw_port = text.rpartition(":")
            if raw_port.isdigit():
                host = normalize_host(raw_host)
                port = int(raw_port)

    if port is None:
        port = 80 if scheme == "http" else 443

    if scheme in {"http", "https"}:
        protocol = scheme
    elif port == 80:
        protocol = "http"
    elif port == 443:
        protocol = "https"
    else:
        protocol = "connect"
    return host, port, protocol


def _policy_target_label(check: HostPolicyCheck) -> str:
    host = check.host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{check.port}"


def _format_result(result: DiagnosticResult, width: int) -> str:
    status = result.status.upper()
    line = f"{result.name:<{width}}  {status:<5}  {redact_text(result.message)}"
    if result.detail:
        line += f" Next: {redact_text(result.detail)}"
    return line


def _validation_to_results(
    issues: Iterable[ValidationIssue],
) -> list[DiagnosticResult]:
    severity_status = {
        "error": "fail",
        "warn": "warn",
        "info": "warn",
    }
    results: list[DiagnosticResult] = []
    for issue in issues:
        if issue.code == "proxy_ports_conflict":
            continue
        name, category = _validation_result_shape(issue)
        results.append(DiagnosticResult(
            name,
            severity_status.get(issue.severity, "warn"),
            issue.message,
            _validation_next_step(issue),
            category,
        ))
    if not results:
        results.append(DiagnosticResult("CONFIG", "pass", "No config issues found."))
    return results


def _validation_result_shape(issue: ValidationIssue) -> tuple[str, str]:
    setup_codes = {
        "auth_key_missing_or_placeholder": "CONFIG AUTH",
        "script_id_missing_or_placeholder": "CONFIG SCRIPT",
        "script_ids_empty": "CONFIG SCRIPT",
        "script_ids_placeholder": "CONFIG SCRIPT",
        "http_port_invalid": "HTTP BIND",
        "socks5_port_invalid": "SOCKS5 BIND",
        "proxy_ports_conflict": "PORT CONFLICT",
        "exit_node_url_missing": "EXIT NODE",
        "exit_node_psk_missing_or_placeholder": "EXIT NODE",
    }
    if issue.code in setup_codes:
        return setup_codes[issue.code], "connectivity"
    return "NOTE", "safety"


def _validation_next_step(issue: ValidationIssue) -> str | None:
    next_steps = {
        "auth_key_missing_or_placeholder": "Set a long auth_key in config.json and Code.gs.",
        "script_id_missing_or_placeholder": "Deploy Apps Script and set script_id.",
        "script_ids_empty": "Add at least one Apps Script deployment ID.",
        "script_ids_placeholder": "Replace placeholder script_ids with deployment IDs.",
        "http_port_invalid": "Choose an HTTP port from 1 to 65535.",
        "socks5_port_invalid": "Choose a SOCKS5 port from 1 to 65535.",
        "proxy_ports_conflict": "Use different HTTP and SOCKS5 ports.",
        "exit_node_url_missing": "Set exit_node.url or disable exit_node.enabled.",
        "exit_node_psk_missing_or_placeholder": "Set a strong exit_node.psk matching the exit node.",
        "lan_sharing_enabled": "Use only on trusted LANs.",
        "http_proxy_listens_all_interfaces": "Prefer 127.0.0.1 unless LAN sharing is intentional.",
        "socks5_exposed_without_auth": "Bind SOCKS5 to localhost unless LAN exposure is intentional.",
        "mitm_ca_private_key_exists": "Do not share ca.key.",
    }
    return next_steps.get(issue.code)


def _ports_conflict(http_port: object, socks_port: object,
                    http_host: str, socks_host: str) -> bool:
    try:
        return int(http_port) == int(socks_port) and http_host == socks_host
    except (TypeError, ValueError):
        return False


def _check_bind(name: str, host: str, port: object) -> DiagnosticResult:
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        return DiagnosticResult(name, "fail", f"Invalid port: {port!r}")
    if port_int < 1 or port_int > 65535:
        return DiagnosticResult(name, "fail", f"Invalid port: {port_int}")

    sock = socket.socket(socket.AF_INET6 if ":" in host and host != "0.0.0.0"
                         else socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port_int))
        return DiagnosticResult(name, "pass", f"{host}:{port_int} is available.")
    except OSError as exc:
        return DiagnosticResult(name, "fail", f"{host}:{port_int} is not available.",
                                str(exc))
    finally:
        sock.close()


def _check_ca_state(
    ca_cert_file: str | None,
    is_ca_trusted_func: Callable[[str], bool] | None,
) -> DiagnosticResult:
    if not ca_cert_file:
        return DiagnosticResult("MITM CA", "skip", "CA path unavailable.",
                                category="safety")
    try:
        import os
        if not os.path.exists(ca_cert_file):
            return DiagnosticResult("MITM CA", "warn", "CA certificate does not exist yet.",
                                    category="safety")
        if is_ca_trusted_func is None:
            return DiagnosticResult("MITM CA", "skip", "CA trust check unavailable.",
                                    category="safety")
        trusted = bool(is_ca_trusted_func(ca_cert_file))
        if trusted:
            return DiagnosticResult("MITM CA", "warn",
                                    "CA certificate exists and is trusted.",
                                    category="safety")
        return DiagnosticResult("MITM CA", "warn",
                                "CA certificate exists but is not trusted.",
                                category="safety")
    except Exception as exc:
        return DiagnosticResult("MITM CA", "warn", "CA trust check failed.", str(exc),
                                category="safety")


def _check_google_front(config: dict, *, timeout: float) -> DiagnosticResult:
    host = str(config.get("google_ip", "216.239.38.120"))
    sni = str(config.get("front_domain", "www.google.com"))
    start = time.perf_counter()
    sock = None
    tls_sock = None
    try:
        sock = socket.create_connection((host, 443), timeout=timeout)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls_sock = context.wrap_socket(sock, server_hostname=sni)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return DiagnosticResult(
            "GOOGLE FRONT",
            "pass",
            f"{host}:443 reachable with SNI {sni} in {elapsed_ms}ms.",
        )
    except Exception as exc:
        return DiagnosticResult(
            "GOOGLE FRONT",
            "warn",
            f"{host}:443 probe failed.",
            str(exc),
        )
    finally:
        for item in (tls_sock, sock):
            try:
                if item:
                    item.close()
            except Exception:
                pass


def _check_exit_node(config: dict, *, timeout: float) -> DiagnosticResult:
    exit_node = config.get("exit_node") or {}
    if not isinstance(exit_node, dict) or not exit_node.get("enabled"):
        return DiagnosticResult("EXIT NODE", "skip", "Exit node disabled.")
    url = str(exit_node.get("url") or exit_node.get("relay_url") or "").strip()
    if not url:
        return DiagnosticResult("EXIT NODE", "warn", "Exit node enabled but URL missing.")

    safe_url = redact_url(url)
    try:
        request = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", response.getcode())
            if 200 <= int(status) < 300:
                return DiagnosticResult("EXIT NODE", "pass",
                                        f"{safe_url} returned HTTP {status}.")
            return DiagnosticResult("EXIT NODE", "warn",
                                    f"{safe_url} returned HTTP {status}.")
    except urllib.error.HTTPError as exc:
        return DiagnosticResult("EXIT NODE", "warn",
                                f"{safe_url} returned HTTP {exc.code}.")
    except Exception as exc:
        return DiagnosticResult("EXIT NODE", "warn",
                                f"{safe_url} health check failed.", str(exc))


def _check_apps_script(config: dict, *, timeout: float) -> DiagnosticResult:
    script_ids = config.get("script_ids") or config.get("script_id")
    if isinstance(script_ids, list):
        sid = str(script_ids[0]) if script_ids else ""
    else:
        sid = str(script_ids or "")
    auth_key = str(config.get("auth_key") or "")
    if not sid or sid == "YOUR_APPS_SCRIPT_DEPLOYMENT_ID":
        return DiagnosticResult("APPS SCRIPT", "fail", "Apps Script deployment ID missing.",
                                "Set script_id in config.json.")
    if not auth_key or auth_key == "CHANGE_ME_TO_A_STRONG_SECRET":
        return DiagnosticResult("APPS SCRIPT", "fail", "auth_key missing or placeholder.",
                                "Set matching auth_key in config.json and Code.gs.")

    google_ip = str(config.get("google_ip", "216.239.38.120"))
    front_domain = str(config.get("front_domain", "www.google.com"))
    lang = str(config.get("apps_script_lang", "en") or "en")
    path = f"/macros/s/{sid}/exec?hl={lang}"
    payload = json.dumps({
        "m": "GET",
        "u": "http://example.com/",
        "k": auth_key,
    }).encode("utf-8")
    request = (
        f"POST {path} HTTP/1.1\r\n"
        "Host: script.google.com\r\n"
        "Content-Type: application/json\r\n"
        "Accept: application/json,text/plain,*/*\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8") + payload

    sock = None
    tls_sock = None
    start = time.perf_counter()
    try:
        sock = socket.create_connection((google_ip, 443), timeout=timeout)
        context = ssl.create_default_context()
        if not bool(config.get("verify_ssl", True)):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        tls_sock = context.wrap_socket(sock, server_hostname=front_domain)
        tls_sock.settimeout(timeout)
        tls_sock.sendall(request)
        response = _recv_limited(tls_sock, limit=64 * 1024)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        lower = response.lower()
        if b"unauthorized" in lower:
            return DiagnosticResult(
                "APPS SCRIPT",
                "fail",
                f"Relay reached but auth was rejected in {elapsed_ms}ms.",
                "Make sure config auth_key matches AUTH_KEY in Code.gs.",
            )
        if response.startswith(b"HTTP/") and b'"s"' in response:
            return DiagnosticResult(
                "APPS SCRIPT",
                "pass",
                f"Relay endpoint responded in {elapsed_ms}ms.",
            )
        if response.startswith(b"HTTP/") and b'"e"' in response:
            return DiagnosticResult(
                "APPS SCRIPT",
                "warn",
                f"Relay endpoint returned an error envelope in {elapsed_ms}ms.",
                "Check Apps Script deployment, quotas, and target reachability.",
            )
        if response.startswith(b"HTTP/"):
            return DiagnosticResult(
                "APPS SCRIPT",
                "warn",
                f"Apps Script endpoint returned an unexpected response in {elapsed_ms}ms.",
                "Check deployment access is set to Anyone and script_id is current.",
            )
        return DiagnosticResult(
            "APPS SCRIPT",
            "warn",
            "Apps Script probe returned a non-HTTP response.",
        )
    except Exception as exc:
        return DiagnosticResult(
            "APPS SCRIPT",
            "warn",
            "Apps Script relay probe failed.",
            f"{exc}; check google_ip, front_domain, script_id, and network filtering.",
        )
    finally:
        for item in (tls_sock, sock):
            try:
                if item:
                    item.close()
            except Exception:
                pass


def _recv_limited(sock, *, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        data = sock.recv(min(8192, limit - total))
        if not data:
            break
        chunks.append(data)
        total += len(data)
        if b"\r\n\r\n" in b"".join(chunks) and total > 2048:
            break
    return b"".join(chunks)
