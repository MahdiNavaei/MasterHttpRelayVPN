#!/usr/bin/env python3
"""
DomainFront Tunnel — Bypass DPI censorship via Google Apps Script.

Run a local HTTP proxy that tunnels all traffic through a Google Apps
Script relay fronted by www.google.com (TLS SNI shows www.google.com
while the encrypted Host header points at script.google.com).
"""

import argparse
import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys

# Project modules live under ./src — add it to sys.path so package imports
# like "from proxy.proxy_server import ProxyServer" work from project root.
_SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from core.cert_installer import install_ca, uninstall_ca, is_ca_trusted
from core.browser_launcher import (
    browser_not_found_message,
    prepare_browser_launch,
)
from core.config_validation import validate_config
from core.constants import __version__
from core.diagnostics import build_policy_checks, format_doctor_report, run_doctor
from core.lan_utils import log_lan_access
from core.google_ip_scanner import scan_sync
from core.logging_utils import configure as configure_logging, print_banner
from proxy.mitm import CA_CERT_FILE, CA_KEY_FILE
from proxy.proxy_server import ProxyServer


_PLACEHOLDER_AUTH_KEYS = {
    "",
    "CHANGE_ME_TO_A_STRONG_SECRET",
    "your-secret-password-here",
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog="domainfront-tunnel",
        description="Local HTTP proxy that relays traffic through Google Apps Script.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["doctor", "status", "browser"],
        help="Optional command. Use 'doctor' for diagnostics or 'browser' for managed browser mode.",
    )
    parser.add_argument(
        "-c", "--config",
        default=os.environ.get("DFT_CONFIG", "config.json"),
        help="Path to config file (default: config.json, env: DFT_CONFIG)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help="Override HTTP proxy port (env: DFT_HTTP_PORT, legacy: DFT_PORT)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Override listen host (env: DFT_HOST)",
    )
    parser.add_argument(
        "--socks5-port",
        type=int,
        default=None,
        help="Override SOCKS5 listen port (env: DFT_SOCKS5_PORT)",
    )
    parser.add_argument(
        "--disable-socks5",
        action="store_true",
        help="Deprecated: SOCKS5 listener is always enabled.",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override log level (env: DFT_LOG_LEVEL)",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--install-cert",
        action="store_true",
        help="Install the MITM CA certificate as a trusted root and exit.",
    )
    parser.add_argument(
        "--uninstall-cert",
        action="store_true",
        help="Remove the MITM CA certificate from trusted roots and exit.",
    )
    parser.add_argument(
        "--no-cert-check",
        action="store_true",
        help="Skip the certificate installation check on startup.",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan Google IPs to find the fastest reachable one and exit.",
    )
    parser.add_argument(
        "--check-host",
        action="append",
        default=[],
        metavar="HOST",
        help="With doctor/status, show observe-only policy recommendation for a host or URL.",
    )
    parser.add_argument(
        "--url",
        default="https://example.com/",
        help="With browser mode, URL to open (default: https://example.com/).",
    )
    parser.add_argument(
        "--browser",
        choices=["auto", "chrome", "edge", "chromium"],
        default="auto",
        help="With browser mode, browser executable family to launch.",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="With browser mode, isolated browser profile directory.",
    )
    parser.add_argument(
        "--temporary-profile",
        action="store_true",
        help="With browser mode, use a temporary isolated profile and remove it on exit.",
    )
    parser.add_argument(
        "--insecure-ignore-cert-errors",
        action="store_true",
        help="With browser mode, pass --ignore-certificate-errors to the browser.",
    )
    return parser.parse_args()


def _load_config(config_path: str, *, allow_wizard: bool) -> dict:
    try:
        with open(config_path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Config not found: {config_path}")
        if not allow_wizard:
            raise SystemExit(1)
        # Offer the interactive wizard if it's available and we're on a TTY.
        wizard = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup.py")
        if os.path.exists(wizard) and sys.stdin.isatty():
            try:
                answer = input("Run the interactive setup wizard now? [Y/n]: ").strip().lower()
            except EOFError:
                answer = "n"
            if answer in ("", "y", "yes"):
                import subprocess
                rc = subprocess.call([sys.executable, wizard])
                if rc != 0:
                    raise SystemExit(rc)
                try:
                    with open(config_path) as f:
                        return json.load(f)
                except Exception as e:
                    print(f"Could not load config after setup: {e}")
                    raise SystemExit(1)
            else:
                print("Copy config.example.json to config.json and fill in your values,")
                print("or run: python setup.py")
                raise SystemExit(1)
        else:
            print("Run: python setup.py   (or copy config.example.json to config.json)")
            raise SystemExit(1)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in config: {e}")
        raise SystemExit(1)


def _apply_overrides(config: dict, args) -> dict:
    # Environment variable overrides
    if os.environ.get("DFT_AUTH_KEY"):
        config["auth_key"] = os.environ["DFT_AUTH_KEY"]
    if os.environ.get("DFT_SCRIPT_ID"):
        config["script_id"] = os.environ["DFT_SCRIPT_ID"]

    # CLI argument overrides
    if args.port is not None:
        config["http_port"] = args.port
    elif os.environ.get("DFT_HTTP_PORT"):
        config["http_port"] = int(os.environ["DFT_HTTP_PORT"])
    elif os.environ.get("DFT_PORT"):
        config["http_port"] = int(os.environ["DFT_PORT"])

    # Backward compatibility for older config files.
    if "http_port" not in config:
        config["http_port"] = int(config.get("listen_port", 8080))

    if args.host is not None:
        config["listen_host"] = args.host
    elif os.environ.get("DFT_HOST"):
        config["listen_host"] = os.environ["DFT_HOST"]

    if args.socks5_port is not None:
        config["socks5_port"] = args.socks5_port
    elif os.environ.get("DFT_SOCKS5_PORT"):
        config["socks5_port"] = int(os.environ["DFT_SOCKS5_PORT"])

    if args.log_level is not None:
        config["log_level"] = args.log_level
    elif os.environ.get("DFT_LOG_LEVEL"):
        config["log_level"] = os.environ["DFT_LOG_LEVEL"]

    return config


def main():
    args = parse_args()

    if args.command in ("doctor", "status"):
        config = _load_config(args.config, allow_wizard=False)
        config = _apply_overrides(config, args)
        report = run_doctor(
            config,
            ca_cert_file=CA_CERT_FILE,
            ca_key_file=CA_KEY_FILE,
            is_ca_trusted_func=is_ca_trusted,
        )
        policy_checks = build_policy_checks(config, args.check_host)
        print(format_doctor_report(report, policy_checks=policy_checks))
        sys.exit(1 if report.has_failures else 0)

    if args.command == "browser":
        _run_browser_command(args)
        return

    # Handle cert-only commands before loading config so they can run standalone.
    if args.install_cert or args.uninstall_cert:
        configure_logging("INFO")
        _log = logging.getLogger("Main")

        if args.install_cert:
            _log.info("Installing CA certificate…")
            if not os.path.exists(CA_CERT_FILE):
                from proxy.mitm import MITMCertManager
                MITMCertManager()  # side-effect: creates ca/ca.crt + ca/ca.key
            ok = install_ca(CA_CERT_FILE)
            sys.exit(0 if ok else 1)

        _log.info("Removing CA certificate…")
        ok = uninstall_ca(CA_CERT_FILE)
        if ok:
            _log.info("CA certificate removed successfully.")
        else:
            _log.warning("CA certificate removal may have failed. Check logs above.")
        sys.exit(0 if ok else 1)

    config = _load_config(args.config, allow_wizard=True)
    config = _apply_overrides(config, args)

    if args.disable_socks5:
        logging.getLogger("Main").warning(
            "--disable-socks5 is deprecated and ignored: SOCKS5 is always enabled."
        )

    # Keep runtime behavior fixed regardless of user config values.
    config["socks5_enabled"] = True

    for key in ("auth_key",):
        if key not in config:
            print(f"Missing required config key: {key}")
            sys.exit(1)

    if config.get("auth_key", "") in _PLACEHOLDER_AUTH_KEYS:
        print(
            "Refusing to start: 'auth_key' is unset or uses a known placeholder.\n"
            "Pick a long random secret and set it in both config.json AND "
            "the AUTH_KEY constant inside Code.gs (they must match)."
        )
        sys.exit(1)

    # Always Apps Script mode — force-set for backward-compat configs.
    config["mode"] = "apps_script"
    sid = config.get("script_ids") or config.get("script_id")
    if not sid or (isinstance(sid, str) and sid == "YOUR_APPS_SCRIPT_DEPLOYMENT_ID"):
        print("Missing 'script_id' in config.")
        print("Deploy the Apps Script from Code.gs and paste the Deployment ID.")
        sys.exit(1)

    # ── Google IP Scanner ──────────────────────────────────────────────────
    if args.scan:
        configure_logging("INFO")
        front_domain = config.get("front_domain", "www.google.com")
        _log = logging.getLogger("Main")
        _log.info(f"Scanning Google IPs (fronting domain: {front_domain})")
        ok = scan_sync(front_domain)
        sys.exit(0 if ok else 1)

    configure_logging(config.get("log_level", "INFO"))
    log = logging.getLogger("Main")

    print_banner(__version__)
    log.info("DomainFront Tunnel starting (Apps Script relay)")

    log.info("Apps Script relay : SNI=%s → script.google.com",
             config.get("front_domain", "www.google.com"))
    script_ids = config.get("script_ids") or config.get("script_id")
    if isinstance(script_ids, list):
        log.info("Script IDs        : %d scripts (sticky per-host)", len(script_ids))
        for i, sid in enumerate(script_ids):
            _s = str(sid)
            masked = f"{_s[:6]}…{_s[-4:]}" if len(_s) > 12 else _s
            log.info("  [%d] %s", i + 1, masked)
    else:
        _s = str(script_ids) if script_ids else "(none)"
        masked = f"{_s[:6]}…{_s[-4:]}" if len(_s) > 12 else _s
        log.info("Script ID         : %s", masked)

    # Ensure CA file exists before checking / installing it.
    # MITMCertManager generates ca/ca.crt on first instantiation.
    if not os.path.exists(CA_CERT_FILE):
        from proxy.mitm import MITMCertManager
        MITMCertManager()  # side-effect: creates ca/ca.crt + ca/ca.key

    # Auto-install MITM CA if not already trusted
    if not args.no_cert_check:
        if not is_ca_trusted(CA_CERT_FILE):
            log.warning("MITM CA is not trusted — attempting automatic installation…")
            ok = install_ca(CA_CERT_FILE)
            if ok:
                log.info("CA certificate installed. You may need to restart your browser.")
            else:
                log.error(
                    "Auto-install failed. Run with --install-cert (may need admin/sudo) "
                    "or manually install ca/ca.crt as a trusted root CA."
                )
        else:
            log.info("MITM CA is already trusted.")

    # ── LAN sharing configuration ────────────────────────────────────────
    lan_sharing = config.get("lan_sharing", False)
    listen_host = config.get("listen_host", "127.0.0.1")
    if lan_sharing:
        # If LAN sharing is enabled and host is still localhost, change to all interfaces
        if listen_host == "127.0.0.1":
            config["listen_host"] = "0.0.0.0"
            listen_host = "0.0.0.0"

    # If either explicit LAN sharing is enabled or we bind to all interfaces,
    # print concrete IPv4 addresses users can use on other devices.
    lan_mode = lan_sharing or listen_host in ("0.0.0.0", "::")
    if lan_mode:
        http_port = config.get("http_port", config.get("listen_port", 8080))
        socks_port = config.get("socks5_port", 1080)
        log_lan_access(http_port, socks_port)

        if lan_sharing:
            # Log CA download URLs so LAN devices know where to get the cert.
            from core.lan_utils import get_lan_ips
            ca_urls = [f"http://{addr}/ca.crt" for addr in get_lan_ips(http_port)]
            if ca_urls:
                log.info(
                    "CA certificate download (install on other devices): %s",
                    "  OR  ".join(ca_urls),
                )
            else:
                log.info(
                    "CA certificate download: http://<your-LAN-IP>:%d/ca.crt", http_port
                )

    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:
        log.info("Stopped")


def _run_browser_command(args) -> None:
    """Run managed browser mode without changing system proxy settings."""
    config = _load_config(args.config, allow_wizard=True)
    config = _apply_overrides(config, args)
    config["socks5_enabled"] = True
    config["mode"] = "apps_script"
    config["lan_sharing"] = False
    config["listen_host"] = "127.0.0.1"
    config["socks5_host"] = "127.0.0.1"

    validation = validate_config(
        config,
        ca_cert_file=CA_CERT_FILE,
        ca_key_file=CA_KEY_FILE,
    )
    errors = [issue for issue in validation.issues if issue.severity == "error"]
    if errors:
        print("Browser mode config validation failed:")
        for issue in errors:
            field = f" ({issue.field})" if issue.field else ""
            print(f"- {issue.message}{field}")
        raise SystemExit(1)

    http_port = int(config.get("http_port", config.get("listen_port", 8080)))
    launch = prepare_browser_launch(
        requested_browser=args.browser,
        proxy_host="127.0.0.1",
        proxy_port=http_port,
        url=args.url,
        profile=args.profile,
        temporary_profile=args.temporary_profile,
        insecure_ignore_cert_errors=args.insecure_ignore_cert_errors,
    )
    if launch is None:
        print(browser_not_found_message(args.browser, "127.0.0.1", http_port))
        raise SystemExit(1)

    configure_logging(config.get("log_level", "INFO"))
    log = logging.getLogger("Browser")
    print_banner(__version__)
    log.info("Managed browser mode starting")
    log.info("HTTP proxy for browser: http://127.0.0.1:%d", http_port)
    log.info("Browser executable: %s", launch.executable.path)
    log.info("Browser profile: %s", launch.profile_dir)
    if launch.insecure_ignore_cert_errors:
        log.warning(
            "--insecure-ignore-cert-errors is enabled. "
            "Use only for testing; it weakens browser TLS validation."
        )
    elif not os.path.exists(CA_CERT_FILE) or not is_ca_trusted(CA_CERT_FILE):
        log.warning(
            "HTTPS sites may show certificate errors until the local CA is trusted. "
            "Run: python main.py --install-cert"
        )

    os.makedirs(launch.profile_dir, exist_ok=True)
    try:
        asyncio.run(_run_managed_browser(config, launch))
    except KeyboardInterrupt:
        log.info("Managed browser mode stopped")
    finally:
        if launch.temporary_profile:
            shutil.rmtree(launch.profile_dir, ignore_errors=True)


async def _run_managed_browser(config: dict, launch) -> int:
    """Start proxy, launch browser, and stop proxy when browser exits."""
    log = logging.getLogger("Browser")
    server = ProxyServer(config)
    server_task = asyncio.create_task(server.start())
    process = None
    try:
        await _wait_for_proxy_listeners(config, server_task, timeout=45.0)
        log.info("Launching browser: %s", launch.url)
        process = subprocess.Popen(list(launch.command))
        return_code = await asyncio.to_thread(process.wait)
        log.info("Browser exited with code %s", return_code)
        return return_code
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=5.0)
            except asyncio.TimeoutError:
                process.kill()
                await asyncio.to_thread(process.wait)
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
        await server.stop()
        stray = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in stray:
            task.cancel()
        if stray:
            await asyncio.gather(*stray, return_exceptions=True)


async def _wait_for_proxy_listeners(
    config: dict,
    server_task: asyncio.Task,
    *,
    timeout: float,
) -> None:
    """Wait until HTTP and SOCKS5 listeners accept local TCP connections."""
    host = "127.0.0.1"
    http_port = int(config.get("http_port", config.get("listen_port", 8080)))
    socks_port = int(config.get("socks5_port", 1080))
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if server_task.done():
            await server_task
        if (
            await _can_connect(host, http_port)
            and await _can_connect(host, socks_port)
        ):
            return
        await asyncio.sleep(0.2)
    raise RuntimeError(
        f"Proxy listeners did not become ready on {host}:{http_port} "
        f"and {host}:{socks_port} within {timeout:.0f}s."
    )


async def _can_connect(host: str, port: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=0.5,
        )
    except Exception:
        return False
    try:
        writer.close()
        await writer.wait_closed()
    finally:
        del reader
    return True



def _make_exception_handler(log):
    """Return an asyncio exception handler that silences Windows WinError 10054
    noise from connection cleanup (ConnectionResetError in
    _ProactorBasePipeTransport._call_connection_lost), which is harmless but
    verbose on Python/Windows when a remote host force-closes a socket."""
    def handler(loop, context):
        exc = context.get("exception")
        cb  = context.get("handle") or context.get("source_traceback", "")
        if (
            isinstance(exc, ConnectionResetError)
            and "_call_connection_lost" in str(cb)
        ):
            return  # suppress: benign Windows socket cleanup race
        log.error("[asyncio]  %s", context.get("message", context))
        if exc:
            loop.default_exception_handler(context)
    return handler


async def _run(config):
    loop = asyncio.get_running_loop()
    _log = logging.getLogger("asyncio")
    loop.set_exception_handler(_make_exception_handler(_log))
    server = ProxyServer(config)
    try:
        await server.start()
    finally:
        await server.stop()
        # Cancel any tasks that leaked through (e.g. fire-and-forget pool tasks).
        stray = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for t in stray:
            t.cancel()
        if stray:
            await asyncio.gather(*stray, return_exceptions=True)


if __name__ == "__main__":
    main()
