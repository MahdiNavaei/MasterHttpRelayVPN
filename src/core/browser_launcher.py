"""Managed browser launch helpers.

This module is intentionally side-effect light: browser discovery and command
construction are pure/testable, while process launching is left to ``main.py``.
Managed browser mode routes only an isolated browser profile through the local
HTTP proxy and never modifies system proxy settings.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping
from urllib.parse import urlsplit


DEFAULT_START_URL = "https://example.com/"
SUPPORTED_BROWSERS = ("auto", "chrome", "edge", "chromium")


@dataclass(frozen=True)
class BrowserExecutable:
    """Resolved browser executable."""

    kind: str
    path: str


@dataclass(frozen=True)
class BrowserLaunch:
    """Prepared browser launch command."""

    executable: BrowserExecutable
    command: tuple[str, ...]
    profile_dir: str
    url: str
    temporary_profile: bool
    insecure_ignore_cert_errors: bool


def normalize_start_url(value: object | None) -> str:
    """Normalize a user supplied URL for browser startup."""
    text = str(value or "").strip()
    if not text:
        return DEFAULT_START_URL
    parsed = urlsplit(text)
    if parsed.scheme:
        return text
    return f"https://{text}"


def default_profile_dir(cwd: str | os.PathLike[str] | None = None) -> str:
    """Return the default persistent managed browser profile directory."""
    base = Path(cwd or os.getcwd())
    return str(base / ".mhr-browser-profile")


def resolve_profile_dir(
    *,
    profile: str | None = None,
    temporary_profile: bool = False,
    cwd: str | os.PathLike[str] | None = None,
    temp_factory: Callable[[str], str] | None = None,
) -> tuple[str, bool]:
    """Resolve the profile directory and whether it is temporary."""
    if temporary_profile:
        factory = temp_factory or (lambda prefix: tempfile.mkdtemp(prefix=prefix))
        return factory("mhr-browser-"), True
    if profile:
        return str(Path(profile).expanduser()), False
    return default_profile_dir(cwd), False


def discover_browser(
    requested: str = "auto",
    *,
    platform: str | None = None,
    env: Mapping[str, str] | None = None,
    path_exists: Callable[[str], bool] | None = None,
    which: Callable[[str], str | None] | None = None,
) -> BrowserExecutable | None:
    """Find a browser executable for Chrome, Edge, or Chromium."""
    requested = (requested or "auto").lower()
    if requested not in SUPPORTED_BROWSERS:
        raise ValueError(f"Unsupported browser: {requested}")

    platform_name = platform or sys.platform
    env_map = env or os.environ
    exists = path_exists or os.path.exists
    which_func = which or shutil.which

    kinds = ("chrome", "edge", "chromium") if requested == "auto" else (requested,)
    for kind in kinds:
        for candidate in _browser_candidates(kind, platform_name, env_map):
            resolved = which_func(candidate) if _is_command_name(candidate) else None
            path = resolved or candidate
            if resolved or exists(path):
                return BrowserExecutable(kind=kind, path=path)
    return None


def build_browser_command(
    executable: BrowserExecutable,
    *,
    proxy_host: str,
    proxy_port: int,
    profile_dir: str,
    url: str | None = None,
    insecure_ignore_cert_errors: bool = False,
) -> tuple[str, ...]:
    """Build a Chromium-family browser command for managed mode."""
    flags = [
        executable.path,
        f"--proxy-server=http://{proxy_host}:{int(proxy_port)}",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-extensions",
        "--disable-component-update",
        "--disable-default-apps",
    ]
    if insecure_ignore_cert_errors:
        flags.append("--ignore-certificate-errors")
    flags.append(normalize_start_url(url))
    return tuple(flags)


def prepare_browser_launch(
    *,
    requested_browser: str,
    proxy_host: str,
    proxy_port: int,
    url: str | None,
    profile: str | None,
    temporary_profile: bool,
    insecure_ignore_cert_errors: bool,
    cwd: str | os.PathLike[str] | None = None,
    temp_factory: Callable[[str], str] | None = None,
    platform: str | None = None,
    env: Mapping[str, str] | None = None,
    path_exists: Callable[[str], bool] | None = None,
    which: Callable[[str], str | None] | None = None,
) -> BrowserLaunch | None:
    """Resolve browser executable, profile, URL, and command."""
    executable = discover_browser(
        requested_browser,
        platform=platform,
        env=env,
        path_exists=path_exists,
        which=which,
    )
    if executable is None:
        return None
    profile_dir, is_temporary = resolve_profile_dir(
        profile=profile,
        temporary_profile=temporary_profile,
        cwd=cwd,
        temp_factory=temp_factory,
    )
    start_url = normalize_start_url(url)
    command = build_browser_command(
        executable,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        profile_dir=profile_dir,
        url=start_url,
        insecure_ignore_cert_errors=insecure_ignore_cert_errors,
    )
    return BrowserLaunch(
        executable=executable,
        command=command,
        profile_dir=profile_dir,
        url=start_url,
        temporary_profile=is_temporary,
        insecure_ignore_cert_errors=insecure_ignore_cert_errors,
    )


def browser_not_found_message(browser: str, proxy_host: str, proxy_port: int) -> str:
    """Return actionable browser-not-found guidance."""
    requested = "Chrome, Edge, or Chromium" if browser == "auto" else browser
    return (
        f"Browser not found ({requested}). Install Chrome, Edge, or Chromium, "
        f"or manually configure a browser HTTP proxy to {proxy_host}:{int(proxy_port)}."
    )


def _browser_candidates(
    kind: str,
    platform_name: str,
    env: Mapping[str, str],
) -> Iterable[str]:
    if platform_name.startswith("win"):
        program_files = [
            env.get("PROGRAMFILES", r"C:\Program Files"),
            env.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            env.get("LOCALAPPDATA", ""),
        ]
        names = {
            "chrome": [
                r"Google\Chrome\Application\chrome.exe",
                "chrome.exe",
                "chrome",
            ],
            "edge": [
                r"Microsoft\Edge\Application\msedge.exe",
                "msedge.exe",
                "msedge",
            ],
            "chromium": [
                r"Chromium\Application\chrome.exe",
                "chromium.exe",
                "chromium",
            ],
        }[kind]
        for name in names:
            if "\\" in name:
                for base in program_files:
                    if base:
                        yield str(Path(base) / name)
            else:
                yield name
        return

    if platform_name == "darwin":
        names = {
            "chrome": [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "google-chrome",
            ],
            "edge": [
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                "microsoft-edge",
            ],
            "chromium": [
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
                "chromium",
            ],
        }[kind]
        yield from names
        return

    names = {
        "chrome": ["google-chrome", "google-chrome-stable", "chrome"],
        "edge": ["microsoft-edge", "microsoft-edge-stable"],
        "chromium": ["chromium", "chromium-browser"],
    }[kind]
    yield from names


def _is_command_name(value: str) -> bool:
    return not any(sep in value for sep in ("/", "\\"))
