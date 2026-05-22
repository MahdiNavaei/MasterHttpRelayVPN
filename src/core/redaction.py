"""Secret redaction helpers for diagnostics and logs.

The functions in this module are deliberately conservative: they preserve
small prefixes/suffixes for debugging while avoiding full credential exposure.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit


SENSITIVE_KEYS = {
    "auth_key",
    "authorization",
    "bearer",
    "key",
    "password",
    "proxy-authorization",
    "proxy_authorization",
    "psk",
    "script_id",
    "script_ids",
    "secret",
    "token",
}

_CREDENTIAL_URL_RE = re.compile(r"\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^@\s/]+)@",
                                re.IGNORECASE)
_BEARER_RE = re.compile(r"\b(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})", re.IGNORECASE)
_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>\b(?:auth_key|script_id|script_ids|psk|token|secret|password)"
    r"\b\s*[:=]\s*[\"']?)(?P<value>[^\"'\s,}]{6,})",
    re.IGNORECASE,
)


def is_sensitive_key(key: object) -> bool:
    """Return True when *key* is normally used to store a secret."""
    normalized = str(key).strip().lower().replace("-", "_")
    if normalized in SENSITIVE_KEYS:
        return True
    return any(token in normalized for token in ("token", "secret", "password"))


def redact_value(value: object, *, keep_start: int = 4, keep_end: int = 4) -> str:
    """Redact one scalar value while preserving limited debugging context."""
    text = "" if value is None else str(value)
    if not text:
        return ""
    if len(text) <= keep_start + keep_end + 3:
        return "***"
    return f"{text[:keep_start]}...{text[-keep_end:]}"


def redact_url(value: str) -> str:
    """Redact credentials embedded in a URL."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return _CREDENTIAL_URL_RE.sub(r"\1***:***@", value)
    if not parts.scheme or "@" not in parts.netloc:
        return _CREDENTIAL_URL_RE.sub(r"\1***:***@", value)

    host_part = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, f"***:***@{host_part}",
                       parts.path, parts.query, parts.fragment))


def redact_text(text: object) -> str:
    """Redact obvious secrets inside a free-form string."""
    value = "" if text is None else str(text)
    value = _CREDENTIAL_URL_RE.sub(r"\1***:***@", value)
    value = _BEARER_RE.sub(lambda m: m.group(1) + redact_value(m.group(2)), value)
    value = _ASSIGNMENT_RE.sub(
        lambda m: m.group("prefix") + redact_value(m.group("value")),
        value,
    )
    return value


def redact_dict(data: Mapping[str, Any]) -> dict[str, Any]:
    """Return a recursively redacted copy of a mapping."""
    out: dict[str, Any] = {}
    for key, value in data.items():
        key_text = str(key)
        if is_sensitive_key(key_text):
            if isinstance(value, list):
                out[key_text] = [redact_value(item) for item in value]
            else:
                out[key_text] = redact_value(value)
            continue
        if isinstance(value, Mapping):
            out[key_text] = redact_dict(value)
        elif isinstance(value, list):
            out[key_text] = [
                redact_dict(item) if isinstance(item, Mapping)
                else redact_text(item) if isinstance(item, str)
                else item
                for item in value
            ]
        elif isinstance(value, str):
            out[key_text] = redact_text(value)
        else:
            out[key_text] = value
    return out
