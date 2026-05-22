# PRD: Resilient Tunnel Framework

## Problem Statement

MasterHttpRelayVPN currently works as a local HTTP/SOCKS5 proxy that can relay browser traffic through Google Apps Script and optional exit nodes. This is useful in restricted or unstable network environments, but the current architecture is not yet a production-ready, policy-based tunneling framework.

Users in environments with inconsistent filtering, throttling, partial international access, provider-dependent routing, DNS interference, and destination-side blocking need a tool that can diagnose what is reachable, route traffic by policy, avoid risky interception for sensitive domains, and eventually support full-system traffic capture without requiring a domain or VPS for the default path.

The improved fork should preserve the existing no-domain/no-VPS spirit where possible, keep Apps Script as a supported transport, and prepare the architecture for other transports without overclaiming that it can solve complete national blackout conditions.

## Product Vision

Transform the project from a browser/local proxy relay into a resilient, policy-based client-side tunneling framework for unstable and restricted networks.

The framework should:

- keep the existing HTTP and SOCKS5 proxy modes
- preserve Apps Script relay as one transport
- add health checks and diagnostics
- add policy routing and split tunneling
- use safer defaults for MITM and sensitive domains
- provide experimental full-system mode through TUN/tun2socks
- make future transports pluggable
- remain transparent about limits and risks

## Target Users

- Users who can configure a local proxy in a browser or app.
- Users in restricted networks where some international destinations are filtered or throttled.
- Users who can deploy a Google Apps Script relay but may not own a VPS or domain.
- Technical users who want a visible open-source engineering project with diagnostics and clear failure modes.
- Maintainers who need a roadmap for turning the existing proxy into a modular tunneling framework.

## Non-Goals

- Do not promise bypass of full national internet shutdowns.
- Do not replace Tor, WireGuard, Shadowsocks, or mature VPN systems.
- Do not make Android full-device VPN mode part of MVP.
- Do not require a VPS or custom domain for the primary MVP path.
- Do not remove existing HTTP/SOCKS5 proxy behavior.
- Do not make MITM invisible or automatic in future safer modes.
- Do not add multiple new transports in MVP unless the transport interface is ready and the change is low risk.

## Use Cases

1. A user runs `doctor` to understand whether local proxy ports, Google fronting, Apps Script, and optional exit nodes are reachable.
2. A user routes domestic, banking, payment, government, and local/private traffic directly while relaying selected international domains.
3. A browser uses local HTTP proxy mode with clear route-decision logs.
4. An app uses local SOCKS5 mode and benefits from the same policy decisions.
5. A technical user enables experimental Windows full-system mode so system traffic enters the existing local SOCKS5 proxy through tun2socks.
6. A maintainer adds a future Worker/WebSocket or optional VPS transport without rewriting proxy routing.

## Functional Requirements

### A. Smart Health Check / Doctor Command

MVP requirements:

- Add `python main.py doctor` or equivalent CLI command.
- Load and validate config without starting long-running proxy listeners.
- Check local HTTP proxy bind feasibility.
- Check local SOCKS5 proxy bind feasibility.
- Check whether configured ports conflict.
- Check Google front reachability using configured `google_ip` and `front_domain`.
- Check Apps Script relay reachability and auth using a safe test request.
- Check exit-node health when configured.
- Check MITM CA existence and trust status.
- Warn when CA private key exists and MITM is enabled.
- Warn when `auth_key`, Apps Script IDs, or exit-node PSK appear placeholder or missing.
- Warn when `lan_sharing` binds to all interfaces.
- Print clear status output with pass/warn/fail and actionable next steps.

Doctor must avoid printing full secrets, deployment IDs, or PSKs.

### B. Policy Routing / Split Rules

MVP requirements:

- Add an explicit routing policy config section.
- Support direct domains.
- Support relay domains.
- Support sensitive domains.
- Support default action.
- Always bypass local/private IPs by default.
- Support domestic/Iranian domains direct by default when configured.
- Support bank/payment/government domains direct by default through a maintained user-editable list.
- Ensure sensitive domains are not MITM'd by default.
- Log route decisions in a concise, redacted format.
- Keep backward compatibility with `direct_hosts`, `bypass_hosts`, and `block_hosts`.

Recommended route actions:

- `direct`
- `relay`
- `block`
- `exit_node`
- `sni_rewrite`
- `no_mitm_direct`

### C. Experimental Full-System Tunnel Mode

Target MVP architecture:

```text
System traffic -> TUN adapter -> tun2socks -> existing local SOCKS5 proxy -> policy router -> selected transport
```

MVP constraints:

- Windows first.
- Linux experimental.
- Android out of scope.
- Require explicit opt-in.
- Detect admin/root requirement before changing routes.
- Capture previous route state and restore it on failure.
- Start from external tun2socks integration as a wrapper design, not a custom packet stack.
- Do not make full-system mode the default.

### D. Security Improvements

MVP requirements:

- Prefer no-MITM defaults where technically possible.
- Print clear warnings when MITM is enabled.
- Sensitive domains must be direct/no-MITM by default.
- Validate config before startup.
- Redact secrets in logs and diagnostics.
- Document CA private key risk.
- Document Apps Script `AUTH_KEY` risk.
- Document exit-node PSK risk.
- Warn on LAN sharing and unauthenticated SOCKS5 exposure.

### E. Transport Abstraction Preparation

MVP should prepare the architecture for:

- `AppsScriptTransport`
- `DirectTransport`
- `ExitNodeTransport`
- future Worker/WebSocket transport
- future optional VPS transport

MVP does not need to implement all transports as production-ready alternatives. The main requirement is to avoid hard-coding every future path inside `ProxyServer` and `DomainFronter`.

## Non-Functional Requirements

- Startup must remain simple for existing users.
- Default behavior must remain backward compatible during early rollout.
- Diagnostics must complete quickly and avoid indefinite hangs.
- Network checks must have explicit timeouts.
- Route decisions must be deterministic for the same config and destination.
- Config parsing must produce stable, actionable errors.
- Logging must be useful at `INFO` without leaking secrets.
- Failure modes must degrade cleanly and explain what happened.

## Security Requirements

- Never log full `auth_key`, script IDs, exit-node PSK, CA key paths with sensitive contents, or full credentials in URLs.
- Do not relay or MITM sensitive domains by default.
- Do not widen listen host to LAN unless explicitly configured.
- Warn when SOCKS5 has no authentication and listens beyond localhost.
- Block private/local IP relay through remote transports unless explicitly and safely configured.
- Validate URL schemes before remote relay.
- Preserve header stripping for forwarding/proxy headers.
- Use timeouts for all doctor and transport checks.
- Make CA install/uninstall explicit in CLI UX for future safer modes.

## UX / CLI Requirements

Proposed CLI shape:

```text
python main.py start
python main.py doctor
python main.py status
python main.py --scan
python main.py --install-cert
python main.py --uninstall-cert
```

Backward compatibility:

- `python main.py` should continue to start the proxy.
- Existing flags should continue to work.

Doctor output should be compact:

```text
CONFIG        PASS  config.json loaded
HTTP PROXY    PASS  127.0.0.1:8085 available
SOCKS5        PASS  127.0.0.1:1080 available
GOOGLE FRONT  WARN  216.239.38.120 reachable but slow
APPS SCRIPT   PASS  relay auth accepted
MITM CA       WARN  trusted root installed; sensitive domains should bypass MITM
EXIT NODE     SKIP  disabled
```

## Configuration Requirements

Add a versioned config model:

```json
{
  "config_version": 1,
  "routing": {
    "default_action": "relay",
    "direct_domains": [],
    "relay_domains": [],
    "sensitive_domains": [],
    "domestic_direct": {
      "enabled": false,
      "suffixes": [".ir"]
    },
    "private_ip_bypass": true,
    "no_mitm_sensitive": true
  }
}
```

Compatibility requirements:

- Existing `direct_hosts`, `bypass_hosts`, and `block_hosts` must still work.
- New config should be additive.
- Unknown fields should produce warnings, not immediate failure, during migration.
- Invalid security-sensitive values should fail closed.

## Observability / Logging Requirements

- Add route-decision logging with action, host, reason, and transport.
- Add doctor output suitable for issue reports.
- Redact secrets by default.
- Include timing for network checks.
- Separate user-facing diagnostics from debug trace logs.
- Eventually add optional structured JSON logs, but not required for MVP.

## Compatibility Requirements

- Python 3.10+.
- Windows primary support for current local proxy and future TUN mode.
- Linux/macOS support for current local proxy.
- Linux experimental support for future TUN mode.
- Docker support should continue for local proxy mode.
- Android is out of scope for MVP.

## Rollout Plan

1. Add docs and target architecture.
2. Add config validation in warning-only mode.
3. Add doctor command without changing proxy runtime behavior.
4. Add policy router in observe-only mode.
5. Enable policy router for direct/block/sensitive decisions behind backward-compatible config.
6. Harden MITM defaults and warnings.
7. Add experimental TUN/tun2socks wrapper with explicit opt-in.
8. Extract transport interfaces after route behavior is covered by tests.

## MVP Scope

MVP includes:

- doctor command
- config validator
- route policy model
- sensitive-domain protection
- route-decision tests
- direct/local/private bypass
- no-MITM sensitive behavior
- experimental Windows TUN/tun2socks wrapper design and guarded CLI
- transport abstraction preparation

MVP excludes:

- Android VPN mode
- GUI/dashboard
- complete DNS subsystem
- mandatory new transport
- custom packet stack
- replacement of Apps Script as primary transport

## Future Scope

- Local DNS resolver.
- DNS-over-HTTPS or DNS-over-TLS options with policy controls.
- Cloudflare Worker/WebSocket transport.
- Optional VPS transport as first-class transport.
- Android VpnService.
- GUI/dashboard.
- Signed release packages.
- More complete integration tests with fake relay servers.
- Route metrics and health-based transport selection.

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| MITM exposes sensitive traffic | Sensitive domains direct/no-MITM by default; prominent warnings; no hidden CA install in new modes. |
| Policy routing breaks existing behavior | Add observe-only mode and tests before enforcement. |
| Apps Script quotas limit reliability | Diagnostics, batching, multiple script IDs, clear quota warnings, future transports. |
| Full-system mode can break connectivity | Explicit opt-in, admin checks, route snapshot, rollback on failure. |
| Secret leakage in logs | Central redaction helper and tests. |
| Transport abstraction becomes overdesigned | Extract only around current behavior first: Apps Script and Direct. |
| Network conditions vary by provider | Doctor reports observed status without claiming universal availability. |

## Success Criteria

- A new user can run `doctor` and identify the first failing setup step.
- Existing proxy startup still works with old configs.
- Route decisions are testable outside network I/O.
- Sensitive domains are not MITM'd or relayed by default in the new policy layer.
- Full-system mode is clearly marked experimental and can restore routes after failure.
- Maintainers can add a new transport without editing unrelated proxy parsing code.

## Open Questions

- What exact sensitive-domain defaults should ship, and how should they be maintained?
- Should MITM remain auto-installed for legacy mode, or become an explicit setup step in the fork?
- What tun2socks binary or library should be recommended for Windows?
- Should policy matching support geosite-style lists, simple suffixes only, or both?
- How should domestic/Iranian direct lists be curated without creating political or operational risk?
- Should Apps Script relay health use `example.com`, a configured test URL, or a built-in neutral endpoint?
- How should the project handle destinations that require HTTP/2 end-to-end?
