# Project Audit

## High-Level Project Summary

MasterHttpRelayVPN is a Python local proxy that accepts browser or application traffic through HTTP proxy and SOCKS5 listeners, then routes much of that traffic through a user-deployed Google Apps Script relay. The documented default path is:

```text
Browser/App -> Local HTTP/SOCKS5 proxy -> Google-facing fronted TLS -> Apps Script relay -> Target website
```

The repository also includes optional exit-node implementations for Cloudflare Workers, Deno Deploy, and a Linux VPS. Exit nodes are not a replacement for the Apps Script relay in the current client design; they are chained behind Apps Script for destinations that reject Google egress IPs.

The project is already more than a minimal script. It includes MITM certificate generation, OS trust-store install/uninstall helpers, HTTP/2 relay transport, request batching, connection warmup, ad-block host rules, direct host bypasses, Google IP scanning, LAN sharing, Docker support, and tests for selected helper modules. The central runtime behavior is still concentrated in a few large classes, especially `ProxyServer` and `DomainFronter`.

## Main Components and Files

| File or directory | Current role |
|---|---|
| `main.py` | CLI entry point. Loads JSON config, applies env/CLI overrides, validates required Apps Script settings, handles CA install/uninstall and Google IP scan, starts `ProxyServer`. |
| `setup.py` | Interactive wizard that writes `config.json` from `config.example.json` plus user-provided `auth_key`, Apps Script deployment IDs, host, and ports. |
| `start.bat` | Windows launcher. Creates `.venv`, installs dependencies, runs setup if needed, starts `main.py`. |
| `start.sh` | Linux/macOS launcher. Similar to `start.bat`. |
| `config.example.json` | Example runtime configuration. Includes Google fronting, ports, relay tuning, direct/block hosts, host overrides, exit node settings, and adblock lists. |
| `src/proxy/proxy_server.py` | Main local proxy implementation. Handles HTTP proxy requests, CONNECT, SOCKS5 target tunnels, MITM, direct tunnels, SNI-rewrite tunnels, local CA serving, cache, adblock, and routing decisions. |
| `src/proxy/socks5.py` | SOCKS5 handshake parser. Supports no-auth CONNECT for IPv4, IPv6, and domain names. |
| `src/proxy/mitm.py` | Generates and loads local root CA plus per-domain certificates for HTTPS interception. |
| `src/proxy/proxy_support.py` | Helper functions for host rules, header parsing, CORS responses, cache TTL, and response logging. |
| `src/relay/domain_fronter.py` | Apps Script relay client. Handles H1/H2 transport, batching, coalescing, retries, connection warmup, script ID selection/blacklisting, exit-node chaining, stats, and large download helpers. |
| `src/relay/h2_transport.py` | HTTP/2 transport used for multiplexed requests to the Google front. |
| `src/relay/relay_response.py` | Relay envelope parsing and raw HTTP response reconstruction helpers. |
| `src/relay/http_reader.py` | HTTP response reader for raw H1 relay responses. |
| `src/core/constants.py` | Central constants for timeouts, limits, Google/SNI rules, cache settings, and relay patterns. |
| `src/core/cert_installer.py` | Windows, macOS, Linux, and Firefox certificate install/uninstall helpers. |
| `src/core/google_ip_scanner.py` | CLI scanner for candidate Google frontend IPs. |
| `src/core/adblock.py` | Adblock list cache/refresh support. |
| `apps_script/Code.gs` | Google Apps Script relay. Authenticates with `AUTH_KEY`, fetches target URLs with `UrlFetchApp`, supports batch mode, strips unsafe headers, gzip-compresses relay responses when useful. |
| `apps_script/cloudflare_worker.js` | Optional Cloudflare Worker exit node with PSK auth and GET health response. |
| `apps_script/vps_exit_node.py` | Optional Linux-only VPS exit node with PSK auth, local/private target blocking, and GET health response. |
| `tests/` | Unit tests for proxy helpers, fronting helpers, codec handling, and adblock behavior. |

## Runtime Flow

1. User runs `start.bat`, `start.sh`, or `python main.py`.
2. `main.py` parses CLI flags and loads `config.json`.
3. Environment variables can override `auth_key`, `script_id`, HTTP/SOCKS ports, listen host, and log level.
4. `main.py` rejects missing or placeholder `auth_key` and missing placeholder `script_id`.
5. Runtime mode is forced to `apps_script`.
6. Unless `--no-cert-check` is used, `main.py` ensures a CA exists and attempts to install it when not trusted.
7. LAN sharing can change `listen_host` from `127.0.0.1` to `0.0.0.0` and logs LAN access details.
8. `ProxyServer.start()` warms the relay, then opens HTTP and SOCKS5 listeners.
9. HTTP proxy traffic is handled by `_on_client()`.
10. SOCKS5 traffic is negotiated in `negotiate_socks5()` and then passed to `_handle_target_tunnel()`.

## Proxy Architecture

`ProxyServer` is the main routing point. It owns:

- listener setup and shutdown
- HTTP proxy parsing
- SOCKS5 handling
- block/direct/bypass host rules
- Google-domain direct shortcut logic
- SNI-rewrite logic
- MITM setup
- plain HTTP relay path
- cache decisions
- large-download streaming path
- CORS preflight handling

The most important routing function is `_handle_target_tunnel(host, port, reader, writer)`:

1. If host matches `block_hosts` or adblock rules, return 403/close.
2. If host matches `direct_hosts` or `bypass_hosts`, use raw direct tunnel.
3. If host is an IP literal:
   - port 443 uses MITM relay
   - port 80 uses plain HTTP relay
   - other ports use direct tunnel
4. If host maps to an SNI rewrite IP, use MITM from browser and outbound TLS with configured Google/front SNI.
5. If host is an allowed Google-owned domain, try direct tunnel first, then SNI rewrite or plain HTTP fallback.
6. For non-Google HTTPS, use MITM and Apps Script relay.
7. For plain HTTP, relay request stream through Apps Script.
8. For non-HTTP ports, use direct tunnel.

This is functional but tightly coupled. A future policy router should be inserted before this branching logic becomes more complex.

## HTTP Proxy Behavior

Plain HTTP requests are parsed in `_do_http()`:

- rejects unsupported `Transfer-Encoding`
- caps request body size via `MAX_REQUEST_BODY_BYTES`
- handles browser CORS preflight locally because Apps Script does not support OPTIONS in this relay model
- optionally streams large downloads
- caches selected GET static responses
- calls `_relay_smart()` when a response is not cached
- injects permissive CORS headers when the browser sent `Origin`

For HTTPS CONNECT, `_do_connect()` accepts the tunnel with `HTTP/1.1 200 Connection Established` and delegates the target decision to `_handle_target_tunnel()`.

## SOCKS5 Behavior

`src/proxy/socks5.py` implements a narrow SOCKS5 server:

- supports version 5 only
- supports no-auth method only
- supports CONNECT only
- supports IPv4, domain names, and IPv6
- does not implement username/password auth
- does not implement UDP ASSOCIATE
- does not implement BIND

After negotiation, SOCKS5 target traffic is routed through the same `_handle_target_tunnel()` path used by HTTP CONNECT.

## HTTPS and MITM Behavior

MITM is present and central to the current relay design:

- `MITMCertManager` creates `ca/ca.key` and `ca/ca.crt` if missing.
- It generates per-domain leaf certificates in a temporary directory.
- `main.py` attempts automatic trusted-root installation unless `--no-cert-check` is used.
- HTTPS destinations that are not direct/bypassed generally require local TLS interception so the proxy can read HTTP requests and send them to Apps Script.

Security-sensitive observations:

- The local CA private key is stored unencrypted at `ca/ca.key`.
- POSIX permissions are restricted to `0600`, but Windows security relies on user-scoped filesystem behavior rather than an explicit ACL hardening step.
- Automatic CA installation improves usability but is risky as a default for production-ready security posture.
- LAN sharing can serve `ca.crt` to LAN clients. It does not serve `ca.key`, but users still need strong warnings around sharing proxy access and CA material.
- The project does not currently have a no-MITM default for HTTPS relay. A no-MITM mode would require a different transport design or tunneling strategy.

## Google Apps Script Relay Behavior

`apps_script/Code.gs` exposes `doPost(e)` and authenticates requests with a shared `AUTH_KEY`. The Python client sends JSON payloads containing method, URL, headers, optional base64 body, and auth key.

The script:

- rejects unauthorized requests
- supports single and batch requests
- uses `UrlFetchApp.fetch()` and `UrlFetchApp.fetchAll()`
- strips hop-by-hop, proxy, forwarding, `x-mhr-hop`, and `accept-encoding` headers
- refuses relay targets that point back to Apps Script macro URLs
- marks outbound requests with `x-mhr-hop`
- gzip-compresses relay response bytes when smaller
- returns JSON with status, headers, base64 body, and optional gzip marker

The code implies Apps Script constraints but does not encode a full quota model:

- relay execution count is logged client-side in `DomainFronter`
- batching and coalescing exist to reduce execution count
- response-size constraints are handled by constants and large-download/range strategies
- comments mention UrlFetchApp response size pressure, especially for media flows

Because quotas and throttling are external Google platform behavior, documentation should avoid hard guarantees and describe them as environment-dependent.

## Relay Client Architecture

`DomainFronter` is the local relay client and is currently large. It includes:

- Google IP/front-domain settings
- SNI rotation
- HTTP/1.1 connection pooling
- optional HTTP/2 transport pool
- batching and sub-batching
- coalescing of concurrent identical GETs
- script ID stable selection and blacklisting
- background probing for blacklisted script IDs
- connection warmup and keepalive
- response parsing and error classification
- site stats logging
- optional exit-node chaining
- range/parallel large download support

This module is the natural place to extract a future `AppsScriptTransport` implementation.

## Exit Node Behavior

Exit node support is present but is integrated inside `DomainFronter`, not abstracted as a transport plugin.

The current client behavior:

- reads `exit_node` config
- supports provider aliases and URL resolution
- supports `full` and `selective` modes
- excludes `googlevideo.com` from exit-node chaining
- wraps the original target request as an inner payload authenticated with exit-node PSK
- sends that inner payload to the exit node through Apps Script
- falls back to normal Apps Script relay if the exit node fails

Exit node scripts:

- Cloudflare Worker returns JSON health on GET, requires POST for relay, uses PSK, strips unsafe headers, detects some loops.
- VPS exit node is Linux only, uses Python stdlib HTTP server, requires PSK, rejects local/private target URLs, and caps request/response sizes.

## Configuration Model

Configuration is an untyped JSON dictionary loaded in `main.py` and passed into `ProxyServer` and `DomainFronter`.

Current config features include:

- Google fronting: `google_ip`, `front_domain`, `front_domains`
- Apps Script: `script_id` or `script_ids`, `auth_key`, `apps_script_lang`
- listeners: `listen_host`, `http_port`, `socks5_port`, `lan_sharing`
- TLS: `verify_ssl`, `no_sni`
- relay tuning: `relay_timeout`, `tls_connect_timeout`, `tcp_connect_timeout`, `parallel_relay`, `h2_connections`, `ping_interval`
- batching: `enable_batch`, `batch_window_micro`, `batch_window_macro`, `enable_sub_batch`
- host policy: `block_hosts`, `direct_hosts`, `bypass_hosts`, `hosts`
- YouTube/path heuristics: `youtube_via_relay`, `relay_url_patterns`
- exit node: `enabled`, `provider`, `url`, `psk`, `mode`, `hosts`
- logging and adblock: `log_level`, `adblock_lists`

Limitations:

- no explicit schema version
- no strict validation layer
- invalid numeric values are often coerced locally by helper functions, but config errors are not reported as a complete diagnostic set
- policy concepts are spread across `block_hosts`, `direct_hosts`, `bypass_hosts`, built-in Google rules, SNI rewrite rules, exit-node host rules, and relay URL patterns
- no explicit sensitive-domain category

## Security-Sensitive Areas

- Root CA generation and automatic installation.
- Unencrypted CA private key at `ca/ca.key`.
- LAN sharing and proxy exposure on `0.0.0.0`.
- Shared `auth_key` for Apps Script relay.
- Exit-node PSK and URL.
- MITM interception of browser credentials and session cookies.
- Header rewriting and forwarding behavior.
- Apps Script `UrlFetchApp` SSRF surface. It currently validates URL scheme and blocks Apps Script loops, but does not appear to block private IP/localhost targets in `Code.gs`.
- Exit-node SSRF surface. The VPS script blocks obvious local/private targets; Worker script validates URL format and loop cases but does not implement a private-IP DNS resolution block.
- Logs can include URLs and hostnames. Full secrets are masked for script IDs in some logs, but a general redaction policy is not centralized.

## Known Limitations Based on Code

- No first-class `doctor` or `status` command.
- No full config schema validation.
- No policy routing abstraction.
- No sensitive-domain default list for banking, payment, government, medical, identity, or password-manager domains.
- MITM is fundamental to most HTTPS relay behavior.
- SOCKS5 supports CONNECT only and no auth.
- DNS handling is limited to normal system DNS plus `hosts` override map. No local DNS resolver exists.
- Full-system TUN/tun2socks mode is not present.
- Exit-node handling is coupled to the Apps Script relay client.
- Tests cover helper functions but not end-to-end proxy routing, MITM, Apps Script relay envelopes, or exit-node fallback behavior.
- Some behavior is optimized for specific services and networks, which is useful but increases routing complexity in `ProxyServer`.

## Risks of MITM/CA Use

- A trusted local CA can impersonate HTTPS sites from the perspective of browsers/apps that trust it.
- Theft of `ca/ca.key` would allow certificate forgery wherever that CA is trusted.
- Automatic CA install can surprise users and makes the security boundary less explicit.
- MITM breaks or degrades apps using certificate pinning, non-HTTP protocols over TLS, HTTP/2 expectations, or custom TLS behavior.
- Sensitive domains should not be intercepted by default in a production-ready fork.
- LAN clients that install the CA and use the proxy extend the trust and attack surface to other devices.

## Apps Script Quota and Performance Assumptions

Visible code and comments imply these assumptions:

- Apps Script executions are a scarce resource, so the client logs execution count and implements batching/coalescing.
- `UrlFetchApp` can fail on large responses; the client includes range and streaming strategies for likely downloads.
- Cold starts are a concern; the client prewarms and keeps the Apps Script container alive.
- Network throttling may be per TCP connection; the code uses HTTP/2 pools and pings to keep flows active.
- Multiple script IDs can improve throughput and resilience, with sticky per-host selection and temporary blacklisting.

These are engineering assumptions encoded in code and comments, not platform guarantees.

## What the Project Currently Does Well

- Provides a complete local proxy startup flow for Windows and Linux/macOS.
- Supports both HTTP proxy and SOCKS5 listeners.
- Includes user-friendly setup and existing documentation.
- Handles MITM certificate generation and OS trust-store integration.
- Implements several practical resilience techniques: warm pools, H2 multiplexing, SNI rotation, batching, coalescing, retries, and script blacklisting.
- Supports direct bypass and block lists.
- Provides optional exit-node scripts.
- Has some focused unit tests.

## What the Project Is Not Designed To Do Yet

- It is not a full-system VPN/tunnel.
- It is not a general multi-transport framework.
- It does not provide a robust policy engine with explainable route decisions.
- It does not make MITM optional for the main HTTPS relay path.
- It does not provide comprehensive diagnostics.
- It does not include a DNS subsystem.
- It does not guarantee availability during complete international connectivity loss or full blocking of Google/Apps Script.
- It does not provide enterprise-grade secret management.

## Concrete Recommendations

1. Add a `doctor` command before adding new tunnel modes.
2. Add a typed config loader/validator with warning and error severity levels.
3. Extract policy routing into a standalone module before expanding split tunneling.
4. Add a sensitive-domain guardrail list and default no-MITM/no-relay behavior for that category.
5. Keep direct local/private IP bypass as a hard default unless explicitly overridden.
6. Extract `AppsScriptTransport` from `DomainFronter` behind a transport interface.
7. Move exit-node logic behind a transport or chained-transport abstraction.
8. Document MITM risks more prominently and avoid auto-installing CA in future safer modes.
9. Add unit tests for route decisions before changing routing behavior.
10. Treat TUN/tun2socks as experimental and add it only after policy routing and diagnostics are stable.
