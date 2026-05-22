# Engineering Recommendations

## Is the Roadmap Realistic?

Yes, with sequencing discipline. The current codebase already contains many ingredients needed for a resilient tunneling framework: HTTP and SOCKS5 listeners, MITM, Apps Script relay, H2 transport, batching, warmup, direct bypass, adblock, Google IP scan, and optional exit nodes.

The risk is not missing functionality. The risk is coupling. `ProxyServer` and `DomainFronter` each own too many responsibilities. A production-ready fork is realistic if the first implementation steps add diagnostics, validation, and route-decision tests before refactoring the relay core.

## Easy Parts to Implement First

- `doctor` command output.
- Config warning layer.
- Secret redaction helper.
- Domain suffix matcher tests.
- Sensitive-domain warning list.
- Route-decision logging in observe-only mode.
- Exit-node health check, because existing exit-node scripts already expose GET health responses.
- CA trust/existence check, because `cert_installer.is_ca_trusted()` already exists.

## Risky Parts

- Changing MITM defaults.
- Moving exit-node behavior out of `DomainFronter`.
- Extracting `AppsScriptTransport` too early.
- Adding TUN/tun2socks route management.
- Adding DNS handling.
- Changing route precedence for Google, YouTube, SNI rewrite, and relay URL patterns.

## Does the Current Structure Support This Extension?

Partially.

Good extension points:

- `main.py` can grow a `doctor` command.
- `proxy_support.py` already has pure helper functions that can inspire policy tests.
- `DomainFronter.relay()` is a natural future boundary for `AppsScriptTransport`.
- `ProxyServer._handle_target_tunnel()` is the current route insertion point.
- Existing exit-node scripts already have health endpoints.

Weak points:

- Route decisions are embedded in `ProxyServer`.
- Apps Script transport, exit-node chaining, batching, retries, and health behavior are embedded in `DomainFronter`.
- Config is untyped and scattered.
- MITM is assumed for most HTTPS relay behavior.

The structure can support the roadmap, but only if policy and diagnostics are extracted before major behavior changes.

## Should Docs/Diagnostics Come Before TUN Mode?

Yes. TUN mode should not be first.

Full-system mode can break a user's network if route setup or rollback is wrong. The project should first add:

- config validation
- doctor checks
- route policy tests
- sensitive-domain guardrails
- clear logs

After those exist, TUN/tun2socks can reuse the existing SOCKS5 listener and policy router with less risk.

## Where Health Checks Should Be Added

Add health checks outside the long-running proxy server path:

- `main.py`: parse `doctor` and call diagnostics.
- `src/core/diagnostics.py`: orchestrate checks and format results.
- `src/core/config_validation.py`: validate config and produce warnings/errors.
- Reuse `src/core/cert_installer.py` for CA trust state.
- Reuse parts of `src/core/google_ip_scanner.py` for Google front probing, but make doctor checks smaller and single-target by default.
- Add a lightweight Apps Script probe helper near `DomainFronter` or in diagnostics using the same request envelope.
- Add exit-node GET health check in diagnostics.

Avoid starting `ProxyServer.start()` for doctor except for explicit listener bind feasibility checks.

## Where Policy Routing Should Be Inserted

The first runtime insertion point is `ProxyServer._handle_target_tunnel()`, before the existing block/direct/IP/SNI/MITM branching.

Recommended sequence:

1. Add pure `PolicyRouter.decide(host, port, protocol, url=None)`.
2. In observe-only mode, call it from `_handle_target_tunnel()` and log decision, but keep existing behavior.
3. Add tests proving decisions match current behavior for existing config.
4. Start enforcing only low-risk decisions: block, direct, sensitive no-MITM, private/local direct.
5. Later move SNI rewrite and exit-node selection into the router.

Plain HTTP `_do_http()` and MITM `_relay_http_stream()` should eventually call policy by full URL, because path-level routing such as `relay_url_patterns` cannot be decided from host/port alone.

## Likely Bugs or Edge Cases

- IPv6 CONNECT target parsing can be tricky when formatted as `[addr]:port`.
- SOCKS5 domain names and HTTP CONNECT hosts may be normalized differently.
- Leading-dot suffix rules do not match the bare domain in current helper behavior. For example `.example.org` matches `sub.example.org` but not `example.org`.
- Apps using certificate pinning will fail under MITM.
- Non-HTTP TLS on port 443 can fail when MITM is attempted.
- `Code.gs` validates URL scheme and loop to Apps Script but does not visibly block private or localhost target URLs.
- Worker exit node does not visibly resolve and block private IP targets after DNS.
- LAN sharing exposes unauthenticated proxy listeners.
- Direct and SNI-rewrite fallback state can create surprising temporary behavior after failures.
- Route rules can conflict with built-in Google/YouTube special cases.
- Logs can include sensitive URLs even if keys are masked.

## What I Would Implement First

I would implement the following first:

1. `src/core/redaction.py`
2. `src/core/config_validation.py`
3. `src/core/diagnostics.py`
4. `python main.py doctor`
5. Tests for all of the above

Reason: this gives maintainers and users immediate value without changing traffic behavior. It also creates the safety infrastructure needed for policy routing, MITM changes, and TUN mode.

## What I Would Avoid in the First MVP

- Do not add TUN mode before route policy and doctor exist.
- Do not remove or disable current MITM behavior abruptly.
- Do not rewrite `DomainFronter` in one pass.
- Do not add a new transport before the transport contract is tested.
- Do not add a GUI.
- Do not add Android mode.
- Do not claim blackout resistance.

## Security Concerns That Should Block Implementation Until Fixed

The following should block any "production-ready" claim until addressed:

- No first-class sensitive-domain no-MITM guardrail.
- No central secret redaction layer.
- No complete config validation.
- No explicit warning when LAN sharing exposes unauthenticated proxy access.
- No clear default policy preventing remote relay of private/local destinations across every relay path.
- MITM CA private key risk is documented but should be surfaced more directly in diagnostics.

These concerns do not block documentation or diagnostics work. They should block marketing the fork as production-ready until implemented and tested.
