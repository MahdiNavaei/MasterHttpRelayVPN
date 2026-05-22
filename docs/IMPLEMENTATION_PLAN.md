# Implementation Plan

## Phase 0: Repository Understanding and Cleanup

### Objective

Document the current architecture and target roadmap without changing product behavior.

### Files Likely Affected

- `docs/`
- No product code files.

### Proposed New Files

- `docs/PROJECT_AUDIT.md`
- `docs/PRD_RESILIENT_TUNNEL.md`
- `docs/GAP_ANALYSIS.md`
- `docs/IMPLEMENTATION_PLAN.md`
- `docs/ARCHITECTURE_TARGET.md`
- `docs/CODEX_RECOMMENDATIONS.md`

### Acceptance Criteria

- Current architecture is described from repository evidence.
- Target architecture is documented with explicit assumptions.
- No implementation behavior changes.
- Existing project name remains unchanged.

### Risks

- Documentation may overstate capabilities if not grounded in code.
- Governance and planning docs can become stale if not updated with implementation.

### Test Strategy

- No runtime tests required for docs-only changes.
- Run existing unit tests if practical to confirm no accidental product changes.

## Phase 1: Diagnostics and Health Checks

### Objective

Add a smart `doctor` or `status` command that helps users identify setup and network failures before starting the proxy.

### Files Likely Affected

- `main.py`
- `src/core/cert_installer.py`
- `src/core/google_ip_scanner.py`
- `src/relay/domain_fronter.py`
- possibly `src/proxy/proxy_server.py` for reusable bind checks only

### Proposed New Files

- `src/core/config_validation.py`
- `src/core/diagnostics.py`
- `tests/test_config_validation.py`
- `tests/test_diagnostics.py`

### Acceptance Criteria

- `python main.py doctor` loads config and exits.
- Doctor checks HTTP/SOCKS bind feasibility.
- Doctor checks Google front reachability.
- Doctor checks Apps Script relay auth using redacted output.
- Doctor checks exit-node health when enabled.
- Doctor checks CA existence/trust state.
- Doctor warns about LAN sharing, placeholder secrets, MITM, and unsafe config.
- No long-running proxy listeners remain open after doctor exits.

### Risks

- Doctor could consume Apps Script quota if checks are too frequent or heavy.
- Network probes can hang without strict timeouts.
- Auth check could leak secrets if logging is careless.

### Test Strategy

- Unit test config warnings and redaction.
- Unit test doctor result formatting.
- Mock network checks.
- Add one optional manual command for live doctor checks.

## Phase 2: Policy Routing

### Objective

Introduce explicit, testable routing decisions without rewriting relay internals.

### Files Likely Affected

- `src/proxy/proxy_server.py`
- `src/proxy/proxy_support.py`
- `src/core/constants.py`
- `main.py`

### Proposed New Files

- `src/core/policy.py`
- `src/core/domain_matcher.py`
- `tests/test_policy.py`
- `tests/test_domain_matcher.py`

### Acceptance Criteria

- Policy engine returns action, reason, and matched rule for host/port/protocol.
- Backward compatibility with `block_hosts`, `direct_hosts`, and `bypass_hosts`.
- Private/local IPs bypass remote relay by default.
- Sensitive domains are identified and return no-MITM/direct action.
- Route decisions can be logged without secrets.
- Existing behavior can run in compatibility mode during rollout.

### Risks

- Incorrect rule precedence can break working routes.
- Sensitive-domain matching can be incomplete.
- Domestic direct rules can be politically and operationally sensitive.

### Test Strategy

- Pure unit tests for exact, suffix, wildcard-like leading-dot, IP, and port cases.
- Snapshot-style tests for route reasons.
- Regression tests for existing direct/block/bypass behavior.

## Phase 3: Security Hardening

### Objective

Reduce accidental risk from MITM, secrets, unsafe relay targets, and proxy exposure.

### Files Likely Affected

- `main.py`
- `src/proxy/mitm.py`
- `src/core/cert_installer.py`
- `src/proxy/proxy_server.py`
- `src/relay/domain_fronter.py`
- `apps_script/Code.gs`
- `apps_script/cloudflare_worker.js`
- `apps_script/vps_exit_node.py`

### Proposed New Files

- `src/core/redaction.py`
- `src/core/security_warnings.py`
- `tests/test_redaction.py`
- `tests/test_security_warnings.py`

### Acceptance Criteria

- Secrets are redacted consistently in logs and doctor output.
- MITM warnings are explicit.
- Sensitive domains bypass MITM by default in the new policy layer.
- Config validation fails closed for placeholder secrets.
- LAN sharing warns when exposing unauthenticated proxy listeners.
- Remote relay paths reject local/private targets where applicable.

### Risks

- Changing MITM defaults can break current HTTPS relay expectations.
- Apps Script private-IP blocking is hard because Apps Script may resolve DNS internally.
- Overzealous redaction can hide useful diagnostics.

### Test Strategy

- Redaction unit tests with auth keys, script IDs, PSKs, and credentialed URLs.
- Policy tests for sensitive no-MITM behavior.
- Manual verification of cert install/uninstall remains unchanged.

## Phase 4: Experimental System Tunnel

### Objective

Add guarded full-system traffic capture using TUN/tun2socks, initially Windows first.

### Files Likely Affected

- `main.py`
- startup scripts only if needed for optional UX
- docs for system tunnel operation

### Proposed New Files

- `src/system_tunnel/__init__.py`
- `src/system_tunnel/tun2socks.py`
- `src/system_tunnel/windows.py`
- `src/system_tunnel/linux.py`
- `tests/test_system_tunnel_plan.py`

### Acceptance Criteria

- Feature is disabled by default.
- CLI refuses to start without explicit opt-in.
- Windows admin requirement is detected before route changes.
- Route state is captured before changes.
- Failure attempts rollback.
- tun2socks process lifecycle is monitored.
- Existing local SOCKS5 proxy is used as the egress target.

### Risks

- Incorrect route changes can break network connectivity.
- External tun2socks binary choice affects trust and distribution.
- DNS leaks remain unless a DNS strategy is added.
- Antivirus/firewall interaction on Windows can vary.

### Test Strategy

- Unit test command construction and rollback state modeling.
- Mock process execution.
- Manual test in a disposable Windows VM.
- Do not run route-changing tests in CI without isolation.

## Phase 5: Transport Abstraction

### Objective

Separate route selection from transport execution so Apps Script, direct, exit node, and future transports can be added cleanly.

### Files Likely Affected

- `src/proxy/proxy_server.py`
- `src/relay/domain_fronter.py`
- `src/relay/h2_transport.py`

### Proposed New Files

- `src/transports/__init__.py`
- `src/transports/base.py`
- `src/transports/apps_script.py`
- `src/transports/direct.py`
- `src/transports/exit_node.py`
- `tests/test_transport_contract.py`

### Acceptance Criteria

- Define a minimal transport interface for HTTP request relay.
- Wrap current Apps Script behavior without changing semantics.
- Direct transport supports no-MITM direct cases.
- Exit-node behavior is represented as a transport or chained transport.
- Policy router selects transport by action.
- Existing tests pass and route behavior remains compatible.

### Risks

- `DomainFronter` is large and stateful; extraction can introduce subtle regressions.
- Direct tunneling and HTTP request relaying have different shapes.
- MITM and raw TCP paths do not map cleanly to a single HTTP transport interface.

### Test Strategy

- Contract tests with fake transports.
- Unit tests for selection.
- Integration tests with fake local HTTP origin and fake relay server.
- Keep extraction incremental and behavior-preserving.

## Phase 6: Future Work

### Objective

Expand resilience and UX after diagnostics, policy, security, TUN, and transport boundaries are stable.

### Files Likely Affected

- New DNS subsystem files.
- New transport files.
- UI/dashboard files if introduced.
- Platform-specific mobile files if Android is later added.

### Proposed New Files

- `src/dns/`
- `src/transports/worker_ws.py`
- `src/transports/vps.py`
- `src/dashboard/`
- Android-specific project files only if a separate mobile scope is approved.

### Acceptance Criteria

- DNS subsystem supports policy-aware resolution.
- Worker/WebSocket transport can be tested independently.
- Optional VPS transport is documented as optional, not required.
- Android VpnService has its own explicit PRD before implementation.
- GUI/dashboard does not replace CLI diagnostics.

### Risks

- Feature creep.
- Increased dependency and packaging complexity.
- Platform-specific maintenance burden.
- Potential legal and policy concerns around distribution and claims.

### Test Strategy

- Separate PRDs for major subsystems.
- Contract tests for each new transport.
- Platform-specific manual test matrices.
- CI tests only for deterministic, non-privileged parts.
