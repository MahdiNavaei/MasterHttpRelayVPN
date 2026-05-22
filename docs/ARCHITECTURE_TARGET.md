# Target Architecture

## Current Approximate Architecture

```text
Browser/App
  -> Local HTTP/SOCKS5 Proxy
  -> Google front / Apps Script relay
  -> Target website
```

More detailed current flow:

```text
Browser/App
  -> HTTP proxy :8085 or SOCKS5 :1080
  -> ProxyServer route logic
     -> direct tunnel, or
     -> SNI-rewrite tunnel, or
     -> MITM HTTP relay
  -> DomainFronter
  -> Google-facing TLS connection
  -> script.google.com Apps Script /exec
  -> UrlFetchApp.fetch(target)
  -> Target website
```

Optional current exit-node flow:

```text
Browser/App
  -> Local proxy
  -> Apps Script relay
  -> Exit node
  -> Target website
```

## Target MVP Architecture

```text
System Apps
  -> TUN adapter
  -> tun2socks
  -> Local SOCKS5/HTTP proxy
  -> Policy Router
  -> Apps Script Transport / Direct / Exit Node
  -> Target
```

Expanded:

```text
                +----------------+
Browser/App --->| HTTP/SOCKS5    |
                | Local Proxy    |
System Apps     +--------+-------+
  -> TUN                 |
  -> tun2socks           v
                +----------------+
                | Policy Router  |
                +---+--------+---+
                    |        |
          +---------+        +----------------+
          v                                  v
 +--------------------+             +----------------+
 | AppsScriptTransport|             | DirectTransport|
 +---------+----------+             +----------------+
           |
           v
 +--------------------+
 | ExitNodeTransport  |  (optional chain or selected route)
 +--------------------+
```

## Future Architecture

```text
System Apps
  -> TUN/DNS/Policy Engine
  -> Transport Selector
  -> Apps Script / Worker / VPS / Direct / Exit Node
  -> Target
```

Expanded:

```text
                 +--------------------------+
System Apps ---->| TUN Capture              |
Browser/App ---->| HTTP/SOCKS5 Proxy        |
DNS Queries ---->| Local DNS Resolver       |
                 +------------+-------------+
                              |
                              v
                 +--------------------------+
                 | Policy Engine            |
                 | - domain/IP rules        |
                 | - sensitive guardrails   |
                 | - domestic/direct rules  |
                 | - health-aware fallback  |
                 +------------+-------------+
                              |
                              v
                 +--------------------------+
                 | Transport Selector       |
                 +--+-----+------+-----+----+
                    |     |      |     |
                    v     v      v     v
                  Apps  Worker  VPS  Direct
                 Script  WS          /Exit
```

## Core Modules

### CLI and Lifecycle

Responsibilities:

- parse commands and flags
- load config
- run validation
- start proxy
- run doctor/status
- manage system tunnel lifecycle

Candidate files:

- `main.py`
- `src/core/config_validation.py`
- `src/core/diagnostics.py`
- `src/system_tunnel/`

### Local Proxy

Responsibilities:

- accept HTTP proxy traffic
- accept SOCKS5 traffic
- parse CONNECT and plain HTTP requests
- delegate route decisions to policy router
- execute selected direct/tunnel/relay path

Candidate files:

- existing `src/proxy/proxy_server.py`
- existing `src/proxy/socks5.py`
- existing `src/proxy/mitm.py`

### Policy Router

Responsibilities:

- decide route action from host, port, protocol, URL, and config
- explain decision with reason
- enforce sensitive-domain guardrails
- centralize direct/block/relay/exit-node matching
- keep local/private IP bypass deterministic

Candidate files:

- `src/core/policy.py`
- `src/core/domain_matcher.py`

Example result:

```python
RouteDecision(
    action="direct",
    transport="direct",
    reason="sensitive_domain_no_mitm",
    mitm_allowed=False,
)
```

### Transport Plugin Model

Transport implementations should hide relay mechanics behind a small interface.

Initial candidate interface:

```text
Transport.name
Transport.health_check()
Transport.relay_http(method, url, headers, body) -> raw HTTP response
```

Initial transports:

- `AppsScriptTransport`: wraps current `DomainFronter`.
- `DirectTransport`: direct origin fetch/tunnel where applicable.
- `ExitNodeTransport`: wraps current exit-node behavior or represents a chained transport.

Future transports:

- `WorkerWebSocketTransport`
- `VpsTransport`
- provider-specific experimental transports

Important constraint:

Raw TCP tunnels and MITM HTTP relay are different execution shapes. The abstraction should start with HTTP request relay and avoid forcing all traffic into one interface too early.

### Health Monitor

Responsibilities:

- run one-shot doctor checks
- later maintain background health state
- test Google front, Apps Script, exit node, ports, CA, config
- report pass/warn/fail with timings

Candidate files:

- `src/core/diagnostics.py`
- `src/core/health.py` in future

### Security Guardrails

Responsibilities:

- sensitive-domain defaults
- no-MITM enforcement
- private/local IP relay prevention
- secret redaction
- LAN sharing warnings
- CA state warnings

Candidate files:

- `src/core/security_warnings.py`
- `src/core/redaction.py`
- `src/core/policy.py`

### Config Schema

Responsibilities:

- version config
- validate types and ranges
- normalize legacy fields
- produce warning/error list
- avoid failing existing users unnecessarily during migration

Candidate files:

- `src/core/config_validation.py`

Example sections:

```json
{
  "config_version": 1,
  "relay": {},
  "listeners": {},
  "routing": {},
  "security": {},
  "exit_node": {}
}
```

### Logging Model

Current logging is human-readable and component-based. Target logging should add:

- route decision records
- doctor result output
- secret redaction
- optional JSON logs later
- consistent timing fields

Example:

```text
ROUTE host=example.com action=relay transport=apps_script reason=default_relay
ROUTE host=bank.example action=direct transport=direct reason=sensitive_no_mitm
```

## Security Guardrails

Default guardrails for MVP:

- local/private IPs direct only
- sensitive domains direct/no-MITM
- no remote relay of localhost/private destinations
- warning when MITM CA is installed
- warning when LAN sharing is enabled
- warning when SOCKS5 listens beyond localhost without auth
- redacted secrets everywhere

## Compatibility Strategy

The target architecture should be introduced incrementally:

1. Add doctor and config validation with no runtime routing changes.
2. Add policy router in observe-only mode.
3. Use policy router for decisions already supported by existing behavior.
4. Add sensitive-domain guardrails.
5. Add experimental TUN wrapper.
6. Extract transport interfaces after route decisions are tested.

This order reduces risk because it makes the current behavior visible and testable before replacing internals.
