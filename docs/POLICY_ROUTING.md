# Policy Routing

Policy routing is currently implemented in observe-only mode.

Observe-only means the policy router calculates and logs what it would recommend, but the existing proxy routing branches still decide the actual traffic path. This preserves current runtime behavior while making future split-routing work testable.

## Supported Rule Types

The policy router understands:

- `block_hosts`
- `direct_hosts`
- `bypass_hosts`
- `exit_node.hosts`
- `exit_node.mode`
- optional `routing.direct_domains`
- optional `routing.relay_domains`
- optional `routing.sensitive_domains`
- optional `routing.domestic_direct`
- optional `routing.default_action`
- optional `routing.private_ip_bypass`
- optional `routing.no_mitm_sensitive`

Private/local IP recommendations include loopback, RFC1918, link-local, IPv6 unique-local, and other non-global IP literals recognized by Python's standard `ipaddress` module.

## Host Rule Behavior

Hostnames are normalized before matching:

- lower-case
- trailing dot removed
- `host:port` handled
- bracketed IPv6 such as `[::1]:443` handled
- URL inputs use their hostname

Exact rules match only the exact host:

```text
example.com matches example.com
example.com does not match api.example.com
example.com does not match badexample.com
```

Leading-dot rules match subdomains only:

```text
.example.com matches api.example.com
.example.com does not match example.com
```

Use both `example.com` and `.example.com` if both the bare domain and subdomains should match.

Simple wildcard-like rules such as `*.example.com` are supported and also match subdomains only.

## Example Config

```json
{
  "routing": {
    "default_action": "relay",
    "direct_domains": [
      "example.ir",
      ".example.ir"
    ],
    "relay_domains": [
      ".github.com"
    ],
    "sensitive_domains": [
      "bank.example",
      ".payment.example"
    ],
    "domestic_direct": {
      "enabled": false,
      "suffixes": [".ir"]
    },
    "private_ip_bypass": true,
    "no_mitm_sensitive": true,
    "observe_only": true
  }
}
```

`observe_only` defaults to `true`. Setting it to `false` currently produces a validation warning because runtime enforcement is not implemented yet.

## Route Observe Logs

When a CONNECT or SOCKS5 target enters the existing tunnel routing function, the proxy logs an advisory decision:

```text
ROUTE OBSERVE host=github.com port=443 action=relay transport=apps_script reason=default_relay matched_rule=- mitm_allowed=true enforce=false
ROUTE OBSERVE host=192.168.1.5 port=443 action=direct transport=direct reason=private_or_local_ip matched_rule=- mitm_allowed=false enforce=false
ROUTE OBSERVE host=login.payment.example port=443 action=sensitive transport=direct reason=sensitive_domain matched_rule=.payment.example mitm_allowed=false enforce=false
```

These logs are advisory only. They do not change the actual path selected by the current proxy code.

## Decision Fields

Policy decisions include:

- `action`: `direct`, `relay`, `block`, `sensitive`, or `unknown`
- `transport`: `direct`, `apps_script`, `exit_node`, or `none`
- `reason`: why the rule matched
- `matched_rule`: the matching config rule when applicable
- `mitm_allowed`: whether MITM would be acceptable for this recommendation
- `enforce`: always `false` in the current implementation

## Future Enforcement Plan

Recommended next steps before enforcement:

1. Keep observe-only logs enabled long enough to compare decisions with current behavior.
2. Add route-decision tests for real-world configs.
3. Add metrics or doctor output for invalid routing config.
4. Enforce only low-risk decisions first, such as private/local direct bypass and explicit block rules.
5. Enforce sensitive-domain no-MITM only after documenting expected behavior and failure modes.

Do not use this policy layer as a security boundary until enforcement is explicitly implemented and tested.
