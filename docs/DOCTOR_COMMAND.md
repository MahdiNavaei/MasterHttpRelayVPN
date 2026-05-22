# Doctor Command

`doctor` is a read-only setup and connectivity troubleshooting command.

Run:

```bash
python main.py doctor
```

`status` is also accepted as an alias:

```bash
python main.py status
```

Policy dry-run examples:

```bash
python main.py doctor --check-host github.com
python main.py doctor --check-host github.com --check-host example.ir
python main.py status --check-host https://github.com
python main.py doctor --check-host github.com:443 --check-host "[::1]:443"
```

## What It Checks

The command focuses on the checks most useful when the proxy does not work:

- config has an `auth_key`
- config has `script_id` or `script_ids`
- HTTP proxy port can bind
- SOCKS5 proxy port can bind
- HTTP and SOCKS5 ports do not conflict
- configured Google front is reachable
- Apps Script relay endpoint accepts a relay-format probe and rejects/accepts auth clearly
- exit node health if `exit_node.enabled` is true
- MITM CA state, shown as a safety note
- observe-only policy recommendations for hosts passed with `--check-host`

## What It Does Not Change

`doctor` does not:

- start the proxy server
- start SOCKS5 or HTTP long-running listeners
- install or uninstall the MITM CA
- modify `config.json`
- modify routes or system proxy settings
- enable TUN/tun2socks
- change runtime traffic behavior
- test whether a `--check-host` target website is actually reachable

The Apps Script probe sends one small relay-format `GET` request for `http://example.com/` when live network checks are enabled. This is used only to confirm the deployment can parse the relay envelope, authenticate the request, fetch a lightweight target, and return a valid relay response. It may consume one Apps Script execution and uses a bounded timeout so cold or slow deployments do not hang the command.

Apps Script result meanings:

- `PASS`: the endpoint returned a valid relay/auth envelope.
- `FAIL`: auth was rejected, usually because `auth_key` in `config.json` does not match `AUTH_KEY` in `Code.gs`.
- `WARN`: the endpoint returned non-relay HTML, malformed JSON, a deployment/quota error, or the network probe timed out.

If the probe reports non-relay HTML, check that `script_id` is the Web App Deployment ID and that the deployment access is set to `Anyone`.

`--check-host` does not make a remote request to the target host. It only runs the local observe-only policy router and prints what action would be recommended.

## Example Output

```text
MasterHttpRelayVPN doctor

Connectivity & Setup
HTTP BIND     PASS   127.0.0.1:8085 is available.
SOCKS5 BIND   PASS   127.0.0.1:1080 is available.
GOOGLE FRONT  PASS   216.239.38.120:443 reachable with SNI www.google.com in 240ms.
EXIT NODE     SKIP   Exit node disabled.
APPS SCRIPT   PASS   Relay endpoint responded in 930ms.

Safety Notes
NOTE          WARN   Current HTTPS relay behavior relies on local MITM unless a host is routed directly.
MITM CA       WARN   CA certificate exists but is not trusted.

Policy Dry Run
github.com:443  relay   apps_script  default_relay  matched=-   mitm_allowed=true   enforce=false
example.ir:443  direct  direct       routing.domestic_direct  matched=.ir  mitm_allowed=false  enforce=false
```

## Privacy And Security

Doctor output redacts obvious secrets, including:

- `auth_key`
- `script_id`
- `script_ids`
- exit-node `psk`
- credentialed URLs
- bearer-token-like values

Do not share unredacted `config.json`, `ca/ca.key`, Apps Script `AUTH_KEY`, or exit-node PSKs in issue reports.

## Full-System Tunnel Status

Full-system TUN/tun2socks mode is not implemented by this command. The current doctor command only validates the existing local proxy, Apps Script relay, optional exit node, and related setup state.
