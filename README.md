# MasterHttpRelayVPN - Resilient Diagnostics Fork

> Experimental resilient HTTP/SOCKS5 relay proxy using Google Apps Script, with connectivity diagnostics, policy dry-run routing, observe-only route logging, and MITM TLS support.

This repository is a fork of [masterking32/MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN).

The original project provides the core Google Apps Script relay, local HTTP/SOCKS5 proxy, MITM TLS flow, batching, HTTP/2 relay transport, Google fronting logic, and optional exit-node support.

This fork focuses on improving usability, diagnostics, policy visibility, and future extensibility for restricted or unstable network environments.

---

## What This Fork Adds

This fork adds a diagnostics and routing-visibility layer on top of the original proxy:

- `python main.py doctor` for read-only connectivity and setup diagnostics.
- `python main.py status` as a diagnostics alias.
- `python main.py doctor --check-host <host>` for policy dry-run checks.
- Observe-only runtime route logging through a dedicated policy router.
- Config validation and secret redaction for safer troubleshooting.
- Public planning docs for a more resilient tunnel architecture.
- A roadmap toward policy-based routing, multi-transport support, and future full-system tunnel mode.

These features are intentionally conservative. They help users understand what is happening without changing the existing proxy traffic behavior.

---

## What It Does

MasterHttpRelayVPN runs a local HTTP/SOCKS5 proxy and relays browser or application traffic through a user-deployed Google Apps Script Web App.

Typical flow:

```text
Browser / App
  -> Local HTTP/SOCKS5 proxy
  -> Google-facing relay path
  -> Apps Script Web App
  -> Target website
```

The project can also use optional exit nodes for destinations that reject Google egress traffic.

This is not a traditional full-device VPN. It is a local proxy and relay-based tunneling tool.

---

## Diagnostics And Policy Dry Run

### Doctor Command

Run:

```bash
python main.py doctor
```

The doctor command checks the most common setup and connectivity problems:

- `config.json` presence and required fields.
- `auth_key` / Apps Script deployment configuration.
- HTTP proxy bind readiness.
- SOCKS5 proxy bind readiness.
- Port conflicts.
- Google front reachability.
- Apps Script relay/auth health.
- Exit node health when configured.
- MITM CA state.
- Safety notes.

It does not start the proxy, install certificates, modify routes, or change runtime behavior.

See:

- [Doctor Command](docs/DOCTOR_COMMAND.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

### Policy Dry Run

Run:

```bash
python main.py doctor --check-host github.com
python main.py doctor --check-host youtube.com --check-host example.ir
python main.py status --check-host https://github.com
```

This prints observe-only policy recommendations for each host.

Example:

```text
Policy Dry Run
github.com:443   relay   apps_script  default_relay        matched=-  mitm_allowed=true   enforce=false
example.ir:443   direct  direct       routing.domestic_direct  matched=.ir  mitm_allowed=false  enforce=false
192.168.1.1:443  direct  direct       private_or_local_ip  matched=-  mitm_allowed=false  enforce=false
```

Policy dry-run does not connect to the target website. It only shows what the policy router would recommend.

Runtime policy logging is currently observe-only. It does not change routing behavior.

See:

- [Policy Routing](docs/POLICY_ROUTING.md)

---

## Managed Browser Mode

Launch an isolated browser profile through the local proxy without changing system proxy settings:

```bash
python main.py browser --url https://example.com/
```

Browser mode starts the local proxy, waits for the HTTP/SOCKS listeners, launches Chrome, Edge, or Chromium with `--proxy-server=http://127.0.0.1:<http_port>`, and stops the proxy when the browser exits. It avoids using your normal browser profile by default and does not enforce observe-only policy decisions.

See:

- [Managed Browser Mode](docs/BROWSER_MODE.md)

---

## Runtime Validation

This fork was smoke-tested locally with a real browser profile through the proxy:

- `https://example.com/` loaded successfully.
- `https://www.youtube.com/` loaded successfully.
- `ROUTE OBSERVE` logs appeared at runtime.
- Apps Script relay activity was observed in proxy logs.

Results can vary by network, Google Apps Script quota, deployment settings, certificate trust, browser behavior, and local configuration.

This validation does not mean YouTube or any specific service is guaranteed to work for every user or network.

---

## Quick Start

### 1. Clone This Fork

```bash
git clone https://github.com/MahdiNavaei/MasterHttpRelayVPN.git
cd MasterHttpRelayVPN
git checkout python_testing
```

### 2. Install Requirements

```bash
pip install -r requirements.txt
```

Or use the launcher.

Windows:

```cmd
start.bat
```

Linux / macOS:

```bash
chmod +x start.sh
./start.sh
```

### 3. Deploy The Apps Script Relay

1. Open [Google Apps Script](https://script.google.com/).
2. Create a new project.
3. Copy the content of [apps_script/Code.gs](apps_script/Code.gs).
4. Paste it into the Apps Script editor.
5. Set a long random `AUTH_KEY`.
6. Deploy as a Web App.
7. Set **Execute as** to **Me**.
8. Set **Who has access** to **Anyone**.
9. Copy the Web App Deployment ID.

### 4. Configure The Local Proxy

Copy the example config:

```bash
cp config.example.json config.json
```

Edit:

```json
{
  "script_id": "YOUR_APPS_SCRIPT_DEPLOYMENT_ID",
  "auth_key": "THE_SAME_SECRET_AS_CODE_GS"
}
```

The `auth_key` in `config.json` must match `AUTH_KEY` inside Apps Script.

### 5. Run Diagnostics

Before starting the proxy, run:

```bash
python main.py doctor
```

Optional host policy dry-run:

```bash
python main.py doctor --check-host github.com --check-host youtube.com --check-host 192.168.1.1
```

### 6. Start The Proxy

```bash
python main.py
```

Default local ports:

| Proxy | Address |
|---|---|
| HTTP | `127.0.0.1:8085` |
| SOCKS5 | `127.0.0.1:1080` |

For browsers, the HTTP proxy is usually the best option.

---

## Browser Setup

Configure your browser to use:

```text
HTTP proxy: 127.0.0.1
Port: 8085
```

For HTTPS browsing, this project uses local MITM TLS interception. The generated CA certificate must be trusted by your browser or operating system.

The CA certificate is created under:

```text
ca/ca.crt
```

You can try automatic certificate installation:

```bash
python main.py --install-cert
```

To remove it:

```bash
python main.py --uninstall-cert
```

Never share the `ca/` folder or `ca/ca.key`.

See:

- [Getting Started](docs/GETTING_STARTED.md)
- [Security Notes](docs/SECURITY.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

---

## Configuration

Most users only need:

```json
{
  "script_id": "YOUR_DEPLOYMENT_ID",
  "auth_key": "YOUR_SHARED_SECRET",
  "http_port": 8085,
  "socks5_port": 1080
}
```

Advanced configuration supports:

- Multiple Apps Script deployments with `script_ids`.
- Google front domain/IP tuning.
- HTTP/2 relay transport.
- Batching and connection warmup.
- Direct, bypass, and block host rules.
- Optional exit node.
- LAN sharing.
- Adblock lists.
- Observe-only routing policy configuration.

See:

- [Configuration Reference](docs/CONFIGURATION.md)
- [LAN Sharing](docs/LAN_SHARING.md)
- [Docker Guide](docs/DOCKER.md)

---

## Policy Routing Status

Policy routing is currently in observe-only mode.

That means:

```text
PolicyRouter calculates and logs recommendations.
Existing proxy routing code still chooses the real traffic path.
```

This makes route behavior visible and testable before any enforcement is introduced.

Current supported policy concepts include:

- Direct domains.
- Relay domains.
- Block hosts.
- Bypass hosts.
- Sensitive domains.
- Domestic direct suffixes.
- Private/local IP bypass.
- Exit-node host matching.

Future versions may enforce selected low-risk rules after more runtime validation.

See:

- [Policy Routing](docs/POLICY_ROUTING.md)
- [Target Architecture](docs/ARCHITECTURE_TARGET.md)

---

## Roadmap

This fork is moving toward a more resilient, policy-based client-side tunneling framework.

Planned direction:

1. Better setup wizard and local Apps Script generation.
2. More accurate diagnostics and offline/no-network checks.
3. Policy routing validation against real-world configs.
4. Low-risk policy enforcement for private/local and explicit block rules.
5. Transport abstraction around Apps Script, direct, and exit-node paths.
6. Experimental full-system mode through TUN/tun2socks.
7. Future local DNS/policy integration.
8. Future optional Worker/WebSocket or VPS transports.

Non-goals for the current version:

- No full-system VPN claim.
- No TUN/tun2socks implementation yet.
- No guarantee during complete internet shutdowns.
- No guarantee that every website or video platform will work on every network.
- No hidden policy enforcement.

See:

- [PRD: Resilient Tunnel Framework](docs/PRD_RESILIENT_TUNNEL.md)
- [Implementation Plan](docs/IMPLEMENTATION_PLAN.md)
- [Gap Analysis](docs/GAP_ANALYSIS.md)
- [Engineering Recommendations](docs/ENGINEERING_RECOMMENDATIONS.md)

---

## Architecture

Current simplified architecture:

```text
Browser/App
  -> Local HTTP/SOCKS5 Proxy
  -> Google front / Apps Script relay
  -> Target website
```

Target direction:

```text
Browser/App or System Traffic
  -> Local Proxy / Future TUN
  -> Policy Router
  -> Transport Selector
  -> Apps Script / Direct / Exit Node / Future Transports
  -> Target
```

See:

- [Architecture](docs/ARCHITECTURE.md)
- [Target Architecture](docs/ARCHITECTURE_TARGET.md)
- [Project Audit](docs/PROJECT_AUDIT.md)

---

## Security Notes

Protect these files and values:

- `config.json`
- `auth_key`
- Apps Script Deployment ID when paired with a valid `auth_key`
- `ca/ca.key`
- The full `ca/` folder
- Exit-node PSKs

Do not paste real secrets into GitHub issues, screenshots, chats, or public logs.

The `doctor` command redacts common secret fields to make troubleshooting safer, but you should still review output before sharing it publicly.

See:

- [Security Notes](docs/SECURITY.md)

---

## Troubleshooting

Start with:

```bash
python main.py doctor
```

Then check common issues:

- Wrong Apps Script Deployment ID.
- Mismatched `auth_key`.
- Apps Script not deployed as Web App.
- Deployment access not set to `Anyone`.
- Google front timeout.
- Certificate trust errors.
- Proxy port conflicts.
- Apps Script quota exhaustion.
- Outdated `Code.gs` deployment.

See:

- [Troubleshooting](docs/TROUBLESHOOTING.md)

---

## Upstream Credits

This repository is a fork of:

[masterking32/MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN)

Credit to the original author and contributors for the core relay/proxy implementation, including:

- Google Apps Script relay.
- Local HTTP/SOCKS5 proxy.
- MITM TLS flow.
- HTTP/1.1 and HTTP/2 relay transport.
- Batching and warmup logic.
- Google fronting support.
- Optional exit-node support.
- Launcher and setup scripts.

This fork builds on that foundation and focuses on diagnostics, policy visibility, and future resilience improvements.

---

## License

This project follows the license of the upstream repository. See [LICENSE](LICENSE) if present in this repository.
