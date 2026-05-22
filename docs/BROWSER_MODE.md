# Managed Browser Mode

Managed browser mode launches an isolated Chrome, Edge, or Chromium profile that uses the local MasterHttpRelayVPN HTTP proxy. It does not change system proxy settings.

Run:

```bash
python main.py browser
```

Open a specific URL:

```bash
python main.py browser --url https://example.com/
```

Use a temporary profile:

```bash
python main.py browser --temporary-profile
```

## What It Does

- Loads `config.json`.
- Validates required proxy and relay configuration.
- Starts the local HTTP and SOCKS5 proxy listeners for this session.
- Waits until both listeners are reachable.
- Launches a Chromium-family browser with `--proxy-server=http://127.0.0.1:<http_port>`.
- Uses an isolated browser profile instead of the user's normal profile.
- Stops the proxy when the managed browser exits.

## What It Does Not Do

- It does not change system proxy settings.
- It does not use the user's normal browser profile by default.
- It does not enforce observe-only policy routing decisions.
- It does not add TUN/tun2socks or full-system tunneling.
- It does not install or uninstall the MITM CA.

## Browser Selection

By default, browser mode tries to find Chrome, Edge, then Chromium:

```bash
python main.py browser --browser auto
```

You can request a specific browser:

```bash
python main.py browser --browser chrome
python main.py browser --browser edge
python main.py browser --browser chromium
```

If no browser is found, install Chrome, Edge, or Chromium, or manually configure a browser HTTP proxy to `127.0.0.1:<http_port>`.

## Profiles

The default managed profile is:

```text
.mhr-browser-profile
```

Use a different persistent profile:

```bash
python main.py browser --profile .my-test-profile
```

Use a temporary profile that is removed when the browser exits:

```bash
python main.py browser --temporary-profile
```

## Certificate Handling

Browser mode does not ignore certificate errors by default. For normal HTTPS browsing, install the local CA:

```bash
python main.py --install-cert
```

For short tests only, you can ask the managed browser to ignore certificate errors:

```bash
python main.py browser --insecure-ignore-cert-errors
```

This weakens browser TLS validation and should not be used for daily browsing.

## Quota Notes

Managed browser mode is useful when you want only one dedicated browser profile to use the relay. This avoids routing unrelated background apps through the proxy and can reduce noisy failures and Apps Script quota consumption.
