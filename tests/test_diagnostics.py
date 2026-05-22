import pathlib
import sys
import unittest
import gzip
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from core.diagnostics import (
    DiagnosticResult,
    build_policy_checks,
    format_doctor_report,
    parse_policy_target,
    run_doctor,
    _classify_apps_script_probe,
    _check_apps_script,
    _check_exit_node,
    _check_google_front,
    _read_http_response_sync,
)


VALID_CONFIG = {
    "auth_key": "strong-secret-value",
    "script_id": "AKfycb1234567890",
    "listen_host": "127.0.0.1",
    "http_port": 18085,
    "socks5_port": 11080,
}


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, _size):
        if not self.chunks:
            return b""
        return self.chunks.pop(0)


class DiagnosticsTests(unittest.TestCase):
    def test_run_doctor_skips_network_when_disabled(self):
        report = run_doctor(
            dict(VALID_CONFIG),
            ca_cert_file=None,
            ca_key_file=None,
            network_checks=False,
        )

        by_name = {result.name: result for result in report.results}
        self.assertEqual(by_name["GOOGLE FRONT"].status, "skip")
        self.assertEqual(by_name["EXIT NODE"].status, "skip")
        self.assertEqual(by_name["APPS SCRIPT"].status, "skip")

    def test_run_doctor_reports_port_conflict(self):
        config = dict(VALID_CONFIG)
        config["socks5_port"] = config["http_port"]

        report = run_doctor(config, network_checks=False)

        self.assertTrue(report.has_failures)
        self.assertIn("PORT CONFLICT", {result.name for result in report.results})

    def test_format_redacts_secret_like_values(self):
        report = format_doctor_report(
            type("Report", (), {
                "results": (
                    DiagnosticResult(
                        "CONFIG",
                        "warn",
                        "auth_key=supersecretvalue Authorization: Bearer abcdefgh12345678",
                    ),
                )
            })()
        )

        self.assertNotIn("supersecretvalue", report)
        self.assertNotIn("abcdefgh12345678", report)

    @mock.patch("core.diagnostics.urllib.request.urlopen")
    def test_exit_node_health_uses_get_and_reports_pass(self, urlopen):
        response = mock.MagicMock()
        response.__enter__.return_value.status = 200
        urlopen.return_value = response

        result = _check_exit_node(
            {"exit_node": {"enabled": True, "url": "https://user:pass@example.com"}},
            timeout=1,
        )

        self.assertEqual(result.status, "pass")
        self.assertIn("https://***:***@example.com", result.message)

    @mock.patch("core.diagnostics.ssl.create_default_context")
    @mock.patch("core.diagnostics.socket.create_connection")
    def test_google_front_uses_timeout_bound_socket_probe(self, create_connection, create_context):
        raw_sock = mock.MagicMock()
        tls_sock = mock.MagicMock()
        create_connection.return_value = raw_sock
        create_context.return_value.wrap_socket.return_value = tls_sock

        result = _check_google_front(VALID_CONFIG, timeout=1)

        self.assertEqual(result.status, "pass")
        create_connection.assert_called_once()
        create_context.return_value.wrap_socket.assert_called_once_with(
            raw_sock,
            server_hostname="www.google.com",
        )

    @mock.patch("core.diagnostics.ssl.create_default_context")
    @mock.patch("core.diagnostics.socket.create_connection")
    def test_apps_script_probe_reports_auth_rejection(self, create_connection, create_context):
        raw_sock = mock.MagicMock()
        tls_sock = mock.MagicMock()
        tls_sock.recv.side_effect = [
            b"HTTP/1.1 200 OK\r\n\r\n{\"e\":\"unauthorized\"}",
            b"",
        ]
        create_connection.return_value = raw_sock
        create_context.return_value.wrap_socket.return_value = tls_sock

        result = _check_apps_script(VALID_CONFIG, timeout=1)

        self.assertEqual(result.status, "fail")
        self.assertIn("auth rejected", result.message)
        tls_sock.sendall.assert_called_once()
        self.assertIn(b"http://example.com/", tls_sock.sendall.call_args.args[0])

    def test_apps_script_probe_classifies_valid_relay_success_json(self):
        body = b'{"s":200,"h":{"Content-Type":"text/html"},"b":"SGVsbG8="}'

        result = _classify_apps_script_probe(200, {"content-type": "text/html"}, body, 123)

        self.assertEqual(result.status, "pass")
        self.assertIn("Relay/auth envelope valid", result.message)
        self.assertIn("HTTP 200", result.message)

    def test_apps_script_probe_classifies_non_relay_html(self):
        body = b"<!doctype html><html><body>Welcome</body></html>"

        result = _classify_apps_script_probe(200, {"content-type": "text/html"}, body, 123)

        self.assertEqual(result.status, "warn")
        self.assertIn("non-relay HTML", result.message)

    def test_apps_script_probe_classifies_malformed_json(self):
        body = b"{not valid json"

        result = _classify_apps_script_probe(200, {"content-type": "application/json"}, body, 123)

        self.assertEqual(result.status, "warn")
        self.assertIn("unexpected response shape", result.message)

    @mock.patch("core.diagnostics.socket.create_connection", side_effect=TimeoutError("timed out"))
    def test_apps_script_probe_reports_network_timeout(self, _create_connection):
        result = _check_apps_script(VALID_CONFIG, timeout=1)

        self.assertEqual(result.status, "warn")
        self.assertIn("relay probe failed", result.message)
        self.assertIn("timed out", result.detail)

    def test_apps_script_probe_reader_decodes_chunked_gzip_body(self):
        relay_json = b'{"s":200,"h":{},"b":""}'
        compressed = gzip.compress(relay_json)
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Encoding: gzip\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"\r\n"
            + f"{len(compressed):x}\r\n".encode("ascii")
            + compressed
            + b"\r\n0\r\n\r\n"
        )
        sock = FakeSocket([response])

        status, headers, body = _read_http_response_sync(sock, timeout=1, limit=4096)

        self.assertEqual(status, 200)
        self.assertEqual(headers["content-encoding"], "gzip")
        self.assertEqual(body, relay_json)

    def test_parse_policy_target_supports_host_port_url_and_ipv6(self):
        self.assertEqual(parse_policy_target("github.com"), ("github.com", 443, "https"))
        self.assertEqual(parse_policy_target("github.com:8443"), ("github.com", 8443, "connect"))
        self.assertEqual(parse_policy_target("https://github.com/path"), ("github.com", 443, "https"))
        self.assertEqual(parse_policy_target("http://github.com/path"), ("github.com", 80, "http"))
        self.assertEqual(parse_policy_target("[::1]:443"), ("::1", 443, "https"))

    def test_policy_dry_run_format_supports_multiple_hosts(self):
        config = {
            "block_hosts": ["blocked.example"],
            "routing": {
                "default_action": "relay",
                "sensitive_domains": [".payment.example"],
            },
        }
        checks = build_policy_checks(
            config,
            ["blocked.example", "https://login.payment.example/path", "192.168.1.1"],
        )
        output = format_doctor_report(
            type("Report", (), {"results": ()})(),
            policy_checks=checks,
        )

        self.assertIn("Policy Dry Run", output)
        self.assertIn("blocked.example:443", output)
        self.assertIn("login.payment.example:443", output)
        self.assertIn("192.168.1.1:443", output)
        self.assertEqual([check.decision.enforce for check in checks], [False, False, False])
        self.assertEqual(checks[0].decision.action, "block")
        self.assertEqual(checks[1].decision.action, "sensitive")
        self.assertEqual(checks[2].decision.reason, "private_or_local_ip")


if __name__ == "__main__":
    unittest.main()
