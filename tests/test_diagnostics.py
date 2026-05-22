import pathlib
import sys
import unittest
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
    _check_apps_script,
    _check_exit_node,
    _check_google_front,
)


VALID_CONFIG = {
    "auth_key": "strong-secret-value",
    "script_id": "AKfycb1234567890",
    "listen_host": "127.0.0.1",
    "http_port": 18085,
    "socks5_port": 11080,
}


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
        self.assertIn("auth was rejected", result.message)
        tls_sock.sendall.assert_called_once()

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
