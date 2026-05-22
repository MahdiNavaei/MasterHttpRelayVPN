import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from core.config_validation import validate_config


def codes(report):
    return {issue.code for issue in report.issues}


class ConfigValidationTests(unittest.TestCase):
    def test_detects_missing_auth_and_script_id(self):
        report = validate_config({"auth_key": "", "script_id": ""})

        self.assertTrue(report.has_errors)
        self.assertIn("auth_key_missing_or_placeholder", codes(report))
        self.assertIn("script_id_missing_or_placeholder", codes(report))

    def test_accepts_non_empty_script_ids_list(self):
        report = validate_config({
            "auth_key": "strong-secret-value",
            "script_ids": ["AKfycb1234567890"],
            "http_port": 8085,
            "socks5_port": 1080,
        })

        self.assertNotIn("script_id_missing_or_placeholder", codes(report))
        self.assertNotIn("script_ids_empty", codes(report))

    def test_warns_for_lan_and_port_conflict(self):
        report = validate_config({
            "auth_key": "strong-secret-value",
            "script_id": "AKfycb1234567890",
            "listen_host": "0.0.0.0",
            "lan_sharing": True,
            "http_port": 1080,
            "socks5_port": 1080,
        })

        found = codes(report)
        self.assertIn("lan_sharing_enabled", found)
        self.assertIn("http_proxy_listens_all_interfaces", found)
        self.assertIn("proxy_ports_conflict", found)

    def test_warns_for_exit_node_missing_psk_and_url(self):
        report = validate_config({
            "auth_key": "strong-secret-value",
            "script_id": "AKfycb1234567890",
            "exit_node": {"enabled": True, "psk": "CHANGE_ME_TO_A_STRONG_SECRET"},
        })

        found = codes(report)
        self.assertIn("exit_node_url_missing", found)
        self.assertIn("exit_node_psk_missing_or_placeholder", found)

    def test_warns_when_ca_files_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert = pathlib.Path(tmp) / "ca.crt"
            key = pathlib.Path(tmp) / "ca.key"
            cert.write_text("cert", encoding="utf-8")
            key.write_text("key", encoding="utf-8")

            report = validate_config(
                {
                    "auth_key": "strong-secret-value",
                    "script_id": "AKfycb1234567890",
                },
                ca_cert_file=str(cert),
                ca_key_file=str(key),
            )

        found = codes(report)
        self.assertIn("mitm_ca_cert_exists", found)
        self.assertIn("mitm_ca_private_key_exists", found)

    def test_warns_for_invalid_routing_section(self):
        report = validate_config({
            "auth_key": "strong-secret-value",
            "script_id": "AKfycb1234567890",
            "routing": {
                "default_action": "teleport",
                "direct_domains": "example.com",
                "observe_only": False,
                "domestic_direct": {"enabled": True, "suffixes": ".ir"},
            },
        })

        found = codes(report)
        self.assertIn("routing_default_action_invalid", found)
        self.assertIn("routing_direct_domains_invalid", found)
        self.assertIn("routing_enforcement_not_implemented", found)
        self.assertIn("routing_domestic_direct_suffixes_invalid", found)


if __name__ == "__main__":
    unittest.main()
