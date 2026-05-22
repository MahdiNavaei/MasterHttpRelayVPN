import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from core.domain_matcher import (
    host_matches_pattern,
    is_ip_literal,
    is_localhost,
    is_private_or_local_ip,
    match_host,
    normalize_host,
)


class DomainMatcherTests(unittest.TestCase):
    def test_normalize_host_handles_case_ports_urls_and_ipv6(self):
        self.assertEqual(normalize_host("Example.COM."), "example.com")
        self.assertEqual(normalize_host("example.com:443"), "example.com")
        self.assertEqual(normalize_host("https://User:Pass@Example.com:443/a"), "example.com")
        self.assertEqual(normalize_host("[::1]:443"), "::1")

    def test_exact_does_not_match_suffix_or_prefix(self):
        self.assertTrue(host_matches_pattern("example.com", "example.com"))
        self.assertFalse(host_matches_pattern("api.example.com", "example.com"))
        self.assertFalse(host_matches_pattern("badexample.com", "example.com"))

    def test_leading_dot_matches_subdomain_not_bare_domain(self):
        self.assertTrue(host_matches_pattern("api.example.com", ".example.com"))
        self.assertFalse(host_matches_pattern("example.com", ".example.com"))

    def test_wildcard_pattern_matches_subdomain_not_bare_domain(self):
        self.assertTrue(host_matches_pattern("api.example.com", "*.example.com"))
        self.assertFalse(host_matches_pattern("example.com", "*.example.com"))

    def test_match_host_returns_original_rule(self):
        self.assertEqual(match_host("api.example.com", ["example.com", ".example.com"]), ".example.com")
        self.assertIsNone(match_host("other.example.net", ["example.com"]))

    def test_ip_local_private_detection(self):
        self.assertTrue(is_ip_literal("127.0.0.1"))
        self.assertTrue(is_ip_literal("[2001:db8::1]:443"))
        self.assertTrue(is_localhost("localhost"))
        self.assertTrue(is_private_or_local_ip("192.168.1.10"))
        self.assertTrue(is_private_or_local_ip("169.254.1.1"))
        self.assertTrue(is_private_or_local_ip("fc00::1"))
        self.assertFalse(is_private_or_local_ip("8.8.8.8"))
        self.assertFalse(is_private_or_local_ip("example.com"))


if __name__ == "__main__":
    unittest.main()
