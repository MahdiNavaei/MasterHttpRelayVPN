import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from core.redaction import redact_dict, redact_text, redact_url, redact_value


class RedactionTests(unittest.TestCase):
    def test_redact_value_preserves_prefix_and_suffix(self):
        self.assertEqual(redact_value("abcd1234efgh5678"), "abcd...5678")
        self.assertEqual(redact_value("short"), "***")

    def test_redact_dict_handles_known_secret_keys_and_nested_psk(self):
        data = {
            "auth_key": "abcd1234efgh5678",
            "script_ids": ["AKfycb1234567890"],
            "exit_node": {"psk": "secret1234567890", "url": "https://example.com"},
        }

        redacted = redact_dict(data)

        self.assertEqual(redacted["auth_key"], "abcd...5678")
        self.assertEqual(redacted["script_ids"], ["AKfy...7890"])
        self.assertEqual(redacted["exit_node"]["psk"], "secr...7890")
        self.assertEqual(redacted["exit_node"]["url"], "https://example.com")

    def test_redact_credentialed_urls(self):
        self.assertEqual(
            redact_url("https://user:password@example.com/path"),
            "https://***:***@example.com/path",
        )
        self.assertEqual(
            redact_text("fetch https://user:password@example.com/path"),
            "fetch https://***:***@example.com/path",
        )

    def test_redact_bearer_and_assignment_values(self):
        text = "Authorization: Bearer abcdefgh12345678 auth_key=supersecretvalue"
        redacted = redact_text(text)

        self.assertNotIn("abcdefgh12345678", redacted)
        self.assertNotIn("supersecretvalue", redacted)
        self.assertIn("Bearer abcd...5678", redacted)


if __name__ == "__main__":
    unittest.main()
