import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from core.policy import PolicyRouter


class PolicyRouterTests(unittest.TestCase):
    def test_defaults_to_observe_only_relay(self):
        decision = PolicyRouter({}).decide(host="github.com", port=443)

        self.assertEqual(decision.action, "relay")
        self.assertEqual(decision.transport, "apps_script")
        self.assertEqual(decision.reason, "default_relay")
        self.assertFalse(decision.enforce)

    def test_block_hosts_recommend_block(self):
        decision = PolicyRouter({"block_hosts": [".ads.example.com"]}).decide(
            host="cdn.ads.example.com",
            port=443,
        )

        self.assertEqual(decision.action, "block")
        self.assertEqual(decision.transport, "none")
        self.assertEqual(decision.matched_rule, ".ads.example.com")
        self.assertFalse(decision.enforce)

    def test_private_ip_recommends_direct_without_mitm(self):
        decision = PolicyRouter({}).decide(host="192.168.1.5", port=443)

        self.assertEqual(decision.action, "direct")
        self.assertEqual(decision.transport, "direct")
        self.assertEqual(decision.reason, "private_or_local_ip")
        self.assertFalse(decision.mitm_allowed)

    def test_sensitive_domain_recommends_direct_no_mitm(self):
        config = {
            "routing": {
                "sensitive_domains": ["bank.example", ".pay.example"],
                "no_mitm_sensitive": True,
            }
        }

        decision = PolicyRouter(config).decide(host="login.pay.example", port=443)

        self.assertEqual(decision.action, "sensitive")
        self.assertEqual(decision.transport, "direct")
        self.assertEqual(decision.reason, "sensitive_domain")
        self.assertFalse(decision.mitm_allowed)

    def test_legacy_direct_and_bypass_recommend_direct(self):
        direct = PolicyRouter({"direct_hosts": ["direct.example"]}).decide(
            host="direct.example",
            port=443,
        )
        bypass = PolicyRouter({"bypass_hosts": [".local.example"]}).decide(
            host="api.local.example",
            port=443,
        )

        self.assertEqual(direct.reason, "direct_hosts")
        self.assertEqual(bypass.reason, "bypass_hosts")
        self.assertEqual(direct.action, "direct")
        self.assertEqual(bypass.action, "direct")

    def test_routing_relay_and_domestic_direct_rules(self):
        config = {
            "routing": {
                "relay_domains": [".relay.example"],
                "domestic_direct": {"enabled": True, "suffixes": [".ir"]},
            }
        }

        relay = PolicyRouter(config).decide(host="api.relay.example", port=443)
        domestic = PolicyRouter(config).decide(host="example.ir", port=443)

        self.assertEqual(relay.action, "relay")
        self.assertEqual(relay.reason, "routing.relay_domains")
        self.assertEqual(domestic.action, "direct")
        self.assertEqual(domestic.reason, "routing.domestic_direct")

    def test_exit_node_selective_and_full_recommend_exit_transport(self):
        selective = PolicyRouter({
            "exit_node": {
                "enabled": True,
                "mode": "selective",
                "hosts": [".openai.com"],
            }
        }).decide(host="chat.openai.com", port=443)
        full = PolicyRouter({
            "exit_node": {"enabled": True, "mode": "full"}
        }).decide(host="github.com", port=443)

        self.assertEqual(selective.transport, "exit_node")
        self.assertEqual(selective.reason, "exit_node.hosts")
        self.assertEqual(full.transport, "exit_node")
        self.assertEqual(full.reason, "exit_node.full")


if __name__ == "__main__":
    unittest.main()
