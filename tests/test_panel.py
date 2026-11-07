import json
import unittest

from vpskitlib import panel


SAMPLE = [
    {
        "node_id": "n1",
        "title": "节点A",
        "host": "203.0.113.10",
        "online": True,
        "error": "",
        "traffic": {
            "cap_gb": 500,
            "cycle_gb": 10,
            "today_gb": 1,
            "remaining_gb": 490,
            "days": [{"label": "11/1", "gb": 1}],
            "alerts": [{"txt": "x", "sev": 1}],
            "ips": [{"ip": "1.2.3.4", "name": "home", "gb": 1, "pct": 10}],
        },
        "services": {"xray": {"active": "active"}},
    }
]


class PanelTest(unittest.TestCase):
    def test_share_masks(self):
        data = panel._share_data(SAMPLE)
        self.assertEqual(data[0]["host"], "")
        self.assertNotIn("ips", data[0]["traffic"])
        self.assertEqual(data[0]["traffic"]["cycle_gb"], 10)

    def test_share_keeps_layout_fields(self):
        sample = dict(SAMPLE[0])
        sample["traffic"] = dict(SAMPLE[0]["traffic"], avg_gb=8.1, projected_gb=240, cycle_start="2026-10-29")
        sample["kernel"] = "6.12.0-test"
        data = panel._share_data([sample])[0]
        self.assertEqual(data["traffic"]["avg_gb"], 8.1)
        self.assertEqual(data["traffic"]["cycle_start"], "2026-10-29")
        self.assertEqual(data["kernel"], "6.12.0-test")

    def test_share_hides_addresses_and_ports(self):
        sample = dict(SAMPLE[0])
        sample["network"] = {"ipv4": ["203.0.113.10"], "ipv6": ["2001:db8:1::5"], "has_v4": True, "has_v6": True}
        sample["node_clients"] = [{"email": "main", "flow": "xtls-rprx-vision"}]
        sample["ports_cfg"] = {"ssh": 22, "reality": 443, "sub": 8888}
        sample["changes"] = [{"time": "2026-01-01 10:00:00", "title": "/root/.vpskit/backups/x"}]
        data = panel._share_data([sample])[0]
        self.assertEqual(data["network"]["ipv4"], ["203.0.*.*"])
        self.assertNotIn("db8:1::5", data["network"]["ipv6"][0])
        self.assertEqual(data["ports_cfg"], {})
        self.assertEqual(data["node_clients"], [])
        self.assertEqual(data["changes"], [])

    def test_page_placeholders(self):
        class State:
            def get(self):
                return SAMPLE

        class P:
            refresh_seconds = 30
            title = "面板 <x>"

        html = panel._page(State(), P(), share=False, api="/api/status?token=abc", title=P.title).decode()
        self.assertIn('const API = "/api/status?token=abc";', html)
        self.assertNotIn("__DATA__", html)
        self.assertNotIn("__API__", html)
        self.assertIn("面板 &lt;x&gt;", html)

    def test_clean_node_payload_ok(self):
        data = panel._clean_node_payload(
            {
                "id": "node2",
                "host": "203.0.113.10",
                "title": "测试",
                "ssh_port": "2222",
                "quota_gb": "300",
                "billing_cycle": "yearly",
                "purchased_on": "2026-01-01",
                "client": "main",
            }
        )
        self.assertEqual(data["__id__"], "node2")
        self.assertEqual(data["ssh_port"], 2222)
        self.assertEqual(data["quota_gb"], 300)
        self.assertNotIn("clients", data)  # 默认 main 不写进配置

    def test_clean_node_payload_rejects(self):
        bad = [
            {"host": "1.2.3.4"},
            {"id": "Bad Id", "host": "1.2.3.4"},
            {"id": "ok", "host": ""},
            {"id": "ok", "host": "1.2.3.4", "billing_cycle": "weekly"},
            {"id": "ok", "host": "1.2.3.4", "purchased_on": "2026/01/01"},
            {"id": "ok", "host": "1.2.3.4", "quota_gb": 0},
            {"id": "ok", "host": "1.2.3.4", "ssh_port": 70000},
        ]
        for payload in bad:
            with self.assertRaises(Exception):
                panel._clean_node_payload(payload)

    def test_insert_under_nodes_keeps_rest(self):
        text = (
            "version: 1\n"
            "defaults:\n"
            "  quota_gb: 500\n"
            "nodes:\n"
            "  a:\n"
            "    host: 203.0.113.1\n"
            "\n"
            "panel:\n"
            "  port: 8787\n"
        )
        block = ["  b:", "    host: 203.0.113.2"]
        out = panel._insert_under_nodes(text, block)
        import yaml

        parsed = yaml.safe_load(out)
        self.assertEqual(sorted(parsed["nodes"]), ["a", "b"])
        self.assertEqual(parsed["nodes"]["b"]["host"], "203.0.113.2")
        self.assertEqual(parsed["panel"]["port"], 8787)

    def test_insert_under_nodes_requires_block(self):
        with self.assertRaises(Exception):
            panel._insert_under_nodes("version: 1\n", ["  b:", "    host: x"])


class PanelConfigTest(unittest.TestCase):
    def test_panel_defaults_are_local_only(self):
        from vpskitlib.config import PanelConfig

        cfg = PanelConfig()
        self.assertEqual(cfg.listen, "127.0.0.1")
        self.assertEqual(cfg.allow_hosts, [])
        self.assertTrue(cfg.allow_write)


if __name__ == "__main__":
    unittest.main()
