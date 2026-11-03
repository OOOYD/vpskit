import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ServerRenderTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = Path(self.td.name)
        (d / "kitconf.py").write_text(
            'TITLE="测试 <节点>"\nTRAFFIC_WEB_PORT=19000\nTRAFFIC_WEB_KEY="abc"\n'
            'SUMMARY_PATH="%s/summary.json"\nCHANGELOG_JSONL="%s/changelog.jsonl"\nCAP_GB=500\n'
            % (d, d),
            encoding="utf-8",
        )
        sys.path.insert(0, str(d))
        for name in ("kitconf",):
            sys.modules.pop(name, None)
        spec = importlib.util.spec_from_file_location("traffic_server_test", ROOT / "vpskitlib/assets/opt/traffic/server.py")
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)
        self.d = d

    def tearDown(self):
        sys.path.remove(str(self.d))
        for name in list(sys.modules):
            if name in ("kitconf", "traffic_server_test"):
                sys.modules.pop(name, None)
        self.td.cleanup()

    def test_render_escapes(self):
        data = {
            "updated": "2026-11-03 22:00:00",
            "iface": "eth0",
            "cap_gb": 500,
            "cycle_gb": 43.2,
            "today_gb": 5.1,
            "remaining_gb": 456.8,
            "down_gb": 30,
            "up_gb": 13,
            "avg_gb": 2.1,
            "projected_gb": 268,
            "cycle_start": "2026-10-29",
            "cycle_end": "2026-11-29",
            "days": [{"label": "11/1", "gb": 1.2, "fmt": "1.20", "unit": "GB"}],
            "ips": [
                {"ip": "1.2.3.4", "name": '<script>alert(1)</script>', "gb": 10.2, "pct": 20, "last_seen": "x"}
            ],
            "ip_total": 1,
            "alerts": [{"txt": "测试告警", "sev": 1}],
            "services": {"xray": "active"},
        }
        html = self.mod.render_page(data, [])
        self.assertIn("测试 &lt;节点&gt;", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("测试告警", html)

    def test_empty_summary(self):
        html = self.mod.render_page(None, [])
        self.assertIn("还没有流量摘要", html)

    def test_changes(self):
        (self.d / "changelog.jsonl").write_text(
            json.dumps({"time": "2026-11-03 22:00", "tag": "网络", "level": "重要", "icon": "🟡", "title": "<b>x</b>", "why": "why"}, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        changes = self.mod.load_changes()
        self.assertEqual(len(changes), 1)
        html = self.mod.render_page(
            {"updated": "x", "cap_gb": 1, "cycle_gb": 0, "today_gb": 0, "days": []}, changes
        )
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", html)


if __name__ == "__main__":
    unittest.main()
