import json
import unittest

from vpskitlib import panel


SAMPLE = [
    {
        "node_id": "n1",
        "title": "东京",
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


if __name__ == "__main__":
    unittest.main()
