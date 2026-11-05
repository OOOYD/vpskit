import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class UnattrTest(unittest.TestCase):
    def test_split_realities_and_ss(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            (base / "hourly").mkdir()
            now = time.time()
            payload = {
                "hour": "20261105-10",
                "ch443": {"1.1.1.1": 1_000_000_000, "2.2.2.2": 2_000_000_000},
                "ch40244": {"3.3.3.3": 3_000_000_000},
            }
            (base / "hourly/usage-20261105-10.json").write_text(json.dumps(payload), encoding="utf-8")
            (base / "authed_ips.json").write_text(json.dumps({"1.1.1.1": now}), encoding="utf-8")
            env = dict(os.environ)
            env["VPSKIT_TRAFFIC_BASE"] = str(base)
            proc = subprocess.run(
                [sys.executable, str(ROOT / "vpskitlib/assets/opt/traffic/unattr.py"), "--write"],
                env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads((base / "unattr.json").read_text())
            self.assertEqual(data["ch443"]["total_gb"], 2.0)
            self.assertEqual(data["ch443"]["level"], "high")
            self.assertEqual(data["ch40244"]["total_gb"], 3.0)
            # SS 不进入 REALITY 未归因
            self.assertEqual([x["ip"] for x in data["ch443"]["top"]], ["2.2.2.2"])


if __name__ == "__main__":
    unittest.main()
