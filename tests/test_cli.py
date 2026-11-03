import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from vpskitlib.config import load_nodes
from vpskitlib.paths import NodePaths
from vpskitlib import secrets as S

ROOT = Path(__file__).resolve().parent.parent
VPSKIT = str(ROOT / "vpskit")


def run(args, root):
    cmd = [sys.executable, VPSKIT, "--root", str(root)] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


class CliTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def test_version(self):
        p = subprocess.run([sys.executable, VPSKIT, "--version"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)
        self.assertIn("vpskit 1.0.0", p.stdout)

    def test_init_list_show(self):
        p = run(["init", "n1", "--host", "203.0.113.9", "--ssh-alias", "n1"], self.root)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue((self.root / "nodes.yaml").exists())
        cfg = load_nodes(self.root / "nodes.yaml")
        self.assertEqual(cfg.nodes["n1"].host, "203.0.113.9")
        p = run(["list", "--json"], self.root)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data[0]["id"], "n1")
        # 生成秘密后才能 show
        node = cfg.nodes["n1"]
        paths = NodePaths(self.root, "n1").ensure()
        S.ensure_secrets(node, paths.secrets)
        p = run(["show", "n1"], self.root)
        self.assertEqual(p.returncode, 0, p.stderr)
        summary = json.loads(p.stdout)
        self.assertIn("reality_public", summary)
        self.assertIn("clients", summary)

    def test_rotate_requires_secrets(self):
        p = run(["init", "n1", "--host", "203.0.113.9"], self.root)
        self.assertEqual(p.returncode, 0)
        p = run(["rotate", "n1", "--all", "--yes"], self.root)
        self.assertNotEqual(p.returncode, 0)


if __name__ == "__main__":
    unittest.main()
