import tempfile
import unittest
from pathlib import Path

from vpskitlib.config import Client, NodeConfig, load_nodes, write_nodes_template
from vpskitlib.util import VpskitError


class ConfigTest(unittest.TestCase):
    def test_template_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "nodes.yaml"
            write_nodes_template(path, "n1", "203.0.113.9")
            cfg = load_nodes(path)
            self.assertEqual(list(cfg.nodes), ["n1"])
            self.assertEqual(cfg.nodes["n1"].host, "203.0.113.9")
            self.assertEqual(cfg.nodes["n1"].clients[0].email, "main")

    def test_duplicate_port(self):
        node = NodeConfig(id="n1", host="1.2.3.4", clients=[Client("main")], sub_port=19000)
        self.assertTrue(any("端口冲突" in e for e in node.validate()))

    def test_bad_cidr(self):
        node = NodeConfig(id="n1", host="1.2.3.4", clients=[Client("main")], admin_ips=["999.1.1.1"])
        with self.assertRaises(VpskitError):
            node.check_ips()

    def test_bad_id(self):
        node = NodeConfig(id="Bad ID", host="1.2.3.4", clients=[Client("main")])
        self.assertTrue(any("节点 id" in e for e in node.validate()))

    def test_unknown_key_warns(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "nodes.yaml"
            path.write_text(
                "nodes:\n  n1:\n    host: 1.2.3.4\n    clients:\n      - email: main\n    typo_key: 1\n",
                encoding="utf-8",
            )
            cfg = load_nodes(path)
            self.assertTrue(any("typo_key" in w for w in cfg.nodes["n1"].warnings))

    def test_secret_in_nodes_is_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "nodes.yaml"
            path.write_text(
                "nodes:\n  n1:\n    host: 1.2.3.4\n    clients:\n      - email: main\n    uuid: should-not-be-here\n",
                encoding="utf-8",
            )
            cfg = load_nodes(path)
            self.assertFalse(hasattr(cfg.nodes["n1"], "uuid"))


if __name__ == "__main__":
    unittest.main()
