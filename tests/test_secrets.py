import json
import os
import tempfile
import unittest
from pathlib import Path

from vpskitlib import secrets as S
from vpskitlib.config import Client, NodeConfig
from vpskitlib.paths import NodePaths


class SecretsTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        self.node = NodeConfig(
            id="n1",
            host="203.0.113.9",
            clients=[Client("main", "xtls-rprx-vision"), Client("friend", "")],
        )
        self.paths = NodePaths(self.root, "n1").ensure()

    def tearDown(self):
        self.td.cleanup()

    def test_ensure_stable_and_private(self):
        a = S.ensure_secrets(self.node, self.paths.secrets)
        b = S.ensure_secrets(self.node, self.paths.secrets)
        self.assertEqual(a, b)
        if os.name != "nt":
            self.assertEqual(os.stat(self.paths.secrets).st_mode & 0o777, 0o600)
        self.assertEqual(S.client_uuid(a, "main"), S.client_uuid(b, "main"))
        self.assertNotEqual(S.client_sub_path(a, "main"), S.client_sub_path(a, "friend"))

    def test_rotate(self):
        a = S.ensure_secrets(self.node, self.paths.secrets)
        old = json.dumps(a, sort_keys=True)
        changed = S.rotate(self.node, a, ["reality", "ss", "traffic", "uuid", "sub"])
        self.assertTrue(changed)
        self.assertNotEqual(old, json.dumps(a, sort_keys=True))
        S.save_secrets(self.paths.secrets, a)
        b = S.load_secrets(self.paths.secrets)
        self.assertEqual(a, b)

    def test_add_client_keeps_existing(self):
        a = S.ensure_secrets(self.node, self.paths.secrets)
        uuid = S.client_uuid(a, "main")
        self.node.clients.append(Client("new", ""))
        b = S.ensure_secrets(self.node, self.paths.secrets)
        self.assertEqual(uuid, S.client_uuid(b, "main"))
        self.assertTrue(S.client_uuid(b, "new"))

    def test_summary_hides_values(self):
        a = S.ensure_secrets(self.node, self.paths.secrets)
        s = S.summary(self.node, a)
        self.assertNotIn(a["reality"]["private_key"], json.dumps(s))
        self.assertNotIn(a["ss_password"], json.dumps(s))


if __name__ == "__main__":
    unittest.main()
