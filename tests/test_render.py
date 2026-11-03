import json
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from vpskitlib import secrets as S
from vpskitlib.config import Client, NodeConfig
from vpskitlib.paths import NodePaths
from vpskitlib.render import RenderOptions, render, write_build
from vpskitlib.workflow import local_validate

ROOT = Path(__file__).resolve().parent.parent


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        self.node = NodeConfig(
            id="test",
            host="203.0.113.10",
            title="测试节点",
            clients=[Client("main", "xtls-rprx-vision"), Client("friend", "")],
            admin_ips=["1.2.3.4", "2001:db8::1"],
            traffic_web_allow_ips=["9.9.9.0/24"],
        )
        self.node.check_ips()
        self.paths = NodePaths(self.root, "test").ensure()
        self.secrets = S.ensure_secrets(self.node, self.paths.secrets)
        self.opts = RenderOptions(
            has_v6=True,
            addresses={"ipv4": "203.0.113.10", "ipv6": "2001:db8::10"},
        )

    def tearDown(self):
        self.td.cleanup()

    def test_render_is_deterministic(self):
        a = render(self.node, self.secrets, self.root, self.opts)
        b = render(self.node, self.secrets, self.root, self.opts)
        self.assertEqual([(f.path, f.content) for f in a.files], [(f.path, f.content) for f in b.files])
        self.assertEqual(local_validate(a), [])

    def test_secrets_are_stable(self):
        before = json.dumps(self.secrets, sort_keys=True)
        again = S.ensure_secrets(self.node, self.paths.secrets)
        self.assertEqual(before, json.dumps(again, sort_keys=True))

    def test_nftables(self):
        r = render(self.node, self.secrets, self.root, self.opts)
        text = next(f for f in r.files if f.path == "/etc/nftables.conf").content.decode()
        self.assertIn("table ip filter", text)
        self.assertIn("table ip6 filter", text)
        self.assertIn("type ipv4_addr", text)
        self.assertIn("@admin4", text)
        self.assertIn("@weballow4", text)
        self.assertIn("tcp dport $SSH_PORT", text)
        self.assertIn("define SSH_PORT = 22", text)
        self.assertIn("define SS_PORT", text)

    def test_no_v6(self):
        r = render(self.node, self.secrets, self.root, RenderOptions(has_v6=False, addresses={"ipv4": "203.0.113.10"}))
        paths = {f.path for f in r.files}
        self.assertNotIn("/etc/shadowsocks-libev/config.json", paths)
        nft = next(f for f in r.files if f.path == "/etc/nftables.conf").content.decode()
        self.assertNotIn("table ip6 filter", nft)

    def test_xray_and_subscription(self):
        r = render(self.node, self.secrets, self.root, self.opts)
        xray = json.loads(next(f for f in r.files if f.path == "/usr/local/etc/xray/config.json").content)
        rs = xray["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(rs["privateKey"], self.secrets["reality"]["private_key"])
        self.assertEqual(len(rs["shortIds"][0]), 16)
        self.assertEqual(len(xray["inbounds"][0]["settings"]["clients"]), 2)
        subs = [f for f in r.files if f.path.startswith("/opt/sub/data/")]
        self.assertEqual(len(subs), 2)
        data = yaml.safe_load(subs[0].content)
        self.assertEqual(data["proxies"][0]["reality-opts"]["public-key"], self.secrets["reality"]["public_key"])
        self.assertEqual(len(data["proxies"]), 2)  # vless + ss

    def test_client_paths_differ(self):
        paths = [self.secrets["clients"][e]["sub_path"] for e in ("main", "friend")]
        self.assertNotEqual(paths[0], paths[1])

    def test_shared_subscription_path(self):
        self.secrets["clients"]["friend"]["sub_path"] = self.secrets["clients"]["main"]["sub_path"]
        r = render(self.node, self.secrets, self.root, self.opts)
        subs = [f for f in r.files if f.path.startswith("/opt/sub/data/")]
        self.assertEqual(len(subs), 1)
        data = yaml.safe_load(subs[0].content)
        names = [p["name"] for p in data["proxies"]]
        self.assertIn("测试节点-main", names)
        self.assertIn("测试节点-friend", names)
        kc = next(f for f in r.files if f.path == "/opt/traffic/kitconf.py").content.decode()
        self.assertIn("SUB_ROUTES", kc)

    def test_custom_ssh_port(self):
        self.node.ssh_port = 2222
        r = render(self.node, self.secrets, self.root, self.opts)
        nft = next(f for f in r.files if f.path == "/etc/nftables.conf").content.decode()
        self.assertIn("define SSH_PORT = 2222", nft)
        self.assertIn("dport $SSH_PORT", nft)
        self.assertNotIn("dport 22", nft)
        jail = next(f for f in r.files if f.path == "/etc/fail2ban/jail.local").content.decode()
        self.assertIn("port = 2222", jail)

    def test_build_modes(self):
        r = render(self.node, self.secrets, self.root, self.opts)
        write_build(r, self.paths.build_dir)
        import os
        self.assertEqual(os.stat(self.paths.build_dir / "client-import.md").st_mode & 0o777, 0o600)
        self.assertTrue((self.paths.build_dir / "manifest.json").exists())
        manifest = json.loads((self.paths.build_dir / "manifest.json").read_text())
        self.assertTrue(any(m["path"] == "/etc/nftables.conf" for m in manifest))


if __name__ == "__main__":
    unittest.main()
