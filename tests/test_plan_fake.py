import json
import shutil
import tempfile
import unittest
from pathlib import Path

from vpskitlib import secrets as S
from vpskitlib.config import Client, NodeConfig
from vpskitlib.paths import NodePaths
from vpskitlib.plan import build_plan, plan_json
from vpskitlib.render import RenderOptions, render

ROOT = Path(__file__).resolve().parent.parent


class FakeRemote:
    def __init__(self, info, existing=None):
        self.info = info
        self.existing = existing or {}

    def inspect(self):
        return self.info

    def hash_files(self, paths):
        return {p: self.existing.get(p) for p in paths}

    def upload_bytes(self, data, path, mode=0o600):
        return None

    def run(self, command, **kwargs):
        return ""

    def download_bytes(self, path):
        return b""


INFO = {
    "ok": True,
    "os": {"id": "debian", "version": "12", "pretty": "Debian 12"},
    "arch": "x86_64",
    "is_root": True,
    "user": "root",
    "has_v6": True,
    "ipv4": ["203.0.113.10"],
    "ipv6": ["2001:db8::10"],
    "ssh_source": "",
    "services": {"xray": {"active": "inactive", "enabled": "disabled"}},
    "ports": [],
    "docker": False,
    "docker_active": False,
    "fail2ban_action_nft": True,
    "sshd_config_include": True,
    "authorized_keys": True,
    "xray": [],
}


class PlanFakeTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        self.node = NodeConfig(
            id="test",
            host="203.0.113.10",
            clients=[Client("main", "xtls-rprx-vision")],
            admin_ips=["1.2.3.4"],
        )
        self.node.check_ips()
        self.paths = NodePaths(self.root, "test").ensure()
        self.secrets = S.ensure_secrets(self.node, self.paths.secrets)

    def tearDown(self):
        self.td.cleanup()

    def _hashes(self):
        r = render(
            self.node,
            self.secrets,
            self.root,
            RenderOptions(has_v6=True, addresses={"ipv4": "203.0.113.10", "ipv6": "2001:db8::10"}),
        )
        return {f.path: {"sha256": f.sha256, "size": len(f.content), "mode": f.mode} for f in r.files}

    def test_all_new(self):
        plan = build_plan(self.node, self.root, FakeRemote(INFO), remote_validate=False)
        self.assertTrue(plan.ok)
        self.assertTrue(all(c.status == "new" for c in plan.changes))
        data = plan_json(plan)
        self.assertEqual(data["node"], "test")
        self.assertTrue(data["ok"])

    def test_no_changes(self):
        hashes = self._hashes()
        plan = build_plan(self.node, self.root, FakeRemote(INFO, hashes), remote_validate=False)
        self.assertEqual(plan.changed, [])
        self.assertTrue(plan.ok)

    def test_docker_blocker_and_allow(self):
        info = dict(INFO)
        info["docker_active"] = True
        plan = build_plan(self.node, self.root, FakeRemote(info), remote_validate=False)
        self.assertFalse(plan.ok)
        self.assertTrue(any("Docker" in b for b in plan.blockers))
        plan2 = build_plan(self.node, self.root, FakeRemote(info), remote_validate=False, allow_flush=True)
        self.assertTrue(all("Docker" not in b for b in plan2.blockers))

    def test_missing_nft_is_not_a_blocker(self):
        info = dict(INFO)
        info["nft"] = ""
        plan = build_plan(self.node, self.root, FakeRemote(info), remote_validate=True)
        self.assertEqual(plan.validation.get("nft"), "skipped")
        self.assertTrue(plan.ok)

    def test_non_root_blocker(self):
        info = dict(INFO)
        info["is_root"] = False
        plan = build_plan(self.node, self.root, FakeRemote(info), remote_validate=False)
        self.assertFalse(plan.ok)


if __name__ == "__main__":
    unittest.main()
