import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class GuardTest(unittest.TestCase):
    def test_flush_before_load(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            fak = d / "bin"
            fak.mkdir()
            log = d / "nft.log"
            for name in ("nft", "systemctl", "logger"):
                p = fak / name
                p.write_text("#!/bin/bash\necho \"%s $*\" >> \"$NFT_LOG\"\n" % name)
                p.chmod(0o755)
            bak = d / "backup"
            bak.mkdir()
            (bak / "nft.ruleset").write_text("table ip filter { }\n")
            env = dict(os.environ)
            env["PATH"] = str(fak) + ":" + env.get("PATH", "")
            env["NFT_LOG"] = str(log)
            env["VPSKIT_GUARD_LOG"] = str(d / "guard.log")
            env["VPSKIT_GUARD_MARKER"] = str(d / "marker")
            proc = subprocess.run(
                ["bash", str(ROOT / "vpskitlib/remote_scripts/firewall-guard.sh"), str(bak), "0"],
                env=env, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            lines = [x.strip() for x in log.read_text().splitlines() if x.strip()]
            self.assertTrue(any(x.startswith("nft flush ruleset") for x in lines), lines)
            self.assertTrue(any(x.startswith("nft -f") for x in lines), lines)
            self.assertLess(
                next(i for i, x in enumerate(lines) if x.startswith("nft flush ruleset")),
                next(i for i, x in enumerate(lines) if x.startswith("nft -f")),
            )


if __name__ == "__main__":
    unittest.main()
