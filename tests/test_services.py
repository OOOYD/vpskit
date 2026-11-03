import py_compile
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ServicesTest(unittest.TestCase):
    def test_python_compiles(self):
        for path in list((ROOT / "vpskitlib/assets/opt").rglob("*.py")) + list((ROOT / "vpskitlib").rglob("*.py")):
            py_compile.compile(str(path), doraise=True)

    def test_shell_syntax(self):
        for path in list((ROOT / "vpskitlib/assets/opt").rglob("*.sh")) + [ROOT / "vpskitlib/assets/opt/ops/ops", ROOT / "install.sh"]:
            proc = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, "%s: %s" % (path, proc.stderr))

    def test_unit_hardening(self):
        web = (ROOT / "vpskitlib/assets/units/traffic-web.service").read_text()
        sub = (ROOT / "vpskitlib/assets/units/sub.service").read_text()
        xray = (ROOT / "vpskitlib/assets/units/xray.service").read_text()
        self.assertIn("User=www-data", web)
        self.assertIn("NoNewPrivileges=true", web)
        self.assertIn("User=www-data", sub)
        self.assertIn("User=nobody", xray)
        self.assertIn("ProtectSystem=strict", web)

    def test_no_production_hardcodes(self):
        for path in list((ROOT / "vpskitlib/assets/opt").rglob("*.py")) + list((ROOT / "vpskitlib/assets/opt").rglob("*.sh")) + [
            ROOT / "vpskitlib/assets/opt/ops/ops"
        ]:
            text = path.read_text(encoding="utf-8", errors="replace")
            self.assertNotIn("103.201.130", text, str(path))
            self.assertNotIn("1031894364@qq.com", text, str(path))

    def test_no_legacy_templates_in_worktree(self):
        # 旧 host 模板（含 live 秘密）已移到 gitignored 的 legacy/，不能再出现在交付树里。
        self.assertFalse((ROOT / "templates").exists())
        self.assertTrue((ROOT / "scripts" / "check-secrets.py").exists())


if __name__ == "__main__":
    unittest.main()
