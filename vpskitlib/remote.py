"""SSH/SCP 远端层：命令、脚本、上传、备份、部署、防火墙保险丝。"""
from __future__ import annotations

import json
import os
import secrets as pysecrets
import shlex
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .config import NodeConfig
from .util import VpskitError, redact_text, run as run_local, which

SCRIPTS = Path(__file__).resolve().parent / "remote_scripts"
REMOTE_ROOT = "/root/.vpskit"

SSH_OPTS = [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=15",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=3",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "LogLevel=ERROR",
]


class RemoteError(VpskitError):
    pass


class Remote:
    def __init__(self, node: NodeConfig):
        self.node = node
        self.ssh = ["ssh"] + SSH_OPTS + node.ssh_args()
        self.scp = ["scp"] + ["-q"] + SSH_OPTS + node.scp_args()
        self.info: Dict[str, Any] = {}

    # ------------------------------------------------------------ basic

    def run(
        self,
        command: str,
        *,
        check: bool = True,
        timeout: int = 120,
        input_text: Optional[str] = None,
        retries: int = 2,
    ) -> str:
        cmd = self.ssh + [command]
        last_error = None
        for attempt in range(retries + 1):
            try:
                proc = subprocess.run(
                    cmd,
                    input=input_text,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as exc:
                last_error = exc
                if attempt < retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise RemoteError("远端命令超时（%ss）: %s" % (timeout, command)) from exc
            # OpenSSH 255：链路瞬断/认证前超时，重试通常安全；apply 的命令都是幂等的
            if proc.returncode == 255 and attempt < retries:
                last_error = proc
                time.sleep(1.5 * (attempt + 1))
                continue
            if check and proc.returncode != 0:
                detail = redact_text((proc.stderr or proc.stdout or "").strip())
                raise RemoteError("远端命令失败（exit %s）: %s\n%s" % (proc.returncode, command, detail))
            return proc.stdout
        raise RemoteError("远端命令失败: %s" % command)

    def tmp_dir(self) -> str:
        path = REMOTE_ROOT + "/tmp"
        self.run("mkdir -p %s && chmod 700 %s %s" % (shlex.quote(path), shlex.quote(REMOTE_ROOT), shlex.quote(path)), timeout=30)
        return path

    def temp_path(self, prefix: str, suffix: str = "") -> str:
        return "%s/%s-%s%s" % (self.tmp_dir(), prefix, pysecrets.token_hex(6), suffix)

    def check(self) -> bool:
        try:
            self.run("true", timeout=20)
            return True
        except RemoteError:
            return False

    def upload_bytes(self, data: bytes, remote_path: str, mode: int = 0o600) -> None:
        self.run("mkdir -p %s" % shlex.quote(os.path.dirname(remote_path)), timeout=30)
        cmd = self.ssh + ["cat > %s" % shlex.quote(remote_path)]
        proc = subprocess.run(cmd, input=data, capture_output=True, timeout=120)
        if proc.returncode != 0:
            raise RemoteError("上传失败: %s" % remote_path)
        self.run("chmod %o %s" % (mode, shlex.quote(remote_path)), timeout=20)

    def download_bytes(self, remote_path: str) -> bytes:
        cmd = self.ssh + ["cat %s" % shlex.quote(remote_path)]
        proc = subprocess.run(cmd, capture_output=True, timeout=120)
        if proc.returncode != 0:
            raise RemoteError("读取远端文件失败: %s" % remote_path)
        return proc.stdout

    def scp_upload(self, local: Path, remote_path: str) -> None:
        self.run("mkdir -p %s" % shlex.quote(os.path.dirname(remote_path)), timeout=30)
        cmd = self.scp + [str(local), self.node.scp_target(remote_path)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise RemoteError("scp 上传失败: %s\n%s" % (remote_path, redact_text(proc.stderr or "")))

    def scp_download(self, remote_path: str, local: Path) -> None:
        cmd = self.scp + [self.node.scp_target(remote_path), str(local)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise RemoteError("scp 下载失败: %s\n%s" % (remote_path, redact_text(proc.stderr or "")))

    def run_script(
        self,
        name: str,
        args: Optional[Sequence[str]] = None,
        *,
        input_text: Optional[str] = None,
        timeout: int = 120,
    ) -> str:
        script = SCRIPTS / name
        if not script.exists():
            raise VpskitError("缺少远端脚本: %s" % script)
        remote = self.temp_path(name, ".py")
        self.upload_bytes(script.read_bytes(), remote, mode=0o700)
        command = "python3 %s" % shlex.quote(remote)
        if args:
            command += " " + " ".join(shlex.quote(str(a)) for a in args)
        try:
            return self.run(command, input_text=input_text, timeout=timeout)
        finally:
            self.run("rm -f %s" % shlex.quote(remote), check=False, timeout=20)

    # ------------------------------------------------------------ inspect

    def inspect(self) -> Dict[str, Any]:
        out = self.run_script("inspect.py", timeout=60)
        try:
            data = json.loads(out)
        except ValueError as exc:
            raise RemoteError("inspect 输出不是 JSON: %s" % out[:300]) from exc
        self.info = data
        return data

    def require_root(self) -> None:
        if not self.info:
            self.inspect()
        if not self.info.get("is_root"):
            raise RemoteError(
                "远端不是 root。vpskit 的 apply/verify 需要 root（当前 user=%s）。"
                "请在 nodes.yaml 里用 ssh_user: root，或给该用户配置免密 sudo（暂未支持）。"
                % self.info.get("user", "?")
            )

    def hash_files(self, paths: Sequence[str]) -> Dict[str, Any]:
        if not paths:
            return {}
        out = self.run_script("hash_files.py", input_text=json.dumps(list(paths)), timeout=120)
        try:
            return json.loads(out)
        except ValueError as exc:
            raise RemoteError("hash_files 输出不是 JSON: %s" % out[:300]) from exc

    # ------------------------------------------------------------ backup / deploy

    def backup(self, paths: Sequence[str], stamp: str) -> str:
        backup_dir = "%s/backups/%s" % (REMOTE_ROOT, stamp)
        out = self.run_script("backup.py", ["--dir", backup_dir], input_text=json.dumps(list(paths)), timeout=120)
        try:
            data = json.loads(out)
        except ValueError as exc:
            raise RemoteError("backup 输出异常: %s" % out[:300]) from exc
        return data.get("backup_dir", backup_dir)

    def deploy(self, staging: str, manifest: str, dry_run: bool = False) -> Dict[str, Any]:
        args = ["--staging", staging, "--manifest", manifest]
        if dry_run:
            args.append("--dry-run")
        out = self.run_script("deploy.py", args, timeout=300)
        try:
            data = json.loads(out.strip().splitlines()[-1])
        except ValueError as exc:
            raise RemoteError("deploy 输出异常: %s" % out[-500:]) from exc
        if data.get("errors"):
            raise RemoteError("部署失败: %s" % json.dumps(data["errors"], ensure_ascii=False)[:800])
        return data

    def rollback(self, backup_dir: str) -> Dict[str, Any]:
        out = self.run_script("rollback.py", ["--dir", backup_dir], timeout=180)
        try:
            return json.loads(out.strip().splitlines()[-1])
        except ValueError as exc:
            raise RemoteError("rollback 输出异常: %s" % out[-300:]) from exc

    # ------------------------------------------------------------ firewall

    def install_guard(self) -> None:
        script = (SCRIPTS / "firewall-guard.sh").read_bytes()
        self.upload_bytes(script, REMOTE_ROOT + "/firewall-guard.sh", mode=0o700)

    def firewall_guard_start(self, backup_dir: str, delay: int) -> None:
        self.run("rm -f /run/vpskit-firewall-ok", check=False, timeout=20)
        cmd = (
            "nohup setsid %s/firewall-guard.sh %s %d "
            ">/root/.vpskit/firewall-guard.log 2>&1 & echo started"
            % (REMOTE_ROOT, shlex.quote(backup_dir), delay)
        )
        self.run(cmd, timeout=30)

    def firewall_guard_mark(self) -> None:
        self.run("touch /run/vpskit-firewall-ok", timeout=20)

    def firewall_guard_stop(self) -> None:
        self.run("pkill -f 'vpskit/firewall-guard.sh' || true", check=False, timeout=20)

    def firewall_check(self, path: str) -> None:
        self.run("nft -c -f %s" % shlex.quote(path), timeout=60)

    def firewall_apply(self) -> None:
        self.run("nft -f /etc/nftables.conf", timeout=60)
        self.run("systemctl restart fail2ban", check=False, timeout=60)

    def firewall_restore(self, backup_dir: str) -> bool:
        """恢复备份规则；失败会抛异常，调用方必须保留 guard。"""
        ruleset = backup_dir + "/nft.ruleset"
        conf = backup_dir + "/etc/nftables.conf"
        if self.run("test -s %s && echo yes || echo no" % shlex.quote(ruleset), check=False, timeout=20).strip() == "yes":
            # dump 是叠加语义：先 flush
            self.run("nft flush ruleset", timeout=30)
            self.run("nft -f %s" % shlex.quote(ruleset), timeout=90)
        elif self.run("test -s %s && echo yes || echo no" % shlex.quote(conf), check=False, timeout=20).strip() == "yes":
            self.run("nft flush ruleset", timeout=30)
            self.run("nft -f %s" % shlex.quote(conf), timeout=90)
        else:
            raise RemoteError("备份里没有可用的 nft 规则（%s）" % backup_dir)
        if self.run("test -f %s && echo yes || echo no" % shlex.quote(conf), check=False, timeout=20).strip() == "yes":
            self.run("cp -f %s /etc/nftables.conf" % shlex.quote(conf), check=False, timeout=30)
        self.run("systemctl restart fail2ban 2>/dev/null || true", check=False, timeout=60)
        return True

    # ------------------------------------------------------------ packages / xray

    def apt_install(self, packages: Sequence[str]) -> None:
        if not packages:
            return
        self.run("apt-get update -qq", timeout=300)
        cmd = (
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "
            + " ".join(shlex.quote(p) for p in packages)
        )
        self.run(cmd, timeout=600)

    def xray_version(self) -> str:
        out = self.run(
            "/usr/local/bin/xray version 2>/dev/null | head -1 || true",
            check=False,
            timeout=20,
        ).strip()
        import re

        m = re.search(r"Xray\s+([0-9][0-9A-Za-z.\-]*)", out)
        return m.group(1) if m else ""

    def install_xray(self, version: str, base: str, arch: str) -> str:
        arch_map = {"x86_64": "64", "aarch64": "arm64-v8a", "armv7l": "arm32-v7a"}
        asset_arch = arch_map.get(arch)
        if not asset_arch:
            raise RemoteError("不支持的架构: %s" % arch)
        current = self.xray_version()
        if version != "latest" and current == version:
            return current
        if version == "latest":
            url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-%s.zip" % asset_arch
            dgst_url = url + ".dgst"
        else:
            base = base.rstrip("/")
            url = "%s/v%s/Xray-linux-%s.zip" % (base, version, asset_arch)
            dgst_url = url + ".dgst"
        script = r'''
set -e
URL="$1"; DGST="$2"; ARCH="$3"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL --retry 3 --max-time 180 -o "$TMP/xray.zip" "$URL"
HAVE=$(sha256sum "$TMP/xray.zip" | awk '{print $1}')
if curl -fsSL --retry 2 --max-time 60 -o "$TMP/xray.dgst" "$DGST" 2>/dev/null; then
  WANT=$(grep -oE '[0-9a-fA-F]{64}' "$TMP/xray.dgst" | head -1 | tr 'A-F' 'a-f')
  if [ -n "$WANT" ] && [ "$HAVE" != "$WANT" ]; then
    echo "checksum mismatch: want=$WANT have=$HAVE" >&2
    exit 3
  fi
else
  echo "WARN: 无法获取 .dgst，跳过校验" >&2
fi
python3 - "$TMP/xray.zip" "$TMP" <<'PY'
import sys, zipfile
zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])
PY
install -m 0755 "$TMP/xray" /usr/local/bin/xray
/usr/local/bin/xray version | head -1
'''
        out = self.run(
            "bash -s -- %s %s %s" % (shlex.quote(url), shlex.quote(dgst_url), shlex.quote(asset_arch)),
            input_text=script,
            timeout=600,
        )
        return out.strip().splitlines()[-1] if out.strip() else ""

    # ------------------------------------------------------------ service helpers

    def systemctl(self, action: str, unit: str, check: bool = False) -> str:
        return self.run("systemctl %s %s" % (action, shlex.quote(unit)), check=check, timeout=60)

    def write_text_remote(self, path: str, text: str, mode: int = 0o600) -> None:
        self.upload_bytes(text.encode("utf-8"), path, mode=mode)

    def read_text_remote(self, path: str) -> str:
        return self.download_bytes(path).decode("utf-8", "replace")
