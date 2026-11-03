"""plan/apply/verify 共用的准备与本地校验。"""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import NodeConfig
from .paths import NodePaths
from .render import RenderOptions, RenderResult, render, write_build
from .secrets import ensure_secrets
from .util import VpskitError, redact_text

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


@dataclass
class Prepared:
    node: NodeConfig
    paths: NodePaths
    secrets: Dict[str, Any]
    result: RenderResult
    build_dir: Path
    info: Dict[str, Any] = field(default_factory=dict)
    has_v6: bool = True
    addresses: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    @property
    def manifest_path(self) -> Path:
        return self.build_dir / "manifest.json"

    @property
    def payload_dir(self) -> Path:
        return self.build_dir / "payload"

    @property
    def remote_paths(self) -> List[str]:
        return [f.path for f in self.result.files]


def resolve_has_v6(node: NodeConfig, info: Dict[str, Any]) -> Tuple[bool, List[str]]:
    warnings: List[str] = []
    actual = bool(info.get("has_v6"))
    if node.has_v6 is True and not actual:
        warnings.append("nodes.yaml 写的是 has_v6: true，但远端没有全局 IPv6；本次按无 v6 处理")
        return False, warnings
    if node.has_v6 is False and actual:
        warnings.append("nodes.yaml 写的是 has_v6: false；本次按无 v6 处理（不渲染 v6 表/SS）")
        return False, warnings
    if node.has_v6 == "auto":
        return actual, warnings
    return bool(node.has_v6), warnings


def addresses_from_info(node: NodeConfig, info: Dict[str, Any], has_v6: bool) -> Dict[str, str]:
    ipv4 = (info.get("ipv4") or [""])[0]
    ipv6 = (info.get("ipv6") or [""])[0] if has_v6 else ""
    if not ipv4 and ":" not in node.host:
        ipv4 = node.host
    if not ipv6 and has_v6 and ":" in node.host:
        ipv6 = node.host
    return {"ipv4": ipv4, "ipv6": ipv6}


def fail2ban_actions(info: Dict[str, Any]) -> Tuple[str, str]:
    if info.get("fail2ban_action_nft"):
        return "nftables-multiport", "nftables-allports"
    return "iptables-multiport", "iptables-allports"


def prepare(
    node: NodeConfig,
    root: Path,
    *,
    info: Optional[Dict[str, Any]] = None,
    write: bool = True,
) -> Prepared:
    paths = NodePaths(root, node.id).ensure()
    secrets = ensure_secrets(node, paths.secrets)
    info = info or {}
    if info:
        has_v6, warnings = resolve_has_v6(node, info)
        addresses = addresses_from_info(node, info, has_v6)
        banaction, allports = fail2ban_actions(info)
    else:
        has_v6 = node.has_v6 is not False
        addresses = {"ipv4": node.host if ":" not in node.host else "", "ipv6": node.host if ":" in node.host else ""}
        warnings = []
        banaction, allports = "nftables-multiport", "nftables-allports"
    render_node = copy.copy(node)
    ssh_source = str(info.get("ssh_source") or "").strip()
    if ssh_source:
        import ipaddress

        try:
            ipaddress.ip_address(ssh_source)
            admin = list(render_node.admin_ips)
            if ssh_source not in admin:
                admin.append(ssh_source)
                render_node.admin_ips = admin
                warnings.append("已将当前 SSH 来源 %s 临时加入 admin 白名单（不写回 nodes.yaml）" % ssh_source)
        except ValueError:
            pass
    opts = RenderOptions(
        has_v6=has_v6,
        addresses=addresses,
        fail2ban_banaction=banaction,
        fail2ban_allports=allports,
    )
    result = render(render_node, secrets, root, opts)
    # render 阶段无法知道落盘路径；这里把构建目录写入
    build_dir = paths.build_dir
    if write:
        write_build(result, build_dir)
    return Prepared(
        node=node,
        paths=paths,
        secrets=secrets,
        result=result,
        build_dir=build_dir,
        info=info,
        has_v6=has_v6,
        addresses=addresses,
        warnings=warnings + list(node.warnings) + list(result.warnings),
    )


def local_validate(result: RenderResult) -> List[str]:
    errors: List[str] = []
    for spec in result.files:
        path = spec.path
        data = spec.content
        if path.endswith(".py"):
            try:
                compile(data, path, "exec")
            except SyntaxError as exc:
                errors.append("%s Python 语法错误: %s" % (path, exc))
        elif path.endswith(".json"):
            try:
                json.loads(data.decode("utf-8"))
            except Exception as exc:
                errors.append("%s JSON 无效: %s" % (path, exc))
        elif path.endswith((".yaml", ".yml")):
            if yaml is not None:
                try:
                    yaml.safe_load(data.decode("utf-8"))
                except Exception as exc:
                    errors.append("%s YAML 无效: %s" % (path, exc))
        elif path.endswith(".sh"):
            bash = shutil.which("bash")
            if not bash:
                continue  # Windows 没有 bash 时跳过 shell 语法检查
            fd, tmp = tempfile.mkstemp(suffix=".sh")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                proc = subprocess.run([bash, "-n", tmp], capture_output=True, text=True)
                if proc.returncode != 0:
                    errors.append("%s shell 语法错误: %s" % (path, (proc.stderr or "").strip()))
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        elif path.endswith("/nftables.conf"):
            text = data.decode("utf-8", "replace")
            if "flush ruleset" not in text:
                errors.append("nftables.conf 缺少 flush ruleset")
            if text.count("{") != text.count("}"):
                errors.append("nftables.conf 花括号不平衡")
        elif path.endswith((".service", ".timer")):
            text = data.decode("utf-8", "replace")
            if "[Unit]" not in text or ("[Service]" not in text and "[Timer]" not in text):
                errors.append("%s 缺少 [Unit]/[Service|Timer]" % path)
    return errors


def redacted_paths(result: RenderResult) -> List[str]:
    return [f.path for f in result.files]


def debug_manifest(prepared: Prepared) -> Dict[str, Any]:
    return {
        "node": prepared.node.id,
        "has_v6": prepared.has_v6,
        "addresses": prepared.addresses,
        "files": len(prepared.result.files),
        "warnings": prepared.warnings,
    }
