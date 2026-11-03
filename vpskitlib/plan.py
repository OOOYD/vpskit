"""plan：渲染 + 远端比对 + 校验，不修改目标机。"""
from __future__ import annotations

import difflib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import NodeConfig
from .remote import Remote
from .render import FileSpec, RenderResult
from .util import VpskitError, detail, info, ok, redact_text, step, warn
from .workflow import Prepared, local_validate, prepare


@dataclass
class Change:
    path: str
    status: str  # new | changed | mode | same | error
    local_hash: str
    remote_hash: Optional[str] = None
    local_mode: int = 0o644
    remote_mode: Optional[int] = None
    note: str = ""


@dataclass
class Plan:
    prepared: Prepared
    changes: List[Change]
    validation: Dict[str, Any] = field(default_factory=dict)
    blockers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def node(self) -> NodeConfig:
        return self.prepared.node

    @property
    def changed(self) -> List[Change]:
        return [c for c in self.changes if c.status in ("new", "changed", "mode")]

    @property
    def ok(self) -> bool:
        return not self.blockers and not self.validation.get("local_errors") and not self.validation.get("fatal")


def _status_for(spec: FileSpec, remote: Optional[Dict[str, Any]]) -> Change:
    if remote is None:
        return Change(spec.path, "new", spec.sha256, None, spec.mode, None)
    if isinstance(remote, dict) and remote.get("error"):
        return Change(spec.path, "error", spec.sha256, None, spec.mode, None, remote["error"])
    rh = remote.get("sha256")
    rm = remote.get("mode")
    if rh == spec.sha256:
        if rm is not None and int(rm) != int(spec.mode):
            return Change(spec.path, "mode", spec.sha256, rh, spec.mode, rm)
        return Change(spec.path, "same", spec.sha256, rh, spec.mode, rm)
    return Change(spec.path, "changed", spec.sha256, rh, spec.mode, rm)


def _remote_validate(remote: Remote, prepared: Prepared) -> Dict[str, Any]:
    result: Dict[str, Any] = {"nft": "skipped", "xray": "skipped", "errors": []}
    # nft -c：只上传到 /tmp，不加载
    nft = next((f for f in prepared.result.files if f.path == "/etc/nftables.conf"), None)
    if nft and prepared.info.get("nft"):
        tmp = remote.temp_path("plan-nft", ".conf")
        try:
            remote.upload_bytes(nft.content, tmp, mode=0o600)
            remote.run("nft -c -f %s" % tmp, timeout=60)
            result["nft"] = "ok"
        except Exception as exc:
            result["nft"] = "fail"
            result["errors"].append("nftables 语法校验失败: %s" % str(exc).splitlines()[-1])
        finally:
            remote.run("rm -f %s" % tmp, check=False, timeout=20)

    # xray -test：只有已装 xray 时才做
    xray = next((f for f in prepared.result.files if f.path == "/usr/local/etc/xray/config.json"), None)
    if xray and prepared.info.get("xray"):
        tmp = remote.temp_path("plan-xray", ".json")
        try:
            remote.upload_bytes(xray.content, tmp, mode=0o600)
            remote.run("/usr/local/bin/xray run -test -config %s" % tmp, timeout=60)
            result["xray"] = "ok"
        except Exception as exc:
            result["xray"] = "fail"
            result["errors"].append("xray 配置校验失败: %s" % str(exc).splitlines()[-1])
        finally:
            remote.run("rm -f %s" % tmp, check=False, timeout=20)
    return result


def _build_warnings(prepared: Prepared, remote_info: Dict[str, Any], node: NodeConfig) -> List[str]:
    warnings = list(prepared.warnings)
    if remote_info.get("docker_active"):
        warnings.append("远端 Docker 正在运行：nftables.conf 里的 flush ruleset 会清掉 Docker 规则，apply 默认会拒绝")
    if not remote_info.get("is_root"):
        warnings.append("远端不是 root：apply 需要 root")
    if not remote_info.get("fail2ban_action_nft"):
        warnings.append("fail2ban 没有 nftables-multiport action；将回退到 iptables-multiport（需要 iptables）")
    if node.ssh_harden and not remote_info.get("sshd_config_include"):
        warnings.append("sshd 没有 Include sshd_config.d：SSH 加固文件会被忽略")
    if node.ssh_harden and not remote_info.get("authorized_keys"):
        warnings.append("远端 ~/.ssh/authorized_keys 为空：apply 会跳过 SSH 加固，避免锁死")
    if node.xray_version == "latest":
        warnings.append("xray_version: latest 无法做 checksum 固定；生产建议写死版本")
    if any(d in node.dest_host for d in ("iana.org", "cloudflare.com")):
        warnings.append(
            "REALITY dest 走 Cloudflare（%s）：官方文档提示这会让你成为 Cloudflare 的转发器；"
            "若开 fallback 限速，限速本身也是指纹。建议评估同 ASN target 或 Nginx 前置。" % node.dest_host
        )
    if not node.admin_ips:
        warnings.append("admin_ips 为空：管理页/SSH 没有管理员白名单")
    return warnings


def build_plan(node: NodeConfig, root: Path, remote: Remote, *, remote_validate: bool = True, allow_flush: bool = False) -> Plan:
    info("连接 %s 并做只读体检 ..." % node.id)
    remote_info = remote.inspect()
    prepared = prepare(node, root, info=remote_info)
    hashes = remote.hash_files(prepared.remote_paths)
    changes = [_status_for(spec, hashes.get(spec.path)) for spec in prepared.result.files]
    local_errors = local_validate(prepared.result)
    validation: Dict[str, Any] = {"local_errors": local_errors}
    if remote_validate:
        validation.update(_remote_validate(remote, prepared))
    blockers: List[str] = []
    if local_errors:
        blockers.append("本地渲染校验失败")
    if validation.get("nft") == "fail":
        blockers.append("nftables 语法校验失败")
    if validation.get("xray") == "fail":
        blockers.append("xray 配置校验失败")
    osid = (remote_info.get("os") or {}).get("id", "")
    if osid not in ("debian", "ubuntu"):
        blockers.append("只支持 Debian/Ubuntu，当前: %s" % (osid or "unknown"))
    if remote_info.get("docker_active") and not allow_flush:
        blockers.append("Docker 在运行，flush ruleset 会破坏 Docker；需 --allow-flush 或改用无 Docker 机器")
    if not remote_info.get("is_root"):
        blockers.append("远端不是 root")
    warnings = _build_warnings(prepared, remote_info, node)
    plan = Plan(prepared=prepared, changes=changes, validation=validation, blockers=blockers, warnings=warnings)
    plan_path = prepared.build_dir / "plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "node": node.id,
                "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "validation": validation,
                "blockers": blockers,
                "warnings": warnings,
                "changes": [
                    {"path": c.path, "status": c.status, "note": c.note}
                    for c in changes
                ],
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return plan


def _safe_diff(local: bytes, remote: bytes, path: str, limit: int = 120) -> str:
    try:
        a = local.decode("utf-8").splitlines()
        b = remote.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return "（二进制文件，跳过 diff）"
    lines = list(
        difflib.unified_diff(
            b,
            a,
            fromfile="remote:" + path,
            tofile="local:" + path,
            lineterm="",
            n=2,
        )
    )
    text = "\n".join(redact_text(line) for line in lines[:limit])
    if len(lines) > limit:
        text += "\n...（已截断）"
    return text


def print_plan(plan: Plan, *, show_diff: bool = False, verbose: bool = False, remote: Optional[Remote] = None) -> None:
    p = plan.prepared
    node = plan.node
    info("节点 %s / %s" % (node.id, node.host))
    osinfo = p.info.get("os") or {}
    detail("系统: %s %s / %s / root=%s" % (
        osinfo.get("id", "?"), osinfo.get("version", ""), p.info.get("arch", "?"), p.info.get("is_root")
    ))
    detail("地址: v4=%s v6=%s / has_v6=%s" % (
        p.addresses.get("ipv4") or "-", p.addresses.get("ipv6") or "-", p.has_v6
    ))
    detail("profile=%s quota=%sG anchor=%s" % (node.profile, node.quota_gb, node.quota_anchor_day))

    counts: Dict[str, int] = {}
    for c in plan.changes:
        counts[c.status] = counts.get(c.status, 0) + 1
    step("文件计划：%s" % ", ".join("%s=%d" % (k, v) for k, v in sorted(counts.items())))
    for c in plan.changes:
        if c.status == "same":
            if verbose:
                detail("  = %s" % c.path)
            continue
        mark = {"new": "+", "changed": "~", "mode": "m", "error": "!"}.get(c.status, "?")
        detail("  %s %s%s" % (mark, c.path, ("（%s）" % c.note) if c.note else ""))
        if show_diff and c.status in ("changed", "new") and remote is not None:
            spec = next((f for f in p.result.files if f.path == c.path), None)
            if spec:
                try:
                    old = remote.download_bytes(c.path) if c.status == "changed" else b""
                    print(_safe_diff(spec.content, old, c.path))
                except Exception as exc:
                    detail("    diff 获取失败: %s" % exc)

    step("服务计划")
    for name in ("xray", "ss-server", "traffic-web", "sub", "fail2ban", "nftables"):
        st = (p.info.get("services") or {}).get(name, {})
        if st:
            detail("  %-14s active=%-8s enabled=%s" % (name, st.get("active", "?"), st.get("enabled", "?")))
    timers = [n for n in (p.info.get("services") or {}) if n.endswith(".timer")]
    for name in timers:
        st = p.info["services"][name]
        detail("  %-22s active=%-8s enabled=%s" % (name, st.get("active", "?"), st.get("enabled", "?")))

    step("校验")
    detail("本地渲染: %s" % ("通过" if not plan.validation.get("local_errors") else "失败"))
    for err in plan.validation.get("local_errors") or []:
        detail("  - %s" % err)
    for key in ("nft", "xray"):
        if key in plan.validation:
            detail("%s: %s" % (key, plan.validation[key]))
    for err in plan.validation.get("errors") or []:
        detail("  - %s" % err)

    if plan.blockers:
        step("阻断项")
        for b in plan.blockers:
            warn(b)
    if plan.warnings:
        step("提醒")
        for w in plan.warnings:
            warn(w)
    if plan.ok:
        if plan.changed:
            ok("计划可执行：%d 个文件会变化" % len(plan.changed))
            detail("执行: vpskit apply %s --yes" % node.id)
        else:
            ok("已经是最新状态，无需 apply")
    else:
        warn("计划存在阻断项，先修掉再 apply")


def plan_json(plan: Plan) -> Dict[str, Any]:
    return {
        "node": plan.node.id,
        "ok": plan.ok,
        "has_v6": plan.prepared.has_v6,
        "addresses": plan.prepared.addresses,
        "changes": [
            {
                "path": c.path,
                "status": c.status,
                "local_sha256": c.local_hash[:12] if c.local_hash else "",
                "remote_sha256": (c.remote_hash or "")[:12],
                "note": c.note,
            }
            for c in plan.changes
        ],
        "validation": plan.validation,
        "blockers": plan.blockers,
        "warnings": plan.warnings,
    }
