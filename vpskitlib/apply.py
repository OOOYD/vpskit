"""apply：把 plan 真正落到远端。默认要求确认；防火墙带保险丝。"""
from __future__ import annotations

import json
import os
import shlex
import socket
import subprocess
import tarfile
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .config import NodeConfig
from .locking import FileLock
from .paths import NodePaths
from .plan import Plan, build_plan, print_plan
from .remote import REMOTE_ROOT, Remote, RemoteError
from .util import VpskitError, detail, info, ok, step, warn
from .verify import print_verify, verify_json, verify_node


def _tcp(host: str, port: int, timeout: float = 8.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False




def _confirm(node: NodeConfig, yes: bool) -> None:
    if yes:
        return
    if not sys.stdin.isatty():
        raise VpskitError("非交互环境必须显式 --yes")
    print()
    warn("即将修改 %s（%s）的文件、服务与防火墙。" % (node.id, node.host))
    answer = input("确认请输入节点 id（%s）: " % node.id).strip()
    if answer != node.id:
        raise VpskitError("已取消")


def _enable(remote: Remote, units: List[str]) -> None:
    for unit in units:
        remote.run("systemctl enable %s" % shlex.quote(unit), check=False, timeout=30)


def _restart(remote: Remote, unit: str) -> None:
    remote.run("systemctl restart %s" % shlex.quote(unit), timeout=60)
    time.sleep(0.5)
    state = remote.run("systemctl is-active %s" % shlex.quote(unit), check=False, timeout=20).strip()
    if state != "active":
        raise VpskitError("%s 重启后不是 active（%s）" % (unit, state))
    ok("%s active" % unit)


def _stop_disable(remote: Remote, unit: str) -> None:
    remote.run("systemctl disable --now %s" % shlex.quote(unit), check=False, timeout=30)


def _apt_packages(node: NodeConfig) -> List[str]:
    packages = [
        "nftables",
        "fail2ban",
        "vnstat",
        "curl",
        "ca-certificates",
        "unzip",
        "python3",
        "python3-systemd",
        "procps",
        "iproute2",
    ]
    if node.ss_enable:
        packages.append("shadowsocks-libev")
    if node.auto_updates:
        packages.append("unattended-upgrades")
    return packages


def _local_tar(prepared) -> Path:
    """用 tarfile 而不是外部 tar，Windows 本地也能跑。"""
    tar_path = prepared.build_dir / "payload.tar.gz"
    if tar_path.exists():
        tar_path.unlink()
    payload = prepared.payload_dir
    with tarfile.open(tar_path, "w:gz") as tf:
        for path in sorted(payload.rglob("*")):
            if path.is_file():
                tf.add(path, arcname=str(path.relative_to(payload)))
    return tar_path


def _verify_connectivity(node: NodeConfig, prepared, remote: Remote) -> List[str]:
    failures = []
    host = prepared.addresses.get("ipv4") or node.host
    # 新 SSH 连接是最重要的检查
    if not remote.check():
        failures.append("SSH 新连接失败")
    ports = [(node.ssh_port, "SSH"), (node.reality_port, "REALITY")]
    if node.sub_enable:
        ports.append((node.sub_port, "订阅页"))
    if node.traffic_web_enable:
        ports.append((node.traffic_web_port, "流量页"))
    for port, name in ports:
        if not _tcp(host, port):
            failures.append("%s %s:%d 不可达" % (name, host, port))
    return failures


def _apply_firewall(
    node: NodeConfig,
    prepared,
    remote: Remote,
    backup_dir: str,
) -> None:
    step("防火墙（语法校验 → 保险丝 → 加载 → 本地回连验证）")
    remote.install_guard()
    remote.firewall_check("/etc/nftables.conf")
    ok("nft -c 语法校验通过")
    remote.firewall_guard_start(backup_dir, node.firewall_guard_seconds)
    ok("保险丝已启动（%ds 未确认则自动恢复）" % node.firewall_guard_seconds)
    remote.firewall_apply()
    ok("nftables 已加载，fail2ban 已重启")
    time.sleep(1)
    failures = _verify_connectivity(node, prepared, remote)
    if failures:
        warn("回连验证失败：" + "; ".join(failures))
        warn("立即恢复备份规则（flush + load）...")
        try:
            remote.firewall_restore(backup_dir)
        except Exception as restore_exc:
            # 恢复失败时不要停 guard：它还会在超时后重试
            raise VpskitError(
                "防火墙加载后回连失败，且立即恢复失败：%s。guard 仍在运行，请从控制台检查。"
                % restore_exc
            ) from restore_exc
        remote.firewall_guard_stop()
        raise VpskitError("防火墙加载后回连失败，已恢复备份规则。请检查 nftables.conf / SSH 白名单。")
    remote.firewall_guard_mark()
    remote.firewall_guard_stop()
    ok("回连验证通过，保险丝已解除")


def _apply_ssh_hardening(node: NodeConfig, prepared, remote: Remote, skip: bool) -> None:
    path = "/etc/ssh/sshd_config.d/99-vpskit.conf"
    if skip or not node.ssh_harden:
        info("跳过 SSH 加固")
        return
    if not prepared.info.get("sshd_config_include"):
        warn("sshd 没有 Include sshd_config.d，跳过 SSH 加固")
        return
    if not prepared.info.get("authorized_keys"):
        warn("authorized_keys 为空，跳过 SSH 加固以防锁死")
        return
    step("SSH 加固校验")
    try:
        remote.run("sshd -t", timeout=30)
    except Exception as exc:
        remote.run("rm -f %s" % path, check=False, timeout=20)
        raise VpskitError("sshd -t 失败，已移除加固文件: %s" % exc) from exc
    remote.run("systemctl reload ssh 2>/dev/null || systemctl reload sshd", check=False, timeout=30)
    time.sleep(1)
    if not remote.check():
        remote.run("rm -f %s" % path, check=False, timeout=20)
        remote.run("systemctl reload ssh 2>/dev/null || systemctl reload sshd", check=False, timeout=30)
        raise VpskitError("SSH 加固后无法建立新连接，已回滚 sshd 配置")
    ok("SSH 加固生效，新连接正常")


def _apply_sysctl(node: NodeConfig, remote: Remote) -> None:
    if not node.sysctl:
        return
    step("内核参数")
    remote.run("modprobe tcp_bbr 2>/dev/null || true", check=False, timeout=20)
    available = remote.run("cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || true", check=False, timeout=20)
    if "bbr" not in available:
        warn("内核不支持 BBR，已从 sysctl 文件移除该项")
        remote.run("sed -i '/tcp_congestion_control/d' /etc/sysctl.d/99-vpskit.conf", check=False, timeout=20)
    remote.run("sysctl -e --system", check=False, timeout=60)
    cc = remote.run("sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true", check=False, timeout=20).strip()
    detail("tcp_congestion_control=%s" % (cc or "?"))


def _apply_auto_updates(node: NodeConfig, remote: Remote) -> None:
    if not node.auto_updates:
        return
    step("自动安全更新")
    remote.run("systemctl enable --now unattended-upgrades", check=False, timeout=60)
    remote.run("systemctl enable --now apt-daily.timer apt-daily-upgrade.timer", check=False, timeout=60)
    active = remote.run("systemctl is-active unattended-upgrades", check=False, timeout=20).strip()
    detail("unattended-upgrades=%s" % active)


def _apply_monitor(remote: Remote) -> None:
    step("生成首份流量摘要")
    remote.run("systemctl start traffic-monitor.service", check=False, timeout=120)
    time.sleep(3)
    exists = remote.run("test -s /opt/traffic/summary.json && echo yes || echo no", check=False, timeout=20).strip()
    if exists == "yes":
        ok("summary.json 已生成")
    else:
        warn("summary.json 未生成；traffic-web 会显示空状态")


def apply_node(
    node: NodeConfig,
    root: Path,
    *,
    yes: bool = False,
    dry_run: bool = False,
    skip_packages: bool = False,
    skip_firewall: bool = False,
    skip_ssh_harden: bool = False,
    allow_flush: bool = False,
    prune: bool = False,
) -> Dict[str, Any]:
    paths = NodePaths(root, node.id).ensure()
    with FileLock(paths.lock):
        remote = Remote(node)
        if not remote.check():
            raise VpskitError("SSH 连不上 %s（检查 ssh alias / host / key）" % node.id)
        plan = build_plan(node, root, remote, allow_flush=allow_flush)
        print_plan(plan)
        if plan.blockers:
            raise VpskitError("存在阻断项，拒绝 apply")
        if dry_run:
            return {"ok": plan.ok, "dry_run": True, "changed": len(plan.changed), "plan": plan}
        if not plan.changed:
            info("没有文件变化，先做一次 verify ...")
            v = verify_node(node, root, remote)
            print_verify(v)
            if v.ok:
                return {"ok": True, "changed": 0, "verify": verify_json(v)}
            warn("文件无变化但验证未通过，继续修复服务")
        _confirm(node, yes)

        prepared = plan.prepared
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup_dir = ""
        firewall_applied = False
        try:
            step("备份现有文件与防火墙规则")
            backup_dir = remote.backup(prepared.remote_paths, stamp)
            ok("备份: %s" % backup_dir)

            if not skip_packages:
                step("安装系统包")
                remote.apt_install(_apt_packages(node))
                ok("系统包完成")
            else:
                warn("--skip-packages：跳过 apt 与 xray 安装")

            if not skip_packages:
                step("安装/校验 Xray")
                installed = remote.install_xray(node.xray_version, node.xray_download_base, prepared.info.get("arch", ""))
                ok("xray: %s" % installed)

            step("上传并部署文件")
            tar_path = _local_tar(prepared)
            remote.run("mkdir -p %s && chmod 700 %s" % (shlex.quote(REMOTE_ROOT), shlex.quote(REMOTE_ROOT)), timeout=30)
            incoming = "%s/incoming/%s" % (REMOTE_ROOT, stamp)
            staging = incoming + "/payload"
            remote.run("mkdir -p %s" % shlex.quote(staging), timeout=30)
            remote.scp_upload(tar_path, incoming + "/payload.tar.gz")
            remote.scp_upload(prepared.manifest_path, incoming + "/manifest.json")
            remote.run("tar -xzf %s -C %s" % (shlex.quote(incoming + "/payload.tar.gz"), shlex.quote(staging)), timeout=120)
            deployed = remote.deploy(staging, incoming + "/manifest.json")
            detail("changed=%d skipped=%d" % (len(deployed.get("changed", [])), len(deployed.get("skipped", []))))
            ok("文件部署完成")

            if prune and node.sub_enable:
                expected = {
                    Path(f.path).name
                    for f in prepared.result.files
                    if f.path.startswith("/opt/sub/data/")
                }
                listing = remote.run("ls -1 /opt/sub/data 2>/dev/null || true", check=False, timeout=30)
                for name in listing.splitlines():
                    if name.startswith("sub-") and name.endswith(".yaml") and name not in expected:
                        remote.run("rm -f %s" % shlex.quote("/opt/sub/data/" + name), check=False, timeout=20)
                        warn("已移除过期订阅: %s" % name)

            step("systemd 配置")
            remote.run("systemctl daemon-reload", timeout=60)
            enable = [
                "xray.service",
                "traffic-web.service",
                "fail2ban.service",
                "traffic-monitor.timer",
                "unattr.timer",
                "traffic-snapshot.timer",
            ]
            if node.sub_enable:
                enable.append("sub.service")
            if node.ss_enable and prepared.has_v6:
                enable.append("ss-server.service")
            if node.autoban_enable:
                enable.append("autoban.timer")
            if node.selfheal_enable:
                enable.append("xray-selfheal.timer")
            _enable(remote, enable)
            remote.run("systemctl enable nftables 2>/dev/null || true", check=False, timeout=30)

            if not node.traffic_web_enable:
                _stop_disable(remote, "traffic-web.service")
            if not node.sub_enable:
                _stop_disable(remote, "sub.service")
            if not (node.ss_enable and prepared.has_v6):
                _stop_disable(remote, "ss-server.service")
            if not node.autoban_enable:
                _stop_disable(remote, "autoban.timer")
            if not node.selfheal_enable:
                _stop_disable(remote, "xray-selfheal.timer")

            _apply_ssh_hardening(node, prepared, remote, skip_ssh_harden)

            if not skip_firewall:
                firewall_applied = True
                _apply_firewall(node, prepared, remote, backup_dir)
                firewall_applied = False  # 已完成确认，之后失败不需要恢复防火墙
            else:
                warn("--skip-firewall：未加载防火墙")

            step("启动/重启服务")
            _restart(remote, "xray.service")
            if node.ss_enable and prepared.has_v6:
                _restart(remote, "ss-server.service")
            if node.traffic_web_enable:
                _restart(remote, "traffic-web.service")
            if node.sub_enable:
                _restart(remote, "sub.service")
            _restart(remote, "fail2ban.service")
            remote.run("systemctl restart traffic-monitor.timer", check=False, timeout=30)
            remote.run("systemctl restart unattr.timer", check=False, timeout=30)
            remote.run("systemctl restart traffic-snapshot.timer", check=False, timeout=30)
            if node.autoban_enable:
                remote.run("systemctl restart autoban.timer", check=False, timeout=30)
            if node.selfheal_enable:
                remote.run("systemctl restart xray-selfheal.timer", check=False, timeout=30)

            _apply_sysctl(node, remote)
            _apply_auto_updates(node, remote)
            remote.run("systemctl restart systemd-journald", check=False, timeout=30)
            remote.run("logrotate -d /etc/logrotate.d/vpskit >/dev/null 2>&1 || true", check=False, timeout=30)
            _apply_monitor(remote)
            remote.run("systemctl start unattr.service", check=False, timeout=120)
            remote.run("systemctl start autoban.service", check=False, timeout=60)

            step("写状态")
            state = {
                "node_id": node.id,
                "kit_version": __version__,
                "last_apply": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "backup": backup_dir,
                "changed": deployed.get("changed", []),
                "has_v6": prepared.has_v6,
                "addresses": prepared.addresses,
            }
            remote.write_text_remote(REMOTE_ROOT + "/state.json", json.dumps(state, indent=2, ensure_ascii=False) + "\n", 0o644)
            paths.state.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            os.chmod(paths.state, 0o600)

            step("验证")
            v = verify_node(node, root, remote, prepared=prepared)
            print_verify(v)
            if not v.ok:
                warn("验证未全部通过；文件/防火墙已生效，请按上面的失败项排查")
            else:
                ok("apply 完成")
            detail("客户端导入卡: %s" % (prepared.build_dir / "client-import.md"))
            detail("回滚: vpskit rollback %s" % node.id)

            # 清理旧 incoming（保留 7 天）
            remote.run(
                "find %s/incoming -mindepth 1 -maxdepth 1 -type d -mtime +7 -exec rm -rf {} + 2>/dev/null || true"
                % REMOTE_ROOT,
                check=False,
                timeout=60,
            )
            return {
                "ok": v.ok,
                "changed": deployed.get("changed", []),
                "backup": backup_dir,
                "verify": verify_json(v),
            }
        except Exception as exc:
            if firewall_applied:
                warn("apply 失败且防火墙可能已加载，尝试立即恢复 ...")
                try:
                    remote.firewall_restore(backup_dir)
                    remote.firewall_guard_stop()
                except Exception as restore_exc:
                    warn("立即恢复失败: %s（保险丝仍在运行，会在超时后重试）" % restore_exc)
            if backup_dir:
                warn("备份: %s" % backup_dir)
                warn("回滚: vpskit rollback %s" % node.id)
            raise
