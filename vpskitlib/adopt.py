"""adopt：从现网机器导入配置与秘密，生成 nodes.yaml + state/<id>/secrets.json。

只读远端；本地写 nodes.yaml 与 secrets（0600）。用于把已经手工维护的机器纳入工具。
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import Client, NodeConfig, NodeConfig as _Node  # noqa: F401
from .crypto import keypair_from_private, random_sub_path
from .paths import NodePaths
from .remote import Remote
from .secrets import client_sub_path, ensure_secrets, summary
from .util import VpskitError, detail, info, ok, step, warn

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


def _is_private(value: str) -> bool:
    import ipaddress

    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return (
        net.is_private
        or net.is_loopback
        or net.is_link_local
        or net.is_multicast
        or net.is_unspecified
    )


def _sub_paths(data: Dict[str, Any], clients: List[Client]) -> Dict[str, str]:
    kit = data.get("kitconf") or {}
    mapping: Dict[str, str] = {}
    raw = kit.get("sub_paths") or {}
    if isinstance(raw, dict):
        for email, path in raw.items():
            if email in [c.email for c in clients] and isinstance(path, str):
                mapping[email] = path
    # sub.py 里的 PATHS 是 {URL 路径: 文件路径}；URL 路径才是客户端要访问的
    script = data.get("sub_paths_from_script") or {}
    script_paths = [k for k in script.keys() if isinstance(k, str) and k.startswith("/")]
    single = str(kit.get("sub_path") or "")
    if single and (single.endswith(".yaml") or single.endswith(".yml")):
        single = ""  # 旧字段可能是文件路径，不是 URL 路径
    if not mapping and script_paths:
        for idx, client in enumerate(clients):
            mapping[client.email] = script_paths[min(idx, len(script_paths) - 1)]
        if len(script_paths) < len(clients):
            warn("现网只有 %d 个订阅路径，但有 %d 个 client；迁移时共用同一个路径（保持旧 URL 可用）" % (len(script_paths), len(clients)))
    if not mapping and single:
        for client in clients:
            mapping[client.email] = single
        if len(clients) > 1:
            warn("现网只有一个订阅路径，%d 个 client 共用它" % len(clients))
    return mapping

def adopt_node(
    node_id: str,
    host: str,
    *,
    root: Path,
    ssh_alias: str = "",
    ssh_user: str = "root",
    ssh_port: int = 22,
    ssh_key: str = "",
    title: str = "",
    dry_run: bool = False,
    force: bool = False,
) -> Dict[str, Any]:
    if yaml is None:
        raise VpskitError("需要 PyYAML")
    stub = NodeConfig(id=node_id, host=host, ssh_alias=ssh_alias, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key)
    remote = Remote(stub)
    info("只读读取 %s 的现网配置 ..." % host)
    remote.inspect()
    remote.require_root()
    data = json.loads(remote.run_script("adopt.py", timeout=90))
    if not data.get("ok") or not data.get("xray"):
        raise VpskitError("没有读到可用的 xray 配置: %s" % (data.get("errors") or "xray config missing"))

    xray = data["xray"]
    clients = []
    seen = set()
    for item in xray.get("clients") or []:
        email = str(item.get("email") or "main").strip() or "main"
        if email in seen:
            email = "%s-%d" % (email, len(seen) + 1)
        seen.add(email)
        clients.append(Client(email=email, flow=str(item.get("flow") or "")))
    if not clients:
        clients = [Client("main", "xtls-rprx-vision")]

    kit = data.get("kitconf") or {}
    ss = data.get("ss") or {}
    server = data.get("server") or {}
    services = data.get("services") or {}
    traffic_active = services.get("traffic-web") == "active"
    sub_active = services.get("sub") == "active"
    traffic_port = int(server.get("PORT") or kit.get("traffic_web_port") or 19000)
    traffic_key = str(kit.get("traffic_web_key") or server.get("KEY") or "")
    traffic_enable = bool(traffic_active or server.get("PORT") or kit.get("traffic_web_port"))
    sub_enable = bool(sub_active or kit.get("sub_port") or kit.get("sub_paths") or data.get("sub_paths_from_script"))
    script_map = data.get("sub_paths_from_script") or {}
    existing_file = ""
    if isinstance(script_map, dict):
        for value in script_map.values():
            if isinstance(value, str) and value.startswith("/") and value.endswith((".yaml", ".yml")):
                existing_file = value
                break
    fallback = xray.get("fallback_upload") or xray.get("fallback_download")
    if fallback and not isinstance(fallback, dict):
        fallback = None
    if isinstance(fallback, dict):
        fallback = {
            "after_bytes": int(fallback.get("afterBytes", 0)),
            "bytes_per_sec": int(fallback.get("bytesPerSec", 0)),
            "burst_bytes_per_sec": int(fallback.get("burstBytesPerSec", 0)),
        }
    admin = [ip for ip in (data.get("jail_ignoreip") or []) if ip and not _is_private(ip)]
    reality_port = int(xray.get("port") or 443)
    ss_port = int(ss.get("port") or 40244)
    sub_port = int(kit.get("sub_port") or 8888)
    traffic_port = int(server.get("PORT") or kit.get("traffic_web_port") or 19000)
    managed = {22, reality_port, ss_port, sub_port, traffic_port}
    extra_ports = [int(p) for p in (data.get("open_tcp_ports") or []) if int(p) not in managed]
    # 去重
    admin = list(dict.fromkeys(admin))

    node = NodeConfig(
        id=node_id,
        host=host,
        ssh_alias=ssh_alias,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        title=title or str(kit.get("title") or server.get("TITLE") or node_id),
        profile="strict",
        has_v6="auto",
        quota_gb=int(kit.get("quota_gb") or server.get("CAP_GB") or 500),
        quota_anchor_day=int(kit.get("anchor_day") or 29),
        daily_alert_gb=int(kit.get("daily_alert_gb") or server.get("DAILY_ALERT_GB") or 20),
        daily_hard_gb=int(kit.get("daily_hard_gb") or server.get("DAILY_HARD_GB") or 30),
        admin_ips=admin,
        clients=clients,
        reality_port=reality_port,
        reality_dest=str(xray.get("dest") or "www.iana.org:443"),
        reality_server_names=[str(x) for x in (xray.get("server_names") or [])],
        reality_max_time_diff=int(xray.get("max_time_diff") or 0),
        reality_fallback=fallback,
        ss_enable=bool(ss.get("port")),
        ss_port=ss_port,
        ss_method=str(ss.get("method") or "chacha20-ietf-poly1305"),
        ss_expose_v4=bool(data.get("ss_v4_listener")),
        sub_enable=sub_enable,
        sub_port=sub_port,
        sub_existing_file=existing_file,
        traffic_web_enable=traffic_enable,
        traffic_web_port=traffic_port,
        extra_web_ports=[{"port": p, "rate": 60} for p in extra_ports],
        xray_version=str(data.get("xray_version") or "26.7.28"),
    )
    node.check_ips()
    errors = node.validate()
    if errors:
        raise VpskitError("导入后的配置不合法:\n  - " + "\n  - ".join(errors))

    paths = NodePaths(root, node_id).ensure()
    secrets = {
        "version": 1,
        "reality": {
            "private_key": str(xray.get("private_key") or ""),
            "public_key": "",
            "short_id": str((xray.get("short_ids") or [""])[0]),
        },
        "ss_password": str(ss.get("password") or ""),
        "traffic_web_key": traffic_key,
        "clients": {},
    }
    if not secrets["reality"]["private_key"]:
        raise VpskitError("xray 配置里没有 privateKey")
    _, pub = keypair_from_private(secrets["reality"]["private_key"])
    secrets["reality"]["public_key"] = pub
    if not secrets["reality"]["short_id"]:
        raise VpskitError("xray 配置里没有 shortIds；无法导入（不会自动改线上）")
    if not secrets["traffic_web_key"]:
        warn("没有读到流量页 key；导入后 apply 会生成新的 key（会改变现有 URL）")
    if not traffic_enable:
        warn("现网 traffic-web 未运行，且没读到端口配置；将按 traffic_web_enable: false 导入")

    sub_paths = _sub_paths(data, clients)
    for idx, client in enumerate(clients):
        src = (xray.get("clients") or [])[idx] if idx < len(xray.get("clients") or []) else {}
        uuid = str(src.get("uuid") or "")
        if not uuid:
            raise VpskitError("client %s 没有 UUID" % client.email)
        subscribed = sub_paths.get(client.email)
        if not subscribed:
            subscribed = random_sub_path()
            warn("client %s 没有找到原订阅路径，已生成新的（apply 后会改变该用户的订阅 URL）" % client.email)
        secrets["clients"][client.email] = {"uuid": uuid, "sub_path": subscribed}

    if dry_run:
        info("dry-run：不写文件")
        _print_summary(node, secrets)
        return {"node": node, "secrets": secrets, "written": False}

    # 先检查 secrets 是否会冲突，再写 nodes.yaml
    if paths.secrets.exists() and not force:
        raise VpskitError("state/%s/secrets.json 已存在；如需覆盖加 --force" % node_id)

    # 写 nodes.yaml
    nodes_path = root / "nodes.yaml"
    if nodes_path.exists():
        try:
            raw = yaml.safe_load(nodes_path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            raise VpskitError("解析现有 nodes.yaml 失败: %s" % exc) from exc
        if not isinstance(raw, dict):
            raise VpskitError("现有 nodes.yaml 顶层不是 mapping")
        if node_id in (raw.get("nodes") or {}) and not force:
            raise VpskitError("nodes.yaml 里已有节点 %s；如需覆盖加 --force" % node_id)
        backup = nodes_path.with_suffix(".yaml.bak.%s" % time.strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(nodes_path, backup)
        raw.setdefault("nodes", {})[node_id] = _node_dict(node)
        _write_nodes(nodes_path, raw)
        info("nodes.yaml 已更新（备份: %s）" % backup.name)
    else:
        raw = {
            "version": 1,
            "defaults": {
                "ssh_user": "root",
                "ssh_port": 22,
                "profile": "strict",
                "has_v6": "auto",
            },
            "panel": {"listen": "127.0.0.1", "port": 8787, "refresh_seconds": 30},
            "nodes": {node_id: _node_dict(node)},
        }
        _write_nodes(nodes_path, raw)
        info("nodes.yaml 已创建")

    # 写 secrets
    paths.secrets.write_text(json.dumps(secrets, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    import os

    os.chmod(paths.secrets, 0o600)
    # 补齐派生字段（public_key/其他客户端）
    secrets = ensure_secrets(node, paths.secrets)
    _print_summary(node, secrets)
    return {"node": node, "secrets": secrets, "written": True}


def _node_dict(node: NodeConfig) -> Dict[str, Any]:
    return {
        "host": node.host,
        "ssh_alias": node.ssh_alias,
        "ssh_user": node.ssh_user,
        "ssh_port": node.ssh_port,
        "ssh_key": node.ssh_key,
        "title": node.display_title,
        "profile": node.profile,
        "has_v6": node.has_v6,
        "quota_gb": node.quota_gb,
        "quota_anchor_day": node.quota_anchor_day,
        "daily_alert_gb": node.daily_alert_gb,
        "daily_hard_gb": node.daily_hard_gb,
        "admin_ips": node.admin_ips,
        "clients": [{"email": c.email, "flow": c.flow} for c in node.clients],
        "reality_port": node.reality_port,
        "reality_dest": node.reality_dest,
        "reality_server_names": node.reality_server_names,
        "reality_max_time_diff": node.reality_max_time_diff,
        "reality_fallback": node.reality_fallback,
        "ss_enable": node.ss_enable,
        "ss_port": node.ss_port,
        "ss_method": node.ss_method,
        "ss_expose_v4": node.ss_expose_v4,
        "sub_enable": node.sub_enable,
        "sub_port": node.sub_port,
        "sub_existing_file": node.sub_existing_file,
        "sub_allow_ips": node.sub_allow_ips,
        "traffic_web_enable": node.traffic_web_enable,
        "traffic_web_port": node.traffic_web_port,
        "traffic_web_allow_ips": node.traffic_web_allow_ips,
        "extra_web_ports": node.extra_web_ports,
        "ssh_harden": node.ssh_harden,
        "sysctl": node.sysctl,
        "auto_updates": node.auto_updates,
        "firewall_guard_seconds": node.firewall_guard_seconds,
        "xray_version": node.xray_version,
        "xray_download_base": node.xray_download_base,
        "smtp_host": node.smtp_host,
        "smtp_port": node.smtp_port,
        "mail_user": node.mail_user,
        "mail_pass_env": node.mail_pass_env,
        "mail_to": node.mail_to,
        "selfheal_enable": node.selfheal_enable,
        "selfheal_mem_avail_kb": node.selfheal_mem_avail_kb,
        "selfheal_xray_rss_kb": node.selfheal_xray_rss_kb,
        "selfheal_min_interval_days": node.selfheal_min_interval_days,
        "autoban_enable": node.autoban_enable,
        "autoban_thresh_mb": node.autoban_thresh_mb,
        "autoban_strikes": node.autoban_strikes,
        "traffic_snapshot_keep_days": node.traffic_snapshot_keep_days,
    }


def _write_nodes(path: Path, raw: Dict[str, Any]) -> None:
    text = yaml.safe_dump(raw, allow_unicode=True, sort_keys=False)
    path.write_text(
        "# vpskit 节点清单（由 vpskit adopt 生成/更新）\n"
        "# 秘密不在这里；见 state/<node>/secrets.json（0600，勿提交）。\n" + text,
        encoding="utf-8",
    )
    import os

    os.chmod(path, 0o600)


def _print_summary(node: NodeConfig, secrets: Dict[str, Any]) -> None:
    step("导入结果：%s" % node.id)
    detail("host=%s title=%s clients=%s" % (node.host, node.display_title, ", ".join(c.email for c in node.clients)))
    detail("REALITY dest=%s port=%s shortId=%s" % (node.reality_dest, node.reality_port, secrets["reality"]["short_id"]))
    detail("SS=%s port=%s / sub=%s port=%s / traffic=%s port=%s" % (
        node.ss_enable, node.ss_port, node.sub_enable, node.sub_port, node.traffic_web_enable, node.traffic_web_port
    ))
    if node.ss_enable:
        detail("SS expose_v4=%s" % node.ss_expose_v4)
    if node.extra_web_ports:
        detail("保留的额外端口: %s" % ", ".join(str(x["port"]) for x in node.extra_web_ports))
    s = summary(node, secrets)
    detail("指纹: reality_pub=%s ss=%s traffic=%s" % (
        s["reality_public"], s["ss_password"], s["traffic_web_key"]
    ))
    for email, item in s["clients"].items():
        detail("  %s uuid=%s sub_path=%s" % (email, item["uuid"], item["sub_path"]))
    ok("秘密已写到 state/%s/secrets.json（0600）" % node.id)
    warn("下一步先 `vpskit plan %s` 看 diff；确认后再 apply。不要直接覆盖生产。" % node.id)
