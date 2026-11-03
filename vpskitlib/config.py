"""nodes.yaml 的加载、合并、校验。"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .util import VpskitError, ensure_dir

try:
    import yaml
except ImportError:  # pragma: no cover - 由 CLI 给出友好提示
    yaml = None  # type: ignore

NODE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,30}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")

DEFAULT_PORTS = {
    "ssh": 22,
    "reality": 443,
    "ss": 40244,
    "sub": 8888,
    "traffic_web": 19000,
}

DEFAULTS: Dict[str, Any] = {
    "ssh_user": "root",
    "ssh_port": 22,
    "ssh_key": "",
    "profile": "strict",
    "has_v6": "auto",
    "title": "",
    "quota_gb": 500,
    "quota_anchor_day": 29,
    "daily_alert_gb": 20,
    "daily_hard_gb": 30,
    "admin_ips": [],
    "clients": [{"email": "main", "flow": "xtls-rprx-vision"}],
    "reality_port": 443,
    "reality_dest": "www.iana.org:443",
    "reality_server_names": [],
    "reality_max_time_diff": 60000,
    "reality_fallback": None,
    "ss_enable": True,
    "ss_port": 40244,
    "ss_method": "chacha20-ietf-poly1305",
    "ss_expose_v4": False,
    "sub_enable": True,
    "sub_port": 8888,
    "sub_template": "",
    "sub_allow_ips": [],
    "traffic_web_enable": True,
    "traffic_web_port": 19000,
    "traffic_web_allow_ips": [],
    "extra_web_ports": [],
    "ssh_harden": True,
    "sysctl": True,
    "auto_updates": True,
    "firewall_guard_seconds": 120,
    "xray_version": "26.7.28",
    "xray_download_base": "https://github.com/XTLS/Xray-core/releases/download",
    "smtp_host": "smtp.qq.com",
    "smtp_port": 465,
    "mail_user": "",
    "mail_pass_env": "SMTP_PASS",
    "mail_to": "",
    "selfheal_enable": True,
    "selfheal_mem_avail_kb": 204800,
    "selfheal_xray_rss_kb": 256000,
    "selfheal_min_interval_days": 7,
    "autoban_enable": True,
    "autoban_thresh_mb": 2,
    "autoban_strikes": 2,
    "traffic_snapshot_keep_days": 14,
}

# 只允许出现在 secrets.json 的字段；写在 nodes.yaml 里会被忽略并警告。
SECRET_KEYS = {
    "uuid",
    "reality_private_key",
    "reality_public_key",
    "reality_short_id",
    "ss_password",
    "traffic_web_key",
    "sub_path",
}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _networks(values: Any, field_name: str) -> List[str]:
    out: List[str] = []
    for raw in _as_list(values):
        text = str(raw).strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise VpskitError("%s 含非法 IP/CIDR: %s" % (field_name, text)) from exc
        out.append(str(net))
    return out


@dataclass
class Client:
    email: str
    flow: str = ""

    def public(self) -> Dict[str, str]:
        return {"email": self.email, "flow": self.flow}


@dataclass
class NodeConfig:
    id: str
    host: str
    ssh_alias: str = ""
    ssh_user: str = "root"
    ssh_port: int = 22
    ssh_key: str = ""
    title: str = ""
    profile: str = "strict"
    has_v6: Any = "auto"
    quota_gb: int = 500
    quota_anchor_day: int = 29
    daily_alert_gb: int = 20
    daily_hard_gb: int = 30
    admin_ips: List[str] = field(default_factory=list)
    clients: List[Client] = field(default_factory=list)
    reality_port: int = 443
    reality_dest: str = "www.iana.org:443"
    reality_server_names: List[str] = field(default_factory=list)
    reality_max_time_diff: int = 60000
    reality_fallback: Optional[Dict[str, int]] = None
    ss_enable: bool = True
    ss_port: int = 40244
    ss_method: str = "chacha20-ietf-poly1305"
    ss_expose_v4: bool = False
    sub_enable: bool = True
    sub_port: int = 8888
    sub_template: str = ""
    sub_existing_file: str = ""
    sub_allow_ips: List[str] = field(default_factory=list)
    traffic_web_enable: bool = True
    traffic_web_port: int = 19000
    traffic_web_allow_ips: List[str] = field(default_factory=list)
    extra_web_ports: List[Dict[str, int]] = field(default_factory=list)
    ssh_harden: bool = True
    sysctl: bool = True
    auto_updates: bool = True
    firewall_guard_seconds: int = 120
    xray_version: str = "26.7.28"
    xray_download_base: str = DEFAULTS["xray_download_base"]
    smtp_host: str = "smtp.qq.com"
    smtp_port: int = 465
    mail_user: str = ""
    mail_pass_env: str = "SMTP_PASS"
    mail_to: str = ""
    selfheal_enable: bool = True
    selfheal_mem_avail_kb: int = 204800
    selfheal_xray_rss_kb: int = 256000
    selfheal_min_interval_days: int = 7
    autoban_enable: bool = True
    autoban_thresh_mb: int = 2
    autoban_strikes: int = 2
    traffic_snapshot_keep_days: int = 14
    raw: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    # ---- 便捷属性 ----
    @property
    def display_title(self) -> str:
        return self.title or self.id

    @property
    def dest_host(self) -> str:
        host = self.reality_dest
        if host.startswith("["):
            return host[1:].split("]", 1)[0]
        if ":" in host:
            return host.rsplit(":", 1)[0]
        return host

    @property
    def dest_port(self) -> int:
        host = self.reality_dest
        if host.startswith("["):
            rest = host.split("]", 1)[1]
            return int(rest[1:]) if rest.startswith(":") else 443
        if ":" in host:
            try:
                return int(host.rsplit(":", 1)[1])
            except ValueError:
                return 443
        return 443

    def resolved_server_names(self) -> List[str]:
        names = [n.strip() for n in self.reality_server_names if n.strip()]
        return names or [self.dest_host]

    def ssh_args(self) -> List[str]:
        if self.ssh_alias:
            args = [self.ssh_alias]
        else:
            args = ["-p", str(self.ssh_port), "%s@%s" % (self.ssh_user, self.host)]
        if self.ssh_key:
            args = ["-i", self.ssh_key] + args
        return args

    def scp_target(self, remote_path: str) -> str:
        if self.ssh_alias:
            return "%s:%s" % (self.ssh_alias, remote_path)
        host = self.host
        if ":" in host and not host.startswith("["):
            host = "[%s]" % host
        return "%s@%s:%s" % (self.ssh_user, host, remote_path)

    def scp_args(self) -> List[str]:
        if self.ssh_alias:
            args: List[str] = []
        else:
            args = ["-P", str(self.ssh_port), "%s@%s" % (self.ssh_user, self.host)]
        if self.ssh_key:
            args = ["-i", self.ssh_key] + args
        return args

    def public_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "host": self.host,
            "title": self.display_title,
            "profile": self.profile,
            "quota_gb": self.quota_gb,
            "quota_anchor_day": self.quota_anchor_day,
            "clients": [c.public() for c in self.clients],
            "reality_port": self.reality_port,
            "ss_port": self.ss_port if self.ss_enable else None,
            "sub_enable": self.sub_enable,
            "traffic_web_enable": self.traffic_web_enable,
        }

    def validate(self) -> List[str]:
        errors: List[str] = []
        if not NODE_ID_RE.match(self.id):
            errors.append("节点 id 只能是小写字母/数字/下划线/连字符，且以字母数字开头: %r" % self.id)
        if not self.host or re.search(r"\s", self.host):
            errors.append("host 为空或含空白字符")
        if not (1 <= self.ssh_port <= 65535):
            errors.append("ssh_port 超出范围")
        if self.profile not in ("strict", "mild"):
            errors.append("profile 只能是 strict 或 mild")
        if self.has_v6 not in (True, False, "auto"):
            errors.append("has_v6 只能是 true / false / auto")
        if not (1 <= self.quota_anchor_day <= 31):
            errors.append("quota_anchor_day 必须在 1..31")
        if self.quota_gb <= 0:
            errors.append("quota_gb 必须 > 0")
        if self.daily_alert_gb <= 0 or self.daily_hard_gb < self.daily_alert_gb:
            errors.append("daily_hard_gb 必须 >= daily_alert_gb > 0")
        if not self.clients:
            errors.append("clients 至少要有 1 个")
        seen = set()
        for client in self.clients:
            if not EMAIL_RE.match(client.email):
                errors.append("client email 只允许字母数字._-: %r" % client.email)
            if client.email in seen:
                errors.append("client email 重复: %s" % client.email)
            seen.add(client.email)
            if client.flow not in ("", "xtls-rprx-vision"):
                errors.append("client %s 的 flow 只能是空或 xtls-rprx-vision" % client.email)
        for port_name, port in (
            ("reality_port", self.reality_port),
            ("ss_port", self.ss_port),
            ("sub_port", self.sub_port),
            ("traffic_web_port", self.traffic_web_port),
        ):
            if not (1 <= int(port) <= 65535):
                errors.append("%s 超出范围" % port_name)
        used = {}
        for port_name, port, enabled in (
            ("22", 22, True),
            ("reality", self.reality_port, True),
            ("ss", self.ss_port, self.ss_enable),
            ("sub", self.sub_port, self.sub_enable),
            ("traffic_web", self.traffic_web_port, self.traffic_web_enable),
        ):
            if not enabled:
                continue
            if port in used:
                errors.append("端口冲突: %s 与 %s 都使用 %s" % (used[port], port_name, port))
            used[port] = port_name
        for item in self.extra_web_ports:
            if not isinstance(item, dict) or "port" not in item:
                errors.append("extra_web_ports 每项必须是 {port, rate}")
                continue
            try:
                p = int(item["port"])
            except (TypeError, ValueError):
                errors.append("extra_web_ports.port 非整数: %r" % item.get("port"))
                continue
            if p in used:
                errors.append("extra_web_ports 端口冲突: %s" % p)
            used[p] = "extra_web"
        if self.reality_fallback is not None:
            for key in ("after_bytes", "bytes_per_sec", "burst_bytes_per_sec"):
                if key not in self.reality_fallback:
                    errors.append("reality_fallback 缺少 %s" % key)
                elif int(self.reality_fallback[key]) < 0:
                    errors.append("reality_fallback.%s 不能为负" % key)
        if self.sub_template:
            path = Path(self.sub_template).expanduser()
            if not path.exists():
                errors.append("sub_template 不存在: %s" % path)
        if self.sub_existing_file and not self.sub_existing_file.startswith("/"):
            errors.append("sub_existing_file 必须是远端绝对路径")
        if self.ssh_key:
            path = Path(self.ssh_key).expanduser()
            if not path.exists():
                errors.append("ssh_key 不存在: %s" % path)
        return errors

    def check_ips(self) -> None:
        self.admin_ips = _networks(self.admin_ips, "admin_ips")
        self.sub_allow_ips = _networks(self.sub_allow_ips, "sub_allow_ips")
        self.traffic_web_allow_ips = _networks(self.traffic_web_allow_ips, "traffic_web_allow_ips")


@dataclass
class PanelConfig:
    listen: str = "127.0.0.1"
    port: int = 8787
    refresh_seconds: int = 30
    token: str = ""
    share_token: str = ""
    title: str = "vpskit"


@dataclass
class NodesConfig:
    path: Path
    nodes: Dict[str, NodeConfig]
    panel: PanelConfig
    defaults: Dict[str, Any]

    def get(self, node_id: str) -> NodeConfig:
        if node_id not in self.nodes:
            raise VpskitError("未知节点: %s（可用: %s）" % (node_id, ", ".join(sorted(self.nodes)) or "无"))
        return self.nodes[node_id]


def _bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y")


def _node_from_dict(node_id: str, data: Dict[str, Any], defaults: Dict[str, Any]) -> NodeConfig:
    merged: Dict[str, Any] = dict(defaults)
    merged.update(data or {})
    warnings: List[str] = []

    for key in list(merged):
        if key in SECRET_KEYS:
            warnings.append("nodes.yaml 中出现秘密字段 %r，已忽略；秘密请放 state/<id>/secrets.json" % key)
            merged.pop(key, None)

    clients_raw = merged.get("clients") or DEFAULTS["clients"]
    clients: List[Client] = []
    for item in clients_raw:
        if isinstance(item, str):
            clients.append(Client(email=item, flow=""))
        elif isinstance(item, dict):
            email = str(item.get("email") or "").strip()
            flow = str(item.get("flow") or "").strip()
            clients.append(Client(email=email, flow=flow))
        else:
            raise VpskitError("节点 %s 的 clients 项格式错误: %r" % (node_id, item))

    fallback = merged.get("reality_fallback")
    if isinstance(fallback, dict):
        fallback = {
            "after_bytes": int(fallback.get("after_bytes", 0)),
            "bytes_per_sec": int(fallback.get("bytes_per_sec", 0)),
            "burst_bytes_per_sec": int(fallback.get("burst_bytes_per_sec", 0)),
        }
    elif fallback is False or fallback is None:
        fallback = None
    else:
        raise VpskitError("节点 %s 的 reality_fallback 必须是 dict 或 false" % node_id)

    extra_web = []
    for item in _as_list(merged.get("extra_web_ports")):
        if isinstance(item, dict) and "port" in item:
            extra_web.append({"port": int(item["port"]), "rate": int(item.get("rate", 12))})
        else:
            raise VpskitError("节点 %s 的 extra_web_ports 项格式错误: %r" % (node_id, item))

    known = {
        "host", "ssh_alias", "ssh_user", "ssh_port", "ssh_key", "title", "profile", "has_v6",
        "quota_gb", "quota_anchor_day", "daily_alert_gb", "daily_hard_gb", "admin_ips", "clients",
        "reality_port", "reality_dest", "reality_server_names", "reality_max_time_diff",
        "reality_fallback", "ss_enable", "ss_port", "ss_method", "ss_expose_v4",
        "sub_enable", "sub_port", "sub_template", "sub_existing_file", "sub_allow_ips",
        "traffic_web_enable", "traffic_web_port", "traffic_web_allow_ips", "extra_web_ports",
        "ssh_harden", "sysctl", "auto_updates", "firewall_guard_seconds",
        "xray_version", "xray_download_base", "smtp_host", "smtp_port", "mail_user",
        "mail_pass_env", "mail_to", "selfheal_enable", "selfheal_mem_avail_kb",
        "selfheal_xray_rss_kb", "selfheal_min_interval_days", "autoban_enable",
        "autoban_thresh_mb", "autoban_strikes", "traffic_snapshot_keep_days",
    }
    for key in sorted(set(merged) - known):
        warnings.append("节点 %s 有未知配置项 %r（已忽略）" % (node_id, key))

    node = NodeConfig(
        id=node_id,
        host=str(merged.get("host") or "").strip(),
        ssh_alias=str(merged.get("ssh_alias") or "").strip(),
        ssh_user=str(merged.get("ssh_user") or "root").strip(),
        ssh_port=int(merged.get("ssh_port") or 22),
        ssh_key=str(merged.get("ssh_key") or "").strip(),
        title=str(merged.get("title") or "").strip(),
        profile=str(merged.get("profile") or "strict").strip(),
        has_v6=merged.get("has_v6", "auto"),
        quota_gb=int(merged.get("quota_gb") or 500),
        quota_anchor_day=int(merged.get("quota_anchor_day") or 29),
        daily_alert_gb=int(merged.get("daily_alert_gb") or 20),
        daily_hard_gb=int(merged.get("daily_hard_gb") or 30),
        admin_ips=[str(x).strip() for x in _as_list(merged.get("admin_ips")) if str(x).strip()],
        clients=clients,
        reality_port=int(merged.get("reality_port") or 443),
        reality_dest=str(merged.get("reality_dest") or "www.iana.org:443").strip(),
        reality_server_names=[str(x).strip() for x in _as_list(merged.get("reality_server_names")) if str(x).strip()],
        reality_max_time_diff=int(merged.get("reality_max_time_diff") or 0),
        reality_fallback=fallback,
        ss_enable=_bool(merged.get("ss_enable"), True),
        ss_port=int(merged.get("ss_port") or 40244),
        ss_method=str(merged.get("ss_method") or "chacha20-ietf-poly1305"),
        ss_expose_v4=_bool(merged.get("ss_expose_v4"), False),
        sub_enable=_bool(merged.get("sub_enable"), True),
        sub_port=int(merged.get("sub_port") or 8888),
        sub_template=str(merged.get("sub_template") or "").strip(),
        sub_existing_file=str(merged.get("sub_existing_file") or "").strip(),
        sub_allow_ips=[str(x).strip() for x in _as_list(merged.get("sub_allow_ips")) if str(x).strip()],
        traffic_web_enable=_bool(merged.get("traffic_web_enable"), True),
        traffic_web_port=int(merged.get("traffic_web_port") or 19000),
        traffic_web_allow_ips=[str(x).strip() for x in _as_list(merged.get("traffic_web_allow_ips")) if str(x).strip()],
        extra_web_ports=extra_web,
        ssh_harden=_bool(merged.get("ssh_harden"), True),
        sysctl=_bool(merged.get("sysctl"), True),
        auto_updates=_bool(merged.get("auto_updates"), True),
        firewall_guard_seconds=int(merged.get("firewall_guard_seconds") or 120),
        xray_version=str(merged.get("xray_version") or "26.7.28"),
        xray_download_base=str(merged.get("xray_download_base") or DEFAULTS["xray_download_base"]),
        smtp_host=str(merged.get("smtp_host") or "smtp.qq.com"),
        smtp_port=int(merged.get("smtp_port") or 465),
        mail_user=str(merged.get("mail_user") or ""),
        mail_pass_env=str(merged.get("mail_pass_env") or "SMTP_PASS"),
        mail_to=str(merged.get("mail_to") or ""),
        selfheal_enable=_bool(merged.get("selfheal_enable"), True),
        selfheal_mem_avail_kb=int(merged.get("selfheal_mem_avail_kb") or 204800),
        selfheal_xray_rss_kb=int(merged.get("selfheal_xray_rss_kb") or 256000),
        selfheal_min_interval_days=int(merged.get("selfheal_min_interval_days") or 7),
        autoban_enable=_bool(merged.get("autoban_enable"), True),
        autoban_thresh_mb=int(merged.get("autoban_thresh_mb") or 2),
        autoban_strikes=int(merged.get("autoban_strikes") or 2),
        traffic_snapshot_keep_days=int(merged.get("traffic_snapshot_keep_days") or 14),
        raw=merged,
        warnings=warnings,
    )
    node.check_ips()
    return node


def load_nodes(path: Path) -> NodesConfig:
    if yaml is None:
        raise VpskitError("需要 PyYAML：python3 -m pip install pyyaml")
    path = path.expanduser().resolve()
    if not path.exists():
        raise VpskitError("找不到 %s；先 cp nodes.example.yaml nodes.yaml 并编辑" % path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise VpskitError("解析 %s 失败: %s" % (path, exc)) from exc
    if not isinstance(raw, dict):
        raise VpskitError("%s 顶层必须是 mapping" % path)
    defaults = dict(DEFAULTS)
    defaults.update(raw.get("defaults") or {})
    nodes_raw = raw.get("nodes") or {}
    if not isinstance(nodes_raw, dict) or not nodes_raw:
        raise VpskitError("%s 里没有 nodes" % path)
    nodes: Dict[str, NodeConfig] = {}
    for node_id, data in nodes_raw.items():
        if not isinstance(data, dict):
            raise VpskitError("节点 %s 必须是 mapping" % node_id)
        node = _node_from_dict(str(node_id), data, defaults)
        errors = node.validate()
        if errors:
            raise VpskitError("节点 %s 配置有误:\n  - %s" % (node_id, "\n  - ".join(errors)))
        nodes[str(node_id)] = node
    panel_raw = raw.get("panel") or {}
    panel = PanelConfig(
        listen=str(panel_raw.get("listen") or "127.0.0.1"),
        port=int(panel_raw.get("port") or 8787),
        refresh_seconds=int(panel_raw.get("refresh_seconds") or 30),
        token=str(panel_raw.get("token") or ""),
        share_token=str(panel_raw.get("share_token") or ""),
        title=str(panel_raw.get("title") or "vpskit"),
    )
    return NodesConfig(path=path, nodes=nodes, panel=panel, defaults=defaults)


def example_node(node_id: str = "new-vps", host: str = "203.0.113.10") -> Dict[str, Any]:
    return {
        "host": host,
        "ssh_user": "root",
        "ssh_port": 22,
        "title": "新 VPS",
        "quota_gb": 500,
        "quota_anchor_day": 29,
        "admin_ips": [],
        "clients": [{"email": "main", "flow": "xtls-rprx-vision"}],
        "reality_dest": "www.iana.org:443",
        "ss_enable": True,
        "ss_port": 40244,
        "sub_enable": True,
        "sub_port": 8888,
        "traffic_web_enable": True,
        "traffic_web_port": 19000,
        "xray_version": "26.7.28",
    }


def write_nodes_template(path: Path, node_id: str = "new-vps", host: str = "203.0.113.10") -> None:
    if yaml is None:
        raise VpskitError("需要 PyYAML：python3 -m pip install pyyaml")
    ensure_dir(path.parent, 0o755)
    data = {
        "version": 1,
        "defaults": {
            "ssh_user": "root",
            "ssh_port": 22,
            "profile": "strict",
            "has_v6": "auto",
            "quota_gb": 500,
            "quota_anchor_day": 29,
            "daily_alert_gb": 20,
            "daily_hard_gb": 30,
            "admin_ips": [],
        },
        "panel": {"listen": "127.0.0.1", "port": 8787, "refresh_seconds": 30},
        "nodes": {node_id: example_node(node_id, host)},
    }
    path.write_text(
        "# vpskit 节点清单。秘密不写在这里；首次 `vpskit apply` 会生成到 state/<id>/secrets.json。\n"
        "# 详细字段见 docs/CONFIG.md。\n" + yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    import os

    os.chmod(path, 0o600)
