"""把节点配置 + 秘密渲染成可部署的文件清单（确定性、幂等）。

render 是纯函数：同样的 node + secrets + options 必须得到逐字节相同的结果。
时间戳、随机数、主机探测结果都不进入被部署的文件。
"""
from __future__ import annotations

import base64
import ipaddress
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

from . import __version__
from .config import NodeConfig
from .secrets import client_sub_path, client_uuid, secret_values
from .util import VpskitError, ensure_dir, sha256_bytes

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

SERVICE_FILES = [
    ("opt/traffic/server.py", "/opt/traffic/server.py", 0o644, "root", "root"),
    ("opt/traffic/monitor.py", "/opt/traffic/monitor.py", 0o644, "root", "root"),
    ("opt/traffic/autoban.py", "/opt/traffic/autoban.py", 0o644, "root", "root"),
    ("opt/traffic/audit_auth.py", "/opt/traffic/audit_auth.py", 0o644, "root", "root"),
    ("opt/traffic/unattr.py", "/opt/traffic/unattr.py", 0o644, "root", "root"),
    ("opt/sub/sub.py", "/opt/sub/sub.py", 0o644, "root", "root"),
    ("opt/ops/ops", "/usr/local/bin/ops", 0o755, "root", "root"),
    ("opt/ops/xray_selfheal.sh", "/opt/ops/xray_selfheal.sh", 0o755, "root", "root"),
    ("opt/ops/vpskit-status.py", "/usr/local/bin/vpskit-status", 0o755, "root", "root"),
    ("opt/traffic/traffic-snapshot.sh", "/usr/local/bin/traffic-snapshot.sh", 0o755, "root", "root"),
]

UNIT_FILES = [
    "xray.service",
    "ss-server.service",
    "traffic-web.service",
    "traffic-monitor.service",
    "traffic-monitor.timer",
    "unattr.service",
    "unattr.timer",
    "traffic-snapshot.service",
    "traffic-snapshot.timer",
    "sub.service",
    "autoban.service",
    "autoban.timer",
    "xray-selfheal.service",
    "xray-selfheal.timer",
]


@dataclass
class FileSpec:
    path: str
    content: bytes
    mode: int = 0o644
    owner: str = "root"
    group: str = "root"
    note: str = ""

    @property
    def source(self) -> str:
        return self.path.lstrip("/")

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.content)


@dataclass
class RenderOptions:
    has_v6: bool = True
    addresses: Dict[str, str] = field(default_factory=dict)
    fail2ban_banaction: str = "nftables-multiport"
    fail2ban_allports: str = "nftables-allports"
    include_services: bool = True


@dataclass
class RenderResult:
    node: NodeConfig
    files: List[FileSpec]
    client_import: str
    meta: Dict[str, Any]
    warnings: List[str] = field(default_factory=list)

    @property
    def by_path(self) -> Dict[str, FileSpec]:
        return {f.path: f for f in self.files}

    def manifest(self) -> List[Dict[str, Any]]:
        return [
            {
                "path": f.path,
                "source": f.source,
                "mode": f.mode,
                "owner": f.owner,
                "group": f.group,
                "sha256": f.sha256,
                "size": len(f.content),
            }
            for f in sorted(self.files, key=lambda x: x.path)
        ]


# ---------------------------------------------------------------- helpers


def _text(path: str, text: str, mode: int = 0o644, owner: str = "root", group: str = "root") -> FileSpec:
    if not text.endswith("\n"):
        text += "\n"
    return FileSpec(path=path, content=text.encode("utf-8"), mode=mode, owner=owner, group=group)


def _json(path: str, data: Any, mode: int = 0o644, owner: str = "root", group: str = "root") -> FileSpec:
    return _text(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n", mode, owner, group)


ASSETS = Path(__file__).resolve().parent / "assets"


def _read(root: Path, rel: str) -> bytes:
    path = root / rel
    if not path.exists():
        path = ASSETS / rel
    if not path.exists():
        raise VpskitError("缺少工具源文件: %s（也没有打包进 %s）" % (root / rel, ASSETS / rel))
    return path.read_bytes()


def _split_cidrs(values: Iterable[str]) -> Tuple[List[str], List[str]]:
    v4: List[str] = []
    v6: List[str] = []
    for raw in values:
        net = ipaddress.ip_network(str(raw), strict=False)
        (v4 if net.version == 4 else v6).append(str(net))
    return v4, v6


def _nft_set(name: str, fam: str, values: List[str], *, interval: bool = True) -> List[str]:
    if not values:
        return []
    type_name = "ipv4_addr" if fam == "ip" else "ipv6_addr"
    lines = [
        "\tset %s {" % name,
        "\t\ttype %s" % type_name,
    ]
    if interval:
        lines.append("\t\tflags interval")
    lines.append("\t\telements = { %s }" % ", ".join(values))
    lines.append("\t}")
    return lines


def _web_entries(node: NodeConfig, fam: str) -> List[Tuple[int, int, Optional[str], bool]]:
    """返回 (port, rate, allow_set, deny_all)。

    allow_set: 该协议族有白名单时，规则只允许集合内来源。
    deny_all: 配置了白名单但该协议族没有任何条目 -> 该协议族一律拒绝。
    """
    v4 = fam == "ip"
    sub = _split_cidrs(node.sub_allow_ips)[0 if v4 else 1]
    web = _split_cidrs(node.traffic_web_allow_ips)[0 if v4 else 1]
    suffix = "4" if v4 else "6"
    entries: List[Tuple[int, int, Optional[str], bool]] = []
    if node.sub_enable:
        entries.append(
            (node.sub_port, 60, "suballow" + suffix if sub else None, bool(node.sub_allow_ips) and not sub)
        )
    if node.traffic_web_enable:
        entries.append(
            (node.traffic_web_port, 15, "weballow" + suffix if web else None, bool(node.traffic_web_allow_ips) and not web)
        )
    for item in node.extra_web_ports:
        entries.append((int(item["port"]), int(item.get("rate", 12)), None, False))
    return entries


def _nft_blocks(node: NodeConfig, has_v6: bool, opts: RenderOptions) -> str:
    """生成 nftables.conf。保持 table ip/ip6 filter + traffic 的命名，兼容 autoban/monitor。"""
    ss_on = bool(node.ss_enable and has_v6)
    admin4, admin6 = _split_cidrs(node.admin_ips)
    sub4, sub6 = _split_cidrs(node.sub_allow_ips)
    web4, web6 = _split_cidrs(node.traffic_web_allow_ips)

    v4: List[str] = [
        "table ip filter {",
        "\tset blackhole {",
        "\t\ttype ipv4_addr",
        "\t\tsize 65535",
        "\t\tflags timeout",
        "\t}",
    ]
    v4 += _nft_set("admin4", "ip", admin4)
    if node.sub_enable:
        v4 += _nft_set("suballow4", "ip", sub4)
    if node.traffic_web_enable:
        v4 += _nft_set("weballow4", "ip", web4)
    v4 += [
        "\tchain INPUT {",
        "\t\ttype filter hook input priority filter; policy drop;",
        '\t\tiif "lo" accept',
        "\t\tct state invalid drop",
        "\t\tip saddr @blackhole tcp dport $REALITY_PORT drop",
        "\t\tct state established,related accept",
        "\t\ticmp type echo-request accept",
    ]
    if admin4:
        v4.append("\t\tip saddr @admin4 tcp dport $SSH_PORT ct state new accept")
    v4 += [
        "\t\ttcp dport $SSH_PORT ct state new meter sshv4 { ip saddr timeout 10m limit rate 15/minute } accept",
        "\t\ttcp dport $SSH_PORT ct state new drop",
    ]
    if node.profile == "strict":
        v4 += [
            "\t\ttcp dport $REALITY_PORT ct state new meter scan443v4 { ip saddr timeout 10m limit rate 120/minute burst 30 packets } accept",
            "\t\ttcp dport $REALITY_PORT ct state new drop",
        ]
    v4.append("\t\ttcp dport $REALITY_PORT accept")
    if ss_on and node.ss_expose_v4:
        v4 += [
            "\t\ttcp dport $SS_PORT accept",
            "\t\tudp dport $SS_PORT accept",
        ]
    for port, rate, allow, deny_all in _web_entries(node, "ip"):
        if deny_all:
            v4.append("\t\ttcp dport %d ct state new drop" % port)
            continue
        if node.profile == "strict":
            if allow:
                v4.append(
                    "\t\tip saddr @%s tcp dport %d ct state new meter webrate%dv4 { ip saddr timeout 10m limit rate %d/minute burst 4 packets } accept"
                    % (allow, port, port, rate)
                )
            else:
                v4.append(
                    "\t\ttcp dport %d ct state new meter webrate%dv4 { ip saddr timeout 10m limit rate %d/minute burst 4 packets } accept"
                    % (port, port, rate)
                )
            v4.append("\t\ttcp dport %d ct state new drop" % port)
        else:
            if allow:
                v4.append("\t\tip saddr @%s tcp dport %d ct state new accept" % (allow, port))
                v4.append("\t\ttcp dport %d ct state new drop" % port)
            else:
                v4.append("\t\ttcp dport %d ct state new accept" % port)
    v4 += [
        "\t}",
        "\tchain FORWARD { type filter hook forward priority filter; policy drop; }",
        "\tchain OUTPUT {",
        "\t\ttype filter hook output priority filter; policy accept;",
        "\t\tip daddr @blackhole tcp sport $REALITY_PORT drop",
        "\t}",
        "}",
    ]

    traffic4 = [
        "table ip traffic {",
        "\tset ss_clients {",
        "\t\ttype ipv4_addr",
        "\t\tsize 65535",
        "\t\tflags dynamic,timeout",
        "\t\tcounter",
        "\t\ttimeout 6h",
        "\t}",
        "\tchain count_in {",
        "\t\ttype filter hook input priority filter - 10; policy accept;",
        "\t\tmeta l4proto tcp tcp dport $REALITY_PORT update @ss_clients { ip saddr timeout 6h }",
        "\t\tmeta l4proto udp udp dport $REALITY_PORT update @ss_clients { ip saddr timeout 6h }",
        "\t}",
        "\tchain count_out {",
        "\t\ttype filter hook output priority filter - 10; policy accept;",
        "\t\tmeta l4proto tcp tcp sport $REALITY_PORT update @ss_clients { ip daddr timeout 6h }",
        "\t\tmeta l4proto udp udp sport $REALITY_PORT update @ss_clients { ip daddr timeout 6h }",
        "\t}",
        "}",
    ]

    blocks: List[str] = v4 + traffic4

    if has_v6:
        v6: List[str] = [
            "table ip6 filter {",
            "\tset blackhole6 {",
            "\t\ttype ipv6_addr",
            "\t\tsize 65535",
            "\t\tflags timeout",
            "\t}",
        ]
        v6 += _nft_set("admin6", "ip6", admin6)
        if node.sub_enable:
            v6 += _nft_set("suballow6", "ip6", sub6)
        if node.traffic_web_enable:
            v6 += _nft_set("weballow6", "ip6", web6)
        v6 += [
            "\tchain INPUT {",
            "\t\ttype filter hook input priority filter; policy drop;",
            '\t\tiif "lo" accept',
            "\t\tct state invalid drop",
            "\t\tip6 saddr @blackhole6 tcp dport $REALITY_PORT drop",
            "\t\tct state established,related accept",
            "\t\ticmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply, nd-neighbor-solicit, nd-neighbor-advert } accept",
        ]
        if admin6:
            v6.append("\t\tip6 saddr @admin6 tcp dport $SSH_PORT ct state new accept")
        v6 += [
            "\t\ttcp dport $SSH_PORT ct state new meter sshv6 { ip6 saddr timeout 10m limit rate 15/minute } accept",
            "\t\ttcp dport $SSH_PORT ct state new drop",
        ]
        if node.profile == "strict":
            v6 += [
                "\t\ttcp dport $REALITY_PORT ct state new meter scan443v6 { ip6 saddr timeout 10m limit rate 120/minute burst 30 packets } accept",
                "\t\ttcp dport $REALITY_PORT ct state new drop",
            ]
        v6.append("\t\ttcp dport $REALITY_PORT accept")
        if ss_on:
            v6 += [
                "\t\ttcp dport $SS_PORT accept",
                "\t\tudp dport $SS_PORT accept",
            ]
        for port, rate, allow, deny_all in _web_entries(node, "ip6"):
            if deny_all:
                v6.append("\t\ttcp dport %d ct state new drop" % port)
                continue
            if node.profile == "strict":
                if allow:
                    v6.append(
                        "\t\tip6 saddr @%s tcp dport %d ct state new meter webrate%dv6 { ip6 saddr timeout 10m limit rate %d/minute burst 4 packets } accept"
                        % (allow, port, port, rate)
                    )
                else:
                    v6.append(
                        "\t\ttcp dport %d ct state new meter webrate%dv6 { ip6 saddr timeout 10m limit rate %d/minute burst 4 packets } accept"
                        % (port, port, rate)
                    )
                v6.append("\t\ttcp dport %d ct state new drop" % port)
            else:
                if allow:
                    v6.append("\t\tip6 saddr @%s tcp dport %d ct state new accept" % (allow, port))
                    v6.append("\t\ttcp dport %d ct state new drop" % port)
                else:
                    v6.append("\t\ttcp dport %d ct state new accept" % port)
        v6 += [
            "\t}",
            "\tchain FORWARD { type filter hook forward priority filter; policy drop; }",
            "\tchain OUTPUT {",
            "\t\ttype filter hook output priority filter; policy accept;",
            "\t\tip6 daddr @blackhole6 tcp sport $REALITY_PORT drop",
            "\t}",
            "}",
        ]
        traffic6 = [
            "table ip6 traffic6 {",
            "\tset ss_clients {",
            "\t\ttype ipv6_addr",
            "\t\tsize 65535",
            "\t\tflags dynamic,timeout",
            "\t\tcounter",
            "\t\ttimeout 6h",
            "\t}",
        ]
        if ss_on:
            traffic6 += [
                "\tset ss_node {",
                "\t\ttype ipv6_addr",
                "\t\tsize 65535",
                "\t\tflags dynamic,timeout",
                "\t\tcounter",
                "\t\ttimeout 6h",
                "\t}",
            ]
        traffic6 += [
            "\tchain count_in {",
            "\t\ttype filter hook input priority filter - 10; policy accept;",
            "\t\tmeta l4proto tcp tcp dport $REALITY_PORT update @ss_clients { ip6 saddr timeout 6h }",
            "\t\tmeta l4proto udp udp dport $REALITY_PORT update @ss_clients { ip6 saddr timeout 6h }",
        ]
        if ss_on:
            traffic6 += [
                "\t\tmeta l4proto tcp tcp dport $SS_PORT update @ss_node { ip6 saddr timeout 6h }",
                "\t\tmeta l4proto udp udp dport $SS_PORT update @ss_node { ip6 saddr timeout 6h }",
            ]
        traffic6 += [
            "\t}",
            "\tchain count_out {",
            "\t\ttype filter hook output priority filter - 10; policy accept;",
            "\t\tmeta l4proto tcp tcp sport $REALITY_PORT update @ss_clients { ip6 daddr timeout 6h }",
            "\t\tmeta l4proto udp udp sport $REALITY_PORT update @ss_clients { ip6 daddr timeout 6h }",
        ]
        if ss_on:
            traffic6 += [
                "\t\tmeta l4proto tcp tcp sport $SS_PORT update @ss_node { ip6 daddr timeout 6h }",
                "\t\tmeta l4proto udp udp sport $SS_PORT update @ss_node { ip6 daddr timeout 6h }",
            ]
        traffic6 += ["\t}", "}"]
        blocks += v6 + traffic6

    head = [
        "#!/usr/sbin/nft -f",
        "# generated by vpskit %s — do not edit by hand" % __version__,
        "# 注意: flush ruleset 会清掉 fail2ban 的 f2b-table；vpskit apply 在加载后会重启 fail2ban。",
        "# 若本机运行 Docker，apply 会拒绝执行（除非显式 --allow-flush）。",
        "flush ruleset",
        "",
        "define SSH_PORT = %d" % node.ssh_port,
        "define REALITY_PORT = %d" % node.reality_port,
    ]
    if ss_on:
        head.append("define SS_PORT = %d" % node.ss_port)
    return "\n".join(head + [""] + blocks) + "\n"


def _xray_config(node: NodeConfig, sv: Dict[str, Any]) -> Dict[str, Any]:
    clients = []
    for client in node.clients:
        item: Dict[str, Any] = {
            "id": sv["clients"][client.email]["uuid"],
            "email": client.email,
        }
        if client.flow:
            item["flow"] = client.flow
        clients.append(item)
    reality: Dict[str, Any] = {
        "show": False,
        "target": node.reality_dest,
        "serverNames": node.resolved_server_names(),
        "privateKey": sv["reality_private_key"],
        "shortIds": [sv["reality_short_id"]],
        "minClientVer": "1.0.0",
    }
    if node.reality_max_time_diff > 0:
        reality["maxTimeDiff"] = int(node.reality_max_time_diff)
    if node.reality_fallback:
        reality["limitFallbackUpload"] = {
            "afterBytes": int(node.reality_fallback["after_bytes"]),
            "bytesPerSec": int(node.reality_fallback["bytes_per_sec"]),
            "burstBytesPerSec": int(node.reality_fallback["burst_bytes_per_sec"]),
        }
        reality["limitFallbackDownload"] = dict(reality["limitFallbackUpload"])
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "::",
                "port": node.reality_port,
                "protocol": "vless",
                "settings": {"clients": clients, "decryption": "none"},
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "sockopt": {"tcpKeepAliveIdle": 90, "tcpNoDelay": True},
                    "realitySettings": reality,
                },
            }
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }


def _ss_config(node: NodeConfig, sv: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "server": "::",
        "server_port": node.ss_port,
        "password": sv["ss_password"],
        "method": node.ss_method,
        "timeout": 300,
        "fast_open": True,
        "mode": "tcp_and_udp",
        "nameserver": "1.1.1.1",
    }


def _kitconf(node: NodeConfig, sv: Dict[str, Any]) -> str:
    sub_paths = {c.email: sv["clients"][c.email]["sub_path"] for c in node.clients}
    sub_files: Dict[str, str] = {}
    sub_routes: Dict[str, str] = {}
    for c in node.clients:
        path = sv["clients"][c.email]["sub_path"]
        if node.sub_existing_file:
            sub_routes[path] = node.sub_existing_file
            continue
        emails = [x.email for x in node.clients if sv["clients"][x.email]["sub_path"] == path]
        filename = "sub-%s.yaml" % emails[0]
        sub_files[c.email] = filename
        sub_routes[path] = filename
    values = {
        "NODE_ID": node.id,
        "KIT_VERSION": __version__,
        "TITLE": node.display_title,
        "CAP_GB": node.quota_gb,
        "QUOTA_ANCHOR_DAY": node.quota_anchor_day,
        "DAILY_ALERT_GB": node.daily_alert_gb,
        "DAILY_HARD_GB": node.daily_hard_gb,
        "REALITY_PORT": node.reality_port,
        "SS_ENABLE": bool(node.ss_enable),
        "SS_PORT": node.ss_port,
        "SS_EXPOSE_V4": bool(node.ss_expose_v4),
        "TRAFFIC_WEB_ENABLE": bool(node.traffic_web_enable),
        "TRAFFIC_WEB_PORT": node.traffic_web_port,
        "TRAFFIC_WEB_KEY": sv["traffic_web_key"],
        "SUB_ENABLE": bool(node.sub_enable),
        "SUB_PORT": node.sub_port,
        "SUB_DATA_DIR": "/opt/sub/data",
        "SUB_PATHS": sub_paths,
        "SUB_FILES": sub_files,
        "SUB_ROUTES": sub_routes,
        "DATA_DIR": "/opt/traffic",
        "SUMMARY_PATH": "/opt/traffic/summary.json",
        "CHANGELOG_JSONL": "/opt/traffic/changelog.jsonl",
        "UNATTR_PATH": "/opt/traffic/unattr.json",
        "AUTOBAN_ENABLE": bool(node.autoban_enable),
        "AUTOBAN_THRESH_MB": node.autoban_thresh_mb,
        "AUTOBAN_STRIKES": node.autoban_strikes,
        "SMTP_HOST": node.smtp_host,
        "SMTP_PORT": node.smtp_port,
        "MAIL_USER": node.mail_user,
        "MAIL_PASS_ENV": node.mail_pass_env,
        "MAIL_TO": node.mail_to,
        "TRAFFIC_SNAPSHOT_KEEP_DAYS": node.traffic_snapshot_keep_days,
        "CLIENTS": [c.email for c in node.clients],
    }
    lines = [
        "# /opt/traffic/kitconf.py — generated by vpskit %s; do not edit" % __version__,
        "# 本文件含秘密，权限 0640 root:www-data。",
        "",
    ]
    for key, value in values.items():
        if isinstance(value, str):
            rendered = json.dumps(value, ensure_ascii=False)
        elif isinstance(value, bool):
            rendered = "True" if value else "False"
        else:
            rendered = json.dumps(value, ensure_ascii=False)
        lines.append("%s = %s" % (key, rendered))
    return "\n".join(lines) + "\n"


def _jail_local(node: NodeConfig, opts: RenderOptions) -> str:
    ignore = ["127.0.0.1/8", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    ignore += [ip for ip in node.admin_ips if ip not in ignore]
    return "\n".join(
        [
            "# generated by vpskit %s; do not edit" % __version__,
            "[DEFAULT]",
            "backend = systemd",
            "ignoreip = " + " ".join(ignore),
            "bantime = 1h",
            "findtime = 10m",
            "maxretry = 3",
            "banaction = " + opts.fail2ban_banaction,
            "banaction_allports = " + opts.fail2ban_allports,
            "",
            "[sshd]",
            "enabled = true",
            "port = %d" % node.ssh_port,
            "filter = sshd",
            "maxretry = 3",
            "findtime = 10m",
            "bantime = 1h",
            "",
            "[recidive]",
            "enabled = true",
            "backend = polling",
            "logpath = /var/log/fail2ban.log",
            "banaction = %(banaction_allports)s",
            "bantime = 1w",
            "findtime = 1d",
            "maxretry = 3",
            "",
        ]
    )


def _sysctl(node: NodeConfig, has_v6: bool) -> str:
    lines = [
        "# generated by vpskit %s" % __version__,
        "net.core.default_qdisc = fq",
        "net.ipv4.tcp_congestion_control = bbr",
        "net.ipv4.tcp_syncookies = 1",
        "net.ipv4.tcp_fastopen = 3",
        "net.ipv4.tcp_mtu_probing = 1",
        "net.core.somaxconn = 4096",
        "net.ipv4.tcp_max_syn_backlog = 8192",
        "net.ipv4.ip_local_port_range = 10240 65000",
        "net.netfilter.nf_conntrack_max = 65536",
        "net.netfilter.nf_conntrack_tcp_timeout_established = 600",
    ]
    if has_v6:
        lines.append("net.ipv6.conf.all.disable_ipv6 = 0")
    return "\n".join(lines) + "\n"


def _sshd_hardening() -> str:
    return "\n".join(
        [
            "# generated by vpskit %s" % __version__,
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "PermitEmptyPasswords no",
            "PermitRootLogin prohibit-password",
            "MaxAuthTries 3",
            "LoginGraceTime 20",
            "X11Forwarding no",
            "AllowAgentForwarding no",
            "ClientAliveInterval 30",
            "ClientAliveCountMax 3",
            "UseDNS no",
            "",
        ]
    )


def _auto_upgrades() -> str:
    return "\n".join(
        [
            'APT::Periodic::Update-Package-Lists "1";',
            'APT::Periodic::Download-Upgradeable-Packages "1";',
            'APT::Periodic::AutocleanInterval "7";',
            'APT::Periodic::Unattended-Upgrade "1";',
            "",
        ]
    )


def _logrotate(node: NodeConfig) -> str:
    paths = [
        "/opt/traffic/autoban.log",
        "/opt/ops/selfheal.log",
        "/root/ops/audit-auth.log",
        "/root/ops/kit-install.log",
    ]
    return "\n".join(
        [
            "# generated by vpskit %s" % __version__,
            " ".join(paths) + " {",
            "    weekly",
            "    rotate 8",
            "    compress",
            "    delaycompress",
            "    missingok",
            "    notifempty",
            "    copytruncate",
            "}",
            "",
        ]
    )


def _journald() -> str:
    return "\n".join(
        [
            "# generated by vpskit %s" % __version__,
            "[Journal]",
            "SystemMaxUse=200M",
            "SystemMaxFileSize=50M",
            "MaxRetentionSec=2week",
            "",
        ]
    )


def _node_info(node: NodeConfig, opts: RenderOptions) -> str:
    info = {
        "node_id": node.id,
        "title": node.display_title,
        "kit_version": __version__,
        "host": node.host,
        "ipv4": opts.addresses.get("ipv4", ""),
        "ipv6": opts.addresses.get("ipv6", "") if opts.has_v6 else "",
        "reality_port": node.reality_port,
        "sub_port": node.sub_port if node.sub_enable else None,
        "traffic_web_port": node.traffic_web_port if node.traffic_web_enable else None,
        "clients": [c.email for c in node.clients],
    }
    if yaml is None:
        return json.dumps(info, indent=2, ensure_ascii=False) + "\n"
    return yaml.safe_dump(info, allow_unicode=True, sort_keys=False)


def _vless_uri(node: NodeConfig, sv: Dict[str, Any], email: str, name: str) -> str:
    client = sv["clients"][email]
    params = {
        "encryption": "none",
        "security": "reality",
        "sni": node.resolved_server_names()[0],
        "fp": "chrome",
        "pbk": sv["reality_public_key"],
        "sid": sv["reality_short_id"],
        "type": "tcp",
    }
    flow = next((c.flow for c in node.clients if c.email == email), "")
    if flow:
        params["flow"] = flow
    query = "&".join("%s=%s" % (k, quote(str(v), safe="")) for k, v in params.items())
    host = node.host
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    return "vless://%s@%s:%d?%s#%s" % (
        client["uuid"],
        host,
        node.reality_port,
        query,
        quote(name, safe=""),
    )


def _ss_uri(node: NodeConfig, sv: Dict[str, Any], name: str, server: str) -> str:
    userinfo = base64.b64encode(
        ("%s:%s" % (node.ss_method, sv["ss_password"])).encode()
    ).decode().rstrip("=")
    host = server
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    return "ss://%s@%s:%d#%s" % (userinfo, host, node.ss_port, quote(name, safe=""))


def _default_subscription(
    node: NodeConfig,
    sv: Dict[str, Any],
    emails: List[str],
    opts: RenderOptions,
) -> Dict[str, Any]:
    server = opts.addresses.get("ipv4") or node.host
    proxies: List[Dict[str, Any]] = []
    for email in emails:
        client = sv["clients"][email]
        name = node.display_title if len(emails) == 1 else "%s-%s" % (node.display_title, email)
        proxy: Dict[str, Any] = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": node.reality_port,
            "uuid": client["uuid"],
            "network": "tcp",
            "tls": True,
            "udp": True,
            "servername": node.resolved_server_names()[0],
            "reality-opts": {
                "public-key": sv["reality_public_key"],
                "short-id": sv["reality_short_id"],
            },
            "client-fingerprint": "chrome",
        }
        flow = next((c.flow for c in node.clients if c.email == email), "")
        if flow:
            proxy["flow"] = flow
        proxies.append(proxy)
    v6 = opts.addresses.get("ipv6", "")
    if node.ss_enable and opts.has_v6 and v6:
        proxies.append(
            {
                "name": node.display_title + " SS",
                "type": "ss",
                "server": v6,
                "port": node.ss_port,
                "cipher": node.ss_method,
                "password": sv["ss_password"],
                "udp": True,
            }
        )
    names = [p["name"] for p in proxies]
    groups = [
        {"name": "PROXY", "type": "select", "proxies": names + ["AUTO", "DIRECT"]},
        {
            "name": "AUTO",
            "type": "url-test",
            "proxies": names,
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
        },
    ]
    rules = [
        "DOMAIN-SUFFIX,local,DIRECT",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT",
        "MATCH,PROXY",
    ]
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "unified-delay": True,
        "tcp-concurrent": True,
        "profile": {"store-selected": True, "store-fake-ip": True},
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["223.5.5.5", "119.29.29.29"],
            "fallback": ["1.1.1.1", "8.8.8.8"],
            "fallback-filter": {"geoip": True, "geoip-code": "CN"},
        },
        "proxies": proxies,
        "proxy-groups": groups,
        "rules": rules,
    }


def _subscription(
    node: NodeConfig,
    sv: Dict[str, Any],
    emails: List[str],
    opts: RenderOptions,
) -> str:
    if yaml is None:
        raise VpskitError("需要 PyYAML 才能生成订阅")
    first = emails[0]
    if node.sub_template:
        template = Path(node.sub_template).expanduser().read_text(encoding="utf-8")
        data = _default_subscription(node, sv, emails, opts)
        proxies_yaml = yaml.safe_dump(data["proxies"], allow_unicode=True, sort_keys=False).rstrip()
        groups_yaml = yaml.safe_dump(data["proxy-groups"], allow_unicode=True, sort_keys=False).rstrip()
        rules_yaml = yaml.safe_dump(data["rules"], allow_unicode=True, sort_keys=False).rstrip()
        text = (
            template.replace("{{PROXIES}}", proxies_yaml)
            .replace("{{PROXY_GROUPS}}", groups_yaml)
            .replace("{{RULES}}", rules_yaml)
            .replace("{{NODE_NAME}}", node.display_title)
            .replace("{{SERVER}}", opts.addresses.get("ipv4") or node.host)
            .replace("{{PORT}}", str(node.reality_port))
            .replace("{{UUID}}", sv["clients"][first]["uuid"])
            .replace("{{PUBLIC_KEY}}", sv["reality_public_key"])
            .replace("{{SHORT_ID}}", sv["reality_short_id"])
            .replace("{{SNI}}", node.resolved_server_names()[0])
            .replace("{{SS_SERVER}}", opts.addresses.get("ipv6", ""))
            .replace("{{SS_PORT}}", str(node.ss_port))
            .replace("{{SS_PASSWORD}}", sv["ss_password"])
        )
        try:
            yaml.safe_load(text)
        except Exception as exc:
            raise VpskitError("自定义订阅模板渲染后不是合法 YAML: %s" % exc) from exc
        return text if text.endswith("\n") else text + "\n"
    data = _default_subscription(node, sv, emails, opts)
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False)


def _client_import(node: NodeConfig, sv: Dict[str, Any], opts: RenderOptions) -> str:
    lines = [
        "# %s 客户端导入卡" % node.display_title,
        "",
        "> 本文件含秘密，权限 0600；不要上传 Git，不要发给别人。",
        "",
        "- 节点: `%s` (%s)" % (node.id, node.host),
        "- IPv4: `%s`  IPv6: `%s`" % (opts.addresses.get("ipv4", "?"), opts.addresses.get("ipv6", "?")),
        "- REALITY: `%s:%d`  SNI `%s`  shortId `%s`" % (
            node.host, node.reality_port, node.resolved_server_names()[0], sv["reality_short_id"]
        ),
        "- 公钥: `%s`" % sv["reality_public_key"],
        "",
        "## 每个用户的 VLESS URI",
        "",
    ]
    for client in node.clients:
        lines += [
            "### %s" % client.email,
            "",
            "```",
            _vless_uri(node, sv, client.email, "%s-%s" % (node.display_title, client.email)),
            "```",
            "",
        ]
        if node.sub_enable:
            lines.append("- 订阅: `http://%s:%d%s`" % (
                node.host, node.sub_port, sv["clients"][client.email]["sub_path"]
            ))
        lines.append("")
    if node.ss_enable and opts.has_v6 and opts.addresses.get("ipv6"):
        lines += [
            "## 应急 SS（仅 IPv6）",
            "",
            "```",
            _ss_uri(node, sv, node.display_title + "-SS", opts.addresses["ipv6"]),
            "```",
            "",
        ]
    if node.traffic_web_enable:
        lines += [
            "## 流量页",
            "",
            "`http://%s:%d/?k=%s`" % (node.host, node.traffic_web_port, sv["traffic_web_key"]),
            "",
        ]
    return "\n".join(lines)


def render(
    node: NodeConfig,
    secrets: Dict[str, Any],
    root: Path,
    opts: Optional[RenderOptions] = None,
) -> RenderResult:
    opts = opts or RenderOptions()
    sv = secret_values(node, secrets)
    files: List[FileSpec] = []
    warnings: List[str] = []

    if node.ss_enable and not opts.has_v6:
        warnings.append("节点没有 IPv6：SS 节点跳过（这是设计约束），REALITY 仍可用")
    if node.reality_fallback:
        warnings.append(
            "reality_fallback 已启用：官方文档认为 fallback 限速本身是指纹，建议先评估；"
            "同一组参数不要在多台机器上复用。"
        )
    if node.profile == "strict" and not node.admin_ips:
        warnings.append("admin_ips 为空：管理页/SSH 没有额外白名单；建议填入家里/公司出口 IP")

    files.append(_text("/etc/nftables.conf", _nft_blocks(node, opts.has_v6, opts), 0o644))
    files.append(_json("/usr/local/etc/xray/config.json", _xray_config(node, sv), 0o644))
    if node.ss_enable and opts.has_v6:
        files.append(_json("/etc/shadowsocks-libev/config.json", _ss_config(node, sv), 0o644))
    files.append(
        _text(
            "/opt/traffic/kitconf.py",
            _kitconf(node, sv),
            0o640,
            "root",
            "www-data",
        )
    )
    if node.sub_enable and not node.sub_existing_file:
        groups: Dict[str, List[str]] = {}
        for client in node.clients:
            path = sv["clients"][client.email]["sub_path"]
            groups.setdefault(path, []).append(client.email)
        for _path, emails in groups.items():
            filename = "sub-%s.yaml" % emails[0]
            files.append(
                _text(
                    "/opt/sub/data/%s" % filename,
                    _subscription(node, sv, emails, opts),
                    0o640,
                    "root",
                    "www-data",
                )
            )
    files.append(_text("/etc/fail2ban/jail.local", _jail_local(node, opts), 0o644))
    files.append(
        _text(
            "/etc/default/xray-selfheal",
            "\n".join(
                [
                    "THRESH_AVAIL=%d" % node.selfheal_mem_avail_kb,
                    "THRESH_RSS=%d" % node.selfheal_xray_rss_kb,
                    "MIN_INTERVAL=%d" % (node.selfheal_min_interval_days * 86400),
                    "",
                ]
            ),
            0o644,
        )
    )
    if node.sysctl:
        files.append(_text("/etc/sysctl.d/99-vpskit.conf", _sysctl(node, opts.has_v6), 0o644))
    if node.ssh_harden:
        files.append(_text("/etc/ssh/sshd_config.d/99-vpskit.conf", _sshd_hardening(), 0o644))
    if node.auto_updates:
        files.append(_text("/etc/apt/apt.conf.d/20auto-upgrades", _auto_upgrades(), 0o644))
    files.append(_text("/etc/logrotate.d/vpskit", _logrotate(node), 0o644))
    files.append(_text("/etc/systemd/journald.conf.d/vpskit.conf", _journald(), 0o644))
    files.append(_text("/root/ops/kit-node-info.yaml", _node_info(node, opts), 0o644))

    if opts.include_services:
        for rel, dest, mode, owner, group in SERVICE_FILES:
            files.append(FileSpec(path=dest, content=_read(root, rel), mode=mode, owner=owner, group=group))
        for unit in UNIT_FILES:
            files.append(
                FileSpec(
                    path="/etc/systemd/system/%s" % unit,
                    content=_read(root, "units/%s" % unit),
                    mode=0o644,
                )
            )

    # 目录不需要 manifest；apply 会 mkdir -p
    meta = {
        "node_id": node.id,
        "title": node.display_title,
        "kit_version": __version__,
        "has_v6": opts.has_v6,
        "addresses": opts.addresses,
        "clients": [c.email for c in node.clients],
        "file_count": len(files),
        "warnings": warnings,
    }
    return RenderResult(
        node=node,
        files=files,
        client_import=_client_import(node, sv, opts),
        meta=meta,
        warnings=warnings,
    )


def write_build(result: RenderResult, build_dir: Path) -> Path:
    """把渲染结果写到 build/<id>/，返回 build 目录。"""
    ensure_dir(build_dir, 0o700)
    payload = build_dir / "payload"
    if payload.exists():
        shutil.rmtree(payload)
    ensure_dir(payload, 0o700)
    for spec in result.files:
        dest = payload / spec.source
        ensure_dir(dest.parent, 0o700)
        dest.write_bytes(spec.content)
        import os

        os.chmod(dest, spec.mode)
    write_json_file = build_dir / "manifest.json"
    import os

    tmp = write_json_file.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(result.manifest(), f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, write_json_file)
    (build_dir / "client-import.md").write_text(result.client_import, encoding="utf-8")
    os.chmod(build_dir / "client-import.md", 0o600)
    (build_dir / "meta.json").write_text(
        json.dumps(result.meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return build_dir
