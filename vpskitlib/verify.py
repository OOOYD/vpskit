"""verify：从本地 + 远端两侧验证实际状态。"""
from __future__ import annotations

import datetime as _dt
import http.client
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import NodeConfig
from .remote import Remote
from .secrets import client_sub_path
from .util import VpskitError, detail, info, ok, step, warn
from .workflow import Prepared, prepare


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    critical: bool = True


@dataclass
class VerifyResult:
    node: str
    checks: List[Check] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks if c.critical)

    def add(self, name: str, ok_: bool, detail_: str = "", critical: bool = True) -> None:
        self.checks.append(Check(name, ok_, detail_, critical))


def _tcp(host: str, port: int, timeout: float = 8.0) -> tuple:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "connected"
    except OSError as exc:
        return False, "%s: %s" % (type(exc).__name__, exc)


def _http(host: str, port: int, path: str, timeout: float = 8.0) -> tuple:
    conn = None
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers={"User-Agent": "vpskit-verify"})
        resp = conn.getresponse()
        body = resp.read(200000)
        return resp.status, body
    except Exception as exc:
        return None, str(exc).encode("utf-8", "replace")
    finally:
        if conn is not None:
            conn.close()


def _service_check(v: VerifyResult, services: Dict[str, Any], name: str, *, need_enabled: bool = True) -> None:
    st = services.get(name)
    if not st:
        v.add("service:" + name, False, "未在体检结果中出现")
        return
    active = st.get("active")
    enabled = st.get("enabled")
    good = active == "active" and (not need_enabled or enabled == "enabled")
    v.add(
        "service:" + name,
        good,
        "active=%s enabled=%s" % (active, enabled),
        critical=True,
    )


def verify_node(node: NodeConfig, root: Path, remote: Remote, *, prepared: Optional[Prepared] = None) -> VerifyResult:
    info("读取 %s 的远端状态 ..." % node.id)
    remote_info = remote.inspect()
    p = prepared or prepare(node, root, info=remote_info, write=False)
    v = VerifyResult(node=node.id)
    services = remote_info.get("services") or {}

    _service_check(v, services, "xray")
    if node.traffic_web_enable:
        _service_check(v, services, "traffic-web")
    if node.sub_enable:
        _service_check(v, services, "sub")
    if node.ss_enable and p.has_v6:
        _service_check(v, services, "ss-server")
    _service_check(v, services, "fail2ban")
    _service_check(v, services, "traffic-monitor.timer")
    if node.autoban_enable:
        _service_check(v, services, "autoban.timer")
    if node.selfheal_enable:
        _service_check(v, services, "xray-selfheal.timer")
    _service_check(v, services, "traffic-snapshot.timer")

    # 文件 hash
    hashes = remote.hash_files(p.remote_paths)
    drift = []
    for spec in p.result.files:
        rh = hashes.get(spec.path)
        if not isinstance(rh, dict) or rh.get("sha256") != spec.sha256:
            drift.append(spec.path)
            continue
        if rh.get("mode") is not None and int(rh["mode"]) != int(spec.mode):
            drift.append(spec.path + "（mode）")
    v.add("files", not drift, "全部匹配" if not drift else "漂移: " + ", ".join(drift[:8]), critical=True)

    # nft 表
    try:
        tables = remote.run("nft list tables", timeout=30)
        need = ["table ip filter", "table ip traffic"]
        if p.has_v6:
            need += ["table ip6 filter", "table ip6 traffic6"]
        missing = [t for t in need if t not in tables]
        v.add("nftables", not missing, "缺少: " + ", ".join(missing) if missing else "表齐全", critical=True)
    except Exception as exc:
        v.add("nftables", False, str(exc), critical=True)

    # xray 配置 test
    xray_spec = next((f for f in p.result.files if f.path == "/usr/local/etc/xray/config.json"), None)
    if xray_spec:
        tmp = remote.temp_path("verify-xray", ".json")
        try:
            remote.upload_bytes(xray_spec.content, tmp, mode=0o600)
            remote.run("/usr/local/bin/xray run -test -config %s" % tmp, timeout=60)
            v.add("xray-config", True, "run -test 通过")
        except Exception as exc:
            v.add("xray-config", False, str(exc).splitlines()[-1])
        finally:
            remote.run("rm -f %s" % tmp, check=False, timeout=20)

    # 本机侧端口/HTTP 探测
    host = p.addresses.get("ipv4") or node.host
    good, msg = _tcp(host, node.reality_port)
    v.add("tcp:reality", good, "%s:%s %s" % (host, node.reality_port, msg), critical=True)
    if node.sub_enable:
        path = client_sub_path(p.secrets, node.clients[0].email)
        status, body = _http(host, node.sub_port, path)
        v.add(
            "http:sub",
            status == 200 and b"proxies" in body,
            "status=%s bytes=%d" % (status, len(body)),
            critical=True,
        )
    if node.traffic_web_enable:
        key = str(p.secrets.get("traffic_web_key", ""))
        status, body = _http(host, node.traffic_web_port, "/?k=" + key)
        v.add(
            "http:traffic",
            status == 200 and len(body) > 1000,
            "status=%s bytes=%d" % (status, len(body)),
            critical=True,
        )

    # summary.json 新鲜度
    try:
        raw = remote.read_text_remote("/opt/traffic/summary.json")
        summary = json.loads(raw)
        updated = str(summary.get("updated", ""))
        fresh = True
        try:
            ts = _dt.datetime.strptime(updated, "%Y-%m-%d %H:%M:%S")
            fresh = (abs((_dt.datetime.now() - ts).total_seconds()) < 1800)
        except ValueError:
            pass
        v.add("traffic-summary", bool(summary), "updated=%s%s" % (updated, "" if fresh else "（超过 30 分钟）"), critical=True)
        if not fresh:
            v.warnings.append("summary.json 超过 30 分钟未更新；检查 traffic-monitor.timer")
    except Exception as exc:
        v.add("traffic-summary", False, str(exc), critical=True)

    # fail2ban 运行
    try:
        out = remote.run("fail2ban-client status sshd", check=False, timeout=30)
        v.add("fail2ban:sshd", "Currently banned:" in out, out.strip().splitlines()[-1] if out.strip() else "no output", critical=False)
    except Exception as exc:
        v.add("fail2ban:sshd", False, str(exc), critical=False)

    if remote_info.get("docker_active"):
        v.warnings.append("Docker 正在运行；nftables flush 会清掉 Docker 规则")
    return v


def print_verify(v: VerifyResult) -> None:
    step("验证结果：%s" % v.node)
    for c in v.checks:
        mark = "✅" if c.ok else ("❌" if c.critical else "⚠️")
        detail("%s %-24s %s" % (mark, c.name, c.detail))
    for w in v.warnings:
        warn(w)
    if v.ok:
        ok("全部关键检查通过")
    else:
        warn("存在未通过的关键检查")


def verify_json(v: VerifyResult) -> Dict[str, Any]:
    return {
        "node": v.node,
        "ok": v.ok,
        "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail, "critical": c.critical} for c in v.checks],
        "warnings": v.warnings,
    }
