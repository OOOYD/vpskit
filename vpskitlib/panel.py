"""多节点只读面板：本地 HTTP + 分享 token。

默认只绑 127.0.0.1；要公网分享，放在 Caddy/Nginx 后面，并设置 panel.token。
"""
from __future__ import annotations

import hmac
import html as html_lib
import json
import os
import re
import shutil
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .config import NodesConfig, load_nodes
from .paths import NodePaths
from .secrets import client_sub_path, client_v2ray_path, load_secrets
from .status import collect_all
from .util import VpskitError, detail, info, mask_ip, warn

ASSET = Path(__file__).resolve().parent / "panel.html"


def _sub_urls(node, root: Path) -> Dict[str, Dict[str, str]]:
    """每个 client 的订阅地址（只在完整视图里给，分享视图不下发）。"""
    out: Dict[str, Dict[str, str]] = {}
    if not node or not getattr(node, "sub_enable", False):
        return out
    try:
        secrets = load_secrets(NodePaths(root, node.id).secrets)
    except Exception:
        return out
    if not secrets:
        return out
    for client in node.clients:
        try:
            clash = "http://%s:%d%s" % (node.host, node.sub_port, client_sub_path(secrets, client.email))
        except Exception:
            clash = ""
        v2ray = ""
        if "v2ray" in getattr(node, "sub_formats", ["clash"]):
            try:
                v2ray = "http://%s:%d%s" % (node.host, node.sub_port, client_v2ray_path(secrets, client.email))
            except Exception:
                v2ray = ""
        out[client.email] = {"clash": clash, "v2ray": v2ray}
    return out


def _mask_network(net: Dict[str, Any]) -> Dict[str, Any]:
    """分享视图：IP 只留前缀，避免把节点地址发给别人。"""
    out = dict(net or {})
    out["ipv4"] = [mask_ip(str(x)) for x in (out.get("ipv4") or [])]
    out["ipv6"] = [mask_ip(str(x)) for x in (out.get("ipv6") or [])]
    return out


def _share_data(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for n in results:
        item = {
            "node_id": n.get("node_id"),
            "title": n.get("title"),
            "online": n.get("online"),
            "uptime_seconds": n.get("uptime_seconds", 0),
            "load": n.get("load", []),
            "mem": n.get("mem", {}),
            "disk": n.get("disk", {}),
            "services": {
                k: {"active": v.get("active")} for k, v in (n.get("services") or {}).items()
            },
            "traffic": None,
            "changes": [],
            "error": "",
            "host": "",
            "provider": n.get("provider", ""),
            "line": n.get("line", ""),
            "purchased_on": n.get("purchased_on", ""),
            "expires_on": n.get("expires_on", ""),
            "billing_cycle": n.get("billing_cycle", ""),
            "cpu": n.get("cpu", {}),
            "network": _mask_network(n.get("network") or {}),
            "system": n.get("system", {}),
            "unattr": n.get("unattr", {}),
            "kernel": n.get("kernel", ""),
            "hostname": n.get("hostname", ""),
            "mail_to": "",
            "node_clients": [],
            "ports_cfg": {},
            "changes": [],
            "xray": (n.get("xray") or [])[:1],
            "backups": {},
        }
        t = n.get("traffic")
        if isinstance(t, dict):
            item["traffic"] = {
                "cap_gb": t.get("cap_gb"),
                "cycle_gb": t.get("cycle_gb"),
                "today_gb": t.get("today_gb"),
                "remaining_gb": t.get("remaining_gb"),
                "days": (t.get("days") or [])[-7:],
                "months": (t.get("months") or [])[-12:],
                "alerts": t.get("alerts") or [],
                "updated": t.get("updated"),
                "down_gb": t.get("down_gb"),
                "up_gb": t.get("up_gb"),
                "avg_gb": t.get("avg_gb"),
                "projected_gb": t.get("projected_gb"),
                "cycle_start": t.get("cycle_start"),
                "cycle_end": t.get("cycle_end"),
            }
        out.append(item)
    return out


_NODE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_CLIENT_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CYCLES = {"monthly", "quarterly", "halfyearly", "yearly", "biennial"}


def _clean_node_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise VpskitError("请求体必须是 JSON 对象")
    node_id = str(payload.get("id") or "").strip().lower()
    if not _NODE_ID_RE.match(node_id):
        raise VpskitError("节点 ID 只能用小写字母/数字/-/_，且以字母数字开头")
    host = str(payload.get("host") or "").strip()
    if not host or len(host) > 253 or re.search(r"\s", host):
        raise VpskitError("地址（IP 或域名）不能为空，且不能含空格")

    data: Dict[str, Any] = {"host": host, "__id__": node_id}
    title = str(payload.get("title") or "").strip()
    if title:
        data["title"] = title[:60]
    alias = str(payload.get("ssh_alias") or "").strip()
    if alias:
        data["ssh_alias"] = alias[:64]
    try:
        port = int(payload.get("ssh_port") or 22)
    except (TypeError, ValueError):
        raise VpskitError("SSH 端口必须是数字")
    if not (1 <= port <= 65535):
        raise VpskitError("SSH 端口超出范围")
    if port != 22:
        data["ssh_port"] = port
    provider = str(payload.get("provider") or "").strip()
    if provider:
        data["provider"] = provider[:60]
    line = str(payload.get("line") or "").strip()
    if line:
        data["line"] = line[:80]
    for key in ("purchased_on", "expires_on"):
        value = str(payload.get(key) or "").strip()
        if not value:
            continue
        if not _DATE_RE.match(value):
            raise VpskitError("%s 必须是 YYYY-MM-DD" % key)
        data[key] = value
    cycle = str(payload.get("billing_cycle") or "").strip().lower()
    if cycle:
        if cycle not in _CYCLES:
            raise VpskitError("billing_cycle 只能是 %s" % ", ".join(sorted(_CYCLES)))
        data["billing_cycle"] = cycle
    quota = payload.get("quota_gb")
    if quota not in (None, ""):
        try:
            quota_i = int(quota)
        except (TypeError, ValueError):
            raise VpskitError("额度必须是整数 GB")
        if quota_i <= 0 or quota_i > 100000:
            raise VpskitError("额度超出范围")
        data["quota_gb"] = quota_i
    client = str(payload.get("client") or "").strip()
    if client and client != "main":
        if not _CLIENT_RE.match(client):
            raise VpskitError("客户端名只能含字母数字 . _ -")
        data["clients"] = [{"email": client, "flow": "xtls-rprx-vision"}]
    return data


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _set_node_field(text: str, node_id: str, key: str, value: str) -> str:
    """在 nodes.yaml 的某个节点块里，改写/新增一个顶层字段，保留其余内容与注释。"""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^\s{0,4}%s\s*:\s*$" % re.escape(node_id), line):
            start = i
            break
    if start is None:
        raise VpskitError("nodes.yaml 里找不到节点 %s" % node_id)
    indent = len(lines[start]) - len(lines[start].lstrip()) + 2
    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cur = len(line) - len(line.lstrip())
        if cur < indent:
            end = i
            break
    safe = value.replace('"', '\\"')
    rendered = "%s%s: \"%s\"" % (" " * indent, key, safe)
    for i in range(start + 1, end):
        if re.match(r"^\s+%s\s*:" % re.escape(key), lines[i]):
            lines[i] = rendered
            return "\n".join(lines) + "\n"
    lines.insert(start + 1, rendered)
    return "\n".join(lines) + "\n"


def _insert_under_nodes(text: str, block_lines: List[str]) -> str:
    """把新节点的 YAML 片段插到顶层 nodes: 块末尾，保留其余内容与注释。"""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^nodes\s*:\s*$", line):
            start = i
            break
    if start is None:
        raise VpskitError("nodes.yaml 里找不到顶层的 `nodes:` 块，请手动添加")
    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if line and not line[0].isspace() and not line.lstrip().startswith("#"):
            end = i
            break
    head_end = end
    while head_end > start + 1 and not lines[head_end - 1].strip():
        head_end -= 1
    head = lines[:head_end]
    rest = lines[end:]
    out = head + [""] + block_lines
    if rest:
        out += [""] + rest
    return "\n".join(out) + "\n"


class _State:
    def __init__(self, nodes: NodesConfig, root: Path):
        self.nodes = nodes
        self.root = root
        self.lock = threading.Lock()
        self.data: List[Dict[str, Any]] = []
        self.time = 0.0
        self.write_times: List[float] = []
        self.stop = threading.Event()

    def refresh(self) -> None:
        try:
            data = collect_all(self.nodes, self.root, cache_seconds=0, workers=4)
            with self.lock:
                self.data = data
                self.time = time.time()
        except Exception as exc:  # 面板不应因为一个节点挂掉
            warn("面板采集失败: %s" % exc)

    def get(self) -> List[Dict[str, Any]]:
        with self.lock:
            if self.data:
                return self.data
        self.refresh()
        with self.lock:
            return self.data

    def loop(self, seconds: int) -> None:
        while not self.stop.wait(0):
            self.refresh()
            if self.stop.wait(max(5, seconds)):
                return

    def set_mail_to(self, payload: Dict[str, Any]) -> str:
        email = str((payload or {}).get("mail_to") or "").strip()
        if not _EMAIL_RE.match(email):
            raise VpskitError("邮箱格式不对")
        node_id = str((payload or {}).get("node_id") or "").strip() or next(iter(self.nodes.nodes))
        if node_id not in self.nodes.nodes:
            raise VpskitError("没有节点 %s" % node_id)
        path = self.nodes.path
        text = path.read_text(encoding="utf-8")
        new_text = _set_node_field(text, node_id, "mail_to", email)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = path.with_name("%s.bak-%s" % (path.name, stamp))
        shutil.copy2(path, backup)
        tmp = path.with_name(path.name + ".tmp")
        try:
            tmp.write_text(new_text, encoding="utf-8")
            os.chmod(tmp, path.stat().st_mode & 0o777)
            os.replace(tmp, path)
            cfg = load_nodes(path)
        except Exception:
            try:
                shutil.copy2(backup, path)
            except OSError:
                pass
            raise
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass
        with self.lock:
            self.nodes = cfg
        threading.Thread(target=self.refresh, daemon=True).start()
        info("面板更新 %s 的告警邮箱（备份 %s）" % (node_id, backup.name))
        return email

    # ---- 添加节点：只追加到 nodes.yaml，先备份，写后重新解析校验 ----
    def add_node(self, payload: Dict[str, Any]) -> str:
        data = _clean_node_payload(payload)
        node_id = data.pop("__id__")
        path = self.nodes.path
        text = path.read_text(encoding="utf-8")
        if node_id in self.nodes.nodes:
            raise VpskitError("节点 %s 已存在" % node_id)
        if re.search(r"^%s\s*:" % re.escape(node_id), text, re.M):
            raise VpskitError("nodes.yaml 里已经有 %s" % node_id)
        import yaml

        block = yaml.safe_dump(
            {node_id: data}, allow_unicode=True, sort_keys=False, default_flow_style=False
        )
        block_lines = [("  " + ln) if ln.strip() else "" for ln in block.splitlines()]
        new_text = _insert_under_nodes(text, block_lines)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = path.with_name("%s.bak-%s" % (path.name, stamp))
        shutil.copy2(path, backup)
        tmp = path.with_name(path.name + ".tmp")
        try:
            tmp.write_text(new_text, encoding="utf-8")
            os.chmod(tmp, path.stat().st_mode & 0o777)
            os.replace(tmp, path)
            cfg = load_nodes(path)
        except Exception:
            try:
                shutil.copy2(backup, path)
            except OSError:
                pass
            raise
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass
        with self.lock:
            self.nodes = cfg
            node = cfg.nodes.get(node_id)
            if node is not None and not any(x.get("node_id") == node_id for x in self.data):
                # 先放一行“等待探测”，后台采集完成后再被真实数据替换
                self.data.append(
                    {
                        "node_id": node_id,
                        "title": node.display_title,
                        "host": node.host,
                        "online": False,
                        "error": "等待首次探测",
                        "services": {},
                        "traffic": None,
                        "provider": node.provider,
                        "line": node.line,
                        "purchased_on": node.purchased_on,
                        "expires_on": node.expires_on,
                        "billing_cycle": node.billing_cycle,
                        "node_clients": [{"email": c.email, "flow": c.flow} for c in node.clients],
                        "ports_cfg": {
                            "ssh": node.ssh_port,
                            "reality": node.reality_port,
                            "sub": node.sub_port if node.sub_enable else 0,
                            "traffic": node.traffic_web_port if node.traffic_web_enable else 0,
                            "ss": node.ss_port if node.ss_enable else 0,
                        },
                    }
                )
        threading.Thread(target=self.refresh, daemon=True).start()
        info("面板新增节点 %s（备份 %s）" % (node_id, backup.name))
        return node_id


def _with_sub_urls(data: List[Dict[str, Any]], state: "_State") -> List[Dict[str, Any]]:
    nodes = getattr(state, "nodes", None)
    root = getattr(state, "root", None)
    if nodes is None or root is None:
        return data
    for item in data:
        node = nodes.nodes.get(item.get("node_id") or "")
        item["sub_urls"] = _sub_urls(node, root) if node else {}
    return data


def _page(state: _State, panel, *, share: bool, api: str, title: str) -> bytes:
    if share:
        data = _share_data(state.get())
    else:
        data = _with_sub_urls(state.get(), state)
    # 防止 </script> 提前闭合
    payload = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")
    html = ASSET.read_text(encoding="utf-8")
    html = (
        html.replace("__TITLE__", html_lib.escape(title))
        .replace("__DATA__", payload)
        .replace("__SHARE__", "true" if share else "false")
        .replace("__API__", json.dumps(api))
        .replace("__REFRESH__", str(max(5, panel.refresh_seconds)))
    )
    return html.encode("utf-8")


def _make_handler(state: _State, panel, token: str, share_token: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "vpskit-panel/1.0"
        timeout = 20

        def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                "img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            )
            self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _local_host(self) -> bool:
            raw = (self.headers.get("Host") or "").strip().lower()
            if raw.startswith("["):
                name = raw.split("]")[0] + "]"
            else:
                name = raw.split(":")[0]
            return name in ("127.0.0.1", "localhost", "[::1]", "::1")

        def _host_ok(self) -> bool:
            """没配 token 时只接受本机 Host，防止隧道转发和 DNS rebinding。"""
            if token:
                return True
            raw = (self.headers.get("Host") or "").strip().lower()
            if raw.startswith("["):
                name = raw.split("]")[0] + "]"
            else:
                name = raw.split(":")[0]
            allowed = {"127.0.0.1", "localhost", "[::1]", "::1"}
            allowed |= {h.lower() for h in (getattr(panel, "allow_hosts", None) or [])}
            return name in allowed

        def _authorized(self) -> bool:
            # 本机访问不需要 token（token 只管局域网/反代进来的人）
            if self._local_host():
                return True
            if not token:
                return True
            q = parse_qs(urlparse(self.path).query)
            supplied = (q.get("token") or [""])[0]
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                supplied = auth[7:]
            return bool(supplied) and hmac.compare_digest(supplied, token)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/healthz":
                self._send(200, b"ok", "text/plain; charset=utf-8")
                return
            if not self._host_ok():
                self._send(
                    403,
                    ("Host %r 不在允许列表；本机用 http://127.0.0.1:%d/ 打开，"
                     "要经隧道/反代访问请先配置 panel.token" % (self.headers.get("Host", ""), panel.port)).encode("utf-8"),
                    "text/plain; charset=utf-8",
                )
                return
            if path.startswith("/share/"):
                supplied = path[len("/share/"):].strip("/")
                if not share_token or not supplied or not hmac.compare_digest(supplied, share_token):
                    self._send(404, b"not found", "text/plain; charset=utf-8")
                    return
                if path.endswith("/api"):
                    data = _share_data(state.get())
                    self._send(200, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")
                else:
                    self._send(200, _page(state, panel, share=True, api="/share/%s/api" % share_token, title=panel.title))
                return
            if path == "/api/status":
                if not self._authorized():
                    self._send(401, b"unauthorized", "text/plain; charset=utf-8")
                    return
                data = _with_sub_urls(state.get(), state)
                self._send(200, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")
                return
            if path == "/" or path == "/index.html":
                if not self._authorized():
                    self._send(401, "unauthorized（需要 ?token=...）".encode("utf-8"), "text/plain; charset=utf-8")
                    return
                api = "/api/status"
                if token:
                    q = parse_qs(parsed.query)
                    t = (q.get("token") or [""])[0]
                    api = "/api/status?token=" + t
                self._send(200, _page(state, panel, share=False, api=api, title=panel.title))
                return
            self._send(404, b"not found", "text/plain; charset=utf-8")

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if not self._host_ok():
                self._send(403, b"host not allowed", "text/plain; charset=utf-8")
                return
            if not getattr(panel, "allow_write", True):
                self._send(403, b"panel.allow_write is false", "text/plain; charset=utf-8")
                return
            if parsed.path not in ("/api/nodes", "/api/settings"):
                self._send(404, b"not found", "text/plain; charset=utf-8")
                return
            if not self._authorized():
                self._send(401, b"unauthorized", "text/plain; charset=utf-8")
                return
            origin = (self.headers.get("Origin") or "").strip()
            if origin:
                host = (self.headers.get("Host") or "").strip()
                if origin not in ("http://" + host, "https://" + host):
                    self._send(403, b"forbidden origin", "text/plain; charset=utf-8")
                    return
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype != "application/json":
                self._send(415, b"expect application/json", "text/plain; charset=utf-8")
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0 or length > 65536:
                self._send(413, b"bad length", "text/plain; charset=utf-8")
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
            except Exception:
                self._send(400, b"invalid json", "text/plain; charset=utf-8")
                return
            now = time.time()
            with state.lock:
                state.write_times = [t for t in state.write_times if now - t < 60]
                if len(state.write_times) >= 6:
                    self._send(429, b"too many writes, slow down", "text/plain; charset=utf-8")
                    return
                state.write_times.append(now)
            try:
                if parsed.path == "/api/settings":
                    email = state.set_mail_to(payload)
                    body = json.dumps({"ok": True, "mail_to": email}, ensure_ascii=False)
                    self._send(200, body.encode("utf-8"), "application/json; charset=utf-8")
                    return
                node_id = state.add_node(payload)
            except VpskitError as exc:
                body = json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False)
                self._send(400, body.encode("utf-8"), "application/json; charset=utf-8")
                return
            except Exception as exc:
                warn("添加节点失败: %s" % exc)
                body = json.dumps({"ok": False, "error": "写入失败: %s" % exc}, ensure_ascii=False)
                self._send(500, body.encode("utf-8"), "application/json; charset=utf-8")
                return
            body = json.dumps({"ok": True, "node_id": node_id}, ensure_ascii=False)
            self._send(200, body.encode("utf-8"), "application/json; charset=utf-8")

        def log_message(self, *args):
            return

    return Handler


def _lan_ips() -> list:
    """尽量列出本机可被手机访问的 IPv4（有 VPN 时会出现多个）。"""
    import socket

    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        if not ip.startswith("127.") and ip not in ips:
            ips.append(ip)
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return ips


def run_panel(nodes: NodesConfig, root: Path, *, listen: str = "", port: int = 0, no_browser: bool = False) -> None:
    panel = nodes.panel
    listen = listen or panel.listen
    port = port or panel.port
    token = panel.token or ""
    share_token = panel.share_token or ""
    if listen not in ("127.0.0.1", "::1", "localhost") and not token:
        raise VpskitError("面板监听在非本机地址时必须配置 panel.token（nodes.yaml）")
    if panel.refresh_seconds < 5:
        warn("refresh_seconds 太小，按 5 秒处理")
        panel.refresh_seconds = 5
    state = _State(nodes, root)
    thread = threading.Thread(target=state.loop, args=(panel.refresh_seconds,), daemon=True)
    thread.start()

    handler = _make_handler(state, panel, token, share_token)
    server = ThreadingHTTPServer((listen, port), handler)
    server.daemon_threads = True
    wildcard = listen in ("0.0.0.0", "::")
    host = "127.0.0.1" if wildcard else listen
    url = "http://%s:%d/" % (host if ":" not in host else "[%s]" % host, port)
    if token:
        url += "?token=" + token
    detail("面板: %s" % url)
    if wildcard:
        for lan in _lan_ips():
            lan_url = "http://%s:%d/" % (lan, port)
            if token:
                lan_url += "?token=" + token
            detail("手机（同一 Wi-Fi）: %s" % lan_url)
    if share_token:
        detail("分享: http://%s:%d/share/%s" % (host if ":" not in host else "[%s]" % host, port, share_token))
    warn("面板默认只读；仅「添加节点」会写 nodes.yaml（先备份、写完校验）。公网使用请放在 Caddy/Nginx + HTTPS 后面。")
    if not no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        info("面板停止")
    finally:
        state.stop.set()
        server.server_close()
