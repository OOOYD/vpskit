"""多节点只读面板：本地 HTTP + 分享 token。

默认只绑 127.0.0.1；要公网分享，放在 Caddy/Nginx 后面，并设置 panel.token。
"""
from __future__ import annotations

import hmac
import html as html_lib
import json
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .config import NodesConfig
from .status import collect_all
from .util import VpskitError, detail, info, mask_ip, warn

ASSET = Path(__file__).resolve().parent / "panel.html"


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
            "network": n.get("network", {}),
            "system": n.get("system", {}),
            "unattr": n.get("unattr", {}),
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
            }
        out.append(item)
    return out


class _State:
    def __init__(self, nodes: NodesConfig, root: Path):
        self.nodes = nodes
        self.root = root
        self.lock = threading.Lock()
        self.data: List[Dict[str, Any]] = []
        self.time = 0.0
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


def _page(state: _State, panel, *, share: bool, api: str, title: str) -> bytes:
    data = _share_data(state.get()) if share else state.get()
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
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
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
                data = state.get()
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

        def log_message(self, *args):
            return

    return Handler


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
    host = "127.0.0.1" if listen in ("0.0.0.0", "::") else listen
    url = "http://%s:%d/" % (host if ":" not in host else "[%s]" % host, port)
    if token:
        url += "?token=" + token
    detail("面板: %s" % url)
    if share_token:
        detail("分享: http://%s:%d/share/%s" % (host if ":" not in host else "[%s]" % host, port, share_token))
    warn("只读面板；没有操作按钮。公网使用请放在 Caddy/Nginx + HTTPS 后面。")
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
