#!/usr/bin/env python3
"""vpskit 订阅服务：每个用户独立路径，只读 /opt/sub/data 下的 YAML。

以 www-data 运行；文件 0640 root:www-data。客户端路径就是能力凭证，不再走 URL 查询参数。
"""
import http.server
import os
import socket
import sys

# 以 /opt/sub/sub.py 运行时 sys.path[0] 是 /opt/sub，必须显式加 kitconf 目录
sys.path.insert(0, "/opt/traffic")
import socketserver
from urllib.parse import urlparse

try:
    import kitconf
except ImportError:
    kitconf = None


def _c(name, default):
    return getattr(kitconf, name, default) if kitconf else default


PORT = int(_c("SUB_PORT", 8888))
DATA_DIR = _c("SUB_DATA_DIR", "/opt/sub/data")
SUB_ROUTES = _c("SUB_ROUTES", {}) or {}
SUB_ROUTE_TYPES = _c("SUB_ROUTE_TYPES", {}) or {}
SUB_PATHS = _c("SUB_PATHS", {}) or {}
SUB_FILES = _c("SUB_FILES", {}) or {}

ROUTES = {}
ROUTE_TYPES = {}
DEFAULT_TYPE = "text/yaml; charset=utf-8"
for path, filename in SUB_ROUTES.items():
    if path and filename:
        ROUTES[path] = filename if filename.startswith("/") else os.path.join(DATA_DIR, filename)
        ROUTE_TYPES[path] = SUB_ROUTE_TYPES.get(path) or DEFAULT_TYPE
# 兼容旧 kitconf / 单路径配置
if not ROUTES:
    if not SUB_PATHS and _c("SUB_PATH", ""):
        SUB_PATHS = {"default": _c("SUB_PATH", "")}
        SUB_FILES = {"default": os.path.basename(_c("SUB_FILE", "subscription.yaml"))}
    for email, path in SUB_PATHS.items():
        filename = SUB_FILES.get(email)
        if path and filename:
            ROUTES[path] = os.path.join(DATA_DIR, filename)


class Handler(http.server.BaseHTTPRequestHandler):
    timeout = 10

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        target = ROUTES.get(path)
        if not target:
            self.send_error(404)
            return
        try:
            with open(target, "rb") as f:
                data = f.read()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ROUTE_TYPES.get(path) or DEFAULT_TYPE)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


if __name__ == "__main__":
    Server(("::", PORT), Handler).serve_forever()
