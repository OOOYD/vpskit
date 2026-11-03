#!/usr/bin/env python3
"""从现网机器提取配置/秘密，输出 JSON 给本地 `vpskit adopt` 落盘。

只读；不修改任何远端文件。输出中包含秘密，请只在 SSH 通道内传输。
"""
import ast
import json
import os
import re
import subprocess
import sys


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def parse_kitconf(path):
    text = read_text(path)
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                out[node.targets[0].id] = ast.literal_eval(node.value)
            except Exception:
                pass
    return out


def parse_sub_paths(path):
    text = read_text(path)
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id == "PATHS":
                try:
                    value = ast.literal_eval(node.value)
                    if isinstance(value, dict):
                        return value
                except Exception:
                    return {}
    return {}


def parse_constants(path):
    text = read_text(path)
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                value = ast.literal_eval(node.value)
            except Exception:
                continue
            if isinstance(value, (str, int, float, bool)):
                out[node.targets[0].id] = value
    return out


def parse_ignoreip(path):
    text = read_text(path)
    result = []
    for line in text.splitlines():
        if re.match(r"^\s*ignoreip\s*=", line):
            result += line.split("=", 1)[1].split()
    return result


def main():
    result = {"ok": False, "errors": []}
    xray_path = "/usr/local/etc/xray/config.json"
    xray = read_json(xray_path)
    if xray:
        try:
            inbound = xray["inbounds"][0]
            rs = inbound["streamSettings"]["realitySettings"]
            clients = []
            for idx, cli in enumerate(inbound.get("settings", {}).get("clients", [])):
                clients.append(
                    {
                        "email": cli.get("email") or ("main" if idx == 0 else "client%d" % (idx + 1)),
                        "uuid": cli.get("id", ""),
                        "flow": cli.get("flow", ""),
                    }
                )
            result["xray"] = {
                "listen": inbound.get("listen", "::"),
                "port": inbound.get("port", 443),
                "clients": clients,
                "private_key": rs.get("privateKey", ""),
                "short_ids": rs.get("shortIds", []),
                "dest": rs.get("target") or rs.get("dest") or "",
                "server_names": rs.get("serverNames", []),
                "max_time_diff": rs.get("maxTimeDiff", 0),
                "fallback_upload": rs.get("limitFallbackUpload"),
                "fallback_download": rs.get("limitFallbackDownload"),
            }
            result["ok"] = True
        except Exception as exc:
            result["errors"].append("xray: %s" % exc)

    ss = read_json("/etc/shadowsocks-libev/config.json")
    if ss:
        result["ss"] = {
            "port": ss.get("server_port"),
            "password": ss.get("password", ""),
            "method": ss.get("method", ""),
            "server": ss.get("server", "::"),
        }

    kit = parse_kitconf("/opt/traffic/kitconf.py")
    if kit:
        result["kitconf"] = {
            "title": kit.get("TITLE", ""),
            "quota_gb": kit.get("CAP_GB"),
            "anchor_day": kit.get("QUOTA_ANCHOR_DAY"),
            "daily_alert_gb": kit.get("DAILY_ALERT_GB"),
            "daily_hard_gb": kit.get("DAILY_HARD_GB"),
            "traffic_web_port": kit.get("TRAFFIC_WEB_PORT"),
            "traffic_web_key": kit.get("TRAFFIC_WEB_KEY", ""),
            "sub_port": kit.get("SUB_PORT"),
            "sub_paths": kit.get("SUB_PATHS") or {},
            "sub_path": kit.get("SUB_PATH", ""),
            "ss_port": kit.get("SS_PORT"),
            "autoban_thresh_mb": kit.get("AUTOBAN_THRESH_MB"),
            "autoban_strikes": kit.get("AUTOBAN_STRIKES"),
        }

    result["sub_paths_from_script"] = parse_sub_paths("/opt/sub/sub.py")
    result["jail_ignoreip"] = parse_ignoreip("/etc/fail2ban/jail.local")
    result["server"] = parse_constants("/opt/traffic/server.py")
    result["monitor"] = parse_constants("/opt/traffic/monitor.py")
    result["services"] = {}
    for name in ("traffic-web", "sub", "xray", "ss-server", "fail2ban"):
        try:
            p = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=8)
            result["services"][name] = (p.stdout or "").strip()
        except Exception:
            result["services"][name] = "unknown"
    nft = read_text("/etc/nftables.conf")
    ip_part = nft.split("table ip6", 1)[0]
    ss_port = str((result.get("ss") or {}).get("port") or "")
    result["nft_ss_v4"] = bool(ss_port and (("dport " + ss_port) in ip_part or ss_port in ip_part))
    ports = []
    for m in re.finditer(r"tcp dport \{([^}]*)\}\s+accept", ip_part):
        for token in m.group(1).split(","):
            token = token.strip()
            if token.isdigit():
                ports.append(int(token))
    for m in re.finditer(r"tcp dport (\d+)\s+accept", ip_part):
        ports.append(int(m.group(1)))
    result["open_tcp_ports"] = sorted(set(ports))
    # 实际监听族：ss_expose_v4 要看 ss-server 是否真的在 v4 监听，而不是只看 nft 放行
    listeners = out(["ss", "-tlnH"])
    ss_v4 = False
    for line in listeners.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[4]
        if ss_port and local.endswith(":" + ss_port) and (local.startswith("0.0.0.0:") or local.startswith("*:")):
            ss_v4 = True
    result["ss_v4_listener"] = ss_v4

    try:
        p = subprocess.run(["/usr/local/bin/xray", "version"], capture_output=True, text=True, timeout=10)
        first = (p.stdout or "").splitlines()[0] if p.stdout else ""
        m = re.search(r"Xray\s+([0-9][0-9A-Za-z.\-]*)", first)
        if m:
            result["xray_version"] = m.group(1)
    except Exception:
        pass

    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
