#!/usr/bin/env python3
"""节点状态 JSON：给 `vpskit status` 与面板用。只读，不含秘密。"""
import json
import os
import re
import shutil
import subprocess
import sys

SERVICES = [
    "xray",
    "ss-server",
    "traffic-web",
    "traffic-monitor",
    "sub",
    "autoban",
    "fail2ban",
    "nftables",
    "traffic-monitor.timer",
    "autoban.timer",
    "xray-selfheal.timer",
    "traffic-snapshot.timer",
    "ssh",
]


def sh(args, timeout=10):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def out(args, timeout=10):
    p = sh(args, timeout)
    return (p.stdout or "").strip() if p else ""


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def parse_simple_yaml(path):
    data = {}
    try:
        for line in open(path, "r", encoding="utf-8"):
            if ":" in line and not line.strip().startswith("#"):
                k, v = line.split(":", 1)
                data[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    return data


def ports():
    p = sh(["ss", "-tulnH"])
    if not p:
        return []
    seen = set()
    result = []
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        if ":" not in local:
            continue
        addr, port = local.rsplit(":", 1)
        try:
            port_i = int(port)
        except ValueError:
            continue
        if (proto, addr, port_i) in seen:
            continue
        seen.add((proto, addr, port_i))
        result.append({"proto": proto, "addr": addr, "port": port_i})
    return sorted(result, key=lambda x: x["port"])


def services():
    result = {}
    for name in SERVICES:
        result[name] = {
            "active": out(["systemctl", "is-active", name]) or "unknown",
            "enabled": out(["systemctl", "is-enabled", name]) or "unknown",
        }
    return result


def meminfo():
    data = {}
    try:
        for line in open("/proc/meminfo", encoding="utf-8"):
            k, v = line.split(":", 1)
            data[k] = int(v.strip().split()[0])
    except OSError:
        pass
    total, avail = data.get("MemTotal", 0), data.get("MemAvailable", 0)
    return {"total_mb": round(total / 1024), "available_mb": round(avail / 1024)}


def fail2ban():
    status = {"active": out(["systemctl", "is-active", "fail2ban"]), "jails": {}, "banned": 0, "total_banned": 0}
    p = sh(["fail2ban-client", "status"], timeout=10)
    if p:
        for line in p.stdout.splitlines():
            if "Jail list:" in line:
                status["jails"] = [x.strip() for x in line.split(":", 1)[1].split(",") if x.strip()]
    p = sh(["fail2ban-client", "status", "sshd"], timeout=10)
    if p:
        for line in p.stdout.splitlines():
            if "Currently banned:" in line:
                status["banned"] = int(re.sub(r"\D", "", line) or 0)
            if "Total banned:" in line:
                status["total_banned"] = int(re.sub(r"\D", "", line) or 0)
    return status


def changes(limit=5):
    result = []
    try:
        with open("/opt/traffic/changelog.jsonl", "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[-limit:]:
            try:
                result.append(json.loads(line))
            except ValueError:
                pass
    except OSError:
        pass
    return result


def main():
    summary = load_json("/opt/traffic/summary.json")
    if isinstance(summary, dict):
        if isinstance(summary.get("ips"), list):
            summary["ips"] = summary["ips"][:30]
        if isinstance(summary.get("days"), list):
            summary["days"] = summary["days"][-7:]
    info = parse_simple_yaml("/root/ops/kit-node-info.yaml")
    data = {
        "ok": True,
        "time": out(["date", "-Is"]),
        "hostname": os.uname()[1],
        "kernel": os.uname()[2],
        "node": info,
        "services": services(),
        "ports": ports(),
        "fail2ban": fail2ban(),
        "traffic": summary,
        "changes": changes(5),
        "mem": meminfo(),
        "disk": dict(zip(["total", "used", "free"], shutil.disk_usage("/"))),
        "load": list(os.getloadavg()),
        "xray": out(["/usr/local/bin/xray", "version"]).splitlines()[:2],
    }
    try:
        data["uptime_seconds"] = float(open("/proc/uptime").read().split()[0])
    except Exception:
        data["uptime_seconds"] = 0
    print(json.dumps(data, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
