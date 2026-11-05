#!/usr/bin/env python3
"""远端只读体检：输出 JSON。由 vpskit 通过 ssh 执行，不修改任何东西。"""
import json
import os
import platform
import re
import shutil
import subprocess

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
    "unattr.timer",
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


def os_release():
    data = {}
    try:
        for line in open("/etc/os-release", encoding="utf-8"):
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                data[k] = v.strip('"')
    except OSError:
        pass
    return {
        "id": data.get("ID", ""),
        "version": data.get("VERSION_ID", ""),
        "pretty": data.get("PRETTY_NAME", ""),
    }


def addrs(family):
    p = sh(["ip", "-%d" % family, "-o", "addr", "show", "scope", "global"])
    if not p:
        return []
    result = []
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            result.append(parts[3].split("/")[0])
    return result


def listeners():
    p = sh(["ss", "-tulnH"])
    if not p:
        return []
    seen = set()
    result = []
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[4]
        if ":" not in local:
            continue
        addr, port = local.rsplit(":", 1)
        try:
            port_i = int(port)
        except ValueError:
            continue
        key = (proto, addr, port_i)
        if key in seen:
            continue
        seen.add(key)
        result.append({"proto": proto, "addr": addr, "port": port_i})
    return sorted(result, key=lambda x: x["port"])


def services():
    result = {}
    for name in SERVICES:
        active = out(["systemctl", "is-active", name]) or "unknown"
        enabled = out(["systemctl", "is-enabled", name]) or "unknown"
        result[name] = {"active": active, "enabled": enabled}
    return result


def meminfo():
    data = {}
    try:
        for line in open("/proc/meminfo", encoding="utf-8"):
            k, v = line.split(":", 1)
            data[k] = int(v.strip().split()[0])
    except OSError:
        pass
    total = data.get("MemTotal", 0)
    avail = data.get("MemAvailable", 0)
    return {"total_kb": total, "available_kb": avail, "used_kb": max(total - avail, 0)}


def main():
    osid = os_release()
    root = os.geteuid() == 0
    data = {
        "ok": True,
        "time": out(["date", "-Is"]),
        "hostname": platform.node(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "os": osid,
        "is_root": root,
        "user": os.environ.get("USER", ""),
        "systemd": os.path.isdir("/run/systemd/system"),
        "has_v6": bool(addrs(6)),
        "ipv4": addrs(4),
        "ipv6": addrs(6),
        "ssh_source": (os.environ.get("SSH_CONNECTION", "").split() or [""])[0],
        "services": services(),
        "ports": listeners(),
        "apt": bool(shutil.which("apt-get")),
        "nft": out(["nft", "--version"]),
        "xray": out(["/usr/local/bin/xray", "version"]).splitlines()[:2],
        "vnstat": bool(shutil.which("vnstat")),
        "docker": bool(shutil.which("docker")),
        "docker_active": out(["systemctl", "is-active", "docker"]) == "active",
        "nftables_enabled": out(["systemctl", "is-enabled", "nftables"]),
        "fail2ban_action_nft": os.path.exists("/etc/fail2ban/action.d/nftables-multiport.conf"),
        "sshd_config_include": bool(out(["grep", "-E", "^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d", "/etc/ssh/sshd_config"])),
        "authorized_keys": os.path.exists(os.path.expanduser("~/.ssh/authorized_keys"))
        and os.path.getsize(os.path.expanduser("~/.ssh/authorized_keys")) > 0,
        "mem": meminfo(),
        "disk": dict(zip(["total", "used", "free"], shutil.disk_usage("/"))),
        "load": list(os.getloadavg()),
    }
    try:
        data["uptime_seconds"] = float(open("/proc/uptime").read().split()[0])
    except Exception:
        data["uptime_seconds"] = 0
    print(json.dumps(data, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
