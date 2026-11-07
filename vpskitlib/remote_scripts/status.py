#!/usr/bin/env python3
"""节点状态 JSON：给 `vpskit status` 与面板用。只读，不含秘密。"""
import datetime
import glob
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time

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


def backups():
    root = "/root/.vpskit/backups"
    try:
        names = sorted(os.listdir(root))
    except Exception:
        return {"count": 0, "latest": "", "time": ""}
    latest = names[-1] if names else ""
    stamp = ""
    if latest:
        try:
            stamp = time.strftime("%m-%d %H:%M", time.localtime(os.path.getmtime(os.path.join(root, latest))))
        except Exception:
            pass
    return {"count": len(names), "latest": latest, "time": stamp}


def net_speed():
    """0.3 秒采样 /proc/net/dev，返回非 lo 网卡的上/下行字节速率。"""
    def snap():
        rx = tx = 0
        with open("/proc/net/dev", "r") as handle:
            for line in handle.readlines()[2:]:
                if ":" not in line:
                    continue
                name, rest = line.split(":", 1)
                if name.strip() == "lo":
                    continue
                parts = rest.split()
                if len(parts) < 9:
                    continue
                rx += int(parts[0])
                tx += int(parts[8])
        return time.time(), rx, tx

    try:
        t1, r1, x1 = snap()
        time.sleep(0.3)
        t2, r2, x2 = snap()
        dt = max(t2 - t1, 0.001)
        return {
            "rx_bps": round(max(r2 - r1, 0) / dt, 1),
            "tx_bps": round(max(x2 - x1, 0) / dt, 1),
        }
    except Exception:
        return {}


def net_info():
    info = {"ipv4": [], "ipv6": [], "has_v4": False, "has_v6": False, "bbr": "", "qdisc": "", "tfo": "", "mtu_probing": "", "arch": platform.machine()}
    try:
        out = subprocess.run(["ip", "-brief", "addr"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            for addr in parts[2:]:
                a = addr.split("/")[0]
                if ":" in a and a != "::1" and not a.startswith("fe80:"):
                    info["ipv6"].append(a)
                elif "." in a and not a.startswith("127."):
                    info["ipv4"].append(a)
    except Exception:
        pass
    info["has_v4"] = bool(info["ipv4"])
    info["has_v6"] = bool(info["ipv6"])
    for key, path in (
        ("bbr", "/proc/sys/net/ipv4/tcp_congestion_control"),
        ("qdisc", "/proc/sys/net/core/default_qdisc"),
        ("tfo", "/proc/sys/net/ipv4/tcp_fastopen"),
        ("mtu_probing", "/proc/sys/net/ipv4/tcp_mtu_probing"),
    ):
        try:
            info[key] = open(path, encoding="utf-8").read().strip()
        except OSError:
            pass
    return info


def provisioned_on():
    dates = []
    for path in ["/etc/hostname", "/var/log/installer", "/var/log/dpkg.log"]:
        try:
            dates.append(datetime.date.fromtimestamp(os.stat(path).st_mtime))
        except OSError:
            pass
    for path in glob.glob("/var/log/dpkg.log*"):
        try:
            dates.append(datetime.date.fromtimestamp(os.stat(path).st_mtime))
        except OSError:
            pass
    dates = [d for d in dates if d.year >= 2000]
    return min(dates).isoformat() if dates else ""


def cpu_info():
    try:
        def snap():
            parts = open("/proc/stat", encoding="utf-8").readline().split()
            vals = [int(x) for x in parts[1:]]
            total = sum(vals)
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
            return total, idle

        t1, i1 = snap()
        time.sleep(0.25)
        t2, i2 = snap()
        dt, di = t2 - t1, i2 - i1
        return {
            "percent": round((1 - di / dt) * 100, 1) if dt > 0 else 0.0,
            "count": os.cpu_count() or 0,
        }
    except Exception:
        return {"percent": 0.0, "count": os.cpu_count() or 0}


def main():
    summary = load_json("/opt/traffic/summary.json")
    if isinstance(summary, dict):
        if isinstance(summary.get("ips"), list):
            summary["ips"] = summary["ips"][:30]
        if isinstance(summary.get("days"), list):
            summary["days"] = summary["days"][-7:]
    unattr = load_json("/opt/traffic/unattr.json")
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
        "unattr": unattr,
        "changes": changes(8),
        "mem": meminfo(),
        "disk": dict(zip(["total", "used", "free"], shutil.disk_usage("/"))),
        "load": list(os.getloadavg()),
        "cpu": cpu_info(),
        "network": dict(net_info(), **net_speed()),
        "provisioned_on": provisioned_on(),
        "backups": backups(),
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
