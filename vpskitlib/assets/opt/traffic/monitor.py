#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vpskit 流量监控：per-IP 统计 + 周期用量 + summary.json + 可选邮件告警。

设计：
  * 所有数据由本脚本（root，timer 每 5 分钟）算好写 summary.json；
  * traffic-web 以 www-data 只读 summary.json，不再跑 vnstat/nft；
  * 默认不把客户端 IP 发给第三方 GeoIP（labels 只来自本地 ip_labels.json）。
"""
import datetime
import json
import os
import re
import smtplib
import subprocess
import sys
import time
from email.header import Header
from email.mime.text import MIMEText

BASE = "/opt/traffic"

try:
    import kitconf
except ImportError:
    kitconf = None


def _c(name, default):
    return getattr(kitconf, name, default) if kitconf else default


BASE = _c("DATA_DIR", BASE)


TITLE = _c("TITLE", "VPS")
NODE_ID = _c("NODE_ID", "")
CAP_GB = float(_c("CAP_GB", 500))
ANCHOR_DAY = int(_c("QUOTA_ANCHOR_DAY", 29))
DAILY_ALERT_GB = float(_c("DAILY_ALERT_GB", 20))
DAILY_HARD_GB = float(_c("DAILY_HARD_GB", 30))
REALITY_PORT = int(_c("REALITY_PORT", 443))
SS_PORT = int(_c("SS_PORT", 0))
SS_ENABLE = bool(_c("SS_ENABLE", False))
SUMMARY_PATH = _c("SUMMARY_PATH", os.path.join(BASE, "summary.json"))
CHANGELOG_JSONL = _c("CHANGELOG_JSONL", os.path.join(BASE, "changelog.jsonl"))
SMTP_HOST = _c("SMTP_HOST", "smtp.qq.com")
SMTP_PORT = int(_c("SMTP_PORT", 465))
MAIL_USER = _c("MAIL_USER", "")
MAIL_TO = _c("MAIL_TO", "")
MAIL_PASS_ENV = _c("MAIL_PASS_ENV", "SMTP_PASS")
AUTOBAN_ENABLE = bool(_c("AUTOBAN_ENABLE", True))

HOURLY_DIR = os.path.join(BASE, "hourly")
HOURLY_KEEP_DAYS = 7
HOURLY_MAX_IPS = 8000

os.environ.setdefault("TZ", "Asia/Shanghai")
try:
    time.tzset()
except Exception:
    pass


# ---------------------------------------------------------------- io


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data, mode=0o644):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def sh(cmd, timeout=20):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def gb_from_bytes(b):
    return b / 1e9


def fmt_pair(gb):
    if gb < 1:
        return ("%.0f" % (gb * 1024), "MB")
    return ("%.2f" % gb, "GB")


# ---------------------------------------------------------------- vnstat


def vnstat_traffic():
    out = sh(["vnstat", "--json"], timeout=20)
    try:
        data = json.loads(out)
    except Exception:
        return None, None, 1
    iface_name = _c("VNSTAT_IFACE", "")
    interfaces = data.get("interfaces") or []
    if not interfaces:
        return None, None, 1
    if iface_name:
        iface = next((i for i in interfaces if i.get("name") == iface_name), interfaces[0])
    else:
        iface = max(interfaces, key=lambda i: i["traffic"]["total"]["rx"] + i["traffic"]["total"]["tx"])
    factor = 1024 if str(data.get("jsonversion", "2")) == "1" else 1
    return iface["name"], iface["traffic"], factor


def _anchor(year, month):
    nxt = datetime.date(year + (month == 12), (month % 12) + 1, 1)
    return datetime.date(year, month, min(ANCHOR_DAY, (nxt - datetime.timedelta(days=1)).day))


def cycle_window(today=None):
    today = today or datetime.date.today()
    start = _anchor(today.year, today.month) if today.day >= _anchor(today.year, today.month).day else _anchor(
        (today.replace(day=1) - datetime.timedelta(days=1)).year,
        (today.replace(day=1) - datetime.timedelta(days=1)).month,
    )
    if start.month == today.month and start.year == today.year:
        nxt = _anchor(today.year + (today.month == 12), (today.month % 12) + 1)
    else:
        nxt = _anchor(today.year, today.month)
    return start, nxt


def cycle_stats(traffic, factor):
    today = datetime.date.today()
    start, nxt = cycle_window(today)
    total = rx = tx = 0
    for item in traffic.get("day") or []:
        d = item.get("date") or {}
        try:
            day = datetime.date(d["year"], d["month"], d["day"])
        except Exception:
            continue
        if day >= start:
            total += item.get("rx", 0) + item.get("tx", 0)
            rx += item.get("rx", 0)
            tx += item.get("tx", 0)
    total_b, rx_b, tx_b = total * factor, rx * factor, tx * factor
    elapsed = max((today - start).days + 1, 1)
    cycle_len = max((nxt - start).days, 1)
    avg_gb = gb_from_bytes(total_b) / elapsed
    return {
        "cycle_gb": round(gb_from_bytes(total_b), 2),
        "down_gb": round(gb_from_bytes(rx_b), 2),
        "up_gb": round(gb_from_bytes(tx_b), 2),
        "avg_gb": round(avg_gb, 2),
        "projected_gb": round(avg_gb * cycle_len, 1),
        "cycle_start": start.isoformat(),
        "cycle_end": nxt.isoformat(),
        "elapsed_days": elapsed,
        "cycle_days": cycle_len,
    }


def day_series(traffic, factor):
    out = []
    for item in (traffic.get("day") or [])[-7:]:
        d = item.get("date") or {}
        val = (item.get("rx", 0) + item.get("tx", 0)) * factor
        gb = gb_from_bytes(val)
        f, u = fmt_pair(gb)
        out.append(
            {
                "label": "%s/%s" % (d.get("month", "?"), d.get("day", "?")),
                "gb": round(gb, 3),
                "fmt": f,
                "unit": u,
            }
        )
    return out


# ---------------------------------------------------------------- per-ip


def parse_set(fam, table, setname):
    out = sh(["nft", "list", "set", fam, table, setname], timeout=15)
    result = {}
    for m in re.finditer(r"([0-9a-fA-F:.]+)\s+counter packets \d+ bytes (\d+)", out):
        ip, value = m.group(1), int(m.group(2))
        if ip in ("0.0.0.0", "::"):
            continue
        result[ip] = value
    return result


def collect_per_ip(now_text):
    baseline = load_json(os.path.join(BASE, "ip_baseline.json"), {})
    usage = load_json(os.path.join(BASE, "ip_usage.json"), {})
    meta = load_json(os.path.join(BASE, "meta.json"), {})
    month = datetime.date.today().strftime("%Y-%m")
    if meta.get("month") and meta["month"] != month:
        usage, baseline = {}, {}
        print("[i] 跨月重置按 IP 统计")
    meta["month"] = month
    save_json(os.path.join(BASE, "meta.json"), meta)

    counters = {}
    for fam, table in (("ip", "traffic"), ("ip6", "traffic6")):
        counters.update(parse_set(fam, table, "ss_clients"))

    hour = {}
    for ip, current in counters.items():
        prev = baseline.get(ip)
        if prev is None:
            baseline[ip] = {"rx": current, "tx": 0, "since": now_text}
            continue
        delta = current - int(prev.get("rx", 0))
        if delta < 0:
            delta = 0
        if delta:
            rec = usage.setdefault(ip, {"rx": 0, "tx": 0, "first_seen": now_text})
            rec["rx"] += delta
            rec["last_seen"] = now_text
            hour[ip] = hour.get(ip, 0) + delta
        prev["rx"] = current
    save_json(os.path.join(BASE, "ip_baseline.json"), baseline)
    save_json(os.path.join(BASE, "ip_usage.json"), usage)
    record_hourly(hour)
    return usage, baseline


def record_hourly(deltas):
    if not deltas:
        return
    try:
        os.makedirs(HOURLY_DIR, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H")
        path = os.path.join(HOURLY_DIR, "usage-%s.json" % stamp)
        cur = load_json(path, {})
        if not isinstance(cur, dict) or cur.get("hour") != stamp:
            cur = {"hour": stamp, "ch443": {}}
        bucket = cur.setdefault("ch443", {})
        for ip, value in deltas.items():
            bucket[ip] = bucket.get(ip, 0) + value
        if len(bucket) > HOURLY_MAX_IPS:
            cur["ch443"] = dict(sorted(bucket.items(), key=lambda kv: -kv[1])[:HOURLY_MAX_IPS])
        save_json(path, cur)
        cutoff = (datetime.date.today() - datetime.timedelta(days=HOURLY_KEEP_DAYS)).strftime("%Y%m%d")
        for name in os.listdir(HOURLY_DIR):
            m = re.match(r"usage-(\d{8})-\d{2}\.json$", name)
            if m and m.group(1) < cutoff:
                try:
                    os.remove(os.path.join(HOURLY_DIR, name))
                except OSError:
                    pass
    except Exception as exc:
        print("[!] hourly 记录失败: %s" % exc)


def ip_rows(usage, limit=20):
    labels = load_json(os.path.join(BASE, "ip_labels.json"), {})
    total = sum(int(v.get("rx", 0)) + int(v.get("tx", 0)) for v in usage.values())
    rows = []
    for ip, rec in usage.items():
        value = int(rec.get("rx", 0)) + int(rec.get("tx", 0))
        if value < 10 * 1024 * 1024:
            continue
        rows.append(
            {
                "ip": ip,
                "name": labels.get(ip, "未备注"),
                "gb": round(gb_from_bytes(value), 2),
                "pct": round(value / total * 100, 1) if total else 0,
                "last_seen": rec.get("last_seen", ""),
            }
        )
    rows.sort(key=lambda r: -r["gb"])
    return rows[:limit], len(rows)


# ---------------------------------------------------------------- system


SERVICES = ["xray", "ss-server", "traffic-web", "sub", "fail2ban", "nftables"]


def service_states():
    result = {}
    for name in SERVICES:
        try:
            p = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=5)
            result[name] = p.stdout.strip() or "unknown"
        except Exception:
            result[name] = "unknown"
    return result


def fail2ban_stats():
    out = sh(["fail2ban-client", "status", "sshd"], timeout=10)
    banned, total = 0, 0
    for line in out.splitlines():
        if "Currently banned:" in line:
            banned = int(re.sub(r"\D", "", line) or 0)
        if "Total banned:" in line:
            total = int(re.sub(r"\D", "", line) or 0)
    return {"banned": banned, "total_banned": total}


def xray_version():
    out = sh(["/usr/local/bin/xray", "version"], timeout=10).splitlines()
    return out[0] if out else ""


# ---------------------------------------------------------------- alerts / mail


def build_alerts(cycle_gb, today_gb):
    alerts = []
    if cycle_gb >= CAP_GB:
        alerts.append({"txt": "本周期已超 %.0f GB 额度，可能被厂商限速" % CAP_GB, "sev": 2})
    elif cycle_gb >= CAP_GB * 0.8:
        alerts.append({"txt": "本周期已用 %.0f GB（%.0f%%），注意额度" % (cycle_gb, cycle_gb / CAP_GB * 100), "sev": 1})
    if today_gb >= DAILY_HARD_GB:
        alerts.append({"txt": "今日已用 %.1f GB，超过硬警戒线 %.0f GB" % (today_gb, DAILY_HARD_GB), "sev": 2})
    elif today_gb >= DAILY_ALERT_GB:
        alerts.append({"txt": "今日已用 %.1f GB，超过预警线 %.0f GB" % (today_gb, DAILY_ALERT_GB), "sev": 1})
    if AUTOBAN_ENABLE:
        try:
            pending = open(os.path.join(BASE, "autoban_pending.txt"), "r", encoding="utf-8").read().strip()
            if pending:
                alerts.append({"txt": "autoban 最近有封禁：%s" % pending.splitlines()[0][:80], "sev": 1})
        except OSError:
            pass
    return alerts


def send_mail(subject, body):
    if not (MAIL_TO and MAIL_USER):
        return False
    password = os.environ.get(MAIL_PASS_ENV, "") or ""
    if not password:
        try:
            raw = open("/root/.smtp.env", "r", encoding="utf-8").read().strip()
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("export "):
                    line = line[7:].strip()
                if line.startswith("SMTP_PASS="):
                    password = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break
            if not password:
                password = raw
        except OSError:
            password = ""
    if not password:
        print("[!] 有 MAIL_TO 但没有 SMTP 密码，跳过邮件")
        return False
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"] = MAIL_USER
    msg["To"] = MAIL_TO
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20) as s:
            s.login(MAIL_USER, password)
            s.sendmail(MAIL_USER, [MAIL_TO], msg.as_string())
        print("[OK] 邮件已发送: %s" % subject)
        return True
    except Exception as exc:
        print("[!] 邮件失败: %s" % exc)
        return False


def maybe_mail(alerts, cycle_gb, today_gb, day_ok):
    if not alerts:
        return
    state_path = os.path.join(BASE, "alerts.json")
    state = load_json(state_path, {})
    today = datetime.date.today().strftime("%Y-%m-%d")
    key = None
    if cycle_gb >= CAP_GB:
        key = "m_over"
    elif cycle_gb >= CAP_GB * 0.8:
        key = "m_80"
    if day_ok and today_gb >= DAILY_HARD_GB:
        key = "d_hard_" + today
    elif day_ok and today_gb >= DAILY_ALERT_GB:
        key = "d_soft_" + today
    if not key or state.get(key) == today:
        return
    lines = ["%s" % TITLE, ""]
    lines += ["- " + a["txt"] for a in alerts]
    lines += ["", "周期: %.1f / %.0f GB（%s 起）" % (cycle_gb, CAP_GB, cycle_start_text())]
    if send_mail("[%s] 流量告警" % TITLE, "\n".join(lines)):
        state[key] = today
        save_json(state_path, state)


def cycle_start_text():
    return cycle_window()[0].isoformat()


# ---------------------------------------------------------------- main


def main():
    now_text = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    usage, _baseline = collect_per_ip(now_text)
    iface_name, traffic, factor = vnstat_traffic()
    if traffic is None:
        print("[!] 读不到 vnstat 数据")
        return 1
    cycle = cycle_stats(traffic, factor)
    days = day_series(traffic, factor)
    today_gb = days[-1]["gb"] if days else 0.0
    cycle_gb = cycle["cycle_gb"]
    rows, total_rows = ip_rows(usage)

    alerts = build_alerts(cycle_gb, today_gb)
    summary = {
        "updated": now_text,
        "node_id": NODE_ID,
        "title": TITLE,
        "iface": iface_name,
        "cap_gb": CAP_GB,
        "cycle_gb": cycle_gb,
        "today_gb": round(today_gb, 2),
        "remaining_gb": round(max(CAP_GB - cycle_gb, 0), 2),
        "down_gb": cycle["down_gb"],
        "up_gb": cycle["up_gb"],
        "avg_gb": cycle["avg_gb"],
        "projected_gb": cycle["projected_gb"],
        "cycle_start": cycle["cycle_start"],
        "cycle_end": cycle["cycle_end"],
        "days": days,
        "ips": rows,
        "ip_total": total_rows,
        "alerts": alerts,
        "services": service_states(),
        "fail2ban": fail2ban_stats(),
        "xray": [xray_version()],
    }
    save_json(SUMMARY_PATH, summary, mode=0o644)
    print("[i] %s 周期 %.1f/%.0f GB，今日 %.2f GB，IP %d 个" % (now_text, cycle_gb, CAP_GB, today_gb, total_rows))
    day_ok = True
    try:
        last = (traffic.get("day") or [])[-1] or {}
        d = last.get("date") or {}
        day_ok = "%04d-%02d-%02d" % (d.get("year", 0), d.get("month", 0), d.get("day", 0)) == datetime.date.today().isoformat()
    except Exception:
        pass
    maybe_mail(alerts, cycle_gb, today_gb, day_ok)
    return 0


if __name__ == "__main__":
    sys.exit(main())
