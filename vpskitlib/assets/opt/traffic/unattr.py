#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""未归属流量核算（拆分版）。

口径：
  * ch443 = REALITY 客户端侧；用 authed_ips.json（xray accepted，7 天窗口）判归属。
    这才是扫描器 fallback 长尾的指标。
  * ch40244 = SS 通道；SS 用密码认证，永远不会出现在 xray accepted 日志里，
    因此单独列，不计入 ch443 的“未归属”阈值。

全只读；默认打印文本，`--write` 同时写 /opt/traffic/unattr.json 供页面/面板读取。
"""
import collections
import datetime
import glob
import json
import os
import sys
import time

BASE = os.environ.get("VPSKIT_TRAFFIC_BASE", "/opt/traffic")
HOURLY = os.path.join(BASE, "hourly")
AUTHED = os.path.join(BASE, "authed_ips.json")
OUT = os.path.join(BASE, "unattr.json")

try:
    import kitconf
except ImportError:
    kitconf = None


def _c(name, default):
    return getattr(kitconf, name, default) if kitconf else default


THRESHOLD_GB = float(_c("UNATTR_THRESH_GB", 1.5))
WINDOW_DAYS = int(_c("UNATTR_WINDOW_DAYS", 7))


def load(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def main():
    now = time.time()
    authed = load(AUTHED, {})
    known = {
        ip for ip, ts in authed.items()
        if isinstance(ts, (int, float)) and now - ts <= WINDOW_DAYS * 86400
    }

    files = sorted(glob.glob(os.path.join(HOURLY, "usage-*.json")))[-24 * WINDOW_DAYS:]
    per_day = collections.defaultdict(lambda: {"known": 0.0, "unknown": 0.0})
    ss_day = collections.defaultdict(float)
    top = collections.Counter()
    for path in files:
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        try:
            day = os.path.basename(path).split("-")[1]
        except IndexError:
            continue
        for ip, value in (data.get("ch443") or {}).items():
            b = value if isinstance(value, (int, float)) else value.get("rx", 0) + value.get("tx", 0)
            gb = b / 1e9
            if ip in known:
                per_day[day]["known"] += gb
            else:
                per_day[day]["unknown"] += gb
                top[ip] += b
        for ip, value in (data.get("ch40244") or {}).items():
            b = value if isinstance(value, (int, float)) else value.get("rx", 0) + value.get("tx", 0)
            ss_day[day] += b / 1e9

    days = sorted(set(per_day) | set(ss_day))
    ch443_total = sum(v["unknown"] for v in per_day.values())
    ndays = max(len(days), 1)
    avg = ch443_total / ndays
    ss_total = sum(ss_day.values())
    result = {
        "updated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "window_days": WINDOW_DAYS,
        "threshold_gb": THRESHOLD_GB,
        "ch443": {
            "total_gb": round(ch443_total, 2),
            "daily_avg_gb": round(avg, 2),
            "level": "high" if avg > THRESHOLD_GB else "ok",
            "known_gb": round(sum(v["known"] for v in per_day.values()), 2),
            "top": [{"ip": ip, "gb": round(b / 1e9, 3)} for ip, b in top.most_common(10)],
        },
        "ch40244": {
            "total_gb": round(ss_total, 2),
            "daily_avg_gb": round(ss_total / ndays, 2),
        },
        "daily": [
            {"date": d, "ch443_unknown_gb": round(per_day[d]["unknown"], 2), "ch40244_gb": round(ss_day[d], 2)}
            for d in days
        ],
    }
    save(OUT, result)

    print("窗口: %d 天 / 留痕 %d 个 / 认证名单 %d 个 IP" % (WINDOW_DAYS, len(files), len(known)))
    print("日期        REALITY未归属(GB)   SS(GB)")
    for row in result["daily"]:
        print("%s        %8.2f          %6.2f" % (row["date"], row["ch443_unknown_gb"], row["ch40244_gb"]))
    print("REALITY 未归属: %.2f GB / 日均 %.2f GB（阈值 %.1f）→ %s" % (
        ch443_total, avg, THRESHOLD_GB, "偏高" if avg > THRESHOLD_GB else "正常"))
    print("SS 通道: %.2f GB / 日均 %.2f GB（单独列，不计入阈值）" % (ss_total, ss_total / ndays))
    for item in result["ch443"]["top"][:5]:
        print("  %-42s %.3f GB" % (item["ip"], item["gb"]))
    if "--write" in sys.argv:
        print("已写 %s" % OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
