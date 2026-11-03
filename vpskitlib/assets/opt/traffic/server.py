#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vpskit 流量页：只读 /opt/traffic/summary.json，不跑 vnstat、不读 /root。

以 www-data 运行；key 用常量时间比较；所有输出做 HTML 转义。
"""
import datetime
import hmac
import html
import json
import os
import socket
import socketserver
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

try:
    import kitconf
except ImportError:
    kitconf = None


def _c(name, default):
    return getattr(kitconf, name, default) if kitconf else default


PORT = int(_c("TRAFFIC_WEB_PORT", 19000))
KEY = str(_c("TRAFFIC_WEB_KEY", ""))
TITLE = str(_c("TITLE", "VPS"))
SUMMARY_PATH = _c("SUMMARY_PATH", "/opt/traffic/summary.json")
CHANGELOG_JSONL = _c("CHANGELOG_JSONL", "/opt/traffic/changelog.jsonl")
CAP_GB = float(_c("CAP_GB", 500))


def esc(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def load_summary():
    try:
        with open(SUMMARY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def load_changes(limit=8):
    out = []
    try:
        with open(CHANGELOG_JSONL, "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit * 2:]
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    except OSError:
        pass
    return out


def fmt_gb(value):
    try:
        v = float(value)
    except (TypeError, ValueError):
        v = 0.0
    if v >= 1:
        return "%.2f" % v, "GB"
    return "%.0f" % (v * 1024), "MB"


def color_for(pct):
    if pct < 60:
        return "#30d158"
    if pct < 85:
        return "#ff9f0a"
    return "#ff453a"


def render_page(data, changes):
    if not data:
        return (
            "<!doctype html><meta charset='utf-8'><title>%s</title>"
            "<body style='font-family:-apple-system,sans-serif;padding:40px;color:#1d1d1f'>"
            "<h1>%s</h1><p>还没有流量摘要。等待 traffic-monitor.timer 运行，或手动执行 "
            "<code>systemctl start traffic-monitor.service</code>。</p></body>" % (esc(TITLE), esc(TITLE))
        )
    cap = float(data.get("cap_gb") or CAP_GB)
    cycle = float(data.get("cycle_gb") or 0)
    today = float(data.get("today_gb") or 0)
    remain = max(cap - cycle, 0)
    pct = min(cycle / cap * 100, 100) if cap else 0
    color = color_for(pct)
    cycle_fmt, cycle_unit = fmt_gb(cycle)
    remain_fmt, remain_unit = fmt_gb(remain)
    today_fmt, today_unit = fmt_gb(today)
    avg_fmt, avg_unit = fmt_gb(data.get("avg_gb") or 0)
    proj_fmt, proj_unit = fmt_gb(data.get("projected_gb") or 0)

    days = data.get("days") or []
    max_day = max([float(d.get("gb") or 0) for d in days] + [0.01])
    bars = []
    for idx, d in enumerate(days):
        h = max(int(float(d.get("gb") or 0) / max_day * 110), 3)
        cls = "bar today" if idx == len(days) - 1 else "bar"
        tag = " · 今天" if idx == len(days) - 1 else ""
        bars.append(
            "<div class='col'><div class='bv'>%s<small> %s</small></div>"
            "<div class='%s' style='height:%dpx'></div><div class='bl'>%s%s</div></div>"
            % (esc(d.get("fmt", "")), esc(d.get("unit", "")), cls, h, esc(d.get("label", "")), tag)
        )

    alerts = data.get("alerts") or []
    if alerts:
        alert_html = "".join(
            "<div class='alert %s'>● %s</div>"
            % ("danger" if a.get("sev", 1) >= 2 else "warn", esc(a.get("txt", "")))
            for a in alerts
        )
    else:
        alert_html = "<div class='alert ok'>● 当前无告警</div>"

    services = data.get("services") or {}
    svc_html = "".join(
        "<span class='chip %s'>%s %s</span>"
        % ("ok" if state == "active" else "bad", esc(name), esc(state))
        for name, state in services.items()
    ) or "<span class='chip'>暂无</span>"

    ips = data.get("ips") or []
    ip_rows = []
    for row in ips:
        ip_rows.append(
            "<div class='iprow'><div><div class='ipname'>%s</div><div class='ipaddr'>%s</div>"
            "<div class='ipmeta'>%s</div></div>"
            "<div class='ipright'><b>%s GB</b><span>%s%%</span></div></div>"
            % (
                esc(row.get("name", "未备注")),
                esc(row.get("ip", "")),
                esc(row.get("last_seen", "")),
                esc(row.get("gb", 0)),
                esc(row.get("pct", 0)),
            )
        )
    if not ip_rows:
        ip_rows.append("<div class='muted'>暂无按 IP 数据</div>")

    change_html = []
    for c in changes:
        change_html.append(
            "<div class='chg'><div class='chgmeta'><span class='tag'>%s %s</span>"
            "<span class='lv %s'>%s</span><span class='tm'>%s</span></div>"
            "<div class='chgt'>%s</div>%s</div>"
            % (
                esc(c.get("icon", "")),
                esc(c.get("tag", "")),
                esc(c.get("level", "")),
                esc(c.get("level", "")),
                esc(c.get("time", "")),
                esc(c.get("title", "")),
                ("<div class='chgw'>💡 %s</div>" % esc(c.get("why", ""))) if c.get("why") else "",
            )
        )

    return """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{title} · 流量</title>
<style>
:root{{--bg:#f5f5f7;--card:#fff;--card2:#e8e8ed;--text:#1d1d1f;--sub:#86868b;--line:#e8e8ed;--blue:#007aff}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;background:var(--bg);color:var(--text);display:flex;justify-content:center;padding:20px 16px 40px}}
.wrap{{width:100%;max-width:430px}}
h1{{font-size:20px;font-weight:700;letter-spacing:-.4px;margin:6px 4px 2px}}
.sub{{color:var(--sub);font-size:11px;margin:0 4px 14px}}
.card{{background:var(--card);border-radius:20px;padding:18px;margin-bottom:12px;box-shadow:0 1px 3px rgba(0,0,0,.05),0 10px 30px rgba(0,0,0,.06)}}
.big{{display:flex;justify-content:space-between;align-items:baseline}}
.num{{font-size:30px;font-weight:700;letter-spacing:-1px}}
.num small{{font-size:13px;font-weight:500;color:var(--sub)}}
.cap{{font-size:11px;color:var(--sub);text-align:right;line-height:1.5}}
.bar{{height:8px;border-radius:6px;background:var(--card2);overflow:hidden;margin:10px 0 6px}}
.fill{{height:100%;border-radius:6px}}
.meta{{display:flex;justify-content:space-between;font-size:10px;color:var(--sub)}}
.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px}}
.stat{{background:var(--card);border-radius:16px;padding:12px 6px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.04)}}
.stat b{{display:block;font-size:16px;font-weight:700}}
.stat span{{font-size:10px;color:var(--sub)}}
.chart{{display:flex;align-items:flex-end;justify-content:space-between;height:150px;padding-top:8px}}
.col{{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%}}
.bar{{width:56%;max-width:22px;background:var(--card2);border-radius:7px 7px 3px 3px}}
.bar.today{{background:linear-gradient(180deg,#64d2ff,var(--blue))}}
.bv{{font-size:9px;color:var(--sub);margin-bottom:2px}}
.bl{{font-size:9px;color:var(--sub);margin-top:4px;white-space:nowrap}}
.alert{{font-size:11px;padding:8px 10px;border-radius:12px;margin-top:6px}}
.alert.ok{{background:rgba(48,209,88,.1);color:#30d158}}
.alert.warn{{background:rgba(255,159,10,.12);color:#ff9f0a}}
.alert.danger{{background:rgba(255,69,58,.12);color:#ff453a}}
.chip{{display:inline-block;font-size:10px;padding:4px 7px;border-radius:8px;background:var(--bg);color:var(--sub);margin:2px 2px 0 0}}
.chip.ok{{color:#30d158}}
.chip.bad{{color:#ff453a;font-weight:600}}
.iprow{{display:flex;justify-content:space-between;align-items:flex-start;padding:9px 0;border-bottom:1px solid var(--line)}}
.iprow:last-child{{border-bottom:none}}
.ipname{{font-size:12px;font-weight:600}}
.ipaddr{{font-size:10px;color:var(--sub);word-break:break-all}}
.ipmeta{{font-size:9px;color:var(--sub)}}
.ipright{{text-align:right;font-size:11px;white-space:nowrap}}
.ipright span{{display:block;color:var(--sub);font-size:9px}}
.muted{{color:var(--sub);font-size:11px;padding:8px 0}}
.chg{{padding:8px 0;border-bottom:1px solid var(--line)}}
.chg:last-child{{border-bottom:none}}
.chgmeta{{display:flex;gap:6px;align-items:center;font-size:10px;color:var(--sub)}}
.tag{{color:var(--blue)}}
.lv{{font-weight:600}}
.lv.关键{{color:#ff453a}} .lv.重要{{color:#ff9f0a}} .lv.一般{{color:#64d2ff}}
.tm{{margin-left:auto}}
.chgt{{font-size:12px;font-weight:600;margin-top:2px}}
.chgw{{font-size:10px;color:var(--blue);margin-top:2px}}
.foot{{text-align:center;color:var(--sub);font-size:10px;margin-top:10px}}
</style></head><body><div class="wrap">
<h1>{title}</h1>
<div class="sub">周期 {start} → {end} · 接口 {iface} · 更新 {updated}</div>

<div class="card">
  <div class="big"><div class="num">{cycle}<small> {cycle_unit}</small></div>
  <div class="cap">周期额度<br><b>{cap:.0f} GB</b></div></div>
  <div class="bar"><div class="fill" style="width:{pct:.1f}%;background:{color}"></div></div>
  <div class="meta"><span>已用 {pct:.1f}%</span><span>剩余 {remain} {remain_unit}</span></div>
</div>

<div class="stats">
  <div class="stat"><b>{today}<small> {today_unit}</small></b><span>今日</span></div>
  <div class="stat"><b>{avg}<small> {avg_unit}</small></b><span>周期日均</span></div>
  <div class="stat"><b>{proj}<small> {proj_unit}</small></b><span>预计周期末</span></div>
</div>

<div class="card"><div class="sub" style="margin:0 0 4px">最近 7 天</div>
  <div class="chart">{bars}</div>
</div>

<div class="card"><div class="sub" style="margin:0 0 6px">告警</div>{alerts}</div>
<div class="card"><div class="sub" style="margin:0 0 6px">服务</div>{services}</div>
<div class="card"><div class="sub" style="margin:0 0 6px">按 IP（Top {ip_count} / 共 {ip_total}）</div>{ips}</div>
<div class="card"><div class="sub" style="margin:0 0 6px">最近变更</div>{changes}</div>
<div class="foot">每 5 分钟更新 · 页面 60 秒自动刷新</div>
</div>
<script>setTimeout(function(){{location.reload()}},60000)</script>
</body></html>""".format(
        title=esc(TITLE),
        start=esc(data.get("cycle_start", "")),
        end=esc(data.get("cycle_end", "")),
        iface=esc(data.get("iface", "")),
        updated=esc(data.get("updated", "")),
        cycle=esc(cycle_fmt),
        cycle_unit=esc(cycle_unit),
        cap=cap,
        pct=pct,
        color=color,
        remain=esc(remain_fmt),
        remain_unit=esc(remain_unit),
        today=esc(today_fmt),
        today_unit=esc(today_unit),
        avg=esc(avg_fmt),
        avg_unit=esc(avg_unit),
        proj=esc(proj_fmt),
        proj_unit=esc(proj_unit),
        bars="".join(bars),
        alerts=alert_html,
        services=svc_html,
        ips="".join(ip_rows),
        ip_count=len(ips),
        ip_total=data.get("ip_total", len(ips)),
        changes="".join(change_html) or "<div class='muted'>暂无变更记录</div>",
    )


class Handler(BaseHTTPRequestHandler):
    timeout = 10
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        q = parse_qs(parsed.query)
        supplied = (q.get("k") or [""])[0]
        if not KEY or not hmac.compare_digest(supplied, KEY):
            self.send_error(404)
            return
        body = render_page(load_summary(), load_changes()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        try:
            msg = fmt % args
            msg = msg.replace(KEY, "***") if KEY else msg
            if "k=" in msg:
                pos = msg.find("k=")
                end = pos + 2
                while end < len(msg) and msg[end] not in ' &"':
                    end += 1
                msg = msg[:pos] + "k=***" + msg[end:]
            print("%s %s %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.client_address[0], msg), flush=True)
        except Exception:
            pass


class DualStackServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    timeout = 10
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


if __name__ == "__main__":
    DualStackServer(("::", PORT), Handler).serve_forever()
