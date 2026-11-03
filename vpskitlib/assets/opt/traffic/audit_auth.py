#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""认证层差集审计 (2026-09-10 起): 区分真用户 vs 扫描噪音
判定依据 = xray accepted 日志(REALITY认证通过) + SS当前连接(40244) + 443 当前入站连接快照
输出: 已认证(你/朋友) / 未认证大流量(分: 活跃客户端 / 静默疑似目标站) / 零星噪音

2026-09-14 增强(家里ZCode): @ss_clients 集合是双向共用的——既记客户端(入站 saddr),
也记本机出访的目标站(出站 daddr), 所以"未认证大流量"里会混入 CDN/目标站 IP。
新增"当前对本机 443 是否有入站连接"维度用于区分: 目标站不会对本机发起入站连接。
注意: 该判据是执行瞬间的快照(离线滥用者会显示为静默), 仅作处置参考, 不作封禁唯一依据;
封禁仍须用户确认, 且 autoban 只对"有入站连接"的 IP 自动处置。
"""
import re, subprocess, json, datetime

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

# 1) 认证层: xray accepted 来源集合
authed = set()
log = sh('journalctl -u xray --since "24 hours ago" --no-pager 2>/dev/null')
for m in re.finditer(r'from \[?([0-9a-fA-F:.]+?)\]?:\d+ accepted', log):
    authed.add(m.group(1))

# 2) SS 通道: 当前 40244 连接来源(SS不走xray日志)
ss_conn = set()
for line in sh('ss -tn 2>/dev/null | grep ":40244"').splitlines():
    m = re.search(r'\s(\[?[0-9a-fA-F:.]+\]?):\d+\s*$', line)
    if m:
        ss_conn.add(m.group(1).strip('[]'))
authed |= ss_conn

# 2b) 443 当前入站连接来源(区分客户端 vs 目标站; 快照判据)
clients = set()
ss_out = sh("ss -Htn state established '( sport = :443 )' 2>/dev/null")
for line in ss_out.splitlines():
    p = line.split()
    if not p:
        continue
    m = re.match(r'\[?([0-9a-fA-F:.]+)\]?:\d+$', p[-1])
    if m:
        ip = m.group(1)
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        clients.add(ip)
clients_ok = bool(ss_out.strip())   # 快照是否可用

# 2c) 黑洞集合: 已封禁的 IP
blackholed = set()
for fam, table, sname in (("ip", "filter", "blackhole"), ("ip6", "filter", "blackhole6")):
    out = sh("nft list set %s %s %s 2>/dev/null" % (fam, table, sname))
    blackholed |= set(re.findall(r'([0-9a-fA-F:.]+) timeout', out))

# 3) 防火墙集合: 所有打过443的 IP + 流量
rows = []
for fam, table in (("ip", "traffic"), ("ip6", "traffic6")):
    out = sh("nft list set %s %s ss_clients 2>/dev/null" % (fam, table))
    for m in re.finditer(r'([0-9a-fA-F:.]+) counter packets (\d+) bytes (\d+)', out):
        rows.append((int(m.group(3)), int(m.group(2)), m.group(1)))
rows.sort(reverse=True)

# 4) 分类
total_b = sum(r[0] for r in rows)
authed_rows = [r for r in rows if r[2] in authed]
scanner_rows = [r for r in rows if r[2] not in authed and r[0] >= 10 * 1024 * 1024]  # 未认证且>=10MB
noise_rows = [r for r in rows if r[2] not in authed and r[0] < 10 * 1024 * 1024]
active_rows = [r for r in scanner_rows if r[2] in clients]      # 有入站连接=活跃客户端
quiet_rows = [r for r in scanner_rows if r[2] not in clients]   # 无入站连接=疑似目标站/已离线

# 5) 标签
try:
    labels = json.load(open("/opt/traffic/ip_labels.json"))
except Exception:
    labels = {}

def tag_of(ip):
    t = labels.get(ip, "")
    if ip in blackholed:
        t = (t + " [已在黑洞]").strip()
    if ip in ss_conn:
        t = (t + " [SS通道]").strip()
    return t

print("=" * 60)
print("认证层差集审计  " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
print("=" * 60)
print("集合总计: %d 个IP / %.1f MB" % (len(rows), total_b / 1e6))
print("  ✅ 已认证(真用户): %d 个 / %.2f MB" % (len(authed_rows), sum(r[0] for r in authed_rows) / 1e6))
print("  ⚠️ 未认证且>=10MB(封禁候选): %d 个 / %.2f MB" % (len(scanner_rows), sum(r[0] for r in scanner_rows) / 1e6))
if scanner_rows:
    print("       ├ 活跃(有443入站连接, autoban 会自动处置): %d 个 / %.2f MB" % (len(active_rows), sum(r[0] for r in active_rows) / 1e6))
    print("       └ 静默(无443入站连接, 疑似目标站/已离线, 不判罚): %d 个 / %.2f MB" % (len(quiet_rows), sum(r[0] for r in quiet_rows) / 1e6))
print("  · 零星噪音(<10MB): %d 个 / %.2f MB" % (len(noise_rows), sum(r[0] for r in noise_rows) / 1e6))
print()
if not clients_ok and scanner_rows:
    print("⚠️ 入站连接快照为空(ss 无输出) —— 下方「静默」标注不可信, 请人工复核")
    print()
if authed_rows:
    print("【真用户】")
    for b, p, ip in authed_rows[:10]:
        print("   %-46s %8.2f MB  %s" % (ip, b / 1e6, tag_of(ip)))
    print()
if active_rows:
    print("【⚠️ 活跃候选: 未认证 + 大流量 + 有443入站连接】")
    for b, p, ip in active_rows[:10]:
        print("   %-46s %8.2f MB  (%d 包)  %s" % (ip, b / 1e6, p, tag_of(ip)))
    print("   → autoban 每 5 分钟自动处置(连续2轮超标即封 6/24/72h); 如需立即手工封禁须用户确认")
    print()
if quiet_rows:
    print("【静默(无入站连接): 疑似目标站/CDN 或已离线, 不判罚】")
    for b, p, ip in quiet_rows[:10]:
        print("   %-46s %8.2f MB  (%d 包)  %s" % (ip, b / 1e6, p, tag_of(ip)))
    print("   → @ss_clients 双向共用, 目标站 IP 会出现在集合里; 无入站连接者不封(除非人工核实)")
    print()
if not scanner_rows:
    print("【✅ 无封禁候选 (无未认证的大流量IP)】")

# 6) 留痕: 结果摘要写日志 (2026-09-11 公司侧ZCode 追加, 供两侧核查审计是否在跑)
try:
    with open("/root/ops/audit-auth.log", "a", encoding="utf-8") as f:
        f.write("%s 总计 %d IP/%.1f MB | 真用户 %d/%.1f MB | 封禁候选 %d/%.1f MB | 噪音 %d/%.1f MB\n" % (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), len(rows), total_b/1e6,
            len(authed_rows), sum(r[0] for r in authed_rows)/1e6,
            len(scanner_rows), sum(r[0] for r in scanner_rows)/1e6,
            len(noise_rows), sum(r[0] for r in noise_rows)/1e6))
        if scanner_rows:
            f.write("   候选构成: 活跃(入站连接) %d/%.1f MB, 静默(无入站) %d/%.1f MB\n" % (
                len(active_rows), sum(r[0] for r in active_rows)/1e6,
                len(quiet_rows), sum(r[0] for r in quiet_rows)/1e6))
            f.write("   候选最高: %s %.1f MB (%d 包)\n" % (scanner_rows[0][2], scanner_rows[0][0]/1e6, scanner_rows[0][1]))
except Exception as e:
    print("[warn] 写日志失败: %s" % e)
