#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""autoban.py — 未认证大流量自动封禁 (2026-09-11, 阈值校准 2026-09-13)

背景: REALITY fallback 会把未认证连接转发到伪装站(www.cloudflare.com);
      扫描器把本机当"免费中转"使用, 每隔几天来一波流量暴涨。
策略: 每 5 分钟读 @ss_clients 计数器增量, 折算成小时率; 对"未认证 + 超阈值"的
      IP 自动加入 nftables blackhole 集合(默认 6h, 反复者递增), 实现自动止损。
      认证用户可以豁免(在 xray accepted 日志里出现过 = 真用户)。
安全边界(2026-09-13 加固, 用户要求"绝不能封到自己"):
      ① 只封"当前对本机 443 有入站连接"的 IP —— @ss_clients 双向共用, 目标站(CDN等)
         也在集合里, 封目标站会切断正常访问; 目标站不会有入站连接, 以此区分;
      ② 认证豁免: 近 26h 出现在 xray accepted 日志的 IP 全部豁免(自有设备旅行/换网
         只要用有效订阅连一次即入豁免表, 保留 7 天);
      ③ 手工白名单 autoban_allow.txt (IP/CIDR, 永不禁);
      ④ 标签豁免: ip_labels.json 中带 家里/公司/手机 的 IP 不禁;
      ⑤ 连续 2 轮超标才封, 防偶发一次性大流量误判。
      ⑥ 应急解封: nft delete element ip|ip6 filter blackhole { <IP> } (SSH 22 不受封禁影响)
校准: 2026-09-13 — 初版阈值 100MB/5min 在 fallback 限速(16KB/s, 单连接上限
      ~5.8MB/5min)之后永远不可达, 上线两天 0 封禁。实测滥用分布后发现
      5MB/h 即可覆盖头部滥用者(实测头部 24~134MB/h)且能抓住"薅1MB豁免"的探测,
      故改为 5MB/小时 折算率。
"""
import json, os, re, subprocess, time, datetime, sys

BASE = "/opt/traffic"
try:
    import kitconf
except ImportError:
    kitconf = None
def _c(name, default):
    return getattr(kitconf, name, default) if kitconf else default
REALITY_PORT = _c("REALITY_PORT", 443)
SS_PORT = _c("SS_PORT", 0)
AUTOBAN_ENABLE = bool(_c("AUTOBAN_ENABLE", True))
STATE = os.path.join(BASE, "autoban_state.json")
LOG = os.path.join(BASE, "autoban.log")
AUTH_DB = os.path.join(BASE, "authed_ips.json")   # {ip: last_seen_ts}
LABELS = os.path.join(BASE, "ip_labels.json")

THRESH_MB = _c("AUTOBAN_THRESH_MB", 2)            # 小时率阈值(MB/h)：未认证 IP 折算小时率超过即封
                         # 2026-10-26 由 5 调至 2：64KB 豁免后扫描器靠多开连接攒量，
                         # 5MB/h 放过中小户；真实用户若未认证早已被 fallback 限速，无外溢风险
WINDOW_OK = 3600         # 折算基准窗口(秒)=1小时，实际按 state 时间差换算
MIN_ELAPSED = 120        # 时间差下限(秒)：防止短间隔重复运行时折算倍数过大
STRIKES_REQUIRED = _c("AUTOBAN_STRIKES", 2)     # 连续 N 轮超标才封（防偶发一次性大流量误判）
BAN_STEPS_H = [6, 24, 72]  # 封禁时长阶梯(小时)：首次/第二次/第三次+
MAX_BAN_KEEP_D = 30      # 封禁记录保留天数
ALLOW_FILE = os.path.join(BASE, "autoban_allow.txt")  # 手工白名单(永不禁)：每行一个 IP/CIDR

def sh(cmd, timeout=25):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)


def sh_out(cmd, timeout=25):
    return sh(cmd, timeout).stdout

def log(msg):
    line = "[%s] %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass

def load_json(p, d):
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return d

def save_json(p, d):
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False)
    os.replace(tmp, p)

def read_counters():
    """读双栈 @ss_clients 计数器 -> {ip: bytes}"""
    res = {}
    for fam, table in (("ip", "traffic"), ("ip6", "traffic6")):
        out = sh_out("nft list set %s %s ss_clients" % (fam, table))
        for m in re.finditer(r"([0-9a-fA-F:.]+) counter packets \d+ bytes (\d+)", out):
            res[m.group(1)] = int(m.group(2))
    return res

def collect_authed():
    """从 xray 日志采集最近认证成功的 IP -> 更新 authed_ips.json"""
    p = sh('journalctl -u xray --since "26 hours ago" --no-pager 2>/dev/null | grep "accepted"', timeout=60)
    if p.returncode != 0 and not p.stdout.strip():
        log("WARN journalctl 读取失败，本轮跳过封禁（防误封）")
        return None
    out = p.stdout
    db = load_json(AUTH_DB, {})
    now = time.time()
    for m in re.finditer(r"from \[?([0-9a-fA-F:.]+?)\]?:\d+ accepted", out):
        db[m.group(1)] = now
    # 清理 7 天未见的
    db = {ip: ts for ip, ts in db.items() if now - ts < 7 * 86400}
    save_json(AUTH_DB, db)
    return set(db.keys())

def blackholed():
    """当前黑洞集合内的 IP：已在封禁中的不重复封禁/升级
    (traffic 表计数先于 filter 表 drop，被封 IP 的计数器仍会增长，
     若不跳过会在封禁期内每轮重复触发、阶梯被瞬间拉满)"""
    out = sh_out("nft list set ip filter blackhole 2>/dev/null; nft list set ip6 filter blackhole6 2>/dev/null")
    return set(re.findall(r"([0-9a-fA-F:.]+) timeout", out))

def current_clients():
    """当前与本机 443 存在活跃入站连接的来源 IP。
    @ss_clients 是双向共用的：既记客户端(入站 saddr)，也记本机出访的目标站(出站 daddr)。
    目标站绝不能被封(会切断正常访问)，而目标站不会对本机 443 发起入站连接，
    因此以"是否有入站连接"区分客户端与目标站。"""
    out = sh_out("ss -Htn state established '( sport = :%d )' 2>/dev/null" % REALITY_PORT)
    ips = set()
    for ln in out.split("\n"):
        p = ln.split()
        if not p:
            continue
        m = re.match(r"\[?([0-9a-fA-F:.]+)\]?:\d+$", p[-1])
        if m:
            ip = m.group(1)
            if ip.startswith("::ffff:"):
                ip = ip[7:]
            ips.add(ip)
    return ips

def load_allow():
    """手工白名单（永不被自动封禁）：每行一个 IP 或 CIDR，# 注释"""
    import ipaddress
    nets = []
    try:
        for ln in open(ALLOW_FILE, encoding="utf-8"):
            ln = ln.split("#")[0].strip()
            if not ln:
                continue
            try:
                nets.append(ipaddress.ip_network(ln, strict=False))
            except ValueError:
                pass
    except OSError:
        pass
    return nets

def in_allow(ip, nets):
    """IP 是否命中白名单（支持单 IP 与 CIDR）"""
    import ipaddress
    if not nets:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)

def ban(ip, hours, dry_run=False):
    fam = "ip6" if ":" in ip else "ip"
    setname = "blackhole6" if fam == "ip6" else "blackhole"
    cmd = "nft add element %s filter %s { %s timeout %dh }" % (fam, setname, ip, hours)
    if dry_run:
        log("[dry-run] 将执行: %s" % cmd)
        return True
    sh(cmd)
    chk = sh_out("nft list set %s filter %s" % (fam, setname))
    return ip in chk


# 重启回填(2026-10-17): /etc/nftables.conf 只声明 blackhole 集合、不写元素,
# 重启会清空全部动态封禁; 而本脚本原先只处理"本轮新超标"的 IP, 不按 state 回填。
# 2026-10-16 宿主机维护重启后, 9 个仍在 72h 有效期内的封禁全部失效。
# 用 /run(tmpfs) 标记位保证"每个启动周期只回填一次"——这样应急解封
# (nft delete element ... blackhole) 之后不会被下一轮又加回去。
RESTORE_MARK = "/run/autoban-restored"


def restore_bans(st, already, allow, labels):
    """把 state 中仍在有效期内的封禁回填进黑洞集合；返回恢复条数"""
    if os.path.exists(RESTORE_MARK):
        return 0
    n = 0
    now = datetime.datetime.now()
    for ip, rec in (st.get("bans") or {}).items():
        try:
            last = datetime.datetime.strptime(rec.get("last", ""), "%Y-%m-%d %H:%M")
        except Exception:
            continue
        left = int(rec.get("hours", 6)) * 3600 - (now - last).total_seconds()
        if left <= 0 or ip in already or in_allow(ip, allow):
            continue
        if any(k in labels.get(ip, "") for k in ("家里", "公司", "手机")):
            continue
        fam = "ip6" if ":" in ip else "ip"
        setname = "blackhole6" if fam == "ip6" else "blackhole"
        secs = max(int(left), 60)
        sh("nft add element %s filter %s { %s timeout %ds }" % (fam, setname, ip, secs))
        if ip in sh_out("nft list set %s filter %s" % (fam, setname)):
            n += 1
    try:
        with open(RESTORE_MARK, "w", encoding="utf-8") as f:
            f.write("%s restored=%d\n" % (now.strftime("%Y-%m-%d %H:%M:%S"), n))
    except OSError:
        pass
    return n


def main(dry_run=False):
    now = time.time()
    st = load_json(STATE, {"counters": {}, "since": now, "bans": {}})
    prev, since = st.get("counters", {}), st.get("since", now)
    elapsed = max(now - since, MIN_ELAPSED)

    cur = read_counters()
    authed = collect_authed()
    if authed is None:
        # 认证日志不可用：只更新计数器，不做任何封禁
        st["counters"] = cur
        st["since"] = now
        st["last_run"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_json(STATE, st)
        print("本轮: 认证日志不可用，跳过封禁")
        return
    labels = load_json(LABELS, {})
    already = blackholed()
    clients = current_clients()
    allow = load_allow()
    strikes = {ip: n for ip, n in st.get("strikes", {}).items() if ip in cur}

    # 开机后首轮回填封禁(失败不影响主流程)
    try:
        restored = restore_bans(st, already, allow, labels)
        if restored:
            already = blackholed()
            log("重启回填: 恢复 %d 个仍在有效期内的封禁" % restored)
    except Exception as e:
        log("重启回填异常(不影响主流程): %s" % e)

    # 判定
    banned, skipped_auth = [], 0
    for ip, b2 in cur.items():
        b1 = prev.get(ip, 0)
        if b2 < b1:          # 集合元素重建(过期)
            prev[ip] = b2
            continue
        delta = b2 - b1
        if delta <= 0:
            continue
        rate_mb = delta / 1048576.0
        # 折算成小时率
        norm_mb = rate_mb * (WINDOW_OK / elapsed)
        if norm_mb < THRESH_MB:
            strikes.pop(ip, None)    # 本轮未超标：连续计数清零
            continue
        if ip not in clients:        # 非本机 443 入站客户端（多为被访问的目标站）→ 不判罚
            continue
        if ip in already:            # 已在黑洞中：不计新罪、不重复升级
            continue
        if ip in authed:             # 近期认证过的 IP（自有设备）→ 豁免
            skipped_auth += 1
            continue
        if in_allow(ip, allow):      # 手工白名单
            continue
        if any(k in labels.get(ip, "") for k in ("家里", "公司", "手机")):
            continue
        strikes[ip] = strikes.get(ip, 0) + 1
        if strikes[ip] < STRIKES_REQUIRED:
            continue                 # 连续 N 轮超标才封，防偶发一次性大流量误判
        # 执行封禁
        bans = st.setdefault("bans", {})
        rec = bans.get(ip, {"n": 0})
        rec["n"] = rec.get("n", 0) + 1
        hours = BAN_STEPS_H[min(rec["n"], len(BAN_STEPS_H)) - 1]
        ok = ban(ip, hours, dry_run=dry_run)
        rec["last"] = datetime.datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M")
        rec["hours"] = hours
        bans[ip] = rec
        if ok:
            banned.append((ip, norm_mb, hours, rec["n"]))
            strikes.pop(ip, None)
            log("已封禁 %s (1小时折算 %.0f MB/h, 第%d次, 禁%dh)" % (ip, norm_mb, rec["n"], hours))
        else:
            log("封禁失败(检查nft): %s" % ip)

    # 清理过期封禁记录
    cutoff = now - MAX_BAN_KEEP_D * 86400
    st["bans"] = {ip: r for ip, r in st.get("bans", {}).items()
                  if datetime.datetime.strptime(r.get("last", "2000-01-01 00:00"), "%Y-%m-%d %H:%M").timestamp() > cutoff}

    # 更新状态
    st["counters"] = cur
    st["since"] = now
    st["strikes"] = strikes
    st["last_run"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_json(STATE, st)

    print("本轮: 检查 %d 个IP, 豁免认证用户 %d 个, 新增封禁 %d 个" % (len(cur), skipped_auth, len(banned)))
    if banned:
        # 有封禁时输出摘要供通知
        with open(os.path.join(BASE, "autoban_pending.txt"), "w", encoding="utf-8") as f:
            for ip, mb, h, n in banned:
                f.write("%s\t%.0f MB\t%dh\t第%d次\n" % (ip, mb, h, n))

if __name__ == "__main__":
    if not AUTOBAN_ENABLE:
        print("[i] AUTOBAN_ENABLE=False，跳过")
        sys.exit(0)
    main(dry_run=("--dry-run" in sys.argv))
