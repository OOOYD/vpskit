#!/bin/bash
# kit-status — AI 排障一条命令：机器当前状态的"蛛丝马迹"快照
# 用法: ssh <host> kit-status          （或 kit-status --tail 看纯尾部）
# 原则: 全部只读；输出就是给 AI 看的，紧凑、可 grep
set -u
TAIL_ONLY=0; [ "${1:-}" = "--tail" ] && TAIL_ONLY=1

S=$(systemctl is-active xray ss-server sub traffic-web traffic-monitor fail2ban 2>/dev/null)
echo "== 服务状态(统一8项) =="
echo "$S"
if [ "$TAIL_ONLY" = "1" ]; then
  journalctl -u xray -n 30 --no-pager 2>/dev/null | tail -15
  tail -20 /opt/traffic/autoban.log 2>/dev/null
  tail -10 /opt/ops/selfheal.log 2>/dev/null
  exit 0
fi

echo "== 资源 =="
uptime | sed 's/^ *//'
free -m 2>/dev/null | awk 'NR==2{printf "内存: %dMB 可用 / %.1fGB 总量 (xray RSS: ", $7, $2/1024}'
[ -n "$(systemctl show -p MainPID --value xray 2>/dev/null)" ] && \
  awk '/VmRSS/{printf "%.0fMB", $2/1024}' /proc/$(systemctl show -p MainPID --value xray)/status 2>/dev/null
echo ")"
df -h / | awk 'NR==2{printf "磁盘: %s 占比 %s\n", $4, $5}'

echo "== 监听端口 =="
ss -tulnp 2>/dev/null | grep LISTEN | awk '{print $5, $(NF)}' | sort -u | head -12

echo "== 防火墙计数器(最近命中) =="
nft list ruleset 2>/dev/null | grep -E "counter packets" | head -6

echo "== fail2ban 封禁 =="
fail2ban-client status sshd 2>/dev/null | grep -E "Currently banned|Total banned"
if command -v vnstat >/dev/null 2>&1; then
  echo "== 流量(近5日) =="
  vnstat -d 5 2>/dev/null | tail -8
fi

echo "== 最近变更留痕 =="
tail -3 /root/ops/kit-install.log 2>/dev/null
cat /root/ops/kit-node-info.yaml 2>/dev/null | head -6

echo "== 日志尾巴 =="
journalctl -u xray -n 20 --no-pager 2>/dev/null | tail -8
echo "-- autoban.log --"
tail -8 /opt/traffic/autoban.log 2>/dev/null
echo "-- selfheal.log --"
tail -5 /opt/ops/selfheal.log 2>/dev/null
echo "-- ssh 失败(近24h) --"
journalctl -u ssh -S -24h 2>/dev/null | grep -c "Failed password"
