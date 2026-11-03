#!/bin/bash
# xray 条件自愈：内存警戒 + xray RSS 高 → 条件重启
# 参数来自 /etc/default/xray-selfheal（unit 的 EnvironmentFile）
set -u
THRESH_AVAIL="${THRESH_AVAIL:-204800}"   # kB
THRESH_RSS="${THRESH_RSS:-256000}"       # kB
MIN_INTERVAL="${MIN_INTERVAL:-604800}"   # 秒
OPS="${OPS:-/usr/local/bin/ops}"
STATE="${STATE:-/opt/ops/selfheal_state}"
LOG="${LOG:-/opt/ops/selfheal.log}"

mkdir -p "$(dirname "$LOG")" "$(dirname "$STATE")"
log() { echo "$(date '+%F %T') $*" >> "$LOG"; }

AVAIL_KB=$(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
XPID=$(systemctl show -p MainPID --value xray 2>/dev/null || echo 0)
if [ -z "$XPID" ] || [ "$XPID" = "0" ]; then
  log "CRIT xray 未运行，需人工介入"
  exit 0
fi
RSS_KB=$(awk '/VmRSS/{print $2}' "/proc/$XPID/status" 2>/dev/null || echo 0)
[ "${FORCE:-0}" = "1" ] && { AVAIL_KB=$((THRESH_AVAIL-1)); RSS_KB=$((THRESH_RSS+1)); }

HITS=0; LAST=0; LAST_ALERT=0
[ -f "$STATE" ] && . "$STATE"
NOW=$(date +%s)

if [ "$AVAIL_KB" -lt "$THRESH_AVAIL" ] && [ "$RSS_KB" -gt "$THRESH_RSS" ]; then
  HITS=$((HITS+1))
  if [ "$HITS" -ge 2 ]; then
    if [ $((NOW - LAST)) -lt "$MIN_INTERVAL" ]; then
      log "ALERT 可用=${AVAIL_KB}kB RSS=${RSS_KB}kB 连续${HITS}轮命中，但距上次自愈不足 7 天，不动手"
      echo "HITS=0; LAST=$LAST; LAST_ALERT=$NOW" > "$STATE"
    else
      log "HEAL 可用=${AVAIL_KB}kB RSS=${RSS_KB}kB 连续2轮命中 → systemctl restart xray"
      systemctl restart xray
      sleep 3
      if systemctl is-active --quiet xray; then
        log "HEAL 重启成功，新PID=$(systemctl show -p MainPID --value xray)"
        if [ -x "$OPS" ]; then
          "$OPS" log -a 自愈脚本 -t 自愈 -l 重要 -i 🛠 -r "xray_selfheal" \
            "自动重启 xray：可用内存<${THRESH_AVAIL}kB 且 RSS>${THRESH_RSS}kB 连续2轮" >> "$LOG" 2>&1 || true
        fi
        echo "HITS=0; LAST=$NOW; LAST_ALERT=$NOW" > "$STATE"
      else
        log "ERROR 重启后 xray 未 active，需人工介入"
        echo "HITS=0; LAST=$LAST; LAST_ALERT=$NOW" > "$STATE"
      fi
    fi
  else
    echo "HITS=$HITS; LAST=$LAST; LAST_ALERT=$LAST_ALERT" > "$STATE"
  fi
else
  if [ "$AVAIL_KB" -lt "$THRESH_AVAIL" ] && [ $((NOW - LAST_ALERT)) -ge 3600 ]; then
    log "ALERT 可用=${AVAIL_KB}kB<${THRESH_AVAIL}kB 但 xray RSS=${RSS_KB}kB<=${THRESH_RSS}kB，疑非 xray 问题，观察"
    LAST_ALERT=$NOW
  fi
  echo "HITS=0; LAST=$LAST; LAST_ALERT=$LAST_ALERT" > "$STATE"
fi
