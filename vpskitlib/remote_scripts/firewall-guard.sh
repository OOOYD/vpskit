#!/bin/bash
# vpskit firewall guard：延迟 N 秒后，如果没看到确认标记，就恢复备份规则。
# 用法: firewall-guard.sh <backup_dir> <delay_seconds>
set -u
BAK="${1:?backup dir}"
DELAY="${2:-120}"
MARKER="${VPSKIT_GUARD_MARKER:-/run/vpskit-firewall-ok}"
LOG="${VPSKIT_GUARD_LOG:-/root/.vpskit/firewall-guard.log}"

sleep "$DELAY"
if [ -f "$MARKER" ]; then
  exit 0
fi

mkdir -p "$(dirname "$LOG")"
{
  echo "[$(date '+%F %T')] 未收到确认，恢复防火墙: $BAK"
  if [ -f "$BAK/nft.ruleset" ] && [ -s "$BAK/nft.ruleset" ]; then
    # 关键：nft list ruleset 的 dump 是“叠加”语义，必须先 flush，否则新规则的 drop 仍在
    if nft flush ruleset 2>>"$LOG" && nft -f "$BAK/nft.ruleset" 2>>"$LOG"; then
      echo "[$(date '+%F %T')] nft ruleset 已恢复（flush + load）"
    else
      echo "[$(date '+%F %T')] nft ruleset 恢复失败" >>"$LOG"
    fi
  fi
  if [ -f "$BAK/etc/nftables.conf" ]; then
    cp -f "$BAK/etc/nftables.conf" /etc/nftables.conf && echo "[$(date '+%F %T')] /etc/nftables.conf 已恢复"
  fi
  systemctl restart fail2ban 2>/dev/null || true
  logger -t vpskit "firewall guard restored rules after ${DELAY}s without confirmation"
} >>"$LOG" 2>&1
exit 0
