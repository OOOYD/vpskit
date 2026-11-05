#!/bin/bash
# 每日快照 + 备份 + 清理；可选 restic 离岸加密备份
set -u
KEEP=$(python3 - <<'PY' 2>/dev/null || echo 14
try:
    import sys
    sys.path.insert(0, "/opt/traffic")
    import kitconf
    print(int(getattr(kitconf, "TRAFFIC_SNAPSHOT_KEEP_DAYS", 14)))
except Exception:
    print(14)
PY
)
STAMP=$(date +%F)
OPS=/usr/local/bin/ops
[ -x "$OPS" ] || { echo "ops 不存在"; exit 1; }
"$OPS" snapshot "daily-$STAMP" || exit 1
"$OPS" backup "daily-$STAMP" || exit 1
find /root/ops/snapshots -mindepth 1 -maxdepth 1 -type d -name 'daily-*' -mtime "+$KEEP" -exec rm -rf {} + 2>/dev/null || true
find /root/ops/backups  -mindepth 1 -maxdepth 1 -type d -name 'daily-*' -mtime "+$KEEP" -exec rm -rf {} + 2>/dev/null || true

# 可选：restic 离岸加密备份（config 里 restic_repo 非空才执行）
RESTIC_REPO=$(python3 - <<'PY' 2>/dev/null || echo ""
try:
    import sys
    sys.path.insert(0, "/opt/traffic")
    import kitconf
    print(getattr(kitconf, "RESTIC_REPO", "") or "")
except Exception:
    print("")
PY
)
if [ -n "$RESTIC_REPO" ]; then
  PASS_FILE=$(python3 - <<'PY' 2>/dev/null || echo "/root/.restic-pass"
try:
    import sys
    sys.path.insert(0, "/opt/traffic")
    import kitconf
    print(getattr(kitconf, "RESTIC_PASSWORD_FILE", "/root/.restic-pass"))
except Exception:
    print("/root/.restic-pass")
PY
)
  if command -v restic >/dev/null 2>&1 && [ -r "$PASS_FILE" ]; then
    export RESTIC_REPOSITORY="$RESTIC_REPO"
    export RESTIC_PASSWORD_FILE="$PASS_FILE"
    if restic backup /root/ops /opt/traffic /opt/sub /etc/nftables.conf --tag vpskit --host "$(hostname)" >> /var/log/vpskit-restic.log 2>&1; then
      restic forget --keep-daily 7 --keep-weekly 4 --prune >> /var/log/vpskit-restic.log 2>&1 || true
      echo "[$(date '+%F %T')] restic 备份完成"
    else
      echo "[$(date '+%F %T')] restic 备份失败，见 /var/log/vpskit-restic.log" >&2
    fi
  else
    echo "[$(date '+%F %T')] 配置了 restic_repo，但 restic 或密码文件不可用" >&2
  fi
fi
echo "[$(date '+%F %T')] snapshot+backup daily-$STAMP ok (keep ${KEEP}d)"
