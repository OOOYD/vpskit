#!/bin/bash
# 每日快照 + 备份 + 清理；由 traffic-snapshot.timer 调用
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
echo "[$(date '+%F %T')] snapshot+backup daily-$STAMP ok (keep ${KEEP}d)"
