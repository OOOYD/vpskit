#!/usr/bin/env bash
# 兼容旧入口：install.sh <ssh别名> [--dry]
# 新工具请直接用: ./vpskit plan <node> / ./vpskit apply <node>
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
if [ $# -lt 1 ]; then
  echo "用法: bash install.sh <node> [--dry]"
  echo "推荐: ./vpskit init <node> --host <ip> 后 ./vpskit plan <node>"
  exit 1
fi
NODE="$1"; shift
DRY=0
for arg in "$@"; do
  case "$arg" in
    --dry) DRY=1 ;;
    *) echo "旧参数不再支持: $arg（请用 ./vpskit --help）"; exit 1 ;;
  esac
done
if [ "$DRY" = "1" ]; then
  exec "$DIR/vpskit" plan "$NODE"
fi
exec "$DIR/vpskit" apply "$NODE"
