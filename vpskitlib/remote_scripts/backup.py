#!/usr/bin/env python3
"""备份 manifest 中的现有文件 + 当前 nft ruleset + 服务状态。"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="备份目录（绝对路径）")
    args = ap.parse_args()

    with open(0, "r", encoding="utf-8") as f:
        paths = json.load(f)

    os.makedirs(args.dir, mode=0o700, exist_ok=True)
    copied = []
    for path in paths:
        try:
            if not os.path.isfile(path):
                continue
            dest = os.path.join(args.dir, path.lstrip("/"))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(path, dest)
            copied.append(path)
        except Exception:
            pass

    nft_path = os.path.join(args.dir, "nft.ruleset")
    try:
        with open(nft_path, "w", encoding="utf-8") as f:
            subprocess.run(["nft", "list", "ruleset"], stdout=f, stderr=subprocess.DEVNULL, timeout=20)
        os.chmod(nft_path, 0o600)
    except Exception:
        pass

    services = ["xray", "ss-server", "traffic-web", "traffic-monitor", "sub", "autoban", "fail2ban", "nftables"]
    with open(os.path.join(args.dir, "services.txt"), "w", encoding="utf-8") as f:
        for name in services:
            try:
                active = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=5).stdout.strip()
                enabled = subprocess.run(["systemctl", "is-enabled", name], capture_output=True, text=True, timeout=5).stdout.strip()
            except Exception:
                active = enabled = "unknown"
            f.write("%s\t%s\t%s\n" % (name, active, enabled))

    with open(os.path.join(args.dir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump({"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "files": copied}, f, ensure_ascii=False, indent=2)

    print(json.dumps({"backup_dir": args.dir, "files": copied, "nft_saved": os.path.exists(nft_path)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
