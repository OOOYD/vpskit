#!/usr/bin/env python3
"""从 backup 目录恢复文件、nft ruleset，并重启服务。

只恢复 /etc /opt /usr/local /root/ops 下的路径，避免备份目录被篡改后写到任意位置。
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

ALLOWED = ("/etc/", "/opt/", "/usr/local/", "/root/ops/")
SKIP = {"meta.json", "services.txt", "nft.ruleset"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    args = ap.parse_args()
    if not os.path.isdir(args.dir):
        print(json.dumps({"ok": False, "error": "backup 目录不存在"}))
        return 2

    restored, errors = [], []
    for root, _dirs, files in os.walk(args.dir):
        for name in files:
            if name in SKIP:
                continue
            src = os.path.join(root, name)
            rel = os.path.relpath(src, args.dir)
            dest = "/" + rel
            if not dest.startswith(ALLOWED):
                errors.append({"path": dest, "error": "path not allowed"})
                continue
            try:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copy2(src, dest)
                restored.append(dest)
            except Exception as exc:
                errors.append({"path": dest, "error": str(exc)})

    nft_file = os.path.join(args.dir, "nft.ruleset")
    nft_ok = False
    if os.path.isfile(nft_file) and os.path.getsize(nft_file) > 0:
        try:
            # dump 是叠加语义：先 flush 再 load，否则旧 drop/新 accept 会混在一起
            subprocess.run(["nft", "flush", "ruleset"], check=True, timeout=20)
            subprocess.run(["nft", "-f", nft_file], check=True, timeout=20)
            nft_ok = True
        except Exception as exc:
            errors.append({"path": "nft.ruleset", "error": str(exc)})
    elif os.path.isfile("/etc/nftables.conf"):
        try:
            subprocess.run(["nft", "flush", "ruleset"], check=True, timeout=20)
            subprocess.run(["nft", "-f", "/etc/nftables.conf"], check=True, timeout=20)
            nft_ok = True
        except Exception as exc:
            errors.append({"path": "/etc/nftables.conf", "error": str(exc)})

    for cmd in (
        ["systemctl", "daemon-reload"],
        ["systemctl", "restart", "xray"],
        ["systemctl", "restart", "ss-server"],
        ["systemctl", "restart", "traffic-web"],
        ["systemctl", "restart", "sub"],
        ["systemctl", "restart", "fail2ban"],
    ):
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        except Exception:
            pass

    print(json.dumps({"ok": not errors, "restored": restored, "nft_ok": nft_ok, "errors": errors}, ensure_ascii=False))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
