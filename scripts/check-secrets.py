#!/usr/bin/env python3
"""扫描 git 跟踪文件里的已知秘密（从本地 state/ 派生，不在仓库里硬编码任何值）。

用法: python3 scripts/check-secrets.py [--history]
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def known_values():
    values = set()
    for path in sorted((ROOT / "state").glob("*/secrets.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        reality = data.get("reality") or {}
        for key in ("private_key", "public_key", "short_id"):
            if reality.get(key):
                values.add(str(reality[key]))
        for key in ("ss_password", "traffic_web_key"):
            if data.get(key):
                values.add(str(data[key]))
        for rec in (data.get("clients") or {}).values():
            for key in ("uuid", "sub_path"):
                if rec.get(key):
                    values.add(str(rec[key]))
    return {v for v in values if len(v) >= 8}


GENERIC = [
    re.compile(r'"privateKey"\s*:\s*"[A-Za-z0-9_-]{40,}"'),
    re.compile(r'"password"\s*:\s*"[^"]{16,}"'),
    re.compile(r'"uuid"\s*:\s*"[0-9a-fA-F-]{36}"'),
]


def scan_worktree(values):
    files = subprocess.check_output(["git", "ls-files", "-z"], cwd=str(ROOT)).split(b"\0")
    bad = 0
    for raw in files:
        if not raw:
            continue
        rel = raw.decode("utf-8", "replace")
        path = ROOT / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for value in values:
            if value and value in text:
                print("[!] 命中已知秘密: %s" % rel)
                bad += 1
                break
        else:
            for pat in GENERIC:
                if pat.search(text):
                    print("[!] 命中疑似秘密格式: %s" % rel)
                    bad += 1
                    break
    if not bad:
        print("[+] 当前工作树（git 跟踪文件）未命中已知秘密")
    return bad


def scan_history(values):
    commits = subprocess.check_output(["git", "rev-list", "--all"], cwd=str(ROOT), text=True).split()
    hits = 0
    for commit in commits:
        for value in values:
            proc = subprocess.run(["git", "grep", "-q", "-F", value, commit], cwd=str(ROOT))
            if proc.returncode == 0:
                print("[!] 历史 commit 含已知秘密: %s" % commit[:10])
                hits += 1
                break
        if hits >= 5:
            break
    if hits:
        print("[!] 旧历史含秘密：不要直接推送；见 docs/MIGRATION.md")
    else:
        print("[+] 历史未命中已知秘密")
    return hits


def main():
    values = known_values()
    bad = scan_worktree(values)
    if "--history" in sys.argv:
        bad += scan_history(values)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
