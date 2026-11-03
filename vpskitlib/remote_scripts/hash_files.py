#!/usr/bin/env python3
"""读取 stdin 的路径列表，输出 {path: {sha256, size, mode} | null}。"""
import hashlib
import json
import os
import stat
import sys


def main():
    paths = json.load(sys.stdin)
    result = {}
    for path in paths:
        try:
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                result[path] = {"error": "symlink"}
                continue
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            result[path] = {
                "sha256": h.hexdigest(),
                "size": st.st_size,
                "mode": stat.S_IMODE(st.st_mode),
            }
        except FileNotFoundError:
            result[path] = None
        except Exception as exc:
            result[path] = {"error": str(exc)}
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
