#!/usr/bin/env python3
"""把 staging 里的文件按 manifest 原子部署到目标路径。

只写 manifest 列出的路径；校验源文件 sha256；目标是 symlink 时拒绝。
"""
import argparse
import grp
import hashlib
import json
import os
import pwd
import shutil
import stat
import sys


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ids(owner, group):
    try:
        uid = pwd.getpwnam(owner).pw_uid
    except KeyError:
        uid = 0
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        gid = 0
    return uid, gid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--staging", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    with open(args.manifest, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    changed, skipped, errors = [], [], []
    for entry in manifest:
        path = entry["path"]
        src = os.path.join(args.staging, entry["source"])
        try:
            if not os.path.isfile(src):
                raise IOError("staging 缺少文件 %s" % src)
            digest = sha256(src)
            if digest != entry["sha256"]:
                raise IOError("staging 文件 hash 不匹配: %s" % src)
            if os.path.islink(path):
                raise IOError("目标是 symlink，拒绝覆盖: %s" % path)
            if os.path.isdir(path):
                raise IOError("目标是目录，拒绝覆盖: %s" % path)
            if os.path.isfile(path) and sha256(path) == digest:
                st = os.lstat(path)
                want_mode = int(entry.get("mode", 0o644))
                want_uid, want_gid = ids(entry.get("owner", "root"), entry.get("group", "root"))
                if stat.S_IMODE(st.st_mode) == want_mode and st.st_uid == want_uid and st.st_gid == want_gid:
                    skipped.append(path)
                    continue
            if args.dry_run:
                changed.append(path)
                continue
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            uid, gid = ids(entry.get("owner", "root"), entry.get("group", "root"))
            tmp = path + ".vpskit-new"
            shutil.copy2(src, tmp)
            os.chmod(tmp, int(entry.get("mode", 0o644)))
            os.chown(tmp, uid, gid)
            os.replace(tmp, path)
            changed.append(path)
        except Exception as exc:
            errors.append({"path": path, "error": str(exc)})

    print(json.dumps({"changed": changed, "skipped": skipped, "errors": errors}, ensure_ascii=False))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
