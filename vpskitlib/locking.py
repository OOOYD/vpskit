"""跨平台本地文件锁：Linux/macOS 用 fcntl，Windows 用 msvcrt。

只用于防止两个 vpskit 进程同时操作同一节点；不是安全边界。
"""
from __future__ import annotations

import os
from pathlib import Path

from .util import VpskitError


class FileLock:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.fh = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "a+", encoding="utf-8")
        try:
            if os.name == "nt":
                import msvcrt  # type: ignore

                self.fh.seek(0, os.SEEK_END)
                if self.fh.tell() == 0:
                    self.fh.write("vpskit-lock")
                    self.fh.flush()
                self.fh.seek(0)
                try:
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise VpskitError("另一个 vpskit 进程正在操作该节点（锁: %s）" % self.path) from exc
            else:
                import fcntl

                try:
                    fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise VpskitError("另一个 vpskit 进程正在操作该节点（锁: %s）" % self.path) from exc
        except Exception:
            self.fh.close()
            self.fh = None
            raise
        return self

    def __exit__(self, *exc):
        if not self.fh:
            return
        try:
            if os.name == "nt":
                import msvcrt  # type: ignore

                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.fh, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            self.fh.close()
            self.fh = None
