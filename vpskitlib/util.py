"""通用工具函数：文件、哈希、JSON、日志、脱敏。"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

# ---------------------------------------------------------------- exceptions


class VpskitError(Exception):
    """可预期的业务错误；CLI 只打印消息，不打印 traceback。"""


class CommandError(VpskitError):
    def __init__(self, cmd: Sequence[str], returncode: int, stdout: str = "", stderr: str = ""):
        self.cmd = list(cmd)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        msg = "命令失败（exit %s）: %s" % (returncode, " ".join(shlex.quote(x) for x in cmd))
        if stderr.strip():
            msg += "\n" + stderr.strip()
        super().__init__(msg)


# ---------------------------------------------------------------- terminal


_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
_JSON_MODE = False


def set_json_mode(enabled: bool) -> None:
    """--json 时把人类可读日志全部赶到 stderr，保证 stdout 只有 JSON。"""
    global _JSON_MODE
    _JSON_MODE = bool(enabled)


def _stream():
    return sys.stderr if _JSON_MODE else sys.stdout


def _c(code: str, text: str) -> str:
    return "\033[%sm%s\033[0m" % (code, text) if _COLOR else text


def info(msg: str) -> None:
    print("%s %s" % (_c("1;34", "[i]"), msg), file=_stream(), flush=True)


def ok(msg: str) -> None:
    print("%s %s" % (_c("1;32", "[+]"), msg), file=_stream(), flush=True)


def warn(msg: str) -> None:
    print("%s %s" % (_c("1;33", "[!]"), msg), file=sys.stderr, flush=True)


def error(msg: str) -> None:
    print("%s %s" % (_c("1;31", "[x]"), msg), file=sys.stderr, flush=True)


def step(msg: str) -> None:
    print("\n%s %s" % (_c("1;36", "==>"), _c("1", msg)), file=_stream(), flush=True)


def detail(msg: str) -> None:
    print("    %s" % msg, file=_stream(), flush=True)


# ---------------------------------------------------------------- time


def now_iso() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def now_stamp() -> str:
    return _dt.datetime.now().strftime("%Y%m%d-%H%M%S")


# ---------------------------------------------------------------- files


def ensure_dir(path: Path, mode: int = 0o755) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    return path


def read_json(path: Path, default: Any = None) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as exc:
        raise VpskitError("读取 JSON 失败 %s: %s" % (path, exc)) from exc


def write_json_atomic(path: Path, data: Any, mode: int = 0o600) -> None:
    ensure_dir(path.parent, 0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=False)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def write_text_atomic(path: Path, text: str, mode: int = 0o644) -> None:
    ensure_dir(path.parent, 0o755)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def sha256_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def file_mode(path: Path) -> int:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return 0


def which(name: str) -> Optional[str]:
    return shutil.which(name)


# ---------------------------------------------------------------- subprocess


def run(
    cmd: Sequence[str],
    *,
    input_text: Optional[str] = None,
    timeout: Optional[int] = 120,
    check: bool = True,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[Path] = None,
) -> subprocess.CompletedProcess:
    """运行本地命令，统一返回 CompletedProcess。"""
    try:
        proc = subprocess.run(
            list(cmd),
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=str(cwd) if cwd else None,
        )
    except FileNotFoundError as exc:
        raise VpskitError("找不到命令: %s" % cmd[0]) from exc
    except subprocess.TimeoutExpired as exc:
        raise VpskitError("命令超时（%ss）: %s" % (timeout, " ".join(cmd))) from exc
    if check and proc.returncode != 0:
        raise CommandError(cmd, proc.returncode, proc.stdout, proc.stderr)
    return proc


# ---------------------------------------------------------------- redaction / display


_SECRET_KEY = (
    r'(?:["\']?(?:private[_-]?key|public[_-]?key|password|passwd|uuid|short[_-]?ids?|'
    r'traffic[_-]?web[_-]?key|sub[_-]?path|token|secret|authorization|bearer)["\']?'
    r'|["\']id["\'])'
)
_SECRET_VALUE = r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|\[[^\]\n]*\]|\{[^}\n]*\}|[^\s,]+)'
_SECRET_LINE_RE = re.compile(r'(?i)(' + _SECRET_KEY + r'\s*[:=]\s*)' + _SECRET_VALUE)


def _redact_value(match: "re.Match") -> str:
    key, value = match.group(1), match.group(2)
    if value.startswith('"'):
        return key + '"***"'
    if value.startswith("'"):
        return key + "'***'"
    return key + "***"

def redact_text(text: str) -> str:
    """把常见秘密字段的值替换成 ***。用于 diff / 日志。"""
    return _SECRET_LINE_RE.sub(_redact_value, text)


def fingerprint(value: str, n: int = 8) -> str:
    """对秘密做不可逆指纹，用于确认“是不是同一把”，不泄露原文。"""
    if not value:
        return "-"
    return sha256_bytes(value.encode())[:n]


def mask_ip(ip: str) -> str:
    """分享视图里掩盖 IP：v4 保留前两段，v6 保留前缀。"""
    if not ip:
        return ip
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:3]) + "::***"
    parts = ip.split(".")
    if len(parts) == 4:
        return "%s.%s.*.*" % (parts[0], parts[1])
    return "***"


def human_bytes(n: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(n)
    for unit in units:
        if abs(value) < 1024 or unit == units[-1]:
            return ("%.0f %s" % (value, unit)) if unit == "B" else ("%.2f %s" % (value, unit))
        value /= 1024.0
    return "%.2f TB" % value


def as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_duration(value: Any, default: int) -> int:
    """'120' / '120s' / '5m' / '1h' -> 秒。"""
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip().lower()
    m = re.fullmatch(r"(\d+)\s*([smh]?)", text)
    if not m:
        return default
    n = int(m.group(1))
    return n * {"": 1, "s": 1, "m": 60, "h": 3600}[m.group(2)]


def unique_preserve(items: Iterable[str]) -> list:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
