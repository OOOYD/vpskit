"""每节点秘密的生成、持久化、轮换。

文件布局：state/<node>/secrets.json（0600）
{
  "version": 1,
  "reality": {"private_key": "...", "public_key": "...", "short_id": "..."},
  "ss_password": "...",
  "traffic_web_key": "...",
  "clients": {"main": {"uuid": "...", "sub_path": "/..."}}
}

原则：
  * 只在首次或显式 rotate 时生成；render 永远不改秘密。
  * 删除的 client 不从 secrets 里删除，方便回滚/重新加回。
  * 任何日志/终端输出只显示指纹，不显示原文。
"""
from __future__ import annotations

import os
import re
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from .config import NodeConfig
from .crypto import generate_keypair, keypair_from_private, random_hex, random_password, random_sub_path
from .util import VpskitError, fingerprint, read_json, write_json_atomic

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _new_client_record() -> Dict[str, str]:
    return {
        "uuid": str(uuid.uuid4()),
        "sub_path": random_sub_path(),
        "v2ray_path": random_sub_path(),
    }


def _normalize(data: Dict[str, Any], node: NodeConfig) -> bool:
    """补齐缺失字段；返回是否有改动。"""
    changed = False
    if data.get("version") != 1:
        data["version"] = 1
        changed = True

    reality = data.setdefault("reality", {})
    if not isinstance(reality, dict):
        reality = {}
        data["reality"] = reality
        changed = True
    private = str(reality.get("private_key") or "")
    public = str(reality.get("public_key") or "")
    if not private:
        private, public = generate_keypair()
        reality["private_key"] = private
        reality["public_key"] = public
        changed = True
    else:
        try:
            _, derived = keypair_from_private(private)
        except ValueError as exc:
            raise VpskitError("secrets.json 里的 REALITY 私钥无效: %s" % exc) from exc
        if public != derived:
            reality["public_key"] = derived
            changed = True
    if not str(reality.get("short_id") or ""):
        reality["short_id"] = random_hex(8)  # 16 hex = 8 bytes
        changed = True
    elif not re.fullmatch(r"[0-9a-f]{2,16}", str(reality["short_id"])):
        raise VpskitError("REALITY short_id 必须是偶数个 hex 字符（2..16）")

    if not str(data.get("ss_password") or ""):
        data["ss_password"] = random_password(32)
        changed = True
    if not str(data.get("traffic_web_key") or ""):
        data["traffic_web_key"] = random_hex(12)
        changed = True

    clients = data.setdefault("clients", {})
    if not isinstance(clients, dict):
        clients = {}
        data["clients"] = clients
        changed = True
    for client in node.clients:
        rec = clients.get(client.email)
        if not isinstance(rec, dict):
            rec = {}
            clients[client.email] = rec
            changed = True
        if not UUID_RE.match(str(rec.get("uuid") or "")):
            rec["uuid"] = str(uuid.uuid4())
            changed = True
        sub_path = str(rec.get("sub_path") or "")
        if not sub_path.startswith("/") or len(sub_path) < 9:
            rec["sub_path"] = random_sub_path()
            changed = True
        v2ray_path = str(rec.get("v2ray_path") or "")
        if not v2ray_path.startswith("/") or len(v2ray_path) < 9:
            rec["v2ray_path"] = random_sub_path()
            changed = True
    return changed


def load_secrets(path: Path) -> Optional[Dict[str, Any]]:
    data = read_json(path, None)
    if data is None:
        return None
    if not isinstance(data, dict):
        raise VpskitError("secrets.json 顶层必须是 object: %s" % path)
    return data


def ensure_secrets(node: NodeConfig, path: Path) -> Dict[str, Any]:
    data = load_secrets(path) or {}
    changed = _normalize(data, node)
    if changed or not path.exists():
        write_json_atomic(path, data, mode=0o600)
    else:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return data


def save_secrets(path: Path, data: Dict[str, Any]) -> None:
    write_json_atomic(path, data, mode=0o600)


def client_uuid(secrets: Dict[str, Any], email: str) -> str:
    try:
        return str(secrets["clients"][email]["uuid"])
    except KeyError as exc:
        raise VpskitError("secrets 缺少 client %s 的 UUID；请重新 render 或 rotate" % email) from exc


def client_sub_path(secrets: Dict[str, Any], email: str) -> str:
    try:
        return str(secrets["clients"][email]["sub_path"])
    except KeyError as exc:
        raise VpskitError("secrets 缺少 client %s 的订阅路径" % email) from exc


def client_v2ray_path(secrets: Dict[str, Any], email: str) -> str:
    try:
        return str(secrets["clients"][email]["v2ray_path"])
    except KeyError as exc:
        raise VpskitError("secrets 缺少 client %s 的 v2ray 订阅路径" % email) from exc


def rotate(
    node: NodeConfig,
    secrets: Dict[str, Any],
    what: Iterable[str],
    client_email: Optional[str] = None,
) -> List[str]:
    """显式轮换。返回变更项名称（不含秘密值）。"""
    what = set(what)
    changed: List[str] = []
    reality = secrets.setdefault("reality", {})
    if "all" in what or "reality" in what:
        private, public = generate_keypair()
        reality["private_key"] = private
        reality["public_key"] = public
        reality["short_id"] = random_hex(8)
        changed.append("REALITY 密钥对 + shortId")
    if "all" in what or "ss" in what:
        secrets["ss_password"] = random_password(32)
        changed.append("SS 密码")
    if "all" in what or "traffic" in what:
        secrets["traffic_web_key"] = random_hex(12)
        changed.append("流量页 key")
    if "all" in what or "sub" in what:
        for email, rec in secrets.setdefault("clients", {}).items():
            if client_email and email != client_email:
                continue
            rec["sub_path"] = random_sub_path()
            rec["v2ray_path"] = random_sub_path()
        changed.append("订阅路径" + ("（%s）" % client_email if client_email else ""))
    if "all" in what or "uuid" in what:
        for email, rec in secrets.setdefault("clients", {}).items():
            if client_email and email != client_email:
                continue
            rec["uuid"] = str(uuid.uuid4())
        changed.append("客户端 UUID" + ("（%s）" % client_email if client_email else ""))
    return changed


def summary(node: NodeConfig, secrets: Dict[str, Any]) -> Dict[str, Any]:
    """给终端/日志看的指纹摘要。"""
    reality = secrets.get("reality", {})
    clients = {}
    for client in node.clients:
        rec = secrets.get("clients", {}).get(client.email, {})
        clients[client.email] = {
            "uuid": fingerprint(str(rec.get("uuid", ""))),
            "sub_path": fingerprint(str(rec.get("sub_path", ""))),
            "v2ray_path": fingerprint(str(rec.get("v2ray_path", ""))),
        }
    return {
        "reality_public": fingerprint(str(reality.get("public_key", ""))),
        "short_id": str(reality.get("short_id", "")),
        "ss_password": fingerprint(str(secrets.get("ss_password", ""))),
        "traffic_web_key": fingerprint(str(secrets.get("traffic_web_key", ""))),
        "clients": clients,
    }


def secret_values(node: NodeConfig, secrets: Dict[str, Any]) -> Dict[str, Any]:
    """完整秘密（只在需要写进配置文件/导入卡时使用，不要打印）。"""
    return {
        "reality_private_key": secrets["reality"]["private_key"],
        "reality_public_key": secrets["reality"]["public_key"],
        "reality_short_id": secrets["reality"]["short_id"],
        "ss_password": secrets.get("ss_password", ""),
        "traffic_web_key": secrets.get("traffic_web_key", ""),
        "clients": {
            c.email: {
                "uuid": client_uuid(secrets, c.email),
                "sub_path": client_sub_path(secrets, c.email),
                "v2ray_path": client_v2ray_path(secrets, c.email),
            }
            for c in node.clients
        },
    }
