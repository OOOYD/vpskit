"""status：多节点状态聚合，给 CLI 和面板共用。"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .config import NodeConfig, NodesConfig
from .paths import NodePaths
from .remote import Remote
from .util import VpskitError, detail, info, ok, step, warn


def collect_one(node: NodeConfig, root: Path, *, cache_seconds: int = 0, timeout: int = 45) -> Dict[str, Any]:
    paths = NodePaths(root, node.id)
    cache = paths.status_cache
    if cache_seconds > 0 and cache.exists():
        try:
            if time.time() - cache.stat().st_mtime < cache_seconds:
                data = json.loads(cache.read_text(encoding="utf-8"))
                data["cached"] = True
                return data
        except Exception:
            pass
    remote = Remote(node)
    try:
        raw = remote.run_script("status.py", timeout=timeout)
        data = json.loads(raw)
        data["node_id"] = node.id
        data["title"] = node.display_title
        data["host"] = node.host
        data["online"] = True
        data["error"] = ""
        try:
            paths.ensure()
            cache.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            import os

            os.chmod(cache, 0o600)
        except OSError:
            pass
        return data
    except Exception as exc:
        return {
            "node_id": node.id,
            "title": node.display_title,
            "host": node.host,
            "online": False,
            "error": str(exc)[:400],
            "services": {},
            "traffic": None,
        }


def collect_all(
    nodes: NodesConfig,
    root: Path,
    only: Optional[Iterable[str]] = None,
    *,
    cache_seconds: int = 0,
    workers: int = 4,
) -> List[Dict[str, Any]]:
    ids = list(only) if only else list(nodes.nodes)
    todo = [nodes.get(i) for i in ids]
    results: Dict[str, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(todo)))) as pool:
        futures = {
            pool.submit(collect_one, node, root, cache_seconds=cache_seconds): node.id
            for node in todo
        }
        for fut in as_completed(futures):
            nid = futures[fut]
            try:
                results[nid] = fut.result()
            except Exception as exc:
                results[nid] = {"node_id": nid, "online": False, "error": str(exc)[:400]}
    return [results.get(i, {"node_id": i, "online": False, "error": "no result"}) for i in ids]


def _gb(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _service_failures(data: Dict[str, Any], required: List[str]) -> List[str]:
    services = data.get("services") or {}
    failed = []
    for name in required:
        st = services.get(name) or {}
        if st.get("active") != "active":
            failed.append(name)
    return failed


def print_status(results: List[Dict[str, Any]], nodes: NodesConfig) -> None:
    step("节点状态")
    header = "%-12s %-6s %-10s %-10s %-10s %-8s %s" % ("NODE", "ONLINE", "周期用量", "今日", "剩余", "LOAD", "异常服务")
    detail(header)
    for data in results:
        nid = data.get("node_id", "?")
        node = nodes.nodes.get(nid)
        if not data.get("online"):
            detail("%-12s %-6s %s" % (nid, "❌", data.get("error", "unreachable")))
            continue
        traffic = data.get("traffic") or {}
        cap = node.quota_gb if node else _gb(traffic.get("cap_gb"))
        cycle = _gb(traffic.get("cycle_gb"))
        today = _gb(traffic.get("today_gb"))
        remain = max(cap - cycle, 0)
        required = ["xray", "fail2ban"]
        if node:
            if node.traffic_web_enable:
                required.append("traffic-web")
            if node.sub_enable:
                required.append("sub")
            if node.ss_enable:
                required.append("ss-server")
        failed = _service_failures(data, required)
        load = data.get("load") or [0]
        detail(
            "%-12s %-6s %-10s %-10s %-10s %-8s %s"
            % (
                nid,
                "✅",
                "%.1f/%dG" % (cycle, cap),
                "%.2fG" % today,
                "%.1fG" % remain,
                "%.2f" % (load[0] if load else 0),
                ",".join(failed) or "-",
            )
        )


def status_json(results: List[Dict[str, Any]], nodes: NodesConfig) -> Dict[str, Any]:
    return {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "nodes": results}
