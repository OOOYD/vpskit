"""vpskit 命令行入口。"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .config import Client, NodeConfig, NodesConfig, example_node, load_nodes, write_nodes_template
from .paths import NodePaths, find_root
from .remote import Remote
from .util import VpskitError, detail, error, info, ok, set_json_mode, step, warn

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


def _root(args) -> Path:
    return Path(args.root).expanduser().resolve() if getattr(args, "root", None) else find_root()


def _nodes(args) -> NodesConfig:
    return load_nodes(_root(args) / "nodes.yaml")


def _dump_nodes(path: Path, raw: Dict[str, Any]) -> None:
    if yaml is None:
        raise VpskitError("需要 PyYAML")
    if path.exists():
        backup = path.with_suffix(".yaml.bak.%s" % time.strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(path, backup)
    path.write_text(
        "# vpskit 节点清单。秘密不在这里；见 state/<node>/secrets.json（0600）。\n"
        + yaml.safe_dump(raw, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)


def _raw_nodes(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"version": 1, "defaults": {}, "panel": {"listen": "127.0.0.1", "port": 8787, "refresh_seconds": 30}, "nodes": {}}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise VpskitError("nodes.yaml 顶层不是 mapping")
    raw.setdefault("nodes", {})
    return raw


# ---------------------------------------------------------------- commands


def cmd_init(args) -> int:
    root = _root(args)
    path = root / "nodes.yaml"
    if args.host is None:
        raise VpskitError("init 需要 --host（新 VPS 的 IP 或域名）")
    if not args.node_id:
        raise VpskitError("init 需要节点 id")
    if path.exists():
        raw = _raw_nodes(path)
        if args.node_id in raw["nodes"] and not args.force:
            raise VpskitError("nodes.yaml 里已有 %s；如需覆盖加 --force" % args.node_id)
        entry = example_node(args.node_id, args.host)
        entry["ssh_alias"] = args.ssh_alias
        entry["title"] = args.title or args.node_id
        raw["nodes"][args.node_id] = entry
        _dump_nodes(path, raw)
        ok("已加入节点 %s" % args.node_id)
    else:
        write_nodes_template(path, args.node_id, args.host)
        raw = _raw_nodes(path)
        raw["nodes"][args.node_id]["ssh_alias"] = args.ssh_alias
        raw["nodes"][args.node_id]["title"] = args.title or args.node_id
        _dump_nodes(path, raw)
        ok("已创建 nodes.yaml")
    detail("下一步: 编辑 nodes.yaml（admin_ips / clients / 配额），然后 vpskit plan %s" % args.node_id)
    return 0


def cmd_import_config(args) -> int:
    legacy = Path(args.legacy).expanduser().resolve()
    if not legacy.exists():
        raise VpskitError("找不到 %s" % legacy)
    data = yaml.safe_load(legacy.read_text(encoding="utf-8")) or {}
    raw = _raw_nodes(_root(args) / "nodes.yaml")
    if args.node_id in raw["nodes"] and not args.force:
        raise VpskitError("节点 %s 已存在；加 --force" % args.node_id)
    clients = []
    for item in data.get("clients") or []:
        if isinstance(item, dict):
            clients.append({"email": str(item.get("email") or "main"), "flow": str(item.get("flow") or "")})
        elif isinstance(item, str):
            clients.append({"email": item, "flow": ""})
    web_ports = []
    for item in data.get("web_ports") or []:
        if isinstance(item, dict) and int(item.get("port", 0)) not in (8888, 19000):
            web_ports.append({"port": int(item["port"]), "rate": int(item.get("rate", 12))})
    entry = {
        "host": args.host or "",
        "ssh_alias": args.ssh_alias,
        "title": data.get("title") or args.node_id,
        "profile": data.get("profile") or "strict",
        "quota_gb": int(data.get("quota_gb") or 500),
        "quota_anchor_day": int(data.get("quota_anchor_day") or 29),
        "daily_alert_gb": int(data.get("daily_alert_gb") or 20),
        "daily_hard_gb": int(data.get("daily_hard_gb") or 30),
        "admin_ips": data.get("admin_ips") or [],
        "clients": clients or [{"email": "main", "flow": "xtls-rprx-vision"}],
        "reality_dest": data.get("reality_dest") or "www.iana.org:443",
        "ss_enable": bool(data.get("ss_enable", True)),
        "ss_port": int(data.get("ss_port") or 40244),
        "sub_enable": bool(data.get("sub_enable", True)),
        "sub_port": int(data.get("sub_port") or 8888),
        "traffic_web_enable": bool(data.get("traffic_web_enable", True)),
        "traffic_web_port": int(data.get("traffic_web_port") or 19000),
        "extra_web_ports": web_ports,
        "selfheal_enable": bool(data.get("selfheal_enable", True)),
        "selfheal_mem_avail_kb": int(data.get("selfheal_mem_avail_kb") or 204800),
        "selfheal_xray_rss_kb": int(data.get("selfheal_xray_rss_kb") or 256000),
        "selfheal_min_interval_days": int(data.get("selfheal_min_interval_days") or 7),
        "autoban_thresh_mb": int(data.get("autoban_thresh_mb") or 2),
        "autoban_strikes": int(data.get("autoban_strikes") or 2),
    }
    raw["nodes"][args.node_id] = entry
    _dump_nodes(_root(args) / "nodes.yaml", raw)
    ok("已从 %s 导入配置（不含秘密）" % legacy.name)
    warn("秘密需要 `vpskit adopt %s --host ...` 从现网读取；不要直接把旧秘密写进 nodes.yaml" % args.node_id)
    return 0


def cmd_adopt(args) -> int:
    from .adopt import adopt_node

    if not args.host:
        raise VpskitError("adopt 需要 --host")
    adopt_node(
        args.node_id,
        args.host,
        root=_root(args),
        ssh_alias=args.ssh_alias,
        ssh_user=args.ssh_user,
        ssh_port=args.ssh_port,
        ssh_key=args.ssh_key,
        title=args.title,
        dry_run=args.dry_run,
        force=args.force,
    )
    return 0


def cmd_plan(args) -> int:
    from .plan import build_plan, plan_json, print_plan

    nodes = _nodes(args)
    node = nodes.get(args.node_id)
    remote = Remote(node)
    plan = build_plan(node, _root(args), remote, allow_flush=args.allow_flush)
    if args.json:
        print(json.dumps(plan_json(plan), indent=2, ensure_ascii=False))
    else:
        print_plan(plan, show_diff=args.show_diff, verbose=args.verbose, remote=remote)
    if args.check and plan.changed:
        return 2
    return 0 if plan.ok else 1


def cmd_apply(args) -> int:
    from .apply import apply_node

    nodes = _nodes(args)
    node = nodes.get(args.node_id)
    result = apply_node(
        node,
        _root(args),
        yes=args.yes,
        dry_run=args.dry_run,
        skip_packages=args.skip_packages,
        skip_firewall=args.skip_firewall,
        skip_ssh_harden=args.skip_ssh_harden,
        allow_flush=args.allow_flush,
        prune=args.prune,
    )
    if args.dry_run:
        return 0
    return 0 if result.get("ok") else 1


def cmd_verify(args) -> int:
    from .verify import print_verify, verify_json, verify_node

    nodes = _nodes(args)
    node = nodes.get(args.node_id)
    remote = Remote(node)
    result = verify_node(node, _root(args), remote)
    if args.json:
        print(json.dumps(verify_json(result), indent=2, ensure_ascii=False))
    else:
        print_verify(result)
    return 0 if result.ok else 1


def cmd_status(args) -> int:
    from .status import collect_all, print_status, status_json

    nodes = _nodes(args)
    results = collect_all(nodes, _root(args), args.nodes or None, cache_seconds=args.cache)
    if args.json:
        print(json.dumps(status_json(results, nodes), indent=2, ensure_ascii=False))
    else:
        print_status(results, nodes)
    return 0


def cmd_rollback(args) -> int:
    from .util import read_json

    nodes = _nodes(args)
    node = nodes.get(args.node_id)
    paths = NodePaths(_root(args), node.id)
    state = read_json(paths.state, {}) or {}
    backup = args.backup or state.get("backup")
    if not backup:
        raise VpskitError("没有找到备份记录；用 --backup /root/.vpskit/backups/<ts> 指定")
    if not str(backup).startswith("/"):
        backup = "/root/.vpskit/backups/%s" % backup
    if not args.yes:
        if not sys.stdin.isatty():
            raise VpskitError("非交互环境必须 --yes")
        warn("将把 %s 恢复到备份 %s，并重启服务/防火墙。" % (node.id, backup))
        if input("输入节点 id 确认: ").strip() != node.id:
            raise VpskitError("已取消")
    remote = Remote(node)
    remote.inspect()
    result = remote.rollback(backup)
    if result.get("ok"):
        ok("回滚完成: %d 个文件" % len(result.get("restored") or []))
    else:
        warn("回滚有错误: %s" % json.dumps(result.get("errors"), ensure_ascii=False))
    return 0 if result.get("ok") else 1


def cmd_rotate(args) -> int:
    from .secrets import load_secrets, rotate, save_secrets, summary

    nodes = _nodes(args)
    node = nodes.get(args.node_id)
    paths = NodePaths(_root(args), node.id).ensure()
    secrets = load_secrets(paths.secrets)
    if not secrets:
        raise VpskitError("没有 secrets.json；先 apply 或 adopt")
    what = [name for name in ("reality", "uuid", "ss", "sub", "traffic", "all") if getattr(args, name, False)]
    if not what:
        raise VpskitError("至少要选一个：--reality / --uuid / --ss / --sub / --traffic / --all")
    if not args.yes:
        if not sys.stdin.isatty():
            raise VpskitError("非交互环境必须 --yes")
        warn("轮换会改变线上配置；客户端需要重新导入/刷新订阅。")
        if input("输入节点 id 确认: ").strip() != node.id:
            raise VpskitError("已取消")
    changed = rotate(node, secrets, what, client_email=args.client)
    save_secrets(paths.secrets, secrets)
    ok("已轮换: " + "; ".join(changed))
    detail("下一步: vpskit plan %s → vpskit apply %s --yes" % (node.id, node.id))
    detail("客户端导入卡会在 apply 后重新生成: build/%s/client-import.md" % node.id)
    return 0


def cmd_show(args) -> int:
    from .secrets import load_secrets, secret_values, summary

    nodes = _nodes(args)
    node = nodes.get(args.node_id)
    paths = NodePaths(_root(args), node.id)
    secrets = load_secrets(paths.secrets)
    if not secrets:
        raise VpskitError("没有 secrets.json；先 apply 或 adopt")
    data = secret_values(node, secrets) if args.secrets else summary(node, secrets)
    if args.secrets:
        warn("以下输出含完整秘密，勿粘贴到聊天/日志。")
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0


def cmd_list(args) -> int:
    nodes = _nodes(args)
    rows = []
    for nid, node in nodes.nodes.items():
        rows.append(
            {
                "id": nid,
                "host": node.host,
                "title": node.display_title,
                "clients": [c.email for c in node.clients],
                "quota_gb": node.quota_gb,
                "profile": node.profile,
            }
        )
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    else:
        step("节点")
        for row in rows:
            detail("%-12s %-24s %-16s clients=%s quota=%sG" % (
                row["id"], row["host"], row["title"], ",".join(row["clients"]), row["quota_gb"]
            ))
    return 0


def cmd_doctor(args) -> int:
    root = _root(args)
    step("vpskit doctor")
    detail("root: %s" % root)
    detail("python: %s" % sys.version.split()[0])
    if sys.version_info < (3, 9):
        warn("建议 Python >= 3.9")
    if yaml is None:
        error("缺少 PyYAML：python3 -m pip install pyyaml")
        return 1
    detail("pyyaml: %s" % getattr(yaml, "__version__", "?"))
    for tool in ("ssh", "scp", "tar", "git"):
        detail("%s: %s" % (tool, shutil.which(tool) or "缺失"))
    nodes_path = root / "nodes.yaml"
    if nodes_path.exists():
        try:
            nodes = load_nodes(nodes_path)
            detail("nodes.yaml: %d 个节点" % len(nodes.nodes))
        except Exception as exc:
            error("nodes.yaml 校验失败: %s" % exc)
            return 1
    else:
        warn("没有 nodes.yaml；先 vpskit init <id> --host <ip>")
    # 秘密是否被 git 跟踪
    git = shutil.which("git")
    if git:
        proc = __import__("subprocess").run(
            [git, "ls-files", "state", "nodes.yaml", "build"],
            cwd=str(root),
            capture_output=True,
            text=True,
        )
        tracked = [x for x in proc.stdout.splitlines() if x.strip()]
        if tracked:
            warn("这些敏感/生成文件被 git 跟踪了: %s" % ", ".join(tracked[:10]))
        else:
            detail("git: state/nodes.yaml/build 未被跟踪")
    return 0


def cmd_panel(args) -> int:
    from .panel import run_panel

    nodes = _nodes(args)
    run_panel(nodes, _root(args), listen=args.listen, port=args.port, no_browser=args.no_browser)
    return 0


# ---------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vpskit", description="通用、幂等、可验证的 VPS 部署工具")
    p.add_argument("--root", help="仓库根目录（默认自动查找 nodes.yaml）")
    p.add_argument("--version", action="version", version="vpskit %s" % __version__)
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("init", help="新增一个节点配置")
    sp.add_argument("node_id")
    sp.add_argument("--host", required=True)
    sp.add_argument("--ssh-alias", default="")
    sp.add_argument("--title", default="")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("import-config", help="从旧的 config-*.yaml 导入非秘密字段")
    sp.add_argument("legacy")
    sp.add_argument("--id", dest="node_id", required=True)
    sp.add_argument("--host", default="")
    sp.add_argument("--ssh-alias", default="")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_import_config)

    sp = sub.add_parser("adopt", help="从现网机器导入配置/秘密")
    sp.add_argument("node_id")
    sp.add_argument("--host", required=True)
    sp.add_argument("--ssh-alias", default="")
    sp.add_argument("--ssh-user", default="root")
    sp.add_argument("--ssh-port", type=int, default=22)
    sp.add_argument("--ssh-key", default="")
    sp.add_argument("--title", default="")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_adopt)

    sp = sub.add_parser("plan", help="只读计划：渲染 + diff + 校验")
    sp.add_argument("node_id")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--show-diff", action="store_true")
    sp.add_argument("--verbose", action="store_true")
    sp.add_argument("--check", action="store_true", help="有变化时退出码 2")
    sp.add_argument("--allow-flush", action="store_true", help="允许在 Docker 主机上 flush ruleset（危险）")
    sp.set_defaults(func=cmd_plan)

    sp = sub.add_parser("apply", help="执行部署（默认要求确认）")
    sp.add_argument("node_id")
    sp.add_argument("--yes", action="store_true")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--skip-packages", action="store_true")
    sp.add_argument("--skip-firewall", action="store_true")
    sp.add_argument("--skip-ssh-harden", action="store_true")
    sp.add_argument("--allow-flush", action="store_true")
    sp.add_argument("--prune", action="store_true", help="删除已从配置移除的订阅文件")
    sp.set_defaults(func=cmd_apply)

    sp = sub.add_parser("verify", help="验证实际状态")
    sp.add_argument("node_id")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("status", help="多节点状态")
    sp.add_argument("nodes", nargs="*")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--cache", type=int, default=0, help="缓存秒数；0=实时")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("rollback", help="从备份回滚")
    sp.add_argument("node_id")
    sp.add_argument("--backup", default="")
    sp.add_argument("--yes", action="store_true")
    sp.set_defaults(func=cmd_rollback)

    sp = sub.add_parser("rotate", help="显式轮换秘密")
    sp.add_argument("node_id")
    sp.add_argument("--reality", action="store_true")
    sp.add_argument("--uuid", action="store_true")
    sp.add_argument("--ss", action="store_true")
    sp.add_argument("--sub", action="store_true")
    sp.add_argument("--traffic", action="store_true")
    sp.add_argument("--all", action="store_true")
    sp.add_argument("--client", default="")
    sp.add_argument("--yes", action="store_true")
    sp.set_defaults(func=cmd_rotate)

    sp = sub.add_parser("show", help="查看秘密指纹或完整秘密")
    sp.add_argument("node_id")
    sp.add_argument("--secrets", action="store_true")
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("list", help="列出节点")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("doctor", help="本地环境自检")
    sp.set_defaults(func=cmd_doctor)

    sp = sub.add_parser("panel", help="启动多节点只读面板")
    sp.add_argument("--listen", default="")
    sp.add_argument("--port", type=int, default=0)
    sp.add_argument("--no-browser", action="store_true")
    sp.set_defaults(func=cmd_panel)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "json", False):
        set_json_mode(True)
    try:
        return args.func(args) or 0
    except VpskitError as exc:
        error(str(exc))
        return 1
    except KeyboardInterrupt:
        error("已中断")
        return 130
