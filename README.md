# vpskit — 通用 VPS 双栈安全套件

把一台 Debian/Ubuntu VPS 变成可复用的节点：nftables 双栈防火墙、Xray REALITY、
Shadowsocks(v6 备份)、订阅页、流量页、autoban、fail2ban、自愈、每日快照/备份、
变更台账，以及一个多节点只读面板。

设计目标只有四个字：**幂等、可验证**。

- `plan` 只读：渲染 + 远端比对 + `nft -c` / `xray -test` 校验
- `apply` 才动手：先备份，再改文件；防火墙带“未确认自动恢复”的保险丝
- 秘密只生成一次：`state/<node>/secrets.json`（0600），重复 apply 不会换 UUID/密钥
- 每个节点独立配置：`nodes.yaml`；秘密不写在这个文件里

> 这是 v1.0 重写版。旧的 `install.sh` 只作为兼容入口保留；旧版文件请留在本地，
> 不要提交。公开仓库只包含代码、文档和示例配置。

---

> 第一次用？直接看 **[docs/USER-GUIDE.md](docs/USER-GUIDE.md)**（从买 VPS 到客户端导入的完整手册）。

## 快速开始

### 0. 安装

```bash
# 方式 A：clone（推荐开发/长期使用）
git clone https://github.com/OOOYD/vpskit.git
cd vpskit
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install --user pyyaml

# 方式 B：装成命令行工具（clone 后）
pipx install .
# 或
python3 -m pip install --user .
# 之后任意目录可用 `vpskit`，不需要在仓库里
```

本机要求：

- Python 3.9+，PyYAML
- `ssh` / `scp` / `tar`
- 目标机：Debian 11/12/13 或 Ubuntu 22.04/24.04，root SSH（密钥登录）
- **Windows 作为本地控制端**：Python 3.9+、Windows OpenSSH 客户端、Git；用 `vpskit` 或
  `python -m vpskitlib`。目标 VPS 仍是 Linux。原生 Windows 尚未在真机验证；WSL2 可直接按 Linux 文档。

```bash
./vpskit doctor          # clone 方式
vpskit doctor            # pipx/pip 安装方式
```

### 1. 建节点配置

```bash
cp nodes.example.yaml nodes.yaml
# 编辑 nodes.yaml：host、ssh_alias、admin_ips、clients、quota_gb、quota_anchor_day
```

或者：

```bash
./vpskit init my-vps --host 203.0.113.10 --ssh-alias my-vps
```

### 2. 先看计划（不改远端）

```bash
./vpskit plan my-vps --show-diff
```

它会：

- SSH 只读体检（系统/架构/IPv4/IPv6/服务/端口/Docker/fail2ban）
- 渲染全部文件并和远端逐文件比 hash（只显示变化）
- 把生成的 `nftables.conf` 上传到 `/tmp` 做 `nft -c`（不加载）
- 把生成的 xray 配置上传到 `/tmp` 做 `xray run -test`
- `--show-diff` 会显示脱敏后的 diff

### 3. 执行

```bash
./vpskit apply my-vps          # 会要求输入节点 id 确认
# 或
./vpskit apply my-vps --yes
```

顺序：备份 → 装包 → 安装/校验 Xray → 部署文件 → `daemon-reload` →
SSH 加固校验 → 防火墙（保险丝+回连验证）→ 启动服务 → 内核参数/自动更新 → 验证。

失败时：

- 防火墙加载后回连失败：立即恢复备份规则，并提示回滚命令
- 文件/服务失败：备份保留在 `/root/.vpskit/backups/<时间戳>/`

### 4. 验证与日常

```bash
./vpskit verify my-vps          # 服务/端口/HTTP/文件 hash/防火墙/summary
./vpskit status                 # 多节点概览
./vpskit status --json          # 给脚本/面板
./vpskit panel                  # 本地面板 http://127.0.0.1:8787
```

---

## 命令

| 命令 | 作用 |
|---|---|
| `vpskit init <id> --host <ip>` | 新增节点配置 |
| `vpskit import-config <old.yaml> --id <id>` | 从旧 `config-*.yaml` 导入非秘密字段 |
| `vpskit adopt <id> --host <ip> [--ssh-alias]` | 从现网机器只读导入真实配置/秘密 |
| `vpskit plan <id> [--show-diff] [--json] [--check]` | 只读计划；`--check` 有变化退出 2 |
| `vpskit apply <id> [--yes] [--dry-run] [--prune]` | 执行部署 |
| `vpskit verify <id> [--json]` | 实际状态验证 |
| `vpskit status [id...] [--json] [--cache 30]` | 多节点状态 |
| `vpskit rollback <id> [--backup <ts>]` | 从远端备份恢复 |
| `vpskit rotate <id> --all/--reality/--uuid/--ss/--sub/--traffic` | 显式轮换秘密 |
| `vpskit show <id> [--secrets]` | 秘密指纹；`--secrets` 才显示原文 |
| `vpskit list` | 节点列表 |
| `vpskit doctor` | 本机环境自检 |
| `vpskit panel` | 多节点只读面板 |

`apply` 额外参数：

- `--skip-packages`：跳过 apt 与 Xray 安装（调试用）
- `--skip-firewall`：不加载防火墙（危险，验证会报错）
- `--skip-ssh-harden`：不改 sshd
- `--allow-flush`：允许在 Docker 主机上 `flush ruleset`（会清掉 Docker 规则）
- `--prune`：删除已从配置移除的订阅文件

---

## 装了什么

| 层 | 组件 |
|---|---|
| 防火墙 | nftables 双表（ip/ip6），默认 drop；SSH 15/min；REALITY 120/min（strict）；管理页各自限速；管理员 IP 可绕过 SSH 限速 |
| 入侵防护 | fail2ban（sshd + recidive） |
| 主动反滥用 | autoban：未认证大流量阶梯封禁（6h→24h→72h），支持 dry-run、认证日志不可用时跳过 |
| 代理 | Xray REALITY(443) + Shadowsocks(v6，可选 v4) |
| 流量 | vnstat + per-IP nft counter；`summary.json`；流量页(19000) |
| 未归属流量 | `unattr.py`：REALITY 未归属（7 天/日均/阈值）与 SS 通道分开统计；每小时写 `unattr.json` |
| 订阅 | 每用户独立路径的 YAML；`sub.py` 以 www-data 只读 |
| 自愈 | xray-selfheal 定时器（参数来自 `/etc/default/xray-selfheal`） |
| 变更管理 | `ops` 快照/备份/diff/rollback/台账；Markdown + JSONL |
| 可观测 | `vpskit-status` JSON（面板/排障用） |
| 主机 | SSH 加固（可选）、BBR/sysctl、unattended-upgrades、logrotate、journald 上限 |

---

## 目录

```
vpskit                 CLI 入口
vpskitlib/             工具本体（config/render/remote/plan/apply/verify/status/panel）
vpskitlib/assets/opt/  部署到节点的服务源码（traffic/sub/ops/status）
vpskitlib/assets/units/ systemd units
vpskitlib/remote_scripts/  远端只读/部署/回滚脚本
nodes.example.yaml     节点配置示例
docs/                  配置/架构/安全/运维/迁移/AI/发布
tests/                 单元测试（44 个）
AGENTS.md              AI/Agent 使用约定
llms.txt               给 LLM 的索引入口
legacy/                旧版本地文件（gitignored）
```

---

## 秘密与 Git

- 秘密在 `state/<node>/secrets.json`，0600；`build/`、`state/`、`nodes.yaml` 都 gitignored。
- `vpskit show <node>` 只显示指纹；`--secrets` 才显示原文（会警告）。
- 轮换：`vpskit rotate <node> --all --yes`，然后 `plan` / `apply`；客户端需要重新导入。
- **旧版历史**：如果旧仓库曾经包含真实秘密，不要把旧历史推到公开仓库；
  必要时 `vpskit rotate <node> --all` 轮换。
- 建议加 `gitleaks` pre-commit；CI 里也加 secret scan。

---

## 面板

```bash
./vpskit panel                  # 127.0.0.1:8787，自动开浏览器
./vpskit panel --no-browser     # 只启动
```

- 只读：没有重启/封禁按钮，避免把面板变成高价值攻击面。
- 默认只绑本机。要公网分享：
  1. `nodes.yaml` 的 `panel.token` 设置一个随机串
  2. 用 Caddy/Nginx 加 HTTPS 反代到 `127.0.0.1:8787`
  3. 给朋友用 `share_token`，分享视图会隐藏 host/IP/端口/fail2ban 细节
- 面板在采集时通过 SSH 读取节点；不新增入站端口，不需要 agent。

---

## 已验证 / 未验证

**已验证（2026-11-03）**

- 45 个单元测试通过（`python3 -m unittest discover -v`）
- 在 Debian 13 测试机上只读校验生成的配置：
  - `nft -c -f /tmp/.../nftables.conf` → rc=0
  - `xray run -test -config /tmp/.../xray.json` → `Configuration OK.`
  - `sshd -t -f <temp config>` → rc=0
  - `systemd-analyze verify` 仅 `User=nobody` 警告
  - Python 编译、shell `bash -n`、logrotate `-d` 通过
- 对测试节点跑过一次完整只读 `plan`：24 changed / 9 new / 1 mode，`nft: ok`、`xray: ok`，未改动远端

**未验证**

- 全新 VPS 的完整 `apply`（需要一台一次性机器；测试机是唯一生产机，不能拿来试）
- Ubuntu 22.04/24.04、arm64、纯 v4 / 纯 v6 的矩阵
- 防火墙把自己锁死后的真实恢复演练（代码有保险丝，未在真实断连中演练）
- 订阅 YAML 在 Stash/Clash 各版本的实际导入
- 高并发/DoS 压测

首次上线建议：先 `plan`，再在一台一次性 VPS 上 `apply`；确认后再对生产 `apply`。

---

## 给 AI / 自动化

- `AGENTS.md` — AI 在本仓库工作的铁律、命令、代码结构
- `docs/AI.md` — 机器可读命令、JSON 形状、退出码、安全协议
- `llms.txt` — LLM 索引入口

## 文档

- `docs/USER-GUIDE.md` — 完整使用手册（推荐第一次读）
- `docs/CONFIG.md` — 全部配置字段
- `docs/ARCHITECTURE.md` — 状态布局、apply 顺序、防火墙保险丝
- `docs/SECURITY.md` — 威胁模型、秘密、AI Agent 规则
- `docs/OPERATIONS.md` — 加节点、轮换、回滚、排障
- `docs/MIGRATION.md` — 从旧版迁移

## License

MIT，见 `LICENSE`。
