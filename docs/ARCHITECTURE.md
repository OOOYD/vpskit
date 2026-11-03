# 架构

## 一句话

`nodes.yaml` + `state/<node>/secrets.json` → 确定性渲染 → `build/<node>/` → SSH 部署 →
远端 `vpskit-status` / `summary.json` → CLI/面板。

## 状态布局

```
nodes.yaml                     # 节点清单（gitignored；示例是 nodes.example.yaml）
state/<node>/secrets.json      # 秘密，0600
state/<node>/state.json        # 最近一次 apply：时间/备份/变更
state/<node>/.lock             # 本地并发锁
state/<node>/status-cache.json # 面板/status 缓存
build/<node>/payload/          # 待部署文件（按目标路径镜像）
build/<node>/manifest.json     # path/source/mode/owner/group/sha256
build/<node>/client-import.md  # 含秘密，0600
build/<node>/plan.json         # 最近一次 plan 摘要
```

远端：

```
/etc/nftables.conf
/usr/local/etc/xray/config.json
/etc/shadowsocks-libev/config.json
/opt/traffic/{server,monitor,autoban,audit_auth,kitconf}.py
/opt/sub/{sub.py,data/sub-*.yaml}
/opt/ops/xray_selfheal.sh
/usr/local/bin/{ops,vpskit-status,traffic-snapshot.sh}
/etc/systemd/system/*.service|timer
/etc/fail2ban/jail.local
/etc/ssh/sshd_config.d/99-vpskit.conf
/etc/sysctl.d/99-vpskit.conf
/etc/logrotate.d/vpskit
/etc/systemd/journald.conf.d/vpskit.conf
/etc/apt/apt.conf.d/20auto-upgrades
/root/ops/kit-node-info.yaml
/root/.vpskit/{state.json,incoming/,backups/,firewall-guard.sh}
```

## 确定性渲染

`render(node, secrets, root, opts)` 是纯函数：

- 同样的输入 → 逐字节相同的输出；
- 不写时间戳、不随机、不探测远端；
- `secrets` 只在 `ensure_secrets` / `rotate` 时生成；
- `manifest` 的 hash 来自渲染内容，可用于幂等判断。

这保证了 `plan` 可以反复跑，`apply` 只在真有变化时动服务。

## plan

1. `Remote.inspect()`：只读 JSON（os/arch/v4/v6/服务/端口/Docker/fail2ban/sshd include/authorized_keys）
2. `prepare()`：加载/补齐 secrets，渲染，写 build
3. `Remote.hash_files()`：远端逐文件 sha256 + mode
4. `nft -c`：把生成的 nftables 上传 `/tmp` 校验（不加载）
5. `xray run -test`：已装 xray 时校验生成配置
6. 输出：new/changed/mode/same + 服务状态 + 阻断项 + 提醒

阻断项（默认拒绝 apply）：

- 本地渲染校验失败
- `nft -c` 或 `xray -test` 失败
- 非 Debian/Ubuntu
- 远端不是 root
- Docker 在运行（`flush ruleset` 会清掉 Docker 规则；`--allow-flush` 才放行）

## apply

```
本地锁
  → plan（同上）
  → 确认
  → 远端备份 /root/.vpskit/backups/<ts>/（文件 + nft ruleset + 服务状态）
  → apt 装包
  → 安装/校验 Xray（固定版本 + sha256）
  → 上传 tar + manifest，远端 deploy.py 原子替换（hash 相同且 mode/owner 相同则跳过）
  → systemd daemon-reload；enable
  → sshd -t；reload；新 SSH 连接验证（失败则移除加固文件并回滚）
  → 防火墙：
       nft -c
       启动 firewall-guard（nohup setsid；N 秒后无标记则恢复备份）
       nft -f
       restart fail2ban
       本地新 SSH + 端口探测
       成功 → touch /run/vpskit-firewall-ok，停 guard
       失败 → 立即恢复备份规则，报错
  → 启动/重启服务
  → sysctl / unattended-upgrades / journald / logrotate
  → 首份 summary.json（traffic-monitor.service）
  → 写远端/本地 state
  → verify
```

### 防火墙保险丝

`remote_scripts/firewall-guard.sh`：

- apply 在加载新规则前启动它；
- 它 `sleep N`（默认 120s）；
- 若 `/run/vpskit-firewall-ok` 不存在，**先 `nft flush ruleset` 再 `nft -f`** 恢复备份的 `nft.ruleset`，
  并恢复 `/etc/nftables.conf`、重启 fail2ban；不 flush 直接 load 是叠加语义，旧 drop 规则会残留；
- apply 在本地回连验证成功后创建标记并停掉 guard。

这解决旧 kit 里“`at` 任务不会被取消、15 分钟后静默回滚”的 bug。

### 当前 SSH 来源的临时白名单

`prepare()` 会把 `inspect.ssh_source` 追加到本次渲染的 `admin_ips`（不写回 `nodes.yaml`）：

- nftables 里 `ip saddr @admin4 tcp dport 22 accept`，绕过 15/min 限速；
- fail2ban 的 `ignoreip` 也包含它；
- 避免 apply 过程中被自己限速/封禁。

## verify

- 服务 active/enabled
- 文件 hash + mode
- nft 表齐全
- xray `run -test`
- 本地侧：22/443/sub/traffic 端口 + sub/traffic HTTP 200
- `summary.json` 存在且更新 < 30 分钟
- fail2ban 运行

## 服务数据流

```
nft sets (ss_clients) ── monitor.py(root,timer) ── summary.json (0644)
                                                    ├─ traffic-web (www-data) 读
                                                    └─ vpskit-status 读
xray accepted 日志 ── autoban.py(root,timer) ── nft blackhole set
ops log ── changelog.md + changelog.jsonl (0644)
```

`traffic-web` 不再跑 `vnstat`、不读 `/root`、不 import 秘密之外的东西；
`sub.py` 只读 `/opt/sub/data`；两者都以 `www-data` 运行。

## 面板

`vpskit panel` 是本地 HTTP 服务（默认 `127.0.0.1:8787`）：

- 后台线程每 `refresh_seconds` 用 SSH 跑 `status.py`，缓存结果；
- `/api/status` 需要 `panel.token`；
- `/share/<share_token>` 返回脱敏视图（去掉 host/IP/端口/fail2ban/变更）；
- 只读，没有操作按钮。

面板不新增入站端口、不需要 agent；它和 CLI 共用 `status.py` 的数据结构。

## 为什么不用 agent

- 目标机已经有 SSH，且 vpskit 的 apply 本来就需要 root；
- 少一个常驻服务/端口/升级面；
- 读路径用 `status.py`，写路径用一次性脚本，权限边界清楚；
- 代价：面板所在机器要能 SSH 到节点。如果以后节点很多，再加 agent 或 pushed 模式。

## 设计取舍

- 保留 `table ip filter` / `ip traffic` 命名，兼容 autoban/monitor，减少一次性重写风险。
- `nftables.conf` 仍有 `flush ruleset`：简单、和 Debian `nftables.service` 兼容；
  代价是会清掉 fail2ban 的 `f2b-table`，所以 apply 后重启 fail2ban，且 Docker 主机默认拒绝。
- 订阅默认是极简 Clash 配置（GEOIP,CN + MATCH），不做大而全规则；需要完整规则用
  `sub_template` 或 Sub-Store。
- 面板只读；操作继续走 CLI，保持“危险动作必须显式命令 + 确认”的原则。
