# vpskit 使用手册

> 面向第一次用的自己/朋友。照着做即可；所有命令都在仓库根目录执行（装成命令后可在任意目录）。
>
> 铁律：**先 `plan` 看计划，再 `apply`**。`apply` 会改远端防火墙/服务，必须你确认。

## 0. 它是什么

一条命令把 Debian/Ubuntu VPS 变成可复用节点：

- nftables 双栈防火墙（默认 drop、SSH/443/管理页限速）
- Xray REALITY(443) + Shadowsocks(v6)
- 订阅页（每用户独立路径）+ 流量页 + 邮件告警
- autoban（未认证大流量阶梯封禁）+ fail2ban
- xray 内存自愈 + 每日快照/备份 + 变更台账
- 多节点只读面板

秘密只在本地 `state/<node>/secrets.json`；`nodes.yaml` 不含秘密。

## 1. 本机准备

需要：

- macOS / Linux，Python 3.9+
- `ssh`、`scp`、`tar`
- 目标 VPS：Debian 11/12/13 或 Ubuntu 22.04/24.04
- 能 root 登录目标机（推荐密钥）
- Windows 作为本地控制端：Python 3.9+、Windows OpenSSH 客户端、Git；用 `vpskit` 或
  `python -m vpskitlib`。目标 VPS 仍是 Linux；原生 Windows 尚未真机验证，WSL2 按 Linux 文档。

```bash
# clone
git clone https://github.com/OOOYD/vpskit.git
cd vpskit
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install --user pyyaml

# 可选：装成全局命令
pipx install .
# 或 python3 -m pip install --user .
```

自检：

```bash
./vpskit doctor      # clone 方式
vpskit doctor        # 安装方式
```

目标机先能 SSH：

```bash
ssh root@<VPS_IP> true
# 如果还没配 key：
ssh-copy-id root@<VPS_IP>
```

## 2. 建节点配置

### 方式 A：复制示例

```bash
cp nodes.example.yaml nodes.yaml
```

编辑 `nodes.yaml`，至少改：

```yaml
nodes:
  my-vps:
    host: <VPS_IP>
    ssh_alias: ""          # 可选；填了就用 ~/.ssh/config 的别名
    title: 我的 VPS
    quota_gb: 500
    quota_anchor_day: 29
    admin_ips:
      - <你家出口IP>/32
      - <公司出口IP>/32
    clients:
      - email: main
        flow: xtls-rprx-vision
```

### 方式 B：命令生成

```bash
./vpskit init my-vps --host <VPS_IP> --ssh-alias my-vps
# 然后编辑 nodes.yaml
```

**不要**把 UUID/私钥/密码写进 `nodes.yaml`；工具会生成到 `state/`。

## 3. 先看计划（最重要）

```bash
./vpskit plan my-vps --show-diff
```

正常输出会包含：

```
==> 文件计划：new=33 ...
==> 校验
    本地渲染: 通过
    nft: ok
    xray: ok
==> 提醒
[+] 计划可执行：33 个文件会变化
```

看三件事：

1. `blockers` 为空
2. `nft: ok` / `xray: ok`
3. 变化列表符合预期（第一次基本全是 new）

`--show-diff` 的秘密已脱敏，但不要把完整 diff 贴到公开地方。

机器可读：

```bash
./vpskit plan my-vps --json
```

## 4. 执行部署

```bash
./vpskit apply my-vps          # 会要求输入节点 id 确认
# 或
./vpskit apply my-vps --yes
```

顺序：

1. 备份到 `/root/.vpskit/backups/<时间>/`
2. 装包、安装/校验 Xray
3. 原子部署文件
4. `sshd -t` + 新 SSH 连接验证
5. 防火墙：`nft -c` → 120s 保险丝 → 加载 → 本地回连验证
6. 启服务、sysctl、自动更新、首份流量摘要
7. `verify`

**会短暂断线**（xray/ss/sub/traffic-web/fail2ban 重启，几秒）；有保险丝，回连失败自动恢复旧规则。

失败时看最后几行：

```bash
./vpskit rollback my-vps
```

## 5. 客户端导入

部署后生成：

```
build/my-vps/client-import.md    # 0600，含秘密
```

里面有：

- 每个用户的 `vless://` 导入 URI
- 订阅 URL：`http://<IP>:8888/<path>`
- 流量页 URL：`http://<IP>:19000/?k=<key>`
- SS（如果启用且 v6 可达）

把对应用户的那段发给对方；**不要发整个文件**。

客户端支持：Stash / Clash / Clash Meta / v2rayN / sing-box 等，导入 VLESS REALITY 或订阅 YAML。

## 6. 验证

```bash
./vpskit verify my-vps
./vpskit status
```

`verify` 检查：

- 服务 active/enabled
- 文件 hash
- nft 表
- xray `run -test`
- REALITY TCP、订阅/流量页 HTTP 200
- summary 新鲜度
- fail2ban

全绿才代表这次部署可用。

## 7. 面板（可选）

```bash
./vpskit panel
# 默认 http://127.0.0.1:8787
```

- 只读，无操作按钮
- 默认只绑本机；公网要 `nodes.yaml` 里设 `panel.token`，并用 Caddy/Nginx 加 HTTPS
- 给朋友分享用 `share_token`，分享视图会隐藏 host/IP/端口

## 8. 多节点

`nodes.yaml` 里加多个节点即可：

```yaml
nodes:
  tokyo: {...}
  new-vps: {...}
```

```bash
./vpskit status
./vpskit status --json
./vpskit plan new-vps
./vpskit apply new-vps --yes
```

## 9. 轮换 / 回滚

```bash
# 轮换（会让客户端断线，需重新导入）
./vpskit rotate my-vps --all --yes
./vpskit plan my-vps && ./vpskit apply my-vps --yes

# 回滚
./vpskit rollback my-vps
./vpskit rollback my-vps --backup 20261103-225541
```

## 10. 从现网机器迁移（可选）

如果机器已经手工配好：

```bash
./vpskit adopt my-vps --host <VPS_IP> --ssh-alias my-vps
./vpskit plan my-vps --show-diff
# 确认 xray/ss 的密钥、UUID、订阅路径没变，再 apply
```

`adopt` 只读导入；会保留现网订阅文件（`sub_existing_file`）、额外端口、SS 的 v4/v6 行为。

## 11. 安全注意

- 公开仓库只放代码；`state/`、`build/`、`nodes.yaml` 永远不要上传/打包发人
- 订阅/流量页默认 HTTP；建议用 Caddy 加 HTTPS
- 不要把 `show --secrets` 的内容贴到聊天/issue
- 本地私有文件（`nodes.yaml`、`state/`、`build/`、`private/`）都在 `.gitignore` 里；
  Git 只跟踪已加入版本库的文件，这些不会上传，也不会让云端和本地“自动变得不一样”
- 旧历史如果曾推过，立即 `vpskit rotate <node> --all`
- 面板只读；`apply/rollback/rotate` 必须人工确认

## 12. 常见问题

| 现象 | 处理 |
|---|---|
| SSH 连不上 | 等 10 分钟（22 端口 15/min 限速）；把出口 IP 加 `admin_ips`；用控制台 |
| 防火墙锁死 | 控制台 `nft flush ruleset` + `systemctl stop fail2ban`，再从 `/root/.vpskit/backups/...` 恢复 |
| `plan` 被 Docker 阻断 | 不要在 Docker 主机 `flush ruleset`，或明确 `--allow-flush` |
| 订阅 404 | 路径要与 `state/<node>/secrets.json` 的 `sub_path` 一致；`sub_existing_file` 检查 `/opt/stash/config.yaml` |
| 流量页 404 | URL 必须带 `?k=`；检查 `traffic_web_allow_ips` |
| 流量页空白 | `systemctl start traffic-monitor.service` |
| xray 起不来 | `xray run -test -config /usr/local/etc/xray/config.json` + `journalctl -u xray` |
| `apply` 中途失败 | `./vpskit rollback <node>`；备份路径在输出里 |
| 面板没数据 | 面板启动后后台采集，等一个 SSH 往返；`ssh <alias> vpskit-status --json` |

## 13. 给 AI/朋友

- AI 使用：`AGENTS.md`、`docs/AI.md`、`llms.txt`
- 配置字段：`docs/CONFIG.md`
- 架构：`docs/ARCHITECTURE.md`
- 安全：`docs/SECURITY.md`
- 运维：`docs/OPERATIONS.md`

## 14. 最小验收清单

- [ ] `./vpskit doctor` 通过
- [ ] `./vpskit plan <node>` 无 blocker，`nft/xray ok`
- [ ] `./vpskit apply <node> --yes` 成功
- [ ] `./vpskit verify <node>` 全绿
- [ ] 手机/电脑导入订阅，REALITY 能上网
- [ ] 流量页能打开
- [ ] `./vpskit plan <node> --check` 退出 0（幂等）
