# 运维手册

## 日常

```bash
./vpskit status                 # 多节点概览
./vpskit verify node1           # 单节点深检
./vpskit panel                  # 本地面板
```

节点上：

```bash
ssh node1 vpskit-status --json  # 面板/脚本用的 JSON
ssh node1 ops status            # 人看的概览
ssh node1 ops changelog -n 20   # 变更台账
ssh node1 ops changelog --json  # JSONL
ssh node1 systemctl status xray traffic-web sub fail2ban --no-pager
```

## 加一台新 VPS

1. `./vpskit init <id> --host <ip> --ssh-alias <alias>`
2. 编辑 `nodes.yaml`：`admin_ips`、`clients`、`quota_gb`、`quota_anchor_day`
3. `./vpskit plan <id> --show-diff`
4. 在一台一次性 VPS 上 `./vpskit apply <id> --yes`
5. `./vpskit verify <id>`
6. 把 `build/<id>/client-import.md` 里的导入卡发给用户（该文件 0600）

## 轮换秘密

```bash
./vpskit rotate node1 --all --yes        # 全部
./vpskit rotate node1 --uuid --client friend --yes
./vpskit rotate node1 --traffic --yes    # 只换流量页 key
./vpskit plan node1 && ./vpskit apply node1 --yes
```

影响：

- `--reality`：REALITY 密钥对 + shortId 变，所有客户端要重新导入/刷新订阅
- `--uuid`：只影响该用户
- `--ss`：SS 密码变
- `--sub`：订阅 URL 变
- `--traffic`：流量页 URL 变

轮换前先 `ops backup`，轮换后 `plan` 看 diff。

## 回滚

```bash
./vpskit rollback node1                  # 用 state.json 里的最近备份
./vpskit rollback node1 --backup 20261103-225541
```

远端备份在 `/root/.vpskit/backups/<ts>/`，包含：

- 被替换的文件（按原路径）
- `nft.ruleset`（当时完整规则）
- `services.txt`（当时 active/enabled）

回滚会恢复文件、`nft -f` 恢复规则、重启 xray/ss-server/traffic-web/sub/fail2ban。
如果回滚后仍然不通，用控制台执行：

```bash
nft flush ruleset                 # 应急：等于无防火墙
systemctl stop fail2ban
# 然后从备份恢复：
cp /root/.vpskit/backups/<ts>/etc/nftables.conf /etc/nftables.conf
```

## 防火墙把自己锁在门外

1. **先别慌**：SSH 22 的 established 连接不会断；新连接可能被 15/min 限速。
2. 等 1–10 分钟再连；或换 `admin_ips` 里的网络。
3. 还不行：VNC/控制台执行
   ```bash
   nft flush ruleset
   systemctl stop fail2ban
   ```
4. 恢复：
   ```bash
   cp /root/.vpskit/backups/<ts>/etc/nftables.conf /etc/nftables.conf
   nft -f /etc/nftables.conf
   systemctl restart fail2ban
   ```
5. 检查 `/root/.vpskit/firewall-guard.log`：保险丝是否触发、为什么。

> 首次 apply 建议在控制台/VNC 可用的窗口做。保险丝默认 120s，apply 本地回连验证成功才会解除。

## 常见问题

### `plan`/`apply` 报 “SSH 连不上”

- 检查 `ssh_alias` / `host` / key；`ssh -v <alias> true`
- 22 端口限速：等 10 分钟，或把当前出口加进 `admin_ips`
- 目标机 sshd 改了端口：`ssh_port`

### `apply` 被 Docker 阻断

`nftables.conf` 里 `flush ruleset` 会清掉 Docker 的 nftables 规则。要么：

- 不要在同一台机器跑 Docker；或
- 明确 `--allow-flush`，并接受 Docker 网络规则被清（不推荐）。

### fail2ban 不封

```bash
fail2ban-client status
fail2ban-client status sshd
fail2ban-client get sshd actions
```
- 需要 `nftables-multiport` action；apply 会自动选。
- 如果只有 iptables，安装 `iptables` 或改 `jail.local` 的 `banaction`。
- 用文档 IP 测试：
  ```bash
  fail2ban-client set sshd banip 198.51.100.77
  nft list ruleset | grep 198.51.100.77
  fail2ban-client set sshd unbanip 198.51.100.77
  ```

### 告警（只支持邮件，可选）

`monitor.py` 会检查：服务 inactive、磁盘 ≥85/90%、可用内存 <120/80MB、额度/日流量、autoban、REALITY 未归属偏高。

```yaml
# nodes.yaml
mail_user: you@example.com
mail_to: you@example.com
smtp_host: smtp.qq.com
smtp_port: 465
mail_pass_env: SMTP_PASS
```

SMTP 密码放 `/root/.smtp.env`（600），然后 `plan/apply`。留空 = 不发邮件，只在流量页/面板显示。没有 Telegram 集成。

### 外部探活

VPS 本机监控看不到“整机失联/被墙”。用 Uptime Kuma、Better Stack 或另一台机器监控：

```text
http://<VPS_IP>:19000/healthz     # 200，无需 key
http://<VPS_IP>:8888/healthz      # 200，无需订阅路径
tcp 443                          # REALITY
tcp 22                           # SSH
```

国外探活无法判断 GFW；大陆侧再用 `kit-wallcheck.py` 定时跑一次。

### 未归属流量（unattr）

```bash
ssh <host> /opt/traffic/unattr.py          # 文本
ssh <host> cat /opt/traffic/unattr.json    # JSON
systemctl status unattr.timer
```

- `ch443` = REALITY 未归属；阈值 `1.5 GB/天`，连续偏高才需要归因
- `ch40244` = SS，始终单列，不计入 ch443 阈值
- 它是估算：依赖 7 天 hourly 留痕 + `authed_ips.json` 的 7 天窗口
- 如果 `unattr.json` 不更新：`systemctl start unattr.service`；看 `journalctl -u unattr`

### 流量页 404

- URL 必须带 `?k=`；key 在 `state/<node>/secrets.json` 的 `traffic_web_key`
- 若配置了 `traffic_web_allow_ips`，你的出口 IP 必须在里面
- `systemctl status traffic-web`；日志在 journald
- `summary.json` 不存在：`systemctl start traffic-monitor.service`

### 订阅 404

- 路径必须和 `secrets.json` 的 `clients.<email>.sub_path` 一致
- `sub_existing_file` 模式：确认远端 `/opt/stash/config.yaml` 存在且 www-data 可读
- `systemctl status sub`；`journalctl -u sub -n 30`
- 新 `sub.py` 需要从 `/opt/traffic` import kitconf；以 `www-data` 测试：
  ```bash
  runuser -u www-data -- python3 -c 'import sys; sys.path.insert(0,"/opt/traffic"); import kitconf; print(kitconf.SUB_ROUTES)'
  ```

### xray 起不来

```bash
/usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
journalctl -u xray -n 50 --no-pager
```
常见：privateKey 不是 base64url 32 字节；shortId 不是偶数 hex；dest 不可达。

### apply 报 xray 下载失败

- 检查到 GitHub 的连通性；`xray_download_base` 可换成镜像
- 固定版本不存在：改 `xray_version` 为实际 release
- `.dgst` 拿不到时脚本会 warning 继续；生产建议手动校验

### 面板没数据/启动慢

- 面板启动后后台采集；第一次请求可能要等一个 SSH 往返
- 节点离线会显示错误；检查 `ssh <alias> vpskit-status --json`
- 公网必须 `panel.token` + TLS

## 离岸备份（可选 restic）

```yaml
# nodes.yaml
restic_repo: s3:s3.amazonaws.com/<bucket>/vpskit
restic_password_file: /root/.restic-pass   # 600
```

配置后 `apply` 会装 `restic`；`traffic-snapshot.timer` 每天备份 `/root/ops /opt/traffic /opt/sub /etc/nftables.conf` 并保留 7 日/4 周。日志 `/var/log/vpskit-restic.log`。不配置 = 只做本地快照。

## 备份策略

- 每日 `traffic-snapshot.timer`：`/root/ops/snapshots/daily-*` + `/root/ops/backups/daily-*`
- 保留 `traffic_snapshot_keep_days`（默认 14 天）
- 建议再加一层离岸加密备份（restic/Borg）到 B2/S3；vpskit 不内置，避免引入凭据管理。
- 恢复演练：`ops rollback <backup> <file>` 单文件；整机用 `vpskit rollback`。

## 变更纪律

1. 改前：`ops changelog -n 20`、`ops snapshot before-<name>`
2. 改后：`ops diff before-<name>`、`ops log -a <你> -t <标签> -l <级别> "..."`
3. 任何 AI/多端协作：先 `vpskit plan`，不要直接 `apply`
4. 防火墙改动后：`systemctl restart fail2ban`
