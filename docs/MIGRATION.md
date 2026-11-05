# 迁移：从旧版到 vpskit

## 现状

- 旧节点原本是手工维护的：`server.py`/`monitor.py`/`autoban.py`/`sub.py` 是硬编码版本，没有 `kitconf.py`；
  nftables 里还额外开了 80/4173；SS 在 v4/v6 都可达；订阅是 `/opt/stash/config.yaml` 一份共享文件。
- 旧仓库的 `templates/*.host` 含有 live 的 REALITY 私钥、UUID、SS 密码；旧 Git 历史里也有。
- 新工具已经在旧节点上做过真实 apply；`plan` 为 `same=33`。

## 一、先处理 Git 历史（最重要）

**不要**把旧 `main` 历史直接推到 GitHub/Gitee。当前 `main` 是单提交的干净历史，只含清洗后的树；直接推 `main`。

```bash
git branch -a            # 只有 main（单提交，安全）
```

### 推荐：新建一个干净仓库

```bash
cd <vpskit-repo>
# 当前树里的秘密都在 gitignored 的 state/ 与 nodes.yaml；旧版文件不要带
rsync -a --exclude .git --exclude legacy --exclude state --exclude build \
      --exclude nodes.yaml --exclude '*.bak.*' ./ ../vpskit-public/
cd ../vpskit-public
git init
git add .
./scripts/check-secrets.sh        # 应该通过
git commit -m "vpskit v1.0.0"
git remote add origin git@github.com:<you>/vpskit.git
git push -u origin main
```

这样不需要轮换密钥（旧历史没有离开本机）。

### 如果已经推过旧历史

视为泄露：

```bash
./vpskit rotate node1 --all --yes
./vpskit plan node1 && ./vpskit apply node1 --yes
# 所有客户端重新导入订阅
```

然后用 `git filter-repo` 清历史或直接新建仓库。GitHub 可能已有缓存/ fork，最稳是轮换。

## 二、把现网节点纳入工具（adopt）

```bash
./vpskit adopt node1 --host <VPS_IP> --ssh-alias node1 --title '<节点名>'
```

它会只读导入：

- REALITY 私钥/公钥/shortId、UUID、dest/serverNames/fallback
- SS 密码/端口/method
- 流量页 key/端口/标题/配额（从现网 `server.py` 解析，因为旧机器没有 `kitconf.py`）
- 订阅路径（从 `sub.py` 的 `PATHS` 键解析，不是文件路径）
- 额外端口（80、4173）
- SS 是否真的在 v4 监听（`ss -tln`，不是只看 nft 放行）。旧节点实际只监听 `[::]:40244`，
  所以收尾时把 `ss_expose_v4` 设为 false 并关闭 v4 40244；没有 IPv6 的客户端请走 REALITY。
- fail2ban ignoreip 里的管理员 IP（如果现网没写，需要手动补 `admin_ips`）

写入：

- `nodes.yaml`（0600，gitignored）
- `state/node1/secrets.json`（0600，gitignored）

> 注意：`adopt --force` 会覆盖 `nodes.yaml`，可能丢掉你手动加的 `admin_ips`。覆盖后重新检查。

## 三、首次 apply 前检查

```bash
./vpskit plan node1 --show-diff
```

重点看：

1. `/usr/local/etc/xray/config.json` 变化：privateKey / UUID / shortId / shortIds / dest / serverNames / fallback 必须和线上一致。
   工具把 `dest` 写成等价的 `target`，并可能加 `tcpNoDelay`；密钥和客户端身份不应变。
2. `/etc/shadowsocks-libev/config.json`：password/port/method 一致。
3. `/etc/nftables.conf`：80/4173/8888/19000/40244/443/22 都还在；`admin_ips` 包含你的出口。
4. `/opt/sub`：如果 `sub_existing_file` 指向 `/opt/stash/config.yaml`，不会覆盖你的完整 Stash 规则；
   `SUB_ROUTES` 应把原路径指向该文件。
5. `nft: ok` / `xray: ok` / 无阻断项。

如果 xray/ss 的密钥出现变化：**停下来**，检查 `state/node1/secrets.json`，不要 apply。

## 四、apply 窗口

建议：

- 有 VNC/控制台可用；
- 避开用户高峰；
- 知道回滚命令：`./vpskit rollback node1`；
- 知道应急命令：`nft flush ruleset` + `systemctl stop fail2ban`。

```bash
./vpskit apply node1 --yes
```

顺序与保险丝见 `docs/ARCHITECTURE.md`。apply 会：

- 备份到 `/root/.vpskit/backups/<ts>/`
- 替换 server/monitor/sub/ops/units/nftables/sshd/sysctl
- 重启 xray/ss-server/traffic-web/sub/fail2ban（数秒断线）
- 防火墙加载后本地回连验证；失败自动恢复旧规则
- 生成首份 summary.json
- 跑 verify

## 五、apply 后验证

```bash
./vpskit verify node1
./vpskit status
./vpskit plan node1 --check     # 应输出 same=33、退出 0
```

再从本机/手机：

- 流量页 URL（key 未变）
- 订阅 URL（路径未变；内容仍是 `/opt/stash/config.yaml`）
- 客户端刷新订阅、测 REALITY
- `ssh node1 ops status`

一次实测结果：`verify` 全绿；订阅 200/9729B；流量页 200；`plan` same=33；
fail2ban 用 `198.51.100.77` 封/解成功；`traffic-snapshot.service` 生成 daily 快照/备份。

## 六、首次 apply 踩过的坑

- **sub.py import 路径**：以 `/opt/sub/sub.py` 运行时 `sys.path[0]` 是 `/opt/sub`，import 不到 `/opt/traffic/kitconf.py`，
  导致 `SUB_ROUTES` 为空、订阅 404。已在 `sub.py` 里显式 `sys.path.insert(0, "/opt/traffic")`。
- **订阅路径**：`sub.py` 的 `PATHS` 是 `{URL路径: 文件路径}`；adopt 必须取 **键**，不能取 value（value 是 `/opt/stash/config.yaml`）。
- **额外端口**：旧 nftables 开了 80/4173；adopt 从 `tcp dport { ... } accept` 解析并写入 `extra_web_ports`。
- **SS v4**：旧机器 nft 放行了 v4 40244，但 `ss-server` 实际只监听 `[::]`；adopt 现在按监听族判断，
  旧节点最终为 `ss_expose_v4: false`，并关闭未使用的 v4 40244。
- **admin_ips**：旧 `jail.local` 没有非私网 IP 时 adopt 会得到空数组；需要手动补家里/公司出口。

## 七、新 VPS（非迁移）

不要 adopt。直接：

```bash
./vpskit init new --host <ip> --ssh-alias new
# 编辑 clients/admin_ips/quota
./vpskit plan new --show-diff
./vpskit apply new --yes
```

新节点默认：

- SS 只 v6（`ss_expose_v4: false`）
- 订阅是新生成的极简 Clash 配置（`GEOIP,CN` + `MATCH`）
- 没有额外端口
- `admin_ips` 为空时，apply 会把当前 SSH 来源临时加进去；建议长期填好

## 八、回滚后

```bash
./vpskit rollback node1
./vpskit verify node1
```

如果回滚后订阅/流量页还是不对，检查：

```bash
ls -l /opt/sub /opt/traffic
systemctl status sub traffic-web --no-pager
journalctl -u sub -u traffic-web -n 50 --no-pager
```
