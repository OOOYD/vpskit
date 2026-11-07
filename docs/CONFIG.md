# 配置字段

所有字段都在 `nodes.yaml`。`defaults` 先合并到每个节点，节点里的同名键覆盖默认值。
**秘密不写在这里**；首次 `apply` 或 `adopt` 写到 `state/<node>/secrets.json`（0600）。

## 顶层

| 字段 | 默认 | 说明 |
|---|---|---|
| `version` | `1` | 配置版本 |
| `defaults` | `{}` | 所有节点的默认值 |
| `panel` | `{}` | 面板配置 |
| `nodes` | 必填 | 节点 map，key 是节点 id |

## panel

| 字段 | 默认 | 说明 |
|---|---|---|
| `listen` | `127.0.0.1` | 监听地址；非本机必须设 `token` |
| `port` | `8787` | 面板端口 |
| `refresh_seconds` | `30` | 采集间隔（最小 5） |
| `token` | `""` | 管理视图 token；URL `?token=` |
| `share_token` | `""` | 只读分享 token；`/share/<token>` |
| `title` | `vpskit` | 面板标题 |
| `allow_hosts` | `[]` | **没配 `token` 时**额外允许的 `Host`；默认只认 `127.0.0.1/localhost/[::1]`，挡隧道转发和 DNS rebinding |
| `allow_write` | `true` | 设 `false` 后 `POST /api/nodes` 直接 403，面板纯只读 |

## 节点通用

| 字段 | 默认 | 说明 |
|---|---|---|
| `host` | 必填 | IP 或域名；订阅/导入卡里的地址 |
| `ssh_alias` | `""` | 填了就使用 `~/.ssh/config` 的别名，忽略 `ssh_user/ssh_port/ssh_key` |
| `ssh_user` | `root` | 非 alias 时使用 |
| `ssh_port` | `22` | 非 alias 时使用 |
| `ssh_key` | `""` | 非 alias 时使用 |
| `title` | 节点 id | 页面/邮件显示名 |
| `profile` | `strict` | `strict`=443/管理页限速；`mild`=只做 SSH 限速 |
| `has_v6` | `auto` | `auto`=探测；`true/false` 可强制（会覆盖探测结果） |
| `quota_gb` | `500` | 厂商月额度（十进制 GB） |
| `quota_anchor_day` | `29` | 计费周期起点（每月几号） |
| `daily_alert_gb` | `20` | 日用量预警线 |
| `daily_hard_gb` | `30` | 日用量硬警戒线 |
| `admin_ips` | `[]` | 管理员 IP/CIDR；用于 fail2ban ignoreip 和 SSH 免限速 |
| `clients` | `[{email: main, flow: xtls-rprx-vision}]` | 每用户一条；`email` 只用于日志/订阅文件名 |
| `extra_web_ports` | `[]` | 额外放行的 HTTP 端口，如 `{port: 80, rate: 12}` |

## REALITY

| 字段 | 默认 | 说明 |
|---|---|---|
| `reality_port` | `443` | 监听端口 |
| `reality_dest` | `www.iana.org:443` | 伪装目标；必须 TLS1.3 + H2；建议同 ASN/非 CDN |
| `reality_server_names` | `[]` | 留空=从 dest 推导 |
| `reality_max_time_diff` | `60000` | 允许的客户端时间差（毫秒）；0=不限制 |
| `reality_fallback` | `null` | 可选 `{after_bytes, bytes_per_sec, burst_bytes_per_sec}`；**默认关闭** |

> 官方文档明确说 fallback 限速本身是指纹，且不要在一键脚本里对所有机器用同一组固定值。
> 如果必须用，请每台机器随机化，并优先考虑同 ASN target / Nginx 前置。

REALITY 私钥/公钥/shortId 在 `secrets.json` 的 `reality` 下，由工具生成：
- 私钥/公钥：X25519，base64url 无填充
- shortId：16 hex（8 字节）

## Shadowsocks

| 字段 | 默认 | 说明 |
|---|---|---|
| `ss_enable` | `true` | 无 IPv6 时自动跳过 |
| `ss_port` | `40244` | |
| `ss_method` | `chacha20-ietf-poly1305` | 如需 SS2022 自行改 |
| `ss_expose_v4` | `false` | 默认只开 v6；true 才在 v4 表放行。adopt 会按 `ss -tln` 实际监听判断，不只看 nft 是否放行 |

## 订阅

| 字段 | 默认 | 说明 |
|---|---|---|
| `sub_enable` | `true` | |
| `sub_formats` | `[clash]` | 订阅输出格式：`clash`（YAML）/ `v2ray`（base64 的 URI 列表，含 IPv4+IPv6）。可同时开 |
| `sub_port` | `8888` | |
| `sub_template` | `""` | 自定义 YAML 模板；支持 `{{PROXIES}}`/`{{PROXY_GROUPS}}`/`{{RULES}}`/`{{SERVER}}`/`{{PORT}}`/`{{UUID}}`/`{{PUBLIC_KEY}}`/`{{SHORT_ID}}`/`{{SNI}}`/`{{SS_*}}` |
| `sub_existing_file` | `""` | 迁移用：直接服务现网已有 YAML（如 `/opt/stash/config.yaml`），不生成新订阅；保留旧路径/旧规则 |
| `sub_allow_ips` | `[]` | 留空=公开（靠路径能力）；填了=只允许这些来源；只填 v4 会同时拒绝所有 v6 |

## 流量页

| 字段 | 默认 | 说明 |
|---|---|---|
| `traffic_web_enable` | `true` | |
| `traffic_web_port` | `19000` | |
| `traffic_web_allow_ips` | `[]` | 留空=公开但需要 `?k=`；填了=只允许这些来源 |

## 主机

| 字段 | 默认 | 说明 |
|---|---|---|
| `ssh_harden` | `true` | 写 `/etc/ssh/sshd_config.d/99-vpskit.conf`；无 authorized_keys 时自动跳过 |
| `sysctl` | `true` | BBR/fq/conntrack 等；内核不支持 BBR 时自动移除该项 |
| `auto_updates` | `true` | unattended-upgrades |
| `firewall_guard_seconds` | `120` | 保险丝等待秒数 |
| `xray_version` | `26.7.28` | 写死版本；`latest` 不校验 checksum |
| `xray_download_base` | GitHub | 可换成镜像 |
| `traffic_snapshot_keep_days` | `14` | 每日快照/备份保留天数 |
| `provider` | `""` | 商家/品牌，仅显示 |
| `line` | `""` | 线路描述（163/CN2GIA/BGP…），仅显示 |
| `purchased_on` | `""` | 开通日期 ISO；用于面板生命周期 |
| `expires_on` | `""` | 到期日期 ISO；年付按开通日+1年 |
| `billing_cycle` | `""` | `monthly` / `yearly`；仅显示与推算 |
| `restic_repo` | `""` | 可选；配置后每日 restic 离岸备份 |
| `restic_password_file` | `/root/.restic-pass` | restic 密码文件（600） |

## 邮件（可选）

| 字段 | 默认 | 说明 |
|---|---|---|
| `smtp_host` / `smtp_port` | `smtp.qq.com` / `465` | |
| `mail_user` | `""` | SMTP 账号 |
| `mail_pass_env` | `SMTP_PASS` | 从环境变量或 `/root/.smtp.env` 读密码 |
| `mail_to` | `""` | 留空=只落盘不发邮件 |

## 自愈 / 反滥用

| 字段 | 默认 | 说明 |
|---|---|---|
| `selfheal_enable` | `true` | |
| `selfheal_mem_avail_kb` | `204800` | 低于 200MB 触发条件之一 |
| `selfheal_xray_rss_kb` | `256000` | xray RSS 高于 250MB 触发条件之一 |
| `selfheal_min_interval_days` | `7` | 距上次自愈最少天数 |
| `autoban_enable` | `true` | |
| `autoban_thresh_mb` | `2` | 未认证 IP 的小时率阈值 |
| `autoban_strikes` | `2` | 连续 N 轮超标才封 |

## secrets.json 结构

```json
{
  "version": 1,
  "reality": {"private_key": "...", "public_key": "...", "short_id": "..."},
  "ss_password": "...",
  "traffic_web_key": "...",
  "clients": {
    "main": {"uuid": "...", "sub_path": "/..."}
  }
}
```

- `vpskit show <node>` 只显示指纹；
- `vpskit show <node> --secrets` 显示原文（终端警告）；
- 只有 `vpskit rotate` 会改这些值；
- `render` 永远不生成新秘密。
