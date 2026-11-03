# Changelog

## 1.0.0 — 2026-11-03

首个可复用版本。

### Added

- `vpskit` CLI：`init/adopt/plan/apply/verify/status/rollback/rotate/show/list/doctor/panel`
- 确定性渲染：nftables 双栈、Xray REALITY、Shadowsocks、订阅、systemd units、sysctl、sshd 加固
- 每节点秘密：`state/<node>/secrets.json`（0600），UUID/REALITY/SS/订阅/流量 key 只生成一次
- `adopt`：从现网只读导入真实配置/秘密，保持 UUID/私钥/订阅路径/额外端口
- 防火墙保险丝：未确认自动恢复；恢复使用 `flush + load`，失败保留 guard
- 订阅：每用户路径、共享路径、`sub_existing_file` 沿用现网 YAML
- 只读面板：token、分享脱敏、无操作按钮
- 文档：README、CONFIG/ARCHITECTURE/SECURITY/OPERATIONS/MIGRATION/PUBLISH/AI
- 44 个单元测试、CI、secret 扫描脚本

### Fixed

- 旧 kit 的 `put` 路径、`HAS_V6`、`mkdir /root/.smtp.env`、REALITY hex 私钥、非幂等、防火墙回滚不取消等问题
- `sub.py` 从 `/opt/sub` 运行时 import 不到 `/opt/traffic/kitconf.py`
- `ssh_port` 贯通 nftables/fail2ban/回连检查
- `plan --show-diff` 的私钥/UUID 脱敏
- 全新 VPS 没有 `nft` 时 plan 误阻断
- `/tmp` 固定临时文件路径

### Verified

- Debian 13 测试机真实 apply + `verify` 全绿；`plan --check` 幂等（same=33）
- fail2ban 文档 IP 封/解、订阅/流量页 200、面板鉴权/分享、daily 快照/备份
