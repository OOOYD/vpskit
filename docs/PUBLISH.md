# 发布到 GitHub（公开仓库）

## 当前状态

- 当前分支：`main`，**单提交**，不含旧模板/旧历史。
- 旧 `main` 历史含 live 秘密，已备份到 `~/.vpskit-private/old-main-with-secrets-*.bundle` 并从本地删除，当前 `main` 是新建的干净历史。
- 旧 `legacy/`、`build/`（含旧模板/客户端导入卡）已移到 `~/.vpskit-private/`。
- `state/`、`nodes.yaml` 是当前管理东京要用的私有状态，**没有进 Git**；不要打包/上传。
- `scripts/check-secrets.sh` 通过；`git ls-files` 里没有 `templates/`、`state/`、`build/`、`legacy/`、`nodes.yaml`。

## 第一次推送

先在 GitHub 建一个空仓库（不要勾 README/LICENSE），然后：

```bash
cd /Users/oyd/Desktop/AI/vpskit
git remote add origin git@github.com:<你的用户名>/vpskit.git
git push -u origin main
```

- **只推 `main`**。不要 `git push --all`，不要再找回旧 `main` bundle。
- 如果 GitHub 仓库默认分支不是 `main`，在 Settings → Branches 改一下。
- HTTPS 用户把 remote 换成 `https://github.com/OOOYD/vpskit.git`。

## 推送前自检

```bash
./scripts/check-secrets.sh
git log --oneline
git ls-files | grep -E '^(templates|state|build|legacy)/|^nodes\.yaml$' || echo "clean"
```

## 朋友下载/安装

```bash
# 方式 A：clone
git clone https://github.com/OOOYD/vpskit.git
cd vpskit
python3 -m pip install --user pyyaml
cp nodes.example.yaml nodes.yaml
./vpskit doctor
./vpskit init my-vps --host <VPS_IP>
# 编辑 nodes.yaml（clients/admin_ips/quota）
./vpskit plan my-vps
./vpskit apply my-vps --yes

# 方式 B：装成命令（不用 clone 常驻）
pipx install git+https://github.com/OOOYD/vpskit.git
mkdir ~/vpskit-node && cd ~/vpskit-node
vpskit init my-vps --host <VPS_IP>
vpskit plan my-vps
vpskit apply my-vps --yes
```

- 他们需要自己的 VPS root SSH key；不要把自己的 `state/`/`nodes.yaml` 发人。
- GitHub 的 “Download ZIP” 也只包含 tracked 文件，不含秘密。

## 如果你以后要恢复东京的本地管理状态

```bash
# 从私有备份（如果当时移走了）
cp -a ~/.vpskit-private/state-YYYYMMDD ./state
cp ~/.vpskit-private/nodes-YYYYMMDD.yaml ./nodes.yaml
# 或者直接从线上重新导入
./vpskit adopt tokyo --host 103.201.130.126 --ssh-alias tokyo
```

## 万一旧历史已经推过

```bash
./vpskit rotate tokyo --all --yes
./vpskit plan tokyo && ./vpskit apply tokyo --yes
# 所有客户端重新导入订阅
```

然后在 GitHub 上删仓库/清历史，或新建仓库。

## 建议的仓库设置

- Public，License: MIT（已带 `LICENSE`）
- Topics: `vps`, `xray`, `reality`, `nftables`, `debian`, `monitoring`
- 不要开启 Actions 的 “Allow all actions” 之外的东西；CI 只跑单元测试
- 不要上传 `state/`、`build/`、`nodes.yaml`、`legacy/`
