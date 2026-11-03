# Contributing

## 本地开发

```bash
git clone https://github.com/OOOYD/vpskit.git
cd vpskit
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e '.[dev]'   # 或 pip install -e . && pip install pyyaml
./vpskit doctor
python -m unittest discover -v
```

## 提交前

```bash
python -m unittest discover -v
./scripts/check-secrets.sh
bash -n install.sh
python -m compileall -q vpskitlib tests
```

## 约定

- Python 3.9+，标准库优先；唯一运行依赖 PyYAML。
- 渲染必须是纯函数（同样输入 → 同样字节）；不要在模板里放时间戳/随机数。
- 秘密只在 `secrets.ensure_secrets`/`rotate` 生成。
- 新文件要同时更新 manifest 的 mode/owner/group，并补测试。
- 新命令必须支持 `--json`（stdout 纯 JSON），并更新 `docs/AI.md`。
- 不要提交 `state/`、`build/`、`nodes.yaml`、`legacy/`。
- 不要在代码里写死节点 IP/邮箱/UUID/私钥/订阅路径。

## PR

- 说明动机、影响面、回滚方式。
- 附测试输出；涉及远端行为的，附 `plan`/`verify` 的脱敏输出。
- 不要包含任何真实秘密。
