"""仓库内路径布局。"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


def find_root(start: Optional[Path] = None) -> Path:
    """从当前目录向上找 nodes.yaml / nodes.example.yaml；找不到则用包所在仓库根。"""
    here = (start or Path.cwd()).resolve()
    for candidate in [here] + list(here.parents):
        if (candidate / "nodes.yaml").exists() or (candidate / "nodes.example.yaml").exists():
            return candidate
    return Path(__file__).resolve().parent.parent


@dataclass
class NodePaths:
    root: Path
    node_id: str

    @property
    def state_dir(self) -> Path:
        return self.root / "state" / self.node_id

    @property
    def build_dir(self) -> Path:
        return self.root / "build" / self.node_id

    @property
    def secrets(self) -> Path:
        return self.state_dir / "secrets.json"

    @property
    def state(self) -> Path:
        return self.state_dir / "state.json"

    @property
    def lock(self) -> Path:
        return self.state_dir / ".lock"

    @property
    def status_cache(self) -> Path:
        return self.state_dir / "status-cache.json"

    def ensure(self) -> "NodePaths":
        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        self.build_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.build_dir, 0o700)
        return self
