# -*- coding: utf-8 -*-
"""盲注提取的断点续跑存储：按 目标(method|url|param) 落盘 json 到 runs/。

- TimeOracle：expr → {"length": N, "chars": {pos: 码点}}（逐字符续跑）
- BoolOracle：expr|start → 块文本（分块并发天然可按块恢复）
--fresh 时返回 None（全仓调用点已做 None 容忍）。
"""
import hashlib
import json
import os


class ProgressStore:
    def __init__(self, path: str):
        self.path = path
        self.data = {}
        try:
            with open(path, encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {}

    @classmethod
    def for_spec(cls, spec):
        if getattr(spec, "fresh", False):
            return None
        raw = f"{spec.method}|{spec.url}|{spec.param}"
        key = hashlib.md5(raw.encode()).hexdigest()[:12]
        runs = os.path.join(os.getcwd(), "runs")
        try:
            os.makedirs(runs, exist_ok=True)
        except OSError:
            return None
        return cls(os.path.join(runs, f"progress_{key}.json"))

    def get(self, key):
        return self.data.get(key)

    def put(self, key, value):
        self.data[key] = value
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False)
        except OSError:
            pass
