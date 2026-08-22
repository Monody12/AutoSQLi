"""解题方法基类与注册表。"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..core.models import AnalysisReport


@dataclass
class TechniqueMeta:
    key: str
    name: str
    category: str          # 有回显 / 无回显 / 特殊
    desc: str


class Technique(ABC):
    meta: TechniqueMeta = None

    @abstractmethod
    def feasible(self, report: AnalysisReport) -> tuple:
        """返回 (是否可行, 原因说明)。基于 WAF 报告与指纹自动裁剪。"""

    def make_oracle(self, report: AnalysisReport):
        """数据型方法返回 Oracle；特殊方法返回 None。"""
        return None


REGISTRY: list = []


def register(cls):
    REGISTRY.append(cls)
    return cls
