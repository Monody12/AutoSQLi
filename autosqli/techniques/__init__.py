from .base import REGISTRY, Technique, TechniqueMeta
from . import methods  # noqa: F401  触发注册

__all__ = ["REGISTRY", "Technique", "TechniqueMeta"]


def all_techniques() -> list:
    return [cls() for cls in REGISTRY]
