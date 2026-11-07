# -*- coding: utf-8 -*-
"""AutoSQLi 本地 mock 靶场：纯标准库 HTTP server + SQLite，断网可跑。

用途：通用回归基准——把 CTFshow 上攻克的 WAF 族规则配置化复现，每次改
工具后跑 tests/regression.py 验证核心能力没有退化（防过拟合）。

用法：
  python tests/mockapp.py --rules tests/rules/scenarios.yaml --port 8765

设计要点：
- 每个场景 = 一个页面（路径/方法/SQL 模板/响应形态/WAF 规则）；
- WAF 规则：reject_regex（整包拒）、strip（str_replace 剥离）、
  ua_gate（require_sqlmap / reject_sqlmap）、decode（b64rev2 等）；
- benchmark/sleep 求值：命中条件时服务端 sleep 模拟延时（SQLite 无
  延时原语，用「翻译条件 → 执行 → 真则延时」实现时间盲注通道）；
- MySQL→SQLite 翻译层：database()/version()/if()/ascii()/limit a,b/
  0x hex 字面量 / benchmark|sleep 剥离——只覆盖工具实际会发出的语法。
"""
import argparse
import base64
import json
import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlparse

import yaml

DB_PATH = None
RULES = None

FLAG_DEFAULT = "flag{mock_regr35510n}"


# ---------------------------------------------------------------- 翻译层
def mysql_to_sqlite(sql: str) -> str:
    s = sql
    # benchmark / sleep：延时由服务端按执行结果模拟，表达式本体置 1
    s = re.sub(r"benchmark\s*\(\s*\d+\s*,\s*(?:\w+\s*\([^()]*\)|[^()]*)\s*\)",
               "1", s, flags=re.I)
    s = re.sub(r"benchmark\s*\([^()]*\)", "1", s, flags=re.I)
    s = re.sub(r"sleep\s*\([^()]*\)", "1", s, flags=re.I)
    # 0x 十六进制字面量 → 字符串字面量（工具只用可打印 ASCII hex）
    def _hex(m):
        try:
            return "'" + bytes.fromhex(m.group(1)).decode("utf-8", "replace") + "'"
        except Exception:      # noqa: BLE001
            return m.group(0)
    s = re.sub(r"\b0x([0-9a-fA-F]+)\b", _hex, s)
    # database()/version()/user() → SQLite 常量
    s = re.sub(r"\bdatabase\s*\(\s*\)", "'main'", s, flags=re.I)
    s = re.sub(r"\bsqlite_version\s*\(\s*\)", "'3.44.0-mock'", s, flags=re.I)
    s = re.sub(r"\bversion\s*\(\s*\)", "'8.0.36-mock'", s, flags=re.I)
    s = re.sub(r"\buser\s*\(\s*\)", "'root@localhost'", s, flags=re.I)
    s = re.sub(r"\bcurrent_user\s*\(\s*\)", "'root@localhost'", s, flags=re.I)
    # ascii() → unicode()（SQLite 取首字符码点）
    s = re.sub(r"\bascii\s*\(", "unicode(", s, flags=re.I)
    # substr/mid 的 FROM..FOR 语法 → SQLite 不支持，改逗号形式。
    # 覆盖三种形态：from 1 for 1 / from(1)for(1) / 混大小写 fRoM(1)for(1)。
    # 替换式不吞不补括号（前导表达式收尾括号与 sUbStR 收尾括号保持原位）
    s = re.sub(r"\bfrom\s*\(?\s*(\d+)\s*\)?\s*for\s*\(?\s*(\d+)\s*\)?",
               r", \1, \2", s, flags=re.I)
    # if() → IIF()（SQLite 3.32+）
    s = re.sub(r"\bif\s*\(", "IIF(", s, flags=re.I)
    # information_schema → 仿视图（表/列枚举全兼容）。
    # 大小写不敏感：工具的 mixed_case 变换会把关键字搅成 iNfOrMaTiOn_sChEmA
    s = re.sub(r"information_schema\.tables", "info_schema_tables", s, flags=re.I)
    s = re.sub(r"information_schema\.columns", "info_schema_columns", s, flags=re.I)
    s = re.sub(r"information_schema\.schemata", "info_schema_tables", s, flags=re.I)
    # limit a,b → limit b offset a
    s = re.sub(r"\blimit\s+(\d+)\s*,\s*(\d+)", r"limit \2 offset \1", s, flags=re.I)
    # MySQL 的 # 行注释 → SQLite 的 --
    s = s.replace("#", "--")
    return s


def has_time_primitives(sql: str) -> bool:
    return bool(re.search(r"\b(benchmark|sleep)\s*\(", sql, flags=re.I))


# ---------------------------------------------------------------- 场景执行
def apply_waf_value(value: str, waf: dict) -> tuple[str, str | None]:
    """对「注入字段的值」应用规则（真实 WAF 只拦参数值，不拦整条 SQL）。
    返回 (处理后的值, 拒绝响应或 None)。顺序：decode → strip → reject。"""
    v = value
    if waf.get("decode"):
        def _php_b64(x):
            # PHP base64_decode 的宽容语义：跳过 '=' 等非法位置字符后补齐。
            # 中间层可能是 bytes（b64 文本），先转 ascii str
            if isinstance(x, bytes):
                x = x.decode("latin-1")
            x = x.replace("=", "")
            return base64.b64decode(x + "=" * (-len(x) % 4))
        try:
            if waf["decode"] == "b64rev2":
                # 目标侧 decode = strrev(b64decode(strrev(b64decode(v))))，
                # 逆运算 = b64decode(v) → strrev → b64decode → strrev
                a = _php_b64(v)[::-1]
                v = _php_b64(a)[::-1].decode("utf-8", "replace")
            elif waf["decode"] == "b64":
                v = _php_b64(v).decode("utf-8", "replace")
        except Exception:                    # noqa: BLE001
            return "", "REJECT"              # 解不开 = 目标侧也是乱码 → 查询失败
    for word in waf.get("strip", []):
        v = v.replace(word, "")
    for pat in waf.get("reject_regex", []):
        if re.search(pat, v, flags=re.I):
            return v, "REJECT"
    if waf.get("reject_words"):
        for w in waf["reject_words"]:
            if w.lower() in v.lower():
                return v, "REJECT"
    return v, None


def check_ua(ua: str, waf: dict) -> str | None:
    gate = waf.get("ua_gate")
    if gate == "require_sqlmap" and "sqlmap" not in ua:
        return '["使用sqlmap是没有灵魂的"]'
    if gate == "reject_sqlmap" and "sqlmap" in ua:
        return '["使用sqlmap是没有灵魂的"]'
    return None


def eval_rows(scenario: dict, values: dict, ua: str) -> tuple[list, str | None, bool]:
    """执行场景 SQL，返回 (rows, 拒绝响应, 是否延时)。"""
    waf = dict(scenario.get("waf", {}))
    rej = check_ua(ua, waf)
    if rej:
        return [], rej, False
    tpl = scenario["template"]
    sql = tpl
    for k, v in values.items():
        v2, frej = apply_waf_value(v, waf)
        if frej:
            return [], frej, False
        sql = sql.replace("{" + k + "}", v2)
    if rej is not None:
        return [], rej, False
    delay = has_time_primitives(sql)
    tsql = mysql_to_sqlite(sql)
    if scenario.get("raw_return"):
        # 表名注入类（web183）：模板本体就是完整语句，直接执行取标量
        pass
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(tsql)
        try:
            rows = [dict(r) for r in cur.fetchall()]
        except sqlite3.Error:
            rows = []
        if delay and rows and any(any(str(v) not in ("0", "", "None") for v in r.values())
                                  for r in rows):
            # 延时按 kicks 自适应：1e6 → 满延时（探测器阈值 3.5s 依赖它），
            # 小 kicks（TimeOracle 校准后的求值）按比例缩短，回归才跑得完
            bd = float(scenario.get("bench_delay", 1.2))
            km = re.search(r"benchmark\s*\(\s*(\d+)", sql, flags=re.I)
            d = bd * (int(km.group(1)) / 1000000) if km else bd
            time.sleep(min(bd, max(0.15, d)))
        return rows, None, delay
    except sqlite3.Error as e:
        return [], f"__SQLERROR__{e}", delay
    finally:
        conn.close()


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):      # noqa: D401
        pass

    def _read_body(self) -> str:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode("utf-8", "replace") if n else ""

    def _respond(self, status: int, body: str, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle(self):
        parsed = urlparse(self.path)
        path = parsed.path
        ua = self.headers.get("User-Agent", "")
        sc = RULES["scenarios"].get(path)
        if sc is None:
            self._respond(404, "<html><body>404</body></html>")
            return
        method = self.method.upper()
        raw = self._read_body()
        # PUT/POST body 一律按表单解析（web214 真实行为：$_POST 由 PHP
        # urldecode；& 分隔、值内 # 不特殊）
        form = dict(parse_qsl(raw))
        query = dict(parse_qsl(parsed.query))

        # 取值：按配置的字段映射
        values = {}
        if sc.get("body_parse") == "json":
            # JSON body 场景：fields 的键即 JSON 键
            try:
                jbody = json.loads(raw) if raw else {}
            except Exception:                 # noqa: BLE001
                jbody = {}
            for k in (sc.get("fields") or {}):
                values[k] = str(jbody.get(k, ""))
        else:
            for out_key, src in sc.get("fields", {}).items():
                if src == "@query":
                    values[out_key] = query.get(out_key, "")
                elif src.startswith("@form:"):
                    values[out_key] = form.get(src.split(":", 1)[1], "")
                else:
                    values[out_key] = query.get(out_key) or form.get(out_key, "")

        rows, rej, _delay = eval_rows(sc, values, ua)
        if rej is not None:
            if rej.startswith("__SQLERROR__"):
                # 报错响应必须确定化（真实应用所有 SQL 报错都是同一失败页）：
                # 具体错误文本不同会让扫描器把「可用」误判成「已过滤」
                mode = sc.get("error_mode", "fail_page")
                if mode == "empty":
                    self._respond(200, "")
                    return
                self._respond(200, json.dumps({"code": 0, "msg": "查询失败",
                                               "data": []}, ensure_ascii=False),
                              "application/json")
                return
            self._respond(200, rej, "application/json")
            return

        resp = sc.get("response", "html_rows")
        debug = (form.get("debug") or query.get("debug") or "")
        if resp == "empty":
            # web214 族：成功也空体；debug=1 回显 SQL 原文
            if debug == "1":
                sql = sc["template"]
                for k, v in values.items():
                    sql = sql.replace("{" + k + "}", v)
                self._respond(200, sql)
            else:
                self._respond(200, "")
        elif resp == "json_rows":
            self._respond(200, json.dumps({"code": 0, "msg": "查询成功", "count": len(rows),
                                           "data": rows}, ensure_ascii=False),
                          "application/json")
        elif resp == "count":
            n = list(rows[0].values())[0] if rows else 0
            self._respond(200, f"$user_count = {n};")
        elif resp == "login":
            ok = bool(rows) and rows[0].get("username")
            if ok:
                flag = sc.get("flag", "")
                self._respond(200, json.dumps({"code": 0, "msg": "登陆成功",
                                               "data": [{"flag": flag}]}),
                              "application/json")
            else:
                self._respond(200, json.dumps({"code": 0, "msg": "用户名或密码错误",
                                               "data": []}),
                              "application/json")
        else:      # html_rows
            if rows:
                parts = ["<table>"]
                for r in rows:
                    parts.append("<tr>" + "".join(f"<td>{v}</td>" for v in r.values())
                                 + "</tr>")
                parts.append("</table>")
                self._respond(200, "".join(parts))
            else:
                # 无结果与 SQL 报错同形（真实应用两类失败同一失败页；
                # 形态不同会让扫描器把可用 token 误判为已过滤）
                self._respond(200, json.dumps({"code": 0, "msg": "查询失败",
                                               "data": []}, ensure_ascii=False),
                              "application/json")
            return

    def do_GET(self):
        self.method = "GET"
        self._handle()

    def do_POST(self):
        self.method = "POST"
        self._handle()

    def do_PUT(self):
        self.method = "PUT"
        self._handle()


def build_db(path: str, flag: str):
    conn = sqlite3.connect(path)
    c = conn.cursor()
    c.executescript("""
    drop table if exists news;
    create table news (id int, title text, content text);
    drop table if exists users;
    create table users (id int, username text, password text);
    drop table if exists info;
    create table info (id int, ip text, cname text);
    drop table if exists flagx;
    create table flagx (id int, flaga text, note text);
    """)
    c.executemany("insert into news values (?,?,?)",
                  [(1, "hello", "world"), (2, "ctf", "practice"),
                   (3, "secret", "flag{mock_regr35510n}")])
    c.executemany("insert into users values (?,?,?)",
                  [(1, "admin", "admin123"), (2, "guest", "guest456"),
                   (3, "flag", flag)])
    c.execute("insert into info values (1,'127.0.0.1','beijing')")
    c.execute("insert into flagx values (1,?,'you get it')", (flag,))
    # information_schema 仿视图：让 MySQL 方言的枚举查询在 SQLite 上直接工作
    c.executescript("""
    drop view if exists info_schema_tables;
    create view info_schema_tables as
      select 'main' as table_schema, name as table_name
      from sqlite_master where type = 'table';
    drop view if exists info_schema_columns;
    create view info_schema_columns as
      select 'main' as table_schema, m.name as table_name, p.name as column_name
      from sqlite_master m join pragma_table_info(m.name) p
      where m.type = 'table';
    """)
    conn.commit()
    conn.close()


def main():
    global DB_PATH, RULES
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--flag", default=FLAG_DEFAULT)
    ap.add_argument("--db", default="")
    a = ap.parse_args()
    RULES = yaml.safe_load(open(a.rules, encoding="utf-8"))
    DB_PATH = a.db or (a.rules + ".mock.db")
    build_db(DB_PATH, a.flag)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print(f"mockapp on 127.0.0.1:{a.port} (flag={a.flag})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
