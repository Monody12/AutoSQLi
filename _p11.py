# -*- coding: utf-8 -*-
"""oracles.py 断点续跑钩子 + models/cli 的 fresh 旗标。"""
import ast

# 1) oracles.py：import + BaseOracle 挂 store
p = "autosqli/core/oracles.py"
s = open(p, encoding="utf-8").read()

old0 = "from .dbms import Dialect"
if old0 in s:
    s = s.replace(old0, "from .dbms import Dialect\nfrom .progress import ProgressStore", 1)
else:
    raise SystemExit("dbms import anchor missing")

old1 = """        self.requests = 0
        self.last_payload = ""                # 最近发送的完整 payload（复盘用）"""
new1 = """        self.requests = 0
        self.last_payload = ""                # 最近发送的完整 payload（复盘用）
        self.progress = ProgressStore.for_spec(session.spec)   # 断点续跑（--fresh 关闭）"""
assert old1 in s, "base oracle anchor"
s = s.replace(old1, new1)

# 2) TimeOracle.scalar 续跑钩子
old2 = """        self.s.log("INFO", f"[time] 长度={length}，游程+分块提取: {expr[:60]}")
        out = []
        prev = None
        for p in range(1, length + 1):
            if self.s.stopped:
                raise OracleError("用户中止")
            if prev:
                eq = "=" if not self.waf.is_filtered("=") else " like "
                a = self._substr_at(expr, p)
                b = self._substr_at(expr, p - 1)
                if self.eval_bool(f"{self.code_expr(a)}{eq}{self.code_expr(b)}"):
                    out.append(prev)
                    continue
            code = self._binsearch(
                lambda m: self._ge(self.code_expr(self._substr_at(expr, p)),
                                   f"{m}", f"{m - 1}"), 32, 126)
            ch = chr(code)
            out.append(ch)
            prev = ch or None
        return "".join(out)"""
new2 = """        self.s.log("INFO", f"[time] 长度={length}，游程+分块提取: {expr[:60]}")
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
        return "".join(out)"""
assert old2 in s, "time scalar anchor"
s = s.replace(old2, new2)

# 3) BoolOracle 块级续跑
old3 = """        result = [""] * length
        BLOCK = 16
        blocks = [(i + 1, min(i + BLOCK, length)) for i in range(0, length, BLOCK)]
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs = {ex.submit(self._extract_block, expr, a, b): (a, b)
                    for a, b in blocks}
            for f in as_completed(futs):
                a, b = futs[f]
                result[a - 1:b] = f.result()
        return "".join(result)"""
new3 = """        result = [""] * length
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
        return "".join(result)"""
assert old3 in s, "bool block anchor"
s = s.replace(old3, new3)
open(p, "w", encoding="utf-8").write(s)
ast.parse(s)
print("oracles resume hooks wired")

# 4) models.py fresh 字段
p = "autosqli/core/models.py"
s = open(p, encoding="utf-8").read()
old4 = "    body_template: str = \"\"                   # JSON/自定义 body 模板（$$ 为注入标记）"
new4 = old4 + "\n    fresh: bool = False                       # 忽略/清除断点续跑存档"
assert old4 in s
s = s.replace(old4, new4)
open(p, "w", encoding="utf-8").write(s)

# 5) cli.py --fresh
p = "autosqli/cli.py"
s = open(p, encoding="utf-8").read()
old5 = '''    ap.add_argument("--max-requests", type=int, default=0,
                    help="请求预算（0=不限；线下赛防封 IP，超限硬停会话）")'''
new5 = old5 + '''
    ap.add_argument("--fresh", action="store_true",
                    help="忽略并清除断点续跑存档（默认自动续跑）")'''
assert old5 in s
s = s.replace(old5, new5)
old6 = "        csrf_field=args.csrf_field,"
new6 = old6 + "\n        fresh=args.fresh,"
assert old6 in s
s = s.replace(old6, new6)
open(p, "w", encoding="utf-8").write(s)
for f in ("autosqli/core/oracles.py", "autosqli/core/models.py", "autosqli/cli.py"):
    ast.parse(open(f, encoding="utf-8").read())
print("fresh flag + resume hooks all wired")
