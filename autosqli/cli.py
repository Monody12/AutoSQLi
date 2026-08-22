"""AutoSQLi 命令行入口（核心引擎无 GUI 复用的验证场）。

用法示例（本地 DVWA）：
  python -m autosqli.cli -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" \
      --dvwa admin:password --dump
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse

from .core.engine import Engine
from .core.models import TargetSpec
from .core.oracles import OracleError


def build_spec(args) -> TargetSpec:
    parsed = urllib.parse.urlparse(args.url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    base = urllib.parse.urlunparse(parsed._replace(query=""))
    cookies = dict(kv.split("=", 1) for kv in args.cookie) if args.cookie else {}
    spec = TargetSpec(
        url=base, method=args.method, params=params,
        cookies=cookies, param=args.param,
        base_value=args.base_value,
        request_interval=args.delay,
    )
    if args.data:
        spec.body_params = dict(kv.split("=", 1) for kv in args.data)
        spec.method = "POST"
    if args.dvwa:
        user, _, pwd = args.dvwa.partition(":")
        spec.login_url = f"{urllib.parse.urlunparse(parsed._replace(path='/login.php', query=''))}"
        spec.login_user, spec.login_pass = user, pwd or "password"
        spec.security = args.security
        if args.security == "high":
            # DVWA 1.10 high：session-input.php(POST) 写 session，主页面读结果
            spec.stage_url = urllib.parse.urlunparse(
                parsed._replace(path="/vulnerabilities/sqli/session-input.php", query=""))
            spec.stage_method = "POST"
    if not spec.param:
        # 默认取第一个非常量参数（URL 参数优先，其次 POST 表单）
        candidates = list(params) + list(spec.body_params.keys())
        for k in candidates:
            if k.lower() not in ("submit",):
                spec.param = k
                break
    if args.dvwa and args.security == "high" and spec.stage_url:
        # 触发页面（读 session）不再携带被测参数
        spec.params.pop(spec.param, None)
    if args.stage_url:
        spec.stage_url = args.stage_url
        spec.params.pop(spec.param, None)     # 触发页面不再携带被测参数
    return spec


def main(argv=None):
    # Windows 控制台默认 GBK：★✓✗ 等字符会 UnicodeEncodeError
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(prog="autosqli", description="CTF SQL 注入自动化分析（WAF 感知）")
    ap.add_argument("-u", "--url", required=True, help="目标 URL")
    ap.add_argument("-p", "--param", default="", help="被测参数名（默认自动选择第一个）")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--data", nargs="*", help="POST 表单 k=v")
    ap.add_argument("--cookie", nargs="*", help="Cookie k=v")
    ap.add_argument("--dvwa", metavar="USER:PASS", default="", help="DVWA 类自动登录")
    ap.add_argument("--security", default="low", help="DVWA security 等级")
    ap.add_argument("--stage-url", default="", help="两步提交入口（先写值再触发，如二次注入/DVWA high）")
    ap.add_argument("--base-value", default="1", help="被测参数基线值")
    ap.add_argument("--delay", type=float, default=0.0, help="请求间隔秒")
    ap.add_argument("--no-waf", action="store_true", help="跳过 WAF 扫描（快速模式）")
    ap.add_argument("--technique", default="union", help="解题方法 key（默认 union）")
    ap.add_argument("--max-rows", type=int, default=20)
    ap.add_argument("--workers", type=int, default=6,
                    help="盲注并发线程数（网络好可调 12-16）")
    ap.add_argument("--dump", action="store_true", help="分析后直接全自动脱库")
    ap.add_argument("--report", default="", help="分析报告输出 JSON 路径")
    ap.add_argument("--solution", default="", help="解题方法复盘输出 Markdown 路径")
    ap.add_argument("--quiet", action="store_true", help="不打印请求日志")
    args = ap.parse_args(argv)

    log = (lambda lvl, msg: None) if args.quiet else \
        (lambda lvl, msg: print(f"[{lvl}] {msg}", flush=True) if lvl != "REQ"
         else print(f"[{lvl}] {msg}", flush=True))

    spec = build_spec(args)
    engine = Engine(spec, log=log)
    report = engine.analyze(scan_waf=not args.no_waf)
    if report.injection is None:
        print("[-] 未发现注入点")
        for n in report.notes:
            print(f"    {n}")
        if report.waf.has_waf:
            print("[*] WAF 线索（即使不可注入，也提示了防护点）:")
            for it in report.waf.filtered_list():
                print(f"    - 已过滤 {it.token!r}: {it.evidence} | 建议: {it.suggestion or '—'}")
        return 1

    print("\n========== 分析报告 ==========")
    print(f"注入点: 参数 {report.injection.param}, 闭合 {report.injection.closure!r}, "
          f"注释 {report.injection.comment!r}, 列数 {report.injection.column_count}, "
          f"回显位 {report.injection.echo_positions}")
    print(f"WAF: {'检出 ' + str(len(report.waf.filtered_list())) + ' 项过滤' if report.waf.has_waf else '未检出'}")
    for it in report.waf.filtered_list():
        print(f"  - 已过滤 {it.token!r}: {it.evidence} | 建议: {it.suggestion or '—'}")
    print("指纹:", json.dumps(report.fingerprint.to_dict(), ensure_ascii=False))
    print("可用方法:")
    for t in report.techniques:
        mark = "★" if t.recommended else ("✓" if t.feasible else "✗")
        print(f"  {mark} [{t.key}] {t.name} — {t.reason}")

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report.to_json())
        print(f"\n[*] 报告已写入 {args.report}")

    if args.dump:
        key = args.technique
        # 自动挑选推荐方法
        if key == "auto":
            rec = [t for t in report.techniques if t.feasible and t.recommended]
            key = rec[0].key if rec else (report.techniques[0].key if report.techniques else "union")
        print(f"\n========== 开始脱库（通道: {key}） ==========")
        try:
            result = engine.solve(report, key, max_rows=args.max_rows,
                                  workers=args.workers)
        except OracleError as e:
            print(f"[-] 通道构造失败: {e}")
            return 2
        print("\n========== 脱库结果 ==========")
        d = result.to_dict()
        print(json.dumps(d, ensure_ascii=False, indent=2)[:8000])
        print(f"\n[+] 请求数: {engine.session.request_count}")

        from .core.solution import build_solution_report
        md = build_solution_report(report, result)
        print("\n" + "=" * 22 + " 解题方法复盘 " + "=" * 22)
        print(md)
        if args.solution:
            with open(args.solution, "w", encoding="utf-8") as f:
                f.write(md)
            print(f"\n[*] 复盘已写入 {args.solution}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
