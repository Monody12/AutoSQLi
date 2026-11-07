# -*- coding: utf-8 -*-
"""AutoSQLi 通用回归基准：mock 靶场场景清单驱动 CLI，断言提取已知 flag。

用法（仓库根目录）：
  python tests/regression.py            # 全量场景
  python tests/regression.py news_union # 只跑名字含 news_union 的场景

每个场景 = mock 规则 + CLI 调用参数 + 期望 flag。任何工具改动后必须
全量 PASS 再提交（防过拟合：这些场景不带任何 CTFshow 平台依赖）。
"""
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import yaml  # noqa: E402

PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"

SCENARIOS = [
    {
        "name": "news_union",
        "page": "/news.php",
        "expect": "flag{mock_regr35510n}",
        "args": ["-u", f"{BASE}/news.php?id=1", "-p", "id", "--dump",
                 "--max-seconds", "120", "--timeout", "10", "--workers", "8"],
    },
    {
        "name": "news_waf209",
        "page": "/news209.php",
        "expect": "flag{mock_regr35510n}",
        "args": ["-u", f"{BASE}/news209.php?id=1", "-p", "id", "--dump",
                 "--max-seconds", "180", "--timeout", "10", "--workers", "8"],
    },
    {
        "name": "news_waf210",
        "page": "/news210.php",
        "expect": "flag{mock_regr35510n}",
        "args": ["-u", f"{BASE}/news210.php?id=1", "-p", "id", "--encode", "b64rev2",
                 "--dump", "--max-seconds", "180", "--timeout", "10", "--workers", "8"],
    },
    {
        "name": "login_or",
        "page": "/login.php",
        "expect": "flag{mock_regr35510n}",
        "args": ["-u", f"{BASE}/login.php", "-p", "password",
                 "--method", "POST", "--data", "username=admin", "password=1",
                 "--dump", "--max-seconds", "150", "--timeout", "10", "--workers", "8"],
    },
    {
        "name": "api_json",
        "page": "/api_json.php",
        "expect": "flag{mock_regr35510n}",
        "args": ["-u", f"{BASE}/api_json.php", "-p", "id",
                 "--method", "POST", "--data", '{"id":"$$"}',
                 "--header", "Content-Type=application/json",
                 "--dump", "--max-seconds", "120", "--timeout", "10", "--workers", "8"],
    },
    {
        "name": "login_csrf",
        "page": "/form_csrf.php",
        "expect": "flag{mock_regr35510n}",
        "args": ["-u", f"{BASE}/form_csrf.php", "-p", "password",
                 "--method", "POST", "--data", "username=admin", "password=1",
                 "--csrf-url", f"{BASE}/form_csrf.php",
                 "--csrf-field", "csrf_token",
                 "--dump", "--max-seconds", "150", "--timeout", "10", "--workers", "6"],
    },
    {
        "name": "api_time214_217",
        "page": "/api/index.php",
        "expect": "flag{mock_regr35510n}",
        "args": ["-u", f"{BASE}/api/index.php", "-p", "ip",
                 "--method", "PUT", "--data", "ip=1", "debug=0", "--raw-body",
                 "--header", "User-Agent=Mozilla/5.0 AutoSQLi",
                 "--dump", "--fast", "--max-seconds", "900", "--timeout", "10",
                 "--workers", "6", "--time-sec", "0.6", "--max-rows", "20"],
    },
]


def start_mock():
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "mockapp.py"),
         "--rules", os.path.join(HERE, "rules", "scenarios.yaml"),
         "--port", str(PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace")
    # 等 mock 就绪
    import urllib.request
    for _ in range(30):
        try:
            urllib.request.urlopen(f"{BASE}/news.php?id=1", timeout=2)
            return proc
        except Exception:
            time.sleep(0.3)
    raise RuntimeError("mockapp 未就绪")


def run_scenario(sc):
    args = [sys.executable, "-u", "-m", "autosqli.cli", *sc["args"]]
    t0 = time.time()
    p = subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=sc_max(sc) + 60)
    out = (p.stdout or "") + (p.stderr or "")
    dt = time.time() - t0
    ok = sc["expect"].lower() in out.lower()
    return ok, dt, out


def sc_max(sc):
    import re
    m = re.search(r"--max-seconds (\d+)", " ".join(sc["args"]))
    return int(m.group(1)) if m else 120


def main():
    filt = sys.argv[1] if len(sys.argv) > 1 else ""
    cases = [s for s in SCENARIOS if filt in s["name"]]
    mock = start_mock()
    results = []
    try:
        for sc in cases:
            try:
                ok, dt, out = run_scenario(sc)
            except subprocess.TimeoutExpired:
                ok, dt, out = False, sc_max(sc) + 60, "(timeout)"
            mark = "PASS" if ok else "FAIL"
            results.append((sc["name"], mark, dt))
            print(f"[{mark}] {sc['name']:16s} {dt:6.1f}s", flush=True)
            if not ok:
                tail = out[-1200:]
                print("  ---- 工具输出尾部 ----")
                for line in tail.splitlines()[-14:]:
                    print("  " + line[:150])
    finally:
        mock.terminate()
    npass = sum(1 for _, m, _ in results if m == "PASS")
    print(f"\n== 回归结果: {npass}/{len(results)} PASS ==")
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
