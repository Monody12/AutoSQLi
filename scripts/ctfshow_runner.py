"""ctf.show 批量刷题 / 回归 runner（AutoSQLi 的端到端测试床）。

做什么：
  1. 通过 ctf.show 官方 API 逐题开容器（同一账号同时只有 1 个容器，
     开新题会立即回收旧容器）；
  2. 等容器就绪后取题目链接，用 `python -m autosqli.cli ... --dump` 跑一遍；
  3. 从输出里抓 `[FLAG]` 与被测参数等信息，落盘成 JSON + Markdown 进度表；
  4. 平台写操作共享 60 秒限频，脚本自动 sleep，绝不触发 403。

用法：
  # 看某板块题目与已跑记录
  python scripts/ctfshow_runner.py --list --filter sql注入

  # 跑 web173、web174（每题开容器 → 跑 → 等 65s → 下一题）
  python scripts/ctfshow_runner.py --run web173 web174 --dump

  # 指定目标 URL 的注入参数（默认 api/?id=1）
  python scripts/ctfshow_runner.py --run web183 --url-tpl "{base}?tableName=1" -p tableName

安全：
  - 登录 cookie 只从文件/环境变量读，不写进仓库；
  - 结果写到 runs/（已在 .gitignore 中忽略），flag 只在本地留存，不提交平台。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

BASE = "https://ctf.show"
COOLDOWN = 65.0          # 平台写操作限频 60s，留 5s 余量
RUNS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runs")

FLAG_RE = re.compile(r"(?:ctfshow|flag|CTF|FLAG)\{[^}\s'\"]{1,120}\}")
URL_RE = re.compile(r'href="(https://[^"]+)"')
CSRF_RE = re.compile(r"csrfNonce'?\s*:\s*[\"']([0-9a-f]{32,})[\"']")

_last_write = 0.0


def load_cookie(path: str | None) -> str:
    if path:
        with open(path, encoding="utf-8-sig") as f:
            return f.read().strip()
    env = os.environ.get("CTFSHOW_SESSION", "").strip()
    if not env:
        raise SystemExit("缺少 cookie：用 --cookie-file 或设置 CTFSHOW_SESSION")
    return env


class Api:
    def __init__(self, cookie: str):
        self.headers = {
            "Cookie": "session=" + cookie,
            "User-Agent": "AutoSQLi-runner/1.0",
            "Accept": "application/json",
        }
        self._nonce = ""

    def req(self, method: str, path: str, body: bytes | None = None, write: bool = False):
        global _last_write
        if write:
            wait = COOLDOWN - (time.time() - _last_write)
            if wait > 0:
                print(f"  [冷却] 等待 {wait:.0f}s 以满足平台 60s 限频…", flush=True)
                time.sleep(wait)
            _last_write = time.time()
        headers = dict(self.headers)
        if write:
            headers["CSRF-Token"] = self.get_nonce()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=40) as r:
                raw = r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            # 403 未必是错误：whale 插件在「别的题容器在跑」时用 403 + JSON 说明，
            # 限频也是 403。统一按 JSON 处理，交给调用方看 message。
            raw = e.read().decode("utf-8", "replace")
            try:
                j = json.loads(raw)
            except json.JSONDecodeError:
                j = {"success": False, "raw": raw}
            j["_status"] = e.code
            return j
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"success": False, "raw": raw}

    def get_nonce(self) -> str:
        if not self._nonce:
            req = urllib.request.Request(BASE + "/challenges", headers=self.headers)
            with urllib.request.urlopen(req, timeout=40) as r:
                html = r.read().decode("utf-8", "replace")
            m = CSRF_RE.search(html)
            self._nonce = m.group(1) if m else ""
        return self._nonce


def challenges(api: Api, filt: str = "") -> list[dict]:
    data = api.req("GET", "/api/v1/challenges").get("data") or []
    if filt:
        data = [c for c in data if filt.lower() in (c.get("category") or "").lower()]
    return data


def detail(api: Api, cid: int) -> dict:
    """单题详情：description=题面（含 waf 源码）、hints、solved_by_me。"""
    return api.req("GET", f"/api/v1/challenges/{cid}")


def by_name(items: list[dict], name: str) -> dict:
    for c in items:
        if (c.get("name") or "").lower() == name.lower():
            return c
    raise SystemExit(f"找不到题目 {name}")


def dump_status() -> dict:
    path = os.path.join(RUNS_DIR, "ctfshow_results.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_status(st: dict):
    os.makedirs(RUNS_DIR, exist_ok=True)
    path = os.path.join(RUNS_DIR, "ctfshow_results.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=2)


def container_url(api: Api, cid: int) -> str:
    """当前正在跑的容器链接；不是本题或没容器则返回空串。"""
    j = api.req("GET", f"/api/v1/plugins/ctfd-whale/container?challenge_id={cid}")
    data = j.get("data") or {}
    m = URL_RE.search(data.get("user_access") or "")
    if m and data.get("remaining_time"):
        return m.group(1).rstrip("/")
    return ""


def boot(api: Api, cid: int) -> str:
    """开容器并返回题目链接；轮询 whale 接口直到 user_access 出现。"""
    j = api.req("POST", f"/api/v1/plugins/ctfd-whale/container?challenge_id={cid}",
                body=b"{}", write=True)
    if not j.get("success") and "Frequency" in str(j.get("message", "")):
        print("  [限频] 平台限频，等待 62s 后重试 boot…", flush=True)
        time.sleep(62)
        j = api.req("POST", f"/api/v1/plugins/ctfd-whale/container?challenge_id={cid}",
                    body=b"{}", write=True)
    if not j.get("success") and "not from this challenge" not in str(j.get("message", "")):
        raise RuntimeError(f"开容器失败: {j.get('message') or j}")
    for _ in range(20):
        j = api.req("GET", f"/api/v1/plugins/ctfd-whale/container?challenge_id={cid}")
        data = j.get("data") or {}
        m = URL_RE.search(data.get("user_access") or "")
        if m:
            return m.group(1).rstrip("/")
        time.sleep(2)
    raise RuntimeError("容器启动超时（未拿到题目链接）")


def ensure_container(api: Api, cid: int) -> str:
    """本题容器已在跑就复用（省一次 60s 冷却），否则创建。"""
    url = container_url(api, cid)
    if url:
        print("  [复用] 本题容器已在运行，跳过重建", flush=True)
        return url
    return boot(api, cid)


def run_cli(url: str, param: str, extra: list[str], timeout: int = 900):
    cmd = [sys.executable, "-m", "autosqli.cli", "-u", url, "-p", param,
           "--dump", "--workers", "8", *extra]
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print("  $ " + " ".join(cmd), flush=True)
    t0 = time.time()
    p = subprocess.run(cmd, cwd=root, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    return p.returncode, out, time.time() - t0


def summarize(out: str) -> dict:
    flags = list(dict.fromkeys(FLAG_RE.findall(out)))
    injected = re.search(r"注入点: 参数 (\S+), 闭合 '?(.*?)'?,", out)
    tech = re.search(r"开始脱库（通道: (\w+)）", out)
    reqs = re.search(r"请求数: (\d+)", out)
    return {
        "flags": flags,
        "param": injected.group(1) if injected else "",
        "closure": injected.group(2) if injected else "",
        "technique": tech.group(1) if tech else "",
        "requests": int(reqs.group(1)) if reqs else 0,
    }


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="ctf.show 批量刷题 runner")
    ap.add_argument("--cookie-file", default="")
    ap.add_argument("--list", action="store_true", help="列出题目（配合 --filter）")
    ap.add_argument("--filter", default="sql注入", help="分类关键词过滤（默认 sql注入）")
    ap.add_argument("--run", nargs="*", metavar="WEB_NNN", help="要跑的题名列表")
    ap.add_argument("--all", action="store_true", help="跑过滤结果里所有未解出的题")
    ap.add_argument("--param", "-p", default="id", help="注入参数名（默认 id）")
    ap.add_argument("--url-tpl", default="{base}/api/?id=1",
                    help="目标 URL 模板，{base} 为容器根链接")
    ap.add_argument("--cli-args", default="", help="透传给 CLI 的额外参数（空格分隔）")
    ap.add_argument("--timeout", type=int, default=900, help="单题 CLI 超时秒数")
    ap.add_argument("--dump", action="store_true", help="（保留参数）跑完即脱库，当前恒为 --dump")
    args = ap.parse_args(argv)

    api = Api(load_cookie(args.cookie_file or
                          os.environ.get("CTFSHOW_COOKIE_FILE", "")))

    items = challenges(api, args.filter)
    st = dump_status()
    if args.list:
        solved = 0
        for c in items:
            rec = st.get(c["name"], {})
            mark = "✅" if rec.get("flags") else ("⏳" if rec.get("error") else "  ")
            print(f"{mark} {c['name']:>8}  id={c['id']:<4} {c.get('category','')}")
            solved += bool(rec.get("flags"))
        print(f"-- {len(items)} 题，本地已出 flag {solved} 题")
        return 0

    names = args.run or []
    if args.all:
        names = [c["name"] for c in items if not st.get(c["name"], {}).get("flags")]
    if not names:
        ap.error("需要 --run 或 --all")

    extra = args.cli_args.split() if args.cli_args else []
    for name in names:
        c = by_name(items, name)
        print(f"\n===== {name} (id={c['id']}) =====", flush=True)
        rec = {"challenge": name, "id": c["id"], "time": time.strftime("%F %T")}
        try:
            base = ensure_container(api, c["id"])
            rec["url"] = base
            print(f"  容器: {base}", flush=True)
            target = args.url_tpl.format(base=base)
            rc, out, secs = run_cli(target, args.param, extra, timeout=args.timeout)
            rec.update(summarize(out))
            rec["seconds"] = round(secs, 1)
            rec["rc"] = rc
            os.makedirs(RUNS_DIR, exist_ok=True)
            log = os.path.join(RUNS_DIR, f"{name}.log")
            with open(log, "w", encoding="utf-8") as f:
                f.write(out)
            if rec["flags"]:
                print(f"  ✅ FLAG: {', '.join(rec['flags'])}  "
                      f"({rec['technique'] or '-'} / {rec['requests']} 请求 / {secs:.0f}s)",
                      flush=True)
            else:
                rec["error"] = "no flag in output"
                print(f"  ❌ 未拿到 flag（rc={rc}, {secs:.0f}s），日志: {log}", flush=True)
        except Exception as e:  # 单题失败不阻断整批
            rec["error"] = f"{type(e).__name__}: {e}"
            print(f"  ⚠️ {rec['error']}", flush=True)
        st[name] = rec
        save_status(st)
    return 0


if __name__ == "__main__":
    sys.exit(main())
