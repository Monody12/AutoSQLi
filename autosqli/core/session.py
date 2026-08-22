"""HTTP 会话层：请求封装、DVWA 登录、线程安全、计时与限速。

设计要点：
- 手工 URL 编码（quote(safe="")），保证宽字节 \\xdf 等原始字节可原样发送；
- 并发场景使用 thread-local Session（requests.Session 非线程安全）；
- 统一返回 ResponseInfo，供上层做差异比较。
"""
from __future__ import annotations

import re
import threading
import time
import urllib.parse
from typing import Callable, Optional

import requests

from .models import ResponseInfo, TargetSpec


class HttpSession:
    """面向"单参数注入"的请求会话。"""

    def __init__(self, spec: TargetSpec, timeout: float = 25.0,
                 logger: Optional[Callable[[str, str], None]] = None):
        self.spec = spec
        self.timeout = timeout
        self.log = logger or (lambda lvl, msg: None)
        self._local = threading.local()
        self._cookie_lock = threading.Lock()
        self._shared_cookies: dict = dict(spec.cookies)
        self._last_request_time = 0.0
        self._rate_lock = threading.Lock()
        self.request_count = 0
        self.found_flags: list = []          # 响应中捕获的 flag（EasySQL 类题型）
        self._stop = threading.Event()

    # ------------------------------------------------------------------ session
    def _new_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AutoSQLi/dev",
            "Accept-Language": "en-US,en;q=0.9",
        })
        if self.spec.headers:
            s.headers.update(self.spec.headers)
        s.cookies.update(self._shared_cookies)
        if not self.spec.verify_ssl:
            s.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return s

    @property
    def session(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = self._new_session()
            self._local.session = s
        return s

    def stop(self):
        self._stop.set()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    # ------------------------------------------------------------------ login
    def login(self) -> bool:
        """DVWA 风格登录：解析 user_token → POST 凭据 → 设置安全等级。"""
        if not self.spec.login_url:
            return False
        s = self.session
        try:
            r = s.get(self.spec.login_url, timeout=self.timeout)
            m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", r.text)
            token = m.group(1) if m else ""
            r = s.post(self.spec.login_url, data={
                self.spec.login_user_field: self.spec.login_user,
                self.spec.login_pass_field: self.spec.login_pass,
                "Login": "Login",
                "user_token": token,
            }, timeout=self.timeout)
            ok = r.status_code == 200 and "login.php" not in r.url
            if ok and self.spec.security:
                self._set_dvwa_security(self.spec.security)
            self._sync_cookies(s)
            self.log("INFO" if ok else "WARN",
                     f"登录 {'成功' if ok else '失败'}: {self.spec.login_url}")
            return ok
        except requests.RequestException as e:
            self.log("ERROR", f"登录请求异常: {e}")
            return False

    def _set_dvwa_security(self, level: str):
        """DVWA 的安全等级存于 $_SESSION，需 POST security.php 才生效。"""
        from urllib.parse import urljoin
        s = self.session
        url = urljoin(self.spec.login_url, "./security.php")
        try:
            r = s.get(url, timeout=self.timeout)
            m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", r.text)
            s.post(url, data={"security": level, "seclev_submit": "Submit",
                              "user_token": m.group(1) if m else ""}, timeout=self.timeout)
            s.cookies.set("security", level)
            self.log("INFO", f"已设置 DVWA 安全等级: {level}")
        except requests.RequestException as e:
            self.log("WARN", f"设置安全等级失败: {e}")

    def _sync_cookies(self, s: requests.Session):
        with self._cookie_lock:
            self._shared_cookies.update(s.cookies.get_dict())

    # ------------------------------------------------------------------ request
    @staticmethod
    def encode_value(value: str) -> str:
        """手工编码：全部转义。宽字节等原始字符（\\xdf）会被编码为 %DF 原样传输。"""
        return urllib.parse.quote(value, safe="")

    def _rate_limit(self):
        interval = self.spec.request_interval
        if interval <= 0:
            return
        with self._rate_lock:
            wait = self._last_request_time + interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last_request_time = time.monotonic()

    def build_url(self, value: str, param: Optional[str] = None) -> str:
        param = param or self.spec.param
        parts = []
        for k, v in self.spec.params.items():
            vv = value if k == param else str(v)
            parts.append(f"{urllib.parse.quote(k, safe='')}={self.encode_value(vv)}")
        if param and param not in self.spec.params:
            parts.append(f"{urllib.parse.quote(param, safe='')}={self.encode_value(value)}")
        base = self.spec.url
        return base + ("&" if "?" in base else "?") + "&".join(parts) if parts else base

    def request_value(self, value: str, param: Optional[str] = None,
                      extra_note: str = "") -> ResponseInfo:
        """向被测参数注入 value 并发出请求。

        若配置了 stage_url（两步提交），先把 value 写入 stage 入口，
        再请求主页面读取结果（DVWA high 模式 / 二次注入题型）。
        """
        if self.stopped:
            raise RuntimeError("session stopped")
        param = param or self.spec.param
        s = self.session
        if self.spec.stage_url:
            stage_param = self.spec.stage_param or param
            t0 = time.perf_counter()
            try:
                if self.spec.stage_method.upper() == "POST":
                    sr = s.post(self.spec.stage_url,
                                data={stage_param: value}, timeout=self.timeout)
                    stage_desc = f"POST {self.spec.stage_url} ({stage_param}=<payload>)"
                else:
                    stage_query = self.spec.stage_url + (
                        "&" if "?" in self.spec.stage_url else "?")
                    stage_query += (f"{urllib.parse.quote(stage_param, safe='')}"
                                    f"={self.encode_value(value)}")
                    sr = s.get(stage_query, timeout=self.timeout)
                    stage_desc = stage_query
                self.log("REQ", f"STAGE {stage_desc} -> {sr.status_code} "
                                f"({(time.perf_counter()-t0)*1000:.0f}ms)")
            except requests.RequestException as e:
                self.log("ERROR", f"stage 请求异常: {e}")
                return ResponseInfo(status_code=-1, body=f"__REQUEST_ERROR__:{e}",
                                    elapsed_ms=0)
        self._rate_limit()
        t0 = time.perf_counter()
        final_url = ""
        for attempt in (1, 2):        # 慢环境网络抖动重试一次
            try:
                if self.spec.method.upper() == "POST":
                    body = {k: (value if k == param else str(v))
                            for k, v in self.spec.body_params.items()}
                    r = s.post(self.spec.url, data=body, timeout=self.timeout)
                    final_url = self.spec.url
                else:
                    final_url = self.build_url(value, param)
                    r = s.get(final_url, timeout=self.timeout)
                break
            except requests.RequestException as e:
                if attempt == 1:
                    self.log("WARN", f"请求超时/异常，1.5s 后重试: {str(e)[:60]}")
                    time.sleep(1.5)
                    continue
                self.log("ERROR", f"请求重试仍失败: {e}")
                return ResponseInfo(status_code=-1, body=f"__REQUEST_ERROR__:{e}",
                                    elapsed_ms=(time.perf_counter() - t0) * 1000)
        elapsed = (time.perf_counter() - t0) * 1000
        self.request_count += 1
        self._sync_cookies(s)
        info = ResponseInfo(status_code=r.status_code, body=r.text,
                            elapsed_ms=elapsed, url=final_url,
                            headers=dict(r.headers))
        flags = info.find_flags()
        for f in flags:
            if f not in self.found_flags:
                self.found_flags.append(f)
                self.log("FLAG", f"🎉 响应中发现 flag: {f}")
        self.log("REQ", f"{self.spec.method} {final_url} -> {r.status_code} "
                        f"({len(r.text)}B, {elapsed:.0f}ms) {extra_note}")
        return info

    def multi(self, values: list, workers: int = 4) -> list:
        """并发发送一批 payload（顺序与 values 对应）。"""
        import concurrent.futures as cf
        results = [None] * len(values)
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(self.request_value, v): i for i, v in enumerate(values)}
            for f in cf.as_completed(futs):
                results[futs[f]] = f.result()
        return results
