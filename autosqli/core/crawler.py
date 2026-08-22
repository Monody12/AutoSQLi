"""入口自动发现：给定题目主页，解析表单与带参链接，产出候选注入目标。

- 表单：method（默认 GET）/ action / input|select|textarea 的 name 与默认值；
- 链接：同域 a[href] 中带查询串的参数；
- 产出 CandidateTarget 列表供引擎逐参数试探。
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser

from .session import HttpSession


@dataclass
class CandidateTarget:
    url: str
    method: str                      # GET / POST
    fields: dict = field(default_factory=dict)   # 参数名 -> 默认值
    source: str = ""                 # 来源描述

    def describe(self) -> str:
        return f"{self.method} {self.url}  参数={list(self.fields)}  ({self.source})"


class _PageParser(HTMLParser):
    """提取 <form> 与 <a href>，容忍 CTF 页面的粗糙 HTML。"""

    def __init__(self):
        super().__init__()
        self.forms: list = []          # [{method, action, fields:{name:val}}]
        self.links: list = []          # [href]
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a":
            href = a.get("href")
            if href:
                self.links.append(href)
        if tag == "form":
            self._form = {
                "method": (a.get("method") or "GET").upper(),
                "action": a.get("action") or "",
                "fields": {},
            }
        elif self._form is not None and tag in ("input", "select", "textarea"):
            name = a.get("name")
            if not name:
                return
            if tag == "input" and (a.get("type") or "text").lower() in (
                    "submit", "button", "reset", "image", "file"):
                # 提交类按钮：记录名字（DVWA 需要 Submit=Submit）
                if a.get("type", "").lower() == "submit" and name:
                    self._form["fields"][name] = a.get("value") or "Submit"
                return
            self._form["fields"][name] = a.get("value") or ""

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag in ("input", "select", "textarea"):
            pass

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


def discover(entry_url: str, session: HttpSession) -> list:
    """抓取入口页并返回候选目标列表（表单优先，其次带参链接）。"""
    s = session.session
    try:
        r = s.get(entry_url, timeout=session.timeout, verify=session.spec.verify_ssl
                  if hasattr(session.spec, "verify_ssl") else False)
    except Exception as e:                                  # noqa: BLE001
        session.log("ERROR", f"入口页抓取失败: {e}")
        return []
    session.log("INFO", f"[发现] 入口页 {entry_url} -> {r.status_code} ({len(r.text)}B)")

    parser = _PageParser()
    try:
        parser.feed(r.text)
    except Exception as e:                                  # noqa: BLE001
        session.log("WARN", f"HTML 解析异常（容忍）: {e}")

    candidates: list = []

    for f in parser.forms:
        action = urllib.parse.urljoin(entry_url, f["action"] or entry_url)
        if not f["fields"]:
            continue
        # 可注入字段：非 submit 的输入；基线默认 1（数字/文本均可探测）
        fields = dict(f["fields"])
        for k in list(fields):
            if not fields[k]:
                fields[k] = "1"
        candidates.append(CandidateTarget(
            url=action, method=f["method"], fields=fields,
            source=f"表单（{len(fields)} 字段）"))

    base_domain = urllib.parse.urlparse(entry_url).netloc
    for href in parser.links:
        if not href or href.startswith(("#", "javascript:", "mailto:", "data:")):
            continue
        absu = urllib.parse.urljoin(entry_url, href)
        p = urllib.parse.urlparse(absu)
        if p.netloc and p.netloc != base_domain:
            continue
        qs = urllib.parse.parse_qsl(p.query)
        if not qs:
            continue
        fields = {k: (v or "1") for k, v in qs}
        candidates.append(CandidateTarget(
            url=urllib.parse.urlunparse(p._replace(query="")),
            method="GET", fields=fields, source="链接参数"))

    # 入口 URL 自身的查询参数也算候选
    p = urllib.parse.urlparse(entry_url)
    if p.query:
        qs = urllib.parse.parse_qsl(p.query)
        candidates.insert(0, CandidateTarget(
            url=urllib.parse.urlunparse(p._replace(query="")), method="GET",
            fields={k: (v or "1") for k, v in qs}, source="入口 URL 参数"))

    for c in candidates:
        session.log("INFO", f"[发现] 候选: {c.describe()}")
    return candidates


def injectable_param_names(cand: CandidateTarget) -> list:
    """候选中值得试探的参数（排除 submit 类）。"""
    return [k for k in cand.fields
            if k.lower() not in ("submit", "login", "button", "token",
                                 "user_token", "csrf")]
