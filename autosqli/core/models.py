"""核心数据模型：目标、响应、注入点、WAF 报告、分析报告。"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# 目标与会话
# ---------------------------------------------------------------------------

@dataclass
class TargetSpec:
    """描述一个待测目标及其访问方式。"""
    url: str
    method: str = "GET"                       # GET / POST
    params: dict = field(default_factory=dict)        # URL 查询参数
    body_params: dict = field(default_factory=dict)   # POST 表单参数
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    param: str = ""                           # 被测参数名
    base_value: str = "1"                     # 被测参数的基线值

    # 登录会话（DVWA 类靶场）
    login_url: str = ""
    login_user_field: str = "username"
    login_pass_field: str = "password"
    login_user: str = ""
    login_pass: str = ""
    security: str = ""                        # DVWA security cookie

    # 两步提交（DVWA high：session-input.php 写 session 再查主页面；二次注入类同理）
    stage_url: str = ""
    stage_param: str = ""                     # 默认同 param
    stage_method: str = "POST"                # stage 写入请求方式

    request_interval: float = 0.0             # 每次请求间隔（秒）
    verify_ssl: bool = False                  # CTF 靶场常为自签证书，默认不校验
    waf_signatures: list = field(default_factory=list)  # 用户自定义拦截页特征（子串或 /正则/）


# ---------------------------------------------------------------------------
# 响应
# ---------------------------------------------------------------------------

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*?\bmysql\b",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"mysql_fetch",
    r"mysqli?_[a-z_]+\(\)",
    r"valid MySQL result",
    r"check the manual that (corresponds to|fits) your",
    r"MariaDB server version",
    r"XPATH syntax error",
    r"Duplicate entry .+? for key",
    r"Data too long for column",
    r"subquery returns more than 1 row",
    r"unknown column",
    r"unknown table",
    r"doesn't exist",
    r"different number of columns",
    r"operand should contain",
    r"truncated incorrect",
    r"mix of collations",
    r"Incorrect .*? value",
]

WAF_BLOCK_PATTERNS = [
    # 通用英文拦截文案
    r"\bwaf\b", r"\bi?d\.waf\b", r"illegal", r"forbidden", r"blocked",
    r"request denied", r"security rule", r"attack detected", r"\bhacked\b",
    r"not acceptable", r"requests appear to be", r"sql injection.*detect",
    r"invalid character", r"malicious", r"sql injection", r"\binjection\b",
    r"not allowed", r"access denied", r"\bhack(?:er|ing)?\b",
    # 中文拦截文案（CTF 常见）
    r"非法", r"拦截", r"攻击", r"防火墙", r"注入", r"危险", r"敏感",
    r"黑名单", r"拉黑", r"不允许", r"违规",
    # 安全产品特征页
    r"安全狗", r"safedog", r"云锁", r"yunsuo", r"云盾", r"宝塔",
    r"雷池", r"safeline", r"长亭",
]

WAF_BLOCK_STATUS = {400, 403, 406, 418, 429, 501}


def sig_match(body_low: str, sig: str) -> bool:
    """用户自定义拦截特征匹配：普通串=不区分大小写子串；/…/=正则。
    body 需传入 lower() 后的文本；sig 亦按小写比较。"""
    if len(sig) >= 3 and sig.startswith("/") and sig.endswith("/"):
        try:
            return re.search(sig[1:-1], body_low, re.I) is not None
        except re.error:
            return False
    return sig.lower() in body_low

# 常见 CTF flag 格式：flag{...} / ctfshow{...} / CTF2{...} / DASCTF{...} 等
FLAG_PATTERN = re.compile(
    r"(?:flag|ctfshow|CTF2|DASCTF|SYC|NSS|BUU|ctf|hgame|moectf|flag_is_here)"
    r"\{[\x21-\x7e]{4,120}\}", re.I)


@dataclass
class ResponseInfo:
    status_code: int
    body: str
    elapsed_ms: float
    url: str = ""
    headers: dict = field(default_factory=dict)
    custom_waf_patterns: list = field(default_factory=list)   # 用户自定义拦截特征

    @property
    def length(self) -> int:
        return len(self.body)

    def has_sql_error(self) -> bool:
        low = self.body.lower()
        return any(re.search(p, low, re.I) for p in SQL_ERROR_PATTERNS)

    def sql_error_text(self) -> str:
        """提取页面中的 SQL 报错文本（<pre> 块优先）。"""
        m = re.search(r"<pre[^>]*>(.*?)</pre>", self.body, re.S | re.I)
        text = m.group(1) if m else self.body
        m = re.search(r"((?:You have an error|XPATH syntax error|Duplicate entry|Incorrect).*?)(?:<|$)",
                      text, re.S | re.I)
        return (m.group(1) if m else text[:200]).strip()

    def has_waf_block(self) -> bool:
        if self.status_code in WAF_BLOCK_STATUS:
            return True
        low = self.body.lower()
        if any(re.search(p, low, re.I) for p in WAF_BLOCK_PATTERNS):
            return True
        return any(sig_match(low, s) for s in self.custom_waf_patterns)

    def contains_all(self, *needles: str) -> bool:
        return all(n in self.body for n in needles)

    def find_flags(self) -> list:
        """提取响应中符合 CTF flag 格式的字符串（万能密码题登录页直出 flag）。"""
        return [m.group(0) for m in FLAG_PATTERN.finditer(self.body)]


def similarity(a: ResponseInfo, b: ResponseInfo) -> float:
    """0~1 页面相似度：内容比对（difflib quick_ratio）+ 状态码惩罚。"""
    import difflib
    ratio = difflib.SequenceMatcher(None, a.body, b.body).quick_ratio()
    return ratio if a.status_code == b.status_code else ratio * 0.7


# ---------------------------------------------------------------------------
# 注入点
# ---------------------------------------------------------------------------

COMMENT_STYLES = ("#", "-- ", "--+#", "/**/", "quote-close", "minus-close")

# 尾部注释方式 → payload 字面量（minus-close：减法盲注用 -' 引号闭合，
# 替代被滤的 #/--，如 xxx'-(cond)-'）
_TAIL_LITERALS = {"quote-close": "", "none": "", "minus-close": "-'"}


@dataclass
class InjectionPoint:
    param: str
    closure: str = ""                # 需要补的前缀闭合：' " ') ") ` 或 ""（数字型）
    comment: str = "#"               # 尾部注释方式
    numeric: bool = False            # 数字型（无需闭合）
    form: str = "classic"            # 实测命中的 payload 形态：classic/paren/inline/tab
    column_count: Optional[int] = None       # union 列数
    echo_positions: list = field(default_factory=list)  # 回显位列序号（从 1 开始）
    bool_markers: dict = field(default_factory=dict)    # {"true": marker, "false": marker}

    def prefix(self, base: str | None = None) -> str:
        """构造 payload 前缀：基线值 + 闭合。"""
        b = self.base_value if base is None else base
        if self.numeric or not self.closure:
            return b
        return b + self.closure

    base_value: str = "1"

    def tail_literal(self) -> str:
        """尾部处理字面量：# / -- 直接用；quote-close/none 无尾部；
        minus-close 用 -'（减法盲注的引号闭合收尾）。"""
        return _TAIL_LITERALS.get(self.comment, self.comment)

    def suffix(self) -> str:
        if self.comment == "quote-close":
            return "' and '1'='1"[-9:]  # 不使用；保留占位
        if self.comment == "/**/":
            return ""
        return self.comment


# ---------------------------------------------------------------------------
# WAF 报告
# ---------------------------------------------------------------------------

# token -> 绕过建议
BYPASS_SUGGESTIONS = {
    "space": "内联注释 /**/ 替代空格；括号法 union(select(1))；Tab/换行符 %09 %0a",    "'": "十六进制 0x... 替代字符串；宽字节 %df'（GBK 环境）；反斜杠转义逃逸",
    '"': "使用单引号或十六进制替代",
    ",": "substr(x from 1 for 1) 免逗号截取；limit 1 offset 1；join 替代多列",
    "=": "like、regexp、between...and、in、> < <> 替代等号",
    "and": "&& 替代；or/|| 替代；异或 ^",
    "or": "|| 替代；&& / and 替代；like((1)like(1))",
    "not": "! 取反；<> 不等",
    "#": "--+ 或 /**/ 或引号闭合",
    "--": "# 或 /**/ 或引号闭合",
    "/*": "引号闭合法收尾",
    ";": "放弃堆叠注入，改用 union/盲注",
    "union": "堆叠注入 prepare/handler；报错注入；MySQL8 table/values row()",
    "select": "堆叠注入 prepare+concat/hex、handler；MySQL8 table；无列名注入",
    "information_schema": "无列名注入（union 重命名法）；sys.x$schema_*；common column 猜测",
    "group_concat": "limit {i},1 逐行读取；concat_ws",
    "concat": "十六进制直接拼接；make_set；lpad/rpad",
    "substr": "mid、left+right、insert() 套娃、trim 剥离、regexp 定位",
    "mid": "substr、left、insert() 套娃",
    "ascii": "ord、hex、binary 比较",
    "ord": "ascii、hex",
    "sleep": "benchmark(count,md5(1))、重计算 rlike、get_lock",
    "if": "case when then else end、sleep(5*(cond))、elt",
    "updatexml": "extractvalue、floor(rand()) 报错、MySQL8 bin_to_uuid",
    "extractvalue": "updatexml、floor 报错、MySQL8 bin_to_uuid",
    "load_file": "堆叠 + prepare；load data infile（需高权限）",
    "outfile": "dumpfile；general_log 写文件（需堆叠+权限）",
    "handler": "prepare 预处理；rename 换表",
    "prepare": "handler；rename + alter",
    "show": "information_schema 查询；sys 库",
    "for": "ascii(mid(x from i)) 取码点（免 for 免逗号截取单字符）",
    "password": "该词含 or 子串易被拦；改用 passwd/pwd 等列名或经 information_schema 查列",
}


@dataclass
class WafItem:
    token: str                 # 被测 token
    category: str              # 分类：关键字/函数/符号
    filtered: Optional[bool]   # True=被过滤 False=可用 None=不确定
    evidence: str = ""         # 判定依据（响应特征摘要）
    suggestion: str = ""       # 绕过建议
    param: str = ""            # 判定所在的参数名（WAF 常按参数分别过滤）

    @property
    def status_text(self) -> str:
        return {True: "已过滤", False: "可用", None: "未知"}[self.filtered]


@dataclass
class WafReport:
    items: list = field(default_factory=list)          # 注入参数上的判定（参与 payload 构造决策）
    param_items: list = field(default_factory=list)    # 其他参数的黑名单快扫（信息展示，不参与构造决策）
    _index: dict = field(default_factory=dict)

    def add(self, item: WafItem):
        self.items.append(item)
        self._index[item.token.lower()] = item

    def add_param_item(self, item: WafItem):
        """其他参数的快扫结果：只入清单，不影响 lookup/is_filtered。

        WAF 常按参数分别过滤（如登录框只查 uname）；uname 上被拦不代表
        注入参数 passwd 里不能用 union，故 payload 决策只看 items。"""
        self.param_items.append(item)

    def lookup(self, token: str) -> Optional[WafItem]:
        return self._index.get(token.lower())

    def is_filtered(self, *tokens: str) -> bool:
        """任一 token 被判定过滤则 True。"""
        return any((i := self.lookup(t)) and i.filtered for t in tokens)

    def available(self, token: str) -> bool:
        """明确可用（未过滤）且 token 在字典中被测过。"""
        it = self.lookup(token)
        return it is not None and it.filtered is False

    def filtered_list(self) -> list:
        return [i for i in self.items + self.param_items if i.filtered]

    @property
    def has_waf(self) -> bool:
        return bool(self.filtered_list())

    def to_dict(self) -> dict:
        return {"has_waf": self.has_waf,
                "items": [{"param": i.param, "token": i.token, "category": i.category,
                           "filtered": i.filtered, "status": i.status_text,
                           "evidence": i.evidence, "suggestion": i.suggestion}
                          for i in self.items],
                "param_scan": [{"param": i.param, "token": i.token, "category": i.category,
                                "filtered": i.filtered, "status": i.status_text,
                                "evidence": i.evidence, "suggestion": i.suggestion}
                               for i in self.param_items]}


# ---------------------------------------------------------------------------
# 注入类型识别与整体报告
# ---------------------------------------------------------------------------

@dataclass
class Fingerprint:
    error_visible: bool = False        # SQL 报错回显
    echo_visible: bool = False         # union 回显位
    boolean_oracle: bool = False       # 布尔差异
    time_oracle: bool = False          # 时间差异
    stacked: bool = False              # 堆叠可用
    widebyte: bool = False             # 宽字节可用
    dbms: str = "MySQL"
    version: str = ""
    current_db: str = ""
    current_user: str = ""

    def to_dict(self) -> dict:
        return {
            "错误回显": self.error_visible, "联合回显": self.echo_visible,
            "布尔盲注": self.boolean_oracle, "时间盲注": self.time_oracle,
            "堆叠注入": self.stacked, "宽字节": self.widebyte,
            "数据库": f"{self.dbms} {self.version}".strip(),
            "当前库": self.current_db, "当前用户": self.current_user,
        }


@dataclass
class TechniqueInfo:
    key: str
    name: str
    category: str          # 有回显 / 无回显 / 特殊
    feasible: bool
    reason: str
    recommended: bool = False


@dataclass
class AnalysisReport:
    target: TargetSpec
    injection: Optional[InjectionPoint] = None
    waf: WafReport = field(default_factory=WafReport)
    fingerprint: Fingerprint = field(default_factory=Fingerprint)
    techniques: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    # 运行时附件（不参与序列化）
    session: object = None
    builder: object = None

    def to_dict(self) -> dict:
        return {
            "url": self.target.url, "param": self.target.param,
            "method": self.target.method,
            "injection": {
                "closure": self.injection.closure if self.injection else None,
                "comment": self.injection.comment if self.injection else None,
                "numeric": self.injection.numeric if self.injection else None,
                "column_count": self.injection.column_count if self.injection else None,
                "echo_positions": self.injection.echo_positions if self.injection else None,
            },
            "waf": self.waf.to_dict(),
            "fingerprint": self.fingerprint.to_dict(),
            "techniques": [t.__dict__ for t in self.techniques],
            "notes": self.notes,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
