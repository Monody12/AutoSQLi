"""GUI 后台工作线程：分析 / 脱库，通过 Qt 信号与主线程通信。"""
from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal

from ..core.engine import Engine
from ..core.models import TargetSpec
from ..core.oracles import OracleError


class AnalysisWorker(QThread):
    log_signal = pyqtSignal(str, str)          # level, message
    done_signal = pyqtSignal(object)           # AnalysisReport
    error_signal = pyqtSignal(str)

    def __init__(self, spec: TargetSpec, scan_waf: bool = True):
        super().__init__()
        self.spec = spec
        self.scan_waf = scan_waf

    def run(self):
        try:
            engine = Engine(self.spec, log=lambda l, m: self.log_signal.emit(l, m))
            report = engine.analyze(scan_waf=self.scan_waf)
            report.engine = engine            # 供后续脱库复用会话
            self.done_signal.emit(report)
        except Exception as e:                 # noqa: BLE001
            self.error_signal.emit(f"分析失败: {e}")


class DumpWorker(QThread):
    log_signal = pyqtSignal(str, str)
    data_signal = pyqtSignal(str, str, str)   # db.table, 列名csv, 行json
    done_signal = pyqtSignal(object)          # DumpResult
    error_signal = pyqtSignal(str)

    def __init__(self, engine: Engine, report, technique_key: str,
                 max_rows: int = 20, dump_all_dbs: bool = False):
        super().__init__()
        self.engine = engine
        self.report = report
        self.key = technique_key
        self.max_rows = max_rows
        self.dump_all_dbs = dump_all_dbs

    def run(self):
        import json
        try:
            self.engine.session.log = lambda l, m: self.log_signal.emit(l, m)
            result = self.engine.solve(self.report, self.key,
                                       max_rows=self.max_rows,
                                       dump_all_dbs=self.dump_all_dbs)
            for (db, table), cols in result.columns.items():
                rows = result.rows.get((db, table), [])
                self.data_signal.emit(f"{db}.{table}", ",".join(cols),
                                      json.dumps(rows, ensure_ascii=False))
            self.done_signal.emit(result)
        except OracleError as e:
            self.error_signal.emit(f"通道不可用: {e}")
        except Exception as e:                 # noqa: BLE001
            self.error_signal.emit(f"脱库失败: {e}")
