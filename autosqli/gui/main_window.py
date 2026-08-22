"""AutoSQLi PyQt6 主界面。

四页签：目标配置 / 分析报告 / 数据浏览 / 日志。
分析流程：目标 → 注入点 → WAF 清单 → 指纹 → 方法推荐 → 一键脱库。
"""
from __future__ import annotations

import json
import urllib.parse

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QCheckBox, QComboBox, QFormLayout, QGroupBox,
                             QHBoxLayout, QLabel, QLineEdit, QMainWindow,
                             QMenu, QMessageBox, QPlainTextEdit, QPushButton,
                             QSpinBox, QSplitter, QTabWidget, QTableWidget,
                             QTableWidgetItem, QTextEdit, QTreeWidget,
                             QTreeWidgetItem, QVBoxLayout, QWidget, QFileDialog)

from ..core.models import TargetSpec
from .workers import AnalysisWorker, DumpWorker


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AutoSQLi — CTF SQL 注入自动化分析（WAF 感知）")
        self.resize(1200, 800)
        self.report = None
        self.engine = None
        self.worker = None
        self.dump_result = None
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self._build_target_tab()
        self._build_analysis_tab()
        self._build_data_tab()
        self._build_log_tab()
        self.log("INFO", "AutoSQLi 就绪。请先在「目标」页配置并开始分析。"
                        "仅可用于授权的 CTF/靶场环境。")

    # ================================================================== 目标页
    def _build_target_tab(self):
        page = QWidget()
        root = QVBoxLayout(page)

        left = QVBoxLayout()
        g_target = QGroupBox("目标")
        f1 = QFormLayout(g_target)
        self.url_edit = QLineEdit("http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit")
        self.method_box = QComboBox()
        self.method_box.addItems(["GET", "POST"])
        self.param_edit = QLineEdit("id")
        self.param_edit.setPlaceholderText("留空自动选择第一个参数")
        self.base_value_edit = QLineEdit("1")
        f1.addRow("目标 URL", self.url_edit)
        f1.addRow("请求方式", self.method_box)
        f1.addRow("被测参数", self.param_edit)
        f1.addRow("基线值", self.base_value_edit)
        left.addWidget(g_target)

        g_login = QGroupBox("登录会话（DVWA 类靶场）")
        f2 = QFormLayout(g_login)
        self.dvwa_check = QCheckBox("启用自动登录")
        self.dvwa_user = QLineEdit("admin")
        self.dvwa_pass = QLineEdit("password")
        self.dvwa_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.dvwa_sec = QComboBox()
        self.dvwa_sec.addItems(["low", "medium", "high", "impossible"])
        f2.addRow("", self.dvwa_check)
        f2.addRow("用户名", self.dvwa_user)
        f2.addRow("密码", self.dvwa_pass)
        f2.addRow("安全等级", self.dvwa_sec)
        left.addWidget(g_login)

        g_adv = QGroupBox("高级")
        f3 = QFormLayout(g_adv)
        self.stage_edit = QLineEdit("")
        self.stage_edit.setPlaceholderText("两步提交入口（二次注入/DVWA high 自动配置）")
        self.cookie_edit = QLineEdit("")
        self.cookie_edit.setPlaceholderText("k=v; k2=v2（可选）")
        self.waf_check = QCheckBox("启用 WAF 字典扫描（约 70+ 请求）")
        self.waf_check.setChecked(True)
        f3.addRow("Stage 入口", self.stage_edit)
        f3.addRow("Cookie", self.cookie_edit)
        f3.addRow("", self.waf_check)
        left.addWidget(g_adv)
        left.addStretch(1)

        right = QVBoxLayout()
        self.help_text = QTextEdit()
        self.help_text.setReadOnly(True)
        self.help_text.setHtml(
            "<h3>使用流程</h3>"
            "<ol>"
            "<li>填写目标 URL 与被测参数（如 DVWA 的 <code>id</code>）</li>"
            "<li>需要登录的靶场勾选自动登录</li>"
            "<li>点击「开始分析」：注入点 → WAF 过滤清单 → 注入类型指纹</li>"
            "<li>在「分析」页选择解题方法（★ 为自动推荐），点击「开始脱库」</li>"
            "<li>在「数据」页浏览 库→表→列→数据，可导出 JSON/Markdown</li>"
            "</ol>"
            "<h3>通道优先级</h3>"
            "<p>union（回显，最快）＞ error（报错）＞ bool_blind（布尔盲注）＞ "
            "time_blind（时间盲注，最慢）。WAF 过滤项会自动跳过不可行构造。</p>"
            "<p style='color:#c62828'>⚠ 仅用于授权 CTF 竞赛与自有靶场。</p>")
        right.addWidget(self.help_text)

        bottom = QHBoxLayout()
        self.analyze_btn = QPushButton("开始分析")
        self.analyze_btn.setMinimumHeight(42)
        self.analyze_btn.setStyleSheet("font-weight:bold;")
        self.analyze_btn.clicked.connect(self.start_analysis)
        self.stop_btn = QPushButton("中止")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_work)
        bottom.addWidget(self.analyze_btn)
        bottom.addWidget(self.stop_btn)

        split = QSplitter(Qt.Orientation.Horizontal)
        w1, w2 = QWidget(), QWidget()
        w1.setLayout(left)
        w2.setLayout(right)
        split.addWidget(w1)
        split.addWidget(w2)
        split.setSizes([480, 400])

        root.addWidget(split)
        root.addLayout(bottom)
        self.tabs.addTab(page, "目标")

    # ================================================================== 分析页
    def _build_analysis_tab(self):
        page = QWidget()
        root = QVBoxLayout(page)

        self.inj_label = QLabel("尚未分析")
        self.inj_label.setStyleSheet("font-weight:bold; padding:4px;")
        root.addWidget(self.inj_label)

        self.fp_label = QLabel("")
        self.fp_label.setWordWrap(True)
        root.addWidget(self.fp_label)

        split = QSplitter(Qt.Orientation.Horizontal)

        waf_box = QGroupBox("WAF 过滤清单（全部字典项）")
        v1 = QVBoxLayout(waf_box)
        self.waf_table = QTableWidget(0, 5)
        self.waf_table.setHorizontalHeaderLabels(["Token", "分类", "状态", "判定依据", "绕过建议"])
        self.waf_table.horizontalHeader().setStretchLastSection(True)
        v1.addWidget(self.waf_table)

        tech_box = QGroupBox("解题方法（★ 推荐 / ✗ 不可行）")
        v2 = QVBoxLayout(tech_box)
        self.tech_list = QTableWidget(0, 4)
        self.tech_list.setHorizontalHeaderLabels(["方法", "类别", "可行性", "原因"])
        self.tech_list.setColumnWidth(0, 180)
        self.tech_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tech_list.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        v2.addWidget(self.tech_list)

        run_row = QHBoxLayout()
        self.dump_btn = QPushButton("开始脱库（当前选中方法）")
        self.dump_btn.setEnabled(False)
        self.dump_btn.setMinimumHeight(38)
        self.dump_btn.clicked.connect(self.start_dump)
        self.max_rows_spin = QSpinBox()
        self.max_rows_spin.setRange(1, 500)
        self.max_rows_spin.setValue(20)
        self.dump_all_check = QCheckBox("脱全部数据库")
        run_row.addWidget(self.dump_btn)
        run_row.addWidget(QLabel("每表最大行数"))
        run_row.addWidget(self.max_rows_spin)
        run_row.addWidget(self.dump_all_check)
        run_row.addStretch(1)
        v2.addLayout(run_row)

        split.addWidget(waf_box)
        split.addWidget(tech_box)
        split.setSizes([600, 560])
        root.addWidget(split, stretch=1)
        self.tabs.addTab(page, "分析")

    # ================================================================== 数据页
    def _build_data_tab(self):
        page = QWidget()
        root = QHBoxLayout(page)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.db_tree = QTreeWidget()
        self.db_tree.setHeaderLabel("数据库 → 表 → 列")
        self.db_tree.itemClicked.connect(self.on_tree_click)
        self.db_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.db_tree.customContextMenuRequested.connect(self.tree_menu)
        split.addWidget(self.db_tree)

        right = QWidget()
        v = QVBoxLayout(right)
        self.data_table = QTableWidget(0, 0)
        self.data_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        v.addWidget(self.data_table)
        export_row = QHBoxLayout()
        btn_json = QPushButton("导出 JSON")
        btn_md = QPushButton("导出 Markdown")
        btn_json.clicked.connect(lambda: self.export_dump("json"))
        btn_md.clicked.connect(lambda: self.export_dump("md"))
        export_row.addWidget(btn_json)
        export_row.addWidget(btn_md)
        export_row.addStretch(1)
        v.addLayout(export_row)
        split.addWidget(right)
        split.setSizes([380, 800])
        root.addWidget(split)
        self.tabs.addTab(page, "数据")

    # ================================================================== 日志页
    def _build_log_tab(self):
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(20000)
        self.tabs.addTab(self.log_view, "日志")

    # ================================================================== 逻辑
    def log(self, level: str, msg: str):
        self.log_view.appendPlainText(f"[{level}] {msg}")

    def stop_work(self):
        if self.engine:
            self.engine.session.stop()
            self.log("WARN", "已发出中止信号（当前请求完成后停止）")

    def _collect_spec(self) -> TargetSpec:
        url = self.url_edit.text().strip()
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        base = urllib.parse.urlunparse(parsed._replace(query=""))
        spec = TargetSpec(url=base, method=self.method_box.currentText(),
                          params=params, base_value=self.base_value_edit.text() or "1")
        param = self.param_edit.text().strip()
        if param:
            spec.param = param
        else:
            for k in params:
                if k.lower() not in ("submit",):
                    spec.param = k
                    break
        if self.cookie_edit.text().strip():
            for kv in self.cookie_edit.text().split(";"):
                if "=" in kv:
                    k, _, v = kv.partition("=")
                    spec.cookies[k.strip()] = v.strip()
        if self.dvwa_check.isChecked():
            spec.login_url = urllib.parse.urlunparse(parsed._replace(path="/login.php", query=""))
            spec.login_user = self.dvwa_user.text()
            spec.login_pass = self.dvwa_pass.text()
            spec.security = self.dvwa_sec.currentText()
            if spec.security == "high":
                spec.stage_url = urllib.parse.urlunparse(
                    parsed._replace(path="/vulnerabilities/sqli/session-input.php", query=""))
                spec.stage_method = "POST"
                spec.params.pop(spec.param, None)
        if self.stage_edit.text().strip():
            spec.stage_url = self.stage_edit.text().strip()
            spec.params.pop(spec.param, None)
        return spec

    def start_analysis(self):
        self.analyze_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.tabs.setCurrentIndex(3)
        self.log("INFO", f"开始分析: {self.url_edit.text()}")
        self.worker = AnalysisWorker(self._collect_spec(), scan_waf=self.waf_check.isChecked())
        self.worker.log_signal.connect(lambda l, m: self.log(l, m))
        self.worker.done_signal.connect(self.on_analysis_done)
        self.worker.error_signal.connect(self.on_work_error)
        self.engine = None            # 待 worker 传回
        self.worker.finished.connect(lambda: (self.analyze_btn.setEnabled(True),
                                              self.stop_btn.setEnabled(False)))
        self.worker.start()

    def on_analysis_done(self, report):
        self.report = report
        self.engine = getattr(report, "engine", None)
        inj = report.injection
        if inj is None:
            self.inj_label.setText("⚠ 未发现注入点")
            self.fp_label.setText("；".join(report.notes))
        else:
            self.inj_label.setText(
                f"注入点: 参数 {inj.param} | 闭合 {inj.closure!r} | 注释 {inj.comment!r} | "
                f"列数 {inj.column_count} | 回显位 {inj.echo_positions}"
                f"{'（数字型）' if inj.numeric else ''}")
            self.fp_label.setText(
                f"指纹: {report.fingerprint.dbms} {report.fingerprint.version} | "
                f"当前库 {report.fingerprint.current_db or '?'} | "
                f"当前用户 {report.fingerprint.current_user or '?'}")
        # WAF 表
        items = report.waf.items
        self.waf_table.setRowCount(len(items))
        for i, it in enumerate(items):
            color = {"已过滤": "#c62828", "可用": "#2e7d32", "未知": "#9e9e9e"}[it.status_text]
            for j, val in enumerate([it.token, it.category, it.status_text,
                                     it.evidence, it.suggestion or "—"]):
                cell = QTableWidgetItem(str(val))
                if j == 2:
                    from PyQt6.QtGui import QColor
                    cell.setForeground(QColor(color))
                self.waf_table.setItem(i, j, cell)
        self.waf_table.resizeColumnsToContents()
        # 方法表
        self.tech_list.setRowCount(len(report.techniques))
        for i, t in enumerate(report.techniques):
            mark = "★ " if t.recommended else ("✓ " if t.feasible else "✗ ")
            self.tech_list.setItem(i, 0, QTableWidgetItem(mark + t.name))
            self.tech_list.setItem(i, 1, QTableWidgetItem(t.category))
            self.tech_list.setItem(i, 2, QTableWidgetItem("可行" if t.feasible else "不可行"))
            self.tech_list.setItem(i, 3, QTableWidgetItem(t.reason))
        self.tech_list.resizeColumnsToContents()
        self.dump_btn.setEnabled(inj is not None)
        self.tabs.setCurrentIndex(1)
        self.log("INFO", "分析完成，切换到「分析」页查看 WAF 清单与方法推荐")

    def on_work_error(self, msg: str):
        self.log("ERROR", msg)
        QMessageBox.warning(self, "AutoSQLi", msg)

    def start_dump(self):
        rows = self.tech_list.selectionModel().selectedRows()
        key = None
        if rows:
            key = self.report.techniques[rows[0].row()].key
        else:
            for t in self.report.techniques:
                if t.feasible and t.recommended:
                    key = t.key
                    break
        if not key:
            QMessageBox.information(self, "AutoSQLi", "请先在方法表中选择一个可行的方法")
            return
        if not self.engine:
            QMessageBox.warning(self, "AutoSQLi", "缺少引擎会话，请重新分析")
            return
        self.dump_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.tabs.setCurrentIndex(3)
        self.log("INFO", f"开始脱库，通道: {key}")
        self.worker = DumpWorker(self.engine, self.report, key,
                                 max_rows=self.max_rows_spin.value(),
                                 dump_all_dbs=self.dump_all_check.isChecked())
        self.worker.log_signal.connect(lambda l, m: self.log(l, m))
        self.worker.data_signal.connect(self.on_dump_data)
        self.worker.done_signal.connect(self.on_dump_done)
        self.worker.error_signal.connect(self.on_work_error)
        self.worker.finished.connect(lambda: (self.dump_btn.setEnabled(True),
                                              self.stop_btn.setEnabled(False)))
        self.worker.start()

    # ------------------------------------------------------------------ 数据页
    def on_dump_data(self, table_id: str, cols_csv: str, rows_json: str):
        cols = cols_csv.split(",") if cols_csv else []
        rows = json.loads(rows_json)
        parts = table_id.split(".")
        db, table = (parts + ["?"])[:2]
        db_root = None
        for i in range(self.db_tree.topLevelItemCount()):
            if self.db_tree.topLevelItem(i).text(0) == db:
                db_root = self.db_tree.topLevelItem(i)
                break
        if db_root is None:
            db_root = QTreeWidgetItem([db])
            self.db_tree.addTopLevelItem(db_root)
        t_item = None
        for i in range(db_root.childCount()):
            if db_root.child(i).text(0) == table:
                t_item = db_root.child(i)
                break
        if t_item is None:
            t_item = QTreeWidgetItem([table])
            db_root.addChild(t_item)
        for c in cols:
            col_item = QTreeWidgetItem([f"列: {c}"])
            col_item.setData(0, Qt.ItemDataRole.UserRole, (table_id, cols, rows))
            t_item.addChild(col_item)
        t_item.setData(0, Qt.ItemDataRole.UserRole, (table_id, cols, rows))
        self.db_tree.expandItem(db_root)
        self.db_tree.expandItem(t_item)

    def on_tree_click(self, item: QTreeWidgetItem, _col: int):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return
        table_id, cols, rows = data
        self.data_table.setRowCount(len(rows))
        self.data_table.setColumnCount(len(cols))
        self.data_table.setHorizontalHeaderLabels(cols)
        for i, row in enumerate(rows):
            for j, c in enumerate(cols):
                self.data_table.setItem(i, j, QTableWidgetItem(str(row.get(c, ""))))
        self.tabs.setCurrentIndex(2)

    def on_dump_done(self, result):
        self.dump_result = result
        n_rows = sum(len(v) for v in result.rows.values())
        self.log("INFO", f"脱库完成: {len(result.tables)} 库, "
                         f"{sum(len(t) for t in result.tables.values())} 表, {n_rows} 行数据")
        self.tabs.setCurrentIndex(2)

    def tree_menu(self, pos):
        item = self.db_tree.itemAt(pos)
        if not item:
            return
        menu = QMenu(self)
        act = menu.addAction("导出该表数据 (JSON)")
        chosen = menu.exec(self.db_tree.viewport().mapToGlobal(pos))
        if chosen == act:
            data = item.data(0, Qt.ItemDataRole.UserRole)
            if data:
                table_id, cols, rows = data
                path, _ = QFileDialog.getSaveFileName(self, "导出", f"{table_id}.json", "JSON (*.json)")
                if path:
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump({"columns": cols, "rows": rows}, f, ensure_ascii=False, indent=2)

    def export_dump(self, fmt: str):
        if not self.dump_result:
            QMessageBox.information(self, "AutoSQLi", "尚无脱库结果")
            return
        d = self.dump_result.to_dict()
        if fmt == "json":
            path, _ = QFileDialog.getSaveFileName(self, "导出", "dump.json", "JSON (*.json)")
            if not path:
                return
            with open(path, "w", encoding="utf-8") as f:
                json.dump(d, f, ensure_ascii=False, indent=2)
        else:
            path, _ = QFileDialog.getSaveFileName(self, "导出", "dump.md", "Markdown (*.md)")
            if not path:
                return
            lines = [f"# AutoSQLi 脱库报告", "",
                     f"- 版本: {d['version']}", f"- 当前库: {d['database']}",
                     f"- 用户: {d['user']}", "", f"## 数据库: {d['databases']}", ""]
            for tid, rows in d["rows"].items():
                lines += [f"### {tid}", ""]
                if rows:
                    cols = list(rows[0].keys())
                    lines.append("| " + " | ".join(cols) + " |")
                    lines.append("|" + "---|" * len(cols))
                    for r in rows:
                        lines.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
                lines.append("")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        self.log("INFO", f"已导出: {path}")


def run_app():
    from PyQt6.QtWidgets import QApplication
    import sys
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
