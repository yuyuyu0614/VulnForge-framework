"""VulnForge Desktop Workbench — PySide6 GUI with multi-agent audit integration.

Run: D:/python/python.exe -m src.ui.main_window
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QMenuBar, QMenu, QStatusBar,
    QDockWidget, QTextEdit, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget, QLabel, QSplitter, QTabWidget,
    QToolBar, QPushButton, QLineEdit, QProgressBar,
    QMessageBox, QFileDialog, QHBoxLayout, QComboBox, QSizePolicy,
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QAction, QFont

from db import get_db
from agents.scheduler import (
    CollaborationScheduler, get_total_token_count,
    get_budget_percentage, TOKEN_BUDGET, TOKEN_WARNING,
    TokenBudgetExceeded,
)
from ui.dispatch_center import DispatchCenter
from ui.panels import (
    AgentMonitorPanel, HookViewPanel, CourtroomPanel, ReportPreviewPanel,
)


# ── Worker Thread ──────────────────────────────────────────────────

class AuditWorker(QThread):
    log_msg = Signal(str)
    progress = Signal(int, int)
    hook_found = Signal(str, str, str)   # func_name, hook_type, file_path
    finding_found = Signal(str, str, str)  # title, severity, cwe
    audit_finished = Signal(int, int)     # total_hooks, total_findings
    audit_error = Signal(str)

    def __init__(self, project_path: str, model: str, parent=None):
        super().__init__(parent)
        self.project_path = project_path
        self.model = model

    def run(self):
        try:
            db = get_db()
            scheduler = CollaborationScheduler(db=db, model=self.model)

            def on_log(msg):
                self.log_msg.emit(msg)

            def on_progress(cur, tot):
                self.progress.emit(cur, tot)

            def on_hook(h):
                self.hook_found.emit(
                    h.get("function_name", h.get("func_name", "?")),
                    h.get("hook_type", "?"),
                    h.get("file_path", "?"),
                )

            def on_finding(f):
                self.finding_found.emit(
                    f.get("title", "Untitled"),
                    f.get("severity", "?"),
                    f.get("cwe", "N/A"),
                )

            scheduler.on_log = on_log
            scheduler.on_progress = on_progress
            scheduler.on_hook = on_hook
            scheduler.on_finding = on_finding

            findings = scheduler.run_collaborative_audit(self.project_path)

            stats = db.stats()
            self.audit_finished.emit(stats["hooks_total"], stats["findings_total"])

        except TokenBudgetExceeded as e:
            self.audit_error.emit(f"Token budget exceeded:\n{e}")
        except Exception as e:
            self.audit_error.emit(f"Audit failed:\n{type(e).__name__}: {e}")


# ── UI Components ──────────────────────────────────────────────────

class _LogPanel(QTextEdit):
    """Read-only text area for real-time log output."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 9))
        self.setPlaceholderText("Audit log will appear here ...")

    def append_log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.append(f"[{ts}] {msg}")


class _HookTree(QTreeWidget):
    """Tree widget showing hooks found during audit."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Function", "Hook Type", "File"])
        self.setRootIsDecorated(False)
        self.setAlternatingRowColors(True)
        self.setColumnWidth(0, 180)
        self.setColumnWidth(1, 150)

    def add_hook(self, func_name: str, hook_type: str, file_path: str):
        item = QTreeWidgetItem([func_name, hook_type, file_path])
        self.insertTopLevelItem(0, item)


class _FindingsPanel(QTreeWidget):
    """Tree widget showing findings from Auditor agent."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Title", "Severity", "CWE"])
        self.setRootIsDecorated(False)
        self.setAlternatingRowColors(True)
        self.setColumnWidth(0, 300)
        self.setColumnWidth(1, 80)
        self.setColumnWidth(2, 120)

    def add_finding(self, title: str, severity: str, cwe: str):
        item = QTreeWidgetItem([title, severity.upper(), cwe])
        # Color-code severity
        if severity.lower() in ("high", "critical"):
            for col in range(3):
                item.setForeground(col, Qt.red)
        elif severity.lower() == "medium":
            for col in range(3):
                item.setForeground(col, Qt.darkYellow)
        self.insertTopLevelItem(0, item)


class _TokenBar(QWidget):
    """Compact token budget display widget."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)

        self._label = QLabel("Tokens: --")
        layout.addWidget(self._label)

        self._bar = QProgressBar()
        self._bar.setMaximum(100)
        self._bar.setMaximumWidth(150)
        self._bar.setMaximumHeight(16)
        self._bar.setTextVisible(True)
        self._bar.setFormat("%p%")
        layout.addWidget(self._bar)

        self._warning_label = QLabel("")
        self._warning_label.setStyleSheet("color: orange; font-weight: bold;")
        layout.addWidget(self._warning_label)

        layout.addStretch()

    def refresh(self):
        try:
            db = get_db()
            total = get_total_token_count(db)
            pct = get_budget_percentage(db)
            self._label.setText(f"Tokens: {total:,} / {TOKEN_BUDGET:,}")
            self._bar.setValue(int(pct))

            if total >= TOKEN_WARNING:
                self._bar.setStyleSheet(
                    "QProgressBar::chunk { background-color: red; }")
                self._warning_label.setText("BUDGET WARNING")
            elif pct > 50:
                self._bar.setStyleSheet(
                    "QProgressBar::chunk { background-color: orange; }")
                self._warning_label.setText("")
            else:
                self._bar.setStyleSheet("")
                self._warning_label.setText("")
        except Exception:
            pass


# ── Main Window ────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    """VulnForge main window with integrated multi-agent audit."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("VulnForge — Security Audit Workbench")
        self.resize(1400, 900)
        # Set minimum size to prevent collapse
        self.setMinimumSize(1024, 600)
        # Let dock widgets share space properly
        self.setDockOptions(
            QMainWindow.AnimatedDocks | 
            QMainWindow.AllowNestedDocks |
            QMainWindow.AllowTabbedDocks
        )

        self._pending_hooks = 0
        self._pending_findings = 0
        self._worker: AuditWorker | None = None
        self._setup_ui()
        self._connect_actions()
        self._connect_dispatch()

        # Poll DB stats every 2 seconds
        # Event-driven refresh — no more polling (replaced by signal connections)
        self._refresh_stats()  # Initial load only
    def _setup_ui(self):
        # self._build_toolbar()  # Replaced by DispatchCenter
        self._build_menu_bar()
        self._build_central_area()
        self._build_docks()
        self._build_status_bar()

    # ── Toolbar ─────────────────────────────────────────────────

    def _build_toolbar(self):
        pass  # Toolbar removed — all controls in DispatchCenter

    # ── Menu Bar ────────────────────────────────────────────────

    def _build_menu_bar(self):
        mb = self.menuBar()

        file_menu = mb.addMenu("&File")
        act_open = QAction("Open Project...", self)
        act_open.triggered.connect(self._browse_project)
        file_menu.addAction(act_open)
        act_exit = QAction("Exit", self)
        act_exit.triggered.connect(self.close)
        file_menu.addAction(act_exit)

        scan_menu = mb.addMenu("&Scan")
        act_scan = QAction("Scan Directory...", self)
        scan_menu.addAction(act_scan)

        analyze_menu = mb.addMenu("&Analyze")
        act_audit = QAction("Run Collaborative Audit", self)
        act_audit.triggered.connect(self._start_audit)
        analyze_menu.addAction(act_audit)
        act_pipeline = QAction("Run Pipeline", self)
        analyze_menu.addAction(act_pipeline)

        view_menu = mb.addMenu("&View")
        act_clear = QAction("Clear Log", self)
        act_clear.triggered.connect(lambda: self._log_panel.clear())
        view_menu.addAction(act_clear)

        help_menu = mb.addMenu("&Help")
        help_menu.addAction(QAction("About VulnForge", self))

    # ── Central Area ────────────────────────────────────────────


    def _build_central_area(self):
        """Minimal central area — dock panels handle all display."""
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        # Quick status header
        self._central_status = QLabel("<h2 style='color:#0FBAB2;'>VulnForge Security Audit Workbench</h2><p>使用左侧 <b>调度中心</b> 选择项目并开始审计。右侧 <b>工具面板</b> 查看法庭和报告。</p>")
        self._central_status.setAlignment(Qt.AlignCenter)
        self._central_status.setWordWrap(True)
        layout.addWidget(self._central_status)

        # Audit log (compact)
        self._log_panel = _LogPanel()
        layout.addWidget(self._log_panel, stretch=1)

        # Detail + PoC tabs (compact)
        tabs = QTabWidget()
        self._details_text = QTextEdit()
        self._details_text.setReadOnly(True)
        self._details_text.setFont(QFont("Consolas", 10))
        self._details_text.setPlaceholderText("Select a finding to view details ...")
        tabs.addTab(self._details_text, "Details")
        self._poc_text = QTextEdit()
        self._poc_text.setReadOnly(True)
        self._poc_text.setFont(QFont("Consolas", 10))
        self._poc_text.setPlaceholderText("PoC code will appear here ...")
        tabs.addTab(self._poc_text, "PoC")
        layout.addWidget(tabs, stretch=1)

        self.setCentralWidget(central)

    def _build_docks(self):
        # Left dock: Dispatch Center (primary)
        left_dispatch = QDockWidget("调度中心", self)
        left_dispatch.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)
        self._dispatch_center = DispatchCenter(main_window=self)
        left_dispatch.setWidget(self._dispatch_center)
        self.addDockWidget(Qt.LeftDockWidgetArea, left_dispatch)

        # Agent monitor — tab into right dock with courtroom/report
        self._agent_panel = AgentMonitorPanel()

        # Right dock: Tabbed panels (courtroom + report)
        right_dock = QDockWidget("工具面板", self)
        right_dock.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)
        right_tabs = QTabWidget()

        self._courtroom_panel = CourtroomPanel()
        self._courtroom_panel.trial_requested.connect(self._on_trial_requested)
        right_tabs.addTab(self._courtroom_panel, "模拟法庭")

        self._report_panel = ReportPreviewPanel()
        right_tabs.addTab(self._report_panel, "报告预览")

        right_dock.setWidget(right_tabs)
        self.addDockWidget(Qt.RightDockWidgetArea, right_dock)

        # Bottom dock: Hook view (full-width table)
        bottom_dock = QDockWidget("钩子与任务", self)
        bottom_dock.setAllowedAreas(Qt.BottomDockWidgetArea | Qt.TopDockWidgetArea)
        self._hook_view = HookViewPanel()
        self._hook_view.hook_selected.connect(self._on_hook_selected)
        self._hook_view.verdict_changed.connect(self._on_verdict_changed)
        bottom_dock.setWidget(self._hook_view)
        self.addDockWidget(Qt.BottomDockWidgetArea, bottom_dock)

    # ── Status Bar ──────────────────────────────────────────────

    def _build_status_bar(self):
        sb = self.statusBar()

        self._status_label = QLabel("Ready")
        sb.addWidget(self._status_label)

        sb.addPermanentWidget(QLabel("  "))

        self._token_bar = _TokenBar()
        sb.addPermanentWidget(self._token_bar)

    # ── Actions ─────────────────────────────────────────────────

    def _connect_actions(self):
        # Toolbar removed — controls via DispatchCenter
        pass

    def _connect_dispatch(self):
        """Connect DispatchCenter signals to main window."""
        dc = self._dispatch_center
        dc.run_requested.connect(self._start_audit)
        dc.stop_requested.connect(self._cancel_audit)
        dc.model_changed.connect(self._on_dispatch_model_changed)


    def _browse_project(self):
        path = QFileDialog.getExistingDirectory(self, "Select Project Directory")
        if path:
            self._dispatch_center._path_input.setText(path)

    
    def _start_audit(self):
        project_path = self._dispatch_center._path_input.text().strip()
        if not project_path or not Path(project_path).exists():
            QMessageBox.warning(self, "Error", f"Project path not found: {project_path}")
            return

        self._log(f"Starting audit: {project_path}")
        self._status_label.setText("Auditing...")

        from feature_extractor import extract_directory
        from false_positive_filter import filter_false_positives, estimate_confidence
        from cwe_classifier import batch_classify

        results = extract_directory(project_path)
        total_hooks = 0
        total_findings = 0

        for r in results:
            total_hooks += len(r.hooks)
            try:
                with open(r.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_content = f.read()
            except Exception:
                file_content = ""
            filtered = filter_false_positives(r.hooks, file_content, r.language)
            findings = batch_classify(filtered, r.language)
            for h in findings:
                total_findings += 1
                fname = r.file_path.split(chr(92))[-1]
                self._log(f"[{h.get('cwe_id', '?')}] {h.get('cwe_title', '?')} in {h.get('func_name', '?')}() > {fname}")
                if hasattr(self, '_dispatch_center'):
                    self._dispatch_center.add_finding_event(
                        f"{h.get('cwe_id', '?')}: {h.get('cwe_title', '?')}",
                        h.get('severity', 'info'),
                        h.get('cwe_id', '?'))

        self._log(f"[DONE] {total_hooks} hooks > {total_findings} findings")
        self._status_label.setText(f"Done: {total_findings} findings")
        if hasattr(self, '_dispatch_center'):
            self._dispatch_center.on_audit_complete(total_hooks, total_findings)
        self._refresh_panels()

    def _cancel_audit(self):
        if self._worker and self._worker.isRunning():
            self._log("Cancelling audit ...")
            # The scheduler checks self._cancelled; we need to access it
            self._worker.terminate()
            self._worker.wait(3000)
        self._reset_ui_state()

    def _reset_ui_state(self):
        if hasattr(self, "_dispatch_center"):
            self._dispatch_center.reset()
        # UI reset handled by dispatch center
        pass

    # ── Signal Handlers (thread-safe) ───────────────────────────

    def _on_log(self, msg: str):
        self._log_panel.append_log(msg)

    def _on_progress(self, cur: int, tot: int):
        pass  # progress widget removed
        pass  # progress widget removed
        pass  # progress widget removed
        pass  # progress widget removed

    def _on_hook(self, func_name: str, hook_type: str, file_path: str):
        self._pending_hooks += 1
        # Update dispatch center stats
        if hasattr(self, "_dispatch_center"):
            self._dispatch_center.add_hook_event(func_name, hook_type, file_path)

    def _on_finding(self, title: str, severity: str, cwe: str):
        self._pending_findings += 1
        if hasattr(self, "_dispatch_center"):
            self._dispatch_center.add_finding_event(title, severity, cwe)

    def _on_finished(self, total_hooks: int, total_findings: int):
        self._log(f"[DONE] Audit complete: {total_hooks} hooks, "
                  f"{total_findings} findings")
        pass  # progress removed
        self._status_label.setText(f"Audit complete — {total_findings} findings")
        # UI reset handled by dispatch center
        self._token_bar.refresh()
        self._agent_panel.clear_all()
        self._refresh_panels()

    def _on_error(self, msg: str):
        self._log(f"[ERROR] {msg}")
        QMessageBox.critical(self, "Audit Error", msg)
        self._reset_ui_state()

    # ── Polling ─────────────────────────────────────────────────

    # 岸岸 Config & Dispatch Center 岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸岸

    def _load_config(self) -> dict:
        import json
        config_path = Path(__file__).resolve().parent.parent.parent / "wa_config.json"
        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _init_dispatch_center(self):
        """Create the unified dispatch center dock widget."""
        self._dispatch_center = DispatchCenter(self)
        dock = QDockWidget("🎯 调度中心", self)
        dock.setWidget(self._dispatch_center)
        dock.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea | Qt.BottomDockWidgetArea)
        dock.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable)
        self.addDockWidget(Qt.RightDockWidgetArea, dock)

        # Connect dispatch actions
        self._dispatch_center.run_requested.connect(self._on_dispatch_run)
        self._dispatch_center.stop_requested.connect(self._on_dispatch_stop)
        self._dispatch_center.model_changed.connect(self._on_dispatch_model_changed)

    def _on_dispatch_run(self):
        """Handle run button from dispatch center."""
        if self._worker and self._worker.isRunning():
            return
        self._start_audit()

    def _on_dispatch_stop(self):
        """Handle stop button from dispatch center."""
        self._cancel_audit()

    def _on_dispatch_model_changed(self, model: str):
        """Handle model selection from dispatch center."""
        pass  # Model is managed entirely within dispatch center

    def _refresh_stats(self, _event: str = ""):
        """Event-driven refresh of UI panels from database."""
        try:
            db = get_db()
            s = db.stats()

            # Update agent monitor budget
            from agents.scheduler import get_total_token_count, get_budget_percentage
            total_tokens = get_total_token_count(db)
            self._agent_panel.update_budget(total_tokens)

            # Update hook view with latest data
            hooks = db.list_hooks()
            findings = db.list_findings()
            self._hook_view.load_data(hooks, findings)

            # Update report panel
            self._report_panel.load_findings(findings, hooks)

            self._token_bar.refresh()
        except Exception:
            pass

    def _refresh_panels(self):
        """One-shot panel refresh (called after audit completes)."""
        try:
            db = get_db()
            hooks = db.list_hooks()
            findings = db.list_findings()

            self._hook_view.load_data(hooks, findings)
            self._report_panel.load_findings(findings, hooks)
        except Exception:
            pass

    # ── Panel Signal Handlers ────────────────────────────────────

    def _on_trial_requested(self, _data: dict):
        """Courtroom panel requested a trial — auto-select first finding if needed."""
        finding = None
        hook = None
        
        # Try report panel selection first
        if hasattr(self._report_panel, '_current_finding') and self._report_panel._current_finding:
            finding = self._report_panel._current_finding
            hook = getattr(self._report_panel, '_current_hook', None)
        
        # Fallback: auto-select first finding from DB
        if not finding:
            try:
                db = get_db()
                findings = db.list_findings()
                if findings:
                    finding = findings[0]
                    self._log(f"Auto-selected first finding: {finding.get('title', '?')}")
                else:
                    QMessageBox.information(self, "No Findings", "请先运行一次审计（▶ 开始审计）\n审计完成后会自动生成 findings。")
                    return
            except Exception as e:
                QMessageBox.information(self, "提示", f"无法获取 findings: {e}\n请先运行审计。")
                return
        
        code_context = ""
        if hook:
            code_context = hook.get("snippet", "")
        elif finding:
            code_context = finding.get("poc", finding.get("snippet", ""))

        model = self._dispatch_center._model_combo.currentText().strip()
        self._log(f"Starting courtroom trial for: {finding.get('title', '?')}")
        self._courtroom_panel.start_trial(finding, hook, code_context, model)

    def _on_hook_selected(self, hook_id: str):
        """Show hook details when selected in hook view."""
        db = get_db()
        hooks = db.list_hooks()
        hook = next((h for h in hooks if h.get("hook_id") == hook_id), None)
        if not hook:
            return

        details = (
            f"Hook ID: {hook_id}\n"
            f"Function: {hook.get('func_name', '?')}\n"
            f"Type: {hook.get('hook_type', '?')}\n"
            f"Severity: {hook.get('severity', '?')}\n"
            f"Status: {hook.get('status', '?')}\n"
            f"Language: {hook.get('language', '?')}\n"
            f"File: {hook.get('file_path', '?')}\n"
            f"Lines: {hook.get('line_start', 0)}-{hook.get('line_end', 0)}\n\n"
            f"Code Snippet:\n{hook.get('snippet', '(none)')}"
        )
        self._details_text.setText(details)

        # Show associated findings
        findings = db.list_findings()
        related = [f for f in findings if f.get("hook_id") == hook_id]
        if related:
            poc_text = "\n\n---\n\n".join(
                f"Finding: {f.get('title', '?')}\n"
                f"Severity: {f.get('severity', '?')} | CWE: {f.get('cwe_id', 'N/A')}\n"
                f"PoC:\n{f.get('poc_code', '(none)')}"
                for f in related
            )
            self._poc_text.setText(poc_text)

    def _on_verdict_changed(self, hook_id: str, new_status: str):
        self._log(f"Hook {hook_id} → {new_status}")
        self._refresh_panels()

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        if hasattr(self, '_log_panel'):
            self._log_panel.append_log(msg)


# ── Entry Point ────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("VulnForge")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
    # — Central Area —

    def _build_central_area(self):
        """Minimal central area — dock panels handle all display."""
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        # Quick status header
        self._central_status = QLabel(
            "<h2 style='color:#0FBAB2;'>VulnForge Security Audit Workbench</h2>"
            "<p>使用左侧 <b>调度中心</b> 选择项目并开始审计。"
            "右侧 <b>工具面板</b> 查看法庭和报告。</p>"
        )
        self._central_status.setAlignment(Qt.AlignCenter)
        self._central_status.setWordWrap(True)
        layout.addWidget(self._central_status)

        # Audit log (compact)
        self._log_panel = _LogPanel()
        layout.addWidget(self._log_panel, stretch=1)

        # Detail + PoC tabs (compact)
        tabs = QTabWidget()
        self._details_text = QTextEdit()
        self._details_text.setReadOnly(True)
        self._details_text.setFont(QFont("Consolas", 10))
        self._details_text.setPlaceholderText("Select a finding to view details ...")
        tabs.addTab(self._details_text, "Details")
        self._poc_text = QTextEdit()
        self._poc_text.setReadOnly(True)
        self._poc_text.setFont(QFont("Consolas", 10))
        self._poc_text.setPlaceholderText("PoC code will appear here ...")
        tabs.addTab(self._poc_text, "PoC")
        layout.addWidget(tabs, stretch=1)

        self.setCentralWidget(central)

    def _build_docks(self):
        # Left dock: Dispatch Center (primary)
        left_dispatch = QDockWidget("调度中心", self)
        left_dispatch.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)
        self._dispatch_center = DispatchCenter(main_window=self)
        left_dispatch.setWidget(self._dispatch_center)
        self.addDockWidget(Qt.LeftDockWidgetArea, left_dispatch)

        # Agent monitor — tab into right dock with courtroom/report
        self._agent_panel = AgentMonitorPanel()
        right_tabs.addTab(self._agent_panel, "Agent 监控")

        # Right dock: Tabbed panels (courtroom + report)
        right_dock = QDockWidget("工具面板", self)
        right_dock.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)
        right_tabs = QTabWidget()

        self._courtroom_panel = CourtroomPanel()
        self._courtroom_panel.trial_requested.connect(self._on_trial_requested)
        right_tabs.addTab(self._courtroom_panel, "模拟法庭")

        self._report_panel = ReportPreviewPanel()
        right_tabs.addTab(self._report_panel, "报告预览")

        right_dock.setWidget(right_tabs)
        self.addDockWidget(Qt.RightDockWidgetArea, right_dock)

        # Bottom dock: Hook view (full-width table)
        bottom_dock = QDockWidget("钩子与任务", self)
        bottom_dock.setAllowedAreas(Qt.BottomDockWidgetArea | Qt.TopDockWidgetArea)
        self._hook_view = HookViewPanel()
        self._hook_view.hook_selected.connect(self._on_hook_selected)
        self._hook_view.verdict_changed.connect(self._on_verdict_changed)
        bottom_dock.setWidget(self._hook_view)
        self.addDockWidget(Qt.BottomDockWidgetArea, bottom_dock)


