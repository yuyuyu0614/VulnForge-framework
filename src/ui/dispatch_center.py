"""VulnForge Dispatch Center — unified audit control panel."""

import time
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QTextEdit, QProgressBar, QGroupBox, QLineEdit,
    QFileDialog, QFrame, QSizePolicy,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont


class DispatchCenter(QWidget):
    """Unified dispatch center — project selection, audit control, real-time events."""

    run_requested = Signal()
    stop_requested = Signal()
    model_changed = Signal(str)

    def __init__(self, main_window=None, parent=None):
        super().__init__(parent)
        self._mw = main_window
        self._running = False
        self._start_time = 0
        self._hook_count = 0
        self._finding_count = 0
        self._event_count = 0

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # — Project —
        proj_group = QGroupBox("📁 项目")
        proj_layout = QVBoxLayout(proj_group)

        path_row = QHBoxLayout()
        self._path_input = QLineEdit()
        self._path_input.setPlaceholderText("选择项目目录 ...")
        self._path_input.setFont(QFont("Consolas", 9))
        path_row.addWidget(self._path_input)

        browse_btn = QPushButton("📂")
        browse_btn.setFixedWidth(36)
        browse_btn.setToolTip("浏览...")
        browse_btn.clicked.connect(self._browse)
        path_row.addWidget(browse_btn)
        proj_layout.addLayout(path_row)

        layout.addWidget(proj_group)

        # — Model —
        model_group = QGroupBox("🤖 模型")
        model_layout = QVBoxLayout(model_group)
        self._model_combo = QComboBox()
        self._model_combo.addItems(["llama3.1:8b", "qwen2.5:7b", "codellama:13b", "deepseek-coder:6.7b"])
        self._model_combo.currentTextChanged.connect(self.model_changed.emit)
        model_layout.addWidget(self._model_combo)
        layout.addWidget(model_group)

        # — Controls —
        ctrl_group = QGroupBox("🎮 控制")
        ctrl_layout = QHBoxLayout(ctrl_group)

        self._run_btn = QPushButton("▶ 开始审计")
        self._run_btn.setStyleSheet("QPushButton { background: #0FBAB2; color: white; font-weight: bold; padding: 8px; }")
        self._run_btn.clicked.connect(self._start)
        ctrl_layout.addWidget(self._run_btn)

        self._stop_btn = QPushButton("⏹ 停止")
        self._stop_btn.setStyleSheet("QPushButton { background: #e74c3c; color: white; font-weight: bold; padding: 8px; }")
        self._stop_btn.clicked.connect(self._stop)
        self._stop_btn.setEnabled(False)
        ctrl_layout.addWidget(self._stop_btn)

        layout.addWidget(ctrl_group)

        # — Progress —
        prog_group = QGroupBox("📊 进度")
        prog_layout = QVBoxLayout(prog_group)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        prog_layout.addWidget(self._progress_bar)

        stats_row = QHBoxLayout()
        self._hook_label = QLabel("Hooks: 0")
        self._finding_label = QLabel("Findings: 0")
        self._time_label = QLabel("耗时: 0s")
        stats_row.addWidget(self._hook_label)
        stats_row.addWidget(self._finding_label)
        stats_row.addWidget(self._time_label)
        prog_layout.addLayout(stats_row)

        layout.addWidget(prog_group)

        # — Token —
        token_group = QGroupBox("💰 Token")
        token_layout = QVBoxLayout(token_group)
        self._token_bar = QProgressBar()
        self._token_bar.setRange(0, 2000000)
        self._token_bar.setValue(0)
        self._token_label = QLabel("0 / 2,000,000")
        token_layout.addWidget(self._token_bar)
        token_layout.addWidget(self._token_label)
        layout.addWidget(token_group)

        # — Event Log —
        log_group = QGroupBox("📋 实时事件")
        log_layout = QVBoxLayout(log_group)
        self._log_view = QTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setFont(QFont("Consolas", 8))
        self._log_view.document().setMaximumBlockCount(500)
        self._log_view.setPlaceholderText("审计事件将实时显示 ...")
        log_layout.addWidget(self._log_view)
        layout.addWidget(log_group)

        # — Quick Actions —
        quick_group = QGroupBox("⚡ 快捷操作")
        quick_layout = QVBoxLayout(quick_group)

        self._quick_scan_btn = QPushButton("🔍 快速扫描 (仅 AST + Semgrep)")
        self._quick_scan_btn.clicked.connect(self._quick_scan)
        quick_layout.addWidget(self._quick_scan_btn)

        self._secrets_btn = QPushButton("🔑 密钥扫描 (truffleHog)")
        self._secrets_btn.clicked.connect(self._secrets_scan)
        quick_layout.addWidget(self._secrets_btn)

        self._courtroom_btn = QPushButton("⚖️ 模拟法庭 (最新finding)")
        self._courtroom_btn.clicked.connect(self._courtroom_trial)
        quick_layout.addWidget(self._courtroom_btn)

        self._report_btn = QPushButton("📄 导出SRC报告")
        self._report_btn.clicked.connect(self._export_report)
        quick_layout.addWidget(self._report_btn)

        layout.addWidget(quick_group)

        # Spacer
        layout.addStretch()

        # Status
        self._status_label = QLabel("🟢 就绪 — 选择项目后点击 开始审计")
        self._status_label.setStyleSheet("color: #888; font-size: 11px; padding: 4px;")
        layout.addWidget(self._status_label)

    # — Slots —

    def _browse(self):
        path = QFileDialog.getExistingDirectory(self, "选择项目目录")
        if path:
            self._path_input.setText(path)
            self.append_log(f"Selected: {path}")

    def _start(self):
        path = self._path_input.text().strip()
        if not path or not Path(path).exists():
            self.append_log(f"Invalid path: {path}")
            self._status_label.setText(f"Invalid path: {path[:60]}")
            return
        self._running = True
        self._start_time = time.time()
        self._hook_count = 0
        self._finding_count = 0
        self._event_count = 0
        self._run_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._status_label.setText("Audit running...")
        self.append_log(f"Starting audit: {path}")
        self.run_requested.emit()

    def _stop(self):
        self._running = False
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._status_label.setText("🔴 已停止")
        if self._mw and self._mw._worker:
            self._mw._worker.cancel()
        self.stop_requested.emit()

    def _quick_scan(self):
        self.append_log("[快捷操作] 触发快速 AST 扫描 ...")
        if self._mw:
            self._mw._run_scan_only()

    def _secrets_scan(self):
        self.append_log("[快捷操作] 触发密钥扫描 ...")
        if self._mw:
            path = self._path_input.text().strip()
            if path:
                from preprocess.secrets_scanner import SecretsScanner
                scanner = SecretsScanner()
                scanner.scan(path)
                self.append_log("  密钥扫描完成")

    def _courtroom_trial(self):
        self.append_log("[快捷操作] 触发模拟法庭 ...")
        if self._mw:
            self._mw._on_trial_requested({})

    def _export_report(self):
        self.append_log("[快捷操作] 导出报告 ...")
        if self._mw and hasattr(self._mw, '_report_panel'):
            self._mw._report_panel.export_markdown()

    # — Event handlers (called from main_window signals) —

    def append_log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self._log_view.append(f"[{ts}] {msg}")
        self._event_count += 1

    def update_progress(self, current: int, total: int):
        if total > 0:
            pct = int(current / total * 100)
            self._progress_bar.setValue(pct)
        elapsed = int(time.time() - self._start_time) if self._start_time else 0
        self._time_label.setText(f"耗时: {elapsed}s")

    def add_hook_event(self, func_name: str, hook_type: str, file_path: str):
        self._hook_count += 1
        self._hook_label.setText(f"Hooks: {self._hook_count}")
        self.append_log(f"🔗 [{hook_type}] {func_name} — {file_path}")

    def add_finding_event(self, title: str, severity: str, cwe: str):
        self._finding_count += 1
        self._finding_label.setText(f"Findings: {self._finding_count}")
        self.append_log(f"🐛 [{severity}] {title} ({cwe})")

    def on_audit_complete(self, total_hooks: int, total_findings: int):
        self._running = False
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        elapsed = int(time.time() - self._start_time) if self._start_time else 0
        self._status_label.setText(f"🟢 完成 — {total_hooks} hooks, {total_findings} findings, {elapsed}s")
        self._progress_bar.setValue(100)
        self.append_log(f"✅ 审计结束: {total_hooks} hooks → {total_findings} findings")

    def on_audit_error(self, msg: str):
        self._running = False
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._status_label.setText(f"🔴 错误: {msg[:80]}")

    def reset(self):
        self._running = False
        self._hook_count = 0
        self._finding_count = 0
        self._start_time = 0
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._progress_bar.setValue(0)
        self._hook_label.setText("Hooks: 0")
        self._finding_label.setText("Findings: 0")
        self._time_label.setText("耗时: 0s")
        self._status_label.setText("🟢 就绪")
