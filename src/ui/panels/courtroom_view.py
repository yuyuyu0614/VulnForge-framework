"""Courtroom view panel — displays VulTrial debate process and jury verdict."""

import json
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QSplitter, QGroupBox, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView,
)
from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtGui import QFont, QColor


class _TrialWorker(QThread):
    """Run VulTrial in a background thread."""
    log = Signal(str)
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, finding: dict, hook: dict | None,
                 code_context: str, model: str, max_rounds: int):
        super().__init__()
        self.finding = finding
        self.hook = hook
        self.code_context = code_context
        self.model = model
        self.max_rounds = max_rounds

    def run(self):
        try:
            from courtroom.trial import VulTrial
            trial = VulTrial(model=self.model, max_rounds=self.max_rounds)

            def on_log(msg):
                self.log.emit(msg)

            trial.on_log = on_log
            result = trial.run_trial(self.finding, self.hook, self.code_context)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(f"{type(e).__name__}: {e}")


class CourtroomPanel(QWidget):
    """VulTrial courtroom panel with debate display and verdict."""

    trial_requested = Signal(dict)  # finding dict

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: _TrialWorker | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # ── Control bar ──────────────────────────────────────────────
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("<b>模拟法庭 (VulTrial)</b>"))
        ctrl.addStretch()
        self._btn_start = QPushButton("开庭审理")
        self._btn_start.setStyleSheet(
            "QPushButton { background-color: #a52; color: white; "
            "font-weight: bold; padding: 4px 12px; }"
            "QPushButton:disabled { background-color: #888; }"
        )
        self._btn_start.clicked.connect(self._request_trial)
        ctrl.addWidget(self._btn_start)
        self._btn_cancel = QPushButton("休庭")
        self._btn_cancel.setEnabled(False)
        ctrl.addWidget(self._btn_cancel)
        layout.addLayout(ctrl)

        # ── Debate display (split view) ──────────────────────────────
        splitter = QSplitter(Qt.Vertical)

        # Upper: prosecutor vs defender side by side
        upper = QSplitter(Qt.Horizontal)

        pros_group = QGroupBox("检察官 (Prosecutor)")
        pros_layout = QVBoxLayout(pros_group)
        self._prosecutor_text = QTextEdit()
        self._prosecutor_text.setReadOnly(True)
        self._prosecutor_text.setFont(QFont("Consolas", 9))
        self._prosecutor_text.setPlaceholderText("检察官的陈词将在此显示...")
        pros_layout.addWidget(self._prosecutor_text)
        upper.addWidget(pros_group)

        def_group = QGroupBox("辩护律师 (Defender)")
        def_layout = QVBoxLayout(def_group)
        self._defender_text = QTextEdit()
        self._defender_text.setReadOnly(True)
        self._defender_text.setFont(QFont("Consolas", 9))
        self._defender_text.setPlaceholderText("辩护律师的陈词将在此显示...")
        def_layout.addWidget(self._defender_text)
        upper.addWidget(def_group)

        upper.setSizes([400, 400])
        splitter.addWidget(upper)

        # Lower: judge + jury
        lower = QSplitter(Qt.Horizontal)

        judge_group = QGroupBox("法官 (Judge)")
        judge_layout = QVBoxLayout(judge_group)
        self._judge_text = QTextEdit()
        self._judge_text.setReadOnly(True)
        self._judge_text.setFont(QFont("Consolas", 9))
        self._judge_text.setPlaceholderText("法官的总结将在此显示...")
        judge_layout.addWidget(self._judge_text)
        lower.addWidget(judge_group)

        jury_group = QGroupBox("陪审团 (Jury Verdict)")
        jury_layout = QVBoxLayout(jury_group)

        self._verdict_label = QLabel("等待开庭...")
        self._verdict_label.setFont(QFont("Arial", 14, QFont.Bold))
        self._verdict_label.setAlignment(Qt.AlignCenter)
        jury_layout.addWidget(self._verdict_label)

        self._jury_text = QTextEdit()
        self._jury_text.setReadOnly(True)
        self._jury_text.setFont(QFont("Consolas", 9))
        self._jury_text.setPlaceholderText("陪审团的裁决和理由将在此显示...")
        jury_layout.addWidget(self._jury_text)

        lower.addWidget(jury_group)

        lower.setSizes([400, 400])
        splitter.addWidget(lower)

        splitter.setSizes([350, 250])
        layout.addWidget(splitter)

        # ── Log area ─────────────────────────────────────────────────
        log_group = QGroupBox("庭审日志")
        log_layout = QVBoxLayout(log_group)
        self._log_text = QTextEdit()
        self._log_text.setReadOnly(True)
        self._log_text.setFont(QFont("Consolas", 8))
        self._log_text.setMaximumHeight(100)
        log_layout.addWidget(self._log_text)
        layout.addWidget(log_group)

    def _request_trial(self):
        self.trial_requested.emit({})
        self._btn_start.setEnabled(False)
        self._btn_cancel.setEnabled(True)

    def start_trial(self, finding: dict, hook: dict | None = None,
                    code_context: str = "", model: str = "llama3.1:8b"):
        """Kick off a trial in a background thread."""
        self._prosecutor_text.clear()
        self._defender_text.clear()
        self._judge_text.clear()
        self._jury_text.clear()
        self._log_text.clear()
        self._verdict_label.setText("审理中...")
        self._verdict_label.setStyleSheet("color: orange;")

        self._worker = _TrialWorker(
            finding, hook, code_context, model, max_rounds=2,
        )
        self._worker.log.connect(self._on_log)
        self._worker.finished.connect(self._on_verdict)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_log(self, msg: str):
        self._log_text.append(msg)

        # Parse and route to appropriate text area
        if "Prosecutor" in msg and "thinking" not in msg:
            pass  # content routed via _on_verdict
        elif "Defender" in msg and "thinking" not in msg:
            pass

    def _on_verdict(self, result: dict):
        verdict = result.get("verdict", "unknown")
        severity = result.get("severity", "?")
        score = result.get("final_score", 0)
        reasoning = result.get("reasoning", "")

        # Verdict display
        verdict_map = {
            "valid": ("有效漏洞 ✓", "darkGreen"),
            "invalid": ("无效漏洞 ✗", "red"),
            "partially_valid": ("部分有效 △", "orange"),
        }
        text, color = verdict_map.get(verdict, (verdict, "gray"))
        self._verdict_label.setText(f"{text}\n严重度: {severity.upper()} | 评分: {score}/100")
        self._verdict_label.setStyleSheet(f"color: {color}; font-weight: bold;")

        self._jury_text.setText(
            f"裁决: {verdict}\n"
            f"严重度: {severity}\n"
            f"评分: {score}/100\n"
            f"置信度: {result.get('confidence', 0):.2f}\n"
            f"CWE: {result.get('cwe_confirmation', 'N/A')}\n\n"
            f"理由:\n{reasoning}\n\n"
            f"建议操作:\n{result.get('recommended_action', 'N/A')}"
        )

        # Judge summary
        judge = result.get("judge_summary", {})
        if judge:
            self._judge_text.setText(json.dumps(judge, ensure_ascii=False, indent=2))

        self._btn_start.setEnabled(True)
        self._btn_cancel.setEnabled(False)

    def _on_error(self, msg: str):
        self._verdict_label.setText(f"错误: {msg}")
        self._verdict_label.setStyleSheet("color: red;")
        self._btn_start.setEnabled(True)
        self._btn_cancel.setEnabled(False)
