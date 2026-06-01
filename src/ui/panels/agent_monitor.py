"""Agent monitoring panel — real-time status, token usage, context window display."""

import time
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QColor

AGENT_DEFINITIONS = [
    {"id": "architect", "name": "Architect (代码结构分析师)", "role": "cloud", "model": "—"},
    {"id": "auditor", "name": "Auditor (安全模式专家)", "role": "cloud", "model": "—"},
    {"id": "verifier", "name": "Verifier (本地验证者)", "role": "local", "model": "—"},
    {"id": "courtroom", "name": "Courtroom (模拟法庭)", "role": "local", "model": "—"},
]

STATUS_ICONS = {
    "idle":    ("空闲", Qt.gray),
    "running": ("运行中", Qt.darkGreen),
    "waiting": ("等待钩子", Qt.darkYellow),
    "error":   ("错误", Qt.red),
    "done":    ("已完成", Qt.blue),
}


class AgentMonitorPanel(QWidget):
    """Dashboard showing agent states and token consumption."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # ── Agent status table ───────────────────────────────────────
        group = QGroupBox("Agent 运行状态")
        group_layout = QVBoxLayout(group)

        self._agent_table = QTableWidget(len(AGENT_DEFINITIONS), 4)
        self._agent_table.setHorizontalHeaderLabels(["Agent", "状态", "当前任务", "消费"])
        self._agent_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._agent_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._agent_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._agent_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._agent_table.setAlternatingRowColors(True)
        self._agent_table.verticalHeader().setVisible(False)
        self._agent_table.setEditTriggers(QTableWidget.NoEditTriggers)

        for i, agent in enumerate(AGENT_DEFINITIONS):
            name_item = QTableWidgetItem(
                f"{agent['name']} [{agent['role'].upper()}]"
            )
            name_item.setToolTip(f"Model: {agent['model'] or 'TBD'}")
            self._agent_table.setItem(i, 0, name_item)
            self._set_agent_status(i, "idle")
            self._agent_table.setItem(i, 2, QTableWidgetItem("—"))
            self._agent_table.setItem(i, 3, QTableWidgetItem("0 tokens"))

        group_layout.addWidget(self._agent_table)
        layout.addWidget(group)

        # ── Token budget summary ─────────────────────────────────────
        budget_group = QGroupBox("Token 预算")
        budget_layout = QVBoxLayout(budget_group)

        self._budget_bar = QProgressBar()
        self._budget_bar.setMaximum(100)
        self._budget_bar.setFormat("Token 消耗: %p% (%v / 2,000,000)")
        budget_layout.addWidget(self._budget_bar)

        self._budget_detail = QLabel("总计: 0 prompt + 0 completion = 0 tokens")
        self._budget_detail.setFont(QFont("Consolas", 9))
        budget_layout.addWidget(self._budget_detail)

        self._budget_warning = QLabel("")
        self._budget_warning.setStyleSheet("color: red; font-weight: bold;")
        budget_layout.addWidget(self._budget_warning)

        layout.addWidget(budget_group)
        layout.addStretch()

    def _set_agent_status(self, row: int, status: str):
        label, color = STATUS_ICONS.get(status, ("未知", Qt.gray))
        item = QTableWidgetItem(label)
        item.setForeground(color)
        font = item.font()
        font.setBold(status == "running")
        item.setFont(font)
        self._agent_table.setItem(row, 1, item)

    def update_agent(self, agent_id: str, status: str,
                     task: str = "—", tokens: int = 0):
        """Update a specific agent's row."""
        row_map = {
            "architect": 0, "Architect": 0,
            "auditor": 1, "Auditor": 1,
            "verifier": 2, "Verifier": 2,
            "courtroom": 3, "Courtroom": 3,
        }
        row = row_map.get(agent_id)
        if row is None:
            return
        self._set_agent_status(row, status)
        self._agent_table.setItem(row, 2, QTableWidgetItem(task[:80] if task else "—"))
        self._agent_table.setItem(
            row, 3, QTableWidgetItem(f"{tokens:,} tokens" if tokens else "—")
        )

    def update_budget(self, total_tokens: int, budget: int = 2_000_000):
        """Update token budget display."""
        pct = int(total_tokens / budget * 100) if budget > 0 else 0
        self._budget_bar.setValue(pct)

        if pct >= 90:
            self._budget_bar.setStyleSheet(
                "QProgressBar::chunk { background-color: red; }")
            self._budget_warning.setText("⚠ 预算即将耗尽，已暂停云端调用")
        elif pct >= 70:
            self._budget_bar.setStyleSheet(
                "QProgressBar::chunk { background-color: orange; }")
            self._budget_warning.setText("⚡ 预算使用超过 70%")
        else:
            self._budget_bar.setStyleSheet("")
            self._budget_warning.setText("")

        self._budget_detail.setText(
            f"总计: {total_tokens:,} / {budget:,} tokens ({pct}%)"
        )

    def clear_all(self):
        """Reset all agents to idle."""
        for i in range(len(AGENT_DEFINITIONS)):
            self._set_agent_status(i, "idle")
            self._agent_table.setItem(i, 2, QTableWidgetItem("—"))
            self._agent_table.setItem(i, 3, QTableWidgetItem("—"))
