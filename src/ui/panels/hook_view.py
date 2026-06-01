"""Hook and task view panel — table with filtering and context actions."""

import json
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton,
    QMenu, QMessageBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QColor


SEVERITY_COLORS = {
    "critical": QColor(255, 0, 0),
    "high":     QColor(255, 60, 60),
    "medium":   QColor(200, 150, 0),
    "low":      QColor(0, 100, 200),
    "info":     QColor(100, 100, 100),
}


class HookViewPanel(QWidget):
    """Tabbed view of hooks and tasks with filtering."""

    hook_selected = Signal(str)  # hook_id
    finding_selected = Signal(str)  # finding_id
    verdict_changed = Signal(str, str)  # hook_id, new_verdict

    def __init__(self, parent=None):
        super().__init__(parent)
        self._hooks_data: list[dict] = []
        self._findings_data: list[dict] = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # ── Filter bar ───────────────────────────────────────────────
        filter_bar = QHBoxLayout()

        filter_bar.addWidget(QLabel("状态:"))
        self._status_filter = QComboBox()
        self._status_filter.addItems([
            "全部", "pending", "analyzing", "verified", "false_positive", "dismissed",
        ])
        self._status_filter.currentTextChanged.connect(self._apply_filters)
        filter_bar.addWidget(self._status_filter)

        filter_bar.addWidget(QLabel("严重度:"))
        self._severity_filter = QComboBox()
        self._severity_filter.addItems([
            "全部", "critical", "high", "medium", "low", "info",
        ])
        self._severity_filter.currentTextChanged.connect(self._apply_filters)
        filter_bar.addWidget(self._severity_filter)

        filter_bar.addWidget(QLabel("类型:"))
        self._type_filter = QComboBox()
        self._type_filter.addItems([
            "全部", "dangerous_call", "route_entry", "input_source",
            "semgrep", "secret_leak", "auth_bypass",
        ])
        self._type_filter.currentTextChanged.connect(self._apply_filters)
        filter_bar.addWidget(self._type_filter)

        filter_bar.addStretch()

        self._btn_refresh = QPushButton("刷新")
        self._btn_refresh.clicked.connect(self._apply_filters)
        filter_bar.addWidget(self._btn_refresh)

        layout.addLayout(filter_bar)

        # ── Hook table ───────────────────────────────────────────────
        self._hook_table = QTableWidget(0, 5)
        self._hook_table.setHorizontalHeaderLabels([
            "函数名", "类型", "严重度", "状态", "文件",
        ])
        self._hook_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._hook_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._hook_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self._hook_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._hook_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self._hook_table.setAlternatingRowColors(True)
        self._hook_table.verticalHeader().setVisible(False)
        self._hook_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._hook_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._hook_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._hook_table.customContextMenuRequested.connect(self._show_context_menu)
        self._hook_table.itemDoubleClicked.connect(self._on_item_double_clicked)

        layout.addWidget(self._hook_table)

        # ── Count label ──────────────────────────────────────────────
        self._count_label = QLabel("共 0 条钩子")
        layout.addWidget(self._count_label)

    def load_data(self, hooks: list[dict], findings: list[dict]):
        """Load hook data into the table."""
        self._hooks_data = hooks
        self._findings_data = findings
        self._apply_filters()

    def _apply_filters(self):
        status_f = self._status_filter.currentText()
        severity_f = self._severity_filter.currentText()
        type_f = self._type_filter.currentText()

        # Filter
        filtered = []
        for h in self._hooks_data:
            if status_f != "全部" and h.get("status") != status_f:
                continue
            if severity_f != "全部" and h.get("severity") != severity_f:
                continue
            if type_f != "全部" and h.get("hook_type") != type_f:
                continue
            filtered.append(h)

        # Populate table
        self._hook_table.setRowCount(len(filtered))
        for i, h in enumerate(filtered):
            self._hook_table.setItem(i, 0, QTableWidgetItem(
                h.get("func_name", h.get("function_name", "?"))[:40]))
            self._hook_table.setItem(i, 1, QTableWidgetItem(
                h.get("hook_type", "?")))

            sev_item = QTableWidgetItem(h.get("severity", "info"))
            sev_color = SEVERITY_COLORS.get(h.get("severity", "info"), QColor(100, 100, 100))
            sev_item.setForeground(sev_color)
            self._hook_table.setItem(i, 2, sev_item)

            status_item = QTableWidgetItem(h.get("status", "?"))
            if h.get("status") == "verified":
                status_item.setForeground(Qt.darkGreen)
            elif h.get("status") == "false_positive":
                status_item.setForeground(Qt.red)
            self._hook_table.setItem(i, 3, status_item)

            fp = h.get("file_path", "?")
            self._hook_table.setItem(i, 4, QTableWidgetItem(fp[:80]))

            # Store hook_id for context menu
            self._hook_table.item(i, 0).setData(Qt.UserRole, h.get("hook_id"))

        self._count_label.setText(f"共 {len(filtered)} 条钩子 (总计 {len(self._hooks_data)})")

    def _show_context_menu(self, pos):
        item = self._hook_table.itemAt(pos)
        if not item:
            return

        row = item.row()
        hook_id = self._hook_table.item(row, 0).data(Qt.UserRole)
        hook = next((h for h in self._hooks_data if h.get("hook_id") == hook_id), None)
        if not hook:
            return

        menu = QMenu(self)

        if hook.get("status") != "verified":
            act_verify = QAction("标记为已确认", self)
            act_verify.triggered.connect(lambda: self._change_verdict(hook_id, "verified"))
            menu.addAction(act_verify)

        if hook.get("status") != "false_positive":
            act_fp = QAction("标记为误报", self)
            act_fp.triggered.connect(lambda: self._change_verdict(hook_id, "false_positive"))
            menu.addAction(act_fp)

        if hook.get("status") != "dismissed":
            act_dis = QAction("标记为已忽略", self)
            act_dis.triggered.connect(lambda: self._change_verdict(hook_id, "dismissed"))
            menu.addAction(act_dis)

        menu.addSeparator()

        act_detail = QAction("查看详情", self)
        act_detail.triggered.connect(lambda: self.hook_selected.emit(hook_id))
        menu.addAction(act_detail)

        menu.exec(self._hook_table.viewport().mapToGlobal(pos))

    def _change_verdict(self, hook_id: str, new_status: str):
        from db import get_db
        db = get_db()
        db.update_hook_status(hook_id, new_status)
        self.verdict_changed.emit(hook_id, new_status)

        # Reload
        self._hooks_data = db.list_hooks()
        self._apply_filters()

    def _on_item_double_clicked(self, item):
        row = item.row()
        hook_id = self._hook_table.item(row, 0).data(Qt.UserRole)
        if hook_id:
            self.hook_selected.emit(hook_id)
