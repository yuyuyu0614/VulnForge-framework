"""Report preview panel — SRC template editor with Markdown export."""

import json
import time
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QComboBox, QFileDialog, QMessageBox, QSplitter,
    QGroupBox, QTableWidget, QTableWidgetItem, QHeaderView,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont

# ── SRC Platform Report Templates ───────────────────────────────

SRC_TEMPLATES = {
    "通用 (30+平台通用)": """# 漏洞报告

## 基本信息
- **漏洞标题**: {title}
- **CWE 编号**: {cwe}
- **严重度**: {severity}
- **发现日期**: {date}

## 漏洞描述
{description}

## 影响范围
- **影响文件**: {file_path}
- **影响函数**: {func_name}

## 复现步骤
1. {repro_step_1}
2. {repro_step_2}
3. {repro_step_3}

## Proof of Concept
```
{poc}
```

## 修复建议
{fix_suggestion}

---

*本报告经人工验证确认，AI仅用于辅助分析。*
""",

    "腾讯 TSRC": """# 腾讯安全应急响应中心 — 漏洞报告

## 漏洞概要
- **漏洞名称**: {title}
- **漏洞类型**: {cwe}
- **危害等级**: {severity}
- **发现时间**: {date}

## 漏洞详情
{description}

## 影响业务
{file_path} — {func_name}

## 复现环境与步骤
### 环境
-

### 步骤
1. {repro_step_1}
2. {repro_step_2}
3. {repro_step_3}

### 结果截图
（请手动附上）

## PoC 代码
```
{poc}
```

## 修复方案
{fix_suggestion}

## 声明
本报告内容经本人手动复现确认，AI工具仅用于代码辅助分析。
""",

    "360 SRC": """# 360安全应急响应中心 — 漏洞报告

## 漏洞信息
- **标题**: {title}
- **类型**: {cwe}
- **严重程度**: {severity}
- **发现日期**: {date}

## 详细描述
{description}

## 漏洞位置
- 文件: {file_path}
- 函数: {func_name}

## 复现证明
### 复现步骤
1. {repro_step_1}
2. {repro_step_2}
3. {repro_step_3}

### PoC
```
{poc}
```

### 复现截图
（请手动附上关键步骤截图）

## 修复建议
{fix_suggestion}

---
*已人工验证：是 / 否*
""",

    "补天漏洞响应平台": """# 补天平台 — 漏洞提交报告

## 漏洞概述
- **漏洞标题**: {title}
- **CWE分类**: {cwe}
- **危害等级**: {severity}
- **提交日期**: {date}

## 漏洞危害说明
{description}

## 漏洞位置
- 文件路径: {file_path}
- 函数名: {func_name}

## 复现步骤（详细）
### 第一步：
{repro_step_1}

### 第二步：
{repro_step_2}

### 第三步：
{repro_step_3}

## 完整PoC
```
{poc}
```

## 关键步骤截图
（请手动附上截图）

## 修复方案
{fix_suggestion}

## 声明
本人承诺：
1. 本报告所涉及漏洞已经过本人手动复现验证
2. 未使用自动化扫描工具对线上系统发起请求
3. 未篡改、泄露、破坏任何业务数据
""",
}


class ReportPreviewPanel(QWidget):
    """SRC report generator with platform-specific templates."""

    export_requested = Signal(str)  # exported file path

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_finding: dict | None = None
        self._current_hook: dict | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # ── Template selector ────────────────────────────────────────
        selector = QHBoxLayout()
        selector.addWidget(QLabel("<b>报告模板:</b>"))
        self._template_combo = QComboBox()
        self._template_combo.addItems(list(SRC_TEMPLATES.keys()))
        self._template_combo.currentTextChanged.connect(self._refresh_preview)
        selector.addWidget(self._template_combo)

        selector.addStretch()

        self._btn_export = QPushButton("导出 Markdown")
        self._btn_export.clicked.connect(self._export_markdown)
        selector.addWidget(self._btn_export)

        self._btn_copy = QPushButton("复制到剪贴板")
        self._btn_copy.clicked.connect(self._copy_to_clipboard)
        selector.addWidget(self._btn_copy)

        layout.addLayout(selector)

        # ── Split: finding data + preview ────────────────────────────
        splitter = QSplitter(Qt.Horizontal)

        # Left: finding selector
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(QLabel("<b>已确认漏洞</b>"))
        self._finding_table = QTableWidget(0, 3)
        self._finding_table.setHorizontalHeaderLabels(["标题", "严重度", "CWE"])
        self._finding_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._finding_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._finding_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self._finding_table.setAlternatingRowColors(True)
        self._finding_table.verticalHeader().setVisible(False)
        self._finding_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._finding_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._finding_table.itemClicked.connect(self._on_finding_selected)
        left_layout.addWidget(self._finding_table)

        # Right: preview
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(QLabel("<b>报告预览</b>"))
        self._preview_edit = QTextEdit()
        self._preview_edit.setReadOnly(True)
        self._preview_edit.setFont(QFont("Consolas", 10))
        self._preview_edit.setPlaceholderText("选择一个漏洞以生成报告预览...")
        right_layout.addWidget(self._preview_edit)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([300, 700])

        layout.addWidget(splitter)

    def load_findings(self, findings: list[dict], hooks: list[dict]):
        """Populate the finding selector table."""
        confirmed = [f for f in findings
                     if f.get("verdict") in ("true_positive", "valid")]
        self._finding_table.setRowCount(len(confirmed))
        for i, f in enumerate(confirmed):
            self._finding_table.setItem(i, 0, QTableWidgetItem(
                f.get("title", "Untitled")[:60]))
            self._finding_table.setItem(i, 1, QTableWidgetItem(
                f.get("severity", "?")))
            self._finding_table.setItem(i, 2, QTableWidgetItem(
                f.get("cwe_id", f.get("cwe", "N/A"))))
            self._finding_table.item(i, 0).setData(Qt.UserRole, f)

    def _on_finding_selected(self, item):
        row = item.row()
        self._current_finding = self._finding_table.item(row, 0).data(Qt.UserRole)

        # Look up associated hook
        from db import get_db
        db = get_db()
        hook_id = self._current_finding.get("hook_id", "")
        hooks = db.list_hooks()
        self._current_hook = next(
            (h for h in hooks if h.get("hook_id") == hook_id), None
        )

        self._refresh_preview()

    def _refresh_preview(self):
        if not self._current_finding:
            return

        template_name = self._template_combo.currentText()
        template = SRC_TEMPLATES.get(template_name, SRC_TEMPLATES["通用 (30+平台通用)"])

        f = self._current_finding
        h = self._current_hook or {}

        desc = f.get("description", f.get("reason", ""))
        poc = f.get("poc_code", f.get("poc", ""))
        if not poc:
            poc = "# 请根据漏洞描述手动编写 PoC 代码"

        # Extract fix suggestion from description
        fix = ""
        if "修复" in desc or "fix" in desc.lower():
            fix = desc
        else:
            fix = f"1. 使用参数化查询或 ORM 防止注入\n2. 对所有用户输入进行验证和清理\n3. 实施最小权限原则"

        report = template.format(
            title=f.get("title", "Untitled"),
            cwe=f.get("cwe_id", f.get("cwe", "N/A")),
            severity=f.get("severity", "medium").upper(),
            date=time.strftime("%Y-%m-%d"),
            description=desc[:2000],
            file_path=h.get("file_path", "未知"),
            func_name=h.get("func_name", h.get("function_name", "未知")),
            repro_step_1="确认漏洞位置，审查相关代码逻辑",
            repro_step_2="构造恶意输入/请求触发漏洞",
            repro_step_3="观察程序异常行为/未授权数据访问/代码执行结果",
            poc=poc.strip()[:2000],
            fix_suggestion=fix[:1000],
        )

        self._preview_edit.setMarkdown(report)

    def _export_markdown(self):
        if not self._current_finding:
            QMessageBox.information(self, "提示", "请先选择一个漏洞")
            return

        title = self._current_finding.get("title", "report")
        safe_title = "".join(c for c in title if c.isalnum() or c in " _-")[:40]
        filepath, _ = QFileDialog.getSaveFileName(
            self, "导出报告", f"{safe_title}.md",
            "Markdown 文件 (*.md);;所有文件 (*)",
        )
        if filepath:
            Path(filepath).write_text(
                self._preview_edit.toMarkdown(), encoding="utf-8"
            )
            self.export_requested.emit(filepath)
            QMessageBox.information(self, "导出成功",
                                    f"报告已保存至:\n{filepath}")

    def _copy_to_clipboard(self):
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(self._preview_edit.toMarkdown())
        QMessageBox.information(self, "已复制", "报告内容已复制到剪贴板")
