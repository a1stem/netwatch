"""
ui/proc_tree.py
---------------
QTreeWidget panel showing the full parent→child chain for a selected
connection, with Trust / Block action buttons.
"""

from __future__ import annotations
from typing import Optional, TYPE_CHECKING

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QIcon
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTreeWidget, QTreeWidgetItem, QPushButton, QFrame,
)

if TYPE_CHECKING:
    from backend.poller import ConnectionRecord
    from backend.resolver import ProcessNode

# ── Colour helpers ──────────────────────────────────────────────────────────

def _item_color(node: "ProcessNode") -> Optional[QColor]:
    if node.is_blocked:
        return QColor("#A32D2D")
    if node.is_trusted:
        return QColor("#3B6D11")
    if node.is_package_manager:
        return QColor("#185FA5")
    return None


class ProcessTreePanel(QWidget):
    """
    Right-hand panel showing the process ancestry for a connection.

    Signals:
        trust_requested(exe)  — user clicked Trust for an exe path
        block_requested(ConnectionRecord) — user clicked Block
    """

    trust_requested: pyqtSignal = pyqtSignal(str)       # exe path
    block_requested: pyqtSignal = pyqtSignal(object)    # ConnectionRecord

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_record: Optional[ConnectionRecord] = None
        self._build_ui()

    # ── UI construction ─────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Title bar
        self._title = QLabel("Process tree")
        self._title.setStyleSheet(
            "font-weight: 600; font-size: 11px; "
            "color: #888; padding: 4px 6px;"
        )
        layout.addWidget(self._title)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFrameShadow(QFrame.Sunken)
        layout.addWidget(sep)

        # Tree widget
        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setIndentation(16)
        self._tree.setAnimated(True)
        self._tree.setFont(QFont("monospace", 9))
        self._tree.setAlternatingRowColors(True)
        self._tree.setSelectionMode(QTreeWidget.NoSelection)
        layout.addWidget(self._tree, stretch=1)

        # Connection details strip
        self._detail = QLabel("")
        self._detail.setWordWrap(True)
        self._detail.setStyleSheet(
            "font-size: 10px; color: #666; padding: 4px 6px; "
            "background: #f8f8f8; border-top: 1px solid #e0e0e0;"
        )
        layout.addWidget(self._detail)

        # Action buttons
        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(4, 4, 4, 4)

        self._btn_trust = QPushButton("Trust app")
        self._btn_trust.setEnabled(False)
        self._btn_trust.setStyleSheet(
            "QPushButton { border: 1px solid #3B6D11; color: #3B6D11; "
            "border-radius: 4px; padding: 4px 10px; font-size: 11px; }"
            "QPushButton:hover { background: #EAF3DE; }"
            "QPushButton:disabled { color: #aaa; border-color: #ddd; }"
        )
        self._btn_trust.clicked.connect(self._on_trust)

        self._btn_block = QPushButton("Block connection")
        self._btn_block.setEnabled(False)
        self._btn_block.setStyleSheet(
            "QPushButton { border: 1px solid #A32D2D; color: #A32D2D; "
            "border-radius: 4px; padding: 4px 10px; font-size: 11px; }"
            "QPushButton:hover { background: #FCEBEB; }"
            "QPushButton:disabled { color: #aaa; border-color: #ddd; }"
        )
        self._btn_block.clicked.connect(self._on_block)

        btn_row.addWidget(self._btn_trust)
        btn_row.addWidget(self._btn_block)
        layout.addLayout(btn_row)

    # ── Public API ──────────────────────────────────────────────────────

    def show_record(self, rec: Optional["ConnectionRecord"]) -> None:
        """Populate the panel for a connection record (or clear it)."""
        self._current_record = rec
        self._tree.clear()

        if rec is None:
            self._title.setText("Process tree")
            self._detail.setText("")
            self._btn_trust.setEnabled(False)
            self._btn_block.setEnabled(False)
            return

        # Title
        self._title.setText(
            f"Process tree  —  {rec.app_name}  (PID {rec.pid})"
        )

        # Build tree items from chain (root first)
        parent_item: Optional[QTreeWidgetItem] = None
        for node in rec.proc_chain:
            label = f"{node.name}   [{node.pid}]"
            if node.exe and node.exe != node.name:
                label += f"   {node.exe}"

            if parent_item is None:
                item = QTreeWidgetItem(self._tree, [label])
            else:
                item = QTreeWidgetItem(parent_item, [label])

            # Colour coding
            color = _item_color(node)
            if color:
                item.setForeground(0, color)

            # Bold the leaf (actual process owning the socket)
            if node == rec.proc_chain[-1]:
                f = item.font(0)
                f.setBold(True)
                item.setFont(0, f)

            # Tooltip: full command line
            item.setToolTip(0, f"cmd: {node.cmdline}\nuser: {node.username}")

            if parent_item is None:
                self._tree.addTopLevelItem(item)
            parent_item = item

        self._tree.expandAll()

        # Detail strip
        geo_str = rec.geo.tooltip() if rec.geo else ""
        enc_str = rec.tls.risk_label if rec.tls else ""
        iface_str = rec.iface.risk_text if rec.iface else ""
        self._detail.setText(
            f"{rec.proto}  {rec.local_ip}:{rec.local_port}  →  "
            f"{rec.remote_display}\n"
            f"{geo_str}   {enc_str}\n"
            f"{iface_str}"
        )

        # Buttons
        is_blocked = rec.is_blocked
        self._btn_trust.setEnabled(not rec.is_trusted and not is_blocked)
        self._btn_block.setEnabled(not is_blocked)
        self._btn_trust.setText(
            "Trusted" if rec.is_trusted else "Trust app"
        )

    def clear(self) -> None:
        self.show_record(None)

    # ── Slots ───────────────────────────────────────────────────────────

    def _on_trust(self) -> None:
        if self._current_record and self._current_record.app_exe:
            self.trust_requested.emit(self._current_record.app_exe)

    def _on_block(self) -> None:
        if self._current_record:
            self.block_requested.emit(self._current_record)
