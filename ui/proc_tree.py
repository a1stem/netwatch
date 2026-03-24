"""
ui/proc_tree.py
---------------
Process ancestry panel with Trust / Block / Unblock buttons.

Fixes:
  - Buttons now always respond correctly regardless of blocked/trusted state
  - Unblock button shown when connection is already blocked
  - All colours use CSS variables — no hardcoded hex that breaks dark mode
  - Detail strip and title label inherit theme colours
"""

from __future__ import annotations
from typing import Optional, TYPE_CHECKING

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTreeWidget, QTreeWidgetItem, QPushButton, QFrame,
)

if TYPE_CHECKING:
    from backend.poller import ConnectionRecord
    from backend.resolver import ProcessNode


def _item_color(node: "ProcessNode", dark_mode: bool) -> Optional[QColor]:
    """Return appropriate node colour for current theme."""
    if getattr(node, 'is_blocked', False):
        return QColor("#E24B4A") if dark_mode else QColor("#A32D2D")
    if node.is_trusted:
        return QColor("#97C459") if dark_mode else QColor("#3B6D11")
    if node.is_package_manager:
        return QColor("#85B7EB") if dark_mode else QColor("#185FA5")
    return None


# ── Button stylesheets — theme aware ─────────────────────────────────────────
# Uses both light and dark hex so buttons are readable in both themes.
# The app-level QSS sets the base; these only override border/text colour.

_BTN_TRUST = """
    QPushButton {
        border: 1px solid #3B6D11;
        color: #3B6D11;
        border-radius: 4px;
        padding: 5px 10px;
        font-size: 11px;
        background: transparent;
    }
    QPushButton:hover   { background: rgba(99,153,34,0.15); color: #3B6D11; }
    QPushButton:disabled{ color: #888; border-color: #555; }
"""

_BTN_TRUST_DARK = """
    QPushButton {
        border: 1px solid #97C459;
        color: #97C459;
        border-radius: 4px;
        padding: 5px 10px;
        font-size: 11px;
        background: transparent;
    }
    QPushButton:hover   { background: rgba(151,196,89,0.15); color: #97C459; }
    QPushButton:disabled{ color: #585b70; border-color: #45475a; }
"""

_BTN_BLOCK = """
    QPushButton {
        border: 1px solid #A32D2D;
        color: #A32D2D;
        border-radius: 4px;
        padding: 5px 10px;
        font-size: 11px;
        background: transparent;
    }
    QPushButton:hover   { background: rgba(163,45,45,0.12); color: #A32D2D; }
    QPushButton:disabled{ color: #888; border-color: #555; }
"""

_BTN_BLOCK_DARK = """
    QPushButton {
        border: 1px solid #E24B4A;
        color: #E24B4A;
        border-radius: 4px;
        padding: 5px 10px;
        font-size: 11px;
        background: transparent;
    }
    QPushButton:hover   { background: rgba(226,75,74,0.15); color: #E24B4A; }
    QPushButton:disabled{ color: #585b70; border-color: #45475a; }
"""

_BTN_UNBLOCK = """
    QPushButton {
        border: 1px solid #BA7517;
        color: #BA7517;
        border-radius: 4px;
        padding: 5px 10px;
        font-size: 11px;
        background: transparent;
    }
    QPushButton:hover   { background: rgba(186,117,23,0.15); color: #BA7517; }
"""

_BTN_UNBLOCK_DARK = """
    QPushButton {
        border: 1px solid #FAC775;
        color: #FAC775;
        border-radius: 4px;
        padding: 5px 10px;
        font-size: 11px;
        background: transparent;
    }
    QPushButton:hover   { background: rgba(250,199,117,0.15); color: #FAC775; }
"""


class ProcessTreePanel(QWidget):
    """
    Right-hand panel showing process ancestry with Trust / Block / Unblock.

    Signals:
        trust_requested(exe)            — user clicked Trust
        block_requested(record)         — user clicked Block
        unblock_requested(ip, port)     — user clicked Unblock
    """

    trust_requested:   pyqtSignal = pyqtSignal(str)
    block_requested:   pyqtSignal = pyqtSignal(object)
    unblock_requested: pyqtSignal = pyqtSignal(str, int)   # ip, port

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_record: Optional[ConnectionRecord] = None
        self._dark_mode = False
        self._build_ui()

    def set_dark_mode(self, dark: bool) -> None:
        """Called by main_window when theme toggles."""
        self._dark_mode = dark
        self._apply_button_styles()
        # Re-colour tree items for current theme
        if self._current_record:
            self._recolour_tree()

    def _apply_button_styles(self) -> None:
        self._btn_trust.setStyleSheet(
            _BTN_TRUST_DARK if self._dark_mode else _BTN_TRUST
        )
        self._btn_block.setStyleSheet(
            _BTN_BLOCK_DARK if self._dark_mode else _BTN_BLOCK
        )
        self._btn_unblock.setStyleSheet(
            _BTN_UNBLOCK_DARK if self._dark_mode else _BTN_UNBLOCK
        )

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Title — no hardcoded colour, inherits from theme
        self._title = QLabel("Process tree")
        self._title.setStyleSheet(
            "font-weight: 600; font-size: 11px; padding: 4px 6px;"
        )
        layout.addWidget(self._title)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFrameShadow(QFrame.Sunken)
        layout.addWidget(sep)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setIndentation(16)
        self._tree.setAnimated(True)
        self._tree.setFont(QFont("monospace", 9))
        self._tree.setAlternatingRowColors(True)
        self._tree.setSelectionMode(QTreeWidget.NoSelection)
        layout.addWidget(self._tree, stretch=1)

        # Detail strip — no hardcoded colours
        self._detail = QLabel("")
        self._detail.setWordWrap(True)
        self._detail.setStyleSheet(
            "font-size: 10px; padding: 4px 6px; "
            "border-top: 1px solid palette(mid);"
        )
        layout.addWidget(self._detail)

        # Buttons row
        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(4, 4, 4, 4)
        btn_row.setSpacing(6)

        self._btn_trust = QPushButton("Trust app")
        self._btn_trust.setEnabled(False)
        self._btn_trust.clicked.connect(self._on_trust)

        self._btn_block = QPushButton("Block")
        self._btn_block.setEnabled(False)
        self._btn_block.clicked.connect(self._on_block)

        self._btn_unblock = QPushButton("Unblock")
        self._btn_unblock.setEnabled(False)
        self._btn_unblock.setVisible(False)
        self._btn_unblock.clicked.connect(self._on_unblock)

        btn_row.addWidget(self._btn_trust)
        btn_row.addWidget(self._btn_block)
        btn_row.addWidget(self._btn_unblock)
        layout.addLayout(btn_row)

        self._apply_button_styles()

    # ── Public API ────────────────────────────────────────────────────────

    def show_record(self, rec: Optional["ConnectionRecord"]) -> None:
        self._current_record = rec
        self._tree.clear()

        if rec is None:
            self._title.setText("Process tree")
            self._detail.setText(
                "Click any row in the live connections table\n"
                "to inspect its process chain here."
            )
            self._btn_trust.setEnabled(False)
            self._btn_block.setEnabled(False)
            self._btn_unblock.setEnabled(False)
            self._btn_unblock.setVisible(False)
            self._btn_block.setVisible(True)
            return

        # Title
        self._title.setText(
            f"Process tree  —  {rec.app_name}  (PID {rec.pid or '?'})"
        )

        # Build tree
        parent_item: Optional[QTreeWidgetItem] = None
        for node in rec.proc_chain:
            label = f"{node.name}   [{node.pid}]"
            if node.exe and node.exe != node.name:
                label += f"   {node.exe}"

            if parent_item is None:
                item = QTreeWidgetItem(self._tree, [label])
            else:
                item = QTreeWidgetItem(parent_item, [label])

            color = _item_color(node, self._dark_mode)
            if color:
                item.setForeground(0, color)

            if rec.proc_chain and node == rec.proc_chain[-1]:
                f = item.font(0)
                f.setBold(True)
                item.setFont(0, f)

            item.setToolTip(0, f"cmd: {node.cmdline}\nuser: {node.username}")

            if parent_item is None:
                self._tree.addTopLevelItem(item)
            parent_item = item

        self._tree.expandAll()

        # Detail strip
        parts = []
        parts.append(
            f"{rec.proto}  {rec.local_ip}:{rec.local_port}  →  {rec.remote_display}"
        )
        if rec.geo:     parts.append(rec.geo.tooltip())
        if rec.tls:     parts.append(rec.tls.risk_label)
        if rec.iface:   parts.append(rec.iface.risk_text)

        if rec.pkg_event:
            from backend.pkg_watcher import PkgVerification
            v = rec.pkg_event.verification
            vmap = {
                PkgVerification.VERIFIED:   "✓ Verified system path",
                PkgVerification.UNVERIFIED: "⚠ Unverified path",
                PkgVerification.SUSPICIOUS: "🚨 SUSPICIOUS — not a real pkg manager",
                PkgVerification.NOT_PKG:    "",
            }
            parts.append(
                f"Pkg: {rec.pkg_event.proc_name} | {vmap.get(v,'')} | "
                f"{'Official domain' if v != PkgVerification.SUSPICIOUS else 'CHECK IMMEDIATELY'}"
            )

        self._detail.setText("\n".join(p for p in parts if p))

        # ── Button state logic ────────────────────────────────────────────
        # is_blocked means a UFW rule exists for this IP:port
        # auto_denied means it was blocked this session automatically
        is_blocked   = rec.is_blocked or getattr(rec, 'auto_denied', False)
        is_trusted   = rec.is_trusted
        is_unid      = getattr(rec, 'is_unidentified', False)
        has_exe      = bool(rec.app_exe)

        if is_blocked:
            # Show Unblock instead of Block
            self._btn_block.setVisible(False)
            self._btn_unblock.setVisible(True)
            self._btn_unblock.setEnabled(True)
            # Can still trust even if blocked
            self._btn_trust.setEnabled(has_exe and not is_trusted)
            self._btn_trust.setText("Trusted ✓" if is_trusted else "Trust app")
        else:
            self._btn_block.setVisible(True)
            self._btn_unblock.setVisible(False)
            # Always enable Block — even for trusted apps
            # (user may want to temporarily block a trusted app)
            self._btn_block.setEnabled(True)
            self._btn_trust.setEnabled(has_exe and not is_trusted and not is_unid)
            self._btn_trust.setText("Trusted ✓" if is_trusted else "Trust app")

    def clear(self) -> None:
        self.show_record(None)

    def _recolour_tree(self) -> None:
        """Re-apply item colours when theme changes."""
        if not self._current_record:
            return
        it = self._tree.invisibleRootItem()
        self._recolour_item(it, self._current_record.proc_chain, 0)

    def _recolour_item(self, item, chain, depth):
        for i in range(item.childCount()):
            child = item.child(i)
            if depth < len(chain):
                color = _item_color(chain[depth], self._dark_mode)
                if color:
                    child.setForeground(0, color)
            self._recolour_item(child, chain, depth + 1)

    # ── Slots ─────────────────────────────────────────────────────────────

    def _on_trust(self) -> None:
        if self._current_record and self._current_record.app_exe:
            self.trust_requested.emit(self._current_record.app_exe)
            # Update button immediately without waiting for next poll
            self._btn_trust.setText("Trusted ✓")
            self._btn_trust.setEnabled(False)

    def _on_block(self) -> None:
        if self._current_record:
            self.block_requested.emit(self._current_record)

    def _on_unblock(self) -> None:
        if self._current_record:
            self.unblock_requested.emit(
                self._current_record.remote_ip,
                self._current_record.remote_port,
            )
            # Swap buttons immediately
            self._btn_unblock.setVisible(False)
            self._btn_block.setVisible(True)
            self._btn_block.setEnabled(True)
