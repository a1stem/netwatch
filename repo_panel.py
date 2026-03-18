"""
ui/repo_panel.py
----------------
Tab showing the repository integrity audit (apt, snap, flatpak sources).
Runs repo_checker.audit_all() in a background thread on demand.
"""

from __future__ import annotations
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QBrush, QFont
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QPushButton,
    QHeaderView, QAbstractItemView, QTextEdit, QSplitter,
)

from backend.repo_checker import RepoEntry, RepoStatus, RepoKind, audit_all


# ── Background worker ───────────────────────────────────────────────────────

class _AuditWorker(QThread):
    done = pyqtSignal(list)

    def run(self):
        entries = audit_all()
        self.done.emit(entries)


# ── Colour maps ─────────────────────────────────────────────────────────────

_STATUS_BG = {
    RepoStatus.SAFE:   QColor("#EAF3DE"),
    RepoStatus.INFO:   QColor("#E6F1FB"),
    RepoStatus.WARN:   QColor("#FAEEDA"),
    RepoStatus.DANGER: QColor("#FCEBEB"),
}
_STATUS_FG = {
    RepoStatus.SAFE:   QColor("#3B6D11"),
    RepoStatus.INFO:   QColor("#185FA5"),
    RepoStatus.WARN:   QColor("#854F0B"),
    RepoStatus.DANGER: QColor("#A32D2D"),
}
_KIND_LABEL = {
    RepoKind.APT:     "apt",
    RepoKind.SNAP:    "snap",
    RepoKind.FLATPAK: "flatpak",
}

COLS = ["Source", "URL", "Type", "HTTPS", "GPG key", "Status"]


class RepoPanel(QWidget):
    """Displays the full repository audit in a table + advisory text."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._entries: list[RepoEntry] = []
        self._worker: _AuditWorker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # Toolbar
        toolbar = QHBoxLayout()
        lbl = QLabel("Repository integrity audit")
        lbl.setStyleSheet("font-weight: 600; font-size: 12px;")
        toolbar.addWidget(lbl)
        toolbar.addStretch()

        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet("font-size: 11px; color: #666;")
        toolbar.addWidget(self._status_lbl)

        self._refresh_btn = QPushButton("Scan repositories")
        self._refresh_btn.clicked.connect(self._run_audit)
        toolbar.addWidget(self._refresh_btn)
        layout.addLayout(toolbar)

        # Splitter: table on top, advisory text below
        splitter = QSplitter(Qt.Vertical)

        # Table
        self._table = QTableWidget(0, len(COLS))
        self._table.setHorizontalHeaderLabels(COLS)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        for i in range(2, len(COLS)):
            self._table.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setAlternatingRowColors(False)
        self._table.setShowGrid(False)
        self._table.setFont(QFont("monospace", 9))
        self._table.itemSelectionChanged.connect(self._on_select)
        splitter.addWidget(self._table)

        # Advisory
        self._advice = QTextEdit()
        self._advice.setReadOnly(True)
        self._advice.setMaximumHeight(120)
        self._advice.setStyleSheet("font-size: 11px; background: #FAFAF8;")
        self._advice.setPlaceholderText(
            "Select a repository row above to see details and advice."
        )
        splitter.addWidget(self._advice)
        splitter.setSizes([400, 120])

        layout.addWidget(splitter)

        # Initial advisory
        self._advice.setHtml(_STATIC_ADVICE)

    # ── Audit lifecycle ─────────────────────────────────────────────────

    def _run_audit(self) -> None:
        self._refresh_btn.setEnabled(False)
        self._status_lbl.setText("Scanning…")
        self._worker = _AuditWorker(self)
        self._worker.done.connect(self._on_done)
        self._worker.start()

    def _on_done(self, entries: list[RepoEntry]) -> None:
        self._entries = entries
        self._populate(entries)
        self._refresh_btn.setEnabled(True)
        danger = sum(1 for e in entries if e.status == RepoStatus.DANGER)
        warn   = sum(1 for e in entries if e.status == RepoStatus.WARN)
        msg = f"{len(entries)} sources scanned"
        if danger:
            msg += f" · {danger} DANGER"
        if warn:
            msg += f" · {warn} warnings"
        self._status_lbl.setText(msg)
        color = "#A32D2D" if danger else ("#854F0B" if warn else "#3B6D11")
        self._status_lbl.setStyleSheet(f"font-size: 11px; color: {color};")

    def _populate(self, entries: list[RepoEntry]) -> None:
        self._table.setRowCount(0)
        for row, e in enumerate(entries):
            self._table.insertRow(row)
            items = [
                e.name,
                e.url,
                _KIND_LABEL.get(e.kind, "?"),
                e.https_label,
                e.gpg_label,
                e.status_label,
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
                if col == len(items) - 1:   # Status column — coloured
                    item.setBackground(QBrush(_STATUS_BG.get(e.status, QColor("white"))))
                    item.setForeground(QBrush(_STATUS_FG.get(e.status, QColor("black"))))
                if not e.is_enabled:
                    item.setForeground(QBrush(QColor("#aaa")))
                    if col == 0:
                        item.setText(f"[disabled] {text}")
                self._table.setItem(row, col, item)
            self._table.setRowHeight(row, 28)

    def _on_select(self) -> None:
        rows = self._table.selectedItems()
        if not rows:
            return
        row = self._table.currentRow()
        if row < 0 or row >= len(self._entries):
            return
        e = self._entries[row]
        self._advice.setHtml(_entry_advice(e))

    def refresh(self) -> None:
        """Called by main window on tab switch."""
        if not self._entries:
            self._run_audit()


# ── Advisory text helpers ────────────────────────────────────────────────────

_STATIC_ADVICE = """
<p style="font-size:11px; color:#555;">
<b>What to check:</b><br>
All sources should use <code>https://</code>. &nbsp;
Every third-party source needs a GPG key in <code>/etc/apt/trusted.gpg.d/</code>. &nbsp;
PPAs are community-run — treat as third-party. &nbsp;
Sources with <i>neither</i> HTTPS <i>nor</i> a GPG key should be removed immediately —
they allow silently injecting malicious packages.
</p>
"""


def _entry_advice(e: RepoEntry) -> str:
    bg = {
        RepoStatus.SAFE:   "#EAF3DE",
        RepoStatus.INFO:   "#E6F1FB",
        RepoStatus.WARN:   "#FAEEDA",
        RepoStatus.DANGER: "#FCEBEB",
    }.get(e.status, "#fff")

    fg = {
        RepoStatus.SAFE:   "#3B6D11",
        RepoStatus.INFO:   "#185FA5",
        RepoStatus.WARN:   "#854F0B",
        RepoStatus.DANGER: "#A32D2D",
    }.get(e.status, "#333")

    advice_text = {
        RepoStatus.SAFE: (
            "This repository uses HTTPS and is GPG-signed. "
            "Packages downloaded from it are encrypted in transit and verified "
            "before installation. No action needed."
        ),
        RepoStatus.INFO: (
            "This is a third-party repository. It uses HTTPS and appears GPG-signed, "
            "which means transit security is good. However, the package maintainer "
            "is not Canonical or Debian — only install from PPAs/third-party sources "
            "you explicitly trust."
        ),
        RepoStatus.WARN: (
            "This repository has a security concern. "
            + ("It uses plain HTTP, so traffic could be intercepted and packages "
               "swapped without you knowing. " if not e.is_https else "")
            + ("No GPG key was found — packages from this source cannot be "
               "cryptographically verified. " if not e.has_gpg else "")
            + "Consider removing or replacing this source."
        ),
        RepoStatus.DANGER: (
            "⚠ DANGER: This repository uses plain HTTP AND has no GPG key. "
            "Packages it provides can be silently replaced by anyone with "
            "access to the network path between you and the server. "
            "This is exactly how repository spoofing attacks work. "
            "Remove this source immediately unless you have a very specific reason to trust it."
        ),
    }.get(e.status, "")

    notes_html = f"<br><i>{e.notes}</i>" if e.notes else ""

    return f"""
    <div style="background:{bg}; border-radius:6px; padding:8px; font-size:11px; color:{fg};">
        <b>{e.name}</b><br>
        <code>{e.url}</code>
        {notes_html}
        <br><br>
        {advice_text}
    </div>
    """
