"""
ui/history_view.py — SQLite connection log browser with CSV export button.
"""

from __future__ import annotations
import csv
import os
from datetime import datetime, timedelta
from ui.sudoers_util import default_export_path
from typing import TYPE_CHECKING

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QBrush, QFont
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QComboBox, QLineEdit,
    QHeaderView, QAbstractItemView, QFileDialog, QMessageBox,
)

if TYPE_CHECKING:
    from data.history import History


COLS = ["Time", "App", "PID", "Interface", "Remote host", "Port",
        "Enc", "Country", "Trusted", "Blocked", "Pkg mgr"]


class HistoryView(QWidget):

    def __init__(self, history: "History", parent=None):
        super().__init__(parent)
        self._history = history
        self._current_rows = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        toolbar = QHBoxLayout()
        lbl = QLabel("Connection history")
        lbl.setStyleSheet("font-weight: 600; font-size: 12px;")
        toolbar.addWidget(lbl)
        toolbar.addStretch()

        self._preset = QComboBox()
        self._preset.addItems(["Recent (500)", "Unknown only", "Blocked only",
                               "Last hour", "Last 24h"])
        self._preset.currentIndexChanged.connect(self._apply_filter)
        toolbar.addWidget(self._preset)

        self._app_filter = QLineEdit()
        self._app_filter.setPlaceholderText("Filter by app…")
        self._app_filter.setMaximumWidth(140)
        self._app_filter.returnPressed.connect(self._apply_filter)
        toolbar.addWidget(self._app_filter)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._apply_filter)
        toolbar.addWidget(refresh_btn)

        export_btn = QPushButton("Export CSV")
        export_btn.setToolTip("Export currently shown rows to a CSV file")
        export_btn.clicked.connect(self._export_csv)
        toolbar.addWidget(export_btn)

        purge_btn = QPushButton("Purge > 30d")
        purge_btn.clicked.connect(self._purge)
        toolbar.addWidget(purge_btn)

        layout.addLayout(toolbar)

        self._stats_lbl = QLabel("")
        self._stats_lbl.setStyleSheet("font-size: 10px; color: #888;")
        layout.addWidget(self._stats_lbl)

        self._table = QTableWidget(0, len(COLS))
        self._table.setHorizontalHeaderLabels(COLS)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        for i in [0, 2, 3, 5, 6, 7, 8, 9, 10]:
            self._table.horizontalHeader().setSectionResizeMode(
                i, QHeaderView.ResizeToContents)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setShowGrid(False)
        self._table.setFont(QFont("monospace", 9))
        layout.addWidget(self._table)

    def refresh(self) -> None:
        self._apply_filter()
        stats = self._history.stats()
        if stats:
            self._stats_lbl.setText(
                f"Total: {stats.get('total',0)}  ·  "
                f"Trusted: {stats.get('trusted',0)}  ·  "
                f"Blocked: {stats.get('blocked',0)}  ·  "
                f"Unknown: {stats.get('unknown',0)}"
            )

    def _apply_filter(self) -> None:
        idx = self._preset.currentIndex()
        app_name = self._app_filter.text().strip()
        if app_name:
            rows = self._history.query_by_app(app_name)
        elif idx == 0: rows = self._history.query_recent(500)
        elif idx == 1: rows = self._history.query_unknown()
        elif idx == 2: rows = self._history.query_blocked()
        elif idx == 3: rows = self._history.query_since(datetime.now() - timedelta(hours=1))
        elif idx == 4: rows = self._history.query_since(datetime.now() - timedelta(hours=24))
        else:          rows = self._history.query_recent(500)
        self._current_rows = rows
        self._populate(rows)

    def _populate(self, rows) -> None:
        self._table.setRowCount(0)
        for r_idx, row in enumerate(rows):
            self._table.insertRow(r_idx)
            is_blocked  = bool(row["is_blocked"])
            is_trusted  = bool(row["is_trusted"])
            is_pm       = bool(row["is_pkg_mgr"])
            plaintext   = row["tls_status"] == "PLAINTEXT"
            is_unid     = str(row["app_name"] or "").strip() in ("", "?", "⚠ unidentified")

            values = [
                str(row["seen_at"] or ""),
                str(row["app_name"] or "?"),
                str(row["pid"] or ""),
                str(row["iface_name"] or ""),
                f"{row['remote_host'] or row['remote_ip']}",
                str(row["remote_port"] or ""),
                "HTTP" if plaintext else ("TLS" if row["tls_status"] == "ENCRYPTED" else "?"),
                str(row["geo_flag"] or ""),
                "✓" if is_trusted else "",
                "✗" if is_blocked else "",
                "pkg" if is_pm else "",
            ]

            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
                if is_blocked:
                    item.setBackground(QBrush(QColor("#FCEBEB")))
                elif is_unid:
                    item.setBackground(QBrush(QColor("#FFF0F0")))
                elif plaintext and is_pm:
                    item.setBackground(QBrush(QColor("#FCEBEB")))
                elif is_pm:
                    item.setBackground(QBrush(QColor("#E6F1FB")))
                self._table.setItem(r_idx, col, item)
            self._table.setRowHeight(r_idx, 24)

    def _export_csv(self) -> None:
        if not self._current_rows:
            QMessageBox.information(self, "Export", "No rows to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export history to CSV",
            default_export_path("netwatch_history.csv"),
            "CSV files (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(self._current_rows[0].keys())
                for row in self._current_rows:
                    writer.writerow(list(row))
            QMessageBox.information(
                self, "Export complete",
                f"Exported {len(self._current_rows)} records to:\n{path}"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))

    def _purge(self) -> None:
        count = self._history.purge_older_than(30)
        self._stats_lbl.setText(f"Purged {count} records older than 30 days.")
        self._apply_filter()
