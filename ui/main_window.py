"""
ui/main_window.py — central QMainWindow.
Fixes: reliable selection → proc tree, auto-deny toggle,
       CSV export in Tools menu, light/dark theme toggle in View menu.
"""

from __future__ import annotations
import csv
import logging
import os
import time
from typing import Optional, TYPE_CHECKING

from PyQt5.QtCore import Qt, QTimer, pyqtSlot
from PyQt5.QtGui import QFont, QKeySequence
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTabWidget, QLabel, QLineEdit,
    QPushButton, QStatusBar, QAction, QMenuBar,
    QMessageBox, QFileDialog,
)

from backend.poller import Poller, ConnectionRecord
from backend.pkg_watcher import PkgEvent
from backend import ufw as ufw_backend
from data.trust_store import TrustStore
from data.history import History
import backend.geoip as geoip

from ui.conn_table import ConnectionTableView
from ui.proc_tree import ProcessTreePanel
from ui.repo_panel import RepoPanel
from ui.history_view import HistoryView
from ui.notif_tray import NotifTray

log = logging.getLogger(__name__)

# ── Stylesheets ───────────────────────────────────────────────────────────────

_LIGHT_STYLE = """
    QMainWindow, QWidget        { background: #FAFAF8; color: #1a1a1a; }
    QTabWidget::pane            { border: 1px solid #D3D1C7; border-radius: 4px; }
    QTabBar::tab                { padding: 6px 14px; font-size: 11px;
                                  background: #F1EFE8; color: #1a1a1a; }
    QTabBar::tab:selected       { background: #FAFAF8; color: #1a1a1a;
                                  border-bottom: 2px solid #534AB7; }
    QTabBar::tab:hover          { background: #E8E6DF; color: #1a1a1a; }
    QStatusBar                  { font-size: 10px; color: #666; background: #F1EFE8; }
    QLineEdit                   { border: 1px solid #D3D1C7; border-radius: 4px;
                                  padding: 4px 8px; background: #fff; color: #1a1a1a; }
    QPushButton                 { border: 1px solid #D3D1C7; border-radius: 4px;
                                  padding: 4px 10px; background: #fff; color: #1a1a1a; }
    QPushButton:hover           { background: #F1EFE8; color: #1a1a1a; }
    QPushButton:disabled        { color: #aaa; border-color: #ddd; background: #f5f5f5; }
    QHeaderView::section        { background: #F1EFE8; color: #1a1a1a; border: none;
                                  border-right: 1px solid #D3D1C7;
                                  padding: 4px 8px; font-size: 10px; font-weight: 600; }
    QTableView                  { border: 1px solid #D3D1C7; color: #1a1a1a;
                                  background: #fff; alternate-background-color: #F8F8F5; }
    QTableView::item:selected   { background: #C8D8F8; color: #1a1a1a; }
    QTreeWidget                 { border: 1px solid #D3D1C7; color: #1a1a1a; background: #fff; }
    QTreeWidget::item:selected  { background: #C8D8F8; color: #1a1a1a; }
    QSplitter::handle           { background: #D3D1C7; width: 1px; }
    QMenuBar                    { background: #F1EFE8; color: #1a1a1a; }
    QMenuBar::item:selected     { background: #D3D1C7; color: #1a1a1a; }
    QMenu                       { background: #FAFAF8; color: #1a1a1a;
                                  border: 1px solid #D3D1C7; }
    QMenu::item:selected        { background: #C8D8F8; color: #1a1a1a; }
    QScrollBar:vertical         { background: #F1EFE8; width: 10px; }
    QScrollBar::handle:vertical { background: #B4B2A9; border-radius: 5px; }
"""

_DARK_STYLE = """
    QMainWindow, QWidget        { background: #1e1e2e; color: #cdd6f4; }
    QTabWidget::pane            { border: 1px solid #45475a; border-radius: 4px; }
    QTabBar::tab                { padding: 6px 14px; font-size: 11px;
                                  background: #313244; color: #cdd6f4; }
    QTabBar::tab:selected       { background: #1e1e2e; color: #cdd6f4;
                                  border-bottom: 2px solid #89b4fa; }
    QTabBar::tab:hover          { background: #45475a; color: #cdd6f4; }
    QStatusBar                  { font-size: 10px; color: #a6adc8; background: #181825; }
    QLineEdit                   { border: 1px solid #45475a; border-radius: 4px;
                                  padding: 4px 8px; background: #313244; color: #cdd6f4; }
    QPushButton                 { border: 1px solid #45475a; border-radius: 4px;
                                  padding: 4px 10px; background: #313244; color: #cdd6f4; }
    QPushButton:hover           { background: #45475a; color: #cdd6f4; }
    QPushButton:disabled        { color: #585b70; border-color: #45475a; background: #1e1e2e; }
    QHeaderView::section        { background: #181825; color: #a6adc8; border: none;
                                  border-right: 1px solid #45475a;
                                  padding: 4px 8px; font-size: 10px; font-weight: 600; }
    QTableView                  { border: 1px solid #45475a; color: #cdd6f4;
                                  background: #1e1e2e; alternate-background-color: #252535;
                                  gridline-color: #45475a; }
    QTableView::item:selected   { background: #45475a; color: #cdd6f4; }
    QTreeWidget                 { border: 1px solid #45475a; color: #cdd6f4;
                                  background: #1e1e2e; }
    QTreeWidget::item:selected  { background: #45475a; color: #cdd6f4; }
    QSplitter::handle           { background: #45475a; width: 1px; }
    QMenuBar                    { background: #181825; color: #cdd6f4; }
    QMenuBar::item:selected     { background: #45475a; color: #cdd6f4; }
    QMenu                       { background: #1e1e2e; color: #cdd6f4;
                                  border: 1px solid #45475a; }
    QMenu::item:selected        { background: #45475a; color: #cdd6f4; }
    QScrollBar:vertical         { background: #181825; width: 10px; }
    QScrollBar::handle:vertical { background: #585b70; border-radius: 5px; }
    QLabel                      { color: #cdd6f4; }
    QTextEdit                   { background: #1e1e2e; color: #cdd6f4;
                                  border: 1px solid #45475a; }
    QComboBox                   { background: #313244; color: #cdd6f4;
                                  border: 1px solid #45475a; border-radius: 4px; padding: 3px 8px; }
    QComboBox QAbstractItemView { background: #1e1e2e; color: #cdd6f4; }
"""


class MainWindow(QMainWindow):

    def __init__(self, trust_store: TrustStore, history: History,
                 poll_interval: int = 5):
        super().__init__()
        self._trust_store = trust_store
        self._history = history
        self._current_records: list[ConnectionRecord] = []
        self._alerted_unknowns: set[str] = set()
        self._dark_mode = False

        self._build_ui()
        self._build_menu()
        self._build_statusbar()
        self._start_poller(poll_interval)
        self._setup_tray()

        # Apply initial light theme
        self._apply_theme(dark=False)

        QTimer.singleShot(500, self._poller.start)

    # ── UI construction ──────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.setWindowTitle("NetWatch — Live Connection Monitor")
        self.resize(1280, 780)
        self.setMinimumSize(900, 600)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(6, 6, 6, 4)
        root.setSpacing(4)

        self._tabs = QTabWidget()
        self._tabs.currentChanged.connect(self._on_tab_changed)

        live_widget = self._build_live_tab()
        self._tabs.addTab(live_widget, "Live connections")

        self._history_view = HistoryView(self._history)
        self._tabs.addTab(self._history_view, "History log")

        self._repo_panel = RepoPanel()
        self._tabs.addTab(self._repo_panel, "Repo integrity")

        root.addWidget(self._tabs)

    def _build_live_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(4)

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(4, 0, 4, 0)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter by app, port, IP, or country…")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._on_filter_changed)
        toolbar.addWidget(self._search, stretch=1)

        self._interval_btn = QPushButton("Refresh: 5s")
        self._interval_btn.clicked.connect(self._cycle_interval)
        toolbar.addWidget(self._interval_btn)

        self._auto_deny_btn = QPushButton("Auto-deny: ON")
        self._auto_deny_btn.setCheckable(True)
        self._auto_deny_btn.setChecked(True)
        self._auto_deny_btn.setToolTip(
            "When ON: connections with no identifiable process are automatically\n"
            "blocked via UFW and flagged red. Toggle to disable."
        )
        self._auto_deny_btn.clicked.connect(self._on_auto_deny_toggled)
        toolbar.addWidget(self._auto_deny_btn)

        self._block_btn = QPushButton("Block selected")
        self._block_btn.setEnabled(False)
        self._block_btn.clicked.connect(self._on_block_selected)
        toolbar.addWidget(self._block_btn)

        layout.addLayout(toolbar)

        splitter = QSplitter(Qt.Horizontal)

        self._table = ConnectionTableView()
        # ── KEY FIX: connect to the table's own record_selected signal ──
        self._table.record_selected.connect(self._on_record_selected)
        splitter.addWidget(self._table)

        self._proc_tree = ProcessTreePanel()
        self._proc_tree.trust_requested.connect(self._on_trust_requested)
        self._proc_tree.block_requested.connect(self._on_block_record)
        self._proc_tree.setMinimumWidth(220)
        self._proc_tree.setMaximumWidth(360)
        splitter.addWidget(self._proc_tree)

        splitter.setSizes([920, 320])
        layout.addWidget(splitter, stretch=1)
        return w

    def _build_menu(self) -> None:
        mb = self.menuBar()

        # File
        file_menu = mb.addMenu("File")
        quit_action = QAction("Quit", self)
        quit_action.setShortcut(QKeySequence.Quit)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        # View  ← new
        view_menu = mb.addMenu("View")
        self._theme_action = QAction("Switch to dark theme", self)
        self._theme_action.triggered.connect(self._toggle_theme)
        view_menu.addAction(self._theme_action)

        # Tools
        tools_menu = mb.addMenu("Tools")

        scan_repos = QAction("Scan repositories now", self)
        scan_repos.triggered.connect(lambda: (
            self._tabs.setCurrentIndex(2), self._repo_panel.refresh()
        ))
        tools_menu.addAction(scan_repos)

        ufw_status = QAction("UFW status…", self)
        ufw_status.triggered.connect(self._show_ufw_status)
        tools_menu.addAction(ufw_status)

        tools_menu.addSeparator()

        export_action = QAction("Export history to CSV…", self)
        export_action.triggered.connect(self._export_history_csv)
        tools_menu.addAction(export_action)

        purge_hist = QAction("Purge history > 30d", self)
        purge_hist.triggered.connect(lambda: self._history.purge_older_than(30))
        tools_menu.addAction(purge_hist)

    def _build_statusbar(self) -> None:
        sb = QStatusBar()
        self.setStatusBar(sb)
        self._sb_connections = QLabel("Waiting…")
        self._sb_ufw         = QLabel("")
        self._sb_iface       = QLabel("")
        self._sb_last        = QLabel("")
        for lbl in [self._sb_connections, self._sb_iface,
                    self._sb_ufw, self._sb_last]:
            lbl.setStyleSheet("font-size: 10px; padding: 0 6px;")
            sb.addWidget(lbl)
        QTimer.singleShot(1000, self._update_ufw_status)

    # ── Poller & Tray ────────────────────────────────────────────────────

    def _start_poller(self, interval: int) -> None:
        self._poll_interval = interval
        self._poller = Poller(
            trust_store=self._trust_store,
            history=self._history,
            interval_sec=interval,
            auto_deny_unidentified=True,
        )
        self._poller.connections_updated.connect(self._on_connections)
        self._poller.pkg_alert.connect(self._on_pkg_alert)
        self._poller.dns_resolved.connect(self._on_dns_resolved)
        self._poller.auto_deny_applied.connect(self._on_auto_deny_applied)
        self._poller.error.connect(self._on_poller_error)

    def _setup_tray(self) -> None:
        self._tray = NotifTray(self)
        if NotifTray.isSystemTrayAvailable():
            self._tray.show()

    # ── Theme ────────────────────────────────────────────────────────────

    def _apply_theme(self, dark: bool) -> None:
        from PyQt5.QtWidgets import QApplication
        self._dark_mode = dark
        QApplication.instance().setStyleSheet(
            _DARK_STYLE if dark else _LIGHT_STYLE
        )
        self._theme_action.setText(
            "Switch to light theme" if dark else "Switch to dark theme"
        )

    def _toggle_theme(self) -> None:
        self._apply_theme(not self._dark_mode)

    # ── Slots ─────────────────────────────────────────────────────────────

    @pyqtSlot(list)
    def _on_connections(self, records: list) -> None:
        self._current_records = records
        self._table.refresh(records)

        for rec in records:
            if not rec.is_trusted and not rec.is_blocked and rec.app_exe:
                if rec.app_exe not in self._alerted_unknowns:
                    self._alerted_unknowns.add(rec.app_exe)
                    self._tray.alert_unknown(rec.app_name, rec.remote_display)

        n_unknown  = sum(1 for r in records if not r.is_trusted and not r.is_blocked)
        n_trusted  = sum(1 for r in records if r.is_trusted)
        n_blocked  = sum(1 for r in records if r.is_blocked)
        n_unid     = sum(1 for r in records if r.is_unidentified)

        self._sb_connections.setText(
            f"{len(records)} connections  ·  "
            f"{n_trusted} trusted  ·  {n_unknown} unknown  ·  "
            f"{n_blocked} blocked"
            + (f"  ·  {n_unid} unidentified ⚠" if n_unid else "")
        )
        self._tray.set_status(len(records), n_unknown)

        wifi_count = sum(1 for r in records if r.is_wifi)
        vpn_count  = sum(1 for r in records if r.is_vpn)
        parts = []
        if wifi_count: parts.append(f"{wifi_count} via WiFi")
        if vpn_count:  parts.append(f"{vpn_count} via VPN")
        self._sb_iface.setText("  ·  ".join(parts))
        self._sb_last.setText(f"Last poll: {time.strftime('%H:%M:%S')}")

    @pyqtSlot(object)
    def _on_record_selected(self, rec) -> None:
        """Fired by ConnectionTableView.record_selected — always reliable."""
        self._proc_tree.show_record(rec)
        self._block_btn.setEnabled(
            rec is not None and not rec.is_blocked and not rec.auto_denied
        )

    @pyqtSlot(object)
    def _on_auto_deny_applied(self, rec) -> None:
        self.statusBar().showMessage(
            f"Auto-denied: unidentified connection to "
            f"{rec.remote_ip}:{rec.remote_port}", 6000
        )

    @pyqtSlot(object)
    def _on_pkg_alert(self, event: PkgEvent) -> None:
        log.warning("pkg alert: %s", event.message)
        self._tray.alert_pkg(event)

    @pyqtSlot(str, str)
    def _on_dns_resolved(self, ip: str, hostname: str) -> None:
        self._table.update_hostname(ip, hostname)

    @pyqtSlot(str)
    def _on_poller_error(self, msg: str) -> None:
        self._sb_connections.setText(f"⚠ {msg}")

    def _on_filter_changed(self, text: str) -> None:
        self._table.set_filter(text)

    def _on_tab_changed(self, idx: int) -> None:
        if idx == 1: self._history_view.refresh()
        elif idx == 2: self._repo_panel.refresh()

    def _on_auto_deny_toggled(self, checked: bool) -> None:
        self._poller.set_auto_deny(checked)
        self._auto_deny_btn.setText(
            "Auto-deny: ON" if checked else "Auto-deny: OFF"
        )
        self.statusBar().showMessage(
            "Auto-deny enabled — unidentified connections will be blocked automatically."
            if checked else
            "Auto-deny disabled — unidentified connections will be flagged only.",
            4000
        )

    # ── Trust / Block ─────────────────────────────────────────────────────

    @pyqtSlot(str)
    def _on_trust_requested(self, exe: str) -> None:
        name = os.path.basename(exe)
        self._trust_store.trust_exe(exe, name)
        log.info("trusted: %s", exe)
        self.statusBar().showMessage(f"Trusted: {name}", 3000)

    @pyqtSlot(object)
    def _on_block_record(self, rec) -> None:
        self._block_connection(rec)

    def _on_block_selected(self) -> None:
        rec = self._table.selected_record()
        if rec:
            self._block_connection(rec)

    def _block_connection(self, rec) -> None:
        reply = QMessageBox.question(
            self, "Block connection",
            f"Block all outbound traffic to\n"
            f"{rec.remote_ip}:{rec.remote_port} ({rec.remote_display})?\n\n"
            f"App: {rec.app_name}\n"
            f"This will apply a UFW deny rule.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        result = ufw_backend.block_outbound(
            rec.remote_ip, rec.remote_port, rec.proto.lower()
        )
        self._trust_store.block_ip_port(
            remote_ip=rec.remote_ip,
            remote_port=rec.remote_port,
            proto=rec.proto.lower(),
            reason=f"Blocked via NetWatch — {rec.app_name}",
            ufw_applied=result.success,
        )
        if result.success:
            self.statusBar().showMessage(
                f"Blocked {rec.remote_ip}:{rec.remote_port} (UFW rule applied)", 5000
            )
        else:
            QMessageBox.warning(
                self, "UFW error",
                f"Rule saved locally but UFW command failed:\n{result.stderr}\n\n"
                f"Manual command:\n{result.command}"
            )

    # ── CSV Export ────────────────────────────────────────────────────────

    def _export_history_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export history to CSV",
            os.path.expanduser("~/netwatch_history.csv"),
            "CSV files (*.csv)"
        )
        if not path:
            return
        try:
            rows = self._history.query_recent(10000)
            if not rows:
                QMessageBox.information(self, "Export", "No history records to export.")
                return
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(rows[0].keys())
                for row in rows:
                    writer.writerow(list(row))
            self.statusBar().showMessage(
                f"Exported {len(rows)} records to {path}", 5000
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))

    # ── Interval cycling ─────────────────────────────────────────────────

    _INTERVALS = [2, 5, 10, 30]

    def _cycle_interval(self) -> None:
        current = self._poll_interval
        next_i = self._INTERVALS[
            (self._INTERVALS.index(current) + 1) % len(self._INTERVALS)
            if current in self._INTERVALS else 0
        ]
        self._poll_interval = next_i
        self._poller.set_interval(next_i)
        self._interval_btn.setText(f"Refresh: {next_i}s")

    # ── Helpers ───────────────────────────────────────────────────────────

    def _update_ufw_status(self) -> None:
        active, _ = ufw_backend.ufw_status()
        self._sb_ufw.setText("UFW: active" if active else "UFW: inactive ⚠")

    def _show_ufw_status(self) -> None:
        _, text = ufw_backend.ufw_status()
        QMessageBox.information(self, "UFW status", text or "Could not read UFW status.")

    def closeEvent(self, event) -> None:
        self._poller.stop()
        self._poller.wait(3000)
        event.accept()
