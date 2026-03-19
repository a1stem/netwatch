"""
ui/main_window.py
-----------------
Central QMainWindow.  Owns the poller thread, the trust store, the history
log, and all UI panels.  Wires all signals and slots together.
"""

from __future__ import annotations
import logging
from typing import Optional, TYPE_CHECKING

from PyQt5.QtCore import Qt, QTimer, pyqtSlot
from PyQt5.QtGui import QFont, QKeySequence
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTabWidget, QLabel, QLineEdit,
    QPushButton, QStatusBar, QAction, QMenuBar,
    QMessageBox, QShortcut,
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


class MainWindow(QMainWindow):

    def __init__(
        self,
        trust_store: TrustStore,
        history: History,
        poll_interval: int = 5,
    ):
        super().__init__()
        self._trust_store = trust_store
        self._history = history
        self._current_records: list[ConnectionRecord] = []

        # Track previously-seen unknown exes so we only alert once per session
        self._alerted_unknowns: set[str] = set()

        self._build_ui()
        self._build_menu()
        self._build_statusbar()
        self._start_poller(poll_interval)
        self._setup_tray()

        # Force an immediate poll
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

        # ── Tab widget ──────────────────────────────────────────────────
        self._tabs = QTabWidget()
        self._tabs.currentChanged.connect(self._on_tab_changed)

        # Tab 0: Live connections
        live_widget = self._build_live_tab()
        self._tabs.addTab(live_widget, "Live connections")

        # Tab 1: History log
        self._history_view = HistoryView(self._history)
        self._tabs.addTab(self._history_view, "History log")

        # Tab 2: Repo integrity
        self._repo_panel = RepoPanel()
        self._tabs.addTab(self._repo_panel, "Repo integrity")

        root.addWidget(self._tabs)

    def _build_live_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(4)

        # ── Toolbar ─────────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(4, 0, 4, 0)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter by app, port, IP, or country…")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._on_filter_changed)
        toolbar.addWidget(self._search, stretch=1)

        self._interval_btn = QPushButton("Refresh: 5s")
        self._interval_btn.setCheckable(False)
        self._interval_btn.clicked.connect(self._cycle_interval)
        toolbar.addWidget(self._interval_btn)

        self._block_btn = QPushButton("Block selected")
        self._block_btn.setEnabled(False)
        self._block_btn.setStyleSheet(
            "QPushButton { color: #A32D2D; border: 1px solid #A32D2D; "
            "border-radius: 4px; padding: 4px 10px; }"
            "QPushButton:hover { background: #FCEBEB; }"
            "QPushButton:disabled { color: #bbb; border-color: #ddd; }"
        )
        self._block_btn.clicked.connect(self._on_block_selected)
        toolbar.addWidget(self._block_btn)

        layout.addLayout(toolbar)

        # ── Main splitter: table | process tree ─────────────────────────
        splitter = QSplitter(Qt.Horizontal)

        self._table = ConnectionTableView()
        self._table.selectionModel().selectionChanged.connect(
            self._on_selection_changed
        )
        splitter.addWidget(self._table)

        self._proc_tree = ProcessTreePanel()
        self._proc_tree.trust_requested.connect(self._on_trust_requested)
        self._proc_tree.block_requested.connect(self._on_block_record)
        self._proc_tree.setMinimumWidth(220)
        self._proc_tree.setMaximumWidth(340)
        splitter.addWidget(self._proc_tree)

        splitter.setSizes([950, 280])
        layout.addWidget(splitter, stretch=1)

        return w

    def _build_menu(self) -> None:
        mb = self.menuBar()

        # File menu
        file_menu = mb.addMenu("File")
        quit_action = QAction("Quit", self)
        quit_action.setShortcut(QKeySequence.Quit)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        # Tools menu
        tools_menu = mb.addMenu("Tools")
        scan_repos = QAction("Scan repositories now", self)
        scan_repos.triggered.connect(lambda: (
            self._tabs.setCurrentIndex(2),
            self._repo_panel.refresh()
        ))
        tools_menu.addAction(scan_repos)

        ufw_status = QAction("UFW status…", self)
        ufw_status.triggered.connect(self._show_ufw_status)
        tools_menu.addAction(ufw_status)

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
            lbl.setStyleSheet("font-size: 10px; color: #666; padding: 0 6px;")
            sb.addWidget(lbl)

        # UFW status check on startup
        QTimer.singleShot(1000, self._update_ufw_status)

    # ── Poller & Tray ────────────────────────────────────────────────────

    def _start_poller(self, interval: int) -> None:
        self._poll_interval = interval
        self._poller = Poller(
            trust_store=self._trust_store,
            history=self._history,
            interval_sec=interval,
        )
        self._poller.connections_updated.connect(self._on_connections)
        self._poller.pkg_alert.connect(self._on_pkg_alert)
        self._poller.dns_resolved.connect(self._on_dns_resolved)
        self._poller.error.connect(self._on_poller_error)

    def _setup_tray(self) -> None:
        self._tray = NotifTray(self)
        if NotifTray.isSystemTrayAvailable():
            self._tray.show()

    # ── Slots ─────────────────────────────────────────────────────────────

    @pyqtSlot(list)
    def _on_connections(self, records: list[ConnectionRecord]) -> None:
        self._current_records = records
        self._table.refresh(records)

        # Alert on new unknowns
        for rec in records:
            if not rec.is_trusted and not rec.is_blocked and rec.app_exe:
                if rec.app_exe not in self._alerted_unknowns:
                    self._alerted_unknowns.add(rec.app_exe)
                    self._tray.alert_unknown(rec.app_name, rec.remote_display)

        # Status bar
        n_unknown = sum(1 for r in records
                        if not r.is_trusted and not r.is_blocked)
        n_trusted = sum(1 for r in records if r.is_trusted)
        n_blocked = sum(1 for r in records if r.is_blocked)
        self._sb_connections.setText(
            f"{len(records)} connections  ·  "
            f"{n_trusted} trusted  ·  {n_unknown} unknown  ·  {n_blocked} blocked"
        )
        self._tray.set_status(len(records), n_unknown)

        # Interface summary
        wifi_count = sum(1 for r in records if r.is_wifi)
        vpn_count  = sum(1 for r in records if r.is_vpn)
        iface_parts = []
        if wifi_count:
            iface_parts.append(f"{wifi_count} via WiFi")
        if vpn_count:
            iface_parts.append(f"{vpn_count} via VPN")
        self._sb_iface.setText("  ·  ".join(iface_parts))

        import time
        self._sb_last.setText(
            f"Last poll: {time.strftime('%H:%M:%S')}"
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
        self._sb_connections.setStyleSheet("font-size: 10px; color: #A32D2D; padding: 0 6px;")

    def _on_selection_changed(self) -> None:
        rec = self._table.selected_record()
        self._proc_tree.show_record(rec)
        self._block_btn.setEnabled(rec is not None and not rec.is_blocked)

    def _on_filter_changed(self, text: str) -> None:
        self._table.set_filter(text)

    def _on_tab_changed(self, idx: int) -> None:
        if idx == 1:
            self._history_view.refresh()
        elif idx == 2:
            self._repo_panel.refresh()

    # ── Trust / Block actions ─────────────────────────────────────────────

    @pyqtSlot(str)
    def _on_trust_requested(self, exe: str) -> None:
        import os
        name = os.path.basename(exe)
        self._trust_store.trust_exe(exe, name)
        log.info("trusted: %s", exe)
        self.statusBar().showMessage(f"Trusted: {name}", 3000)

    @pyqtSlot(object)
    def _on_block_record(self, rec: ConnectionRecord) -> None:
        self._block_connection(rec)

    def _on_block_selected(self) -> None:
        rec = self._table.selected_record()
        if rec:
            self._block_connection(rec)

    def _block_connection(self, rec: ConnectionRecord) -> None:
        reply = QMessageBox.question(
            self,
            "Block connection",
            f"Block all outbound traffic to\n"
            f"{rec.remote_ip}:{rec.remote_port} ({rec.remote_display})?\n\n"
            f"This will apply a UFW deny rule.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        result = ufw_backend.block_outbound(rec.remote_ip, rec.remote_port, rec.proto.lower())
        ufw_ok = result.success

        self._trust_store.block_ip_port(
            remote_ip=rec.remote_ip,
            remote_port=rec.remote_port,
            proto=rec.proto.lower(),
            reason=f"Blocked via NetWatch — {rec.app_name}",
            ufw_applied=ufw_ok,
        )

        if ufw_ok:
            self.statusBar().showMessage(
                f"Blocked {rec.remote_ip}:{rec.remote_port} (UFW rule applied)", 5000
            )
        else:
            QMessageBox.warning(
                self, "UFW error",
                f"Rule saved locally but UFW command failed:\n{result.stderr}\n\n"
                f"You may need to apply the rule manually:\n{result.command}"
            )

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
        color = "#3B6D11" if active else "#A32D2D"
        self._sb_ufw.setStyleSheet(
            f"font-size: 10px; color: {color}; padding: 0 6px;"
        )

    def _show_ufw_status(self) -> None:
        _, text = ufw_backend.ufw_status()
        QMessageBox.information(self, "UFW status", text or "Could not read UFW status.")

    # ── Window close ─────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:
        self._poller.stop()
        self._poller.wait(3000)
        event.accept()
