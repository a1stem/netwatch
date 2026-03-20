"""
ui/notif_tray.py
----------------
System tray icon using the shared icon_loader for the NetWatch SVG logo.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QSystemTrayIcon, QMenu, QAction, QApplication

from ui.icon_loader import tray_icon_normal, tray_icon_alert, tray_icon_warn

if TYPE_CHECKING:
    from backend.pkg_watcher import PkgEvent


class NotifTray(QSystemTrayIcon):

    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window
        self._alert_count = 0

        # Use SVG-based icons from the shared loader
        self.setIcon(tray_icon_normal())
        self.setToolTip("NetWatch — monitoring")

        menu = QMenu()
        show_action = QAction("Show NetWatch", self)
        show_action.triggered.connect(self._show_window)
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(QApplication.quit)
        menu.addAction(show_action)
        menu.addSeparator()
        menu.addAction(quit_action)
        self.setContextMenu(menu)

        self.activated.connect(self._on_activated)

        self._reset_timer = QTimer(self)
        self._reset_timer.setSingleShot(True)
        self._reset_timer.timeout.connect(self._reset_icon)

    # ── Public API ────────────────────────────────────────────────────────

    def alert_pkg(self, event: "PkgEvent") -> None:
        self._alert_count += 1
        self.setIcon(tray_icon_alert(self._alert_count))
        self.showMessage(
            "NetWatch — Package update alert",
            event.message,
            QSystemTrayIcon.Critical,
            8000,
        )
        self._reset_timer.start(60_000)

    def alert_unknown(self, app_name: str, remote: str) -> None:
        self._alert_count += 1
        self.setIcon(tray_icon_warn(self._alert_count))
        self.showMessage(
            "NetWatch — Unknown connection",
            f"'{app_name}' connected to {remote}\n"
            "Open NetWatch to trust or block this app.",
            QSystemTrayIcon.Warning,
            6000,
        )
        self._reset_timer.start(60_000)

    def set_status(self, n_connections: int, n_unknown: int) -> None:
        self.setToolTip(
            f"NetWatch  —  {n_connections} connections  ·  {n_unknown} unknown"
        )

    # ── Private ───────────────────────────────────────────────────────────

    def _show_window(self) -> None:
        self._main_window.showNormal()
        self._main_window.raise_()
        self._main_window.activateWindow()

    def _on_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.Trigger:
            if self._main_window.isVisible():
                self._main_window.hide()
            else:
                self._show_window()

    def _reset_icon(self) -> None:
        self._alert_count = 0
        self.setIcon(tray_icon_normal())
