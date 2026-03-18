"""
ui/notif_tray.py
----------------
System tray icon with alert badge and desktop notifications.
Fires a QSystemTrayIcon.showMessage() for high-risk events.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QIcon, QPixmap, QColor, QPainter, QFont
from PyQt5.QtWidgets import (
    QSystemTrayIcon, QMenu, QAction, QApplication,
)

if TYPE_CHECKING:
    from backend.pkg_watcher import PkgEvent


def _make_icon(color: str = "#185FA5", badge: int = 0) -> QIcon:
    """Render a simple coloured circle icon with optional red badge count."""
    px = QPixmap(22, 22)
    px.fill(QColor(0, 0, 0, 0))
    p = QPainter(px)
    p.setRenderHint(QPainter.Antialiasing)

    # Main circle
    p.setBrush(QColor(color))
    p.setPen(QColor("#ffffff"))
    p.drawEllipse(1, 1, 20, 20)

    # Letter N
    p.setFont(QFont("sans-serif", 9, QFont.Bold))
    p.drawText(px.rect(), 0x84, "N")   # AlignCenter = 0x84

    # Badge
    if badge > 0:
        p.setBrush(QColor("#A32D2D"))
        p.setPen(QColor("#ffffff"))
        p.drawEllipse(13, 0, 9, 9)
        p.setFont(QFont("sans-serif", 6, QFont.Bold))
        p.drawText(13, 0, 9, 9, 0x84, str(min(badge, 99)))

    p.end()
    return QIcon(px)


class NotifTray(QSystemTrayIcon):
    """
    System tray icon for NetWatch.

    Usage:
        tray = NotifTray(main_window)
        tray.show()
        tray.alert_pkg(pkg_event)
    """

    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window
        self._alert_count = 0
        self._icon_normal = _make_icon("#185FA5")
        self._icon_alert  = _make_icon("#A32D2D")

        self.setIcon(self._icon_normal)
        self.setToolTip("NetWatch — monitoring")

        # Context menu
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

        # Auto-reset alert icon after 60s
        self._reset_timer = QTimer(self)
        self._reset_timer.setSingleShot(True)
        self._reset_timer.timeout.connect(self._reset_icon)

    # ── Public API ───────────────────────────────────────────────────────

    def alert_pkg(self, event: "PkgEvent") -> None:
        """Show a desktop notification for a high-risk package manager event."""
        self._alert_count += 1
        self.setIcon(_make_icon("#A32D2D", self._alert_count))
        self.showMessage(
            "NetWatch — Package update alert",
            event.message,
            QSystemTrayIcon.Critical,
            8000,
        )
        self._reset_timer.start(60_000)

    def alert_unknown(self, app_name: str, remote: str) -> None:
        """Notify when a new unknown app makes its first connection."""
        self._alert_count += 1
        self.setIcon(_make_icon("#BA7517", self._alert_count))
        self.showMessage(
            "NetWatch — Unknown connection",
            f"'{app_name}' connected to {remote}\n"
            "Open NetWatch to trust or block this app.",
            QSystemTrayIcon.Warning,
            6000,
        )
        self._reset_timer.start(60_000)

    def set_status(self, n_connections: int, n_unknown: int) -> None:
        """Update tooltip with current counts."""
        self.setToolTip(
            f"NetWatch  —  {n_connections} connections  ·  {n_unknown} unknown"
        )

    # ── Private ──────────────────────────────────────────────────────────

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
        self.setIcon(self._icon_normal)
