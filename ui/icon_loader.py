"""
ui/icon_loader.py
-----------------
Single source of truth for the NetWatch application icon.

Loads assets/netwatch_logo.svg and rasterises it at multiple sizes
so Qt can pick the sharpest version for each context:
  - 16x16  system tray (small notification area)
  - 22x22  system tray (HiDPI / larger panels)
  - 32x32  taskbar / window list
  - 48x48  Alt+Tab switcher / task manager
  - 64x64  large application list
  - 128x128 app launcher / Wayland dock
  - 256x256 retina / file manager

Falls back to a painted "N" circle if the SVG file is missing or
if the SVG renderer is unavailable, so the app always opens cleanly.

Usage (anywhere in the codebase):
    from ui.icon_loader import app_icon, tray_icon_normal, tray_icon_alert
"""

from __future__ import annotations
import os
import logging
from functools import lru_cache
from typing import Optional

from PyQt5.QtCore import Qt, QSize, QRectF
from PyQt5.QtGui import (
    QIcon, QPixmap, QColor, QPainter, QFont, QImage
)
from PyQt5.QtSvg import QSvgRenderer

log = logging.getLogger(__name__)

# Path to the SVG — relative to this file's location (ui/ → assets/)
_SVG_PATH = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "..", "assets", "netwatch_logo.svg")
)

# Sizes to rasterise for the full application icon
_APP_SIZES = [16, 22, 32, 48, 64, 128, 256]

# Tray icon is always square, rendered at these sizes
_TRAY_SIZES = [16, 22, 32]


def _svg_to_pixmap(svg_path: str, size: int) -> Optional[QPixmap]:
    """Render an SVG file to a QPixmap at the given square pixel size."""
    try:
        renderer = QSvgRenderer(svg_path)
        if not renderer.isValid():
            log.warning("icon_loader: SVG renderer rejected %s", svg_path)
            return None
        img = QImage(size, size, QImage.Format_ARGB32_Premultiplied)
        img.fill(Qt.transparent)
        painter = QPainter(img)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setRenderHint(QPainter.SmoothPixmapTransform)
        renderer.render(painter, QRectF(0, 0, size, size))
        painter.end()
        return QPixmap.fromImage(img)
    except Exception as exc:
        log.warning("icon_loader: failed to render SVG at %dpx: %s", size, exc)
        return None


def _painted_fallback(size: int, color: str = "#185FA5",
                      badge: int = 0) -> QPixmap:
    """
    Paint a simple 'N' circle as fallback when the SVG is unavailable.
    Identical logic to the original _make_icon() in notif_tray.py.
    """
    px = QPixmap(size, size)
    px.fill(QColor(0, 0, 0, 0))
    p = QPainter(px)
    p.setRenderHint(QPainter.Antialiasing)

    margin = max(1, size // 20)
    p.setBrush(QColor(color))
    p.setPen(QColor("#ffffff"))
    p.drawEllipse(margin, margin, size - margin * 2, size - margin * 2)

    font_size = max(6, int(size * 0.45))
    p.setFont(QFont("sans-serif", font_size, QFont.Bold))
    p.drawText(px.rect(), Qt.AlignCenter, "N")

    if badge > 0:
        b = max(6, size // 3)
        p.setBrush(QColor("#A32D2D"))
        p.setPen(QColor("#ffffff"))
        p.drawEllipse(size - b, 0, b, b)
        p.setFont(QFont("sans-serif", max(4, b // 2), QFont.Bold))
        p.drawText(size - b, 0, b, b, Qt.AlignCenter, str(min(badge, 99)))

    p.end()
    return px


@lru_cache(maxsize=1)
def app_icon() -> QIcon:
    """
    Full multi-resolution QIcon for the main window and taskbar.
    Qt automatically selects the best size for each display context.

    Call QApplication.setWindowIcon(app_icon()) once in main.py,
    and setWindowIcon(app_icon()) on the QMainWindow — both are needed
    for the taskbar entry AND the window title bar / Alt+Tab to work.
    """
    icon = QIcon()
    svg_available = os.path.isfile(_SVG_PATH)

    if not svg_available:
        log.info("icon_loader: SVG not found at %s — using painted fallback", _SVG_PATH)

    for size in _APP_SIZES:
        if svg_available:
            px = _svg_to_pixmap(_SVG_PATH, size)
        else:
            px = None

        if px is None:
            px = _painted_fallback(size)

        icon.addPixmap(px, QIcon.Normal, QIcon.Off)

    return icon


def tray_icon(color: str = "#185FA5", badge: int = 0) -> QIcon:
    """
    Icon for the system tray.  When the SVG is available, renders a
    cropped version of it at tray sizes.  Falls back to the painted circle.

    For alert states, always uses the painted circle (red with badge)
    so the alert is visually distinct from the normal logo.
    """
    icon = QIcon()
    svg_available = os.path.isfile(_SVG_PATH) and badge == 0 and color == "#185FA5"

    for size in _TRAY_SIZES:
        if svg_available:
            px = _svg_to_pixmap(_SVG_PATH, size)
        else:
            px = None

        if px is None:
            px = _painted_fallback(size, color, badge)

        icon.addPixmap(px, QIcon.Normal, QIcon.Off)

    return icon


def tray_icon_normal() -> QIcon:
    return tray_icon("#185FA5", 0)


def tray_icon_alert(badge: int = 1) -> QIcon:
    return tray_icon("#A32D2D", badge)


def tray_icon_warn(badge: int = 1) -> QIcon:
    return tray_icon("#BA7517", badge)
