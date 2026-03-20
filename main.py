#!/usr/bin/env python3
"""
main.py — NetWatch entry point
"""

import os
import sys

# ── Path setup — absolute, sudo-safe ─────────────────────────────────────────
# os.path.abspath resolves relative __file__ values that sudo can produce.
# We also add the parent of wherever this file physically lives, so the
# backend/, ui/, and data/ sibling packages are always importable.

_HERE = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Belt-and-suspenders: also insert cwd in case __file__ is still ambiguous
_CWD = os.path.abspath(os.getcwd())
if _CWD not in sys.path:
    sys.path.insert(0, _CWD)

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("netwatch.main")

# ── Diagnostic (comment out once working) ────────────────────────────────────
log.info("sys.path[0:3] = %s", sys.path[:3])
log.info("_HERE = %s", _HERE)
log.info("backend exists = %s", os.path.isdir(os.path.join(_HERE, "backend")))

# ── PyQt5 import ─────────────────────────────────────────────────────────────

try:
    from PyQt5.QtWidgets import QApplication, QMessageBox
    from PyQt5.QtCore import Qt
    from PyQt5.QtGui import QFont
except ImportError:
    print("ERROR: PyQt5 is not installed.\n"
          "Install it with:  sudo apt install python3-pyqt5\n"
          "or:               pip3 install PyQt5")
    sys.exit(1)

# ── Icon (import here so path is resolved after sys.path is set) ────────────
from ui.icon_loader import app_icon

# ── Privilege check ───────────────────────────────────────────────────────────

def _check_privileges() -> bool:
    return os.geteuid() == 0


# ── Subsystem bootstrap ───────────────────────────────────────────────────────

def _init_subsystems():
    from backend import geoip
    geoip.init()

    from data.trust_store import TrustStore
    from data.history import History

    trust = TrustStore()
    hist  = History()
    return trust, hist


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("NetWatch")
    app.setWindowIcon(app_icon())       # taskbar + Alt+Tab on most desktops
    app.setOrganizationName("NetWatch")
    app.setQuitOnLastWindowClosed(False)

    font = QFont("Ubuntu", 10)
    font.setStyleHint(QFont.SansSerif)
    app.setFont(font)

    app.setStyleSheet("""
        QMainWindow, QWidget  { background: #FAFAF8; }
        QTabWidget::pane      { border: 1px solid #D3D1C7; border-radius: 4px; }
        QTabBar::tab          { padding: 6px 14px; font-size: 11px; }
        QTabBar::tab:selected { background: #FAFAF8; border-bottom: 2px solid #534AB7; }
        QStatusBar            { font-size: 10px; color: #888; }
        QLineEdit             { border: 1px solid #D3D1C7; border-radius: 4px;
                                padding: 4px 8px; background: #fff; }
        QPushButton           { border: 1px solid #D3D1C7; border-radius: 4px;
                                padding: 4px 10px; background: #fff; }
        QPushButton:hover     { background: #F1EFE8; }
        QHeaderView::section  { background: #F1EFE8; border: none;
                                border-right: 1px solid #D3D1C7;
                                padding: 4px 8px; font-size: 10px; font-weight: 600; }
        QTableView            { border: 1px solid #D3D1C7; }
        QTreeWidget           { border: 1px solid #D3D1C7; }
        QSplitter::handle     { background: #D3D1C7; width: 1px; }
    """)

    if not _check_privileges():
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("NetWatch — Insufficient privileges")
        msg.setText(
            "NetWatch requires root privileges to read network connections.\n\n"
            "Restart with:\n"
            "    sudo python3 main.py\n\n"
            "Or grant the capability permanently:\n"
            "    sudo setcap cap_net_admin+eip /usr/bin/python3"
        )
        msg.setInformativeText(
            "The application will start but connection monitoring may be empty."
        )
        msg.exec_()

    try:
        trust_store, history = _init_subsystems()
    except Exception as exc:
        log.exception("Failed to initialise subsystems")
        QMessageBox.critical(None, "NetWatch — startup error", str(exc))
        return 1

    from ui.main_window import MainWindow
    window = MainWindow(trust_store=trust_store, history=history)
    window.show()

    log.info("NetWatch started (pid=%d, euid=%d)", os.getpid(), os.geteuid())
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
