#!/usr/bin/env python3
"""
main.py — NetWatch entry point
-------------------------------
Checks for necessary privileges, initialises all subsystems,
and launches the PyQt5 application.

Run with:
    sudo python3 main.py
or (recommended):
    pkexec python3 /full/path/to/netwatch/main.py
"""

import logging
import os
import sys

# ── Logging setup (before any imports that log) ─────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("netwatch.main")

# ── Path setup ───────────────────────────────────────────────────────────────

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

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

# ── Privilege check ───────────────────────────────────────────────────────────

def _check_privileges() -> bool:
    """
    psutil.net_connections(kind='inet') requires either root or CAP_NET_ADMIN.
    We warn the user rather than hard-exit so they can at least see the GUI.
    """
    return os.geteuid() == 0


# ── Subsystem bootstrap ───────────────────────────────────────────────────────

def _init_subsystems():
    """Initialise all backend singletons before creating the window."""
    import backend.geoip as geoip
    geoip.init()            # loads GeoLite2-Country.mmdb if present

    from data.trust_store import TrustStore
    from data.history import History

    trust = TrustStore()
    hist  = History()
    return trust, hist


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("NetWatch")
    app.setOrganizationName("NetWatch")
    app.setQuitOnLastWindowClosed(False)    # keep running in tray

    # Global font
    font = QFont("Ubuntu", 10)
    font.setStyleHint(QFont.SansSerif)
    app.setFont(font)

    # Stylesheet — minimal, dark-border theme
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

    # Privilege warning
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

    # Initialise subsystems
    try:
        trust_store, history = _init_subsystems()
    except Exception as exc:
        log.exception("Failed to initialise subsystems")
        QMessageBox.critical(None, "NetWatch — startup error", str(exc))
        return 1

    # Create and show main window
    from ui.main_window import MainWindow
    window = MainWindow(trust_store=trust_store, history=history)
    window.show()

    log.info("NetWatch started (pid=%d, euid=%d)", os.getpid(), os.geteuid())
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
