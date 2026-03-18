"""
ui/conn_table.py
----------------
QTableWidget subclass for the live connections table.
Columns: Status dot | App | PID | Interface | Local port | Remote | Enc | Country | Status badges
"""

from __future__ import annotations
from typing import Optional, TYPE_CHECKING

from PyQt5.QtCore import Qt, QSortFilterProxyModel, QAbstractTableModel, QModelIndex, QVariant
from PyQt5.QtGui import QColor, QFont, QBrush
from PyQt5.QtWidgets import (
    QTableView, QHeaderView, QAbstractItemView
)

if TYPE_CHECKING:
    from backend.poller import ConnectionRecord

# ── Column definitions ──────────────────────────────────────────────────────

COLS = [
    ("●",          40,  False),   # 0 status dot
    ("Application",180, True),    # 1
    ("PID",        60,  False),   # 2
    ("Interface",  80,  False),   # 3
    ("Local port", 85,  False),   # 4
    ("Remote host",210, True),    # 5
    ("Enc",        55,  False),   # 6 TLS heuristic
    ("Country",    70,  False),   # 7
    ("Status",     160, False),   # 8
]

COL_DOT      = 0
COL_APP      = 1
COL_PID      = 2
COL_IFACE    = 3
COL_LPORT    = 4
COL_REMOTE   = 5
COL_ENC      = 6
COL_COUNTRY  = 7
COL_STATUS   = 8

# ── Colour palette (matches design plan) ───────────────────────────────────

_COLORS = {
    "trusted":        ("#EAF3DE", "#3B6D11"),
    "unknown":        ("#FAEEDA", "#854F0B"),
    "blocked":        ("#FCEBEB", "#A32D2D"),
    "update-traffic": ("#E6F1FB", "#185FA5"),
    "update-risk":    ("#FCEBEB", "#A32D2D"),
    "wifi":           ("#FAEEDA", "#854F0B"),
    "vpn":            ("#E1F5EE", "#085041"),
    "unencrypted":    ("#FCEBEB", "#A32D2D"),
}

_DOT_COLOR = {
    "trusted":  "#639922",
    "unknown":  "#BA7517",
    "blocked":  "#A32D2D",
    "update":   "#185FA5",
}


def _dot_color(rec: "ConnectionRecord") -> str:
    if rec.is_blocked:
        return _DOT_COLOR["blocked"]
    if rec.is_pkg_manager:
        return _DOT_COLOR["update"]
    if rec.is_trusted:
        return _DOT_COLOR["trusted"]
    return _DOT_COLOR["unknown"]


def _row_bg(rec: "ConnectionRecord") -> Optional[QColor]:
    if rec.is_blocked:
        return QColor("#FCEBEB")
    if rec.is_pkg_manager and rec.is_plaintext:
        return QColor("#FCEBEB")
    if rec.is_pkg_manager:
        return QColor("#E6F1FB")
    if not rec.is_trusted:
        return QColor("#FFFDF5")
    return None


def _status_text(rec: "ConnectionRecord") -> str:
    parts = []
    if rec.is_blocked:
        parts.append("Blocked")
    elif rec.is_pkg_manager:
        if rec.pkg_event:
            parts.append(rec.pkg_event.badge_text())
        else:
            parts.append("Update traffic")
    elif rec.is_trusted:
        parts.append("Trusted")
    else:
        parts.append("Unknown")

    if rec.is_plaintext:
        parts.append("Unencrypted!")
    if rec.is_wifi:
        parts.append("WiFi")
    if rec.is_vpn:
        parts.append("VPN")
    return "  ·  ".join(parts)


def _enc_text(rec: "ConnectionRecord") -> str:
    if rec.tls is None:
        return "?"
    return {
        "ENCRYPTED":   "TLS",
        "LIKELY_ENC":  "~TLS",
        "PLAINTEXT":   "HTTP",
        "UNKNOWN":     "?",
    }.get(rec.tls.status.name, "?")


def _enc_color(rec: "ConnectionRecord") -> Optional[QColor]:
    if rec.tls is None:
        return None
    return {
        "ENCRYPTED":   QColor("#639922"),
        "LIKELY_ENC":  QColor("#BA7517"),
        "PLAINTEXT":   QColor("#A32D2D"),
    }.get(rec.tls.status.name)


# ── Table model ─────────────────────────────────────────────────────────────

class ConnectionModel(QAbstractTableModel):
    """
    Data model for the live connections table.
    Call refresh(records) to push a new snapshot from the poller.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records: list[ConnectionRecord] = []

    def refresh(self, records: "list[ConnectionRecord]") -> None:
        self.beginResetModel()
        self._records = records
        self.endResetModel()

    def update_hostname(self, ip: str, hostname: str) -> None:
        """Called when an async DNS lookup completes."""
        for i, rec in enumerate(self._records):
            if rec.remote_ip == ip and rec.hostname != hostname:
                rec.hostname = hostname
                left  = self.index(i, COL_REMOTE)
                right = self.index(i, COL_REMOTE)
                self.dataChanged.emit(left, right)

    def record_at(self, row: int) -> Optional["ConnectionRecord"]:
        if 0 <= row < len(self._records):
            return self._records[row]
        return None

    # ── QAbstractTableModel interface ────────────────────────────────────

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._records)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(COLS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLS[section][0]
        return QVariant()

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return QVariant()
        rec = self._records[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            return self._display(rec, col)

        if role == Qt.ForegroundRole:
            if col == COL_ENC:
                c = _enc_color(rec)
                if c:
                    return QBrush(c)
            if col == COL_DOT:
                return QBrush(QColor(_dot_color(rec)))

        if role == Qt.BackgroundRole:
            bg = _row_bg(rec)
            if bg:
                return QBrush(bg)

        if role == Qt.TextAlignmentRole:
            if col in (COL_DOT, COL_PID, COL_LPORT, COL_ENC):
                return Qt.AlignCenter

        if role == Qt.ToolTipRole:
            return self._tooltip(rec, col)

        if role == Qt.UserRole:
            # Return raw record for sorting
            return self._sort_key(rec, col)

        return QVariant()

    def _display(self, rec: "ConnectionRecord", col: int) -> str:
        if col == COL_DOT:     return "●"
        if col == COL_APP:     return rec.app_name
        if col == COL_PID:     return str(rec.pid) if rec.pid else ""
        if col == COL_IFACE:   return rec.iface_badge
        if col == COL_LPORT:   return str(rec.local_port)
        if col == COL_REMOTE:  return rec.remote_display
        if col == COL_ENC:     return _enc_text(rec)
        if col == COL_COUNTRY: return rec.geo.display() if rec.geo else ""
        if col == COL_STATUS:  return _status_text(rec)
        return ""

    def _tooltip(self, rec: "ConnectionRecord", col: int) -> str:
        if col == COL_IFACE and rec.iface:
            return rec.iface.risk_text
        if col == COL_ENC and rec.tls:
            return rec.tls.risk_label
        if col == COL_COUNTRY and rec.geo:
            return rec.geo.tooltip()
        if col == COL_APP:
            chain = " → ".join(n.name for n in rec.proc_chain)
            return f"Chain: {chain}\nExe: {rec.app_exe}"
        if col == COL_REMOTE:
            return (f"IP: {rec.remote_ip}\n"
                    f"Host: {rec.hostname}\n"
                    f"Port: {rec.remote_port}  Proto: {rec.proto}")
        return ""

    def _sort_key(self, rec: "ConnectionRecord", col: int):
        if col == COL_APP:    return rec.app_name.lower()
        if col == COL_PID:    return rec.pid
        if col == COL_LPORT:  return rec.local_port
        if col == COL_REMOTE: return rec.remote_ip
        return ""


# ── View ─────────────────────────────────────────────────────────────────────

class ConnectionTableView(QTableView):
    """
    Configured QTableView for the connection model.
    Includes a filter proxy for the search bar.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self._model = ConnectionModel(self)
        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self._proxy.setFilterKeyColumn(-1)      # search all columns
        self.setModel(self._proxy)

        # Appearance
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setSortingEnabled(True)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(30)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)

        # Column widths
        hh = self.horizontalHeader()
        hh.setStretchLastSection(False)
        for i, (_, width, stretch) in enumerate(COLS):
            if stretch:
                hh.setSectionResizeMode(i, QHeaderView.Stretch)
            else:
                hh.setSectionResizeMode(i, QHeaderView.Fixed)
                self.setColumnWidth(i, width)

        # Font
        f = QFont()
        f.setPointSize(10)
        self.setFont(f)

    def refresh(self, records: "list[ConnectionRecord]") -> None:
        self._model.refresh(records)

    def update_hostname(self, ip: str, hostname: str) -> None:
        self._model.update_hostname(ip, hostname)

    def set_filter(self, text: str) -> None:
        self._proxy.setFilterFixedString(text)

    def selected_record(self) -> Optional["ConnectionRecord"]:
        indexes = self.selectedIndexes()
        if not indexes:
            return None
        source_row = self._proxy.mapToSource(indexes[0]).row()
        return self._model.record_at(source_row)
