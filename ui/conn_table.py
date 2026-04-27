"""
ui/conn_table.py
----------------
Live connection table — five-tier trust model, org fingerprint column.

Tiers and colours:
  TRUSTED      green   — user explicitly trusted this exe
  KNOWN_INFRA  blue    — recognised CDN / cloud / major service (monitor only)
  UNKNOWN      amber   — unrecognised, flag for user attention
  SUSPICIOUS   orange  — known-bad infra or masquerading pkg manager
  BLOCKED      red     — user explicitly blocked
"""

from __future__ import annotations
from typing import Optional, TYPE_CHECKING

from PyQt5.QtCore import Qt, QSortFilterProxyModel, QAbstractTableModel, \
    QModelIndex, QVariant, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QBrush
from PyQt5.QtWidgets import QTableView, QHeaderView, QAbstractItemView

if TYPE_CHECKING:
    from backend.poller import ConnectionRecord

# ── Columns ────────────────────────────────────────────────────────────────────
COLS = [
    ("●",           36,  False),   # 0  tier dot
    ("Application", 165, True),    # 1
    ("Organisation",150, True),    # 2  NEW — org fingerprint
    ("PID",         55,  False),   # 3
    ("Interface",   75,  False),   # 4
    ("Local port",  80,  False),   # 5
    ("Remote host", 200, True),    # 6
    ("Enc",         50,  False),   # 7
    ("Country",     65,  False),   # 8
    ("Status",      155, False),   # 9
]

COL_DOT=0; COL_APP=1; COL_ORG=2; COL_PID=3; COL_IFACE=4
COL_LPORT=5; COL_REMOTE=6; COL_ENC=7; COL_COUNTRY=8; COL_STATUS=9

# ── Tier colours (light / dark pairs) ─────────────────────────────────────────
_TIER_DOT = {
    "trusted":      "#639922",
    "known_infra":  "#378ADD",
    "unknown":      "#BA7517",
    "suspicious":   "#D85A30",
    "blocked":      "#E24B4A",
}

_TIER_BG_LIGHT = {
    "trusted":      None,           # no highlight — trusted is normal
    "known_infra":  None,           # no highlight — known infra is normal
    "unknown":      "#FFFBF0",      # very subtle amber tint
    "suspicious":   "#FFF0E8",      # orange tint
    "blocked":      "#FFF0F0",      # red tint
}

_TIER_BG_DARK = {
    "trusted":      None,
    "known_infra":  None,
    "unknown":      "#252218",      # subtle dark amber
    "suspicious":   "#2a1a0f",      # dark orange
    "blocked":      "#2d1515",      # dark red
}

_THEME_DARK = False


def set_theme_dark(dark: bool) -> None:
    """Set by main window when theme toggles."""
    global _THEME_DARK
    _THEME_DARK = bool(dark)


def _is_dark() -> bool:
    return _THEME_DARK


def _tier(rec: "ConnectionRecord") -> str:
    return rec.trust_tier


def _dot_color(rec: "ConnectionRecord") -> str:
    return _TIER_DOT.get(_tier(rec), _TIER_DOT["unknown"])


def _row_bg(rec: "ConnectionRecord") -> Optional[QColor]:
    t = _tier(rec)
    color_str = (_TIER_BG_DARK if _is_dark() else _TIER_BG_LIGHT).get(t)
    return QColor(color_str) if color_str else None


def _status_text(rec: "ConnectionRecord") -> str:
    parts = []
    t = _tier(rec)
    if t == "blocked":
        parts.append("Blocked")
    elif t == "trusted":
        parts.append("Trusted")
    elif t == "known_infra":
        if rec.is_pkg_manager:
            parts.append(rec.pkg_event.badge_text() if rec.pkg_event
                         else "Update — unverified")
        else:
            parts.append("Known service")
    elif t == "suspicious":
        if rec.pkg_event and rec.pkg_event.is_suspicious_masquerade:
            parts.append("⚠ Masquerade")
        else:
            parts.append("⚠ Suspicious")
    else:
        parts.append("Unknown")
    if rec.is_unidentified:
        parts.append("no PID")
    if rec.is_plaintext:
        parts.append("Unencrypted!")
    if rec.is_wifi:
        parts.append("WiFi")
    if rec.is_vpn:
        parts.append("VPN")
    return "  ·  ".join(parts)


def _enc_text(rec: "ConnectionRecord") -> str:
    if not rec.tls:
        return "?"
    return {"ENCRYPTED": "TLS", "LIKELY_ENC": "~TLS",
            "PLAINTEXT": "HTTP", "UNKNOWN": "?"}.get(rec.tls.status.name, "?")


def _enc_color(rec: "ConnectionRecord") -> Optional[QColor]:
    if not rec.tls:
        return None
    return {"ENCRYPTED":  QColor("#639922"),
            "LIKELY_ENC": QColor("#BA7517"),
            "PLAINTEXT":  QColor("#E24B4A")}.get(rec.tls.status.name)


# ── Model ──────────────────────────────────────────────────────────────────────

class ConnectionModel(QAbstractTableModel):

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records: list = []

    def refresh(self, records) -> None:
        self.beginResetModel()
        self._records = records
        self.endResetModel()

    def update_hostname(self, ip: str, hostname: str) -> None:
        for i, rec in enumerate(self._records):
            if rec.remote_ip == ip and rec.hostname != hostname:
                rec.hostname = hostname
                self.dataChanged.emit(
                    self.index(i, COL_REMOTE),
                    self.index(i, COL_REMOTE)
                )

    def update_org(self, ip: str, org_label: str) -> None:
        """Called when async DNS resolves and org is fingerprinted."""
        for i, rec in enumerate(self._records):
            if rec.remote_ip == ip:
                self.dataChanged.emit(
                    self.index(i, COL_ORG),
                    self.index(i, COL_ORG)
                )

    def record_at(self, row: int):
        return self._records[row] if 0 <= row < len(self._records) else None

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
            if col == COL_DOT:
                return QBrush(QColor(_dot_color(rec)))
            if col == COL_ENC:
                c = _enc_color(rec)
                if c:
                    return QBrush(c)
            if col == COL_ORG and rec.org and rec.org.is_known:
                # Muted colour for known-infra org label
                return QBrush(QColor("#6a82b4") if _is_dark()
                               else QColor("#4a5a8a"))
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
            return self._sort_key(rec, col)
        return QVariant()

    def _display(self, rec, col) -> str:
        if col == COL_DOT:     return "●"
        if col == COL_APP:     return rec.app_name
        if col == COL_ORG:     return rec.org_label
        if col == COL_PID:     return str(rec.pid) if rec.pid else ""
        if col == COL_IFACE:   return rec.iface_badge
        if col == COL_LPORT:   return str(rec.local_port)
        if col == COL_REMOTE:  return rec.remote_display
        if col == COL_ENC:     return _enc_text(rec)
        if col == COL_COUNTRY: return rec.geo.display() if rec.geo else ""
        if col == COL_STATUS:  return _status_text(rec)
        return ""

    def _tooltip(self, rec, col) -> str:
        if col == COL_APP:
            chain = " → ".join(n.name for n in rec.proc_chain) or "No chain"
            return (f"Chain: {chain}\n"
                    f"Exe: {rec.app_exe or '(unknown)'}\n"
                    f"PID: {rec.pid or '?'}")
        if col == COL_ORG:
            if rec.org and rec.org.is_known:
                return (f"Organisation: {rec.org.org_name}\n"
                        f"Domain: {rec.org.root_domain or '(IP match)'}\n"
                        f"Detail: {rec.org.detail or 'n/a'}\n"
                        f"Tier: {rec.org.tier.name}")
            return "Organisation not recognised"
        if col == COL_REMOTE:
            direction = "outbound" if rec.local_port > 1024 else "inbound"
            return (f"IP: {rec.remote_ip}\n"
                    f"Host: {rec.hostname or '(resolving…)'}\n"
                    f"Port: {rec.remote_port}  Proto: {rec.proto}\n"
                    f"Direction: {direction}")
        if col == COL_IFACE and rec.iface:
            return rec.iface.risk_text
        if col == COL_ENC and rec.tls:
            return rec.tls.risk_label
        if col == COL_COUNTRY and rec.geo:
            return rec.geo.tooltip()
        if col == COL_STATUS and rec.is_unidentified:
            return ("No process could be identified for this connection.\n"
                    "This may be a kernel socket, a process that exited\n"
                    "mid-poll, or insufficient read permissions.\n\n"
                    "Check the Organisation column — if it shows a known\n"
                    "service this is likely legitimate background traffic.")
        return ""

    def _sort_key(self, rec, col):
        if col == COL_APP:    return rec.app_name.lower()
        if col == COL_ORG:    return rec.org_label.lower()
        if col == COL_PID:    return rec.pid
        if col == COL_LPORT:  return rec.local_port
        if col == COL_REMOTE: return rec.remote_ip
        return ""


# ── View ───────────────────────────────────────────────────────────────────────

class ConnectionTableView(QTableView):

    record_selected = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._model = ConnectionModel(self)
        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self._proxy.setFilterKeyColumn(-1)
        self.setModel(self._proxy)

        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setSortingEnabled(True)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(28)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)

        hh = self.horizontalHeader()
        hh.setStretchLastSection(False)
        for i, (_, width, stretch) in enumerate(COLS):
            if stretch:
                hh.setSectionResizeMode(i, QHeaderView.Stretch)
            else:
                hh.setSectionResizeMode(i, QHeaderView.Fixed)
                self.setColumnWidth(i, width)

        f = QFont()
        f.setPointSize(10)
        self.setFont(f)

        self.clicked.connect(self._on_clicked)

    def _on_clicked(self, proxy_index: QModelIndex) -> None:
        source_index = self._proxy.mapToSource(proxy_index)
        rec = self._model.record_at(source_index.row())
        self.record_selected.emit(rec)

    def refresh(self, records) -> None:
        self._model.refresh(records)

    def update_hostname(self, ip: str, hostname: str) -> None:
        self._model.update_hostname(ip, hostname)

    def update_org(self, ip: str, org_label: str) -> None:
        self._model.update_org(ip, org_label)

    def set_filter(self, text: str) -> None:
        self._proxy.setFilterFixedString(text)

    def selected_record(self):
        indexes = self.selectedIndexes()
        if not indexes:
            return None
        source_row = self._proxy.mapToSource(indexes[0]).row()
        return self._model.record_at(source_row)

    def set_dark_mode(self, dark: bool) -> None:
        set_theme_dark(dark)
        # Ensure row colours are recalculated immediately.
        self.viewport().update()
